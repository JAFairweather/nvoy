// agent_memory.mjs — memory_claim and memory_withdraw: an agent writing room-scoped Hive memory
// under its own key (docs/DESIGN_HIVE_MEMORY.md).
//
// The keyless channel MCP can only ask. It resolves the room, refuses every scope but room:<uuid>,
// runs the memory secret guard and test-builds the claim with memory.mjs, so the agent hears a
// refusal at once, then spools one bounded `memory-request` file (`<id>.tmp`, fsynced, renamed to
// `<id>.json`). The broker (instance-broker-memory.mjs) re-checks every field against the manifest's
// may_remember block, counts the hourly cap on its own durable counter, builds the kind 30078 from
// those fields, signs it and submits it to the private Hive memory store, then unlinks the request.
// The agent never supplies an event, and the rate log beside the spool holds only ids and times.

import { appendFileSync, closeSync, fsyncSync, lstatSync, openSync, readFileSync, renameSync, rmSync, writeSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { resolve } from 'node:path'
import { HOUR_MS } from './agent_limits.mjs'
import { FALLBACK_MEMORY_KIND, MEMORY_TOOL_SPECS, buildClaimTemplate, buildWithdrawalTemplate, checkClaimPayloadSecrets, formatFactKey, parseScope } from './memory.mjs'
import { withheld } from './outbound_secrets.mjs'

// Agent claims use the fallback kind the Bunker pairing already allows.
export const REMEMBER_KIND = FALLBACK_MEMORY_KIND
export const MEMORY_NOT_PERMITTED = 'this identity may not write memory'
export const MEMORY_REQUEST_FILE = /^[0-9a-f]{32}\.json$/
export const MAX_MEMORY_REQUEST_BYTES = 64 * 1024
export const memoryQueueDir = manifest => resolve(manifest.runtimeDir, 'memory-requests')
export const memoryRequestPath = (manifest, id) => resolve(memoryQueueDir(manifest), `${id}.json`)
export const memoryRatePath = manifest => resolve(manifest.runtimeDir, 'memory-rate.jsonl')
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const TOOLS = Object.freeze({ claim: 'memory_claim', withdraw: 'memory_withdraw' })
const FIELDS = Object.freeze({
  claim: ['slug', 'topic', 'claim', 'because', 'evidence', 'as_of_git', 'as_of_evt', 'ttl_sec', 'supersedes'],
  withdraw: ['slug', 'because'],
})
const schemaOf = op => MEMORY_TOOL_SPECS.find(s => s.name === TOOLS[op]).inputSchema

export function memoryToolSpec(manifest, op) {
  const m = manifest.mayRemember, schema = schemaOf(op)
  const { scope, ...properties } = schema.properties
  const limits = m ? ` Rooms: ${m.rooms.join(', ')} (default ${m.rooms[0]}). At most ${m.perHour} memory writes an hour.`
    : ` Refused: ${MEMORY_NOT_PERMITTED}.`
  const what = op === 'claim'
    ? 'Record a signed room memory claim in the private Hive memory store under your own key.' +
      ' What counts: (1) a reviewed decision with who made it and why, (2) a non-obvious fact or gotcha another agent would otherwise rediscover,' +
      ' (3) a project status change (started, blocked, shipped, dropped), or (4) who owns what next.' +
      ' One fact per claim at a stable slug; set topic to the project slug (e.g. nvoy, herd-infra, hive-memory, buzz, r1).' +
      ' Cite concrete evidence (commit, PR, file path, message id) and an as_of_git (<repo>@<sha>) or as_of_evt (<64-hex>) anchor.' +
      ' Retention (ttl_sec): 1..2592000 (default 1209600, 14 days; at most 30 days) for a Class A status claim that expires;' +
      ' a workflow checkpoint (slug ending -review, -status, -owner, -wip or -handoff) defaults to 86400 (24 h) and is capped at 48 h;' +
      ' 0 for a Class B durable decision or standing project fact that stays active until withdrawn or superseded.' +
      ' When your claim closes another agent\'s checkpoint (you merged the PR they reviewed), name its event id in supersedes so it leaves the default view.' +
      (manifest.mayRecall ? ' Check memory_query first to avoid duplicates.' : '') + ' When a fact changes, supersede it at the same slug (supersedes: [<prior event id>]); when it stops being true, call memory_withdraw.' +
      ' Never record chatter, narration, guesses, personal details, secrets, or prose already in git or docs: cite those in evidence instead.'
    : 'Withdraw your room memory claim at one slug as soon as it stops being true, is resolved, or was wrong.' +
      ' The broker looks up your current claim at the fact key and submits a replacement marked withdrawn, with a strictly later created_at.'
  return {
    name: TOOLS[op],
    description: `${what} The broker checks the manifest's may_remember block, signs a kind ${REMEMBER_KIND} and submits it to the private Hive memory store, never to a relay. Only room:<uuid> scopes; hive:ops, hive:canon and self are refused.${limits}`,
    inputSchema: { type: 'object', properties: { room: { type: 'string', pattern: UUID.source }, scope, ...properties },
      required: schema.required.filter(k => k !== 'scope'), additionalProperties: false },
  }
}

const fitsString = (value, s) => typeof value === 'string' && value.length >= (s.minLength || 0) &&
  value.length <= (s.maxLength ?? Infinity) && (!s.pattern || new RegExp(s.pattern).test(value))
// The fields against the memory.mjs schema, or the reason they do not fit.
function fieldError(op, fields) {
  const schema = schemaOf(op)
  for (const [key, value] of Object.entries(fields)) {
    const s = schema.properties[key]
    if (!FIELDS[op].includes(key) || !s) return `${key} is not a ${TOOLS[op]} field`
    const fits = s.type === 'string' ? fitsString(value, s)
      : s.type === 'integer' ? Number.isInteger(value) && value >= s.minimum && value <= s.maximum
        : Array.isArray(value) && value.length >= (s.minItems || 0) && value.length <= s.maxItems && value.every(x => fitsString(x, s.items))
    if (!fits) return `${key} does not fit its schema`
  }
  const missing = schema.required.find(k => k !== 'scope' && fields[k] == null)
  return missing ? `${missing} is required` : null
}

// A scope (or room) to the one room it names, or the refusal: an agent writes room memory only.
export function resolveMemoryScope(manifest, { scope, room } = {}) {
  const m = manifest.mayRemember
  if (!m) return { code: 'NVOY_MEMORY_NOT_PERMITTED', message: MEMORY_NOT_PERMITTED }
  const raw = scope != null ? String(scope) : `room:${room != null ? String(room).toLowerCase() : m.rooms[0]}`
  const parsed = parseScope(raw)
  if (!parsed || parsed.type !== 'room') return { code: 'NVOY_MEMORY_SCOPE_REFUSED',
    message: `only room:<uuid> scopes may be written by an agent; ${parsed ? `${parsed.type} is` : 'that scope is'} refused` }
  if (room != null && String(room).toLowerCase() !== parsed.roomId) return { code: 'NVOY_BAD_MEMORY', message: 'room and scope name different rooms' }
  if (!m.rooms.includes(parsed.roomId)) return { code: 'NVOY_MEMORY_ROOM_REFUSED', message: `room is not in may_remember.rooms (${m.rooms.join(', ')})` }
  return { scope: parsed.scope, roomId: parsed.roomId }
}

// The memory secret guard over every field the agent wrote; the name of the pattern hit, or null.
export const memorySecretIn = fields => checkClaimPayloadSecrets({ claim: fields.claim, because: fields.because, evidence: fields.evidence,
  tags: [[fields.slug, fields.topic, fields.as_of_git, fields.as_of_evt, ...(fields.supersedes || [])].filter(x => x != null)] })

// The unsigned kind 30078 a request builds, after `prior`, this identity's latest event at the
// fact key. A withdrawal is that replacement alone: Buzz takes a kind 5 with exactly one target, the
// replaced claim is already gone, and an `a` target would also delete the replacement itself.
export function memoryTemplates(manifest, { op, scope, fields }, prior = null, nowSec = Math.floor(Date.now() / 1000)) {
  if (op === 'claim') {
    return { event: buildClaimTemplate({ pubkey: manifest.pubkey, scope, slug: fields.slug, topic: fields.topic, claim: fields.claim,
      because: fields.because, evidence: fields.evidence, asOfGit: fields.as_of_git, asOfEvt: fields.as_of_evt, ttlSec: fields.ttl_sec,
      supersedes: fields.supersedes, kind: REMEMBER_KIND, nowSec, priorCreatedAt: prior?.created_at || 0 }) }
  }
  const { replacement } = buildWithdrawalTemplate({ pubkey: manifest.pubkey, priorEvent: prior, scope, slug: fields.slug,
    because: fields.because, kind: REMEMBER_KIND, nowSec })
  return { event: replacement }
}

// Broker side: the one shape a memory request may have, re-checked against the manifest. The
// keyless writer may have put anything in the queue, so nothing it resolved is trusted.
export function validateMemoryRequest(row, manifest) {
  const keys = ['version', 'type', 'id', 'instance', 'op', 'scope', 'fields', 'requested_at']
  if (!row || typeof row !== 'object' || Array.isArray(row) || Object.keys(row).some(k => !keys.includes(k)) ||
      row.version !== 1 || row.type !== 'memory-request' || row.instance !== manifest.id || !/^[0-9a-f]{32}$/.test(String(row.id || '')) ||
      !Object.hasOwn(FIELDS, row.op) || typeof row.scope !== 'string' || !row.fields || typeof row.fields !== 'object' ||
      Array.isArray(row.fields) || !Number.isFinite(row.requested_at)) throw new Error('memory request has an invalid or overbroad shape')
  if (!manifest.mayRemember) throw new Error(`memory refused: ${MEMORY_NOT_PERMITTED}`)
  const resolved = resolveMemoryScope(manifest, { scope: row.scope })
  if (resolved.code) throw new Error(`memory refused: ${resolved.message}`)
  const bad = fieldError(row.op, row.fields)
  if (bad) throw new Error(`memory refused: ${bad}`)
  return { ...row, d: formatFactKey(resolved.scope, row.fields.slug), roomId: resolved.roomId }
}

// The memory rate log: one { id, requested_at } line per spooled request, never the words.
function rateRows(path) {
  const st = lstatSync(path)
  if (!st.isFile() || st.isSymbolicLink()) throw new Error('memory rate log must be a regular non-symlink file')
  if (st.size > 16 * 1024 * 1024) throw new Error('memory rate log exceeds its 16 MiB bound')
  return readFileSync(path, 'utf8').split('\n').filter(Boolean).map(line => { try { return JSON.parse(line) } catch { return null } })
}

function writeDurably(path, body, mode) {
  const fd = openSync(path, 'wx', mode)
  try {
    const data = Buffer.from(body)
    let off = 0
    while (off < data.length) off += writeSync(fd, data, off, data.length - off)
    fsyncSync(fd)
  } finally { closeSync(fd) }
}

// The keyless tool: resolve, guard, test-build, advise on the cap, spool. Returns the tool's JSON answer.
export function queueMemory(manifest, op, args = {}, now = Date.now()) {
  const resolved = resolveMemoryScope(manifest, args)
  if (resolved.code) return { error: resolved }
  const fields = Object.fromEntries(Object.entries(args).filter(([k, v]) => k !== 'room' && k !== 'scope' && v != null))
  const bad = fieldError(op, fields)
  if (bad) return { error: { code: 'NVOY_BAD_MEMORY', message: bad } }
  const secret = memorySecretIn(fields)
  if (secret) {
    const { error, log } = withheld({ instance: manifest.id, path: TOOLS[op], name: secret, text: JSON.stringify(fields) })
    console.error(log)
    return { error }
  }
  try { memoryTemplates(manifest, { op, scope: resolved.scope, fields }, null, Math.floor(now / 1000)) }
  catch (error) { return { error: { code: 'NVOY_BAD_MEMORY', message: error.message } } }
  const dir = memoryQueueDir(manifest), ratePath = memoryRatePath(manifest)
  // Provisioned by instance-runtime-init for a may_remember manifest; the reader never creates them.
  try {
    const st = lstatSync(dir)
    if (!st.isDirectory() || st.isSymbolicLink()) throw new Error('not a directory')
    lstatSync(ratePath)
  } catch { return { error: { code: 'NVOY_MEMORY_QUEUE_FAILED', message: 'memory request spool is not provisioned; re-run the runtime init' } } }
  let tmp = null
  try {
    const recent = rateRows(ratePath).filter(r => /^[0-9a-f]{32}$/.test(String(r?.id)) && Number.isFinite(r.requested_at) && now - r.requested_at < HOUR_MS).length
    if (recent >= manifest.mayRemember.perHour) return { error: { code: 'NVOY_MEMORY_RATE_LIMITED', message: `over the hourly cap: ${recent}/${manifest.mayRemember.perHour} memory writes in the last hour` } }
    const row = { version: 1, type: 'memory-request', id: randomBytes(16).toString('hex'), instance: manifest.id, op, scope: resolved.scope, fields, requested_at: now }
    const body = JSON.stringify(row)
    if (Buffer.byteLength(body) > MAX_MEMORY_REQUEST_BYTES) return { error: { code: 'NVOY_BAD_MEMORY', message: 'memory request exceeds its 64 KiB bound' } }
    tmp = resolve(dir, `${row.id}.tmp`)
    writeDurably(tmp, body, 0o640)
    renameSync(tmp, memoryRequestPath(manifest, row.id))
    tmp = null
    appendFileSync(ratePath, JSON.stringify({ id: row.id, requested_at: now }) + '\n')
    return { ok: { queued: true, request: row.id, op, scope: row.scope, d: formatFactKey(row.scope, fields.slug) } }
  } catch (error) {
    if (tmp) rmSync(tmp, { force: true })
    return { error: { code: 'NVOY_MEMORY_QUEUE_FAILED', message: error.message } }
  }
}
