// agent_memory.mjs — memory_claim and memory_withdraw: an agent writing room-scoped Hive memory
// under its own key (docs/DESIGN_HIVE_MEMORY.md).
//
// The keyless channel MCP can only ask. It resolves the room, refuses every scope but room:<uuid>,
// runs the memory secret guard and test-builds the claim with memory.mjs, so the agent hears a
// refusal at once, then appends one bounded `memory-request`. The broker (instance-broker-memory.mjs)
// re-checks every field against the manifest's may_remember block, counts the hourly cap on its own
// durable counter, builds the kind 30078 from those fields, signs and publishes. The agent never
// supplies an event.

import { appendFileSync, existsSync, lstatSync, readFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { resolve } from 'node:path'
import { HOUR_MS } from './agent_limits.mjs'
import { FALLBACK_MEMORY_KIND, MEMORY_TOOL_SPECS, buildClaimTemplate, buildWithdrawalTemplate, checkClaimPayloadSecrets, formatFactKey, parseScope } from './memory.mjs'
import { withheld } from './outbound_secrets.mjs'

// buzz-relay refuses kind 30079, so agent claims use the fallback kind the Bunker already allows.
export const REMEMBER_KIND = FALLBACK_MEMORY_KIND
export const MEMORY_NOT_PERMITTED = 'this identity may not write memory'
export const memoryQueuePath = manifest => resolve(manifest.runtimeDir, 'memory-requests.jsonl')
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
    ? 'Record a room memory claim under your own key. Record a decision, a fact others would otherwise rediscover, a project status change, or who owns what next.' +
      ' One fact per claim; topic is the project name. Cite evidence (commit, PR, message id) and an as_of_git or as_of_evt anchor.' +
      ' Check memory_query first to avoid duplicates. When a claim becomes wrong, withdraw it, or supersede it with a new claim at the same slug.' +
      ' Do not record narration, guesses, chat, anything personal, or what is already in git or docs: cite that as evidence instead.' +
      ' A claim expires after ttl_sec (default 14 days, at most 30).'
    : 'Withdraw your room memory claim at one slug when it is wrong or finished. The broker publishes a replacement marked withdrawn, with a later created_at.'
  return {
    name: TOOLS[op],
    description: `${what} The broker checks the manifest's may_remember block, signs a kind ${REMEMBER_KIND} and publishes it to the room. Only room:<uuid> scopes; hive:ops, hive:canon and self are refused.${limits}`,
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

function queueRows(path) {
  const st = lstatSync(path)
  if (!st.isFile() || st.isSymbolicLink()) throw new Error('memory request queue must be a regular non-symlink file')
  if (st.size > 64 * 1024 * 1024) throw new Error('memory request queue exceeds its 64 MiB bound')
  return readFileSync(path, 'utf8').split('\n').filter(Boolean).map(line => { try { return JSON.parse(line) } catch { return null } })
}

// The keyless tool: resolve, guard, test-build, advise on the cap, append. Returns the tool's JSON answer.
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
  const path = memoryQueuePath(manifest)
  // Provisioned by instance-runtime-init for a may_remember manifest; the reader never creates it.
  if (!existsSync(path)) return { error: { code: 'NVOY_MEMORY_QUEUE_FAILED', message: 'memory request queue is not provisioned; re-run the runtime init' } }
  try {
    const recent = queueRows(path).filter(r => r?.type === 'memory-request' && Number.isFinite(r.requested_at) && now - r.requested_at < HOUR_MS).length
    if (recent >= manifest.mayRemember.perHour) return { error: { code: 'NVOY_MEMORY_RATE_LIMITED', message: `over the hourly cap: ${recent}/${manifest.mayRemember.perHour} memory writes in the last hour` } }
    const row = { version: 1, type: 'memory-request', id: randomBytes(16).toString('hex'), instance: manifest.id, op, scope: resolved.scope, fields, requested_at: now }
    appendFileSync(path, JSON.stringify(row) + '\n')
    return { ok: { queued: true, request: row.id, op, scope: row.scope, d: formatFactKey(row.scope, fields.slug) } }
  } catch (error) { return { error: { code: 'NVOY_MEMORY_QUEUE_FAILED', message: error.message } } }
}
