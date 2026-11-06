#!/usr/bin/env node
// instance-broker-memory.mjs — the keyed actuator for memory_claim and memory_withdraw.
//
// A memory write answers nothing, so its authority is the owner's standing opt-in: the manifest's
// may_remember block, which names the rooms, how many writes an hour, and the writer transport to
// the private Hive memory store. Everything the keyless spool says is re-checked here; the event is
// built from its fields by memory.mjs, never taken from it. Only room:<uuid> scopes and only kind
// 30078, which the Bunker pairing already allows.
//
// The store is asked first for this identity's current event at the fact key, so a replacement is
// strictly later than what it replaces and names it as its expected prior; a request that cannot
// ask is held rather than guessed. Then the post discipline: the cap is counted before the event
// exists, the exact event is frozen before it is signed, and a retry resubmits that event. Once the
// store answers for good, the record is scrubbed of the event and the spooled request is unlinked,
// so no claim text outlives the write on this host.

import { spawn } from 'node:child_process'
import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { connect } from 'node:net'
import { resolve } from 'node:path'
import { getEventHash, verifyEvent } from 'nostr-tools/pure'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { brokerSigner } from './broker_signer.mjs'
import { replyRequestDigest } from './outbound_record.mjs'
import { countInWindow } from './agent_limits.mjs'
import { MAX_MEMORY_REQUEST_BYTES, MEMORY_NOT_PERMITTED, REMEMBER_KIND, memoryRequestPath, memorySecretIn, memoryTemplates, validateMemoryRequest } from './agent_memory.mjs'
import { validateMemoryEvent } from './memory.mjs'
import { withheldMessage } from './outbound_secrets.mjs'

// Store refusals no retry can change. Anything else (not ready, fenced, rate-limited, ledger I/O,
// a reader socket configured as the writer, transport) holds the request for retry.
const TERMINAL = new Set(['HIVE_MEMORY_SCOPE_NOT_AUTHORIZED', 'HIVE_MEMORY_WRITER_MISMATCH', 'HIVE_MEMORY_INVALID_EVENT', 'HIVE_MEMORY_PRIOR_MISMATCH',
  'HIVE_MEMORY_NOT_NEWER', 'HIVE_MEMORY_NOTHING_TO_WITHDRAW', 'HIVE_MEMORY_PURGED_EVENT'])
const RPC_TIMEOUT_MS = 20000

let signer
const exit = code => { try { signer?.close?.() } catch { /* best effort */ } process.exit(code) }
const die = m => { console.error(`instance-broker-memory: ${m}`); exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), requestId = flag('--request').toLowerCase()
if (!id || !/^[0-9a-f]{32}$/.test(requestId)) die('usage: --instance <id> --request <32-hex-id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }
if (manifest.brokerMode !== 'local') die('remote-broker Desktop manifests cannot sign locally')
if (!manifest.mayRemember) die(`memory refused: ${MEMORY_NOT_PERMITTED}`)

const spoolPath = memoryRequestPath(manifest, requestId)
const unlinkSpool = () => { try { rmSync(spoolPath, { force: true }) } catch (e) { console.error(`instance-broker-memory: cannot unlink request ${requestId.slice(0, 12)}…: ${e.code || e.message}`) } }
const memoryDir = resolve(manifest.stateDir, 'memory')
mkdirSync(memoryDir, { recursive: true, mode: 0o700 })
const recordPath = resolve(memoryDir, `${requestId}.json`)
let record = null
const persist = () => {
  const tmp = `${recordPath}.${process.pid}.tmp`
  try { writeFileSync(tmp, JSON.stringify(record), { mode: 0o600 }); renameSync(tmp, recordPath) } catch (e) { die(`cannot persist memory record: ${e.message}`) }
}
if (existsSync(recordPath)) {
  const st = lstatSync(recordPath)
  if (!st.isFile() || st.isSymbolicLink()) die('memory record must be a regular non-symlink file')
  try { record = JSON.parse(readFileSync(recordPath, 'utf8')) } catch { die('memory record is invalid') }
  if (record?.version !== 1 || record.request_id !== requestId) die('memory record does not bind this request')
  // Scrubbed: the store already answered for good, so a retry only reports that answer.
  if (record.published === true) {
    unlinkSpool()
    console.log(JSON.stringify({ request: requestId, accepted: true, replay: true }))
    exit(0)
  }
  if (record.refused) { unlinkSpool(); die(`memory refused: ${record.refused}`) }
}

let request
try {
  const st = lstatSync(spoolPath)
  if (!st.isFile() || st.isSymbolicLink()) die('memory request must be a regular non-symlink file')
  if (st.size > MAX_MEMORY_REQUEST_BYTES) die('memory request has an invalid or overbroad shape')
  request = JSON.parse(readFileSync(spoolPath, 'utf8'))
} catch (e) {
  die(e.code === 'ENOENT' ? 'memory request is not present in this instance spool' : 'memory request has an invalid or overbroad shape')
}
if (request?.id !== requestId) die('memory request has an invalid or overbroad shape')
let checked
try { checked = validateMemoryRequest(request, manifest) } catch (e) { die(e.message) }
// Again here, where the signer is: a client that writes the spool without the tool skips the tool's check.
const leaked = memorySecretIn(request.fields)
if (leaked) die(`memory refused: ${withheldMessage(leaked)} instance ${manifest.id}`)
const digest = replyRequestDigest(request)
// What any event built for this request must be: kind 30078, this key, this room and fact key.
const unsignedOk = ev => {
  const v = validateMemoryEvent(ev, { allowedKinds: [REMEMBER_KIND], verifySignature: false })
  return v.ok && ev.kind === REMEMBER_KIND && v.pubkey === manifest.pubkey && v.scopeType === 'room' && v.roomId === checked.roomId && v.d === checked.d &&
    v.status === (request.op === 'claim' ? 'active' : 'withdrawn') ? null : v.reason || 'built event does not bind this request'
}
const signedOk = (ev, fingerprint) => ev && ev.id === fingerprint && getEventHash(ev) === fingerprint && verifyEvent(JSON.parse(JSON.stringify(ev)))
if (record) {
  const ev = record.unsigned_event
  if (record.request_digest !== digest || !ev || getEventHash(ev) !== record.fingerprint || unsignedOk(ev) ||
      !(record.expected_prior_id === null || /^[0-9a-f]{64}$/.test(String(record.expected_prior_id))) ||
      (record.event && !signedOk(record.event, record.fingerprint))) die('memory record does not bind this request')
}

// One newline JSON-RPC tools/call on the writer transport: the socket itself, or a forced command
// whose stdio is that socket.
function callStore(name, args) {
  return new Promise((resolveCall, rejectCall) => {
    const { socket, command } = manifest.mayRemember.submit
    let child = null, conn = null, buf = '', done = false
    const finish = (err, value) => {
      if (done) return
      done = true
      clearTimeout(timer)
      try { conn?.destroy() } catch { /* closed */ }
      try { child?.kill() } catch { /* exited */ }
      if (err) rejectCall(err); else resolveCall(value)
    }
    const timer = setTimeout(() => finish(new Error('the memory store did not answer in time')), RPC_TIMEOUT_MS)
    const onData = chunk => {
      buf += chunk
      const nl = buf.indexOf('\n')
      if (nl < 0) return
      try {
        const msg = JSON.parse(buf.slice(0, nl))
        if (msg.error) return finish(new Error(`memory store error ${msg.error.code}: ${msg.error.message}`))
        finish(null, JSON.parse(msg.result.content[0].text))
      } catch (e) { finish(new Error(`unreadable memory store reply: ${e.message}`)) }
    }
    const line = `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } })}\n`
    if (socket) {
      conn = connect(socket)
      conn.setEncoding('utf8')
      conn.on('data', onData)
      conn.on('error', e => finish(new Error(`memory store unreachable: ${e.code || e.message}`)))
      conn.on('close', () => finish(new Error('memory store closed the connection')))
      conn.on('connect', () => conn.write(line))
    } else {
      child = spawn(command[0], command.slice(1), { stdio: ['pipe', 'pipe', 'ignore'] })
      child.stdout.setEncoding('utf8')
      child.stdout.on('data', onData)
      child.on('error', e => finish(new Error(`memory store bridge failed: ${e.code || e.message}`)))
      child.on('close', () => finish(new Error('memory store bridge exited')))
      child.stdin.on('error', () => {})
      child.stdin.write(line)
    }
  })
}
const refusedOrHeld = (out, what) => TERMINAL.has(out.code)
  ? `memory refused: ${out.code}: ${out.message}`
  : `${what}: ${out.code || 'unknown'}: ${out.message || ''}; held for retry`

if (!signer) ({ signer } = brokerSigner(die, { idleMs: 30000 }))
let me
try { me = String(await signer.getPublicKey()).toLowerCase() } catch (e) { die(`signer unavailable: ${e.message}`) }
if (me !== manifest.pubkey) die('signer does not match manifest pubkey')

if (!record) {
  let prior
  try { prior = await callStore('memory_lookup_prior', { d: checked.d }) } catch (e) {
    die(request.op === 'withdraw' ? `cannot look up the claim to withdraw: ${e.message}; held for retry`
      : `cannot look up the latest claim at ${checked.d}: ${e.message}; held for retry`)
  }
  if (prior?.accepted === false) die(refusedOrHeld(prior, `cannot look up the latest claim at ${checked.d}`))
  if (typeof prior?.found !== 'boolean' || (prior.found && (prior.pubkey !== me || prior.d !== checked.d || !/^[0-9a-f]{64}$/.test(String(prior.id)) ||
      !Number.isSafeInteger(prior.created_at)))) die('the memory store answered a lookup for another key or fact key; held for retry')
  if (request.op === 'withdraw') {
    if (!prior.found) die(`memory refused: no claim by this identity at ${checked.d} to withdraw`)
    if (prior.status === 'withdrawn') die(`memory refused: the claim at ${checked.d} is already withdrawn`)
  }
  // Counted before anything exists to sign, so a crash after signing can never buy an extra write.
  let verdict
  try { verdict = countInWindow(resolve(manifest.stateDir, 'agent-limits', 'memory.json'), { key: 'memory', id: requestId, limit: manifest.mayRemember.perHour }) }
  catch (e) { die(`cannot read the memory counter: ${e.message}`) }
  if (!verdict.allowed) die(`memory refused: over the hourly cap (${verdict.count}/${manifest.mayRemember.perHour} in the last hour)`)
  let built
  try { built = memoryTemplates(manifest, request, prior.found ? { created_at: prior.created_at } : null) } catch (e) { die(`memory refused: ${e.message}`) }
  const bad = unsignedOk(built.event)
  if (bad) die(`memory refused: ${bad}`)
  record = { version: 1, request_id: requestId, request_digest: digest, op: request.op, fingerprint: getEventHash(built.event), unsigned_event: built.event,
    event: null, expected_prior_id: prior.found ? prior.id : null, published: false }
  persist()
}

if (!record.event) {
  let ev
  try { ev = await signer.signEvent(record.unsigned_event) } catch (e) { die(`signer refused the memory event: ${e.message}`) }
  if (!signedOk(ev, record.fingerprint)) die('signer changed or invalidly signed the frozen memory event')
  record.event = ev
  persist()
}
if (!validateMemoryEvent(record.event, { allowedKinds: [REMEMBER_KIND] }).ok) die('memory refused: the signed event does not validate')
let out
try { out = await callStore('memory_submit', { event: record.event, expected_prior_id: record.expected_prior_id }) } catch (e) {
  die(`the memory store did not take the persisted event: ${e.message}; held for retry`)
}
const scrub = extra => {
  record = { version: 1, request_id: requestId, request_digest: digest, op: request.op, fingerprint: record.fingerprint, ...extra }
  persist()
  unlinkSpool()
}
if (out?.accepted !== true || out.id !== record.fingerprint) {
  if (out?.accepted === true) die('the memory store accepted a different event; held for retry')
  if (TERMINAL.has(out?.code)) scrub({ published: false, refused: out.code, refused_at: Date.now() })
  die(refusedOrHeld(out || {}, 'the memory store held the persisted event'))
}
scrub({ published: true, published_at: Date.now() })
// The audit line: which event, where. Never the words.
console.log(`instance-broker-memory: ${request.op === 'claim' ? 'claimed' : 'withdrew'} ${record.fingerprint.slice(0, 12)}… in ${request.scope}${out.replay ? ' (replay)' : ''}`)
exit(0)
