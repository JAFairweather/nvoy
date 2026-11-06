#!/usr/bin/env node
// instance-broker-memory.mjs — the keyed actuator for memory_claim and memory_withdraw.
//
// A memory write answers nothing, so its authority is the owner's standing opt-in: the manifest's
// may_remember block, which names the rooms and how many writes an hour. Everything the keyless
// queue says is re-checked here; the event is built from its fields by memory.mjs, never taken
// from it. Only room:<uuid> scopes and only kind 30078, which the Bunker pairing already allows.
//
// The relay is asked first for this identity's latest event at the fact key, so a replacement is
// strictly later than what it replaces; a request that cannot ask is held rather than guessed.
// Then the post discipline: the cap is counted before the event exists, the exact event is frozen
// before it is signed, and a retry republishes that event.

import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { getEventHash, verifyEvent } from 'nostr-tools/pure'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { brokerSigner } from './broker_signer.mjs'
import { openBuzzSession } from './buzz_native.mjs'
import { replyRequestDigest } from './outbound_record.mjs'
import { countInWindow } from './agent_limits.mjs'
import { MEMORY_NOT_PERMITTED, REMEMBER_KIND, memoryQueuePath, memorySecretIn, memoryTemplates, validateMemoryRequest } from './agent_memory.mjs'
import { nip01Newer, validateMemoryEvent } from './memory.mjs'
import { withheldMessage } from './outbound_secrets.mjs'

let signer, session
const exit = code => { try { session?.close() } catch { /* best effort */ } try { signer?.close?.() } catch { /* best effort */ } process.exit(code) }
const die = m => { console.error(`instance-broker-memory: ${m}`); exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), requestId = flag('--request').toLowerCase()
if (!id || !/^[0-9a-f]{32}$/.test(requestId)) die('usage: --instance <id> --request <32-hex-id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }
if (manifest.brokerMode !== 'local') die('remote-broker Desktop manifests cannot sign locally')
if (!manifest.mayRemember) die(`memory refused: ${MEMORY_NOT_PERMITTED}`)

const queue = memoryQueuePath(manifest)
let request
try {
  const st = lstatSync(queue)
  if (!st.isFile() || st.isSymbolicLink()) die('memory request queue must be a regular non-symlink file')
  for (const line of readFileSync(queue, 'utf8').split('\n')) {
    try { const x = JSON.parse(line); if (x?.id === requestId) { request = x; break } } catch { /* append may be mid-line */ }
  }
} catch (e) { die(`cannot read memory request queue: ${e.message}`) }
if (!request) die('memory request is not present in this instance queue')
let checked
try { checked = validateMemoryRequest(request, manifest) } catch (e) { die(e.message) }
// Again here, where the signer is: a client that writes the queue without the tool skips the tool's check.
const leaked = memorySecretIn(request.fields)
if (leaked) die(`memory refused: ${withheldMessage(leaked)} instance ${manifest.id}`)
const digest = replyRequestDigest(request)
const tagOf = (ev, name) => ev?.tags?.find(t => t[0] === name)?.[1]
// What any event built for this request must be: kind 30078, this key, this room and fact key.
const unsignedOk = ev => {
  const v = validateMemoryEvent(ev, { allowedKinds: [REMEMBER_KIND], verifySignature: false })
  return v.ok && ev.kind === REMEMBER_KIND && v.pubkey === manifest.pubkey && v.scopeType === 'room' && v.roomId === checked.roomId && v.d === checked.d &&
    v.status === (request.op === 'claim' ? 'active' : 'withdrawn') ? null : v.reason || 'built event does not bind this request'
}

const memoryDir = resolve(manifest.stateDir, 'memory')
mkdirSync(memoryDir, { recursive: true, mode: 0o700 })
const recordPath = resolve(memoryDir, `${requestId}.json`)
const persist = () => {
  const tmp = `${recordPath}.${process.pid}.tmp`
  try { writeFileSync(tmp, JSON.stringify(record), { mode: 0o600 }); renameSync(tmp, recordPath) } catch (e) { die(`cannot persist memory record: ${e.message}`) }
}
const signedOk = (ev, fingerprint) => ev && ev.id === fingerprint && getEventHash(ev) === fingerprint && verifyEvent(JSON.parse(JSON.stringify(ev)))
let record
if (existsSync(recordPath)) {
  const st = lstatSync(recordPath)
  if (!st.isFile() || st.isSymbolicLink()) die('memory record must be a regular non-symlink file')
  try { record = JSON.parse(readFileSync(recordPath, 'utf8')) } catch { die('memory record is invalid') }
  const ev = record?.unsigned_event
  if (record?.version !== 1 || record.request_id !== requestId || record.request_digest !== digest || !ev || getEventHash(ev) !== record.fingerprint || unsignedOk(ev) ||
      (record.event && !signedOk(record.event, record.fingerprint))) die('memory record does not bind this request')
  if (record.published === true) { console.log(JSON.stringify({ request: requestId, accepted: record.accepted, replay: true })); exit(0) }
}

if (!signer) ({ signer } = brokerSigner(die, { idleMs: 30000 }))
let me
try { me = String(await signer.getPublicKey()).toLowerCase() } catch (e) { die(`signer unavailable: ${e.message}`) }
if (me !== manifest.pubkey) die('signer does not match manifest pubkey')
try { session = await openBuzzSession({ relay: manifest.buzz.relay, signer }) } catch (e) { die(`Buzz relay unavailable: ${e.message}; held for retry`) }

if (!record) {
  let prior = null
  try {
    const found = await session.fetch({ kinds: [REMEMBER_KIND], authors: [me], '#d': [checked.d], limit: 1 })
    for (const ev of found) {
      if (ev?.kind === REMEMBER_KIND && ev.pubkey === me && tagOf(ev, 'd') === checked.d && verifyEvent(ev) && nip01Newer(ev, prior)) prior = ev
    }
  } catch (e) {
    die(request.op === 'withdraw' ? `cannot look up the claim to withdraw: ${e.message}; held for retry`
      : `cannot look up the latest claim at ${checked.d}: ${e.message}; held for retry`)
  }
  if (request.op === 'withdraw') {
    if (!prior) die(`memory refused: no claim by this identity at ${checked.d} to withdraw`)
    if (validateMemoryEvent(prior, { verifySignature: false }).status === 'withdrawn') die(`memory refused: the claim at ${checked.d} is already withdrawn`)
  }
  // Counted before anything exists to sign, so a crash after signing can never buy an extra write.
  let verdict
  try { verdict = countInWindow(resolve(manifest.stateDir, 'agent-limits', 'memory.json'), { key: 'memory', id: requestId, limit: manifest.mayRemember.perHour }) }
  catch (e) { die(`cannot read the memory counter: ${e.message}`) }
  if (!verdict.allowed) die(`memory refused: over the hourly cap (${verdict.count}/${manifest.mayRemember.perHour} in the last hour)`)
  let built
  try { built = memoryTemplates(manifest, request, prior) } catch (e) { die(`memory refused: ${e.message}`) }
  const bad = unsignedOk(built.event)
  if (bad) die(`memory refused: ${bad}`)
  record = { version: 1, request_id: requestId, request_digest: digest, op: request.op, fingerprint: getEventHash(built.event), unsigned_event: built.event, event: null, published: false }
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
let accepted = 0
try { const r = await session.publishSigned(record.event); if (r.accepted) accepted = 1; else console.error(`instance-broker-memory: Buzz refused the memory event: ${r.message}`) }
catch (e) { console.error(`instance-broker-memory: Buzz relay unavailable: ${e.message}`) }
if (!accepted) die('the Buzz relay did not accept the persisted memory event; it remains retryable')
record.published = true; record.published_at = Date.now(); record.accepted = accepted
persist()
// The audit line: which event, where. Never the words.
console.log(`instance-broker-memory: ${request.op === 'claim' ? 'claimed' : 'withdrew'} ${record.fingerprint.slice(0, 12)}… in ${request.scope}`)
exit(0)
