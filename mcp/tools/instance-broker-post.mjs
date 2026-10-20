#!/usr/bin/env node
// instance-broker-post.mjs — the keyed actuator for nvoy_channel_post.
//
// A reply is authorised by the live grant chain of the message it answers. A post answers nothing,
// so its authority is the owner's standing opt-in instead: the manifest's may_post block, which
// names the channels, the people the post may p-tag, and how many posts an hour. Everything the
// keyless queue says is re-checked here against that block.
//
// Same discipline as a native reply: the cap is counted before the event exists, the exact kind:9
// is frozen before the signer opens, and a retry republishes that event instead of a second one.
// It is still a kind:9 in a channel the identity already speaks in, so the Bunker pairing needs no
// new permission.

import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { getEventHash, verifyEvent } from 'nostr-tools/pure'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { brokerSigner } from './broker_signer.mjs'
import { channelPost, openBuzzSession } from './buzz_native.mjs'
import { replyRequestDigest } from './outbound_record.mjs'
import { countInWindow } from './agent_limits.mjs'
import { POST_ONLY_REPLY, postQueuePath, validatePostRequest } from './agent_post.mjs'

let signer
const exit = code => { try { signer?.close?.() } catch { /* best effort */ } process.exit(code) }
const die = m => { console.error(`instance-broker-post: ${m}`); exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), requestId = flag('--request').toLowerCase()
if (!id || !/^[0-9a-f]{32}$/.test(requestId)) die('usage: --instance <id> --request <32-hex-id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }
if (manifest.brokerMode !== 'local') die('remote-broker Desktop manifests cannot sign locally')
if (!manifest.mayPost) die(`post refused: ${POST_ONLY_REPLY}`)

const queue = postQueuePath(manifest)
let request
try {
  const st = lstatSync(queue)
  if (!st.isFile() || st.isSymbolicLink()) die('post request queue must be a regular non-symlink file')
  for (const line of readFileSync(queue, 'utf8').split('\n')) {
    try { const x = JSON.parse(line); if (x?.id === requestId) { request = x; break } } catch { /* append may be mid-line */ }
  }
} catch (e) { die(`cannot read post request queue: ${e.message}`) }
if (!request) die('post request is not present in this instance queue')
try { validatePostRequest(request, manifest) } catch (e) { die(e.message) }
const digest = replyRequestDigest(request)

const postsDir = resolve(manifest.stateDir, 'posts')
mkdirSync(postsDir, { recursive: true, mode: 0o700 })
const recordPath = resolve(postsDir, `${requestId}.json`)
const persist = () => {
  const tmp = `${recordPath}.${process.pid}.tmp`
  try { writeFileSync(tmp, JSON.stringify(record), { mode: 0o600 }); renameSync(tmp, recordPath) } catch (e) { die(`cannot persist post record: ${e.message}`) }
}
let record
if (existsSync(recordPath)) {
  const st = lstatSync(recordPath)
  if (!st.isFile() || st.isSymbolicLink()) die('post record must be a regular non-symlink file')
  try { record = JSON.parse(readFileSync(recordPath, 'utf8')) } catch { die('post record is invalid') }
  const ev = record?.unsigned_event
  if (record?.version !== 1 || record.request_id !== requestId || record.request_digest !== digest || !ev || getEventHash(ev) !== record.fingerprint ||
      (record.event && (record.event.id !== record.fingerprint || !verifyEvent(JSON.parse(JSON.stringify(record.event)))))) die('post record does not bind this request')
  if (record.published === true) { console.log(JSON.stringify({ request: requestId, accepted: record.accepted, replay: true })); exit(0) }
} else {
  // Counted before anything exists to sign, so a crash after signing can never buy an extra post.
  let verdict
  try { verdict = countInWindow(resolve(manifest.stateDir, 'agent-limits', 'posts.json'), { key: 'post', id: requestId, limit: manifest.mayPost.perHour }) }
  catch (e) { die(`cannot read the post counter: ${e.message}`) }
  if (!verdict.allowed) die(`post refused: over the hourly cap (${verdict.count}/${manifest.mayPost.perHour} in the last hour)`)
  const unsignedEvent = { pubkey: manifest.pubkey, ...channelPost({ channel: request.channel, content: request.content, mentions: request.mention }) }
  record = { version: 1, request_id: requestId, request_digest: digest, fingerprint: getEventHash(unsignedEvent),
    unsigned_event: unsignedEvent, event: null, published: false }
  persist()
}

;({ signer } = brokerSigner(die, { idleMs: 30000 }))
let me
try { me = String(await signer.getPublicKey()).toLowerCase() } catch (e) { die(`signer unavailable: ${e.message}`) }
if (me !== manifest.pubkey) die('signer does not match manifest pubkey')
if (!record.event) {
  let ev
  try { ev = await signer.signEvent(record.unsigned_event) } catch (e) { die(`signer refused the post: ${e.message}`) }
  if (ev?.id !== record.fingerprint || getEventHash(ev) !== record.fingerprint || !verifyEvent(JSON.parse(JSON.stringify(ev)))) die('signer changed or invalidly signed the frozen post')
  record.event = ev
  persist()
}
let accepted = 0
try {
  const session = await openBuzzSession({ relay: manifest.buzz.relay, signer })
  try { const r = await session.publishSigned(record.event); if (r.accepted) accepted = 1; else console.error(`instance-broker-post: Buzz refused the post: ${r.message}`) }
  finally { session.close() }
} catch (e) { console.error(`instance-broker-post: Buzz relay unavailable: ${e.message}`) }
if (!accepted) die('the Buzz relay did not accept the persisted post; it remains retryable')
record.published = true; record.published_at = Date.now(); record.accepted = accepted
persist()
// The audit line: which event, where. Never the words.
console.log(`instance-broker-post: posted ${record.fingerprint.slice(0, 12)}… in ${request.channel} (${request.mention.length} mention(s))`)
exit(0)
