#!/usr/bin/env node
// instance-broker-reply.mjs — the only outbound mouth for a keyless worker.
//
// A worker may request a reply, never a signature.  The broker accepts it only when the
// request is bound to one of its own recorded admissions: envelope + exact permitted sender.
// The credential stays here, the exact signed wrap is persisted before publication, and a
// retry therefore republishes the same event instead of authoring a second message.

import { readFileSync, writeFileSync, existsSync, lstatSync, mkdirSync, renameSync } from 'node:fs'
import { resolve } from 'node:path'
import { replyRequestDigest, validateOutboundRecord } from './outbound_record.mjs'
import { spawnSync } from 'node:child_process'
import WebSocket from 'ws'
import { getPublicKey, getEventHash, finalizeEvent, generateSecretKey, verifyEvent } from 'nostr-tools/pure'
import { decode } from 'nostr-tools/nip19'
import * as nip44 from 'nostr-tools/nip44'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { makeBunkerSigner } from './nip46-signer.mjs'
import { verifyOutboundApproval } from './outbound_approval.mjs'

const die = m => { console.error(`instance-broker-reply: ${m}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), requestId = flag('--request').toLowerCase(), source = flag('--source') || 'worker', approvalPath = flag('--approval')
const prepareOnly = process.argv.includes('--prepare')
// AD-12 distinguishes two actuators. A public event is permanent and world-readable, so it is
// enacted only by a discrete signed approval. A private channel-carry reply is a sealed answer into
// a channel the owner already admitted this identity to, enacted by the live admit/task/task-relay
// chain that is rechecked below. `--direct` is that second path, and the check that it IS that path
// lives here rather than in the caller — a mistaken daemon must not be able to talk the signer into
// enacting a public event without approval.
const direct = process.argv.includes('--direct')
if (!id || !/^[0-9a-f]{32}$/.test(requestId) || !['worker', 'desktop'].includes(source) ||
    [prepareOnly, !!approvalPath, direct].filter(Boolean).length !== 1) {
  die('usage: --instance <id> --request <32-hex-id> [--source worker|desktop] (--prepare | --direct | --approval <signed-event.json>)')
}
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }
if (manifest.brokerMode !== 'local') die('remote-broker Desktop manifests cannot sign locally')

function regular(path, label) {
  let st; try { st = lstatSync(path) } catch { die(`${label} is missing`) }
  if (!st.isFile() || st.isSymbolicLink()) die(`${label} must be a regular non-symlink file`)
}
const queue = resolve(manifest.runtimeDir, source === 'desktop' ? 'desktop-reply-requests.jsonl' : 'reply-requests.jsonl')
regular(queue, 'reply request queue')
let request
try {
  for (const line of readFileSync(queue, 'utf8').split('\n')) {
    try { const x = JSON.parse(line); if (x.id === requestId) { request = x; break } } catch { /* append may be mid-line */ }
  }
} catch (e) { die(`cannot read reply request queue: ${e.message}`) }
if (!request || typeof request !== 'object') die('reply request is not present in this instance queue')
const allowedKeys = ['version', 'type', 'id', 'instance', 'receipt', 'content']
if (Object.keys(request).some(k => !allowedKeys.includes(k)) || request.type !== 'reply-request' || request.instance !== manifest.id ||
  request.version !== 1 || !/^[0-9a-f]{64}$/.test(String(request.receipt || '')) ||
  typeof request.content !== 'string' || !request.content.trim() || Buffer.byteLength(request.content, 'utf8') > 4000) die('reply request has an invalid or overbroad shape')
request.receipt = request.receipt.toLowerCase()

const receiptBase = resolve(manifest.stateDir, 'receipts', `${request.receipt}.json`)
const receiptInflight = resolve(manifest.stateDir, 'receipts', `${request.receipt}.${requestId}.inflight`)
const receiptUsed = resolve(manifest.stateDir, 'receipts', `${request.receipt}.${requestId}.used`)
if (existsSync(receiptUsed)) { console.log(JSON.stringify({ request: requestId, receipt: request.receipt, replay: true })); process.exit(0) }
let receiptPath = existsSync(receiptInflight) ? receiptInflight : receiptBase
regular(receiptPath, 'admission receipt')
let receipt; try { receipt = JSON.parse(readFileSync(receiptPath, 'utf8')) } catch { die('admission receipt is invalid') }
// The receipt establishes WHICH envelope, sender and grant are being answered, and the one-use
// rename below stops it being replayed. What it must not do is decide whether the answer is
// still authorised — the present-tense policy re-check further down does that, re-deriving the
// whole chain from live relays and requiring every field here to match it.
//
// It used to also carry a five-minute deadline started at ADMISSION. But admission and delivery
// are deliberately decoupled: a wake exists precisely so a session can read an envelope later.
// That clock therefore ran almost entirely before the agent could act, and any wake not answered
// inside it became permanently unanswerable — still queued, grant chain still live, readable in
// full, and impossible to reply to. Three replies died that way in one evening (#150).
//
// The deadline is no longer a gate. Nothing is loosened: authorisation was never coming from it.
if (![1, 2].includes(receipt.version) || receipt.instance !== manifest.id || receipt.broker !== manifest.pubkey || receipt.envelope !== request.receipt ||
  !/^[0-9a-f]{64}$/.test(String(receipt.sender || '')) || !Number.isFinite(receipt.expires_at)) {
  die('admission receipt is not a live broker-bound sender capability')
}
const channelCarry = receipt.version === 2 && receipt.mode === 'channel-carry'
if (receipt.version === 2 && (!channelCarry || !/^[0-9a-f]{64}$/.test(String(receipt.carrier || '')) ||
  !/^[0-9a-f]{64}$/.test(String(receipt.carrier_grant_id || '')) ||
  !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(String(receipt.reply_channel || '')) ||
  !manifest.carriers.some(entry => entry.pubkey === receipt.carrier && entry.channels.includes(receipt.reply_channel)))) {
  die('channel-carry receipt is not bound to an allowed carrier and channel')
}
const credential = process.env.NVOY_BROKER_CREDENTIAL
if (!credential || !existsSync(credential)) die('broker credential file is unavailable')
let raw; try { raw = readFileSync(credential, 'utf8').trim() } catch { die('cannot read broker credential') }
if (!/^nsec1[023456789acdefghjklmnpqrstuvwxyz]+$/.test(raw) && !/^[0-9a-f]{64}$/i.test(raw)) die('broker credential is not an nsec or hex key')
let signer
let bunkerUri = process.env.NVOY_BUNKER_URI || ''
if (!bunkerUri && process.env.NVOY_BUNKER_URI_FILE) { try { bunkerUri = readFileSync(process.env.NVOY_BUNKER_URI_FILE, 'utf8').trim() } catch { die('cannot read Bunker URI credential') } }
if (bunkerUri) {
  signer = makeBunkerSigner(bunkerUri, raw)
} else {
  const sk = raw.startsWith('nsec1') ? decode(raw).data : Uint8Array.from(Buffer.from(raw, 'hex'))
  signer = { getPublicKey: async () => getPublicKey(sk), signEvent: async event => finalizeEvent(event, sk),
    nip44Encrypt: async (peer, text) => nip44.encrypt(text, nip44.getConversationKey(sk, peer)) }
}
if (await signer.getPublicKey() !== manifest.pubkey) die('signer does not match manifest pubkey')

// A receipt is only a short-lived capability, never a substitute for present-tense policy.
// Re-open the exact envelope through the same signer and require the recorded grant to remain
// live before consuming the one-use receipt or authoring a seal.
const attention = resolve(new URL('.', import.meta.url).pathname, 'attention.mjs')
const checkEnv = { HOME: manifest.stateDir, PATH: process.env.PATH || '', NVOY_RELAYS: manifest.relays.join(','),
  GRANTORS: manifest.grantors.join(','), NVOY_TASK_CARRIERS: JSON.stringify(manifest.carriers) }
if (bunkerUri) { checkEnv.NVOY_BUNKER_URI = bunkerUri; checkEnv.NVOY_NIP46_CLIENT_NSEC = raw } else checkEnv.NVOY_NSEC = raw
const checked = spawnSync(process.execPath, [attention, '--json', '--envelope', receipt.envelope], { env: checkEnv, encoding: 'utf8', timeout: 60000 })
if (![0, 10].includes(checked.status)) die('could not recheck live grant policy')
let policy; try { policy = JSON.parse(checked.stdout) } catch { die('live grant policy result is invalid') }
const current = Array.isArray(policy.admissions) ? policy.admissions : []
const liveAdmission = current.length === 1 ? current[0] : null
if (!policy.policyUsable || !liveAdmission || liveAdmission.from !== receipt.sender || liveAdmission.grant_id !== receipt.grant_id ||
  (channelCarry && (liveAdmission.mode !== 'channel-carry' || liveAdmission.carrier !== receipt.carrier ||
    liveAdmission.carrier_grant_id !== receipt.carrier_grant_id || liveAdmission.reply_channel !== receipt.reply_channel ||
    liveAdmission.source_event !== receipt.source_event))) die('admission receipt no longer has a live matching grant chain')
// The chain was just re-derived from live relays, so record when that happened and move the
// window forward. `expires_at` is now an audit trail of the last live validation rather than a
// gate — a stale value on disk would misreport how fresh this authorisation actually is.
receipt.revalidated_at = Date.now()
receipt.expires_at = receipt.revalidated_at + 5 * 60 * 1000
try { writeFileSync(receiptPath, JSON.stringify(receipt), { mode: 0o600 }) }
catch (e) { die(`cannot record receipt revalidation: ${e.message}`) }
if (receiptPath === receiptBase) {
  try { renameSync(receiptBase, receiptInflight); receiptPath = receiptInflight }
  catch (e) { die(`cannot atomically claim one-use admission receipt: ${e.message}`) }
}

const outboundDir = resolve(manifest.stateDir, 'outbound')
mkdirSync(outboundDir, { recursive: true, mode: 0o700 })
const recordPath = resolve(outboundDir, `${requestId}.json`)
const digest = replyRequestDigest(request)
let record
if (existsSync(recordPath)) {
  regular(recordPath, 'outbound record')
  try { record = JSON.parse(readFileSync(recordPath, 'utf8')) } catch { die('outbound record is invalid') }
  try { validateOutboundRecord(record, { requestId, requestDigest: digest }) } catch (e) { die(e.message) }
  if (record.version !== 2) die('legacy signed reply record has no discrete approval and cannot be resumed')
  if (record.published === true) {
    try { renameSync(receiptInflight, receiptUsed) } catch (e) { die(`could not finalize one-use receipt: ${e.message}`) }
    console.log(JSON.stringify({ request: requestId, receipt: request.receipt, accepted: record.accepted || 0, replay: true }))
    process.exit(0)
  }
} else {
  const now = Math.floor(Date.now() / 1000)
  const peer = channelCarry ? receipt.carrier : receipt.sender
  const rumor = { kind: 14, pubkey: manifest.pubkey, created_at: now,
    tags: [['p', peer], ['e', channelCarry ? receipt.source_event : receipt.envelope, '', 'reply'],
      ...(channelCarry ? [['relay', receipt.reply_channel]] : [])], content: request.content }
  rumor.id = getEventHash(rumor)
  const backdated = () => Math.floor(Date.now() / 1000 - Math.random() * 2 * 24 * 60 * 60)
  const unsignedSeal = { kind: 13, pubkey: manifest.pubkey, created_at: backdated(), tags: [],
    content: await signer.nip44Encrypt(peer, JSON.stringify(rumor)) }
  record = { version: 2, request_digest: digest, request_id: requestId,
    fingerprint: getEventHash(unsignedSeal), unsigned_seal: unsignedSeal, wrap: null, published: false }
  const tmp = `${recordPath}.${process.pid}.tmp`
  try { writeFileSync(tmp, JSON.stringify(record), { mode: 0o600 }); renameSync(tmp, recordPath) } catch (e) { die(`cannot persist outbound record: ${e.message}`) }
}

// Which actuator applies is a property of the receipt, decided here so the daemon never infers it.
// `channelCarry` was already validated above against an allowed carrier and an allowed channel.
const action = channelCarry ? 'nostr-private-reply' : 'nostr-public-event'
if (prepareOnly) {
  console.log(JSON.stringify({ request: requestId, receipt: request.receipt, action,
    status: channelCarry ? 'enactable' : 'awaiting-approval',
    approval_required: !channelCarry, fingerprint: record.fingerprint }))
  process.exit(0)
}
let approval = null
if (direct) {
  // The whole argument for this path: waggle carries across the boundary, and the identity is
  // already an admitted member of the destination channel. The admit/task/task-relay chain checked
  // live above IS the authorisation to post — there is no second thing for a human to approve.
  // It stays confined to that case: a public event is permanent and world-readable, so it keeps
  // its discrete approval.
  if (!channelCarry) die('direct enactment is permitted only for a private channel-carry reply; a public event requires a discrete approval')
  if (record.approval_id) die('this proposal is already bound to an approval and cannot be enacted directly')
} else {
  regular(approvalPath, 'approval event')
  let approvalEvent
  try { approvalEvent = JSON.parse(readFileSync(approvalPath, 'utf8')) } catch { die('approval event is invalid JSON') }
  try {
    approval = verifyOutboundApproval(approvalEvent, { instance: manifest.id, proposalId: requestId,
      fingerprint: record.fingerprint, approvers: manifest.grantors,
      ...(record.approval_id ? { maxAgeMs: Number.MAX_SAFE_INTEGER } : {}) })
  } catch (e) { die(e.message) }
  if (record.approval_id && record.approval_id !== approval.eventId) die('outbound proposal is already bound to another approval')
}
if (!record.wrap) {
  const seal = await signer.signEvent(record.unsigned_seal)
  if (seal.id !== record.fingerprint || getEventHash(seal) !== record.fingerprint || !verifyEvent(JSON.parse(JSON.stringify(seal)))) die('signer changed or invalidly signed the frozen seal')
  const peer = channelCarry ? receipt.carrier : receipt.sender
  const wrapSk = generateSecretKey()
  const backdated = () => Math.floor(Date.now() / 1000 - Math.random() * 2 * 24 * 60 * 60)
  record.wrap = finalizeEvent({ kind: 1059, created_at: backdated(), tags: [['p', peer]],
    content: nip44.encrypt(JSON.stringify(seal), nip44.getConversationKey(wrapSk, peer)) }, wrapSk)
  // Record which actuator opened the signer, so an audit of this file can tell a legitimate direct
  // private reply from a record that lost its approval. validateOutboundRecord enforces exactly one.
  if (direct) record.enactment = 'channel-carry-direct'
  else record.approval_id = approval.eventId
  const tmp = `${recordPath}.${process.pid}.approved.tmp`
  try { writeFileSync(tmp, JSON.stringify(record), { mode: 0o600 }); renameSync(tmp, recordPath) } catch (e) { die(`cannot persist approved outbound record: ${e.message}`) }
}

async function publish(url) {
  return await new Promise(resolvePublish => {
    let done = false
    const ws = new WebSocket(url)
    const finish = ok => { if (done) return; done = true; clearTimeout(timer); try { ws.close() } catch {}; resolvePublish(ok) }
    const timer = setTimeout(() => finish(false), 9000)
    ws.on('open', () => ws.send(JSON.stringify(['EVENT', record.wrap])))
    ws.on('message', rawMessage => { try { const m = JSON.parse(rawMessage.toString()); if (m[0] === 'OK' && m[1] === record.wrap.id) finish(!!m[2]) } catch {} })
    ws.on('error', () => finish(false))
  })
}
let accepted = 0
for (const relay of manifest.relays) if (await publish(relay)) accepted++
if (!accepted) die('no relay accepted the persisted outbound wrap; it remains retryable')
record.published = true; record.published_at = Date.now(); record.accepted = accepted
try { writeFileSync(recordPath, JSON.stringify(record), { mode: 0o600 }) } catch (e) { die(`published but could not finalize record: ${e.message}`) }
try { renameSync(receiptInflight, receiptUsed) } catch (e) { die(`published but could not finalize one-use receipt: ${e.message}`) }
console.log(JSON.stringify({ request: requestId, receipt: request.receipt, accepted }))
