#!/usr/bin/env node
// instance-broker-reply.mjs — the only outbound mouth for a keyless worker.
//
// A worker may request a reply, never a signature.  The broker accepts it only when the
// request is bound to one of its own recorded admissions: envelope + exact permitted sender.
// The credential stays here, the exact signed wrap is persisted before publication, and a
// retry therefore republishes the same event instead of authoring a second message.

import { readFileSync, writeFileSync, existsSync, lstatSync, mkdirSync, renameSync } from 'node:fs'
import { resolve } from 'node:path'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import WebSocket from 'ws'
import { getPublicKey, getEventHash, finalizeEvent, generateSecretKey } from 'nostr-tools/pure'
import { decode } from 'nostr-tools/nip19'
import * as nip44 from 'nostr-tools/nip44'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { makeBunkerSigner } from './nip46-signer.mjs'

const die = m => { console.error(`instance-broker-reply: ${m}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), requestId = flag('--request').toLowerCase(), source = flag('--source') || 'worker'
if (!id || !/^[0-9a-f]{32}$/.test(requestId) || !['worker', 'desktop'].includes(source)) die('usage: --instance <id> --request <32-hex-id> [--source worker|desktop]')
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
if (![1, 2].includes(receipt.version) || receipt.instance !== manifest.id || receipt.broker !== manifest.pubkey || receipt.envelope !== request.receipt ||
  !/^[0-9a-f]{64}$/.test(String(receipt.sender || '')) || !Number.isFinite(receipt.expires_at) || Date.now() > receipt.expires_at) {
  die('admission receipt is not a live broker-bound sender capability')
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
  GRANTORS: manifest.grantors.join(','), RELAY_ATTESTORS: manifest.relayAttestors.join(',') }
if (bunkerUri) { checkEnv.NVOY_BUNKER_URI = bunkerUri; checkEnv.NVOY_NIP46_CLIENT_NSEC = raw } else checkEnv.NVOY_NSEC = raw
const checked = spawnSync(process.execPath, [attention, '--json', '--envelope', receipt.envelope], { env: checkEnv, encoding: 'utf8', timeout: 60000 })
if (![0, 10].includes(checked.status)) die('could not recheck live grant policy')
let policy; try { policy = JSON.parse(checked.stdout) } catch { die('live grant policy result is invalid') }
const current = Array.isArray(policy.admissions) ? policy.admissions : []
const principal = receipt.version === 2 ? receipt.principal : receipt.sender
if (!policy.policyUsable || current.length !== 1 || current[0].from !== principal ||
    String(current[0].reply_to || current[0].from) !== receipt.sender || current[0].grant_id !== receipt.grant_id) die('admission receipt no longer has a live matching grant')
if (receiptPath === receiptBase) {
  try { renameSync(receiptBase, receiptInflight); receiptPath = receiptInflight }
  catch (e) { die(`cannot atomically claim one-use admission receipt: ${e.message}`) }
}

const outboundDir = resolve(manifest.stateDir, 'outbound')
mkdirSync(outboundDir, { recursive: true, mode: 0o700 })
const recordPath = resolve(outboundDir, `${requestId}.json`)
const digest = createHash('sha256').update(JSON.stringify(request)).digest('hex')
let record
if (existsSync(recordPath)) {
  regular(recordPath, 'outbound record')
  try { record = JSON.parse(readFileSync(recordPath, 'utf8')) } catch { die('outbound record is invalid') }
  if (record.request_digest !== digest || !record.wrap || record.wrap.kind !== 1059) die('outbound record does not bind this request')
  if (record.published === true) {
    try { renameSync(receiptInflight, receiptUsed) } catch (e) { die(`could not finalize one-use receipt: ${e.message}`) }
    console.log(JSON.stringify({ request: requestId, receipt: request.receipt, accepted: record.accepted || 0, replay: true }))
    process.exit(0)
  }
} else {
  const now = Math.floor(Date.now() / 1000)
  const tags = [['p', receipt.sender], ['e', receipt.envelope, '', 'reply']]
  if (receipt.version === 2 && receipt.relay_channel) tags.push(['relay', receipt.relay_channel])
  const rumor = { kind: 14, pubkey: manifest.pubkey, created_at: now, tags, content: request.content }
  rumor.id = getEventHash(rumor)
  const backdated = () => Math.floor(Date.now() / 1000 - Math.random() * 2 * 24 * 60 * 60)
  const seal = await signer.signEvent({ kind: 13, created_at: backdated(), tags: [],
    content: await signer.nip44Encrypt(receipt.sender, JSON.stringify(rumor)) })
  const wrapSk = generateSecretKey()
  const wrap = finalizeEvent({ kind: 1059, created_at: backdated(), tags: [['p', receipt.sender]],
    content: nip44.encrypt(JSON.stringify(seal), nip44.getConversationKey(wrapSk, receipt.sender)) }, wrapSk)
  record = { version: 1, request_digest: digest, request_id: requestId, wrap, published: false }
  const tmp = `${recordPath}.${process.pid}.tmp`
  try { writeFileSync(tmp, JSON.stringify(record), { mode: 0o600 }); renameSync(tmp, recordPath) } catch (e) { die(`cannot persist outbound record: ${e.message}`) }
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
