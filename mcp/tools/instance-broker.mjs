#!/usr/bin/env node
// instance-broker.mjs — the keyed half of an isolated participant runtime (#44).
//
// It is deliberately not an MCP tool. A supervisor starts one broker for one fixed instance;
// it receives opaque watcher markers, re-evaluates the live signed grant policy, decrypts only
// after that check, and pushes admitted plaintext to the fixed private adapter socket. The
// adapter has no key, key path, manifest path, or decryption command.

import { readFileSync, existsSync, lstatSync, renameSync, mkdirSync, openSync, writeFileSync, closeSync, unlinkSync } from 'node:fs'
import { resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import net from 'node:net'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { claimChannelSource, completeChannelSource } from './channel_source_dedup.mjs'

const die = message => { console.error(`instance-broker: ${message}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const command = process.argv[2]
const id = flag('--instance')
const envelope = flag('--envelope').toLowerCase()
if (command !== 'deliver' || !id || !/^[0-9a-f]{64}$/.test(envelope)) die('usage: deliver --instance <id> --envelope <64-hex-id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }
if (manifest.brokerMode !== 'local') die('remote-broker Desktop manifests cannot start a local broker')

// One broker owns one state root at a time. A stale lock is reclaimable only if its recorded PID
// is demonstrably gone; a malformed or foreign lock fails closed rather than guessing.
mkdirSync(manifest.stateDir, { recursive: true, mode: 0o700 })
const lockPath = resolve(manifest.stateDir, 'broker.lock')
function claimLock() {
  try {
    const fd = openSync(lockPath, 'wx', 0o600)
    writeFileSync(fd, JSON.stringify({ pid: process.pid, instance: manifest.id, started_at: Date.now() }))
    closeSync(fd)
    return
  } catch (e) {
    if (e.code !== 'EEXIST') die(`cannot claim broker lock: ${e.message}`)
  }
  let prior
  try {
    const st = lstatSync(lockPath)
    if (!st.isFile() || st.isSymbolicLink()) die('broker lock is not a regular file')
    prior = JSON.parse(readFileSync(lockPath, 'utf8'))
  } catch (e) { die(`cannot validate existing broker lock: ${e.message}`) }
  if (prior.instance !== manifest.id || !Number.isInteger(prior.pid) || prior.pid < 1) die('broker lock does not bind this instance')
  try { process.kill(prior.pid, 0); die(`broker already running as pid ${prior.pid}`) }
  catch (e) { if (e.code !== 'ESRCH') die(`cannot establish whether existing broker is alive: ${e.message}`) }
  try { unlinkSync(lockPath) } catch (e) { die(`cannot reclaim stale broker lock: ${e.message}`) }
  claimLock()
}
claimLock()
process.on('exit', () => { try { unlinkSync(lockPath) } catch {} })

// Atomically claim the one marker whose name is derived from the trusted manifest + opaque event
// id. No caller can redirect the broker to an arbitrary marker path.
const pendingMarker = resolve(manifest.spoolDir, `${envelope}.pending`)
const markerPath = resolve(manifest.spoolDir, `${envelope}.inflight`)
try { renameSync(pendingMarker, markerPath) } catch (e) { die(`cannot atomically claim pending marker: ${e.message}`) }
// A marker is only a wake hint. It must never carry plaintext, sender identity, grant id, or a
// command. The broker nevertheless requires one so no process can turn it into a broad inbox
// reader by simply scheduling `deliver` with no observed envelope.
let marker
try {
  const st = lstatSync(markerPath)
  if (!st.isFile() || st.isSymbolicLink()) die('marker must be a regular non-symlink file')
  marker = JSON.parse(readFileSync(markerPath, 'utf8'))
} catch (e) { die(`cannot read marker: ${e.message}`) }
if (String(marker.envelope || '').toLowerCase() !== envelope || !Number.isFinite(Number(marker.observed_at))) die('marker does not bind the claimed opaque envelope and observation time')
if (Object.keys(marker).some(k => !['envelope', 'observed_at'].includes(k))) die('marker carries fields beyond the opaque wake hint')

// Only the broker is given this environment variable by its service definition. It contains a
// *credential file*, never an nsec itself, and is stripped before any child other than attention.
const credential = process.env.NVOY_BROKER_CREDENTIAL
if (!credential || !existsSync(credential)) die('broker credential file is unavailable')
let nsec
try { nsec = readFileSync(credential, 'utf8').trim() } catch { die('cannot read broker credential') }
if (!/^nsec1[023456789acdefghjklmnpqrstuvwxyz]+$/.test(nsec) && !/^[0-9a-f]{64}$/i.test(nsec)) die('broker credential is not an nsec or hex key')

const attention = resolve(new URL('.', import.meta.url).pathname, 'attention.mjs')
const env = { HOME: manifest.stateDir, PATH: process.env.PATH || '', NVOY_RELAYS: manifest.relays.join(','),
  GRANTORS: manifest.grantors.join(','), NVOY_TASK_CARRIERS: JSON.stringify(manifest.carriers) }
// In production this file is the stable NIP-46 *transport* credential, never the participant
// identity nsec. The Bunker owns the identity and performs every decrypt/sign operation.
const bunkerUriPath = process.env.NVOY_BUNKER_URI_FILE || ''
if (bunkerUriPath) {
  let bunkerUri; try { bunkerUri = readFileSync(bunkerUriPath, 'utf8').trim() } catch { die('cannot read Bunker URI credential') }
  if (!/^bunker:\/\//i.test(bunkerUri)) die('Bunker URI credential is invalid')
  env.NVOY_BUNKER_URI = bunkerUri
  env.NVOY_NIP46_CLIENT_NSEC = nsec
} else env.NVOY_NSEC = nsec
const result = spawnSync(process.execPath, [attention, '--json', '--envelope', envelope], { env, encoding: 'utf8', timeout: 60000 })
// 10 is attention's intentional "actionable" signal. Any other nonzero status is failure
// closed: no plaintext leaves the broker.
if (![0, 10].includes(result.status)) die(`attention failed (${result.status ?? 'signal'}): ${String(result.stderr || '').trim()}`)
let report
try { report = JSON.parse(result.stdout) } catch { die('attention returned invalid JSON') }
if (report.me !== manifest.pubkey) die('credential does not match manifest pubkey')
// No relay answer is not a denial. Policy is deliberately default-closed, but the opaque marker
// must remain retryable so a transient relay outage cannot silently consume valid mail forever.
if (!report.policyUsable) {
  try { renameSync(markerPath, pendingMarker) } catch (e) { die(`policy unavailable and marker could not be requeued: ${e.message}`) }
  console.error('instance-broker: live grant policy unavailable; marker requeued')
  process.exit(75)
}
const notifications = Array.isArray(report.notifications) ? report.notifications : []
if ((!Array.isArray(report.actionable) || !report.actionable.length) && !notifications.length) {
  try { renameSync(markerPath, `${markerPath}.done`) } catch (e) { die(`cannot finalize terminal marker: ${e.message}`) }
  process.exit(0)
}

// A notification is mutually exclusive with an actionable delivery for one outer envelope. It
// carries only provenance; there is no source body, receipt, reply target, or authority object.
if (!report.actionable.length && notifications.length) {
  if (notifications.length !== 1) die('one envelope must not produce multiple notifications')
  const n = notifications[0]
  const packet = { type: 'verified-notification', instance: manifest.id, envelope,
    notification: { version: 1, type: 'verified-channel-activity', ...n } }
  const socket = resolve(manifest.runtimeDir, 'adapter.sock')
  const client = net.createConnection(socket)
  const timer = setTimeout(() => { client.destroy(); die('adapter acknowledgement timed out') }, 15000)
  client.on('error', e => { clearTimeout(timer); die(`adapter socket unavailable: ${e.message}`) })
  client.on('connect', () => client.write(JSON.stringify(packet) + '\n'))
  let received = ''
  client.on('data', chunk => {
    received += chunk
    if (!received.includes('\n')) return
    clearTimeout(timer)
    let ack; try { ack = JSON.parse(received.split('\n')[0]) } catch { die('adapter acknowledgement is malformed') }
    if (ack.type !== 'ack' || ack.instance !== manifest.id) die('adapter acknowledgement does not bind this instance')
    const marked = spawnSync(process.execPath, [attention, '--mark', '--json', '--envelope', envelope], { env, encoding: 'utf8', timeout: 60000 })
    if (marked.status !== 0) die(`attention watermark failed (${marked.status ?? 'signal'})`)
    try { renameSync(markerPath, `${markerPath}.done`) } catch (e) { die(`acknowledged but could not finalize marker: ${e.message}`) }
    client.end()
  })
  // Do not fall through and manufacture an instruction receipt for a notification.
  await new Promise((resolveDone, rejectDone) => {
    client.on('close', resolveDone)
    client.on('error', rejectDone)
  })
  process.exit(0)
}

// A reply may only be addressed to someone who was admitted for this exact envelope.  The
// keyless adapter never creates this receipt and cannot add a new reply target to it.
const receiptDir = resolve(manifest.stateDir, 'receipts')
const receiptPath = resolve(receiptDir, `${envelope}.json`)
const admissions = Array.isArray(report.admissions) ? report.admissions : []
if (report.actionable.length !== 1 || admissions.length !== 1) die('an outbound-capable delivery must bind exactly one admitted sender')
const admission = admissions[0]
if (!/^[0-9a-f]{64}$/.test(String(admission?.from || '')) || !/^[0-9a-f]{64}$/.test(String(admission?.grant_id || '')) ||
  !/^[0-9a-f]{64}$/.test(String(admission?.grantor || '')) || !['task', 'task+act'].includes(admission?.cap) ||
  String(admission.from).toLowerCase() !== String(report.actionable[0].from).toLowerCase()) die('admitted payload lacks a verifiable sender/grant binding')
const channelCarry = admission.mode === 'channel-carry'
if (!['direct', 'channel-carry'].includes(admission.mode)) die('admitted payload has no valid delivery mode')
if (channelCarry && (!/^[0-9a-f]{64}$/.test(String(admission.carrier || '')) ||
  !/^[0-9a-f]{64}$/.test(String(admission.carrier_grant_id || '')) ||
  !/^[0-9a-f]{64}$/.test(String(admission.carrier_grantor || '')) ||
  !/^[0-9a-f]{64}$/.test(String(admission.source_event || '')) ||
  !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(String(admission.reply_channel || '')) ||
  !manifest.carriers.some(entry => entry.pubkey === admission.carrier && entry.channels.includes(admission.reply_channel)))) {
  die('channel carry lacks a verifiable carrier/source/channel binding')
}
const sourceIndex = resolve(manifest.stateDir, 'channel-source-admissions.jsonl')
if (channelCarry) {
  let claim
  try { claim = claimChannelSource(sourceIndex, String(admission.source_event).toLowerCase(), envelope) }
  catch (e) { die(`cannot claim channel source: ${e.message}`) }
  if (!claim.accepted) {
    // A different outer envelope carrying the same signed source is terminal. It gets no reply
    // receipt and no adapter delivery; task-relay therefore cannot amplify the author's grant.
    try { renameSync(markerPath, `${markerPath}.done`) } catch (e) { die(`cannot finalize duplicate-source marker: ${e.message}`) }
    console.error(`instance-broker: duplicate channel source ${String(admission.source_event).slice(0, 12)}… suppressed`)
    process.exit(0)
  }
}
const receipt = { version: channelCarry ? 2 : 1, mode: admission.mode, instance: manifest.id, broker: manifest.pubkey, envelope,
  sender: String(admission.from).toLowerCase(), grant_id: String(admission.grant_id).toLowerCase(),
  grantor: String(admission.grantor || '').toLowerCase(), cap: String(admission.cap || ''),
  admitted_at: Date.now(), expires_at: Date.now() + 5 * 60 * 1000 }
if (channelCarry) Object.assign(receipt, {
  carrier: String(admission.carrier).toLowerCase(), carrier_grant_id: String(admission.carrier_grant_id).toLowerCase(),
  carrier_grantor: String(admission.carrier_grantor || '').toLowerCase(), source_event: String(admission.source_event).toLowerCase(),
  reply_channel: String(admission.reply_channel).toLowerCase(),
})
if (!/^[0-9a-f]{64}$/.test(receipt.sender)) die('admitted payload had no valid sender identity')
try {
  mkdirSync(receiptDir, { recursive: true, mode: 0o700 })
  const tmp = `${receiptPath}.${process.pid}.tmp`
  writeFileSync(tmp, JSON.stringify(receipt), { mode: 0o600 })
  renameSync(tmp, receiptPath)
} catch (e) { die(`cannot persist admission receipt: ${e.message}`) }

const socket = resolve(manifest.runtimeDir, 'adapter.sock')
// Preserve the exact authorization decision across the keyless Desktop boundary. The scope
// subject is the participant identity: attention accepted the grant only after recomputing its
// salted da-scope hash for report.me. This attestation grants no capability beyond task/task+act.
const authority = { version: channelCarry ? 2 : 1, type: 'scoped-instruction', sender: receipt.sender,
  grant_id: receipt.grant_id, grantor: receipt.grantor, cap: receipt.cap,
  scope_subject: manifest.pubkey, policy_checked_at: receipt.admitted_at }
if (channelCarry) Object.assign(authority, { carrier: receipt.carrier, carrier_grant_id: receipt.carrier_grant_id,
  carrier_grantor: receipt.carrier_grantor,
  source_event: receipt.source_event, reply_channel: receipt.reply_channel })
const payload = JSON.stringify({ type: 'admitted-task', instance: manifest.id, envelope, authority, messages: report.actionable }) + '\n'
const client = net.createConnection(socket)
const timer = setTimeout(() => { client.destroy(); die('adapter acknowledgement timed out') }, 15000)
client.on('error', e => { clearTimeout(timer); die(`adapter socket unavailable: ${e.message}`) })
client.on('connect', () => client.write(payload))
let received = ''
client.on('data', chunk => {
  received += chunk
  if (!received.includes('\n')) return
  clearTimeout(timer)
  let ack; try { ack = JSON.parse(received.split('\n')[0]) } catch { die('adapter acknowledgement is malformed') }
  if (ack.type !== 'ack' || ack.instance !== manifest.id) die('adapter acknowledgement does not bind this instance')
  if (channelCarry) {
    try { completeChannelSource(sourceIndex, receipt.source_event, envelope) }
    catch (e) { die(`adapter acknowledged but channel source completion failed: ${e.message}`) }
  }
  // Mark only after the adapter has durably accepted this exact delivery. A broker crash before
  // this point yields redelivery; a crash after it yields no duplicate from this watermark.
  const marked = spawnSync(process.execPath, [attention, '--mark', '--json', '--envelope', envelope], { env, encoding: 'utf8', timeout: 60000 })
  if (marked.status !== 0) die(`attention watermark failed (${marked.status ?? 'signal'})`)
  // A completed marker stays as durable audit evidence but cannot be delivered a second time.
  // Rename is atomic on the single spool filesystem; a second broker sees no source marker.
  try { renameSync(markerPath, `${markerPath}.done`) } catch (e) { die(`acknowledged but could not finalize marker: ${e.message}`) }
  client.end()
})
