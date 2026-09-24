#!/usr/bin/env node
// instance-broker-native.mjs — the keyed half of native Buzz ears (salvage plan 2.3).
//
// The keyless watcher heard a channel message on the Buzz relay that names this identity, and
// left an opaque `<event>.buzz.pending` marker. A marker is only a hint. This process fetches the
// event itself, as the identity, re-verifies that it is a signed mention in one of the manifest's
// channels, and admits it only if its AUTHOR holds a live task grant for this identity. There is
// no carrier: the author signed the channel message, so the author's grant is the whole chain.
//
// Admission shares the channel-source index with carried mail, so one signed message heard both
// natively and through a carrier is admitted once, whichever path gets there first.

import { readFileSync, lstatSync, renameSync, mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import net from 'node:net'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { claimChannelSource, completeChannelSource } from './channel_source_dedup.mjs'
import { claimBrokerLock } from './broker_lock.mjs'
import { brokerSigner } from './broker_signer.mjs'
import { nativeMention, openBuzzSession } from './buzz_native.mjs'

const HEX64 = /^[0-9a-f]{64}$/
let signer
const exit = code => { try { signer?.close?.() } catch { /* best effort */ } process.exit(code) }
const die = message => { console.error(`instance-broker-native: ${message}`); exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
const eventId = flag('--event').toLowerCase()
if (process.argv[2] !== 'deliver' || !id || !HEX64.test(eventId)) die('usage: deliver --instance <id> --event <64-hex-id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }
if (manifest.brokerMode !== 'local') die('remote-broker Desktop manifests cannot start a local broker')
if (!manifest.buzz) die('this manifest has no buzz block; there is nothing native to deliver')
claimBrokerLock(manifest, die)

const pendingMarker = resolve(manifest.spoolDir, `${eventId}.buzz.pending`)
const markerPath = resolve(manifest.spoolDir, `${eventId}.buzz.inflight`)
try { renameSync(pendingMarker, markerPath) } catch (e) { die(`cannot atomically claim pending marker: ${e.message}`) }
try {
  const st = lstatSync(markerPath)
  if (!st.isFile() || st.isSymbolicLink()) die('marker must be a regular non-symlink file')
  const marker = JSON.parse(readFileSync(markerPath, 'utf8'))
  if (String(marker.envelope || '').toLowerCase() !== eventId || !Number.isFinite(Number(marker.observed_at)) ||
      Object.keys(marker).some(k => !['envelope', 'observed_at'].includes(k))) die('marker does not bind exactly the claimed event and observation time')
} catch (e) { die(`cannot read marker: ${e.message}`) }
// No answer is not a denial: put the marker back so a relay or Bunker outage cannot consume a
// real mention. A terminal verdict keeps the marker as `.done` audit evidence.
const requeue = reason => {
  try { renameSync(markerPath, pendingMarker) } catch (e) { die(`${reason}; and the marker could not be requeued: ${e.message}`) }
  console.error(`instance-broker-native: ${reason}; marker requeued`)
  exit(75)
}
const finish = reason => {
  try { renameSync(markerPath, `${markerPath}.done`) } catch (e) { die(`cannot finalize terminal marker: ${e.message}`) }
  console.error(`instance-broker-native: ${eventId.slice(0, 12)}… ${reason}`)
  exit(0)
}

let attentionEnv
;({ signer, attentionEnv } = brokerSigner(die, { idleMs: 30000 }))
let me
try { me = String(await signer.getPublicKey()).toLowerCase() } catch (e) { requeue(`signer unavailable: ${e.message}`) }
if (me !== manifest.pubkey) die('signer does not match manifest pubkey')

// 1. The event, read as ourselves. Only what the relay returns under this id counts.
let source
try {
  const session = await openBuzzSession({ relay: manifest.buzz.relay, signer })
  try { source = (await session.fetch({ ids: [eventId], kinds: [9], '#h': manifest.buzz.channels })).find(ev => ev?.id === eventId) }
  finally { session.close() }
} catch (e) { requeue(`Buzz relay unavailable: ${e.message}`) }
if (!source) finish('is not stored in any configured channel')
const mention = nativeMention(source, { me, channels: manifest.buzz.channels })
if (!mention) finish('is not a signed mention of this identity')

// 2. Live policy: does the AUTHOR hold a task grant for this identity, right now?
const attention = resolve(new URL('.', import.meta.url).pathname, 'attention.mjs')
const policyEnv = { HOME: manifest.stateDir, PATH: process.env.PATH || '', NVOY_RELAYS: manifest.relays.join(','),
  GRANTORS: manifest.grantors.join(','), ...attentionEnv }
const checked = spawnSync(process.execPath, [attention, '--policy-only'], { env: policyEnv, encoding: 'utf8', timeout: 60000 })
if (checked.status !== 0) requeue(`policy check failed (${checked.status ?? 'signal'})`)
let policy
try { policy = JSON.parse(checked.stdout) } catch { requeue('policy check returned invalid JSON') }
if (policy.me !== me) die('policy was evaluated for a different identity')
if (!policy.policyUsable) requeue('live grant policy unavailable')
const grants = (Array.isArray(policy.grants) ? policy.grants : []).filter(g => g?.pubkey === mention.author && manifest.grantors.includes(g.grantor))
const grant = grants.find(g => g.cap === 'task+act') || grants.find(g => g.cap === 'task')
if (!grant || !HEX64.test(String(grant.grant_id || ''))) finish('author holds no live task grant; heard as data only')

// 3. One signed message, one admission — across native and carried paths alike.
const sourceIndex = resolve(manifest.stateDir, 'channel-source-admissions.jsonl')
let claim
try { claim = claimChannelSource(sourceIndex, eventId, eventId) } catch (e) { die(`cannot claim channel source: ${e.message}`) }
if (!claim.accepted) finish('was already admitted through another path')

// 4. The receipt the reply actuator will require. It records where a reply threads, so the reply
// needs no second read of the source.
const marked = marker => (source.tags || []).find(t => t?.[0] === 'e' && t[3] === marker && HEX64.test(String(t[1])))?.[1]
const admittedAt = Date.now()
const receipt = { version: 3, mode: 'buzz-native', instance: manifest.id, broker: me, envelope: eventId,
  sender: mention.author, grant_id: grant.grant_id, grantor: grant.grantor, cap: grant.cap,
  source_event: eventId, reply_channel: mention.channel, reply_root: marked('root') || marked('reply') || eventId,
  admitted_at: admittedAt, expires_at: admittedAt + 5 * 60 * 1000 }
const receiptDir = resolve(manifest.stateDir, 'receipts')
try {
  mkdirSync(receiptDir, { recursive: true, mode: 0o700 })
  const path = resolve(receiptDir, `${eventId}.json`), tmp = `${path}.${process.pid}.tmp`
  writeFileSync(tmp, JSON.stringify(receipt), { mode: 0o600 })
  renameSync(tmp, path)
} catch (e) { die(`cannot persist admission receipt: ${e.message}`) }

// 5. Hand the admitted task to the keyless adapter, and finish only on its acknowledgement.
const authority = { version: 3, type: 'scoped-instruction', sender: receipt.sender, grant_id: receipt.grant_id,
  grantor: receipt.grantor, cap: receipt.cap, scope_subject: me, policy_checked_at: admittedAt,
  source_event: eventId, reply_channel: receipt.reply_channel }
const payload = JSON.stringify({ type: 'admitted-task', instance: manifest.id, envelope: eventId, authority,
  messages: [{ from: mention.author, at: source.created_at, content: String(source.content), event_id: eventId, kind: 9 }] }) + '\n'
const client = net.createConnection(resolve(manifest.runtimeDir, 'adapter.sock'))
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
  try { completeChannelSource(sourceIndex, eventId, eventId) } catch (e) { die(`adapter acknowledged but channel source completion failed: ${e.message}`) }
  try { renameSync(markerPath, `${markerPath}.done`) } catch (e) { die(`acknowledged but could not finalize marker: ${e.message}`) }
  console.log(`instance-broker-native: ${eventId.slice(0, 12)}… admitted from ${mention.author.slice(0, 8)} (${grant.cap})`)
  client.end()
  exit(0)
})
