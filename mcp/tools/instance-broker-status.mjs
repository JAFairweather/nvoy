#!/usr/bin/env node
// instance-broker-status.mjs — native Buzz status reactions for one broker identity.
//
// Supervised by the broker daemon beside the AUTH oracle, as the broker, with the broker's signer.
// It follows two append-only logs: the broker's own facts (an admission whose source is a Buzz
// message in this manifest's channels; a reply the relay accepted for it) and the keyless reader's
// status requests ("I have started on envelope X"). From them it puts 👀 and 💬 on the admitted
// message and removes both when the reply lands or the turn goes stale. See buzz_status.mjs.

import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { brokerSigner } from './broker_signer.mjs'
import { openBuzzSession } from './buzz_native.mjs'
import { lineFollower } from './admitted_queue.mjs'
import { claimPidLock } from './pid_lock.mjs'
import { mkdirSync } from 'node:fs'
import { createStatusKeeper, parseStatusFact, parseStatusRequest, statusEnabled, statusPaths } from './buzz_status.mjs'

const die = message => { console.error(`instance-broker-status: ${message}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
if (!id) die('usage: --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }
if (manifest.brokerMode !== 'local') die('remote-broker Desktop manifests cannot start a local broker')
if (!statusEnabled(manifest)) die('this manifest has no buzz block with status reactions enabled')

const paths = statusPaths(manifest)
mkdirSync(paths.dir, { recursive: true, mode: 0o700 })
let release
try { release = claimPidLock(paths.lock, manifest.id, 'status keeper', { program: 'instance-broker-status.mjs' }) } catch (e) { die(e.message) }

// Long-lived like the AUTH oracle's: a status is only worth showing while the turn is live.
const { signer } = brokerSigner(die, { idleMs: 10 * 60 * 1000 })
let me
try { me = String(await signer.getPublicKey()).toLowerCase() } catch (e) { die(`signer unavailable: ${e.message}`) }
if (me !== manifest.pubkey) die('signer does not match manifest pubkey')

const log = line => console.error(`instance-broker-status: ${line}`)
let keeper
try {
  keeper = createStatusKeeper({ manifest, signer, log,
    openSession: () => openBuzzSession({ relay: manifest.buzz.relay, signer, timeoutMs: 8000 }) })
} catch (e) { die(`cannot load status state: ${e.message}`) }
const facts = lineFollower(paths.facts, 'status fact log')
const requests = lineFollower(paths.requests, 'status request queue')
const read = (follow, parse, label) => {
  try { return follow().lines.map(line => parse(line, manifest)).filter(Boolean) }
  catch (e) { log(`${label} unreadable: ${e.message}`); return [] }
}

let stopping = false
const stop = () => { stopping = true; try { keeper.close() } catch { /* best effort */ } try { signer.close?.() } catch { /* best effort */ } release?.(); process.exit(0) }
process.on('SIGTERM', stop)
process.on('SIGINT', stop)
console.log(`instance-broker-status: keeping status reactions for ${manifest.id} on ${manifest.buzz.relay}`)
while (!stopping) {
  try {
    await keeper.step({ facts: read(facts, parseStatusFact, 'status fact log'), requests: read(requests, parseStatusRequest, 'status request queue') })
  } catch (e) { log(`step failed: ${e.message || e}`) }
  await new Promise(r => setTimeout(r, 1000))
}
