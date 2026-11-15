#!/usr/bin/env node
// instance-broker-buzz.mjs — persistent shared Buzz session for one broker identity (q-150).
//
// Short-lived broker children (reply, post, rooms, native delivery, profile, status) all speak to
// the same Buzz community relay as this identity. Instead of opening a fresh WebSocket and signing
// a new NIP-42 AUTH challenge in every child, this supervised helper holds one authenticated Buzz
// connection behind a 0600 Unix socket in stateDir (reachable only by broker processes), logs phase
// timings and close codes, and reconnects on demand when the relay drops the socket.

import { resolve } from 'node:path'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { brokerSigner } from './broker_signer.mjs'
import { serveBuzzSession } from './buzz_native.mjs'

const die = message => { console.error(`instance-broker-buzz: ${message}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
if (!id) die('usage: --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }
if (manifest.brokerMode !== 'local') die('remote-broker Desktop manifests cannot start a local broker')
if (!manifest.buzz) die('this manifest has no buzz block')

const { signer } = brokerSigner(die, { idleMs: 10 * 60 * 1000 })
let me
try { me = String(await signer.getPublicKey()).toLowerCase() } catch (e) { die(`signer unavailable: ${e.message}`) }
if (me !== manifest.pubkey) die('signer does not match manifest pubkey')

const socketPath = resolve(manifest.stateDir, 'buzz-session.sock')
const log = line => console.error(`instance-broker-buzz: ${line}`)
let server
try {
  server = await serveBuzzSession({ socketPath, relay: manifest.buzz.relay, signer, pubkey: me, log })
} catch (e) { die(`cannot serve shared Buzz session: ${e.message}`) }

const parentPid = process.ppid
let stopping = false
const stop = () => {
  if (stopping) return
  stopping = true
  clearInterval(watchdog)
  try { server?.close() } catch { /* best effort */ }
  try { signer.close?.() } catch { /* best effort */ }
  process.exit(0)
}
const watchdog = setInterval(() => { if (process.ppid !== parentPid) stop() }, 2000)
watchdog.unref?.()
process.on('SIGTERM', stop)
process.on('SIGINT', stop)
console.log(`instance-broker-buzz: sharing Buzz session for ${manifest.id}`)
