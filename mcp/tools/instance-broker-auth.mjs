#!/usr/bin/env node
// instance-broker-auth.mjs — the NIP-42 AUTH oracle that lets the keyless Buzz watcher log in.
//
// The Buzz relay reads nothing for a connection that has not authenticated as a member, so the
// watcher needs one signature per connection. It gets exactly that from here and nothing more:
// each request is checked by checkAuthTemplate (a fresh kind 22242 for this relay, with only the
// `relay` and `challenge` tags), rate-bounded, and signed by the broker's own signer. The socket
// lives in the watcher spool, which the adapter does not mount; group-readable by the broker/
// adapter gid is therefore reachable by the watcher and the broker only.

import { resolve } from 'node:path'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { brokerSigner } from './broker_signer.mjs'
import { serveAuthOracle } from './buzz_native.mjs'

const die = message => { console.error(`instance-broker-auth: ${message}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
if (!id) die('usage: --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }
if (manifest.brokerMode !== 'local') die('remote-broker Desktop manifests cannot start a local broker')
if (!manifest.buzz) die('this manifest has no buzz block')

// A long-lived Bunker transport: AUTH must be answered inside the relay's 5s window, and a cold
// NIP-46 round trip can take most of that.
const { signer } = brokerSigner(die, { idleMs: 10 * 60 * 1000 })
let me
try { me = String(await signer.getPublicKey()).toLowerCase() } catch (e) { die(`signer unavailable: ${e.message}`) }
if (me !== manifest.pubkey) die('signer does not match manifest pubkey')
const socketPath = resolve(manifest.spoolDir, 'buzz-auth.sock')
try {
  await serveAuthOracle({ socketPath, relay: manifest.buzz.relay, signer, pubkey: me, gid: manifest.brokerAdapterGid })
} catch (e) { die(`cannot serve AUTH oracle: ${e.message}`) }
const stop = () => { try { signer.close?.() } catch { /* best effort */ } process.exit(0) }
process.on('SIGTERM', stop)
process.on('SIGINT', stop)
console.log(`instance-broker-auth: serving AUTH for ${manifest.id} on ${manifest.buzz.relay}`)
