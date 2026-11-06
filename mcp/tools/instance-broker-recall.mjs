#!/usr/bin/env node
// instance-broker-recall.mjs — the broker-side forwarder for memory_wake and memory_query
// (agent_recall.mjs). It runs as the broker UID in its own service and holds no Bunker credential:
// only the private socket in the shared runtime and the store's reader transport, may_recall.read.

import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { RECALL_NOT_PERMITTED, startRecallForwarder } from './agent_recall.mjs'

const die = m => { console.error(`instance-broker-recall: ${m}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
if (!id) die('usage: --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }
if (manifest.brokerMode !== 'local') die('remote-broker Desktop manifests have no local broker')
if (!manifest.mayRecall) die(`memory recall refused: ${RECALL_NOT_PERMITTED}`)
if (process.getuid?.() !== manifest.brokerUid) die('the memory recall forwarder must run as the manifest broker user')
let forwarder
try { forwarder = await startRecallForwarder({ manifest }) } catch (e) { die(e.message) }
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { forwarder.close().then(() => process.exit(0)); setTimeout(() => process.exit(0), 2000).unref() })
console.log(`instance-broker-recall: forwarding memory_wake and memory_query for ${manifest.id}`)
