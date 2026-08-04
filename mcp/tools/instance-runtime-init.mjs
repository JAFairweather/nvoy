#!/usr/bin/env node
// instance-runtime-init.mjs — root-only, one-shot volume provisioner for #44 Docker runtimes.
// It is the ONLY role allowed to chown runtime roots. It briefly receives root-readable source
// credentials, copies them into separate role-owned volumes, and exits before watcher/broker/
// adapter/worker start; each later role is non-root and gets only its own credential mount.

import { mkdirSync, lstatSync, chownSync, chmodSync, statSync, openSync, closeSync, readFileSync, writeFileSync, renameSync } from 'node:fs'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'

const die = m => { console.error(`instance-runtime-init: ${m}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
if (!id) die('usage: --instance <id>')
if (process.getuid?.() !== 0) die('must run as root during one-shot volume provisioning')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let m
try { m = readManifest(root, instanceId(id)); assertNoCollisions(root, m) } catch (e) { die(e.message) }

function provision(path, uid, gid, mode, label) {
  try { const s = lstatSync(path); if (!s.isDirectory() || s.isSymbolicLink()) die(`${label} root is not a real directory`) }
  catch (e) { if (e.code === 'ENOENT') mkdirSync(path, { recursive: true, mode }); else throw e }
  chownSync(path, uid, gid); chmodSync(path, mode)
  const s = statSync(path), actual = s.mode & 0o777
  if (s.uid !== uid || s.gid !== gid || actual !== mode) die(`${label} root ownership/mode verification failed`)
}
provision(m.stateDir, m.brokerUid, m.brokerAdapterGid, 0o700, 'broker state')
provision(m.spoolDir, m.watcherUid, m.brokerAdapterGid, 0o770, 'watcher spool')
// Worker needs only traversal to its exact handoff paths; it never shares the socket group.
provision(m.runtimeDir, m.adapterUid, m.brokerAdapterGid, 0o711, 'adapter runtime')
function provisionFile(path, uid, gid, mode, label) {
  try { const s = lstatSync(path); if (!s.isFile() || s.isSymbolicLink()) die(`${label} is not a regular file`) }
  catch (e) { if (e.code === 'ENOENT') closeSync(openSync(path, 'wx', mode)); else throw e }
  chownSync(path, uid, gid); chmodSync(path, mode)
  const s = statSync(path), actual = s.mode & 0o777
  if (s.uid !== uid || s.gid !== gid || actual !== mode) die(`${label} ownership/mode verification failed`)
}
// Worker only has group traversal on the adapter-owned runtime root. These named files are the
// whole cross-UID protocol: task input is adapter-write/group-read; requests are worker-write/
// group-read; consumed state is worker-private. No role can create a replacement socket or queue.
provisionFile(`${m.runtimeDir}/admitted-tasks.jsonl`, m.adapterUid, m.workerHandoffGid, 0o640, 'admitted task queue')
provisionFile(`${m.runtimeDir}/reply-requests.jsonl`, m.workerUid, m.brokerAdapterGid, 0o640, 'worker reply queue')
// The restricted Desktop SSH principal is the credential-free adapter UID, never the model
// worker UID. Its separate queue is writable by that UID and readable by the broker group.
provisionFile(`${m.runtimeDir}/desktop-reply-requests.jsonl`, m.adapterUid, m.brokerAdapterGid, 0o640, 'Desktop reply queue')
provisionFile(`${m.runtimeDir}/worker-consumed.jsonl`, m.workerUid, m.workerUid, 0o600, 'worker consumed queue')
// Only the adapter can create these immutable per-envelope inputs; the worker gets group
// traversal/read access but cannot replace an input belonging to a different envelope.
provision(`${m.runtimeDir}/worker-input`, m.adapterUid, m.workerHandoffGid, 0o710, 'worker input directory')

// Compose file-backed secrets are bind-mounted as root-readable files even when a service uses
// a non-root UID. Keep those host sources root:root 0600, then make one role-owned copy in a
// private named volume during this root-only, one-shot initialization. The broker and worker
// never share a credential mount; watcher/adapter receive neither one.
function provisionSecret(source, target, uid, gid, label) {
  const st = lstatSync(source)
  if (!st.isFile() || st.isSymbolicLink()) die(`${label} source must be a regular file`)
  const body = readFileSync(source)
  if (!body.length) die(`${label} source is empty`)
  const tmp = `${target}.${process.pid}.tmp`
  writeFileSync(tmp, body, { mode: 0o400 })
  chownSync(tmp, uid, gid); chmodSync(tmp, 0o400); renameSync(tmp, target)
  const copied = statSync(target), actual = copied.mode & 0o777
  if (!copied.isFile() || copied.uid !== uid || copied.gid !== gid || actual !== 0o400) die(`${label} ownership/mode verification failed`)
}
const sources = {
  bunkerUri: process.env.NVOY_BUNKER_URI_SOURCE || '',
  bunkerClient: process.env.NVOY_BUNKER_CLIENT_SOURCE || '',
  workerProvider: process.env.NVOY_WORKER_PROVIDER_SOURCE || '',
}
const sourceValues = Object.values(sources)
if (sourceValues.some(Boolean)) {
  if (sourceValues.some(v => !v)) die('credential sources must be supplied as one complete set')
  const brokerCredDir = '/run/nvoy-broker-credentials', workerCredDir = '/run/nvoy-worker-credentials'
  provision(brokerCredDir, 0, 0, 0o711, 'broker credential directory')
  provision(workerCredDir, 0, 0, 0o711, 'worker credential directory')
  provisionSecret(sources.bunkerUri, `${brokerCredDir}/bunker-uri`, m.brokerUid, m.brokerAdapterGid, 'Bunker URI')
  provisionSecret(sources.bunkerClient, `${brokerCredDir}/bunker-client`, m.brokerUid, m.brokerAdapterGid, 'Bunker client')
  provisionSecret(sources.workerProvider, `${workerCredDir}/provider`, m.workerUid, m.workerHandoffGid, 'worker provider')
}
console.log(`instance-runtime-init: provisioned ${m.id}`)
