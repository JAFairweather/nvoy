#!/usr/bin/env node
// instance-runtime-init.mjs — root-only, one-shot volume provisioner for #44 Docker runtimes.
// It is the ONLY role allowed to chown runtime roots. It reads no credential and exits before
// watcher/broker/adapter start; each later role is non-root and gets only its own mounts.

import { mkdirSync, lstatSync, chownSync, chmodSync, statSync, openSync, closeSync } from 'node:fs'
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
provision(m.stateDir, m.brokerUid, m.sharedGid, 0o700, 'broker state')
provision(m.spoolDir, m.watcherUid, m.sharedGid, 0o770, 'watcher spool')
provision(m.runtimeDir, m.adapterUid, m.sharedGid, 0o710, 'adapter runtime')
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
provisionFile(`${m.runtimeDir}/admitted-tasks.jsonl`, m.adapterUid, m.sharedGid, 0o640, 'admitted task queue')
provisionFile(`${m.runtimeDir}/reply-requests.jsonl`, m.workerUid, m.sharedGid, 0o640, 'worker reply queue')
provisionFile(`${m.runtimeDir}/worker-consumed.jsonl`, m.workerUid, m.workerUid, 0o600, 'worker consumed queue')
// Only the adapter can create these immutable per-envelope inputs; the worker gets group
// traversal/read access but cannot replace an input belonging to a different envelope.
provision(`${m.runtimeDir}/worker-input`, m.adapterUid, m.sharedGid, 0o710, 'worker input directory')
console.log(`instance-runtime-init: provisioned ${m.id}`)
