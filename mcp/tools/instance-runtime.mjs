#!/usr/bin/env node
// instance-runtime.mjs — one isolated Nvoy participant runtime per identity.
//
// A manifest is intentionally boring JSON: its public half names one participant, its state
// directory, policy grantors, and relays. Its sole private reference is a mode-0600 nsec file.
// `watch` never reads that file; it starts the keyless envelope observer. Decryption belongs to
// the separately supervised broker described in docs/RUNTIME_SUPERVISOR.md — NEVER this adapter
// process. No decrypted message is persisted or passed to a watcher.
//
//   node tools/instance-runtime.mjs describe --manifest codex.json
//   node tools/instance-runtime.mjs watch --manifest codex.json
// The `attention` command was intentionally removed: giving an adapter the key through a child
// environment defeats the broker boundary. The broker service will own that operation.

import { resolve } from 'node:path'
import { spawn } from 'node:child_process'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'

const die = m => { console.error(`instance-runtime: ${m}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const command = process.argv[2]
const idFlag = flag('--instance')
if (!['describe', 'watch'].includes(command) || !idFlag) die('usage: describe|watch --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(idFlag)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }
const baseEnv = { ...process.env, HOME: manifest.stateDir, NVOY_RELAYS: manifest.relays.join(','), GRANTORS: manifest.grantors.join(',') }
delete baseEnv.NVOY_NSEC
const tool = name => resolve(new URL('.', import.meta.url).pathname, name)
if (command === 'describe') {
  console.log(JSON.stringify({ id: manifest.id, recipient: manifest.pubkey, grantors: manifest.grantors,
    relays: manifest.relays, stateDir: manifest.stateDir, watcher: 'keyless' }, null, 2)); process.exit(0)
}
if (command === 'watch') {
  const child = spawn(process.execPath, [tool('keyless-wake-watcher.mjs'), '--recipient', manifest.pubkey,
    '--seen-path', resolve(manifest.stateDir, 'keyless-wake-seen.log'), '--queue-path', resolve(manifest.stateDir, 'keyless-wake-queue.jsonl')], { env: baseEnv, stdio: 'inherit' })
  child.on('exit', code => process.exit(code ?? 1))
}
