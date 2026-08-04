#!/usr/bin/env node
// Import broker-admitted records into a local desktop adapter queue. SSH provides transport
// authentication; this boundary still validates every record, binds it to one owner-selected
// instance, and deduplicates by envelope. It never receives a signer or relay credential.

import { appendFileSync, chmodSync, existsSync, lstatSync, mkdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { readManifest, instanceId } from './runtime_manifest.mjs'
import { validateAdmittedTask } from './admitted_task.mjs'

const die = message => { console.error(`instance-admitted-import: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), baseline = process.argv.includes('--baseline')
if (!id || process.argv.some((v, i) => i > 1 && !['--instance', id, '--baseline'].includes(v))) die('usage: --instance <id> [--baseline]')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)) } catch (error) { die(error.message) }
if (manifest.deliveryMode !== 'codex_app_server') die('local import requires codex_app_server delivery')

let input = ''
for await (const chunk of process.stdin) {
  input += chunk
  if (Buffer.byteLength(input) > 64 * 1024 * 1024) die('remote export exceeds import bound')
}

mkdirSync(manifest.runtimeDir, { recursive: true, mode: 0o700 })
const queue = resolve(manifest.runtimeDir, 'admitted-tasks.jsonl')
const cursor = resolve(manifest.runtimeDir, 'remote-imported.jsonl')
for (const path of [queue, cursor]) {
  if (!existsSync(path)) continue
  const stat = lstatSync(path)
  if (!stat.isFile() || stat.isSymbolicLink()) die('local queue state must be a regular non-symlink file')
}
const seen = new Set()
for (const path of [cursor, queue]) {
  if (!existsSync(path)) continue
  for (const line of readFileSync(path, 'utf8').split('\n').filter(Boolean)) {
    try { const record = JSON.parse(line); if (/^[0-9a-f]{64}$/.test(record.envelope || '')) seen.add(record.envelope) } catch {}
  }
}

let imported = 0, skipped = 0
for (const line of input.split('\n').filter(Boolean)) {
  if (Buffer.byteLength(line) > 1024 * 1024) die('remote record exceeds import bound')
  let record
  try { record = JSON.parse(line) } catch { die('remote export contains malformed JSON') }
  try { validateAdmittedTask(record, { instance: manifest.id, scopeSubject: manifest.pubkey, grantors: manifest.grantors, carriers: manifest.carriers }) } catch { die('remote export contains an invalid admitted record') }
  if (seen.has(record.envelope)) { skipped++; continue }
  const durable = JSON.stringify({ version: 1, envelope: record.envelope, imported_at: Date.now() })
  // Queue first, cursor second. A crash after queue append is deduplicated on restart because
  // startup unions both files; the opposite ordering could suppress a task that never queued.
  if (!baseline) { appendFileSync(queue, JSON.stringify(record) + '\n', { mode: 0o600 }); chmodSync(queue, 0o600); imported++ }
  else skipped++
  appendFileSync(cursor, durable + '\n', { mode: 0o600 }); chmodSync(cursor, 0o600)
  seen.add(record.envelope)
}
console.log(`instance-admitted-import: ${baseline ? 'baselined' : 'imported'} ${baseline ? skipped : imported}; skipped ${baseline ? 0 : skipped}`)
