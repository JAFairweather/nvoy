#!/usr/bin/env node
// Fixed-command server half of a keyless Desktop bridge. Run as the manifest adapter UID. It may
// read adapter-admitted tasks and append bounded reply requests, but has no signer, broker state,
// relay client, model-provider credential, thread selector, or arbitrary path argument.

import { appendFileSync, lstatSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { readManifest, instanceId } from './runtime_manifest.mjs'
import { validateAdmittedTask } from './admitted_task.mjs'

const die = message => { console.error(`instance-desktop-sync: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
if (!id || process.argv.length !== 4) die('usage: --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)) } catch (error) { die(error.message) }
if (manifest.brokerMode !== 'local') die('server sync requires the single local broker manifest')
if (process.getuid?.() !== manifest.adapterUid) die('must run as the manifest-bound adapter user')

function regular(path, label) {
  let stat
  try { stat = lstatSync(path) } catch { die(`${label} is missing`) }
  if (!stat.isFile() || stat.isSymbolicLink()) die(`${label} must be a regular non-symlink file`)
  return stat
}
const admittedPath = resolve(manifest.runtimeDir, 'admitted-tasks.jsonl')
const replyPath = resolve(manifest.runtimeDir, 'desktop-reply-requests.jsonl')
for (const [path, label] of [[admittedPath, 'admitted queue'], [replyPath, 'reply request queue']]) {
  if (regular(path, label).size > 64 * 1024 * 1024) die(`${label} exceeds sync bound`)
}
const admittedLines = readFileSync(admittedPath, 'utf8').split('\n').filter(Boolean)
const admitted = new Set()
for (const line of admittedLines) {
  if (Buffer.byteLength(line) > 1024 * 1024) die('admitted record exceeds sync bound')
  let record
  try { record = JSON.parse(line) } catch { die('admitted queue contains malformed JSON') }
  try { validateAdmittedTask(record, { instance: manifest.id, scopeSubject: manifest.pubkey, grantors: manifest.grantors, carriers: manifest.carriers }) } catch { die('admitted queue contains an invalid record') }
  admitted.add(record.envelope)
}
const existing = new Set()
for (const line of readFileSync(replyPath, 'utf8').split('\n').filter(Boolean)) {
  try { const record = JSON.parse(line); if (/^[0-9a-f]{32}$/.test(String(record.id || ''))) existing.add(record.id) } catch { die('reply request queue contains malformed JSON') }
}

let input = ''
for await (const chunk of process.stdin) {
  input += chunk
  if (Buffer.byteLength(input) > 16 * 1024 * 1024) die('Desktop reply stream exceeds sync bound')
}
for (const line of input.split('\n').filter(Boolean)) {
  if (Buffer.byteLength(line) > 8192) die('Desktop reply request exceeds sync bound')
  let request
  try { request = JSON.parse(line) } catch { die('Desktop reply stream contains malformed JSON') }
  const keys = ['version', 'type', 'id', 'instance', 'receipt', 'content']
  if (Object.keys(request).some(key => !keys.includes(key)) || request.version !== 1 || request.type !== 'reply-request' ||
      request.instance !== manifest.id || !/^[0-9a-f]{32}$/.test(String(request.id || '')) ||
      !/^[0-9a-f]{64}$/.test(String(request.receipt || '')) || !admitted.has(request.receipt) ||
      typeof request.content !== 'string' || !request.content.trim() || Buffer.byteLength(request.content) > 4000) die('Desktop reply request is invalid or not bound to an admitted envelope')
  if (!existing.has(request.id)) {
    appendFileSync(replyPath, JSON.stringify(request) + '\n', { mode: 0o640 })
    existing.add(request.id)
  }
}
for (const line of admittedLines) process.stdout.write(line + '\n')
