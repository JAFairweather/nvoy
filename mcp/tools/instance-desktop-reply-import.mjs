#!/usr/bin/env node
// Remote worker-side endpoint for one forced-command SSH key. It accepts only a bounded reply
// request for an envelope already present in this instance's adapter queue. It cannot choose a
// recipient, decrypt, sign, or publish; the broker resolves the sender from its own live receipt.

import { appendFileSync, existsSync, lstatSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { readManifest, instanceId } from './runtime_manifest.mjs'

const die = message => { console.error(`instance-desktop-reply-import: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
if (!id || process.argv.length !== 4) die('usage: --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)) } catch (error) { die(error.message) }
if (!['notify_only', 'codex_app_server'].includes(manifest.deliveryMode)) die('desktop reply import requires a non-headless delivery mode')
if (process.getuid?.() !== manifest.workerUid) die('must run as the manifest-bound worker user')

let input = ''
for await (const chunk of process.stdin) {
  input += chunk
  if (Buffer.byteLength(input) > 16 * 1024) die('reply request exceeds transport bound')
}
let request
try { request = JSON.parse(input) } catch { die('reply request is not valid JSON') }
const allowed = ['version', 'type', 'id', 'instance', 'receipt', 'content']
if (!request || Object.keys(request).some(key => !allowed.includes(key)) || request.version !== 1 ||
    request.type !== 'reply-request' || request.instance !== manifest.id ||
    !/^[0-9a-f]{32}$/.test(String(request.id || '')) || !/^[0-9a-f]{64}$/.test(String(request.receipt || '')) ||
    typeof request.content !== 'string' || !request.content.trim() || Buffer.byteLength(request.content) > 4000) {
  die('reply request has an invalid or overbroad shape')
}

const queue = resolve(manifest.runtimeDir, 'admitted-tasks.jsonl')
const replies = resolve(manifest.runtimeDir, 'reply-requests.jsonl')
function records(path, label) {
  if (!existsSync(path)) return []
  const stat = lstatSync(path)
  if (!stat.isFile() || stat.isSymbolicLink()) die(`${label} must be a regular non-symlink file`)
  return readFileSync(path, 'utf8').split('\n').flatMap(line => { try { return [JSON.parse(line)] } catch { return [] } })
}
const admitted = records(queue, 'admitted queue').find(record => record.type === 'admitted-task' && record.instance === manifest.id && record.envelope === request.receipt)
if (!admitted || !Array.isArray(admitted.messages) || admitted.messages.length !== 1 ||
    !/^[0-9a-f]{64}$/.test(String(admitted.messages[0]?.from || ''))) die('reply receipt is not a single-sender admitted task')
const prior = records(replies, 'reply queue')
if (prior.some(record => record.id === request.id)) { console.log(JSON.stringify({ request: request.id, receipt: request.receipt, replay: true })); process.exit(0) }
if (prior.some(record => record.receipt === request.receipt)) die('reply receipt already has a request')
appendFileSync(replies, JSON.stringify(request) + '\n', { mode: 0o640 })
console.log(JSON.stringify({ request: request.id, receipt: request.receipt, queued: true }))
