#!/usr/bin/env node
// Keyless Desktop reply boundary. It can request one bounded response only for an envelope that
// the broker admitted and the manifest-bound Codex thread actually accepted. Recipient selection,
// grant revalidation, signing, and publication remain exclusively in the remote broker.

import { appendFileSync, existsSync, lstatSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { randomBytes } from 'node:crypto'
import { readManifest, instanceId } from './runtime_manifest.mjs'

const die = message => { console.error(`desktop-reply-request: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), receipt = flag('--receipt').toLowerCase()
if (!id || !/^[0-9a-f]{64}$/.test(receipt)) die('usage: --instance <id> --receipt <64-hex-envelope>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)) } catch (error) { die(error.message) }
if (manifest.brokerMode !== 'remote' || manifest.deliveryMode !== 'codex_app_server') die('reply requests require a keyless remote-broker Desktop manifest')

let content = ''
for await (const chunk of process.stdin) {
  content += chunk
  if (Buffer.byteLength(content) > 4000) die('reply exceeds 4000 UTF-8 bytes')
}
content = content.trim()
if (!content) die('reply is empty')

function records(path, label) {
  if (!existsSync(path)) die(`${label} is missing`)
  const stat = lstatSync(path)
  if (!stat.isFile() || stat.isSymbolicLink()) die(`${label} must be a regular non-symlink file`)
  return readFileSync(path, 'utf8').split('\n').flatMap(line => { try { return [JSON.parse(line)] } catch { return [] } })
}
const admitted = records(resolve(manifest.runtimeDir, 'admitted-tasks.jsonl'), 'admitted queue')
  .find(record => record?.type === 'admitted-task' && record.instance === manifest.id && record.envelope === receipt)
if (!admitted || admitted.messages?.length !== 1 || !/^[0-9a-f]{64}$/.test(String(admitted.messages[0]?.from || ''))) die('receipt is not a single-sender admitted notification')
const delivered = records(resolve(manifest.runtimeDir, 'codex-app-server-delivered.jsonl'), 'Codex delivery log')
  .find(record => record?.envelope === receipt && record.thread_id === manifest.codexThreadId && /^[0-9a-f-]{36}$/i.test(String(record.turn_id || '')))
if (!delivered) die('receipt was not delivered to the manifest-bound Codex thread')

const queue = resolve(manifest.runtimeDir, 'reply-requests.jsonl')
const prior = existsSync(queue) ? records(queue, 'reply request queue') : []
if (prior.some(record => record?.receipt === receipt)) die('this delivered notification already has a reply request')
const request = { version: 1, type: 'reply-request', id: randomBytes(16).toString('hex'),
  instance: manifest.id, receipt, content }
appendFileSync(queue, JSON.stringify(request) + '\n', { mode: 0o600 })
console.log(JSON.stringify({ request: request.id, receipt }))
