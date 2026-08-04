#!/usr/bin/env node
// Submit one reply from an exact Codex Desktop delivery to the remote identity broker. The SSH
// key is forced to the instance-desktop-reply-import endpoint. This process has no Nostr signer
// and the request deliberately contains no recipient.

import { lstatSync, readFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { readManifest, instanceId } from './runtime_manifest.mjs'

const die = message => { console.error(`codex-remote-reply: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), receipt = String(flag('--envelope')).toLowerCase(), target = flag('--ssh-target')
const identityFlag = flag('--ssh-identity'), knownHostsFlag = flag('--known-hosts')
if (!id || !/^[0-9a-f]{64}$/.test(receipt) || !/^[a-z_][a-z0-9_-]{0,31}@[a-z0-9.-]+$/i.test(target) || !identityFlag || !knownHostsFlag) {
  die('usage: --instance <id> --envelope <64-hex> --ssh-target <restricted-user@host> --ssh-identity <file> --known-hosts <file>')
}
const identity = resolve(identityFlag), knownHosts = resolve(knownHostsFlag)
for (const [path, label, secret] of [[identity, 'SSH identity', true], [knownHosts, 'known-hosts file', false]]) {
  let stat; try { stat = lstatSync(path) } catch { die(`${label} is missing`) }
  if (!stat.isFile() || stat.isSymbolicLink()) die(`${label} must be a regular non-symlink file`)
  if (secret && (stat.mode & 0o077)) die('SSH identity must not be group/world accessible')
}
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)) } catch (error) { die(error.message) }
if (manifest.deliveryMode !== 'codex_app_server' || manifest.codexTransport !== 'local_control_socket') die('manifest is not bound to a local Codex control socket')
const deliveredPath = resolve(manifest.runtimeDir, 'codex-app-server-delivered.jsonl')
let delivered
try {
  const stat = lstatSync(deliveredPath)
  if (!stat.isFile() || stat.isSymbolicLink()) die('Codex delivery log must be a regular non-symlink file')
  delivered = readFileSync(deliveredPath, 'utf8').split('\n').flatMap(line => { try { return [JSON.parse(line)] } catch { return [] } })
} catch (error) { die(error.message) }
if (!delivered.some(record => record.envelope === receipt && record.thread_id === manifest.codexThreadId)) die('envelope was not delivered to this manifest-bound Codex thread')

let content = ''
for await (const chunk of process.stdin) {
  content += chunk
  if (Buffer.byteLength(content) > 4000) die('reply exceeds 4000 UTF-8 bytes')
}
content = content.trim()
if (!content) die('reply is empty')
const request = { version: 1, type: 'reply-request', id: randomBytes(16).toString('hex'), instance: manifest.id, receipt, content }
const args = ['-i', identity, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
  '-o', `UserKnownHostsFile=${knownHosts}`, '-o', 'ClearAllForwardings=yes', '-T', target]
const sent = spawnSync('ssh', args, { encoding: 'utf8', input: JSON.stringify(request), maxBuffer: 64 * 1024 })
if (sent.status !== 0) die(`restricted reply queue failed (${sent.status}): ${String(sent.stderr || '').trim()}`)
let ack; try { ack = JSON.parse(String(sent.stdout || '').trim()) } catch { die('restricted reply endpoint returned an invalid acknowledgement') }
if (ack.request !== request.id || ack.receipt !== receipt || (!ack.queued && !ack.replay)) die('restricted reply acknowledgement does not bind this request')
console.log(JSON.stringify(ack))
