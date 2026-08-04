#!/usr/bin/env node
// instance-adapter.mjs — keyless local hand-off endpoint for Claude/Codex workers.
// It writes admitted tasks to its own private queue and acks only after fsync-like close. The
// actual runner can watch that queue or send a platform-specific notification; this process
// never receives a Nostr key or decrypt command.

import { mkdirSync, appendFileSync, chmodSync, chownSync, lstatSync, unlinkSync } from 'node:fs'
import { resolve } from 'node:path'
import net from 'node:net'
import { readManifest, instanceId } from './runtime_manifest.mjs'

const die = m => { console.error(`instance-adapter: ${m}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
if (!id) die('usage: --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)) } catch (e) { die(e.message) }
const socket = resolve(manifest.runtimeDir, 'adapter.sock')
mkdirSync(manifest.runtimeDir, { recursive: true, mode: 0o770 })
chownSync(manifest.runtimeDir, -1, manifest.sharedGid)
chmodSync(manifest.runtimeDir, 0o770)
try { if (lstatSync(socket).isSocket()) unlinkSync(socket); else die('adapter socket path is not a socket') } catch (e) { if (e.code !== 'ENOENT') die(e.message) }
const queue = resolve(manifest.runtimeDir, 'admitted-tasks.jsonl')
const server = net.createServer(conn => {
  let data = ''
  conn.on('data', chunk => { data += chunk; if (!data.includes('\n')) return
    let packet; try { packet = JSON.parse(data.split('\n')[0]) } catch { conn.destroy(); return }
    if (packet.type !== 'admitted-task' || packet.instance !== manifest.id || !Array.isArray(packet.messages)) { conn.destroy(); return }
    try { appendFileSync(queue, JSON.stringify(packet) + '\n', { mode: 0o600 }); chmodSync(queue, 0o600) }
    catch { conn.destroy(); return }
    conn.end(JSON.stringify({ type: 'ack', instance: manifest.id }) + '\n')
  })
})
server.on('error', e => die(`cannot bind private adapter socket: ${e.message}`))
server.listen(socket, () => { chownSync(socket, -1, manifest.sharedGid); chmodSync(socket, 0o660); console.log(`instance-adapter: listening for ${manifest.id}`) })
