#!/usr/bin/env node
// instance-adapter.mjs — keyless local hand-off endpoint for Claude/Codex workers.
// It writes admitted tasks to its own private queue and acks only after fsync-like close. The
// actual runner can watch that queue or send a platform-specific notification; this process
// never receives a Nostr key or decrypt command.

import { mkdirSync, appendFileSync, chmodSync, chownSync, lstatSync, unlinkSync, readFileSync, writeFileSync, renameSync } from 'node:fs'
import { resolve } from 'node:path'
import net from 'node:net'
import { readManifest, instanceId } from './runtime_manifest.mjs'
import { validateDesktopDelivery } from './admitted_task.mjs'

const die = m => { console.error(`instance-adapter: ${m}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
if (!id) die('usage: --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)) } catch (e) { die(e.message) }
const socket = resolve(manifest.runtimeDir, 'adapter.sock')
// Broker gets group execute to traverse and group write on adapter.sock itself, but never
// directory write: it must not be able to unlink/replace the socket or adapter queue.
mkdirSync(manifest.runtimeDir, { recursive: true, mode: 0o710 })
chownSync(manifest.runtimeDir, -1, manifest.brokerAdapterGid)
chmodSync(manifest.runtimeDir, 0o711)
try { if (lstatSync(socket).isSocket()) unlinkSync(socket); else die('adapter socket path is not a socket') } catch (e) { if (e.code !== 'ENOENT') die(e.message) }
const queue = resolve(manifest.runtimeDir, 'admitted-tasks.jsonl')
const workerInputDir = resolve(manifest.runtimeDir, 'worker-input')
mkdirSync(workerInputDir, { recursive: true, mode: 0o710 })
chownSync(workerInputDir, -1, manifest.workerHandoffGid)
chmodSync(workerInputDir, 0o710)
// The broker can be restarted after its adapter ACK but before it finalizes the marker. Queue
// records are therefore the durable idempotency index: replaying the same envelope ACKs again,
// but it never becomes a second task for the worker.
const delivered = new Set()
try { for (const line of readFileSync(queue, 'utf8').split('\n')) { try { const x = JSON.parse(line); if (/^[0-9a-f]{64}$/.test(x.envelope || '')) delivered.add(x.envelope) } catch {} } } catch {}
const server = net.createServer(conn => {
  let data = ''
  conn.on('data', chunk => { data += chunk; if (!data.includes('\n')) return
    let packet; try { packet = JSON.parse(data.split('\n')[0]) } catch { conn.destroy(); return }
    try { validateDesktopDelivery(packet, { instance: manifest.id, scopeSubject: manifest.pubkey, grantors: manifest.grantors, carriers: manifest.carriers }) } catch { conn.destroy(); return }
    try {
      if (!delivered.has(packet.envelope)) {
        // The worker may only read/traverse this adapter-owned directory. Atomically publish the
        // one task input before queueing its envelope, so a queue record never names missing data.
        const input = resolve(workerInputDir, `${packet.envelope}.json`), tmp = `${input}.${process.pid}.tmp`
        writeFileSync(tmp, JSON.stringify(packet.type === 'verified-notification'
          ? { envelope: packet.envelope, notification: packet.notification }
          : { envelope: packet.envelope, authority: packet.authority || null, messages: packet.messages }), { mode: 0o640 })
        renameSync(tmp, input); chownSync(input, -1, manifest.workerHandoffGid); chmodSync(input, 0o640)
        appendFileSync(queue, JSON.stringify(packet) + '\n', { mode: 0o640 }); chownSync(queue, -1, manifest.workerHandoffGid); chmodSync(queue, 0o640); delivered.add(packet.envelope)
      }
    }
    catch { conn.destroy(); return }
    conn.end(JSON.stringify({ type: 'ack', instance: manifest.id }) + '\n')
  })
})
server.on('error', e => die(`cannot bind private adapter socket: ${e.message}`))
server.listen(socket, () => { chownSync(socket, -1, manifest.brokerAdapterGid); chmodSync(socket, 0o660); console.log(`instance-adapter: listening for ${manifest.id}`) })
