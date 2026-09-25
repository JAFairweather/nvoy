#!/usr/bin/env node
// The wake feed for one portable Codex harness, run on the fleet by its own forced-command key. It
// follows the instance's admitted queue and writes one NDJSON line per new envelope: the envelope
// id, its type and its receipt time, and nothing else. The message stays on the fleet, reached only
// through nvoy_channel_read on the channel key. The feed is keyless and reads no read log or reply.
//
// It also holds the identity's Codex consumer lock. The Codex channel tools are stateless per call,
// so before this nothing stopped two Codex harnesses answering the same envelope; now a second feed
// for the identity is refused while the first one's PID is alive.
//
// Cursor: an envelope id, not a line offset. The supervisor already keys what it has delivered by
// envelope, an envelope is the same wherever it sits in the file, and an offset into a file that
// was ever rewritten would silently skip or replay. An envelope the queue no longer holds cannot be
// placed, so the feed says so and starts from now rather than replaying an unknown history as live.
//
// The cursor arrives as the first stdin line, {"since": <envelope>|"start"|null}, because a forced command
// fixes argv; --since does the same for a local run. null means from now (a first start baselines
// there); "start" means the whole queue, for a client that baselined on an empty one. Every later
// stdin line is a keepalive. A client
// that stops sending them is gone even when the carrier keeps the pipe open (#168), so the feed then
// exits and frees the lock, and the supervisor reconnects from its cursor.

import { closeSync, fstatSync, lstatSync, openSync, readSync } from 'node:fs'
import { resolve } from 'node:path'
import { StringDecoder } from 'node:string_decoder'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { claimPidLock } from './pid_lock.mjs'

const die = message => { console.error(`nvoy-codex-channel-feed: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const bounded = (name, fallback, min, max) => {
  const value = Number(flag(name) || fallback)
  if (!Number.isInteger(value) || value < min || value > max) die(`${name} must be ${min}..${max}`)
  return value
}
const HEX64 = /^[0-9a-f]{64}$/
const id = flag('--instance')
if (!id) die('usage: --instance <id> [--since <envelope>] [--heartbeat-ms n] [--client-timeout-ms n] [--handshake-ms n] [--poll-ms n]')
const heartbeatMs = bounded('--heartbeat-ms', 15000, 100, 3600000)
const clientTimeoutMs = bounded('--client-timeout-ms', 120000, 500, 86400000)
const handshakeMs = bounded('--handshake-ms', 30000, 500, 3600000)
const pollMs = bounded('--poll-ms', 1000, 20, 60000)
const argvSince = process.argv.includes('--since') ? flag('--since') : undefined
const sinceValid = since => since === null || since === 'start' || HEX64.test(String(since))
if (argvSince !== undefined && argvSince !== '' && !sinceValid(argvSince)) die('--since must be an envelope id or start')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (error) { die(error.message) }
if (manifest.brokerMode !== 'local' || manifest.deliveryMode !== 'notify_only' || manifest.workerEnabled) {
  die('Codex channel feed requires a local-broker, worker-disabled notify_only manifest')
}
if (process.getuid?.() !== manifest.workerUid) die('Codex channel feed must run as the manifest-bound worker user')

const queuePath = resolve(manifest.runtimeDir, 'admitted-tasks.jsonl')
let release
try { release = claimPidLock(resolve(manifest.runtimeDir, 'codex-mcp-state', 'feed.lock'), manifest.id, 'Codex harness feed', { program: 'codex-channel-feed.mjs' }) } catch (error) { die(error.message) }
process.on('exit', () => release())
for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.on(signal, () => process.exit(0))
process.stdout.on('error', () => process.exit(0))

const MAX_RECORD = 1024 * 1024, MAX_QUEUE = 64 * 1024 * 1024, MAX_CLIENT_LINE = 4096
const emit = row => process.stdout.write(JSON.stringify(row) + '\n')

// Metadata only, built fresh: whatever else a queue line carries never reaches the wire.
function meta(line) {
  let row
  try { row = JSON.parse(line) } catch { return null }
  const envelope = String(row?.envelope || '')
  if (!HEX64.test(envelope)) return null
  const at = Number(row.received_at)
  return { envelope, type: row.type === 'verified-notification' ? 'verified-notification' : 'admitted-task', at: Number.isFinite(at) ? at : null }
}

let offset = 0, partial = '', skipping = false, decoder = new StringDecoder('utf8')
function readNew() {
  let st
  try { st = lstatSync(queuePath) } catch { return { rows: [], reset: false } }
  if (!st.isFile() || st.isSymbolicLink()) throw new Error('admitted queue must be a regular non-symlink file')
  if (st.size > MAX_QUEUE) throw new Error('admitted queue exceeds its 64 MiB bound')
  const reset = st.size < offset
  if (reset) { offset = 0; partial = ''; skipping = false; decoder = new StringDecoder('utf8') }
  if (st.size === offset) return { rows: [], reset }
  const fd = openSync(queuePath, 'r'), rows = []
  try {
    const size = Math.min(fstatSync(fd).size, MAX_QUEUE), chunk = Buffer.alloc(Math.min(size - offset, MAX_RECORD))
    while (offset < size) {
      const n = readSync(fd, chunk, 0, Math.min(chunk.length, size - offset), offset)
      if (n <= 0) break
      offset += n
      const parts = (partial + decoder.write(chunk.subarray(0, n))).split('\n')
      partial = parts.pop()
      for (const line of parts) {
        if (skipping) { skipping = false; continue }
        if (line.trim() && Buffer.byteLength(line) <= MAX_RECORD) { const row = meta(line); if (row) rows.push(row) }
      }
      // A record over its bound is dropped whole, not split into lines that might parse.
      if (Buffer.byteLength(partial) > MAX_RECORD) { partial = ''; skipping = true }
    }
  } finally { closeSync(fd) }
  return { rows, reset }
}

let cursor = null, started = false, lastClient = Date.now()
function start(since) {
  started = true
  const { rows } = readNew()
  const at = since === 'start' ? -1 : since ? rows.map(row => row.envelope).lastIndexOf(since) : rows.length - 1
  const backlog = since === 'start' || (since && at >= 0) ? rows.slice(at + 1) : []
  cursor = rows.length ? rows.at(-1).envelope : null
  emit({ event: 'hello', instance: manifest.id, since_found: since === 'start' ? true : since ? at >= 0 : null, cursor })
  for (const row of backlog) emit({ event: 'admitted', ...row })
  setInterval(() => {
    let next
    try { next = readNew() } catch (error) { die(error.message) }
    // A rewritten queue is re-placed on the last envelope sent; failing that, the feed starts from now.
    let rows = next.rows
    if (next.reset) { const i = rows.map(row => row.envelope).lastIndexOf(cursor); rows = i >= 0 ? rows.slice(i + 1) : [] }
    for (const row of rows) { emit({ event: 'admitted', ...row }); cursor = row.envelope }
    if (next.reset && !rows.length && next.rows.length) cursor = next.rows.at(-1).envelope
  }, pollMs)
  setInterval(() => emit({ event: 'heartbeat', at: Date.now(), cursor }), heartbeatMs)
}

let input = ''
process.stdin.on('data', data => {
  lastClient = Date.now()
  input += data
  if (Buffer.byteLength(input) > MAX_CLIENT_LINE) die('client line exceeds its bound')
  let at
  while ((at = input.indexOf('\n')) >= 0) {
    const line = input.slice(0, at); input = input.slice(at + 1)
    if (started) continue
    let hello
    try { hello = JSON.parse(line) } catch { die('the first client line must be {"since": <envelope>|"start"|null}') }
    const since = hello?.since ?? null
    if (!sinceValid(since)) die('since must be an envelope id, "start" or null')
    try { start(since) } catch (error) { die(error.message) }
  }
})
process.stdin.on('end', () => process.exit(0))
process.stdin.on('error', () => process.exit(0))
if (argvSince !== undefined) try { start(argvSince || null) } catch (error) { die(error.message) }
setTimeout(() => { if (!started) { console.error(`nvoy-codex-channel-feed: no client cursor within ${handshakeMs}ms; releasing the feed lock`); process.exit(0) } }, handshakeMs)
setInterval(() => {
  if (Date.now() - lastClient <= clientTimeoutMs) return
  console.error(`nvoy-codex-channel-feed: no client keepalive for ${clientTimeoutMs}ms; releasing the feed lock`)
  process.exit(0)
}, Math.max(100, Math.min(heartbeatMs, clientTimeoutMs / 4)))
