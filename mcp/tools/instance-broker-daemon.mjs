#!/usr/bin/env node
// instance-broker-daemon.mjs — supervisor entrypoint for one keyed broker identity (#44).
// It owns no relay subscription. It serially drains only this manifest's opaque pending markers;
// crash-left `.inflight` markers are requeued at boot and are harmless because the adapter queue
// deduplicates on envelope before ACKing.

import { readdirSync, renameSync, readFileSync, lstatSync } from 'node:fs'
import { resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { isTerminalReplyFailure, loadTerminalReplyIds, recordTerminalReply } from './reply_retry.mjs'

const die = m => { console.error(`instance-broker-daemon: ${m}`); process.exit(1) }
const flag = n => { const i = process.argv.indexOf(n); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
if (!id) die('usage: --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (e) { die(e.message) }
if (!process.env.NVOY_BROKER_CREDENTIAL) die('broker credential path is unavailable')
const broker = resolve(new URL('.', import.meta.url).pathname, 'instance-broker.mjs')
const reply = resolve(new URL('.', import.meta.url).pathname, 'instance-broker-reply.mjs')
const childEnv = { PATH: process.env.PATH || '', NVOY_INSTANCE_ROOT: root, NVOY_BROKER_CREDENTIAL: process.env.NVOY_BROKER_CREDENTIAL,
  ...(process.env.NVOY_BUNKER_URI_FILE ? { NVOY_BUNKER_URI_FILE: process.env.NVOY_BUNKER_URI_FILE } : {}) }
const terminalRepliesPath = resolve(manifest.stateDir, 'terminal-replies.jsonl')
let terminalReplyIds
try { terminalReplyIds = loadTerminalReplyIds(terminalRepliesPath) }
catch (e) { die(`cannot load terminal reply log: ${e.message || e}`) }

function recover() {
  let names = []
  try { names = readdirSync(manifest.spoolDir) } catch (e) { die(`cannot read marker spool: ${e.message}`) }
  for (const name of names) {
    const m = name.match(/^([0-9a-f]{64})\.inflight$/)
    if (!m) continue
    try { renameSync(resolve(manifest.spoolDir, name), resolve(manifest.spoolDir, `${m[1]}.pending`)) }
    catch (e) { die(`cannot recover inflight marker ${m[1].slice(0, 12)}…: ${e.message}`) }
  }
}
function drain() {
  let names = []
  try { names = readdirSync(manifest.spoolDir).sort() } catch (e) { console.error(`instance-broker-daemon: spool read failed: ${e.message}`); return }
  // A marker contains no plaintext or sender identity, but it does carry the watcher's
  // observation time. Prefer the newest first: a backlog after a broker outage must not turn
  // a live @mention into an hours-late task simply because its random Nostr id sorts last.
  const pending = names.flatMap(name => {
    const m = name.match(/^([0-9a-f]{64})\.pending$/)
    if (!m) return []
    let observed = 0
    try {
      const marker = JSON.parse(readFileSync(resolve(manifest.spoolDir, name), 'utf8'))
      if (String(marker.envelope || '').toLowerCase() === m[1] && Number.isFinite(Number(marker.observed_at))) observed = Number(marker.observed_at)
    } catch { /* broker deliver will validate this malformed marker before any decrypt */ }
    return [{ envelope: m[1], observed }]
  }).sort((a, b) => b.observed - a.observed || a.envelope.localeCompare(b.envelope))
  for (const item of pending) {
    const r = spawnSync(process.execPath, [broker, 'deliver', '--instance', manifest.id, '--envelope', item.envelope], { env: childEnv, encoding: 'utf8', timeout: 90000 })
    if (r.status !== 0) console.error(`instance-broker-daemon: ${item.envelope.slice(0, 12)}… held for retry: ${String(r.stderr || '').trim()}`)
  }
  // The adapter-owned queue is append-only.  A reply tool receives only a 32-hex request id;
  // it reopens this fixed queue, then binds the request to the broker-authored admission receipt.
  const replyQueue = resolve(manifest.runtimeDir, 'reply-requests.jsonl')
  try {
    const st = lstatSync(replyQueue)
    if (!st.isFile() || st.isSymbolicLink()) throw new Error('reply queue is not a regular file')
    const ids = new Set()
    for (const line of readFileSync(replyQueue, 'utf8').split('\n')) {
      try { const x = JSON.parse(line); if (/^[0-9a-f]{32}$/.test(String(x.id || ''))) ids.add(x.id) } catch { /* trailing partial line */ }
    }
    for (const request of ids) {
      if (terminalReplyIds.has(request)) continue
      const r = spawnSync(process.execPath, [reply, '--instance', manifest.id, '--request', request], { env: childEnv, encoding: 'utf8', timeout: 90000 })
      if (r.status !== 0) {
        const stderr = String(r.stderr || '').trim()
        if (isTerminalReplyFailure(stderr)) {
          try {
            if (recordTerminalReply(terminalRepliesPath, terminalReplyIds, request, stderr))
              console.error(`instance-broker-daemon: reply ${request.slice(0, 12)}… terminal — its receipt is no longer live`)
          } catch (e) { console.error(`instance-broker-daemon: cannot record terminal reply ${request.slice(0, 12)}…: ${e.message || e}`) }
        } else console.error(`instance-broker-daemon: reply ${request.slice(0, 12)}… held for retry: ${stderr}`)
      }
    }
  } catch (e) { if (e.code !== 'ENOENT') console.error(`instance-broker-daemon: reply queue unavailable: ${e.message}`) }
}
recover()
drain()
setInterval(drain, 1000)
console.log(`instance-broker-daemon: draining ${manifest.id}`)
