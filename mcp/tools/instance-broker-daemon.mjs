#!/usr/bin/env node
// instance-broker-daemon.mjs — supervisor entrypoint for one keyed broker identity (#44).
// It owns no relay subscription. It serially drains only this manifest's opaque pending markers;
// crash-left `.inflight` markers are requeued at boot and are harmless because the adapter queue
// deduplicates on envelope before ACKing.

import { closeSync, openSync, readdirSync, renameSync, readFileSync, lstatSync, unlinkSync, writeFileSync } from 'node:fs'
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
if (manifest.brokerMode !== 'local') die('remote-broker Desktop manifests cannot start a local broker daemon')
if (!process.env.NVOY_BROKER_CREDENTIAL) die('broker credential path is unavailable')
// One identity may have exactly one live draining daemon. Two drain the same spool without either
// objecting: duplicated proposal announcements, doubled relay queries per tick, and two writers
// appending to one terminal-reply log. The child broker's own lock serialises the decrypt/sign path,
// but that is a downstream accident, not a property this process provides.
//
// Claimed BEFORE recover() and before the terminal-reply log is opened, because both touch state a
// second daemon must not be racing us on. Reclaim only a lock whose recorded pid is demonstrably
// gone — a stale lock from a killed process must not become its own outage — and fail closed on a
// malformed or foreign lock. This is the shape claude-channel.mjs already uses.
const lockPath = resolve(manifest.stateDir, 'broker-daemon.lock')
function claimLock() {
  try {
    const fd = openSync(lockPath, 'wx', 0o600)
    writeFileSync(fd, JSON.stringify({ version: 1, instance: manifest.id, pid: process.pid, started_at: Date.now() }))
    closeSync(fd)
    return
  } catch (error) { if (error.code !== 'EEXIST') throw error }
  let prior
  try {
    const stat = lstatSync(lockPath)
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('broker daemon lock is not a regular file')
    prior = JSON.parse(readFileSync(lockPath, 'utf8'))
  } catch (error) { throw new Error(`cannot validate existing broker daemon lock: ${error.message}`) }
  if (prior?.version !== 1 || prior?.instance !== manifest.id || !Number.isInteger(prior?.pid) || prior.pid < 1) {
    throw new Error('broker daemon lock does not bind this instance')
  }
  // EPERM means the pid exists under another uid — a live holder we cannot signal, so fail closed.
  try { process.kill(prior.pid, 0); throw new Error(`broker daemon already runs as pid ${prior.pid} for instance ${manifest.id}`) }
  catch (error) { if (error.code !== 'ESRCH') throw error }
  unlinkSync(lockPath)
  claimLock()
}
// Refusing is correct; refusing SILENTLY is the failure mode this exists to prevent, so the reason
// goes to stderr and the exit status is non-zero.
try { claimLock() } catch (error) { die(error.message) }
process.on('exit', () => { try { unlinkSync(lockPath) } catch {} })

// A proposal whose admission receipt has died can never be revived, so re-proposing it re-queries
// relays once per tick forever. Terminal ids are durable: a restart must not resurrect the loop.
const terminalRepliesPath = resolve(manifest.stateDir, 'terminal-replies.jsonl')
let terminalReplyIds
try { terminalReplyIds = loadTerminalReplyIds(terminalRepliesPath) }
catch (e) { die(`cannot load terminal reply log: ${e.message || e}`) }
const broker = resolve(new URL('.', import.meta.url).pathname, 'instance-broker.mjs')
const childEnv = { PATH: process.env.PATH || '', NVOY_INSTANCE_ROOT: root, NVOY_BROKER_CREDENTIAL: process.env.NVOY_BROKER_CREDENTIAL,
  ...(process.env.NVOY_BUNKER_URI_FILE ? { NVOY_BUNKER_URI_FILE: process.env.NVOY_BUNKER_URI_FILE } : {}) }
const retryAfter = new Map()
const proposalRetryAfter = new Map()
const announcedProposals = new Set()

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
    if ((retryAfter.get(item.envelope) || 0) > Date.now()) continue
    const r = spawnSync(process.execPath, [broker, 'deliver', '--instance', manifest.id, '--envelope', item.envelope], { env: childEnv, encoding: 'utf8', timeout: 90000 })
    if (r.status !== 0) {
      retryAfter.set(item.envelope, Date.now() + 5000)
      console.error(`instance-broker-daemon: ${item.envelope.slice(0, 12)}… held for retry: ${String(r.stderr || '').trim()}`)
    } else retryAfter.delete(item.envelope)
  }
  // AD-12: adapter/worker output is a proposal, never standing authority to sign. The daemon may
  // announce a queued proposal, but it must not invoke the keyed reply actuator. A separate,
  // discrete approval path will bind an exact frozen fingerprint before opening the signer.
  for (const [source, filename] of [['worker', 'reply-requests.jsonl'], ['desktop', 'desktop-reply-requests.jsonl']]) {
    const replyQueue = resolve(manifest.runtimeDir, filename)
    try {
      const st = lstatSync(replyQueue)
      if (!st.isFile() || st.isSymbolicLink()) throw new Error('reply queue is not a regular file')
      const ids = new Set()
      for (const line of readFileSync(replyQueue, 'utf8').split('\n')) {
        try { const x = JSON.parse(line); if (/^[0-9a-f]{32}$/.test(String(x.id || ''))) ids.add(x.id) } catch { /* trailing partial line */ }
      }
      for (const request of ids) {
        const key = `${source}:${request}`
        if (announcedProposals.has(key)) continue
        if (terminalReplyIds.has(request)) continue
        if ((proposalRetryAfter.get(key) || 0) > Date.now()) continue
        const proposed = spawnSync(process.execPath, [resolve(new URL('.', import.meta.url).pathname, 'instance-broker-reply.mjs'),
          '--instance', manifest.id, '--request', request, '--source', source, '--prepare'], { env: childEnv, encoding: 'utf8', timeout: 90000 })
        if (proposed.status !== 0) {
          const stderr = String(proposed.stderr || '').trim()
          if (isTerminalReplyFailure(stderr)) {
            try {
              if (recordTerminalReply(terminalRepliesPath, terminalReplyIds, request, stderr))
                console.error(`instance-broker-daemon: ${source} reply proposal ${request.slice(0, 12)}… terminal — its receipt is no longer live`)
            } catch (e) { console.error(`instance-broker-daemon: cannot record terminal reply ${request.slice(0, 12)}…: ${e.message || e}`) }
            continue
          }
          proposalRetryAfter.set(key, Date.now() + 5000)
          console.error(`instance-broker-daemon: ${source} reply proposal ${request.slice(0, 12)}… held: ${stderr}`)
          continue
        }
        proposalRetryAfter.delete(key)
        // The actuator decides which path applies and says so; the daemon never infers it from the
        // manifest or the instance name. A public event waits for a discrete approval. A private
        // channel-carry reply is enacted now, on the live grant chain that already admitted it —
        // and `--direct` re-checks that for itself, so a wrong answer here cannot open the signer.
        let verdict = null
        try { verdict = JSON.parse(String(proposed.stdout || '')) } catch { verdict = null }
        if (verdict?.approval_required === false && verdict?.action === 'nostr-private-reply') {
          const enacted = spawnSync(process.execPath, [resolve(new URL('.', import.meta.url).pathname, 'instance-broker-reply.mjs'),
            '--instance', manifest.id, '--request', request, '--source', source, '--direct'], { env: childEnv, encoding: 'utf8', timeout: 90000 })
          if (enacted.status !== 0) {
            const stderr = String(enacted.stderr || '').trim()
            if (isTerminalReplyFailure(stderr)) {
              try {
                if (recordTerminalReply(terminalRepliesPath, terminalReplyIds, request, stderr))
                  console.error(`instance-broker-daemon: ${source} reply ${request.slice(0, 12)}… terminal — its receipt is no longer live`)
              } catch (e) { console.error(`instance-broker-daemon: cannot record terminal reply ${request.slice(0, 12)}…: ${e.message || e}`) }
            } else {
              proposalRetryAfter.set(key, Date.now() + 5000)
              console.error(`instance-broker-daemon: ${source} reply ${request.slice(0, 12)}… held for retry: ${stderr}`)
            }
            continue
          }
          announcedProposals.add(key)
          console.log(`instance-broker-daemon: ${source} reply ${request.slice(0, 12)}… enacted on its live grant chain`)
          continue
        }
        announcedProposals.add(key)
        console.log(`instance-broker-daemon: ${source} reply proposal ${request.slice(0, 12)}… awaiting discrete approval`)
      }
    } catch (e) { if (e.code !== 'ENOENT') console.error(`instance-broker-daemon: ${source} reply queue unavailable: ${e.message}`) }
  }
}
recover()
drain()
setInterval(drain, 1000)
console.log(`instance-broker-daemon: draining ${manifest.id}`)
