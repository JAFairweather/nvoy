#!/usr/bin/env node
// instance-broker-daemon.mjs — supervisor entrypoint for one keyed broker identity (#44).
// It owns no relay subscription. It serially drains only this manifest's opaque pending markers;
// crash-left `.inflight` markers are requeued at boot and are harmless because the adapter queue
// deduplicates on envelope before ACKing.

import { readdirSync, renameSync, readFileSync, lstatSync } from 'node:fs'
import { resolve } from 'node:path'
import { spawn, spawnSync } from 'node:child_process'
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
// A proposal whose admission receipt has died can never be revived, so re-proposing it re-queries
// relays once per tick forever. Terminal ids are durable: a restart must not resurrect the loop.
const terminalRepliesPath = resolve(manifest.stateDir, 'terminal-replies.jsonl')
let terminalReplyIds
try { terminalReplyIds = loadTerminalReplyIds(terminalRepliesPath) }
catch (e) { die(`cannot load terminal reply log: ${e.message || e}`) }
const broker = resolve(new URL('.', import.meta.url).pathname, 'instance-broker.mjs')
const nativeBroker = resolve(new URL('.', import.meta.url).pathname, 'instance-broker-native.mjs')
const childEnv = { PATH: process.env.PATH || '', NVOY_INSTANCE_ROOT: root, NVOY_BROKER_CREDENTIAL: process.env.NVOY_BROKER_CREDENTIAL,
  ...(process.env.NVOY_BUNKER_URI_FILE ? { NVOY_BUNKER_URI_FILE: process.env.NVOY_BUNKER_URI_FILE } : {}) }
const retryAfter = new Map()
const proposalRetryAfter = new Map()
const announcedProposals = new Set()

function recover() {
  let names = []
  try { names = readdirSync(manifest.spoolDir) } catch (e) { die(`cannot read marker spool: ${e.message}`) }
  for (const name of names) {
    const m = name.match(/^([0-9a-f]{64})(\.buzz)?\.inflight$/)
    if (!m) continue
    try { renameSync(resolve(manifest.spoolDir, name), resolve(manifest.spoolDir, `${m[1]}${m[2] || ''}.pending`)) }
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
    const m = name.match(/^([0-9a-f]{64})(\.buzz)?\.pending$/)
    if (!m) return []
    // A `.buzz` marker was heard natively on the Buzz relay; it names a channel event, not a wrap.
    if (m[2] && !manifest.buzz) return []
    let observed = 0
    try {
      const marker = JSON.parse(readFileSync(resolve(manifest.spoolDir, name), 'utf8'))
      if (String(marker.envelope || '').toLowerCase() === m[1] && Number.isFinite(Number(marker.observed_at))) observed = Number(marker.observed_at)
    } catch { /* broker deliver will validate this malformed marker before any decrypt */ }
    return [{ envelope: m[1], observed, native: Boolean(m[2]) }]
  }).sort((a, b) => b.observed - a.observed || a.envelope.localeCompare(b.envelope))
  for (const item of pending) {
    const key = `${item.native ? 'buzz:' : ''}${item.envelope}`
    if ((retryAfter.get(key) || 0) > Date.now()) continue
    const args = item.native ? [nativeBroker, 'deliver', '--instance', manifest.id, '--event', item.envelope]
      : [broker, 'deliver', '--instance', manifest.id, '--envelope', item.envelope]
    const r = spawnSync(process.execPath, args, { env: childEnv, encoding: 'utf8', timeout: 90000 })
    if (r.status !== 0) {
      retryAfter.set(key, Date.now() + 5000)
      console.error(`instance-broker-daemon: ${item.envelope.slice(0, 12)}… held for retry: ${String(r.stderr || '').trim()}`)
    } else retryAfter.delete(key)
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
        if (verdict?.approval_required === false && ['nostr-private-reply', 'buzz-channel-reply'].includes(verdict?.action)) {
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
// The keyless Buzz watcher can log in only through this oracle. It is supervised here, beside the
// drain, so it runs as the broker and holds the same credential; a crash is restarted with backoff.
function superviseAuthOracle(delay = 1000) {
  const child = spawn(process.execPath, [resolve(new URL('.', import.meta.url).pathname, 'instance-broker-auth.mjs'), '--instance', manifest.id],
    { env: childEnv, stdio: ['ignore', 'inherit', 'inherit'] })
  const started = Date.now()
  child.on('exit', code => {
    const next = Date.now() - started > 60000 ? 1000 : Math.min(delay * 2, 60000)
    console.error(`instance-broker-daemon: AUTH oracle exited (${code ?? 'signal'}); restarting in ${next / 1000}s`)
    setTimeout(() => superviseAuthOracle(next), next).unref?.()
  })
}
recover()
if (manifest.buzz) superviseAuthOracle()
drain()
setInterval(drain, 1000)
console.log(`instance-broker-daemon: draining ${manifest.id}`)
