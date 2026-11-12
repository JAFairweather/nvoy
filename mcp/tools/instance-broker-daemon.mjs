#!/usr/bin/env node
// instance-broker-daemon.mjs — supervisor entrypoint for one keyed broker identity (#44).
// It owns no relay subscription. It serially drains only this manifest's opaque pending markers;
// crash-left `.inflight` markers are requeued at boot and are harmless because the adapter queue
// deduplicates on envelope before ACKing.

import { appendFileSync, existsSync, readdirSync, renameSync, readFileSync, lstatSync, rmSync } from 'node:fs'
import { resolve } from 'node:path'
import { spawn, spawnSync } from 'node:child_process'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { isTerminalReplyFailure, loadTerminalReplyIds, recordTerminalReply, terminalReplyReason } from './reply_retry.mjs'
import { childVerdict } from './broker_verdict.mjs'
import { finishedProfileRequests, PROFILE_PUBLIC_RETRY_EXIT } from './agent_profile.mjs'
import { MEMORY_REQUEST_FILE, memoryQueueDir } from './agent_memory.mjs'

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
// Agent-initiated posts (nvoy_channel_post). A refusal by the manifest or the hourly cap is final:
// recorded by id, with no content, so the queue is not re-proposed every tick or after a restart.
const terminalPostsPath = resolve(manifest.stateDir, 'terminal-posts.jsonl')
const postDone = new Set()
try {
  for (const line of readFileSync(terminalPostsPath, 'utf8').split('\n')) {
    try { const x = JSON.parse(line); if (x?.type === 'terminal-post' && /^[0-9a-f]{32}$/.test(String(x.id))) postDone.add(x.id) } catch { /* partial line */ }
  }
} catch (e) { if (e.code !== 'ENOENT') die(`cannot load terminal post log: ${e.message}`) }
const isTerminalPost = stderr => /post refused:|post request has an invalid|post record does not bind/.test(stderr)
// Agent memory writes (memory_claim, memory_withdraw), terminal on the same terms as posts.
const terminalMemoryPath = resolve(manifest.stateDir, 'terminal-memory.jsonl')
const memoryDone = new Set()
try {
  for (const line of readFileSync(terminalMemoryPath, 'utf8').split('\n')) {
    try { const x = JSON.parse(line); if (x?.type === 'terminal-memory' && /^[0-9a-f]{32}$/.test(String(x.id))) memoryDone.add(x.id) } catch { /* partial line */ }
  }
} catch (e) { if (e.code !== 'ENOENT') die(`cannot load terminal memory log: ${e.message}`) }
const isTerminalMemory = stderr => /memory refused:|memory request has an invalid|memory record does not bind/.test(stderr)
const profileDone = new Set()
const profileRetryAfter = new Map()
let profileActive = null
// Public relays still pending are tried again on a slow clock, across restarts.
const PROFILE_PUBLIC_RETRY_MS = 10 * 60 * 1000
if (manifest.maySetProfile) {
  try {
    for (const request of finishedProfileRequests(readFileSync(resolve(manifest.runtimeDir, 'profile-results.jsonl'), 'utf8'))) profileDone.add(request)
  } catch (error) { if (error.code !== 'ENOENT') die(`cannot load profile results: ${error.message}`) }
}

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
    const verdict = childVerdict(r)
    if (r.status !== 0) {
      retryAfter.set(key, Date.now() + 5000)
      console.error(`instance-broker-daemon: ${item.envelope.slice(0, 12)}… held for retry: ${verdict.join(' | ') || `exit ${r.status ?? 'signal'}: ${String(r.stderr || '').trim().slice(0, 240)}`}`)
    } else {
      retryAfter.delete(key)
      // The funnel's only record of what became of a heard message: admitted, or why not.
      for (const line of verdict) console.log(`instance-broker-daemon: ${line}`)
    }
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
                console.error(`instance-broker-daemon: ${source} reply proposal ${request.slice(0, 12)}… terminal (${terminalReplyReason(stderr)})`)
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
                  console.error(`instance-broker-daemon: ${source} reply ${request.slice(0, 12)}… terminal (${terminalReplyReason(stderr)})`)
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
function drainPosts() {
  const queue = resolve(manifest.runtimeDir, 'post-requests.jsonl')
  let ids
  try {
    const st = lstatSync(queue)
    if (!st.isFile() || st.isSymbolicLink()) throw new Error('post queue is not a regular file')
    ids = new Set(readFileSync(queue, 'utf8').split('\n').flatMap(line => { try { const x = JSON.parse(line); return /^[0-9a-f]{32}$/.test(String(x?.id)) ? [x.id] : [] } catch { return [] } }))
  } catch (e) { if (e.code !== 'ENOENT') console.error(`instance-broker-daemon: post queue unavailable: ${e.message}`); return }
  for (const request of ids) {
    const key = `post:${request}`
    if (postDone.has(request) || (proposalRetryAfter.get(key) || 0) > Date.now()) continue
    const r = spawnSync(process.execPath, [resolve(new URL('.', import.meta.url).pathname, 'instance-broker-post.mjs'),
      '--instance', manifest.id, '--request', request], { env: childEnv, encoding: 'utf8', timeout: 90000 })
    const stderr = String(r.stderr || '').trim()
    if (r.status === 0) { postDone.add(request); proposalRetryAfter.delete(key); if (/^instance-broker-post: posted/.test(r.stdout)) console.log(r.stdout.trim()); continue }
    if (isTerminalPost(stderr)) {
      postDone.add(request)
      try { appendFileSync(terminalPostsPath, JSON.stringify({ version: 1, type: 'terminal-post', id: request, at: Date.now() }) + '\n', { mode: 0o600 }) }
      catch (e) { console.error(`instance-broker-daemon: cannot record terminal post ${request.slice(0, 12)}…: ${e.message}`) }
      console.error(`instance-broker-daemon: post ${request.slice(0, 12)}… terminal: ${stderr.replace(/^instance-broker-post: /, '')}`)
      continue
    }
    proposalRetryAfter.set(key, Date.now() + 5000)
    console.error(`instance-broker-daemon: post ${request.slice(0, 12)}… held for retry: ${stderr}`)
  }
}
// The spool holds one <id>.json per request. Success and terminal outcomes unlink it, so the
// claim text lives on this host only while a write is pending; a .tmp the writer never renamed is
// swept once it is stale.
const STALE_MEMORY_TMP_MS = 5 * 60 * 1000
const MEMORY_RECORD_KEEP_MS = 30 * 24 * 3600 * 1000
let memoryRecordsSweptAt = 0
// A scrubbed enactment record keeps only ids and times; after 30 days it goes too. A record still
// holding an event is pending and is never swept.
function sweepMemoryRecords() {
  if (Date.now() - memoryRecordsSweptAt < 3600 * 1000) return
  memoryRecordsSweptAt = Date.now()
  const dir = resolve(manifest.stateDir, 'memory')
  let names
  try { names = readdirSync(dir) } catch { return }
  for (const name of names) {
    if (!MEMORY_REQUEST_FILE.test(name)) continue
    try {
      const path = resolve(dir, name), x = JSON.parse(readFileSync(path, 'utf8'))
      const at = x?.published === true ? x.published_at : x?.refused_at
      if (!x?.unsigned_event && !x?.event && Number.isFinite(at) && Date.now() - at > MEMORY_RECORD_KEEP_MS) rmSync(path, { force: true })
    } catch { /* unreadable records are left for the operator */ }
  }
}
function drainMemory() {
  sweepMemoryRecords()
  const dir = memoryQueueDir(manifest)
  let names
  try {
    const st = lstatSync(dir)
    if (!st.isDirectory() || st.isSymbolicLink()) throw new Error('memory spool is not a directory')
    names = readdirSync(dir)
  } catch (e) { if (e.code !== 'ENOENT') console.error(`instance-broker-daemon: memory spool unavailable: ${e.message}`); return }
  const unlink = name => { try { rmSync(resolve(dir, name), { force: true }) } catch (e) { console.error(`instance-broker-daemon: cannot unlink memory spool ${name.slice(0, 12)}…: ${e.code || e.message}`) } }
  for (const name of names) {
    if (!name.endsWith('.tmp')) continue
    try { if (Date.now() - lstatSync(resolve(dir, name)).mtimeMs > STALE_MEMORY_TMP_MS) unlink(name) } catch { /* already gone */ }
  }
  for (const name of names) {
    if (!MEMORY_REQUEST_FILE.test(name)) continue
    const request = name.slice(0, 32), key = `memory:${request}`
    if (memoryDone.has(request)) { unlink(name); continue }
    if ((proposalRetryAfter.get(key) || 0) > Date.now()) continue
    const r = spawnSync(process.execPath, [resolve(new URL('.', import.meta.url).pathname, 'instance-broker-memory.mjs'),
      '--instance', manifest.id, '--request', request], { env: childEnv, encoding: 'utf8', timeout: 90000 })
    const stderr = String(r.stderr || '').trim()
    if (r.status === 0) {
      memoryDone.add(request); proposalRetryAfter.delete(key); unlink(name)
      if (/^instance-broker-memory: (claimed|withdrew)/.test(r.stdout)) console.log(r.stdout.trim())
      continue
    }
    if (isTerminalMemory(stderr)) {
      memoryDone.add(request)
      try { appendFileSync(terminalMemoryPath, JSON.stringify({ version: 1, type: 'terminal-memory', id: request, at: Date.now() }) + '\n', { mode: 0o600 }) }
      catch (e) { console.error(`instance-broker-daemon: cannot record terminal memory write ${request.slice(0, 12)}…: ${e.message}`) }
      unlink(name)
      console.error(`instance-broker-daemon: memory ${request.slice(0, 12)}… terminal: ${stderr.replace(/^instance-broker-memory: /, '')}`)
      continue
    }
    proposalRetryAfter.set(key, Date.now() + 5000)
    console.error(`instance-broker-daemon: memory ${request.slice(0, 12)}… held for retry: ${stderr}`)
  }
}
function drainProfiles() {
  if (profileActive) return
  let ids
  try {
    const path = resolve(manifest.runtimeDir, 'profile-requests.jsonl'), stat = lstatSync(path)
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 64 * 1024 * 1024) throw new Error('profile queue is invalid')
    ids = new Set(readFileSync(path, 'utf8').split('\n').flatMap(line => {
      try { const row = JSON.parse(line); return /^[0-9a-f]{32}$/.test(String(row?.id)) ? [row.id] : [] } catch { return [] }
    }))
  } catch (error) { console.error(`instance-broker-daemon: profile queue unavailable: ${error.message}`); return }
  for (const request of ids) {
    if (profileDone.has(request) || (profileRetryAfter.get(request) || 0) > Date.now()) continue
    const child = spawn(process.execPath, [resolve(new URL('.', import.meta.url).pathname, 'instance-broker-profile.mjs'),
      '--instance', manifest.id, '--request', request], { env: childEnv, stdio: ['ignore', 'ignore', 'pipe'] })
    profileActive = request
    let stderr = '', settled = false
    child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-240) })
    const timeout = setTimeout(() => child.kill('SIGKILL'), 90000)
    const complete = (code, error) => {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      profileActive = null
      if (code === 0) {
        profileDone.add(request)
        profileRetryAfter.delete(request)
        console.log(`instance-broker-daemon: profile ${request.slice(0, 12)}… complete`)
      } else if (code === PROFILE_PUBLIC_RETRY_EXIT) {
        profileRetryAfter.set(request, Date.now() + PROFILE_PUBLIC_RETRY_MS)
        console.log(`instance-broker-daemon: profile ${request.slice(0, 12)}… on Buzz; public relays pending, retrying in 10 min`)
      } else {
        profileRetryAfter.set(request, Date.now() + 5000)
        console.error(`instance-broker-daemon: profile ${request.slice(0, 12)}… held for retry: ${String(error?.message || stderr || `exit ${code}`).trim().slice(0, 240)}`)
      }
    }
    child.on('error', error => complete(null, error))
    child.on('exit', code => complete(code))
    break
  }
}
// The keyless Buzz watcher can log in only through this oracle, and the status keeper puts the
// native 👀/💬 on admitted Buzz messages. Both are supervised here, beside the drain, so they run as
// the broker and hold the same credential; a crash is restarted with backoff.
function supervise(script, label, delay = 1000) {
  const child = spawn(process.execPath, [resolve(new URL('.', import.meta.url).pathname, script), '--instance', manifest.id],
    { env: childEnv, stdio: ['ignore', 'inherit', 'inherit'] })
  const started = Date.now()
  child.on('exit', code => {
    const next = Date.now() - started > 60000 ? 1000 : Math.min(delay * 2, 60000)
    console.error(`instance-broker-daemon: ${label} exited (${code ?? 'signal'}); restarting in ${next / 1000}s`)
    setTimeout(() => supervise(script, label, next), next).unref?.()
  })
}
// The agent card is checked at start and hourly; the child re-signs only when the card is due.
function publishCard() {
  const child = spawn(process.execPath, [resolve(new URL('.', import.meta.url).pathname, 'instance-broker-card.mjs'), '--instance', manifest.id],
    { env: childEnv, stdio: ['ignore', 'inherit', 'inherit'] })
  const timeout = setTimeout(() => child.kill('SIGKILL'), 90000)
  const complete = code => { clearTimeout(timeout); if (code !== 0) console.error(`instance-broker-daemon: agent card unconfirmed (${code ?? 'signal'}); next check in an hour`) }
  child.on('error', () => complete(null))
  child.on('exit', complete)
}
// Channel presence (waggle #721 step 4): every 30 s, only when the host collector has written this
// instance's snapshot. The child signs only on a change or a refresh, and never on an unproven read.
let presenceRunning = false
function publishPresence() {
  if (presenceRunning) return
  const dir = process.env.NVOY_PRESENCE_DIR || '/run/nvoy-presence'
  if (!existsSync(resolve(dir, `${manifest.id}.json`))) return
  presenceRunning = true
  const child = spawn(process.execPath, [resolve(new URL('.', import.meta.url).pathname, 'instance-broker-presence.mjs'), '--instance', manifest.id],
    { env: childEnv, stdio: ['ignore', 'inherit', 'inherit'] })
  const timeout = setTimeout(() => child.kill('SIGKILL'), 60000)
  const complete = code => { clearTimeout(timeout); presenceRunning = false; if (code !== 0) console.error(`instance-broker-daemon: presence unconfirmed (${code ?? 'signal'}); retrying the same event in 30 s`) }
  child.on('error', () => complete(null))
  child.on('exit', complete)
}
// Room members for the channel MCPs' mention lists (#321): at start and every five minutes.
function refreshRooms() {
  const child = spawn(process.execPath, [resolve(new URL('.', import.meta.url).pathname, 'instance-broker-rooms.mjs'), '--instance', manifest.id],
    { env: childEnv, stdio: ['ignore', 'inherit', 'inherit'] })
  const timeout = setTimeout(() => child.kill('SIGKILL'), 90000)
  const complete = code => { clearTimeout(timeout); if (code !== 0) console.error(`instance-broker-daemon: room members unrefreshed (${code ?? 'signal'}); next read in five minutes`) }
  child.on('error', () => complete(null))
  child.on('exit', complete)
}
recover()
if (manifest.mayPost?.mentionRooms) { refreshRooms(); setInterval(refreshRooms, 5 * 60 * 1000) }
if (manifest.agentCard) { publishCard(); setInterval(publishCard, 60 * 60 * 1000) }
publishPresence(); setInterval(publishPresence, 30 * 1000)
if (manifest.buzz) supervise('instance-broker-auth.mjs', 'AUTH oracle')
if (manifest.buzz?.statusReactions) supervise('instance-broker-status.mjs', 'status keeper')
drain()
setInterval(drain, 1000)
if (manifest.mayPost) { drainPosts(); setInterval(drainPosts, 1000) }
if (manifest.mayRemember) { drainMemory(); setInterval(drainMemory, 1000) }
if (manifest.maySetProfile) { drainProfiles(); setInterval(drainProfiles, 1000) }
console.log(`instance-broker-daemon: draining ${manifest.id}`)
