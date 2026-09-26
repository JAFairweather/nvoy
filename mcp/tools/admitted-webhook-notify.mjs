#!/usr/bin/env node
// The webhook wake for one identity whose harness is hosted somewhere that cannot hold an SSH stream
// (a bot whose routine runs when an HTTPS webhook fires). It runs on the fleet as the `notifier`
// service, follows the instance's admitted queue, and for each new envelope sends one HTTPS POST whose
// body is {"instance", "envelope", "type", "at"} and nothing else. The message stays on the fleet: the
// woken harness reads it with nvoy_channel_read over its channel key, as any other harness does.
//
// Cursor: an envelope id in <runtime>/wake-webhook-state/state.json, advanced once an envelope's first
// POST is settled (answered 2xx, or given up after --attempts). The first start baselines at the
// queue's end, so history is never posted. A kill mid-POST re-posts that envelope on restart.
//
// Re-notify: a harness woken inside the fleet channel's lock window (its previous session's lock is
// still held) drains nothing and nothing retries. So an envelope still absent from the Claude
// channel's read log --renotify-ms after its last POST is posted again, at most --renotify-max times.
//
// Logs carry only `POST <envelope 8-hex> -> <status>` and error classes: never the URL, a header, a
// response body or message content.

import { lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { request } from 'node:https'
import { resolve } from 'node:path'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { claimPidLock } from './pid_lock.mjs'
import { HEX64, admittedFollower, lineFollower } from './admitted_queue.mjs'
import { MAX_HEADERS_FILE, MAX_URL_FILE, errorClass, parseWebhookHeaders, parseWebhookUrl, readCredential, wakeBody } from './wake_webhook.mjs'

const die = message => { console.error(`nvoy-wake-webhook: ${message}`); process.exit(1) }
const log = message => console.log(`nvoy-wake-webhook: ${message}`)
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const bounded = (name, fallback, min, max) => {
  const value = Number(flag(name) || fallback)
  if (!Number.isInteger(value) || value < min || value > max) die(`${name} must be ${min}..${max}`)
  return value
}
const id = flag('--instance')
if (!id) die('usage: --instance <id> [--poll-ms n] [--timeout-ms n] [--attempts n] [--retry-ms n] [--retry-max-ms n] [--renotify-ms n] [--renotify-max n]')
const pollMs = bounded('--poll-ms', 1000, 20, 60000)
const timeoutMs = bounded('--timeout-ms', 10000, 100, 60000)
const attempts = bounded('--attempts', 6, 1, 20)
const retryMs = bounded('--retry-ms', 2000, 10, 600000)
const retryMaxMs = bounded('--retry-max-ms', 60000, 10, 3600000)
const renotifyMs = bounded('--renotify-ms', 720000, 100, 86400000)
const renotifyMax = bounded('--renotify-max', 2, 0, 10)
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (error) { die(error.message) }
if (!manifest.wakeWebhook) die('the manifest has no wake_webhook block')
if (manifest.brokerMode !== 'local' || manifest.deliveryMode !== 'notify_only' || manifest.workerEnabled) {
  die('the wake webhook requires a local-broker, worker-disabled notify_only manifest')
}
// The worker UID is the one that can read both the admitted queue and the channel's read log.
if (process.getuid?.() !== manifest.workerUid) die('the wake webhook notifier must run as the manifest-bound worker user')

let url, headers
try {
  url = parseWebhookUrl(readCredential(process.env.NVOY_WAKE_WEBHOOK_URL_FILE || manifest.wakeWebhook.urlRef, 'wake webhook URL file', MAX_URL_FILE))
  headers = parseWebhookHeaders(readCredential(process.env.NVOY_WAKE_WEBHOOK_HEADERS_FILE || manifest.wakeWebhook.headersRef, 'wake webhook headers file', MAX_HEADERS_FILE))
} catch (error) { die(error.message) }

const stateDir = resolve(manifest.runtimeDir, 'wake-webhook-state')
try {
  let st
  try { st = lstatSync(stateDir) } catch { mkdirSync(stateDir, { mode: 0o700 }); st = lstatSync(stateDir) }
  if (!st.isDirectory() || st.isSymbolicLink()) throw new Error('wake webhook state must be a directory, never a symlink')
} catch (error) { die(error.message) }
let release
try { release = claimPidLock(resolve(stateDir, 'notifier.lock'), manifest.id, 'wake webhook notifier') } catch (error) { die(error.message) }
process.on('exit', () => release())
for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.on(signal, () => process.exit(0))

const MAX_STATE = 1024 * 1024, MAX_WATCH = 256, MAX_READ_IDS = 100000
const statePath = resolve(stateDir, 'state.json')
const short = envelope => envelope ? envelope.slice(0, 8) : 'the empty queue'
const sleep = ms => new Promise(done => setTimeout(done, ms))

function loadState() {
  let st
  try { st = lstatSync(statePath) } catch { return null }
  if (!st.isFile() || st.isSymbolicLink() || st.size > MAX_STATE) throw new Error('wake webhook state must be a bounded regular file')
  let raw
  try { raw = JSON.parse(readFileSync(statePath, 'utf8')) } catch { throw new Error('wake webhook state is not valid JSON') }
  const entry = w => HEX64.test(String(w?.envelope || '')) && ['admitted-task', 'verified-notification'].includes(w.type) &&
    (w.at === null || Number.isFinite(w.at)) && Number.isInteger(w.posts) && w.posts >= 1 && Number.isFinite(w.last)
  if (raw?.version !== 1 || raw.instance !== manifest.id || !(raw.cursor === null || HEX64.test(String(raw.cursor))) ||
      !Array.isArray(raw.watch) || raw.watch.length > MAX_WATCH || !raw.watch.every(entry)) {
    throw new Error('wake webhook state is invalid; remove it to re-baseline at the queue end')
  }
  return { version: 1, instance: manifest.id, cursor: raw.cursor, watch: raw.watch.map(({ envelope, type, at, posts, last }) => ({ envelope, type, at, posts, last })) }
}
function saveState() {
  const tmp = `${statePath}.${process.pid}.tmp`
  writeFileSync(tmp, JSON.stringify(state) + '\n', { mode: 0o600 })
  renameSync(tmp, statePath)
}

const readQueue = admittedFollower(resolve(manifest.runtimeDir, 'admitted-tasks.jsonl'))
const readLog = lineFollower(resolve(manifest.runtimeDir, 'claude-channel-state', 'read.jsonl'), 'Claude channel read log')
const readIds = new Set()
let readLogFault = ''
function refreshRead() {
  let next
  try { next = readLog() } catch (error) {
    if (readLogFault !== error.message) log(`read log unavailable (${error.message}); re-notify treats nothing as read`)
    readLogFault = error.message
    return
  }
  readLogFault = ''
  if (next.reset) readIds.clear()
  for (const line of next.lines) {
    let row
    try { row = JSON.parse(line) } catch { continue }
    if (row?.instance !== manifest.id || !HEX64.test(String(row?.envelope || ''))) continue
    readIds.delete(row.envelope); readIds.add(row.envelope)
    if (readIds.size > MAX_READ_IDS) readIds.delete(readIds.values().next().value)
  }
}

let state, pending = [], lastSeen = null
const queuedRenotify = new Set()
try {
  state = loadState()
  const { rows } = readQueue()
  lastSeen = rows.at(-1)?.envelope ?? null
  if (!state) {
    state = { version: 1, instance: manifest.id, cursor: lastSeen, watch: [] }
    saveState()
    log(`baselined at ${short(lastSeen)}; earlier envelopes are not posted`)
  } else if (state.cursor === null) {
    pending = rows
  } else {
    const at = rows.map(row => row.envelope).lastIndexOf(state.cursor)
    if (at >= 0) pending = rows.slice(at + 1)
    else { log('cursor is not in the admitted queue; starting from its end'); state.cursor = lastSeen; saveState() }
  }
} catch (error) { die(error.message) }

function poll() {
  let next
  try { next = readQueue() } catch (error) { die(error.message) }
  // A rewritten queue is re-placed on the last envelope seen; failing that, from its end.
  let rows = next.rows
  if (next.reset) {
    const at = rows.map(row => row.envelope).lastIndexOf(lastSeen)
    rows = at >= 0 ? rows.slice(at + 1) : []
    if (at < 0 && next.rows.length) log('admitted queue was rewritten without the last envelope seen; continuing from its end')
  }
  pending.push(...rows)
  if (next.rows.length) lastSeen = next.rows.at(-1).envelope
  refreshRead()
  const now = Date.now(), before = state.watch.length
  state.watch = state.watch.filter(item => {
    if (readIds.has(item.envelope)) return false
    if (queuedRenotify.has(item.envelope) || now - item.last < renotifyMs) return true
    if (item.posts > renotifyMax) { log(`${short(item.envelope)} still unread after ${item.posts - 1} re-notify; stopping`); return false }
    queuedRenotify.add(item.envelope)
    pending.push({ envelope: item.envelope, type: item.type, at: item.at, renotify: true })
    return true
  })
  if (state.watch.length !== before) saveState()
}

// One fresh connection per POST: no pooled socket, no redirect followed, no proxy from the
// environment, and the response body is never read.
function post(row) {
  const body = wakeBody(manifest.id, row)
  return new Promise(done => {
    let timer
    const finish = outcome => { clearTimeout(timer); done(outcome) }
    const req = request(url, { method: 'POST', agent: false,
      headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, response => {
      finish(response.statusCode); response.destroy()
    })
    timer = setTimeout(() => { finish('timeout'); req.destroy() }, timeoutMs)
    req.on('error', error => finish(errorClass(error)))
    req.end(body)
  })
}

async function deliver(row) {
  const watched = state.watch.find(item => item.envelope === row.envelope)
  if (row.renotify && !watched) { queuedRenotify.delete(row.envelope); return }
  const label = row.renotify ? ` (re-notify ${watched.posts}/${renotifyMax})` : ''
  let delivered = false
  for (let attempt = 1; attempt <= attempts && !delivered; attempt++) {
    const outcome = await post(row)
    delivered = Number.isInteger(outcome) && outcome >= 200 && outcome < 300
    const delay = Math.min(retryMs * 2 ** (attempt - 1), retryMaxMs)
    log(`POST ${short(row.envelope)} -> ${outcome}${label}${!delivered && attempt < attempts ? `; retry in ${delay}ms` : ''}`)
    if (!delivered && attempt < attempts) await sleep(delay)
  }
  if (!delivered) log(`gave up on ${short(row.envelope)} after ${attempts} attempt(s)${label}`)
  if (row.renotify) {
    queuedRenotify.delete(row.envelope)
    watched.posts++; watched.last = Date.now()
  } else {
    state.cursor = row.envelope
    if (delivered && renotifyMax > 0) {
      state.watch.push({ envelope: row.envelope, type: row.type, at: row.at, posts: 1, last: Date.now() })
      if (state.watch.length > MAX_WATCH) log(`re-notify list is full; no longer watching ${short(state.watch.shift().envelope)}`)
    }
  }
  saveState()
}

for (;;) {
  poll()
  const row = pending.shift()
  if (!row) { await sleep(pollMs); continue }
  if (readIds.has(row.envelope) && !row.renotify) {
    log(`${short(row.envelope)} already read; not posted`)
    state.cursor = row.envelope; saveState()
    continue
  }
  try { await deliver(row) } catch (error) { die(error.message) }
}
