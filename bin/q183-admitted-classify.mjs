#!/usr/bin/env node
// q-183: read-only, per-seat classifier for the admitted queue and the broker spool.
// It writes nothing, and prints counts, ages and envelope ids, never message content.
//
//   node bin/q183-admitted-classify.mjs [--root /etc/nvoy/instances] [--instance ID ...]
//        [--harness-home ID=PATH ...] [--ids N]
//
// Each admitted row (runtimeDir/admitted-tasks.jsonl, appended only by instance-adapter.mjs)
// falls in exactly one class:
//   notification  a verified-notification row: delivered for reading, no answer expected
//   answered      a reply was published: stateDir/receipts/<envelope>.<request>.used exists
//   terminal      a reply request for it ended terminally (stateDir/terminal-replies.jsonl)
//   read          a consumer marked it read or consumed, but no reply was published
//   delivered     a consumer took it (Codex turn, Desktop delivery, remote import), not yet read
//   unconsumed    no consumer evidence at all
// Consumer evidence is the union of every cursor nvoy writes, whichever harness the seat runs;
// the codex harness cursor lives in the harness home, so it is read only with --harness-home.
// Spool markers (spoolDir/<64hex>[.buzz].pending|.inflight|.inflight.done) are counted by state,
// and .done markers are split by whether their envelope reached the admitted queue.
import { lstatSync, readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'

const HEX64 = /^[0-9a-f]{64}$/
const MARKER = /^([0-9a-f]{64})(\.buzz)?\.(pending|inflight|inflight\.done)$/
const REQUEST = /^[0-9a-f]{32}$/
const RECEIPT_USED = /^([0-9a-f]{64})\.[0-9a-f]{32}\.used$/
export const MAX_IDS = 1000
export const CLASSES = ['notification', 'answered', 'terminal', 'read', 'delivered', 'unconsumed']

export function options(argv) {
  const out = { root: process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances', instances: [], harnessHomes: {}, ids: 20 }
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i], value = argv[i + 1]
    if (!['--root', '--instance', '--harness-home', '--ids'].includes(key)) throw new Error(`unknown option ${key}`)
    if (value === undefined || value.startsWith('--')) throw new Error(`${key} needs a value`)
    i++
    if (key === '--root') out.root = value
    else if (key === '--instance') out.instances.push(value)
    else if (key === '--ids') {
      if (!/^\d{1,4}$/.test(value) || Number(value) > MAX_IDS) throw new Error(`--ids needs a whole number from 0 to ${MAX_IDS}`)
      out.ids = Number(value)
    } else {
      const at = value.indexOf('=')
      if (at < 1 || !value.slice(at + 1).startsWith('/')) throw new Error('--harness-home needs ID=/absolute/path')
      out.harnessHomes[value.slice(0, at)] = value.slice(at + 1)
    }
  }
  return out
}

// Parses a JSONL file without keeping any field but those asked for. A missing file is empty;
// a bad line is counted, never quoted.
export function jsonl(path, pick, read = readFileSync) {
  let text
  try { text = read(path, 'utf8') } catch (error) {
    if (error?.code === 'ENOENT') return { rows: [], bad: 0, missing: true }
    throw new Error(`cannot read ${path}: ${error.code || error.message}`)
  }
  const rows = []
  let bad = 0
  for (const line of text.split('\n')) {
    if (!line.trim()) continue
    try { const row = pick(JSON.parse(line)); if (row) rows.push(row) } catch { bad++ }
  }
  return { rows, bad, missing: false }
}

const envelopeOf = row => (typeof row?.envelope === 'string' && HEX64.test(row.envelope) ? row.envelope : null)

// Pure: everything already read, one seat's classes and spool counts.
export function classify({ admitted, consumed, delivered, answered, terminalRequests, replyRequests, markers, now, ids = 20 }) {
  const terminalEnvelopes = new Set(replyRequests.filter(r => terminalRequests.has(r.id)).map(r => r.receipt))
  const classes = Object.fromEntries(CLASSES.map(name => [name, { count: 0, oldest_at: null, envelopes: [] }]))
  const admittedSet = new Set()
  for (const row of admitted) {
    if (admittedSet.has(row.envelope)) continue
    admittedSet.add(row.envelope)
    const name = row.type === 'verified-notification' ? 'notification'
      : answered.has(row.envelope) ? 'answered'
        : terminalEnvelopes.has(row.envelope) ? 'terminal'
          : consumed.has(row.envelope) ? 'read'
            : delivered.has(row.envelope) ? 'delivered' : 'unconsumed'
    const c = classes[name]
    c.count++
    if (row.at && (!c.oldest_at || row.at < c.oldest_at)) c.oldest_at = row.at
    if (c.envelopes.length < ids) c.envelopes.push(row.envelope)
  }
  const spool = { pending: 0, inflight: 0, done: 0, done_admitted: 0, done_not_admitted: 0, oldest_pending_at: null, oldest_done_at: null }
  for (const m of markers) {
    if (m.state === 'inflight.done') {
      spool.done++
      admittedSet.has(m.envelope) ? spool.done_admitted++ : spool.done_not_admitted++
      if (!spool.oldest_done_at || m.mtime < spool.oldest_done_at) spool.oldest_done_at = m.mtime
    } else {
      spool[m.state]++
      if (m.state === 'pending' && (!spool.oldest_pending_at || m.mtime < spool.oldest_pending_at)) spool.oldest_pending_at = m.mtime
    }
  }
  const unconsumedOldest = classes.unconsumed.oldest_at
  return {
    admitted_rows: admitted.length,
    admitted_envelopes: admittedSet.size,
    classes,
    spool,
    unconsumed_oldest_age_h: unconsumedOldest ? Math.round((now - Date.parse(unconsumedOldest)) / 36e5 * 10) / 10 : null,
  }
}

const iso = ms => (Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString() : null)

function listDir(path) {
  try { return readdirSync(path) } catch (error) {
    if (error?.code === 'ENOENT') return []
    throw new Error(`cannot list ${path}: ${error.code || error.message}`)
  }
}

// Reads one seat's files; returns the classify() input and per-source read notes.
export function collect(manifest, harnessHome) {
  const run = p => resolve(manifest.runtimeDir, p), state = p => resolve(manifest.stateDir, p)
  const sources = {}
  const load = (label, path, pick) => {
    const r = jsonl(path, pick)
    sources[label] = r.missing ? 'absent' : { rows: r.rows.length, bad_lines: r.bad }
    return r.rows
  }
  const admitted = load('admitted-tasks', run('admitted-tasks.jsonl'), row => {
    const envelope = envelopeOf(row)
    if (!envelope) return null
    const checked = Number(row.authority?.policy_checked_at)
    return { envelope, type: row.type, at: iso(checked) }
  })
  const envelopes = row => envelopeOf(row) && { envelope: row.envelope }
  const consumed = new Set([
    ...load('claude-read', run('claude-channel-state/read.jsonl'), envelopes),
    ...load('codex-mcp-read', run('codex-mcp-state/read.jsonl'), envelopes),
    ...load('worker-consumed', run('worker-consumed.jsonl'), envelopes),
    ...load('macos-desktop-completed', run('macos-desktop-completed.jsonl'), envelopes),
  ].map(r => r.envelope))
  const delivered = new Set([
    ...load('codex-app-server-delivered', run('codex-app-server-delivered.jsonl'), envelopes),
    ...load('macos-desktop-visible', run('macos-desktop-visible.jsonl'), envelopes),
    ...load('remote-imported', run('remote-imported.jsonl'), envelopes),
    ...(harnessHome ? load('codex-harness-delivered', resolve(harnessHome, '.nvoy-harness/delivered.jsonl'), envelopes) : []),
  ].map(r => r.envelope))
  // Only id and receipt are kept from a reply request; its content is never held or printed.
  const request = row => (REQUEST.test(String(row?.id || '')) && HEX64.test(String(row?.receipt || '')) ? { id: row.id, receipt: row.receipt } : null)
  const replyRequests = [
    ...load('reply-requests', run('reply-requests.jsonl'), request),
    ...load('desktop-reply-requests', run('desktop-reply-requests.jsonl'), request),
  ]
  // Same row test as reply_retry.mjs loadTerminalReplyIds.
  const terminalRequests = new Set(load('terminal-replies', state('terminal-replies.jsonl'),
    row => (row?.version === 1 && row?.type === 'terminal-reply' && REQUEST.test(String(row.id || '')) ? { id: row.id } : null)).map(r => r.id))
  const answered = new Set(listDir(state('receipts')).map(name => RECEIPT_USED.exec(name)?.[1]).filter(Boolean))
  const markers = []
  for (const name of listDir(manifest.spoolDir)) {
    const m = MARKER.exec(name)
    if (!m) continue
    let mtime
    try { mtime = lstatSync(resolve(manifest.spoolDir, name)).mtimeMs } catch { continue }
    markers.push({ envelope: m[1], state: m[3], mtime: iso(mtime) })
  }
  sources.receipts_used = answered.size
  sources.spool_markers = markers.length
  return { input: { admitted, consumed, delivered, answered, terminalRequests, replyRequests, markers }, sources }
}

// A seat error is printed as a fixed reason only: a parser message (for example a manifest that is
// not valid JSON) can quote the file it read, and this runs as root over every seat.
export function safeError(error) {
  if (typeof error?.code === 'string' && /^E[A-Z]+$/.test(error.code)) return `cannot read (${error.code})`
  const head = String(error?.message || '').split(':')[0]
  return /^[a-z][a-z0-9 ,._/()-]{0,119}$/i.test(head) ? head : 'unreadable (details withheld)'
}

function instanceIds(root) {
  return listDir(root).filter(name => name.endsWith('.json')).map(name => name.slice(0, -5)).sort()
}

export function run(argv, { log = line => console.log(line), now = Date.now(), readSeat = readManifest, collectSeat = collect } = {}) {
  const opts = options(argv)
  const ids = opts.instances.length ? opts.instances : instanceIds(opts.root)
  const seats = {}
  for (const id of ids) {
    try {
      const manifest = readSeat(opts.root, id)
      const { input, sources } = collectSeat(manifest, opts.harnessHomes[id])
      seats[id] = { harness: manifest.harness?.runner || null, delivery_mode: manifest.deliveryMode || null, ...classify({ ...input, now, ids: opts.ids }), sources }
    } catch (error) {
      seats[id] = { error: safeError(error) }
    }
  }
  log(JSON.stringify({ read_at: new Date(now).toISOString(), root: opts.root, read_only: true, seats }, null, 2))
  return seats
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try { run(process.argv.slice(2)) } catch (error) {
    console.error(`q183-admitted-classify: ${error?.message || error}`)
    process.exitCode = 1
  }
}
