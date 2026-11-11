// buzz_status.mjs — native Buzz status reactions, signed by the identity's own key.
//
// Buzz's own agent runner shows its state on the message it is answering: 👀 once it has the
// mention, 💬 while it works, both removed when the turn ends. A reaction is a NIP-25 kind 7 with
// exactly one `e` tag naming the message; its removal is a NIP-09 kind 5 naming the reaction. The
// relay derives the channel from the target, so neither carries `h`, `p` or `k`.
//
// Authority stays where it was. Only the broker signs, and it reacts only to the source event of an
// envelope it admitted itself, in one of its manifest's Buzz channels. The keyless side can say one
// thing — "I have started on envelope X" — and nothing about which emoji, which event or which
// relay. A deletion names only a reaction this broker signed and recorded. Every failure is logged
// by class and swallowed: a status is decoration, and it never holds up a delivery or a reply.

import { appendFileSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { verifyEvent } from 'nostr-tools/pure'

const HEX64 = /^[0-9a-f]{64}$/
export const STATUS = Object.freeze({ seen: '\u{1F440}', working: '\u{1F4AC}' })
// A turn that never replies must not leave 💬 on the message for ever. Buzz clears when the turn
// ends on any exit; the broker cannot see a turn end, so it clears what is still up after this long.
export const STATUS_STALE_MS = 20 * 60 * 1000
const KEEP_MS = 24 * 60 * 60 * 1000
// The worker can read an envelope a moment before the broker records its admission fact.
const WORKING_GRACE_MS = 60 * 1000
const CLEAR_ATTEMPTS = 3

export const statusEnabled = manifest => manifest?.buzz?.statusReactions === true
export const statusPaths = manifest => {
  const dir = resolve(manifest.stateDir, 'buzz-status')
  return { dir, facts: resolve(dir, 'facts.jsonl'), state: resolve(dir, 'state.json'), lock: resolve(dir, 'status.lock'),
    requests: resolve(manifest.runtimeDir, 'status-requests.jsonl') }
}

export function statusReactionTemplate(target, which, now = Math.floor(Date.now() / 1000)) {
  if (!HEX64.test(String(target))) throw new Error('a status reaction needs the target event id')
  if (!Object.hasOwn(STATUS, which)) throw new Error('unknown status')
  return { kind: 7, created_at: now, content: STATUS[which], tags: [['e', target]] }
}
export function statusDeletionTemplate(reaction, now = Math.floor(Date.now() / 1000)) {
  if (!HEX64.test(String(reaction))) throw new Error('a deletion needs the reaction event id')
  return { kind: 5, created_at: now, content: '', tags: [['e', reaction]] }
}

// --- broker side: durable facts the status keeper acts on -------------------------------------
// Written only by the broker's own admission and reply processes, into its private state root.
function appendFact(manifest, row) {
  const { dir, facts } = statusPaths(manifest)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  try { const st = lstatSync(facts); if (!st.isFile() || st.isSymbolicLink()) throw new Error('status fact log is not a regular file') }
  catch (e) { if (e.code !== 'ENOENT') throw e }
  appendFileSync(facts, JSON.stringify(row) + '\n', { mode: 0o600 })
}
// `channel` is where the admitted source was said; outside the manifest's Buzz channels the
// identity is not a member, so there is nothing it could react to.
export function recordStatusAdmission(manifest, { envelope, target, channel, now = Date.now() }) {
  if (!statusEnabled(manifest) || !manifest.buzz.channels.includes(channel)) return false
  if (!HEX64.test(String(envelope)) || !HEX64.test(String(target))) throw new Error('status admission needs envelope and target ids')
  appendFact(manifest, { version: 1, fact: 'admitted', envelope, target, channel, at: now })
  return true
}
export function recordStatusReplied(manifest, { envelope, now = Date.now() }) {
  if (!statusEnabled(manifest)) return false
  if (!HEX64.test(String(envelope))) throw new Error('status reply needs the envelope id')
  appendFact(manifest, { version: 1, fact: 'replied', envelope, at: now })
  return true
}
export function parseStatusFact(line, manifest) {
  let row
  try { row = JSON.parse(line) } catch { return null }
  if (row?.version !== 1 || !HEX64.test(String(row.envelope || '')) || !Number.isFinite(row.at)) return null
  if (row.fact === 'replied') return { fact: 'replied', envelope: row.envelope, at: row.at }
  if (row.fact !== 'admitted' || !HEX64.test(String(row.target || '')) || !manifest.buzz?.channels?.includes(row.channel)) return null
  return { fact: 'admitted', envelope: row.envelope, target: row.target, channel: row.channel, at: row.at }
}

// --- keyless side: "I have started on this envelope" -------------------------------------------
// Called by a channel reader on the first read of an envelope. It names the envelope and nothing
// else, and only for an instruction whose source is a Buzz message in one of this identity's
// channels. The queue is provisioned by the installer; a reader never creates it. Never throws.
export function requestWorkingStatus(manifest, record) {
  try {
    if (!statusEnabled(manifest) || record?.type !== 'admitted-task' || !HEX64.test(String(record.envelope || ''))) return false
    const a = record.authority
    if (!a || ![2, 3].includes(a.version) || !HEX64.test(String(a.source_event || '')) || !manifest.buzz.channels.includes(a.reply_channel)) return false
    const { requests } = statusPaths(manifest)
    const st = lstatSync(requests)
    if (!st.isFile() || st.isSymbolicLink()) return false
    appendFileSync(requests, JSON.stringify({ version: 1, type: 'status-request', instance: manifest.id, envelope: record.envelope, state: 'working' }) + '\n')
    return true
  } catch { return false }
}
export function parseStatusRequest(line, manifest) {
  let row
  try { row = JSON.parse(line) } catch { return null }
  if (!row || typeof row !== 'object' || Array.isArray(row)) return null
  if (Object.keys(row).some(k => !['version', 'type', 'instance', 'envelope', 'state'].includes(k))) return null
  if (row.version !== 1 || row.type !== 'status-request' || row.instance !== manifest.id || row.state !== 'working' || !HEX64.test(String(row.envelope || ''))) return null
  return row.envelope
}

// A failure class, never a message body, relay payload or credential.
export function classifyFailure(error) {
  const m = String(error?.message || error || '')
  if (/^bunker: /.test(m)) return 'bunker-refused'
  if (/nip46 \w+ timed out/.test(m)) return 'signer-timeout'
  if (/nip46|signer/i.test(m)) return 'signer-unavailable'
  if (/AUTH refused/.test(m)) return 'auth-refused'
  if (/timed out/.test(m)) return 'relay-timeout'
  return 'relay-unavailable'
}

const cleanCopy = ({ id, pubkey, created_at, kind, tags, content, sig }) => ({ id, pubkey, created_at, kind, tags, content, sig })

// The single writer of the reaction state. `openSession` returns an authenticated Buzz session
// (openBuzzSession in production); it is opened lazily and closed again when idle.
export function createStatusKeeper({ manifest, signer, openSession, now = () => Date.now(), log = line => console.error(line), idleMs = 60000 }) {
  const me = manifest.pubkey
  const { dir, state: statePath } = statusPaths(manifest)
  let state = { version: 1, envelopes: {} }
  try {
    const st = lstatSync(statePath)
    if (!st.isFile() || st.isSymbolicLink()) throw new Error('status state is not a regular file')
    const loaded = JSON.parse(readFileSync(statePath, 'utf8'))
    if (loaded?.version === 1 && loaded.envelopes && typeof loaded.envelopes === 'object') state = loaded
  } catch (e) { if (e.code !== 'ENOENT') throw e }
  const save = () => {
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const tmp = `${statePath}.${process.pid}.tmp`
    writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 })
    renameSync(tmp, statePath)
  }
  const pendingWorking = new Map()
  const refusalAnnounced = new Set()
  let session = null, lastUsed = 0

  const dropSession = () => { const s = session; session = null; try { s?.close() } catch { /* already gone */ } }
  async function publish(ev) {
    if (!session) {
      const s = await openSession()
      session = s
      s.closed?.then(() => { if (session === s) session = null })
    }
    lastUsed = now()
    try { return await session.publishSigned(ev) } catch (e) { dropSession(); throw e }
  }
  async function sign(template) {
    const ev = await signer.signEvent(template)
    if (ev?.pubkey !== me || ev.kind !== template.kind || ev.content !== template.content ||
        JSON.stringify(ev.tags) !== JSON.stringify(template.tags) || !verifyEvent(cleanCopy(ev))) throw new Error('signer returned a different event')
    return cleanCopy(ev)
  }
  function fail(label, envelope, kind, error) {
    const cls = typeof error === 'string' ? error : classifyFailure(error)
    log(`status[${label}] ${envelope.slice(0, 12)} failed: ${cls}`)
    if (cls === 'bunker-refused' && !refusalAnnounced.has(kind)) {
      refusalAnnounced.add(kind)
      log(`status: Bunker refused kind ${kind} — widen the pairing's permissions to sign kinds 7 and 5; delivery and replies continue`)
    }
    return cls
  }

  // At most once per envelope and status: the slot is recorded before the signer is asked, and the
  // signed event before it is published, so a restart neither signs a second reaction nor loses the
  // id it must later delete.
  async function react(envelope, entry, which) {
    if (entry[which] || entry.cleared_at) return
    const slot = entry[which] = { at: now() }
    save()
    try { slot.event = await sign(statusReactionTemplate(entry.target, which, Math.floor(now() / 1000))) }
    catch (e) { slot.failed = fail(STATUS[which], envelope, 7, e); save(); return }
    save()
    try {
      const r = await publish(slot.event)
      slot.published = r.accepted === true
      if (!slot.published) slot.failed = fail(STATUS[which], envelope, 7, 'relay-refused')
    } catch (e) { slot.failed = fail(STATUS[which], envelope, 7, e) }
    save()
  }

  // Removal names only reactions this keeper signed. A deletion is signed once and its publish
  // retried a bounded number of times; republishing the same event is idempotent at the relay.
  async function clear(envelope, entry, reason) {
    if (!entry.cleared_at) {
      entry.cleared_at = now(); entry.cleared_by = reason
      // A reaction the relay refused outright is not there to remove.
      entry.deletions = ['seen', 'working'].filter(w => entry[w]?.event && entry[w].failed !== 'relay-refused').map(w => ({ which: w, target: entry[w].event.id, attempts: 0 }))
      save()
    }
    for (const d of entry.deletions) {
      if (d.done || d.attempts >= CLEAR_ATTEMPTS || d.failed === 'bunker-refused') continue
      d.attempts++
      const label = `clear ${STATUS[d.which]}`
      if (!d.event) {
        try { d.event = await sign(statusDeletionTemplate(d.target, Math.floor(now() / 1000))) }
        catch (e) { d.failed = fail(label, envelope, 5, e); save(); continue }
        save()
      }
      try {
        const r = await publish(d.event)
        if (r.accepted === true) { d.done = true; delete d.failed }
        else d.failed = fail(label, envelope, 5, 'relay-refused')
      } catch (e) { d.failed = fail(label, envelope, 5, e) }
      save()
    }
  }
  const unfinished = e => e.deletions?.some(d => !d.done && d.attempts < CLEAR_ATTEMPTS && d.failed !== 'bunker-refused')

  async function step({ facts = [], requests = [] } = {}) {
    for (const f of facts) {
      const entry = state.envelopes[f.envelope]
      if (f.fact === 'admitted') {
        // A fact replayed after a restart, or one older than a live turn, is history, not a mention.
        if (entry || now() - f.at > STATUS_STALE_MS) continue
        const created = state.envelopes[f.envelope] = { target: f.target, channel: f.channel, admitted_at: f.at }
        save()
        await react(f.envelope, created, 'seen')
      } else if (f.fact === 'replied' && entry && !entry.cleared_at) await clear(f.envelope, entry, 'replied')
    }
    for (const envelope of requests) if (!pendingWorking.has(envelope)) pendingWorking.set(envelope, now())
    for (const [envelope, since] of pendingWorking) {
      const entry = state.envelopes[envelope]
      if (entry) { pendingWorking.delete(envelope); await react(envelope, entry, 'working') }
      else if (now() - since > WORKING_GRACE_MS) pendingWorking.delete(envelope)
    }
    let pruned = false
    for (const [envelope, entry] of Object.entries(state.envelopes)) {
      if (!entry.cleared_at && now() - entry.admitted_at > STATUS_STALE_MS) await clear(envelope, entry, 'stale')
      else if (entry.cleared_at && unfinished(entry)) await clear(envelope, entry, entry.cleared_by)
      if (entry.cleared_at && !unfinished(entry) && now() - entry.cleared_at > KEEP_MS) { delete state.envelopes[envelope]; pruned = true }
    }
    if (pruned) save()
    if (session && now() - lastUsed > idleMs) dropSession()
  }
  return Object.freeze({ step, close: dropSession, snapshot: () => JSON.parse(JSON.stringify(state)) })
}
