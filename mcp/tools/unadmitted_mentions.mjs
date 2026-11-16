// unadmitted_mentions.mjs — q-198: a refused mention is recorded, and the seat may be told (docs/DESIGN_UNADMITTED_MENTION_NOTICE.md).
//
// The native broker used to refuse a mention with one stderr line and a `.done` marker, so a missing
// grant looked exactly like silence. Two layers replace that:
//
//   1. every refusal appends one content-free row to `unadmitted-mentions.jsonl` in the broker's state
//      root: ids, a fixed reason and the time. Never the message text or tags;
//   2. for the refusals a person can fix (no grant, a DM from someone who is not the owner), a
//      content-free notice to the seat, at most one per author and six per seat an hour. Hop and rate
//      limits never produce one: they are brakes on loops, and a notice would wake the agent the brake
//      exists to stop.
//
// James, 16 Nov 2026 (Hive nvoy-q198-fail-loud-decision): show who sent the dropped mention, yes; a
// visible mark on the source message, no; the 1-per-author, 6-per-seat cap, yes.

import { appendFileSync, chmodSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { HOUR_MS } from './agent_limits.mjs'

const HEX64 = /^[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
export const REFUSAL_REASONS = Object.freeze(['no-grant', 'no-grant-suspect', 'dm-not-owner', 'hop-limit', 'rate-limit'])
export const NOTICE_REASONS = Object.freeze(['no-grant', 'no-grant-suspect', 'dm-not-owner'])
export const NOTICE_TYPE = 'unadmitted-mention'
export const MAX_ROWS = 10000
export const NOTICE_CAPS = Object.freeze({ perAuthor: 1, perSeat: 6 })

// The reason an admissionLimit() string stands for. Its wording is ours (agent_limits.mjs), never the sender's.
export const limitReason = text => (String(text).startsWith('hop limit:') ? 'hop-limit' : 'rate-limit')

function regularOrAbsent(path) {
  try {
    const st = lstatSync(path)
    if (!st.isFile() || st.isSymbolicLink()) throw new Error(`${path} is not a regular file`)
    return true
  } catch (e) { if (e.code === 'ENOENT') return false; throw e }
}

// Layer 1. Returns 'recorded', 'repeat' (this event already has a row) or throws. The caller treats a
// throw as a lost row and still refuses: the record is evidence, never a gate.
export function recordRefusal(path, { sourceEvent, author, channel, reason, lookup = null, at = Date.now(), maxRows = MAX_ROWS }) {
  if (!HEX64.test(String(sourceEvent)) || !HEX64.test(String(author)) || !UUID.test(String(channel)) || !REFUSAL_REASONS.includes(reason)) {
    throw new Error('refusal row is malformed')
  }
  const row = { version: 1, source_event: sourceEvent, author, channel, reason,
    ...(reason.startsWith('no-grant') && lookup ? { grant_lookup: { suspect: lookup.suspect === true, relays: String(lookup.summary || 'none') } } : {}),
    at: Math.floor(at / 1000) }
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  let lines = []
  if (regularOrAbsent(path)) lines = readFileSync(path, 'utf8').split('\n').filter(Boolean)
  // Dedupe on source_event: a requeued marker or a second path must not double-count one refusal.
  // A line that is not JSON is kept, unread, until a trim drops it.
  if (lines.some(line => { try { return JSON.parse(line)?.source_event === sourceEvent } catch { return false } })) return 'repeat'
  if (lines.length >= maxRows) {
    // Past the cap, keep the newest half and the new row: an ungranted sender must not be able to fill the disk.
    const kept = lines.slice(lines.length - Math.floor(maxRows / 2))
    const tmp = `${path}.${process.pid}.tmp`
    writeFileSync(tmp, [...kept, JSON.stringify(row)].join('\n') + '\n', { mode: 0o600 })
    renameSync(tmp, path)
  } else {
    appendFileSync(path, JSON.stringify(row) + '\n', { mode: 0o600 })
  }
  chmodSync(path, 0o600)
  return 'recorded'
}

function loadBudget(path) {
  if (!regularOrAbsent(path)) return []
  const raw = JSON.parse(readFileSync(path, 'utf8'))
  if (raw?.version !== 1 || !Array.isArray(raw.entries) || !raw.entries.every(e =>
    HEX64.test(String(e?.author)) && HEX64.test(String(e?.id)) && Number.isFinite(e?.at))) throw new Error('notice budget is malformed')
  return raw.entries
}

// Layer 2's budget: may this refusal wake the seat? Checks both caps and records the notice in one step.
// A grantor is never counted, since a grantor always holds the grant. Retrying the same event is
// idempotent. A budget that cannot be read or written throws, and the caller sends no notice.
export function takeNoticeBudget(path, { author, sourceEvent, grantors = [], at = Date.now(), caps = NOTICE_CAPS }) {
  if (grantors.includes(author)) return { allowed: true, counted: false }
  const live = loadBudget(path).filter(e => at - e.at < HOUR_MS)
  if (live.some(e => e.id === sourceEvent)) return { allowed: true, counted: false, repeat: true }
  if (live.filter(e => e.author === author).length >= caps.perAuthor) return { allowed: false, why: 'author' }
  if (live.length >= caps.perSeat) return { allowed: false, why: 'seat' }
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  const tmp = `${path}.${process.pid}.tmp`
  writeFileSync(tmp, JSON.stringify({ version: 1, entries: [...live, { author, id: sourceEvent, at }] }), { mode: 0o600 })
  renameSync(tmp, path)
  return { allowed: true, counted: true }
}

// The notice rides in the existing verified-notification envelope, so every queue reader already routes
// it as a content-free, non-replyable notification. Only its inner type and fields are new.
export function buildNotice({ instance, sourceEvent, author, channel, reason, observedAt }) {
  if (!NOTICE_REASONS.includes(reason)) throw new Error(`no notice is sent for ${reason}`)
  return { type: 'verified-notification', instance, envelope: sourceEvent,
    notification: { version: 1, type: NOTICE_TYPE, source_author: author, source_event: sourceEvent, source_channel: channel,
      reason, observed_at: Math.floor(Number(observedAt) || Date.now() / 1000) } }
}

// The reader's wording. A suspect notice must never read as a sound "no".
export function describeNotice(n) {
  const why = n.reason === 'dm-not-owner' ? 'it is a DM, and only this identity\'s owner is heard in a DM'
    : n.reason === 'no-grant-suspect' ? 'grant lookup unreliable: the relays returned no grants, but have held them before'
      : 'the relays read held no live task grant for its author'
  return `Nvoy notice: a mention of this identity was not admitted, because ${why}.`
}

// Classifier view of layer 1: counts by reason and the newest row's time. Ids and reasons only.
export function summarizeRefusals(rows) {
  const by_reason = Object.fromEntries(REFUSAL_REASONS.map(r => [r, 0]))
  let newest = 0
  for (const row of rows) {
    if (!REFUSAL_REASONS.includes(row?.reason)) continue
    by_reason[row.reason]++
    if (Number.isFinite(row.at) && row.at > newest) newest = row.at
  }
  return { total: Object.values(by_reason).reduce((a, b) => a + b, 0), by_reason, newest_at: newest ? new Date(newest * 1000).toISOString() : null }
}
