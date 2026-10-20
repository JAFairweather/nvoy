// agent_limits.mjs — the brakes on agents directing agents.
//
// A reply p-tags its parent's author, and a granted agent is admitted on any mention of itself. Two
// granted agents therefore answer each other for ever unless something outside both of them stops
// it. Three things do, all decided by the broker and none by the model:
//
//   - a hop count. Every kind:9 a broker signs carries ['nvoy-hop', n]: a post is 1, a reply is its
//     parent's hop + 1. A tagged event at or past `max_hops` is never admitted as a task. A human
//     client sets no tag and is unaffected — the brake is for brokers, which always set it;
//   - a rolling-hour admission cap per sender, for every sender that is not a manifest grantor;
//   - a rolling-hour cap on posts the identity starts itself (`may_post.per_hour`).
//
// The counters are durable in the broker's state root, so a restart cannot reset a budget.

import { lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

export const HOP_TAG = 'nvoy-hop'
export const HOUR_MS = 60 * 60 * 1000
export const DEFAULT_LIMITS = Object.freeze({ maxHops: 3, perSenderPerHour: 12 })

// null: no tag, so not broker-signed. A tag that is not one canonical non-negative integer is not
// something a broker wrote, and it counts as past every limit rather than as absent. The sentinel is
// finite on purpose: a carried admission crosses attention's JSON, where Infinity would become null.
export const MALFORMED_HOP = Number.MAX_SAFE_INTEGER
export function hopOf(ev) {
  const values = (Array.isArray(ev?.tags) ? ev.tags : []).filter(t => t?.[0] === HOP_TAG).map(t => t[1])
  if (!values.length) return null
  if (values.length !== 1 || !/^(0|[1-9][0-9]{0,5})$/.test(String(values[0]))) return MALFORMED_HOP
  return Number(values[0])
}
// A hop read back from JSON: absent is null, anything not a non-negative integer is malformed.
export const hopFromJson = value => value == null ? null : Number.isSafeInteger(value) && value >= 0 ? value : MALFORMED_HOP
export const nextHop = parentHop => (Number.isSafeInteger(parentHop) && parentHop >= 0 ? parentHop : 0) + 1
export const hopLimited = (hop, maxHops) => hop != null && hop >= maxHops

// NIP-40. A grant whose expiration has passed is treated exactly as a revoked one.
export function grantExpired(ev, nowSec = Math.floor(Date.now() / 1000)) {
  const tag = (Array.isArray(ev?.tags) ? ev.tags : []).find(t => t?.[0] === 'expiration')
  if (!tag) return false
  const at = Number(tag[1])
  // A malformed expiration cannot be honoured, and a grant that might have expired is not a grant.
  return !/^[0-9]{1,12}$/.test(String(tag[1])) || at <= nowSec
}

// Pure sliding window. `id` makes a retry idempotent: the same event or request is counted once
// and, once counted, is never refused by its own earlier entry.
export function slideWindow(entries, { key, id, at, limit, windowMs = HOUR_MS }) {
  const live = entries.filter(e => at - e.at < windowMs)
  const mine = live.filter(e => e.key === key)
  if (mine.some(e => e.id === id)) return { allowed: true, entries: live, count: mine.length, repeat: true }
  if (mine.length >= limit) return { allowed: false, entries: live, count: mine.length, retryAt: Math.min(...mine.map(e => e.at)) + windowMs }
  return { allowed: true, entries: [...live, { key, id, at }], count: mine.length + 1 }
}

function loadWindow(path) {
  let st
  try { st = lstatSync(path) } catch (e) { if (e.code === 'ENOENT') return []; throw e }
  if (!st.isFile() || st.isSymbolicLink()) throw new Error('limit counter is not a regular file')
  const raw = JSON.parse(readFileSync(path, 'utf8'))
  if (raw?.version !== 1 || !Array.isArray(raw.entries) || !raw.entries.every(e =>
    typeof e?.key === 'string' && typeof e.id === 'string' && Number.isFinite(e.at))) throw new Error('limit counter is malformed')
  return raw.entries
}

// Check and record in one step. The broker holds its lock or is the daemon's only child, so there
// is one writer; a counter that cannot be read or written throws, and the caller fails closed.
export function countInWindow(path, { key, id, limit, at = Date.now(), windowMs = HOUR_MS }) {
  const verdict = slideWindow(loadWindow(path), { key, id, at, limit, windowMs })
  if (verdict.allowed && !verdict.repeat) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    const tmp = `${path}.${process.pid}.tmp`
    writeFileSync(tmp, JSON.stringify({ version: 1, entries: verdict.entries }), { mode: 0o600 })
    renameSync(tmp, path)
  }
  return verdict
}

// The admission gate both brokers apply once a grant is found and before the source is claimed.
// Returns null to admit, or the one-line reason it was not admitted (never content).
export function admissionLimit({ limits, grantors, sender, eventId, hop, path, at = Date.now() }) {
  if (hopLimited(hop, limits.maxHops)) return `hop limit: ${hop === MALFORMED_HOP ? 'malformed nvoy-hop' : `nvoy-hop ${hop}`} >= max_hops ${limits.maxHops}; not admitted`
  if (grantors.includes(sender)) return null
  const verdict = countInWindow(path, { key: sender, id: eventId, limit: limits.perSenderPerHour, at })
  return verdict.allowed ? null
    : `rate limit: sender ${sender.slice(0, 8)} already admitted ${verdict.count}/${limits.perSenderPerHour} in the last hour; not admitted`
}
