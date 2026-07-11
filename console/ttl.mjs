// ttl.mjs — hard expiry and relinquish policy: the console-side scheduler
// logic (spec §6.4.3, §6.6) as pure plans plus one rotation executor.
// DOM-free on purpose — test/ledger.mjs and the §7 M4 acceptance script
// drive this exact module in Node; main.mjs/ledger.mjs only add timers and
// buttons on top.
//
// Honesty (spec §6.4.3, decision 2): client-side scheduling runs while the
// console is open — that is what "hard expiry" means here. Console closed =
// soft expiry only (compliant runtimes stop serving; auto_relinquish agents
// destroy their keys) until the next visit sweeps. The optional operator
// daemon (bin/nvoy-ttl.mjs) or a future hosted scheduler closes that gap.

import { fetchScope, saveGrantIndex, toIssuedEntry, fromIssuedEntry } from '../lib/nipxx.mjs'
import { rotateWithTerms } from './nvoygrant.mjs'
import { appendLedger, deriveDelegations, rotatedEvent, relinquishedEvent, expiredRotatedEvent } from './ledgerlog.mjs'

const nowSec = () => Math.floor(Date.now() / 1000)

/**
 * Rotate one scope past a set of agents, preserving every survivor's original
 * terms, and record the move in the index + ledger in ONE save. The shared
 * spine of revoke-now, TTL rotation, and relinquish finalization.
 *
 * `makeEvents({ from_v, to_v, survivors })` returns the ledger events to
 * append (already-built events pass through unchanged). Throws (without
 * rotating) if the scope cannot be read back — rotating blind would destroy
 * the payload.
 */
export async function rotateDropping(relay, signer, index, { scope, drop, relayHint = '', makeEvents }) {
  const entry = (index.issued ?? []).find(e => e.scope === scope)
  if (!entry) throw new Error('scope not in the index — cannot rotate')
  const rec = fromIssuedEntry(entry)
  const me = await signer.getPublicKey()
  const res = await fetchScope(relay, {
    publisher: me, scopeId: rec.scopeId, generation: rec.generation, scopeKey: rec.scopeKey,
  })
  if (res.status !== 'ok')
    throw new Error(`cannot read own scope back from relays (${res.status}) — not rotating, that would destroy the data`)
  const dels = deriveDelegations(index)
  const survivors = rec.grantees.filter(p => !drop.includes(p)).map(pub => ({
    pub, terms: dels.find(x => x.scope === scope && x.agent === pub)?.terms ?? null,
  }))
  const rot = await rotateWithTerms(relay, signer, {
    scopeId: rec.scopeId, generation: rec.generation, payload: res.data,
    scopeName: rec.scopeName, survivors, relayHint,
  })
  index.issued = index.issued.map(e => e.scope !== scope ? e :
    toIssuedEntry({ scopeId: rec.scopeId, scopeName: rec.scopeName, generation: rot.generation, scopeKey: rot.scopeKey },
      survivors.map(s => s.pub)))
  for (const ev of makeEvents({ from_v: rec.generation, to_v: rot.generation, survivors: survivors.length }))
    index.nvoy_ledger = appendLedger(index, ev)
  await saveGrantIndex(relay, signer, index)
  return { from_v: rec.generation, to_v: rot.generation, survivors: survivors.map(s => s.pub) }
}

// ------------------------------------------------------------- TTL (§6.4.3)

/**
 * What the scheduler must do right now: one item per scope holding at least
 * one delegation past its expires_at. `expired` lists the agents to drop;
 * everyone else in the scope's grantees survives under original terms.
 */
export function expiryRotationPlan(index, now = nowSec()) {
  const issued = new Map((index.issued ?? []).map(e => [e.scope, e]))
  const byScope = new Map()
  for (const d of deriveDelegations(index, now)) {
    if (d.status !== 'expired') continue
    // Only grantees still HOLDING the current generation need rotating out —
    // 'expired' also labels pairs a previous expiry-rotation already dropped.
    if (!issued.get(d.scope)?.grantees?.includes(d.agent)) continue
    if (!byScope.has(d.scope)) byScope.set(d.scope, { scope: d.scope, scopeName: d.scopeName, expired: [] })
    byScope.get(d.scope).expired.push(d.agent)
  }
  return [...byScope.values()]
}

/** The next future expiry among active delegations (unix seconds), or null —
 *  what the console arms its timer for. */
export function nextExpiry(index, now = nowSec()) {
  let next = null
  for (const d of deriveDelegations(index, now))
    if (d.status === 'active' && d.expiresAt !== null && d.expiresAt > now)
      next = next === null ? d.expiresAt : Math.min(next, d.expiresAt)
  return next
}

/** Execute one plan item: rotate the scope past its expired grantees,
 *  ledger 'expired-rotated'. Returns the rotation summary. */
export async function runExpiryRotation(relay, signer, index, item, { relayHint = '' } = {}) {
  return rotateDropping(relay, signer, index, {
    scope: item.scope, drop: item.expired, relayHint,
    makeEvents: ({ from_v, to_v, survivors }) =>
      [expiredRotatedEvent({ scope: item.scope, from_v, to_v, expired: item.expired.length, survivors })],
  })
}

// ------------------------------------------------- relinquishment (§6.6)

/**
 * Classify received relinquish notices against the current index (decision
 * 6): only notices from agents STILL holding the scope's current generation
 * count (already-rotated ones are done — self-healing, no id bookkeeping).
 *   auto     the relinquishing agent was the sole grantee → rotate now
 *   confirm  other grantees exist → queue a one-tap confirm (rotation
 *            re-grants them; the human stays in the loop)
 * One item per (scope, agent), newest notice wins.
 */
export function relinquishPlan(index, relinquishes) {
  const issued = new Map((index.issued ?? []).map(e => [e.scope, e]))
  const seen = new Set()
  const auto = [], confirm = []
  for (const notice of relinquishes) { // already newest-first
    const key = `${notice.scope}:${notice.from}`
    if (seen.has(key)) continue
    seen.add(key)
    const entry = issued.get(notice.scope)
    if (!entry?.grantees?.includes(notice.from)) continue // already rotated out
    const item = {
      scope: notice.scope, scopeName: entry.scope_name, agent: notice.from,
      reason: notice.reason, destroyed_at: notice.destroyed_at, v: entry.v,
      others: entry.grantees.filter(p => p !== notice.from).length,
    }
    ;(item.others === 0 ? auto : confirm).push(item)
  }
  return { auto, confirm }
}

/** Finalize one relinquishment (§6.6 phase 2): rotate the scope past the
 *  agent, re-grant any others under original terms, ledger arc
 *  relinquished → rotated. */
export async function runRelinquishRotation(relay, signer, index, item, { relayHint = '' } = {}) {
  return rotateDropping(relay, signer, index, {
    scope: item.scope, drop: [item.agent], relayHint,
    makeEvents: ({ from_v, to_v, survivors }) => [
      relinquishedEvent({ scope: item.scope, agent: item.agent, v: from_v, reason: item.reason, destroyed_at: item.destroyed_at }),
      rotatedEvent({ scope: item.scope, from_v, to_v, survivors }),
    ],
  })
}
