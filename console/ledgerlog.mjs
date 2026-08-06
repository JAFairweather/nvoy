// ledgerlog.mjs — the nvoy_ledger event log and the delegation views derived
// from it. App-level field on the Grant Index (pattern: nvelope_invites):
// the 10440 payload is app-extensible JSON, so the delegation history rides
// encrypted-to-self next to the issued/received entries — everything the
// ledger screen shows reconstitutes from the delegator's nsec alone.
//
// Event shapes (decision, recorded in CLAUDE.md):
//   { t: 'granted', at, scope, agent, v, terms, name }    terms = full §4 object or null
//   { t: 'rotated', at, scope, from_v, to_v, survivors }  survivors = count
//   { t: 'revoked', at, scope, agent, v, reason, notice } notice = whether a 441 was sent
//   { t: 'relinquished', at, scope, agent, v, reason, destroyed_at }
//       agent-initiated (§6.6): the runtime destroyed its key and told us
//   { t: 'expired-rotated', at, scope, from_v, to_v, expired, survivors }
//       the TTL scheduler's hard expiry (§6.4.3): expired = count dropped
//   { t: 'consumed', at, scope, publisher, name, outcome, noteId }
//       THE ONLY INBOUND EVENT: the Director acted on a grant he RECEIVED (Ngage posting a draft in
//       his own hand, or passing on it). `publisher` is the agent that issued it, never him — see
//       consumedEvent() for why this is not a `granted`.
// Append-only, capped at LEDGER_CAP (oldest trimmed) to keep the 10440 sane.
//
// DOM-free on purpose — test/ledger.mjs drives this module in Node.

export const LEDGER_CAP = 500

const nowSec = () => Math.floor(Date.now() / 1000)

export const ledgerOf = (index) => index.nvoy_ledger ?? []

/** Append an event, trimming the oldest past LEDGER_CAP. Returns the new log
 *  (assign it back to index.nvoy_ledger before saving the index). */
export function appendLedger(index, event) {
  const log = [...ledgerOf(index), event]
  return log.length > LEDGER_CAP ? log.slice(log.length - LEDGER_CAP) : log
}

export const grantedEvent = ({ scope, agent, v, terms, name, at = nowSec() }) =>
  ({ t: 'granted', at, scope, agent, v, terms: terms ?? null, name })

export const rotatedEvent = ({ scope, from_v, to_v, survivors, at = nowSec() }) =>
  ({ t: 'rotated', at, scope, from_v, to_v, survivors })

export const revokedEvent = ({ scope, agent, v, reason, notice, at = nowSec() }) =>
  ({ t: 'revoked', at, scope, agent, v, reason: reason || null, notice: !!notice })

export const relinquishedEvent = ({ scope, agent, v, reason, destroyed_at, at = nowSec() }) =>
  ({ t: 'relinquished', at, scope, agent, v, reason: reason || null, destroyed_at })

export const expiredRotatedEvent = ({ scope, from_v, to_v, expired, survivors, at = nowSec() }) =>
  ({ t: 'expired-rotated', at, scope, from_v, to_v, expired, survivors })

/**
 * The Director acted on a grant he RECEIVED. A new direction in this log, and that is why it needs its
 * own event rather than reusing `granted`.
 *
 * Every event above describes something the Director ISSUED. An inbound `draft:` grant is the opposite:
 * an agent granted it TO him, and he consumed it by posting the note in his own hand or passing on it.
 * Ngage recorded that only in `localStorage`, so half of what the desk did was invisible in the one
 * console that claims to be the source of truth for all grants — invisible BY CONSTRUCTION, which is the
 * same class of defect as the agent that showed in Nvoy and not in Nact.
 *
 * Filing it as `granted` would have been the easy fix and the wrong one: it would claim the Director
 * granted something he received, inverting the direction of authority in the audit log to avoid adding a
 * word. `publisher` is therefore the agent that issued it — never the Director.
 *
 * @param outcome 'posted' (signed and published in his own hand) | 'passed' (declined)
 */
export const consumedEvent = ({ scope, publisher, name, outcome, noteId = null, at = nowSec() }) =>
  ({ t: 'consumed', at, scope, publisher, name: name ?? null, outcome, noteId })

/**
 * Every received grant this key has acted on, newest first.
 *
 * Deliberately NOT folded into `deriveDelegations`: that answers "what did I grant, and to whom", and an
 * inbound grant has no place in that answer. A reader who saw a received draft in the delegations list
 * would reasonably conclude the Director had delegated something. Two questions, two readers.
 *
 * A malformed row is dropped and COUNTED — a consumption the Director cannot see is precisely what this
 * event was added to end, so losing one silently would reintroduce the defect at a new layer.
 */
export function receivedActions(index) {
  const log = Array.isArray(index?.nvoy_ledger) ? index.nvoy_ledger : []
  const rows = []
  let dropped = 0
  for (const ev of log) {
    if (ev?.t !== 'consumed') continue
    if (typeof ev.scope !== 'string' || typeof ev.publisher !== 'string'
      || (ev.outcome !== 'posted' && ev.outcome !== 'passed')) { dropped++; continue }
    rows.push({
      scope: ev.scope, publisher: ev.publisher, name: ev.name ?? ev.scope,
      outcome: ev.outcome, noteId: ev.noteId ?? null, at: Number.isFinite(ev.at) ? ev.at : null,
    })
  }
  rows.sort((a, b) => (b.at || 0) - (a.at || 0))
  return { rows, dropped }
}

/**
 * Derive the delegation list the ledger renders: one row per (scope, agent)
 * pair ever granted. Status comes from the CURRENT issued entries — the
 * authoritative record — with the ledger supplying history and terms:
 *   active       agent holds the current generation, not expired
 *   expired      agent holds the current generation but terms.expires_at
 *                passed (soft — the TTL scheduler rotates it), OR was
 *                dropped by an expired-rotation (hard expiry landed)
 *   relinquished agent handed the delegation back (§6.6) and was rotated out
 *   revoked      agent no longer in the scope's grantees for any other
 *                reason (revoke-now, scope gone)
 */
export function deriveDelegations(index, now = nowSec()) {
  const issued = new Map((index.issued ?? []).map(e => [e.scope, e]))
  const pairs = new Map() // scope:agent → { firstAt, terms/name from latest grant }
  for (const ev of ledgerOf(index)) {
    if (ev.t !== 'granted') continue
    const k = `${ev.scope}:${ev.agent}`
    const prev = pairs.get(k)
    pairs.set(k, {
      scope: ev.scope, agent: ev.agent,
      grantedAt: prev?.grantedAt ?? ev.at,
      terms: ev.terms ?? null, name: ev.name,
    })
  }
  // Defensive: grantees present in the index without a granted event (index
  // written by another client) still get a row — terms unknown.
  for (const [scope, e] of issued)
    for (const pub of e.grantees ?? [])
      if (!pairs.has(`${scope}:${pub}`))
        pairs.set(`${scope}:${pub}`, { scope, agent: pub, grantedAt: null, terms: null, name: e.scope_name })

  // A dropped pair's terminal state comes from its newest terminal event:
  // relinquished (agent handed it back) beats revoked beats aged-out.
  const droppedStatus = (log, p) => {
    for (let i = log.length - 1; i >= 0; i--) {
      const ev = log[i]
      if (ev.scope !== p.scope) continue
      if (ev.t === 'relinquished' && ev.agent === p.agent) return 'relinquished'
      if (ev.t === 'revoked' && ev.agent === p.agent) return 'revoked'
      if (ev.t === 'expired-rotated' && p.terms?.expires_at !== undefined && p.terms.expires_at <= ev.at) return 'expired'
    }
    return 'revoked'
  }

  const log = ledgerOf(index)
  const rows = []
  for (const p of pairs.values()) {
    const e = issued.get(p.scope)
    const held = !!e?.grantees?.includes(p.agent)
    const expiresAt = p.terms?.expires_at ?? null
    const status = !held
      ? droppedStatus(log, p)
      : (expiresAt !== null && expiresAt <= now ? 'expired' : 'active')
    rows.push({
      scope: p.scope,
      scopeName: e?.scope_name ?? p.name ?? p.scope,
      agent: p.agent,
      v: e?.v ?? null,
      status,
      terms: p.terms,
      purpose: p.terms?.purpose ?? null,
      grantedAt: p.grantedAt,
      expiresAt,
    })
  }
  const rank = { active: 0, expired: 1, relinquished: 2, revoked: 3 }
  return rows.sort((a, b) => rank[a.status] - rank[b.status] || (b.grantedAt ?? 0) - (a.grantedAt ?? 0))
}

/** Event history for one delegation: its own granted/revoked/relinquished
 *  events plus every scope-wide rotation (manual or TTL), oldest first. */
export const eventsFor = (index, scope, agent) =>
  ledgerOf(index)
    .filter(ev => ev.scope === scope && (ev.t === 'rotated' || ev.t === 'expired-rotated' || ev.agent === agent))
    .sort((a, b) => a.at - b.at)

/** The totals line. A grantee is one of two kinds: a registered **agent**
 *  (in the Nvoy registry) or another **identity** — an npub that holds a grant
 *  but isn't an agent (e.g. a contact granted their own data). `agentPubs` (a
 *  Set of registered agent hexes) splits the two; passing null counts every
 *  grantee as an agent (back-compat). */
export function computeTotals(delegations, ledger, now = nowSec(), agentPubs = null) {
  const active = delegations.filter(d => d.status === 'active')
  const grantees = [...new Set(active.map(x => x.agent))]
  const d = new Date(now * 1000)
  const monthStart = Math.floor(new Date(d.getFullYear(), d.getMonth(), 1).getTime() / 1000)
  return {
    active: active.length,
    agents: agentPubs ? grantees.filter(p => agentPubs.has(p)).length : grantees.length,
    identities: agentPubs ? grantees.filter(p => !agentPubs.has(p)).length : 0,
    revokedThisMonth: ledger.filter(ev => ev.t === 'revoked' && ev.at >= monthStart).length,
  }
}

const dur = (sec) => {
  const m = Math.floor(sec / 60), h = Math.floor(m / 60), days = Math.floor(h / 24)
  if (days >= 2) return `${days}d ${h % 24}h`
  if (h >= 1) return `${h}h ${m % 60}m`
  if (m >= 1) return `${m}m`
  return '<1m'
}

/** Expiry countdown text: 'no expiry' | 'expires in 6d 23h' | 'expired 3h ago'. */
export function fmtCountdown(expiresAt, now = nowSec()) {
  if (expiresAt === null || expiresAt === undefined) return 'no expiry'
  const diff = expiresAt - now
  return diff > 0 ? `expires in ${dur(diff)}` : `expired ${dur(-diff)} ago`
}
