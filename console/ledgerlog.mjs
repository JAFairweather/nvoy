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

/**
 * Derive the delegation list the ledger renders: one row per (scope, agent)
 * pair ever granted. Status comes from the CURRENT issued entries — the
 * authoritative record — with the ledger supplying history and terms:
 *   active   agent holds the current generation, not expired
 *   expired  agent holds the current generation but terms.expires_at passed
 *            (soft — hard expiry is the M4 TTL rotation)
 *   revoked  agent no longer in the scope's grantees (or scope gone)
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

  const rows = []
  for (const p of pairs.values()) {
    const e = issued.get(p.scope)
    const held = !!e?.grantees?.includes(p.agent)
    const expiresAt = p.terms?.expires_at ?? null
    const status = !held ? 'revoked' : (expiresAt !== null && expiresAt <= now ? 'expired' : 'active')
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
  const rank = { active: 0, expired: 1, revoked: 2 }
  return rows.sort((a, b) => rank[a.status] - rank[b.status] || (b.grantedAt ?? 0) - (a.grantedAt ?? 0))
}

/** Event history for one delegation: its own granted/revoked events plus
 *  every scope-wide rotation, oldest first. */
export const eventsFor = (index, scope, agent) =>
  ledgerOf(index)
    .filter(ev => ev.scope === scope && (ev.t === 'rotated' || ev.agent === agent))
    .sort((a, b) => a.at - b.at)

/** The totals line: "N active delegations to M agents, K revoked this month." */
export function computeTotals(delegations, ledger, now = nowSec()) {
  const active = delegations.filter(d => d.status === 'active')
  const d = new Date(now * 1000)
  const monthStart = Math.floor(new Date(d.getFullYear(), d.getMonth(), 1).getTime() / 1000)
  return {
    active: active.length,
    agents: new Set(active.map(x => x.agent)).size,
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
