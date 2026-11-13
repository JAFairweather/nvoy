// onboard_delegate.mjs — which keys an owner has granted the right to ask for new agents (waggle
// docs/DESIGN_ONBOARDING_DELEGATE.md, Part 1, "Fleet changes", discovery and fail closed).
//
// An owner (a grantor of an installed template) signs one kind 440 with `da-cap onboard` to a delegate
// key, and revokes it with one kind 441. This module finds the live ones, cold, from the grant relays.
// It only discovers. Whether a delegate's setup request is acceptable (consent, templates, no giver, the
// daily cap, the staged key) is decided where requests are parsed, and every effect re-checks liveness.
//
// Two rules differ from the task-grant fold in admission.mjs on purpose:
// - A 441 revokes its grant whatever either event's created_at says. A signer can backdate an event,
//   so order by timestamp would let a 441 dated before its grant leave the grant live.
// - A read that did not complete on a quorum of the relays answers "unknown", never "no grants" and
//   never the grants it happened to see. Unknown is treated as revoked: no delegate step runs.

export const ONBOARD_CAP = 'onboard'
export const GRANT_KIND = 440
export const REVOKE_KIND = 441
const HEX64 = /^[0-9a-f]{64}$/

const tag = (ev, name) => (Array.isArray(ev?.tags) ? ev.tags : []).find(t => Array.isArray(t) && t[0] === name)
const one = (ev, name) => { const t = tag(ev, name); return typeof t?.[1] === 'string' ? t[1] : null }

// NIP-40, as admission.mjs grantExpired: a malformed expiration is an expired grant.
function expired(ev, nowSec) {
  const t = tag(ev, 'expiration')
  if (!t) return false
  return !/^[0-9]{1,12}$/.test(String(t[1])) || Number(t[1]) <= nowSec
}

// The grant and revocation events from these grantors.
export const grantFilter = grantors => ({ kinds: [GRANT_KIND, REVOKE_KIND], authors: [...new Set(grantors)] })

// More than half of the relays asked must have answered in full.
export const quorumOf = relayCount => Math.floor(relayCount / 2) + 1

// The live onboard grants in `events`, by delegate: Map(delegate -> [grant, ...]), newest first, where a
// grant is { grantId, grantor, delegate, created_at, policy, age }. `policy` and `age` are the consent
// tags as signed (null when absent); judging them is the request parser's job.
// The scope is a salted hash of the grantor's own key (`scopeHash(grantor, salt)`): the right is to add
// agents to that owner's hive, so a grant cannot be replayed as another owner's.
export function foldOnboardGrants(events, { grantors, verify, scopeHash, nowSec = Math.floor(Date.now() / 1000) }) {
  const by = new Set((grantors || []).map(g => String(g).toLowerCase()))
  const grants = new Map(), revoked = new Set()
  let rejected = 0
  for (const ev of Array.isArray(events) ? events : []) {
    const author = String(ev?.pubkey || '').toLowerCase()
    if (!by.has(author) || (ev.kind !== GRANT_KIND && ev.kind !== REVOKE_KIND)) continue
    let ok = false
    try { ok = verify(JSON.parse(JSON.stringify(ev))) === true } catch { ok = false }
    if (!ok) { rejected++; continue }
    if (ev.kind === REVOKE_KIND) {
      // Kept with its author: only the grant's own grantor can revoke it.
      const id = one(ev, 'e')
      if (id) revoked.add(`${author}:${id}`)
      continue
    }
    if (one(ev, 'da-cap') !== ONBOARD_CAP) continue
    const delegate = String(one(ev, 'p') || '').toLowerCase(), scope = tag(ev, 'da-scope')
    if (!HEX64.test(delegate) || delegate === author || !scope || scope[1] !== scopeHash(author, scope[2] || '')) continue
    if (expired(ev, nowSec)) continue
    grants.set(ev.id, { grantId: ev.id, grantor: author, delegate, created_at: Number.isInteger(ev.created_at) ? ev.created_at : 0,
      policy: one(ev, 'policy'), age: one(ev, 'age') })
  }
  const live = new Map()
  for (const g of grants.values()) {
    if (revoked.has(`${g.grantor}:${g.grantId}`)) continue
    if (!live.has(g.delegate)) live.set(g.delegate, [])
    live.get(g.delegate).push(g)
  }
  for (const list of live.values()) list.sort((a, b) => b.created_at - a.created_at || (a.grantId < b.grantId ? 1 : -1))
  return { live, rejected }
}

// One cold read of the owners' grants and revocations from `urls`. `read(url, filter)` resolves to
// { answered, complete, events } (onboard_watch.mjs readPages gives that shape). The answer is known
// only when at least a quorum of the relays read in full. Then grants come only from the complete reads,
// since a partial read may hold a grant without the 441 that ended it; but a 441 from any relay that
// answered, in full or not, still revokes. Otherwise `known` is false and `live` is empty: the caller
// runs no delegate step and says the grant state is unknown.
export async function readOnboardGrants({ urls, grantors, read, verify, scopeHash, nowSec }) {
  const list = [...new Set(urls || [])]
  const owners = [...new Set((grantors || []).map(g => String(g).toLowerCase()))].filter(g => HEX64.test(g))
  if (!list.length || !owners.length) return { known: false, live: new Map(), complete: 0, needed: quorumOf(list.length), reason: !list.length ? 'no grant relay' : 'no owner' }
  const reads = await Promise.all(list.map(async url => {
    try { return await read(url, grantFilter(owners)) } catch { return { answered: false, complete: false, events: [] } }
  }))
  const complete = reads.filter(r => r?.answered && r.complete).length, needed = quorumOf(list.length)
  if (complete < needed) return { known: false, live: new Map(), complete, needed, reason: `only ${complete} of ${list.length} grant relays read in full; ${needed} needed` }
  const fromComplete = reads.filter(r => r?.answered && r.complete).flatMap(r => r.events || [])
  const vetoes = reads.filter(r => r?.answered && !r.complete).flatMap(r => (r.events || []).filter(ev => ev?.kind === REVOKE_KIND))
  const events = [...new Map([...fromComplete, ...vetoes].map(ev => [ev?.id, ev])).values()]
  const { live, rejected } = foldOnboardGrants(events, { grantors: owners, verify, scopeHash, nowSec })
  return { known: true, live, complete, needed, rejected }
}

// The live grant behind a delegate's request, or null: the newest live onboard grant to `delegate` from
// one of `grantors` (for a request, the template's grantors). Unknown state is never live.
export function liveGrantFor(state, delegate, grantors) {
  if (!state?.known) return null
  const allowed = new Set((grantors || []).map(g => String(g).toLowerCase()))
  return (state.live.get(String(delegate || '').toLowerCase()) || []).find(g => allowed.has(g.grantor)) || null
}

// The live grant a request names by its signed `consent` id, from one of `grantors`, or null. A delegate may hold
// more than one live grant; the request is judged against the one it names, never the newest.
export function liveGrantById(state, delegate, grantId, grantors) {
  if (!state?.known || typeof grantId !== 'string') return null
  const allowed = new Set((grantors || []).map(g => String(g).toLowerCase()))
  return (state.live.get(String(delegate || '').toLowerCase()) || []).find(g => g.grantId === grantId && allowed.has(g.grantor)) || null
}

// The extra authors a fetch of setup requests reads: every live delegate, never when unknown.
export const delegateAuthors = state => state?.known ? [...state.live.keys()] : []
