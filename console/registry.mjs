// registry.mjs — the agent roster, projected so a headless slice can read it.
//
// THE PROBLEM THIS EXISTS FOR, stated plainly because it is the one the Director reported: an agent
// could exist in Nvoy and be invisible in Nact, and the only symptom was an ABSENCE, which nobody can
// see. nact#57 fixed the mechanism — the join key is the lowercase hex pubkey on both sides — but a
// join needs two sets, and Nact cannot read Nvoy's. The roster lives on the Director's kind-10440,
// NIP-44-encrypted to himself, so a runtime holding no key of his is structurally unable to see it.
//
// So the roster is PROJECTED: published as a scoped dataset (`data:agents/registry`) and granted to
// each runtime that needs it. Three properties follow, and each is the reason for a choice below:
//
//   · The projection is a GRANT, so revoking a slice's view is a scope-key rotation — a mechanism
//     that already exists and is already audited. AD-6's two tests force this answer: roster content
//     is sensitive to Nave, and a slice like the waggle bridge is off-box, so grant-to-app.
//   · The projection is a COPY, so it can be stale. It therefore carries `generated_at`, and a
//     consumer must render that rather than implying it is live.
//   · The projection carries no more than the roster holds. It is not a place to add fields, and it
//     must never become a second authority — AD-12: every slice roster row is a projection of the
//     registry, never authority.
//
// Pure and DOM-free so test/registry.mjs can drive it.

/** The scope name. `data:*` per AD-8's namespace; the Ledger's Type facet reads that prefix. */
export const REGISTRY_SCOPE = 'data:agents/registry'

/** Bumped when the payload shape changes, so a consumer can refuse a shape it does not know. */
export const REGISTRY_VERSION = 1

const HEX64 = /^[0-9a-f]{64}$/

/**
 * Build the projection payload from the delegator's Grant Index.
 *
 * Rows are normalised to the join key and nothing else is invented: today `nvoy_agents` holds
 * `{ pub, added_at }`, so that is what ships. A projection that carried a `handle` the registry does
 * not have would be a guess wearing the registry's authority.
 *
 * A malformed row is DROPPED and COUNTED. Dropping silently would hand a slice a roster that is
 * quietly shorter than the real one — which is the original bug, moved one layer out.
 */
export function buildProjection(index, { now = 0 } = {}) {
  const raw = Array.isArray(index?.nvoy_agents) ? index.nvoy_agents : []
  const agents = []
  const seen = new Set()
  let dropped = 0
  for (const a of raw) {
    const pub = typeof a?.pub === 'string' ? a.pub.toLowerCase() : null
    if (!pub || !HEX64.test(pub)) { dropped++; continue }
    if (seen.has(pub)) { dropped++; continue }     // one key, one Agent (ruling 1)
    seen.add(pub)
    const row = { pub }
    if (Number.isFinite(a.added_at)) row.added_at = a.added_at
    agents.push(row)
  }
  agents.sort((x, y) => x.pub.localeCompare(y.pub))   // stable, so an unchanged roster hashes the same
  return {
    payload: {
      v: REGISTRY_VERSION,
      generated_at: now || null,
      agents,
      // Said in the payload, not just in a doc, because the consumer that needs to know is a program.
      note: 'A projection of the delegator\'s agent registry at generated_at. A copy, not a live view — '
        + 'render its age. Never authority: the registry is the delegator\'s 10440.',
    },
    dropped,
  }
}

/**
 * Has the roster actually changed? Compares the projected agent set only.
 *
 * Rotating a scope key costs every grantee a re-delivery, so republishing an unchanged roster is not
 * free — it is churn that looks like activity in the Ledger. Callers use this to refuse a no-op.
 */
export function projectionChanged(prevPayload, nextPayload) {
  const keys = (p) => (Array.isArray(p?.agents) ? p.agents : []).map(a => a.pub).join(',')
  if (prevPayload?.v !== nextPayload?.v) return true
  return keys(prevPayload) !== keys(nextPayload)
}

/**
 * THE DIVERGENCE ROWS. Given the registry's key set and a runtime's key set, say who is where.
 *
 * This is the whole answer to "some agents show in Nvoy that do not show in Nact", and the reason it
 * is a function rather than a screen: the mismatch becomes a VISIBLE ROW instead of an unobservable
 * absence, and it becomes so identically on every surface that renders it.
 *
 * `registryKnown` is a THIRD state, not a boolean. When the projection was never read, the honest
 * answer is neither "known to both" nor "known only to the box" — it is "not verified", and a
 * consumer must render that rather than picking whichever reads better.
 */
export function diffRosters({ registry = null, box = [] } = {}) {
  const norm = (xs) => new Set((Array.isArray(xs) ? xs : [])
    .map(x => (typeof x === 'string' ? x : x?.pub))
    .filter(p => typeof p === 'string' && HEX64.test(p.toLowerCase()))
    .map(p => p.toLowerCase()))

  const boxSet = norm(box)
  if (registry === null) {
    // The projection did not answer. Every on-box key is reported as unverified — never as
    // "known only to the box", which would be a claim about a store that was never read.
    return {
      registryKnown: false,
      both: [], onlyRegistry: [], onlyBox: [],
      unverified: [...boxSet].sort(),
    }
  }
  const regSet = norm(registry)
  return {
    registryKnown: true,
    both: [...regSet].filter(p => boxSet.has(p)).sort(),
    onlyRegistry: [...regSet].filter(p => !boxSet.has(p)).sort(),
    onlyBox: [...boxSet].filter(p => !regSet.has(p)).sort(),
    unverified: [],
  }
}

/**
 * The sentence a divergence row carries. Copy lives here, beside the classifier, so two surfaces
 * cannot describe the same state two ways — the reason `lib/tiers.mjs` is shared with `sign.html`.
 */
export function divergenceNote(kind) {
  switch (kind) {
    case 'onlyRegistry':
      return 'known only to Nvoy — you registered this agent, and no key slot for it exists on the box. '
        + 'It can hold grants and cannot act here.'
    case 'onlyBox':
      return 'known only to Nact — a key exists on the box with no row in your registry. It is not an '
        + 'agent until you register it, and nothing here treats it as one.'
    case 'unverified':
      return 'not verified — the registry projection was not read, so whether Nvoy knows this key is '
        + 'unknown. This is not the same as "Nvoy does not know it."'
    case 'both':
      return 'in both'
    default:
      return 'unrecognised state'
  }
}

/**
 * The roster after enrolling `pub`, and whether that changed anything.
 *
 * WHY THIS EXISTS. Only two paths ever appended to `nvoy_agents` — approving an access request and
 * pasting an npub — and the grant composer was not one of them. So the most direct way to give an
 * agent authority, issuing it a data grant, did not make it an agent: it appeared in the Ledger as a
 * grantee and nowhere in the roster. That is the "OTHER IDENTITIES · 21 grantees" the Director
 * reported, and it is AD-12 ruling (g) unimplemented — Nvoy is the front door and the only place an
 * Agent is created, but its front door did not write the register.
 *
 * Pure, and it does not save. The caller folds the returned roster into the SAME `saveGrantIndex`
 * call as the grant it came from. A second write that can fail on its own would reintroduce exactly
 * the divergence this closes, one layer up.
 *
 * `added: false` always carries a `reason` CODE — `malformed` · `self` · `duplicate` — because the
 * three ways to change nothing are not alike: a duplicate is success, your own key is a category
 * error, and a malformed key is a bug upstream. A caller that can only show "added" or silence
 * cannot tell the Director which happened. A code and not a sentence, on purpose: the copy belongs
 * to the surface, which is why the composer and the roster word `duplicate` differently.
 */
export const ENROL_REASONS = ['malformed', 'self', 'duplicate']

export function enrol(index, pub, { me = null, now = 0 } = {}) {
  const agents = Array.isArray(index?.nvoy_agents) ? index.nvoy_agents : []
  const key = typeof pub === 'string' ? pub.toLowerCase() : ''
  const unchanged = (reason) => ({ agents, added: false, reason })
  if (!HEX64.test(key)) return unchanged('malformed')
  // One key, one Agent (ruling 1) — and the Director is not one of his own agents.
  if (me && key === String(me).toLowerCase()) return unchanged('self')
  if (agents.some(a => typeof a?.pub === 'string' && a.pub.toLowerCase() === key))
    return unchanged('duplicate')
  return { agents: [...agents, { pub: key, added_at: now || 0 }], added: true, reason: '' }
}
