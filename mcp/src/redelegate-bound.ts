// redelegate-bound.ts — re-delegation is standing authority, so it carries an envelope (#111).
//
// THE ASYMMETRY THIS FIXES. AD-12 ruling 3 says an Action Grant's Capability mode is "refused at issuance
// if absent" its envelope: action class · max tier · TTL · rate limit · one bound approval path. But the
// DATA side's equivalent — `terms.redelegate` — is a bare boolean. So the same doctrine has been enforced
// two ways: an agent's authority to ACT must be bounded in advance, while its authority to RE-DELEGATE the
// Director's data is yes-or-no and otherwise unlimited.
//
// WHY THIS IS THE RIGHT FIX, AND NOT THE TWO OBVIOUS ONES. I proposed both and neither survives:
//
//   · "Enforce that the child's payload is a subset of the parent's." Not generally possible. A payload is
//     arbitrary JSON with app-defined meaning; there is no computable subset relation over it, and a check
//     that ALMOST worked would be worse than none — it would license the word "attenuated" while leaving
//     gaps.
//   · "Queue every derivation for a tap." Sound by the doctrine, and it breaks a deliberate privacy
//     property: the lineage is encrypted to the sub-issuer precisely so a delegator cannot see its agent's
//     fan-out, avoiding "a new public linkage between delegator and leaf" (nvoy#103). Making him approve
//     each leaf makes him see every leaf.
//
// Bounding the ENVELOPE resolves both. The delegator decides, at issuance, HOW MUCH re-delegation this
// grant permits — a count, a grantee limit, a deadline. He never sees the leaves, so the privacy property
// holds. And the agent cannot exceed what he set, so it is standing authority to PROPOSE within a bound
// rather than standing authority to sign without one. That is the doctrine's own sentence: "always narrow,
// always short-TTL, always rate-limited, always revocable."
//
// LEGACY `redelegate: true` IS LIVE, and both easy readings are wrong. Treating it as unbounded preserves
// exactly the hole this closes; treating it as zero silently breaks agents mid-flight. So it takes the
// estate default and SAYS it is doing so — the same tighten-only shape as AD-12 3d, where a forgotten
// field fails safe rather than wide.
//
// Pure and dependency-free so test/redelegate-bound.mjs can drive it.

/** Estate defaults for a legacy or unspecified bound. Deliberately small: a forgotten field fails SAFE. */
export const REDELEGATE_DEFAULTS = Object.freeze({
  maxChildren: 8,      // total derived grants this parent may ever produce
  maxGrantees: 4,      // distinct recipients across those children
})

export interface RedelegateBound {
  maxChildren: number
  maxGrantees: number
  /** true when the parent carried a bare boolean and these are estate defaults, not the delegator's choice. */
  defaulted: boolean
}

/**
 * Read the bound off a parent's terms.
 *
 * Accepts three shapes, and the middle one is the whole point of the migration:
 *   `redelegate: false | undefined`  → no re-delegation at all
 *   `redelegate: true`               → LEGACY: estate defaults, flagged `defaulted`
 *   `redelegate: { max_children, max_grantees }` → the delegator's own bound
 *
 * A nonsense value is refused rather than coerced. Coercing would turn a typo into authority.
 */
export function boundOf(terms: unknown): { ok: true; bound: RedelegateBound } | { ok: false; why: string } {
  const t = (terms ?? {}) as Record<string, unknown>
  const r = t.redelegate
  if (r === undefined || r === null || r === false) {
    return { ok: false, why: 'this grant does not permit re-delegation' }
  }
  if (r === true) {
    return { ok: true, bound: { ...REDELEGATE_DEFAULTS, defaulted: true } }
  }
  if (typeof r !== 'object') {
    return { ok: false, why: `redelegate must be false, true, or a bound object; got ${typeof r}` }
  }
  const o = r as Record<string, unknown>
  const num = (v: unknown, d: number) => {
    if (v === undefined || v === null) return d
    return (typeof v === 'number' && Number.isInteger(v) && v > 0) ? v : NaN
  }
  const maxChildren = num(o.max_children, REDELEGATE_DEFAULTS.maxChildren)
  const maxGrantees = num(o.max_grantees, REDELEGATE_DEFAULTS.maxGrantees)
  if (Number.isNaN(maxChildren) || Number.isNaN(maxGrantees)) {
    return { ok: false, why: 'max_children and max_grantees must be positive integers when present' }
  }
  // TIGHTEN ONLY (AD-12 3d). A bound wider than the estate default is REFUSED, not clamped: a silent clamp
  // teaches the issuer they got what they asked for.
  if (maxChildren > REDELEGATE_DEFAULTS.maxChildren) {
    return { ok: false, why: `max_children may only be tightened: ${maxChildren} exceeds the estate default of ${REDELEGATE_DEFAULTS.maxChildren}` }
  }
  if (maxGrantees > REDELEGATE_DEFAULTS.maxGrantees) {
    return { ok: false, why: `max_grantees may only be tightened: ${maxGrantees} exceeds the estate default of ${REDELEGATE_DEFAULTS.maxGrantees}` }
  }
  return { ok: true, bound: { maxChildren, maxGrantees, defaulted: false } }
}

/**
 * Would one more derivation stay inside the bound?
 *
 * @param existing the rows already recorded for THIS parent (publisher+scope), from `nvoy_derived_children`
 * @param recipient the proposed new grantee
 *
 * REVOKED CHILDREN STILL COUNT toward maxChildren, and that is deliberate. The bound is on how far the
 * Director's data has been spread, not on how much of it is live: a key that was granted and revoked was
 * still handed the data once, and rotation does not un-see it. Counting only active children would let an
 * agent cycle indefinitely through the same budget.
 *
 * Grantees are counted as DISTINCT keys, so re-granting to someone who already holds a child does not
 * consume a fresh grantee slot — that is a re-issue to a party the Director already permitted.
 */
export function admitsAnother(
  bound: RedelegateBound,
  existing: Array<{ child?: { grantee?: string } }>,
  recipient: string,
): { ok: true } | { ok: false; why: string } {
  const rows = Array.isArray(existing) ? existing : []
  if (rows.length >= bound.maxChildren) {
    return { ok: false, why: `this grant's re-delegation budget is spent: ${rows.length} of ${bound.maxChildren} `
      + `children already issued${bound.defaulted ? ' (the estate default, because the parent carried a bare `redelegate: true`)' : ''}. `
      + 'Revoked children still count — the bound is on how far this data has been spread, not on how much is live.' }
  }
  const grantees = new Set(rows.map(r => r?.child?.grantee).filter(Boolean))
  if (!grantees.has(recipient) && grantees.size >= bound.maxGrantees) {
    return { ok: false, why: `this grant may reach ${bound.maxGrantees} distinct recipients and already reaches `
      + `${grantees.size}${bound.defaulted ? ' (the estate default)' : ''}. Re-granting to a key that already holds `
      + 'a child is still allowed — that party was already permitted.' }
  }
  return { ok: true }
}

/** What the Ledger should say about a parent's re-delegation budget. Honest about a defaulted bound. */
export function boundNote(bound: RedelegateBound, used: number): string {
  const base = `re-delegation: ${used}/${bound.maxChildren} children, up to ${bound.maxGrantees} recipients`
  return bound.defaulted
    ? `${base} — this grant carried a bare \`redelegate: true\`, so these are ESTATE DEFAULTS rather than a `
      + 'bound you chose. Re-issue it with an explicit bound to set your own.'
    : base
}
