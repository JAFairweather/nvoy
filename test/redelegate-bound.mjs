// Re-delegation carries an envelope, because it is standing authority (#111).
//
//   node test/redelegate-bound.mjs
//
// THE ASYMMETRY. AD-12 ruling 3 refuses an Action Grant at issuance if its envelope is absent — action
// class, max tier, TTL, rate limit, one bound approval path. The DATA side's equivalent, `terms.redelegate`,
// is a bare boolean. So an agent's authority to ACT had to be bounded in advance, while its authority to
// RE-DELEGATE the Director's data was yes-or-no and otherwise unlimited.
//
// I proposed two fixes on #111 and both fail:
//   · "check the child payload is a subset of the parent" — not computable over arbitrary app-defined JSON,
//     and a check that ALMOST worked would license the word "attenuated" while leaving gaps.
//   · "queue every derivation for a tap" — sound by the doctrine, but the lineage is encrypted to the
//     sub-issuer PRECISELY so a delegator cannot see its agent's fan-out (nvoy#103). Approving each leaf
//     means seeing every leaf.
//
// Bounding the envelope resolves both: the Director sets a budget at issuance and never sees the leaves, so
// the privacy property holds AND the authority is bounded. That is the doctrine's own sentence — "always
// narrow, always short-TTL, always rate-limited, always revocable" — applied to data rather than action.

import assert from 'node:assert'
import { boundOf, admitsAnother, boundNote, REDELEGATE_DEFAULTS } from '../mcp/dist/redelegate-bound.js'

let pass = 0, fail = 0
const t = (name, fn) => { try { fn(); console.log(`ok   — ${name}`); pass++ }
  catch (e) { console.log(`FAIL — ${name}\n       ${e.message}`); fail++ } }

const A = 'a'.repeat(64), B = 'b'.repeat(64), C = 'c'.repeat(64)
const child = (g) => ({ child: { grantee: g } })

// ── reading the bound ───────────────────────────────────────────────────────
t('no redelegate term means no re-delegation', () => {
  for (const terms of [{}, { redelegate: false }, undefined, null])
    assert.equal(boundOf(terms).ok, false)
})
t('LEGACY `true` takes the estate default and is FLAGGED as defaulted', () => {
  // Neither easy reading is right: unbounded preserves the hole, zero breaks live agents mid-flight.
  const r = boundOf({ redelegate: true })
  assert.equal(r.ok, true)
  assert.equal(r.bound.maxChildren, REDELEGATE_DEFAULTS.maxChildren)
  assert.equal(r.bound.defaulted, true, 'the Director must be able to tell this was not his choice')
})
t('an explicit bound is the delegator\'s own, not defaulted', () => {
  const r = boundOf({ redelegate: { max_children: 2, max_grantees: 1 } })
  assert.equal(r.bound.maxChildren, 2)
  assert.equal(r.bound.defaulted, false)
})
t('a WIDER bound is refused, not clamped (AD-12 3d)', () => {
  const r = boundOf({ redelegate: { max_children: REDELEGATE_DEFAULTS.maxChildren + 1 } })
  assert.equal(r.ok, false)
  assert.match(r.why, /may only be tightened/)
})
t('nonsense is refused rather than coerced — a typo must not become authority', () => {
  for (const bad of [{ max_children: 0 }, { max_children: -1 }, { max_children: 1.5 }, { max_children: 'lots' }])
    assert.equal(boundOf({ redelegate: bad }).ok, false, `accepted ${JSON.stringify(bad)}`)
  assert.equal(boundOf({ redelegate: 'yes' }).ok, false)
})
t('a partial bound fills the missing half from the default, safely', () => {
  const r = boundOf({ redelegate: { max_children: 2 } })
  assert.equal(r.bound.maxGrantees, REDELEGATE_DEFAULTS.maxGrantees)
})

// ── enforcing it ────────────────────────────────────────────────────────────
const bound = boundOf({ redelegate: { max_children: 3, max_grantees: 2 } }).bound
t('within budget, another derivation is admitted', () => {
  assert.equal(admitsAnother(bound, [child(A)], B).ok, true)
})
t('the child budget stops the next derivation, and says what is spent', () => {
  const r = admitsAnother(bound, [child(A), child(A), child(A)], B)
  assert.equal(r.ok, false)
  assert.match(r.why, /3 of 3/)
})
t('REVOKED children still count — rotation does not un-see data', () => {
  // Counting only live children would let an agent cycle through the same budget forever. The bound is on
  // how far this data has been SPREAD, not on how much of it is currently readable.
  const rows = [child(A), child(B), child(C)]   // any/all may since have been revoked
  assert.equal(admitsAnother(bound, rows, 'd'.repeat(64)).ok, false)
  assert.match(admitsAnother(bound, rows, 'd'.repeat(64)).why, /still count/)
})
t('the grantee budget stops a NEW recipient', () => {
  const r = admitsAnother(bound, [child(A), child(B)], C)
  assert.equal(r.ok, false)
  assert.match(r.why, /2 distinct recipients/)
})
t('…but re-granting to an EXISTING recipient is allowed — already permitted', () => {
  assert.equal(admitsAnother(bound, [child(A), child(B)], A).ok, true)
})
t('a defaulted bound says so in the refusal, so the Director knows why', () => {
  const d = boundOf({ redelegate: true }).bound
  const rows = Array.from({ length: d.maxChildren }, () => child(A))
  assert.match(admitsAnother(d, rows, B).why, /estate default/)
})
t('garbage rows do not throw inside a signing boundary', () => {
  assert.equal(admitsAnother(bound, null, A).ok, true)
  assert.equal(admitsAnother(bound, undefined, A).ok, true)
  assert.equal(admitsAnother(bound, [{ child: {} }], A).ok, true, 'one unreadable row leaves budget')
})
t('a MALFORMED row still counts toward the child budget — fail safe, not fail wide', () => {
  // My first expectation here was that garbage should be ignored. That is the wrong direction: a row whose
  // grantee cannot be read is still a recorded derivation, and discounting it would let a corrupted index
  // WIDEN the budget. Counting it can only ever be conservative.
  const r = admitsAnother(bound, [null, {}, { child: {} }], A)
  assert.equal(r.ok, false)
  assert.match(r.why, /3 of 3/)
})

// ── what the Ledger tells the Director ─────────────────────────────────────
t('the note reports the budget as used/total', () => {
  assert.match(boundNote(bound, 1), /1\/3 children, up to 2 recipients/)
})
t('a defaulted bound is disclosed as NOT his choice, with the repair', () => {
  const note = boundNote(boundOf({ redelegate: true }).bound, 0)
  assert.match(note, /ESTATE DEFAULTS rather than a bound you chose/)
  assert.match(note, /Re-issue it with an explicit bound/)
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
