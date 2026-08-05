// lineage.mjs — reading back what THIS key granted onward (nvoy#93).
//
// `mcp/src/subgrants.ts` has always recorded every derived grant and cascaded revocation
// recursively. Nothing read it, so attenuation — authority NARROWING as it spreads — was
// invisible even to the party who performed it.
//
// The property this suite protects is not the rendering. It is the honesty of the coverage
// claim. A row is legible to exactly one key: `saveLineage` writes through the sub-issuer's
// signer and `loadGrantIndex` decrypts to self, so a delegator cannot read what its agent
// granted onward — deliberately, because `subgrants.ts` avoids "a new public linkage between
// delegator and leaf."
//
// So the Ledger must never imply completeness it cannot have. Two failure modes, both worse
// than showing nothing:
//   · claiming a grant has no descendants when it holds a redelegate term and the holder's
//     ledger is unreadable — absence of a readable row is not absence of a child;
//   · attributing someone else's derivation to this key by matching a scope `d` alone.
//
//   node test/lineage.mjs

import { childrenOf, lineageSummary, mayHaveHiddenDescendants, coverageNote } from '../console/lineage.mjs'

let pass = 0, fail = 0
const ok = (name, value, detail = '') => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}${value ? '' : ` (${detail})`}`); value ? pass++ : fail++ }

const ME = 'a'.repeat(64), OTHER = 'b'.repeat(64), LEAF1 = 'c'.repeat(64), LEAF2 = 'd'.repeat(64)
const row = (o = {}) => ({
  parent: { publisher: ME, scope: 'house-style', generation: 3, ...(o.parent || {}) },
  child: { scope: 'kid-1', generation: 1, grantee: LEAF1, scope_name: 'derived:house-style/tone', ...(o.child || {}) },
  state: o.state || 'active',
  issued_at: o.issued_at ?? 1000,
  ...(o.revoked_at ? { revoked_at: o.revoked_at } : {}),
})
const index = (rows) => ({ issued: [], received: [], nvoy_derived_children: rows })

// ── reading the chain ─────────────────────────────────────────────────────────
ok('a child of this parent is found', childrenOf(index([row()]), 'house-style', ME).length === 1)
ok('a child of a DIFFERENT parent scope is not', childrenOf(index([row()]), 'other-scope', ME).length === 0)
ok('a same-named scope from another publisher is not conflated — the d alone is not identity',
  childrenOf(index([row({ parent: { publisher: OTHER } })]), 'house-style', ME).length === 0)
ok('publisher matching can be waived when the caller does not know it',
  childrenOf(index([row({ parent: { publisher: OTHER } })]), 'house-style', null).length === 1)
ok('the chain reads in the order it happened',
  childrenOf(index([row({ issued_at: 200, child: { scope: 'late' } }), row({ issued_at: 100, child: { scope: 'early' } })]), 'house-style', ME)
    .map(r => r.child.scope).join() === 'early,late')
ok('a revoked child is still returned — a severed branch is history, not nothing',
  childrenOf(index([row({ state: 'revoked', revoked_at: 2000 })]), 'house-style', ME)[0].state === 'revoked')

// ── malformed rows are ignored, never guessed ────────────────────────────────
for (const [name, bad] of [
  ['a row with no parent', { child: { scope: 'x', grantee: LEAF1 }, state: 'active' }],
  ['a row with no child', { parent: { publisher: ME, scope: 'house-style' }, state: 'active' }],
  ['a row with an unknown state', row({ state: 'pending' })],
  ['a non-object row', 'nonsense'],
  ['a null row', null],
]) {
  ok(`${name} is ignored`, childrenOf(index([bad]), 'house-style', ME).length === 0)
}
ok('a missing lineage field is not an error', childrenOf({ issued: [], received: [] }, 'house-style', ME).length === 0)
ok('a non-array lineage field is not an error', childrenOf(index('nope'), 'house-style', ME).length === 0)
ok('a missing index is not an error', childrenOf(undefined, 'house-style', ME).length === 0)

// ── the summary ───────────────────────────────────────────────────────────────
const many = index([
  row({ child: { scope: 'k1', grantee: LEAF1 } }),
  row({ child: { scope: 'k2', grantee: LEAF2 }, state: 'revoked', revoked_at: 9 }),
  row({ parent: { scope: 'project-brief' }, child: { scope: 'k3', grantee: LEAF1 } }),
])
const sum = lineageSummary(many)
ok('the summary counts rows, active and revoked', sum.rows === 3 && sum.active === 2 && sum.revoked === 1)
ok('the summary counts distinct parents', sum.parents === 2)
ok('the summary counts distinct grantees, not rows', sum.grantees === 2)

// ── the coverage claim — the part that must not lie ──────────────────────────
// A grant this key ISSUED to an agent, with redelegate permitted: the agent may have derived,
// and its ledger is encrypted to itself. Silence here is not evidence of no children.
const issuedToAgent = { scope: 'house-style', agent: OTHER, terms: { redelegate: true } }
ok('a redelegate-permitted grant issued to someone else may have hidden descendants',
  mayHaveHiddenDescendants(issuedToAgent, ME) === true)
const note = coverageNote(issuedToAgent, index([]), ME)
ok('…and the row says so rather than implying none exist', typeof note === 'string' && note.length > 40)
ok('…and it explains WHY it cannot be shown, not merely that it cannot',
  /link you to every leaf|design refuses/.test(note))

ok('a grant that forbids redelegation makes no such claim',
  coverageNote({ scope: 'house-style', agent: OTHER, terms: { redelegate: false } }, index([]), ME) === null)
ok('a grant with no terms makes no such claim',
  coverageNote({ scope: 'house-style', agent: OTHER }, index([]), ME) === null)
// A grant this key HOLDS: its own derivations are readable, so there is nothing to disclaim.
ok('a grant held by this key needs no disclaimer — its own derivations are readable',
  mayHaveHiddenDescendants({ scope: 'house-style', agent: ME, terms: { redelegate: true } }, ME) === false)
// And once children ARE shown, the disclaimer would be noise.
ok('a row that already shows children does not also disclaim',
  coverageNote({ scope: 'house-style', agent: ME, terms: { redelegate: true } },
    index([row({ parent: { publisher: ME } })]), ME) === null)

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
