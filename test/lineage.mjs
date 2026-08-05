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

import { childrenOf, lineageSummary, mayHaveHiddenDescendants, coverageNote,
  lineageByParent, unrenderedLineage, parentKey } from '../console/lineage.mjs'
import { deriveDelegations } from '../console/ledgerlog.mjs'

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

// ── composition: what the Ledger ACTUALLY renders ─────────────────────────────
//
// The assertions above all pass on a build where the first derived child is invisible, because
// each one tests a function in isolation. The defect only exists in the composition: `renderLedger`
// builds cards from `deriveDelegations(index)` — this key's ISSUED grants — and then asks
// `childrenOf(index, d.scope, ME)`. A first-hop row carries the upstream delegator as
// `parent.publisher` (`mcp/src/subgrants.ts` stores the parent verbatim), so it matches no card.
//
// So this section drives the REAL `deriveDelegations` over a REAL index and asserts the property
// the screen owes: every readable row reaches the reader from its own parent identity.

const DIRECTOR = 'e'.repeat(64)

// An index shaped the way one actually arrives: this key issued one grant onward to LEAF2, and
// separately derived a child from `project-brief` — a grant the DIRECTOR issued TO this key.
const composed = {
  issued: [{ scope: 'my-own', scope_name: 'my-own', grantees: [LEAF2] }],
  received: [],
  nvoy_ledger: [{ t: 'granted', scope: 'my-own', agent: LEAF2, at: 500, v: 1, name: 'my-own' }],
  nvoy_derived_children: [
    // the case that motivated the PR: derived from a grant this key HOLDS
    row({ parent: { publisher: DIRECTOR, scope: 'project-brief', generation: 2 },
      child: { scope: 'kid-first', grantee: LEAF1, generation: 1, scope_name: 'derived:project-brief/tone' },
      issued_at: 1200 }),
    // and a later hop whose parent IS this key's own scope, which always worked
    row({ parent: { publisher: ME, scope: 'my-own', generation: 1 },
      child: { scope: 'kid-second', grantee: LEAF2, generation: 1, scope_name: 'derived:my-own/x' },
      issued_at: 1300 }),
  ],
}
const cards = deriveDelegations(composed)
// Exactly how renderLedger computes what it can host inline.
const covered = new Set(cards.map(d => parentKey(ME, d.scope)))
const inlineShown = cards.flatMap(d => childrenOf(composed, d.scope, ME))
const onward = unrenderedLineage(composed, covered)

ok('deriveDelegations produces a card for the grant this key ISSUED', cards.some(d => d.scope === 'my-own'))
ok('…and produces NO card for the grant this key HOLDS — which is why the inline call cannot host it',
  !cards.some(d => d.scope === 'project-brief'))
ok('the second-hop child IS shown inline, as it always was',
  inlineShown.some(k => k.child.scope === 'kid-second'))
ok('THE DEFECT: the first derived child is invisible to the inline call alone',
  !inlineShown.some(k => k.child.scope === 'kid-first'))
ok('THE FIX: the first derived child is visible in the onward view',
  onward.some(g => g.children.some(k => k.child.scope === 'kid-first')))
ok('…keyed by its REAL parent identity, not by this key',
  onward.some(g => g.publisher === DIRECTOR && g.scope === 'project-brief'))
ok('…carrying the parent generation, so the reader knows which key version it attenuated',
  onward.find(g => g.scope === 'project-brief')?.generation === 2)
ok('the onward view does not duplicate what a card already shows',
  !onward.some(g => g.children.some(k => k.child.scope === 'kid-second')))

// The partition invariant. This is the assertion that makes the class of bug unrepeatable: it
// fails for ANY row the composition drops, not just the one row this PR was about.
const rendered = new Set([...inlineShown, ...onward.flatMap(g => g.children)].map(k => k.child.scope))
ok('EVERY readable row reaches the reader — inline or onward, none dropped',
  composed.nvoy_derived_children.every(r => rendered.has(r.child.scope)),
  `dropped: ${composed.nvoy_derived_children.filter(r => !rendered.has(r.child.scope)).map(r => r.child.scope)}`)
ok('…and each row appears exactly once', rendered.size === composed.nvoy_derived_children.length)

// A row whose parent is neither an issued card nor a currently-readable received grant must still
// be reachable. The Ledger reports the miss; it does not drop the child to hide it.
const rotatedAway = { ...composed, nvoy_derived_children: [composed.nvoy_derived_children[0]] }
ok('a row whose parent grant is no longer readable is still shown, not silently dropped',
  unrenderedLineage(rotatedAway, new Set(deriveDelegations(rotatedAway).map(d => parentKey(ME, d.scope))))
    .flatMap(g => g.children).length === 1)

// Grouping is by the pair, never the `d` alone — the same conflation guarded at the top, at the
// level where two delegators could hand this key the same scope name.
const twoParents = index([
  row({ parent: { publisher: DIRECTOR, scope: 'brief' }, child: { scope: 'k1', grantee: LEAF1, generation: 1 } }),
  row({ parent: { publisher: OTHER, scope: 'brief' }, child: { scope: 'k2', grantee: LEAF2, generation: 1 } }),
])
ok('two delegators granting the same scope name stay two parents, not one',
  lineageByParent(twoParents).length === 2)

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
