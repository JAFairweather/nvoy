// lineage.mjs — what THIS key granted onward, read from its own Grant Index.
//
// `mcp/src/subgrants.ts` records every derived grant it mints as an `nvoy_derived_children`
// row, and cascades revocation recursively when a parent dies. Nothing has ever read it back,
// so attenuation — the one mechanism that lets authority NARROW as it spreads — has been
// invisible even to the party who performed it.
//
// WHOSE LINEAGE THIS IS, AND WHY IT CANNOT BE ANYONE ELSE'S. `saveLineage` writes through the
// sub-issuer's own signer, and `loadGrantIndex` reads `{ kinds:[10440], authors:[own pubkey] }`
// and NIP-44-decrypts to self. So a row is legible to exactly one key: the one that issued the
// child. A delegator therefore cannot see what its agent granted onward, and that is a design
// property rather than a gap — `subgrants.ts` keeps the ledger self-encrypted specifically to
// avoid "a new public linkage between delegator and leaf." Surfacing an agent's fan-out to its
// delegator would mean publishing that chain.
//
// The consequence a reader must be told, because otherwise the Ledger implies completeness it
// does not have: a grant whose terms permit re-delegation can have descendants this console
// will never show.
//
// Pure and DOM-free so `test/lineage.mjs` can drive it under Node — same reason
// `scope-facet.mjs` moved out of `ledger.mjs`.

/** A row as `subgrants.ts` writes it. Anything not matching this shape is ignored, not guessed. */
const wellFormed = (r) =>
  !!r && typeof r === 'object' &&
  !!r.parent && typeof r.parent.publisher === 'string' && typeof r.parent.scope === 'string' &&
  !!r.child && typeof r.child.scope === 'string' && typeof r.child.grantee === 'string' &&
  (r.state === 'active' || r.state === 'revoked')

/**
 * Children this key issued from one parent scope.
 * @param index the signed-in key's decrypted Grant Index
 * @param parentScope the `d` of the parent grant a row is being rendered for
 * @param parentPublisher optional — the parent's author, when known, so two scopes that
 *   happen to share a `d` across publishers cannot be conflated
 */
export function childrenOf(index, parentScope, parentPublisher = null) {
  const rows = Array.isArray(index?.nvoy_derived_children) ? index.nvoy_derived_children : []
  return rows
    .filter(wellFormed)
    .filter(r => r.parent.scope === parentScope &&
      (parentPublisher === null || r.parent.publisher === parentPublisher))
    // Newest last reads as a chain in the order it happened.
    .sort((a, b) => (a.issued_at || 0) - (b.issued_at || 0))
}

/** The join key for a parent identity. A scope `d` is only unique per publisher. */
export const parentKey = (publisher, scope) => `${publisher}:${scope}`

/**
 * Every readable row, grouped by its REAL parent identity `(publisher, scope)`.
 *
 * This is the total partition of the lineage ledger: each row lands in exactly one group, so a
 * caller that renders every group cannot silently omit a row. That property is the point.
 * `childrenOf(index, scope, selfPub)` answers a NARROWER question — children derived from a scope
 * THIS key published — and is the right call for a card the Ledger built from `index.issued`. But
 * the first hop of an attenuation chain has `parent.publisher = the upstream delegator`
 * (`mcp/src/subgrants.ts` writes the parent verbatim), so it belongs to no issued scope and would
 * be invisible to a view built only from `deriveDelegations`. Grouping by the real parent is how a
 * row's parent identity is recovered rather than assumed.
 */
export function lineageByParent(index) {
  const rows = (Array.isArray(index?.nvoy_derived_children) ? index.nvoy_derived_children : []).filter(wellFormed)
  const groups = new Map()
  for (const r of rows) {
    const key = parentKey(r.parent.publisher, r.parent.scope)
    if (!groups.has(key)) groups.set(key, {
      key,
      publisher: r.parent.publisher,
      scope: r.parent.scope,
      generation: typeof r.parent.generation === 'number' ? r.parent.generation : null,
      children: [],
    })
    groups.get(key).children.push(r)
  }
  for (const g of groups.values()) g.children.sort((a, b) => (a.issued_at || 0) - (b.issued_at || 0))
  return [...groups.values()].sort((a, b) => (b.children[0]?.issued_at || 0) - (a.children[0]?.issued_at || 0))
}

/**
 * The lineage groups a caller has NOT already rendered under a parent card.
 *
 * `renderedParents` is the set of `parentKey(publisher, scope)` values the caller can show inline.
 * Whatever comes back has no home yet and MUST be given one — the Ledger may not claim to show
 * what this key granted onward while dropping the rows whose parent it never had a card for.
 */
export function unrenderedLineage(index, renderedParents) {
  const seen = renderedParents instanceof Set ? renderedParents : new Set(renderedParents || [])
  return lineageByParent(index).filter(g => !seen.has(g.key))
}

/** Every parent scope this key has derived from — for a "granted onward" summary. */
export function lineageSummary(index) {
  const rows = (Array.isArray(index?.nvoy_derived_children) ? index.nvoy_derived_children : []).filter(wellFormed)
  const active = rows.filter(r => r.state === 'active').length
  return {
    rows: rows.length,
    active,
    revoked: rows.length - active,
    parents: new Set(rows.map(r => `${r.parent.publisher}:${r.parent.scope}`)).size,
    grantees: new Set(rows.map(r => r.child.grantee)).size,
  }
}

/**
 * Whether a grant can have descendants this console cannot show.
 *
 * True when the terms permit re-delegation and the grant was issued BY someone else — i.e. the
 * holder is a runtime that may have derived from it, and its ledger is encrypted to itself.
 * The distinction matters: for a grant this key issued to an agent, the agent's derivations are
 * unreadable; for a grant this key HOLDS, its own derivations are readable and shown.
 */
export function mayHaveHiddenDescendants(d, selfPub) {
  return d?.terms?.redelegate === true && d?.agent !== selfPub
}

/**
 * One honest line about coverage, for a grant row.
 * Returns null when there is nothing to disclaim — never a reassuring "none", because absence
 * of a readable row is not evidence of absence of a child.
 */
export function coverageNote(d, index, selfPub) {
  const mine = childrenOf(index, d?.scope, selfPub)
  if (mine.length) return null                       // shown below the row; nothing hidden to flag
  if (!mayHaveHiddenDescendants(d, selfPub)) return null
  return 'You permitted re-delegation, so this grant may have descendants. They are recorded on the ' +
    'holder\'s own encrypted index and cannot be shown here — publishing that chain would link you ' +
    'to every leaf, which the design refuses.'
}
