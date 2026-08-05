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
