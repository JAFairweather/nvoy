// scope-facet.mjs — what KIND of authority a grant conveys, decided by its scope namespace.
//
// Pure and dependency-free on purpose: the Ledger imports it, `test/scope-facet.mjs` imports it
// under Node, and the agent page and Nact's action surface will both need the same answer. A
// classifier that lives inside a DOM module cannot be tested, which is how the version this
// replaces went un-covered long enough to hardcode an identity's name into UI logic.

// The "type" facet: classify a delegation by the nature of what it grants — from the SCOPE
// NAMESPACE, never from a substring of a display string.
//
// It used to grep the rendered name: `n.includes('steer')`, `/nactjaf|approval/`,
// `n.includes('credential')`. Two things wrong with that. A facet that greps a display name
// lies the moment someone renames an agent — and one identity's name was hardcoded into the
// classifier, so `nactjaf` was load-bearing UI logic: rename that identity and its grants
// silently leave the facet they belonged to.
//
// AD-8 blessed the namespace precisely so this would not be necessary, and named this console
// as the consumer: `profile:* · credential:* · data:* · capability:*`, plus the working scopes
// the estate actually uses (`draft:`, `steer:`, `derived:`, `channel:`). AD-12 settles the
// facet values.
//
// A scope with no namespace is `unnamespaced` — an honest bucket rather than a guess. Filing
// unrecognised scopes under `data` by default is how the old classifier came to LOOK like it
// worked: everything fell somewhere plausible.
export const NS_TYPE = {
  credential: 'credential',
  capability: 'action',
  channel: 'action',
  data: 'data',
  profile: 'data',
  draft: 'data',
  steer: 'data',
  derived: 'data',
}
// A capability grant read off the relays carries its `da-cap`, which is more specific than any
// scope name: admission and tasking are different kinds of authority and an operator filters
// for them separately. (capgrants puts the cap in `purpose` on the row it builds.)
export const CAP_TYPE = {
  admit: 'admission', 'admit+read': 'admission', mirror: 'admission',
  task: 'action', 'task+act': 'action', 'task-relay': 'action',
}
export function scopeKind(d) {
  // External grants carry no Nvoy scope name, so the namespace parse cannot apply — classify
  // by the capability they assert. An unknown cap is still authority, so it reads as `action`
  // rather than being filed with data.
  if (d.external) return CAP_TYPE[d.purpose] || 'action'
  const name = String(d.scopeName || '')
  const i = name.indexOf(':')
  if (i <= 0) return 'unnamespaced'
  return NS_TYPE[name.slice(0, i).trim().toLowerCase()] || 'unnamespaced'
}
export const TYPES = ['data', 'credential', 'action', 'admission', 'unnamespaced']
