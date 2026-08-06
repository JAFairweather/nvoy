// grantee-kind.mjs — what KIND of party holds this grant.
//
// The Ledger asked one question — "is this pubkey in `nvoy_agents`?" — and used the answer to sort every
// grantee into `Agents` or `Other identities`. On a real estate that produced a heading reading
// "OTHER IDENTITIES · 21 grantees · 27 grants" containing, side by side:
//
//   · a community member holding a waggle `admit` capability — a HUMAN who may post in a channel
//   · an agent runtime with four grants that nobody ever registered
//   · the DIRECTOR HIMSELF
//
// Three different facts under one heading, so the heading meant nothing. Only the middle one is a
// registry gap; the first is correctly not an agent, and the third is a category error — the grantor
// listed as a peer of his grantees.
//
// WHY THE GAP EXISTS, since the fix is not just cosmetic. Only two code paths ever append to
// `nvoy_agents`: approving an access request (`requests.mjs`) and pasting an npub (`agents.mjs`).
// `delegate.mjs` — the data-grant composer — never touches it. So issuing a grant does not register its
// grantee, and AD-12 ruling 7 ("Nvoy is the front door and the only place an Agent is created") is a
// doctrine the composers do not implement.
//
// THE TWO JUDGEMENT CALLS, recorded because they are decisions and not deductions:
//
//  1. An admitted community member is NOT an agent. It holds a capability over a channel; it does not
//     act on the Director's behalf. So the fix is a third bucket driven by `da-cap`, NOT registering
//     them — registering a human as an agent would corrupt the roster to tidy a heading, and every
//     slice projecting that roster would inherit the error.
//  2. The Director gets his own labelled row rather than being filtered out. Excluding him silently
//     would hide real self-grants (a credential granted to his own key is a legitimate thing to see);
//     showing him unlabelled among his grantees is what currently misleads.
//
// Pure and DOM-free so test/grantee-kind.mjs can drive it.

/** Capabilities that admit a party to a slice rather than delegating the Director's authority. */
const ADMISSION_CAPS = new Set(['admit', 'admit+read', 'mirror'])

/**
 * Classify one grantee.
 *
 * @param pub       the grantee's hex pubkey
 * @param opts.me   the signed-in Director's hex pubkey
 * @param opts.registered  Set of pubkeys in `nvoy_agents`
 * @param opts.rows        every delegation row for this grantee (to read its caps)
 * @returns 'self' | 'agent' | 'admitted' | 'unregistered'
 */
export function granteeKind(pub, { me = null, registered = new Set(), rows = [] } = {}) {
  if (me && pub === me) return 'self'
  if (registered.has(pub)) return 'agent'
  // An external capability grant carries its `da-cap` in `purpose` (scope-facet.mjs). A party whose
  // ONLY grants are admissions is an admitted participant, not an agent this key delegates to. "Only"
  // matters: a key holding both an admission and a data grant is being delegated to, and the data grant
  // is the more consequential fact.
  const mine = rows.filter(r => r?.agent === pub)
  if (mine.length && mine.every(r => r.external && ADMISSION_CAPS.has(r.purpose))) return 'admitted'
  return 'unregistered'
}

/** Section headings and the sentence each one owes the reader. */
export const KIND_LABEL = {
  self: 'You',
  agent: 'Agents',
  admitted: 'Admitted to your apps',
  unregistered: 'Holds a grant · not registered',
}
export const KIND_NOTE = {
  self: 'Grants where your own key is the grantee. Shown separately because you are the grantor here — '
    + 'listing yourself among the parties you delegate to is what made this list unreadable.',
  agent: 'In your agent registry, and holding grants.',
  admitted: 'These hold a capability over one of your apps — posting in a community, being mirrored. '
    + 'They are NOT agents and are deliberately not registered as such: they do not act on your behalf, '
    + 'and registering a person as an agent would corrupt the roster every slice projects.',
  unregistered: 'These hold grants you issued and are absent from your agent registry, so nothing that '
    + 'reads the registry — Nact, a slice — knows they exist. Issuing a grant does not register its '
    + 'grantee today (AD-12 ruling 7 says it should).',
}

/** Render order: you, then agents, then admitted parties, then the gap that needs attention. */
export const KIND_ORDER = ['self', 'agent', 'admitted', 'unregistered']

/**
 * Bucket every grantee. Returns a Map kind → pubkeys, in KIND_ORDER, omitting empty kinds so a clean
 * estate does not grow four headings to say nothing.
 */
export function bucketGrantees(pubs, opts) {
  const out = new Map()
  for (const kind of KIND_ORDER) out.set(kind, [])
  for (const pub of pubs) out.get(granteeKind(pub, opts)).push(pub)
  for (const [k, v] of out) if (!v.length) out.delete(k)
  return out
}
