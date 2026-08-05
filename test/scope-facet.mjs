// scope-facet.mjs — the Ledger's Type facet reads the scope NAMESPACE (nvoy#91, AD-8/AD-12).
//
// It used to grep the rendered display string:
//
//   if (n.includes('steer')) return 'steering'
//   if (/nactjaf|approval/.test(n)) return 'approvals'
//   if (n.includes('credential')) return 'credentials'
//   return 'data'
//
// Two defects, and `scopeKind` had NO test coverage, which is how they survived.
//
//   1. It greps a DISPLAY name. Rename an agent and its grants silently change facet — the
//      filter stops meaning what it says without anything failing.
//   2. One identity's name — `nactjaf` — was hardcoded into UI logic. That is a specific
//      identity load-bearing in a classifier that has nothing to do with it.
//
// And the fallback hid both: everything unrecognised returned 'data', so the classifier
// always LOOKED like it worked. An honest `unnamespaced` bucket is what makes a missing
// namespace visible instead of plausible.
//
//   node test/scope-facet.mjs

import { scopeKind } from '../console/scope-facet.mjs'

let pass = 0, fail = 0
const ok = (name, value, detail = '') => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}${value ? '' : ` (${detail})`}`); value ? pass++ : fail++ }
const kind = (scopeName, extra = {}) => scopeKind({ scopeName, ...extra })

// ── the AD-8 namespace ────────────────────────────────────────────────────────
ok('credential: is a credential', kind('credential:anthropic') === 'credential')
ok('data: is data', kind('data:travel-prefs') === 'data')
ok('profile: is data', kind('profile:contact-card') === 'data')
ok('capability: is action', kind('capability:waggle/admit') === 'action')

// ── the working scopes the estate actually uses ───────────────────────────────
ok('draft: is data (an offer, not authority)', kind('draft:post/9be302a1') === 'data')
ok('steer: is data', kind('steer:draft') === 'data')
ok('derived: is data', kind('derived:house-style/tone') === 'data')
ok('channel: is action (approver-channel authority)', kind('channel:bind') === 'action')

// ── the honest bucket ─────────────────────────────────────────────────────────
ok('an un-namespaced scope is unnamespaced, NOT silently filed as data',
  kind('house-style') === 'unnamespaced')
ok('an unknown namespace is unnamespaced rather than guessed',
  kind('sonar:ping') === 'unnamespaced')
ok('an empty name is unnamespaced', kind('') === 'unnamespaced')
ok('a missing name is unnamespaced', scopeKind({}) === 'unnamespaced')
ok('a leading colon is not a namespace', kind(':orphan') === 'unnamespaced')

// ── the regressions this exists to prevent ────────────────────────────────────
// Each of these was classified by the OLD substring rules and must no longer be.
ok('a scope merely CONTAINING "credential" is not a credential grant',
  kind('notes-about-credential-rotation') === 'unnamespaced')
ok('a scope merely CONTAINING "steer" is not steering',
  kind('steering-committee-minutes') === 'unnamespaced')
ok('an agent NAMED in a scope no longer decides the facet — the nactjaf hardcode is gone',
  kind('nactjaf-handover-notes') === 'unnamespaced')
ok('the word "approval" in a scope name no longer implies authority',
  kind('approval-process-doc') === 'unnamespaced')
// The inverse, and the sharper half: renaming an identity must not move its grants.
ok('renaming an agent does not change any facet',
  kind('credential:anthropic') === kind('credential:anthropic'.replace('anthropic', 'renamed-agent')))
// The scope id must not leak into classification — the old rule concatenated it.
ok('the opaque scope id cannot influence the facet',
  kind('house-style', { scope: 'credential-looking-scope-id' }) === 'unnamespaced')

// ── external capability grants classify by cap, not by name ───────────────────
// capgrants puts the da-cap in `purpose` on the row it builds; there is no scope name.
const ext = (purpose) => scopeKind({ external: true, purpose, scopeName: 'Channel admission' })
ok('admit is an admission', ext('admit') === 'admission')
ok('admit+read is an admission', ext('admit+read') === 'admission')
ok('mirror is an admission (a consent record about access)', ext('mirror') === 'admission')
ok('task is action', ext('task') === 'action')
ok('task+act is action', ext('task+act') === 'action')
ok('task-relay is action', ext('task-relay') === 'action')
ok('an UNKNOWN cap is still authority — action, never filed with data',
  ext('some-future-cap') === 'action')
ok('an external grant with no cap is action, not unnamespaced',
  scopeKind({ external: true, purpose: null }) === 'action')
ok('external classification ignores the display label entirely',
  scopeKind({ external: true, purpose: 'task', scopeName: 'credential:looks-like-one' }) === 'action')

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
