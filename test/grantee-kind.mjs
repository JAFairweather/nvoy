// What KIND of party holds this grant — four answers, not two.
//
//   node test/grantee-kind.mjs
//
// The Ledger asked one question ("is this pubkey in nvoy_agents?") and used it to sort every grantee into
// `Agents` or `Other identities`. On a real estate that produced a heading reading
// "OTHER IDENTITIES · 21 grantees · 27 grants" containing side by side: a community member holding a
// waggle admission, an agent runtime nobody registered, and the DIRECTOR HIMSELF. Three different facts
// under one heading, so the heading meant nothing.
//
// Only the middle one is a defect. The first is correctly not an agent; the third is a category error.
// This suite pins all three apart, and pins the two judgement calls behind the split so a later change
// has to argue with them rather than quietly reverse them.

import { granteeKind, bucketGrantees, KIND_LABEL, KIND_NOTE, KIND_ORDER } from '../console/grantee-kind.mjs'

let pass = 0, fail = 0
const ok = (name, cond) => { console.log(`${cond ? 'ok  ' : 'FAIL'} — ${name}`); cond ? pass++ : fail++ }

const ME = 'd'.repeat(64), AGENT = 'a'.repeat(64), HUMAN = 'b'.repeat(64), GHOST = 'c'.repeat(64)
const admission = (pub, cap = 'admit') => ({ agent: pub, external: true, purpose: cap })
const dataGrant = (pub) => ({ agent: pub, external: false, scopeName: 'data:notes' })
const opts = (rows, registered = [AGENT]) => ({ me: ME, registered: new Set(registered), rows })

ok('the Director is `self`, never a peer of his own grantees',
  granteeKind(ME, opts([dataGrant(ME)])) === 'self')
ok('a registered key holding grants is an `agent`',
  granteeKind(AGENT, opts([dataGrant(AGENT)])) === 'agent')
ok('a key whose ONLY grants are admissions is `admitted`, not an agent',
  granteeKind(HUMAN, opts([admission(HUMAN)])) === 'admitted')
ok('…for every admission cap in the family',
  ['admit', 'admit+read', 'mirror'].every(c => granteeKind(HUMAN, opts([admission(HUMAN, c)])) === 'admitted'))
ok('a key holding an admission AND a data grant is NOT merely admitted — the data grant is the bigger fact',
  granteeKind(HUMAN, opts([admission(HUMAN), dataGrant(HUMAN)])) === 'unregistered')
ok('a task capability is authority, not admission',
  granteeKind(GHOST, opts([{ agent: GHOST, external: true, purpose: 'task' }])) === 'unregistered')
ok('an unregistered key holding a real grant is `unregistered` — the actual defect',
  granteeKind(GHOST, opts([dataGrant(GHOST)])) === 'unregistered')
ok('registration beats everything except being the Director',
  granteeKind(AGENT, opts([admission(AGENT)])) === 'agent')
ok('the Director wins even if he is also registered',
  granteeKind(ME, opts([dataGrant(ME)], [AGENT, ME])) === 'self')
ok('an unknown key with no rows is unregistered, never silently an agent',
  granteeKind('e'.repeat(64), opts([])) === 'unregistered')
ok('no `me` supplied does not make everyone self',
  granteeKind(ME, { registered: new Set(), rows: [dataGrant(ME)] }) === 'unregistered')

// ── bucketing ───────────────────────────────────────────────────────────────
const rows = [dataGrant(ME), dataGrant(AGENT), admission(HUMAN), dataGrant(GHOST)]
const b = bucketGrantees([ME, AGENT, HUMAN, GHOST], opts(rows))
ok('every grantee lands in exactly one bucket',
  [...b.values()].flat().sort().join() === [ME, AGENT, HUMAN, GHOST].sort().join())
ok('…and the four are told apart', b.size === 4)
ok('render order puts you first and the defect last',
  [...b.keys()].join() === 'self,agent,admitted,unregistered')
ok('an empty kind is omitted rather than growing a heading that says nothing',
  !bucketGrantees([AGENT], opts([dataGrant(AGENT)])).has('admitted'))
ok('KIND_ORDER covers every label and note', KIND_ORDER.every(k => KIND_LABEL[k] && KIND_NOTE[k]))

// ── the judgement calls, pinned as prose a later change has to argue with ──
ok('the admitted note REFUSES to register humans, and says why',
  /NOT agents/.test(KIND_NOTE.admitted) && /corrupt the roster/.test(KIND_NOTE.admitted))
ok('the unregistered note names the defect as the composer\'s, not the reader\'s',
  /does not register its grantee/.test(KIND_NOTE.unregistered) && /ruling 7/.test(KIND_NOTE.unregistered))
ok('the self note explains why the Director is separated rather than hidden',
  /you are the grantor/.test(KIND_NOTE.self))
ok('no heading is "Other identities" any more — the word did too much work',
  !Object.values(KIND_LABEL).some(l => /other identit/i.test(l)))

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
