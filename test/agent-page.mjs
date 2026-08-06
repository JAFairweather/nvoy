// agent-page.mjs — the screen renders what it claims to, and stays silent about what it cannot see.
//
//   node test/agent-page.mjs
//
// WHY THIS EXISTS. The agent page shipped with a section that could never render. It asked
// `childrenOf(state.index, null, state.me)` for "everything I derived to this agent", but
// `childrenOf` filters `r.parent.scope === parentScope`, and `wellFormed` guarantees that field is a
// string — so a `null` wildcard is always false. The "Granted onward" heading was unreachable code.
// Nothing caught it: no test imported the page, and a section that renders nothing looks exactly
// like an agent with no derived children.
//
// That is the same defect class twice over. The Ledger dropped first-hop rows by filtering on the
// wrong publisher; the agent page dropped every row by filtering on a parent it did not care about.
// Both were invisible because ABSENCE IS THE FAILURE MODE OF THIS WHOLE SCREEN — and this screen's
// entire purpose is to distinguish "nothing there" from "nobody answered".
//
// So this suite drives the REAL `renderAgentPage` against a minimal DOM and asserts on the HTML it
// produces. A unit test of the helper would not have caught the original bug, because the helper was
// correct — it was asked the wrong question.

import assert from 'node:assert'
import { getPublicKey, generateSecretKey } from 'nostr-tools'

let pass = 0, fail = 0
const ok = (name, fn) => {
  try { fn(); console.log(`ok   — ${name}`); pass++ }
  catch (e) { console.log(`FAIL — ${name}\n       ${e.message}`); fail++ }
}

// ── a DOM just real enough to render into, and to read back out of ────────────
// Unlike console-smoke's shim, `getElementById` must return STABLE elements: the page writes to
// `$('agent').innerHTML` and this suite then reads it. A fresh stub per call would discard the
// output and every assertion would pass against an empty string.
const els = new Map()
const mk = (doc, id = '') => {
  const t = {
    // `style` needs setProperty: the plane switcher sets a per-app accent as a CSS custom property.
    id, style: { setProperty() {}, removeProperty() {}, getPropertyValue: () => '' },
    dataset: {}, hidden: false, textContent: '', innerHTML: '', value: '', disabled: false,
    classList: { toggle() {}, add() {}, remove() {}, contains: () => false },
    append() {}, appendChild() {}, addEventListener() {}, insertAdjacentHTML() {},
    setAttribute() {}, removeAttribute() {}, getAttribute: () => null,
    focus() {}, scrollIntoView() {}, remove() {}, closest: () => null, select() {},
    onclick: null, onkeydown: null, oninput: null,
  }
  t.ownerDocument = doc
  t.querySelector = () => mk(doc)
  t.querySelectorAll = () => []
  return t
}
const doc = {}
Object.assign(doc, mk(doc), {
  getElementById: (id) => { if (!els.has(id)) els.set(id, mk(doc, id)); return els.get(id) },
  querySelector: () => mk(doc), querySelectorAll: () => [],
  createElement: () => mk(doc), head: mk(doc), body: mk(doc), addEventListener() {},
})
globalThis.document = doc
globalThis.location = { hash: '', replace() {} }
globalThis.window = { location: globalThis.location, addEventListener() {}, matchMedia: () => ({ matches: false, addEventListener() {} }) }
const store = () => ({ getItem: () => null, setItem() {}, removeItem() {} })
globalThis.localStorage = store()
globalThis.sessionStorage = store()
globalThis.WebSocket = class { constructor() {} close() {} send() {} }
globalThis.alert = () => {}

const { state } = await import('../console/main.mjs')
const { openAgentPage, renderAgentPage } = await import('../console/agent-page.mjs')
const { childrenTo, childrenOf } = await import('../console/lineage.mjs')

const key = () => getPublicKey(generateSecretKey())
const ME = key(), AGENT = key(), DIRECTOR = key(), OTHER = key()

const derived = (o = {}) => ({
  parent: { publisher: DIRECTOR, scope: 'project-brief', generation: 2, ...(o.parent || {}) },
  child: { scope: 'kid-1', generation: 1, grantee: AGENT, scope_name: 'derived:brief/tone', ...(o.child || {}) },
  state: o.state || 'active',
  issued_at: o.issued_at ?? 1000,
})

/** Put the console into a known state and render the page for AGENT. */
const render = ({ delegations = [], lineage = [], agents = [], received = [] } = {}) => {
  state.me = ME
  state.profiles = new Map()
  state.received = received
  state.pendingRelinquish = []
  state.delegations = delegations
  state.index = { issued: [], received: [], nvoy_agents: agents, nvoy_ledger: [], nvoy_derived_children: lineage }
  openAgentPage(AGENT)
  renderAgentPage()
  return els.get('agent').innerHTML
}

const grant = (o = {}) => ({
  scope: 'house-style', scopeName: 'house-style', agent: AGENT, status: 'active', v: 3,
  terms: {}, purpose: '', expiresAt: null, ...o,
})

// ── the bug: a section that could never render ────────────────────────────────
ok('the wildcard the page originally used matches nothing — the trap, pinned', () => {
  // Kept as an assertion rather than a comment so nobody reintroduces it believing it works.
  assert.equal(childrenOf({ nvoy_derived_children: [derived()] }, null, ME).length, 0)
})
ok('childrenTo finds a child by grantee, whatever parent it came from', () => {
  assert.equal(childrenTo({ nvoy_derived_children: [derived()] }, AGENT).length, 1)
})
ok('…including a FIRST-HOP child, whose parent publisher is the upstream delegator', () => {
  const rows = childrenTo({ nvoy_derived_children: [derived({ parent: { publisher: DIRECTOR } })] }, AGENT)
  assert.equal(rows.length, 1, 'a first-hop derivation must not be filtered out by publisher')
  assert.equal(rows[0].parent.publisher, DIRECTOR)
})
ok('…and does not leak another agent\'s children', () => {
  assert.equal(childrenTo({ nvoy_derived_children: [derived({ child: { grantee: OTHER } })] }, AGENT).length, 0)
})

// ── the composition: the rendered page, which is what the bug lived in ───────
ok('THE REGRESSION: a derived child RENDERS in the page, not just in the helper', () => {
  const html = render({ lineage: [derived()] })
  assert.match(html, /Granted onward/, 'the section heading must appear')
  assert.match(html, /derived:brief\/tone/, 'the child scope name must appear')
})
ok('the section is absent — not empty-with-a-count — when there is nothing derived', () => {
  const html = render({ lineage: [] })
  assert.doesNotMatch(html, /Granted onward/)
})
ok('a severed child still renders, marked severed — a cut branch is history', () => {
  const html = render({ lineage: [derived({ state: 'revoked' })] })
  assert.match(html, /severed/)
})

// ── the honesty contract, which is the load-bearing part of the screen ───────
ok('custody says Nact did not answer, and says what that is NOT', () => {
  const html = render()
  assert.match(html, /Key custody/)
  assert.match(html, /did not answer/)
  assert.match(html, /no key on the box/, 'must name the wrong conclusion it is preventing')
})
ok('approval path is a skeleton too — never a guess derived from nothing', () => {
  assert.match(render(), /Approval path/)
})
ok('Where it acts names the slices and reports that none answered', () => {
  const html = render()
  assert.match(html, /Where it acts/)
  assert.match(html, /waggle and Ngage/)
  assert.match(html, /this agent acts nowhere/, 'must name the wrong conclusion it is preventing')
})
ok('an admission is described as what you granted, NOT as proof a slice honours it', () => {
  // The real shape: an admission is an EXTERNAL grant read off the relays whose `da-cap` lands in
  // `purpose` (scope-facet.mjs). A `capability:*` scope name classifies as `action` — the terms live
  // there, but the enforceable cap is the public tag, which is the seam AD-12 records.
  const html = render({ delegations: [grant({ external: true, purpose: 'admit', scopeName: '' })] })
  // Whitespace-tolerant: the copy is indented inside a template literal, so it carries a newline
  // and the surrounding indent. Matching the exact spacing would make this a formatting test.
  assert.match(html, /not proof a slice is\s+honouring it/)
  assert.match(html, /You signed 1 admission/)
})
ok('an idle agent reports "no runtime answered", never that it is idle', () => {
  const html = render()
  assert.match(html, /Running now/)
  assert.match(html, /this agent is idle/, 'the skeleton must name "idle" as the conclusion NOT to draw')
})
ok('a grantee absent from the registry is marked not registered, not silently promoted', () => {
  assert.match(render({ agents: [] }), /not registered/)
})
ok('a registered agent is badged as one', () => {
  assert.doesNotMatch(render({ agents: [{ pub: AGENT, added_at: 1 }] }), /not registered/)
})

// ── revoke-everything must enumerate, and must state its limits ──────────────
ok('with nothing active, the page says so instead of offering a blanket revoke', () => {
  const html = render({ delegations: [grant({ status: 'revoked' })] })
  assert.match(html, /Nothing active to revoke/)
})
ok('with active grants, the count is stated and each is promised before signing', () => {
  const html = render({ delegations: [grant(), grant({ scope: 'brief', scopeName: 'brief' })] })
  assert.match(html, /2 active grants/)
  assert.match(html, /shown each one before anything is signed/)
})

// ── the deep link IS the join key (AD-12) ────────────────────────────────────
ok('opening the page sets an #agent/<npub> hash, so the link lands from any surface', () => {
  render()
  assert.match(globalThis.location.hash, /^agent\/npub1/)
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
