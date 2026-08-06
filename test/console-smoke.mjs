// console-smoke.mjs — does the console still LOAD?
//
// Nothing tested this, and it should have. While building the agent page I imported two modules
// that live on unmerged branches; every unit test stayed green because none of them touches the
// console's module graph. The console would simply have failed to boot in a browser, with the
// only symptom a blank shell — the exact failure mode `deploy/caddy/Caddyfile` already records
// for a drifted import map: "rendered perfectly and failed only at the moment someone tried to
// sign in."
//
// This is not a UI test. It evaluates the real module graph against a minimal DOM and asserts
// three things a unit test cannot see:
//   · every relative import resolves
//   · no import cycle bites at module-evaluation time (several modules import main.mjs, which
//     imports them back — legal only because the references are inside functions)
//   · no top-level code touches an element the HTML does not contain
//
//   node test/console-smoke.mjs

import { readFileSync, readdirSync } from 'node:fs'
import { existsSync } from 'node:fs'
import { join, normalize, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
let pass = 0, fail = 0
const ok = (name, value, detail = '') => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}${value ? '' : ` (${detail})`}`); value ? pass++ : fail++ }

// ── every relative import resolves ────────────────────────────────────────────
const unresolved = []
for (const f of readdirSync(join(ROOT, 'console')).filter(f => f.endsWith('.mjs'))) {
  const src = readFileSync(join(ROOT, 'console', f), 'utf8')
  for (const m of src.matchAll(/from\s+'(\.[^']+)'/g)) {
    const p = normalize(join(ROOT, 'console', m[1]))
    if (!existsSync(p)) unresolved.push(`${f} → ${m[1]}`)
  }
}
ok('every relative import in console/ resolves', unresolved.length === 0, unresolved.join(', '))

// ── every id the entry module reaches for exists in the page ──────────────────
const html = readFileSync(join(ROOT, 'console/index.html'), 'utf8')
const main = readFileSync(join(ROOT, 'console/main.mjs'), 'utf8')
const missingIds = [...new Set([...main.matchAll(/\$\('([a-z0-9-]+)'\)/g)].map(m => m[1]))]
  .filter(id => !html.includes(`id="${id}"`))
ok('every element id main.mjs reaches for exists in index.html', missingIds.length === 0, missingIds.join(' '))

// ── every declared tab is routable, and every route has a pane ────────────────
const tabs = [...new Set([...html.matchAll(/data-tab="([a-z]+)"/g)].map(m => m[1]))]
const routed = (main.match(/const TABS = \{([^}]+)\}/) || [, ''])[1]
ok('every tab in the page is routed', tabs.every(t => routed.includes(`${t}:`)), tabs.join(' '))
ok('every routed tab has a pane in the page',
  routed.split(',').map(s => s.split(':')[0].trim()).filter(Boolean).every(t => html.includes(`id="${t}"`)))

// ── the graph evaluates against a minimal DOM ─────────────────────────────────
const mk = (doc) => {
  const t = {
    // `style` needs setProperty: the plane switcher sets a per-app accent as a CSS custom property.
    style: { setProperty() {}, removeProperty() {}, getPropertyValue: () => '' },
    dataset: {}, hidden: false, textContent: '', innerHTML: '', value: '', disabled: false,
    classList: { toggle() {}, add() {}, remove() {}, contains: () => false },
    append() {}, appendChild() {}, addEventListener() {}, insertAdjacentHTML() {},
    setAttribute() {}, removeAttribute() {}, getAttribute: () => null,
    focus() {}, scrollIntoView() {}, remove() {}, closest: () => null, select() {},
    onclick: null, onkeydown: null, oninput: null,
  }
  t.ownerDocument = doc            // the titlebar renders into el.ownerDocument, not `document`
  t.querySelector = () => mk(doc)
  t.querySelectorAll = () => []
  return t
}
const doc = {}
Object.assign(doc, mk(doc), {
  getElementById: () => mk(doc), querySelector: () => mk(doc), querySelectorAll: () => [],
  createElement: () => mk(doc), head: mk(doc), body: mk(doc), addEventListener() {},
})
globalThis.document = doc
globalThis.location = { hash: '', replace() {} }
globalThis.window = { location: globalThis.location, addEventListener() {}, matchMedia: () => ({ matches: false, addEventListener() {} }) }
const store = () => ({ getItem: () => null, setItem() {}, removeItem() {} })
globalThis.localStorage = store()
globalThis.sessionStorage = store()
globalThis.WebSocket = class { constructor() {} close() {} send() {} }

let evalError = null
try { await import('../console/main.mjs') } catch (e) { evalError = e }
ok('the console module graph evaluates against a minimal DOM',
  evalError === null, evalError && `${evalError.message} — ${String(evalError.stack).split('\n')[1]?.trim()}`)

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
