// console-imports.mjs — every name a console module uses is actually imported.
//
// WHY THIS EXISTS. `console/ledger.mjs` shipped a reference to `childrenOf` and `coverageNote`
// with no import statement for either. Every focused unit suite stayed green — they import the
// pure modules directly — while the Ledger itself would have thrown `ReferenceError` on the first
// card render, taking the whole screen down. The console is unbundled ES modules loaded straight
// by the browser, so nothing between the editor and production ever resolves these names.
//
// This is the cheapest possible guard for that class: import every console module under Node and
// let the module loader do the resolving. A named import of a symbol the target does not export is
// a link-time SyntaxError, so it fails here rather than in front of the Director.
//
// It does NOT catch a free identifier inside a function body that is never called — for that,
// `test/console-smoke.mjs` evaluates the render path against a minimal DOM. The two are
// complementary and both cheap; neither substitutes for the other.
//
//   node test/console-imports.mjs

import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const dir = join(root, 'console')

let pass = 0, fail = 0
const ok = (name, value, detail = '') => {
  console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}${value ? '' : ` (${detail})`}`)
  value ? pass++ : fail++
}

// Modules that touch `window`/`document` at import time cannot load under bare Node. They are
// still checked statically below; this list is the honest record of what the loader could not do,
// rather than a silent skip.
const NEEDS_DOM = new Set(['main.mjs'])

const files = readdirSync(dir).filter(f => f.endsWith('.mjs')).sort()
ok('there are console modules to check', files.length > 0)

for (const f of files) {
  if (NEEDS_DOM.has(f)) { console.log(`skip — ${f} (imports DOM globals; covered by console-smoke)`); continue }
  let err = null
  try { await import(join(dir, f)) } catch (e) { err = e }
  // A missing FILE or a DOM global at import time is environmental. A missing EXPORT is the bug
  // this guard is for, and it arrives as a SyntaxError from the linker.
  const isLinkError = err instanceof SyntaxError ||
    /does not provide an export|Cannot find module/.test(err?.message || '')
  ok(`${f} — every named import resolves`, !isLinkError, err?.message?.split('\n')[0])
}

// Static pass: catch a bare identifier used by a module that imports nothing providing it. This is
// the exact shape of the ledger.mjs defect — a name referenced with no import statement at all.
// Deliberately narrow: only the symbols the console's own modules export are checked, so a browser
// or Node global can never be mistaken for a missing import.
const exportsOf = (src) => {
  const names = new Set()
  for (const m of src.matchAll(/^export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/gm)) names.add(m[1])
  for (const m of src.matchAll(/^export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)/gm)) names.add(m[1])
  return names
}
/** Every name the file binds itself, at any indent. A module may shadow a sibling's export — e.g.
 *  `consent.mjs` declares its own `$` rather than importing main.mjs's, which would drag the DOM
 *  in. Note `$` is not a `\w`, so a `\b` boundary silently fails to match it; this guard's first
 *  version reported 26 phantom failures in exactly that spot. */
const bindingsOf = (code) => {
  const names = new Set()
  for (const m of code.matchAll(/(?:^|[^.\w$])(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/g)) names.add(m[1])
  for (const m of code.matchAll(/(?:^|[^.\w$])(?:const|let|var)\s+([A-Za-z_$][\w$]*)/g)) names.add(m[1])
  return names
}
const owned = new Map()   // symbol → module that exports it
for (const f of files) for (const n of exportsOf(readFileSync(join(dir, f), 'utf8'))) owned.set(n, f)

for (const f of files) {
  const src = readFileSync(join(dir, f), 'utf8')
  const imported = new Set()
  for (const m of src.matchAll(/^import\s*(?:type\s*)?\{([^}]*)\}\s*from/gms))
    for (const part of m[1].split(',')) {
      const name = part.trim().split(/\s+as\s+/)[0].trim()
      if (name) imported.add(name)
    }
  // Strip comments ONLY.
  //
  // Template literals must survive: this console renders almost entirely inside them, often via an
  // inline IIFE, and the ledger.mjs defect this guard exists for lived in exactly such a block. A
  // first version stripped `` `…` `` to avoid mistaking prose for a call and was therefore blind to
  // the one call site it was written to find. Quoted strings are left alone too, because stripping
  // them mis-parses the apostrophe in ordinary interface copy and can swallow real code after it.
  //
  // The cost is that a symbol named in prose as `someExport(` would false-positive. That is a
  // visible, one-line failure with an obvious fix, which is the right way round: this guard must
  // fail loudly on a maybe, never stay silent on a certainty.
  const code = src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^\s*\/\/.*$/gm, ' ')
  const bound = bindingsOf(code)
  const missing = new Set()
  for (const m of code.matchAll(/(?:^|[^.\w$])([A-Za-z_$][\w$]*)\s*\(/g)) {
    const name = m[1]
    if (!owned.has(name) || owned.get(name) === f) continue   // not a console export, or its own
    if (imported.has(name) || bound.has(name)) continue        // imported, or bound locally
    missing.add(name)
  }
  // One failure per symbol, not per call site: 26 lines saying `$` is undefined is a worse report
  // than one line saying it, and it buries whatever comes next.
  for (const name of missing)
    ok(`${f} — calls ${name}() without importing it`, false, `exported by console/${owned.get(name)}`)
}
ok('no console module calls another module\'s export without importing it', fail === 0,
  'see the failures above')

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
