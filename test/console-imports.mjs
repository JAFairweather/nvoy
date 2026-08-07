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


// ── token hygiene: the transitional alias stays gone (Wave 5) ────────────────
//
// `--panel2` was a NEAR-MISS of the system's `--panel-2`: two silently separate variables, so this
// console fell back to unset for that surface and nothing complained. It was aliased for one deploy —
// deliberately, because a token change that also moves markup is unreviewable — and Wave 5 removed the
// alias after renaming the rulesets.
//
// Asserted rather than trusted because the failure is invisible: a re-introduced `var(--panel2)` renders
// as "no background" on a dark surface, which looks like a design choice.
{
  const offenders = []
  for (const f of readdirSync(dir).filter(f => f.endsWith('.mjs') || f.endsWith('.html'))) {
    const src = readFileSync(join(dir, f), 'utf8')
    // Only the USE and the DECLARATION, never prose: the history of this bug is recorded in a comment
    // in index.html and must stay readable.
    for (const m of src.matchAll(/var\(\s*--panel2\s*\)|--panel2\s*:/g)) offenders.push(`${f}: ${m[0]}`)
  }
  ok('the --panel2 alias has not returned', offenders.length === 0, offenders.join(' | '))
}

// ── styled but never emitted: a class with a rule and no markup ──────────────
//
// WHY THIS EXISTS. `ledger.mjs` styled `.lg-super-note` and never wrote it. The caller had been
// passing the note as a SIXTH argument to a five-parameter arrow, and JavaScript drops an extra
// argument without a word — so every grantee heading rendered as a bare label and the sentence each
// kind owes the reader, including the only one naming a defect, never appeared. Nothing caught it:
// the code was correct, the call was correct, and the symptom was an absence.
//
// A CSS rule is a claim that some markup exists. This checks the claim. It looks across ALL console
// modules, not just the declaring one, because a style block in one module legitimately dresses
// markup built in another.
//
// Classes only ever added at runtime via classList have no literal anywhere, so they are named here
// rather than silently tolerated — an allowlist that must be read is better than a check that quietly
// permits the bug it exists for.
{
  const RUNTIME_ONLY = new Set(['lg-focused'])
  // COMMENTS ARE STRIPPED, and this is load-bearing. The first version of this guard passed its own
  // negative control: the fix commit explained itself with a comment naming `.lg-super-note`, and
  // prose mentioning a class satisfied the search for markup emitting it. A guard that a sentence can
  // satisfy is a guard against writing about the bug, not against having it. Template literals stay,
  // because they are where the markup lives.
  const decomment = (s) => s.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^\s*\/\/.*$/gm, ' ')
  // Both the stylesheet and the haystack come from the SAME decommented text. The second version of
  // this guard also passed its own control: it cut the style block out of the raw source but searched
  // the decommented source, so the two strings never matched, the stylesheet was never removed, and
  // every class was "emitted" by its own CSS rule. Two false greens in a row from a check that reads
  // correctly — which is the argument for running the control, not for reading the code again.
  const decommented = new Map(files.map(f => [f, decomment(readFileSync(join(dir, f), 'utf8'))]))
  const offenders = []
  for (const f of files) {
    const src = decommented.get(f)
    for (const block of src.matchAll(/const\s+[A-Z0-9_]*STYLE\s*=\s*`([\s\S]*?)`/g)) {
      const style = block[1]
      const rest = files.map(g => g === f ? src.split(style).join(' ') : decommented.get(g)).join('\n')
      for (const sel of new Set(style.match(/\.[a-z][a-z0-9-]*/g) || [])) {
        const cls = sel.slice(1)
        if (RUNTIME_ONLY.has(cls)) continue
        if (!cls.includes('-')) continue               // single words collide with prose and CSS idents
        if (rest.includes(cls)) continue
        // A whole FAMILY is often emitted by interpolation — `class="card st-${d.status}"` styles
        // .st-active and its siblings without ever writing them out. So a literal miss is retried
        // against each hyphen prefix followed by a template hole. Without this the guard reports four
        // healthy status classes, and a check that cries wolf gets deleted rather than read.
        const parts = cls.split('-')
        const prefixes = parts.slice(0, -1).map((_, i) => parts.slice(0, i + 1).join('-') + '-')
        if (prefixes.some(p => rest.includes(p + '${'))) continue
        offenders.push(`${f}: .${cls}`)
      }
    }
  }
  ok('no console class is styled but never emitted', offenders.length === 0, offenders.join(' | '))
}

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
