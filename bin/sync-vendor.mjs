#!/usr/bin/env node
// sync-vendor — pull this repo's vendored copies of the Nave design system from the hub.
//
// It replaces `npm run sync-titlebar`, which could not work from here: that script resolves
// `../nave.pub`, and on the maintainer's machine nvoy lives at ~/Projects/nvoy while the hub
// lives at ~/Projects/nave-spine/nave.pub. So `../nave.pub` is a directory that does not
// exist, the script has never run from this checkout, and the vendored titlebar carries a
// hand-copied provenance stamp (`@ 6516d86`) that is now several releases stale. Exactly the
// same defect as nave-drift's original `--root` handling: a hardcoded sibling assumption in a
// fleet whose clones are not all siblings.
//
// The hub is therefore configurable, and the manifest decides what to copy — `design/VENDOR.json`
// exists to be the one place that knows, so a new shared component does not need a new npm
// script.
//
//   npm run sync-vendor                       # default hub, see HUB_DEFAULTS
//   NAVE_HUB=/path/to/nave.pub npm run sync-vendor
//   npm run sync-vendor -- --check            # verify only; non-zero if anything is stale
//
// Each copy gets a HASH provenance stamp, not a prose one. Every prose stamp in the fleet was
// stale while its body was current, which is precisely why staleness has to be computable.

import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const argv = process.argv.slice(2)
const CHECK = argv.includes('--check')

// Where the hub might be. Tried in order; the first that has a VENDOR.json wins.
const HUB_DEFAULTS = [
  process.env.NAVE_HUB,
  join(REPO, '../nave.pub'),                 // a true sibling layout
  join(REPO, '../nave-spine/nave.pub'),      // the maintainer's actual layout
  join(REPO, '../../nave-spine/nave.pub'),
].filter(Boolean)

const hub = HUB_DEFAULTS.find(p => existsSync(join(p, 'design/VENDOR.json')))
if (!hub) {
  console.error('sync-vendor: no hub found. Set NAVE_HUB to a nave.pub checkout.')
  console.error('  tried:'); for (const p of HUB_DEFAULTS) console.error(`    ${p}`)
  process.exit(2)
}

const sha = (buf) => createHash('sha256').update(buf).digest('hex')
const manifest = JSON.parse(readFileSync(join(hub, 'design/VENDOR.json'), 'utf8'))
const hubRev = (() => {
  try {
    return readFileSync(join(hub, '.git/HEAD'), 'utf8').trim().replace(/^ref: /, '')
  } catch { return 'unknown' }
})()

// What this repo vendors, and where. Derived from the manifest's own consumer list so the two
// cannot disagree — but a component with no consumer row yet can still be adopted here by
// naming it, which is how adoption starts.
const ADOPT = [
  { artifact: 'components/nave-titlebar.mjs', to: 'lib/nave-titlebar.mjs' },
  { artifact: 'components/nave-tabs.mjs', to: 'lib/nave-tabs.mjs' },
  { artifact: 'components/nave-cap.mjs', to: 'lib/nave-cap.mjs' },
  { artifact: 'components/nave-source-note.mjs', to: 'lib/nave-source-note.mjs' },
]

let stale = 0, wrote = 0
for (const { artifact, to } of ADOPT) {
  const src = join(hub, artifact)
  if (!existsSync(src)) { console.error(`  ! ${artifact} — not in the hub at ${hub}`); stale++; continue }
  const body = readFileSync(src, 'utf8')
  const stamp = `// vendored: ${artifact} @ sha256:${sha(Buffer.from(body, 'utf8')).slice(0, 16)} — nave.pub@${hubRev.slice(0, 12)}\n` +
    `// DO NOT EDIT. Change it in nave.pub and re-run: npm run sync-vendor\n`
  const next = stamp + body
  const dest = join(REPO, to)
  const current = existsSync(dest) ? readFileSync(dest, 'utf8') : null

  // Compare BODIES, not whole files: the stamp carries a hub revision that moves on doc-only
  // hub commits, and re-vendoring identical code on every unrelated hub push is noise.
  const bodyOf = (text) => text.split('\n').filter(l => !l.startsWith('// vendored:') && !l.startsWith('// DO NOT EDIT.')).join('\n')
  const same = current !== null && bodyOf(current) === bodyOf(next)
  if (same) { console.log(`  ok    ${to}`); continue }
  if (CHECK) { console.log(`  STALE ${to} — differs from ${artifact}`); stale++; continue }
  mkdirSync(dirname(dest), { recursive: true })
  writeFileSync(dest, next)
  console.log(`  wrote ${to}  ← ${artifact}`)
  wrote++
}

// tokens.css is INLINED into the console's <style>, not a file copy, so it cannot be written
// here. Report the divergence and point at the tool that explains it, rather than silently
// omitting the artifact most likely to be stale — nvoy's copy is missing the entire light
// theme, and that is invisible until someone with a light OS opens the console.
const hubTokens = join(hub, 'design/tokens.css')
if (existsSync(hubTokens)) {
  const decls = (css) => new Set([...css.matchAll(/(--[a-z0-9-]+)\s*:/gi)].map(m => m[1]))
  const want = decls(readFileSync(hubTokens, 'utf8'))
  const have = decls(readFileSync(join(REPO, 'console/index.html'), 'utf8'))
  const missing = [...want].filter(t => !have.has(t))
  if (missing.length) {
    console.log(`  INLINE design/tokens.css — console/index.html is missing ${missing.length} declaration(s):`)
    console.log(`          ${missing.slice(0, 8).join(' ')}${missing.length > 8 ? ` +${missing.length - 8}` : ''}`)
    console.log(`          Inlined, so it must be pasted by hand. nave-drift explains the verdict.`)
    stale++
  } else console.log('  ok    design/tokens.css (inlined declarations all present)')
}

console.log(`\nsync-vendor: hub ${hub}`)
console.log(`  ${wrote} written · ${stale} stale/absent`)
if (CHECK && stale) { console.error('\nsync-vendor --check: vendored copies are out of date'); process.exit(1) }
process.exit(0)
