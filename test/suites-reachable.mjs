// Every assertion in every suite is actually REACHED.
//
//   node test/suites-reachable.mjs
//
// WHY THIS EXISTS, and it is embarrassing enough to be worth writing down. On 2026-08-06 I appended
// assertions after a suite's terminal `process.exit(...)` FOUR separate times:
//
//   · test/ledger.mjs — 8 assertions for the new `consumed` event. The run reported `ALL 46 PASS`.
//   · bin/nave-drift — the roster check, added after the table renders. The sentinel said 10 artifacts
//     while the printed breakdown totalled 9.
//   · test/console-imports.mjs — the token-hygiene block, twice, and its negative control "passed"
//     in both directions because neither run executed the assertion.
//
// Every one of those looked healthy. That is the whole problem: dead assertions do not fail, they
// simply do not exist, and a green suite is indistinguishable from a green suite that checks less.
// Reviewing the diff does not catch it either — the code is correct, it is merely unreachable.
//
// So the property is asserted mechanically: in a suite that ends by exiting, nothing that looks like
// an assertion may appear after the exit. Cheap, and it closes a class I demonstrably cannot be
// trusted to avoid by care alone.

import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const dir = join(dirname(fileURLToPath(import.meta.url)))

let pass = 0, fail = 0
const ok = (name, value, detail = '') => {
  console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}${value ? '' : ` (${detail})`}`)
  value ? pass++ : fail++
}

// Anything that would run a check. Deliberately broad: the point is to catch code that MEANT to assert.
// Two regexes for one pattern, deliberately: a /g regex is STATEFUL under .test() (it advances
// lastIndex), so sharing one between matchAll and test would make results depend on call order — a
// bug in a tool whose entire job is catching bugs that depend on order.
const ASSERTION_SRC = String.raw`\b(?:assert|ok|check|t)\s*\(|\bassert\.`
const ASSERTION_G = new RegExp(ASSERTION_SRC, 'g')
const ASSERTION = new RegExp(ASSERTION_SRC)

// A SUITE is a file `npm test` actually runs — not every .mjs in this directory. Two files here are test
// INFRASTRUCTURE, not suites: fsintercept.mjs is a NODE_OPTIONS preload, wsrelay.mjs is a fake relay
// server. Judging by directory listing reported both as broken suites, which they are not.
//
// Deriving the list from the test script also catches the converse, which really happened: test/lineage.mjs
// existed, passed, and was never wired into `npm test`, so it had never run in CI once.
const pkg = JSON.parse(readFileSync(join(dir, '..', 'package.json'), 'utf8'))
const script = Object.values(pkg.scripts || {}).join(' && ')
const wired = new Set([...script.matchAll(/test\/([\w.-]+\.mjs)/g)].map(m => m[1]))
// Files in test/ that are NOT suites. Declared with a reason each, never inferred — an unexplained
// exclusion list is how a real suite gets quietly dropped, which is the defect this file exists to catch.
const INFRA = new Set([
  'fsintercept.mjs',        // a NODE_OPTIONS preload, loaded INTO the server binary
  'wsrelay.mjs',            // a fake relay SERVER, started with a port argument
  'suites-reachable.mjs',   // this file
  'agentread.mjs',          // manual E2E driver: takes an agent + scope, played by the browser E2E
  'agenttool.mjs',          // manual E2E driver: drives one MCP tool as a given agent
  'nvoygrant.mjs',          // a library that happens to live here, not a suite (see console/nvoygrant.mjs)
])
const files = [...wired].filter(f => !INFRA.has(f)).sort()
ok('the test script names suites to check', files.length > 0)

// Any suite-shaped file the script never runs. A suite that does not run is indistinguishable from one
// that passes, which is how a whole file of assertions sat unrun in CI.
const onDisk = readdirSync(dir).filter(f => f.endsWith('.mjs'))
const unwired = onDisk.filter(f => !wired.has(f) && !INFRA.has(f))
ok('every suite on disk is wired into npm test', unwired.length === 0,
  `${unwired.join(', ')} exist but never run — a suite that does not run cannot fail`)

let offenders = []
for (const f of files) {
  const src = readFileSync(join(dir, f), 'utf8')
  // The LAST terminal exit — a suite may legitimately exit early on a missing fixture, and code after
  // such a guard is reachable. Only what follows the final one is dead.
  const exits = [...src.matchAll(/^process\.exit\(/gm)]
  if (!exits.length) continue
  const last = exits[exits.length - 1]
  const tail = src.slice(last.index + last[0].length)
  // Strip comments: a suite may sensibly end with a prose footer that mentions assert().
  const code = tail.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^\s*\/\/.*$/gm, ' ')
  const hits = [...code.matchAll(ASSERTION_G)]
  if (hits.length) {
    offenders.push(`${f}: ${hits.length} assertion(s) after the final process.exit — dead code that reports as pass`)
  }
}
ok('no suite has assertions after its terminal process.exit', offenders.length === 0, offenders.join(' | '))

// The counterpart in the other direction: a suite whose failures cannot fail a run.
//
// NOT "does it call process.exit". My first version asserted that and produced four false positives on
// the crew's suites — a bare `assert` from node:assert THROWS, and an uncaught throw exits non-zero all
// by itself, so those suites fail correctly. Nearly reported working code as broken.
//
// The real risk is narrower: a suite that CATCHES its failures, records them, and then neither exits
// non-zero nor rethrows. That one prints FAIL and returns 0, which is the same shape as the dead-code bug
// above — a failure that does not fail.
const swallowed = files.filter(f => {
  const src = readFileSync(join(dir, f), 'utf8')
  if (/from 'node:test'/.test(src)) return false          // the runner owns the exit code
  if (!/\bcatch\b/.test(src)) return false               // nothing is caught; a throw propagates
  return !/process\.exit\(/.test(src) && !/process\.exitCode/.test(src) && !/\bthrow\b/.test(src)
})
ok('no suite catches its own failures and still exits zero', swallowed.length === 0,
  `${swallowed.join(', ')} record failures but cannot fail a run`)

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
