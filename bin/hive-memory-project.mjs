#!/usr/bin/env node
// hive-memory-project.mjs — Offline static Public Cortex projection generator (Frontier E1).
//
//   node bin/hive-memory-project.mjs --db <snapshot.sqlite> --allowlist <allowlist.json> --out <dir> [--now <unix-sec>]
//
// Reads an offline SQLite snapshot read-only, filters strictly to allowlisted scopes, topics and
// opted-in chosen claims, enforces the two-layer secret & publication-boundary sanitiser, and writes
// static `cortex-public.json` + `index.html` into `--out`. Opens no sockets or network connections and
// refuses live store, daemon socket and live publication paths.

import {
  assertOfflineProjectionPaths,
  loadAllowlistFile,
  projectOfflinePublicCortex,
} from '../mcp/tools/memory-public-projection.mjs'

const KNOWN_FLAGS = new Set(['--db', '--allowlist', '--out', '--now'])

function fail(msg, code = 1) {
  console.error(`hive-memory-project: ${msg}`)
  process.exit(code)
}

const argv = process.argv.slice(2)
if (argv.length === 0 || argv.length % 2 !== 0) {
  fail('usage: hive-memory-project.mjs --db <snapshot.sqlite> --allowlist <allowlist.json> --out <dir> [--now <unix-sec>]', 2)
}

const flags = new Map()
for (let i = 0; i < argv.length; i += 2) {
  const key = argv[i]
  const val = argv[i + 1]
  if (!KNOWN_FLAGS.has(key) || val === undefined || val.startsWith('--')) {
    fail('usage: hive-memory-project.mjs --db <snapshot.sqlite> --allowlist <allowlist.json> --out <dir> [--now <unix-sec>]', 2)
  }
  if (flags.has(key)) {
    fail(`duplicate flag ${key}`, 2)
  }
  flags.set(key, val)
}

const dbPath = flags.get('--db') || ''
const allowlistPath = flags.get('--allowlist') || ''
const outDir = flags.get('--out') || ''
const nowRaw = flags.get('--now')

if (!dbPath || !allowlistPath || !outDir) {
  fail('needs --db, --allowlist and --out', 2)
}

let nowSec
if (nowRaw !== undefined) {
  if (!/^[1-9][0-9]*$/.test(nowRaw)) {
    fail('--now takes a positive integer unix timestamp in seconds', 2)
  }
  nowSec = Number(nowRaw)
}

try {
  const checked = assertOfflineProjectionPaths({ dbPath, outDir, allowlistPath })
  const allowlist = loadAllowlistFile(checked.allowlistPath)
  const { projection, findings } = projectOfflinePublicCortex({
    dbPath: checked.dbPath,
    allowlist,
    outDir: checked.outDir,
    ...(nowSec !== undefined ? { nowSec } : {}),
  })
  for (const f of findings) {
    console.error(`hive-memory-project: withheld: ${f.what} at ${f.path}`)
  }
  console.log(JSON.stringify({
    coarse_state: projection.coarse_state,
    withheld: Boolean(projection.withheld),
    generated_at: projection.generated_at,
    scopes: Array.isArray(projection.scopes) ? projection.scopes.length : 0,
    topics: Array.isArray(projection.topics) ? projection.topics.length : 0,
    chosen_claims: Array.isArray(projection.chosen_claims) ? projection.chosen_claims.length : 0,
    withheld_claims: projection.counts?.withheld_claims ?? 0,
  }))
  if (projection.withheld) process.exit(1)
} catch (e) {
  fail(e.message || 'projection failed', 1)
}
