// B4 synthetic engineering load only; never a real-corpus recall score.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { arch, cpus, platform, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { performance } from 'node:perf_hooks'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { buildClaimTemplate } from './memory.mjs'
import { HiveMemoryStore, migrateStoreJson, recordVerifiedBackup, validateAndResolveConfig } from './hive_memory_store.mjs'

export function nearestRank(values, p) {
  if (!Array.isArray(values) || !values.length || values.some(v => !Number.isFinite(v) || v < 0) ||
      !Number.isFinite(p) || p <= 0 || p > 1) throw new Error('invalid percentile input')
  return [...values].sort((a, b) => a - b)[Math.ceil(p * values.length) - 1]
}

const SHA = value => createHash('sha256').update(value).digest('hex')
const VOCAB = ['telescope mirror calibration', 'lantern battery maintenance', 'quartz lens alignment', 'garden weather observation']
const QUERIES = ['telescope', 'battery maintenance', 'lens alignment', 'garden weather', 'absenttokenxyz']
const NOW = 1_800_000_000
const GLOBAL_CH = '11111111-2222-4333-8444-555555555555'

export function runSyntheticLoad({ rows = 50_000, samples = 1_000, warmups = 100 } = {}) {
  for (const [name, value] of Object.entries({ rows, samples, warmups })) {
    if (!Number.isSafeInteger(value) || value < (name === 'warmups' ? 0 : 1)) throw new Error(`invalid ${name}`)
  }
  const dir = mkdtempSync(join(tmpdir(), 'b4-synthetic-load-'))
  let store
  try {
    // Ephemeral test signing material: generated locally, never printed or persisted.
    const sk = generateSecretKey(), pk = getPublicKey(sk)
    const config = validateAndResolveConfig({
      memoryGlobalChannelId: GLOBAL_CH, ownerPubkey: pk, maxUnbackedSec: 3600,
      globalWriters: [pk], readers: { fixture: pk }, writers: { fixture: { pubkey: pk, perHour: 3600 } }, rooms: {},
    })
    const paths = { dbPath: join(dir, 'memory.sqlite'), ledgerPath: join(dir, 'ledger.jsonl'), receiptPath: join(dir, 'receipt.json') }
    const fixtureHash = createHash('sha256')
    const started = performance.now()
    const entries = Array.from({ length: rows }, (_, i) => {
      const claim = `Synthetic station ${i}: ${VOCAB[i % VOCAB.length]}. Serial marker${i}.`
      fixtureHash.update(`${claim}\n`)
      return { event: finalizeEvent(buildClaimTemplate({
        pubkey: pk, scope: 'hive:ops', slug: `load-fixture-${i}`, topic: 'nvoy', claim,
        because: 'Synthetic engineering fixture, not an operational fact.', evidence: ['synthetic:b4-load-v1'],
        asOfGit: 'synthetic-fixture-v1', memoryGlobalChannelId: GLOBAL_CH, ttlSec: 0, nowSec: NOW,
      }), sk) }
    })
    const storeJsonPath = join(dir, 'fixture.json')
    writeFileSync(storeJsonPath, JSON.stringify({ version: 1, entries }), { mode: 0o600 })
    migrateStoreJson({ storeJsonPath, ...paths, config, nowSec: NOW })
    recordVerifiedBackup({ receiptPath: paths.receiptPath, snapshotId: SHA('synthetic-backup-receipt'), writeSeq: 1, at: NOW, nowSec: NOW })
    store = new HiveMemoryStore({ ...paths, config })
    assert.equal(store.start().ready, true, 'fixture must reconcile, not fake READY')
    const setup_ms = performance.now() - started
    const actualRows = store.db.prepare('SELECT count(*) AS n FROM events WHERE is_current = 1').get().n
    const fts_rows = store.db.prepare('SELECT count(*) AS n FROM events_fts').get().n
    assert.equal(actualRows, rows)
    assert.equal(fts_rows, rows)
    const query = text => store.query({ readerPubkey: pk, text, limit: 10, nowSec: NOW })
    const firstStart = performance.now()
    const probe = query('synthetic')
    const first_query_ms = performance.now() - firstStart
    assert.equal(probe.answer, 'found')
    assert.equal(probe.total_matched, rows)
    for (let i = 0; i < warmups; i++) query(QUERIES[i % QUERIES.length])
    const timings_ms = [], queries = []
    for (let i = 0; i < samples; i++) {
      const text = QUERIES[i % QUERIES.length]
      const start = performance.now()
      const result = query(text)
      const ms = performance.now() - start
      assert.notEqual(result.answer, 'unknown', 'unknown is not a valid fast result')
      queries.push({ text, answer: result.answer, total_matched: result.total_matched, returned: result.returned, ms })
      timings_ms.push(ms)
    }
    const here = dirname(fileURLToPath(import.meta.url))
    return {
      corpus_kind: 'synthetic-not-recall-accuracy', fixture_version: 1, fixture_text_sha256: fixtureHash.digest('hex'),
      rows: actualRows, fts_rows, probe_matched: probe.total_matched, reconciled_ready: true,
      samples, warmups, limit: 10, setup_ms, first_query_ms, timings_ms, queries,
      p50_ms: nearestRank(timings_ms, 0.5), p95_ms: nearestRank(timings_ms, 0.95), max_ms: Math.max(...timings_ms),
      percentile_method: 'nearest-rank ceil(p*n)', timing_scope: 'synchronous HiveMemoryStore.query including row reads, ACL, parsing, ranking and response projection; no socket/RPC',
      cache_treatment: 'first query after migration/startup, then explicit warmups; not OS-cold; shared host, no affinity or cache flush',
      fixture_limits: 'deterministic text, ephemeral random signer/event IDs; all current, accepted, one writer and one public ops scope; not a representative private/history/ACL corpus',
      runtime: { node: process.version, platform: platform(), arch: arch(), cpu: cpus()[0]?.model },
      git_revision: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: here, encoding: 'utf8' }).trim(),
      source_sha256: Object.fromEntries(['memory-load-benchmark.mjs', 'hive_memory_store.mjs', 'memory.mjs'].map(name => [name, SHA(readFileSync(join(here, name)))])),
    }
  } finally {
    store?.close()
    rmSync(dir, { recursive: true, force: true })
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  if (process.argv.length > 5) throw new Error('usage: node memory-load-benchmark.mjs [rows [samples [warmups]]]')
  const [rows = 50_000, samples = 1_000, warmups = 100] = process.argv.slice(2).map(Number)
  console.log(JSON.stringify(runSyntheticLoad({ rows, samples, warmups }), null, 2))
}
