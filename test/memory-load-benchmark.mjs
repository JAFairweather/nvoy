import assert from 'node:assert/strict'
import test from 'node:test'
import { nearestRank, runSyntheticLoad } from '../mcp/tools/memory-load-benchmark.mjs'
import { HiveMemoryStore } from '../mcp/tools/hive_memory_store.mjs'

test('nearest-rank p95 sorts a copy and selects ceil(p*n)', () => {
  const values = [5, 1, 4, 2, 3]
  assert.equal(nearestRank(values, 0.95), 5)
  assert.deepEqual(values, [5, 1, 4, 2, 3])
  assert.equal(nearestRank([3], 0.95), 3)
  assert.equal(nearestRank(Array.from({ length: 100 }, (_, i) => i + 1), 0.95), 95)
})

test('reject invalid samples and quantiles rather than emit invented timing', () => {
  for (const values of [[], [NaN], [Infinity], [-1]]) {
    assert.throws(() => nearestRank(values, 0.95))
  }
  for (const p of [0, -1, 1.1, NaN]) assert.throws(() => nearestRank([1], p))
})

test('reject invalid benchmark sizes', () => {
  for (const options of [{ rows: 0 }, { samples: -1 }, { warmups: 0.5 }]) {
    assert.throws(() => runSyntheticLoad(options))
  }
})

test('seed through verified migration, query real store, label synthetic and retain all timings', () => {
  const report = runSyntheticLoad({ rows: 12, samples: 4, warmups: 1 })
  assert.equal(report.corpus_kind, 'synthetic-not-recall-accuracy')
  assert.equal(report.rows, 12)
  assert.equal(report.fts_rows, 12)
  assert.equal(report.probe_matched, 12)
  assert.equal(report.timings_ms.length, 4)
  assert.equal(report.samples, 4)
  assert.equal(report.warmups, 1)
  assert.equal(report.p95_ms, nearestRank(report.timings_ms, 0.95))
  assert.ok(report.timings_ms.every(t => Number.isFinite(t) && t >= 0))
  assert.equal(report.queries.length, 4)
  assert.equal(report.reconciled_ready, true)
  assert.match(report.fixture_text_sha256, /^[0-9a-f]{64}$/)
})

test('a fast empty-query mutant cannot pass the engineering load probe', () => {
  const original = HiveMemoryStore.prototype.query
  try {
    HiveMemoryStore.prototype.query = () => ({ answer: 'none', total_matched: 0, records: [] })
    assert.throws(() => runSyntheticLoad({ rows: 4, samples: 1, warmups: 0 }), /found/)
  } finally {
    HiveMemoryStore.prototype.query = original
  }
})
