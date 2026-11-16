#!/usr/bin/env node
// q-173 (15 Nov 2026): James opened the memory viewer and saw nothing for a long time. Two causes:
// - every poll that saw a write recomputed the topic eigenvector pass (2-4 s of synchronous CPU for about 1,500
//   records), so the event loop stalled and page and API requests waited up to 20 s;
// - in the page, every corpus delta that arrived while the full-corpus fetch was in flight started a new fetch and
//   threw the earlier answer away, so on a slow server the full corpus could keep missing.
// These checks run the real page script in a vm with a stub DOM, and the pure server rule for reusing the pass.
import assert from 'node:assert/strict'
import vm from 'node:vm'
import { canReuseSpectral, INITIAL_STATE_RECORDS_LIMIT, renderViewerHtml, SPECTRAL_REFRESH_MS } from '../mcp/tools/memory-viewer.mjs'

let failed = 0
async function test(name, fn) {
  try {
    await fn()
    console.log(`ok - ${name}`)
  } catch (err) {
    failed += 1
    console.error(`not ok - ${name}`)
    console.error(err)
  }
}

function makeRecords(n) {
  return Array.from({ length: n }, (_, i) => ({
    event_id: `e${String(i).padStart(4, '0')}`,
    d: `hive-memory:room:x:slug-${i}`,
    author_pubkey: 'a'.repeat(64),
    topic: 'hive-memory',
    scope: 'room:x',
    claim: `claim ${i}`,
    created_at: 1_794_000_000 + i,
    computed_rank: 3,
    is_current: true,
    status: 'active',
    verification: 'accepted',
  }))
}

// A function-backed Proxy: any property is another stub, any call returns a stub, so the page's canvas and DOM
// code runs without a browser. Assigned properties read back.
function stub() {
  const values = {}
  const target = function () {}
  return new Proxy(target, {
    get(_t, k) {
      if (k === Symbol.toPrimitive) return () => 0
      if (k === 'then') return undefined
      if (k === 'length') return 0
      if (typeof k === 'symbol') return undefined
      if (!(k in values)) values[k] = stub()
      return values[k]
    },
    set(_t, k, v) {
      values[k] = v
      return true
    },
    apply: () => stub(),
    construct: () => stub(),
  })
}

function bootPage({ total = 40, digest = 'aa' } = {}) {
  const records = makeRecords(total)
  const html = renderViewerHtml({
    connected: true,
    records,
    corpus_digest: digest,
    store_state: { state: 'READY', write_seq: 5, current_claims: total },
    poll_seq: 1,
  })
  const init = html.match(/<script id="initial-state" type="application\/json">([\s\S]*?)<\/script>/)[1]
  const code = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n')
  const els = {}
  const fetches = []
  const timers = []
  const ctx = {
    console,
    setTimeout: fn => {
      timers.push(fn)
      return timers.length
    },
    clearTimeout() {},
    setInterval: () => 1,
    clearInterval() {},
    requestAnimationFrame: () => 1,
    fetch: url =>
      new Promise(resolve => {
        fetches.push({ url, resolve })
      }),
    EventSource: function EventSource(url) {
      ctx.es = this
      this.url = url
    },
    navigator: stub(),
    localStorage: stub(),
    performance: { now: () => 0 },
    innerWidth: 1400,
    innerHeight: 900,
    devicePixelRatio: 1,
    addEventListener() {},
    document: {
      getElementById(id) {
        if (id === 'initial-state') return { textContent: init }
        if (!els[id]) els[id] = stub()
        return els[id]
      },
      createElement: () => stub(),
      querySelector: () => stub(),
      querySelectorAll: () => [],
      addEventListener() {},
      body: stub(),
      documentElement: stub(),
    },
  }
  ctx.window = ctx
  ctx.window.location = stub()
  vm.createContext(ctx)
  vm.runInContext(code, ctx)
  const runTimers = () => {
    for (const fn of timers.splice(0)) fn()
  }
  const answer = async (i, body) => {
    fetches[i].resolve({ ok: true, json: async () => body })
    for (let k = 0; k < 5; k++) await Promise.resolve()
  }
  return { ctx, els, fetches, runTimers, answer, records }
}

function corpusBody(records, digest, pollSeq) {
  return {
    connected: true,
    records,
    total_records: records.length,
    next_offset: null,
    corpus_digest: digest,
    poll_seq: pollSeq,
    store_state: { state: 'READY', write_seq: 5, current_claims: records.length },
    consolidated_sources: {},
  }
}

await test('the page paints the embedded first screen before any corpus fetch answers', () => {
  const page = bootPage({ total: 40 })
  assert.equal(page.els['records-count'].textContent, `${INITIAL_STATE_RECORDS_LIMIT} of 40 records`)
  assert.equal(page.fetches.length, 0, 'nothing has been fetched yet')
})

await test('the full corpus loads behind the first screen, with a loading line', async () => {
  const page = bootPage({ total: 40 })
  page.runTimers()
  assert.deepEqual(page.fetches.map(f => f.url), ['/api/records?include_corpus=1'])
  assert.equal(page.els['corpus-loading'].hidden, false, 'loading line is shown while the corpus loads')
  await page.answer(0, corpusBody(page.records, 'aa', 1))
  assert.equal(page.els['records-count'].textContent, '40 records')
  assert.equal(page.els['corpus-loading'].hidden, true, 'loading line is hidden once the corpus is in')
  assert.equal(page.fetches.length, 1)
})

await test('a delta during a slow corpus fetch queues one more fetch instead of discarding the answer', async () => {
  const page = bootPage({ total: 40 })
  page.runTimers()
  // The store moves on twice while the first fetch is still out.
  for (const [from, to, seq] of [['aa', 'bb', 2], ['bb', 'cc', 3]]) {
    page.ctx.es.onmessage({
      data: JSON.stringify({
        connected: true,
        poll_seq: seq,
        store_state: { state: 'READY', write_seq: 5 + seq, current_claims: 40 },
        corpus_digest: to,
        corpus_delta: { from_digest: from, to_digest: to, upserted_records: [], removed_event_ids: [] },
      }),
    })
  }
  assert.equal(page.fetches.length, 1, 'no second fetch while the first is in flight')
  // The first answer is an older snapshot; it still paints, and one more fetch goes out.
  await page.answer(0, corpusBody(page.records, 'aa', 1))
  assert.equal(page.els['records-count'].textContent, '40 records', 'the older snapshot is painted')
  assert.equal(page.fetches.length, 2, 'exactly one follow-up fetch')
  assert.equal(page.els['corpus-loading'].hidden, false)
  await page.answer(1, corpusBody(page.records, 'cc', 3))
  assert.equal(page.els['corpus-loading'].hidden, true)
  assert.equal(page.fetches.length, 2, 'caught up: no further fetch')
})

await test('a scheduled poll reuses the eigenvector pass for SPECTRAL_REFRESH_MS; a forced poll never does', () => {
  const cached = { spectral: { topic_map: {} }, atMs: 1_000_000, aclSig: 'acl' }
  const at = ms => ({ forceFull: false, aclSig: 'acl', nowMs: 1_000_000 + ms })
  assert.equal(canReuseSpectral(cached, at(0)), true)
  assert.equal(canReuseSpectral(cached, at(SPECTRAL_REFRESH_MS - 1)), true)
  assert.equal(canReuseSpectral(cached, at(SPECTRAL_REFRESH_MS)), false, 'stale after the refresh window')
  assert.equal(canReuseSpectral(cached, at(-1)), false, 'a clock that went backwards recomputes')
  assert.equal(canReuseSpectral(cached, { ...at(10), forceFull: true }), false, 'startup and tests always recompute')
  assert.equal(canReuseSpectral(cached, { ...at(10), aclSig: 'other' }), false, 'a new reader binding recomputes')
  assert.equal(canReuseSpectral(null, at(10)), false)
  assert.equal(canReuseSpectral(cached), false, 'defaults to recomputing')
})

if (failed) {
  console.error(`${failed} memory-viewer-first-paint check(s) failed`)
  process.exit(1)
}
console.log('memory-viewer-first-paint: all checks passed')
