// test/memory-viewer.mjs — Unit and integration tests for mcp/tools/memory-viewer.mjs.

import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { buildClaimTemplate } from '../mcp/tools/memory.mjs'
import { ACTIVITY_MAX, handleSocketJsonRpc, startMemoryDaemon } from '../mcp/tools/memory-daemon.mjs'
import { HiveMemoryStore, initEmptyStore, recordVerifiedBackup, validateAndResolveConfig } from '../mcp/tools/hive_memory_store.mjs'
import {
  buildMobileState,
  computeAgentHealth,
  computeCoherence,
  computeDreamingTelemetry,
  computeMemoryTrends,
  computeSynapticEfficacy,
  CORPUS_CACHE_TTL_MS,
  diffViewerSnapshots,
  readWatchStatus,
  watchAlert,
  watchView,
  WATCH_STALE_SEC,
  escapeHtml,
  parseListenTarget,
  parseViewerFlags,
  renderMobileViewerHtml,
  renderViewerHtml,
  resolveDreamDisplayMode,
  safeJsonForScript,
  sanitizeActivity,
  startMemoryViewer,
} from '../mcp/tools/memory-viewer.mjs'

const SNAP_ID = 'c'.repeat(64)

let passed = 0
let failed = 0

async function test(name, fn) {
  try {
    await fn()
    console.log(`  ok — ${name}`)
    passed++
  } catch (err) {
    console.error(`  FAIL — ${name}: ${err.message}`)
    if (err.stack) console.error(err.stack)
    failed++
  }
}

function httpGet(port, path, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, path, method }, res => {
      let body = ''
      res.setEncoding('utf8')
      res.on('data', chunk => {
        body += chunk
      })
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }))
    })
    req.on('error', reject)
    req.end()
  })
}

console.log('=== Hive Shared Memory Viewer Tests ===')

await test('parseViewerFlags and parseListenTarget validate socket, host/port, and bracketed IPv6', () => {
  const parsed1 = parseViewerFlags(['--socket', '/run/hive-memory/viewer.sock', '--host', '127.0.0.1', '--port', '8787'])
  assert.equal(parsed1.socketPath, '/run/hive-memory/viewer.sock')
  assert.equal(parsed1.host, '127.0.0.1')
  assert.equal(parsed1.port, 8787)
  assert.equal(parsed1.pollMs, 3000)

  const parsed2 = parseViewerFlags([
    '--socket',
    '/run/hive-memory/viewer.sock',
    '--listen',
    '[fd7a:115c:a1e0::ab36:5615]:8788',
    '--poll-ms',
    '1500',
  ])
  assert.equal(parsed2.host, 'fd7a:115c:a1e0::ab36:5615')
  assert.equal(parsed2.port, 8788)
  assert.equal(parsed2.pollMs, 1500)

  const parsed3 = parseListenTarget({ listen: '127.0.0.1:0' })
  assert.equal(parsed3.host, '127.0.0.1')
  assert.equal(parsed3.port, 0)

  assert.throws(() => parseViewerFlags(['--socket', 'relative/viewer.sock', '--listen', '127.0.0.1:8787']), /absolute/)
  assert.throws(
    () => parseViewerFlags(['--socket', '/a.sock', '--socket', '/b.sock', '--listen', '127.0.0.1:8787']),
    /only one --socket/
  )
  assert.throws(() => parseViewerFlags(['--socket', '/a.sock']), /listen address is required/)
  assert.throws(() => parseViewerFlags(['--socket', '/a.sock', '--listen', '127.0.0.1:99999']), /--port/)
  assert.throws(() => parseViewerFlags(['--socket', '/a.sock', '--listen', '127.0.0.1:8787', '--poll-ms', '10']), /--poll-ms/)
})

await test('escapeHtml and safeJsonForScript neutralize HTML, script tags, and markdown links', () => {
  const hostile = '</script><script>alert("xss")</script> [click](https://evil.example)'
  const escaped = escapeHtml(hostile)
  assert(!escaped.includes('<script>'))
  assert(escaped.includes('&lt;script&gt;'))

  const safeJson = safeJsonForScript({ claim: hostile })
  assert(!safeJson.includes('</script>'))
  assert(safeJson.includes('\\u003c/script\\u003e'))

  const html = renderViewerHtml({
    connected: true,
    reader: 'viewer',
    server_name: 'hive-memory-viewer',
    store_state: { state: 'READY', write_seq: 2 },
    records: [
      {
        record_type: 'memory-claim',
        authority: null,
        trustedInstruction: false,
        verification: 'accepted',
        computed_rank: 2,
        scope: 'hive:canon',
        d: 'hive-memory:hive:canon:test',
        claim: hostile,
        because: '<b>bold</b>',
        evidence: ['nvoy@8aa86b8:mcp/tools/memory.mjs'],
        author_pubkey: 'a'.repeat(64),
        event_id: 'b'.repeat(64),
      },
    ],
    event_log: [],
  })
  assert(!html.includes('<script>alert("xss")</script>'))
  assert(!/<a\s/i.test(html), 'viewer HTML must never render clickable <a> links')
})

await test('diffViewerSnapshots logs store state, write_seq, backup and record additions/updates/removals', () => {
  const s0 = diffViewerSnapshots(
    null,
    { connected: true, store_state: { state: 'READY', write_seq: 1, unbacked_writes: 0 }, scope_counts: { unverified_total: 0 }, records: [] },
    1000
  )
  assert.equal(s0.length, 1)
  assert.equal(s0[0].kind, 'init')
  assert(s0[0].summary.includes('store_state=READY'))

  const prev = {
    connected: true,
    store_state: { state: 'DB_BEHIND_LEDGER', write_seq: null, unbacked_writes: null },
    scope_counts: { unverified_total: 0 },
    records: [],
  }
  const next = {
    connected: true,
    store_state: { state: 'READY', write_seq: 2, unbacked_writes: 1 },
    scope_counts: { unverified_total: 1 },
    records: [
      {
        scope: 'hive:canon',
        d: 'hive-memory:hive:canon:rule-1',
        author_pubkey: '4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d',
        event_id: '1'.repeat(64),
        verification: 'accepted',
        conflict: false,
      },
    ],
  }
  const diffs = diffViewerSnapshots(prev, next, 1010)
  const kinds = diffs.map(d => d.kind)
  assert(kinds.includes('store'))
  assert(kinds.includes('write'))
  assert(kinds.includes('backup'))
  assert(kinds.includes('unverified'))
  assert(kinds.includes('claim-added'))
  assert(!diffs.some(d => /relay|sync/i.test(d.summary)))
})

await test('computeCoherence calculates 5-axis HCI score and retroactive inception-to-now trajectory', () => {
  const empty = computeCoherence()
  assert.equal(empty.score, 0)
  assert.deepEqual(empty.history, [])

  const roster = [
    { id: 'james', pubkey: '1'.repeat(64), is_writer: true },
    { id: 'mydude', pubkey: '2'.repeat(64), is_writer: true },
    { id: 'neil', pubkey: '3'.repeat(64), is_writer: true },
  ]
  const records = [
    {
      scope: 'room:a8186b53-537d-46ad-a7e7-b6486c58970e',
      d: 'hive-memory:room:a8186b53-537d-46ad-a7e7-b6486c58970e:init-spec',
      topic: 'hive-memory',
      claim: 'Initial spec for PR #335',
      author_pubkey: '2'.repeat(64),
      as_of_git: 'nvoy@9c995af',
      evidence: ['nvoy@9c995af:mcp/tools/memory-daemon.mjs'],
      created_at: 1000,
      expires_at: 2000,
      conflict: false,
      stale_warning: null,
    },
    {
      scope: 'hive:canon',
      d: 'hive-memory:hive:canon:priorities',
      topic: 'hive',
      claim: 'Active Hive priorities',
      author_pubkey: '1'.repeat(64),
      as_of_git: 'nvoy@9c995af',
      evidence: ['nvoy@9c995af:README.md'],
      created_at: 1100,
      expires_at: null,
      conflict: false,
      stale_warning: null,
    },
    {
      scope: 'room:a8186b53-537d-46ad-a7e7-b6486c58970e',
      d: 'hive-memory:room:a8186b53-537d-46ad-a7e7-b6486c58970e:deploy-status',
      topic: 'herd-infra',
      claim: 'Holding PR #335 deploy at nvoy@9c995af',
      author_pubkey: '3'.repeat(64),
      as_of_git: 'nvoy@9c995af',
      evidence: ['nvoy@9c995af:mcp/tools/memory-viewer.mjs'],
      created_at: 1200,
      expires_at: null,
      conflict: false,
      stale_warning: null,
    },
  ]
  const coh = computeCoherence({
    records,
    agent_roster: roster,
    recent_activity: [{ kind: 'wake', actor: 'neil' }, { kind: 'submit', actor: 'neil' }],
    store_state: { write_seq: 6 },
  })
  assert.equal(coh.inception_at, 1000)
  assert(coh.score > coh.inception_score, 'coherence should improve as canon and shared PR/commit refs converge')
  assert(coh.delta_since_inception > 0)
  assert(coh.shared_artifacts >= 2)
  assert.equal(coh.axes.grounding, 100)
  assert.equal(coh.history.length, 2)
  assert.equal(coh.history[0].claims, 1)
  assert.equal(coh.history[1].claims, 3)

  // Verify history_records folds supersessions and withdrawals at their chronological epoch
  const historyWithWithdrawal = [
    ...records,
    {
      ...records[0],
      event_id: 'w'.repeat(64),
      status: 'withdrawn',
      verification: 'withdrawn',
      is_current: true,
      created_at: 1300,
    },
  ]
  const coh2 = computeCoherence({
    records: records.slice(1),
    history_records: historyWithWithdrawal,
    agent_roster: roster,
    store_state: { write_seq: 7 },
  })
  assert.equal(coh2.total_events, 4)
  assert.equal(coh2.history.at(-1).events, 4)
  assert.equal(coh2.history.at(-1).claims, 2)

  // Verify post-event expiration at now_sec and cross-author checkpoint consolidation
  const crossAuthorHistory = [
    {
      event_id: 'e1'.padEnd(64, '0'),
      author_pubkey: '2'.repeat(64),
      scope: 'room:a8186b53-537d-46ad-a7e7-b6486c58970e',
      d: 'hive-memory:room:a8186b53-537d-46ad-a7e7-b6486c58970e:pr-status',
      topic: 'nvoy',
      claim: 'PR #336 opened',
      evidence: ['nvoy@1111111'],
      as_of_git: '1'.repeat(40),
      created_at: 100,
      expires_at: 150,
      verification: 'expired',
    },
    {
      event_id: 'e2'.padEnd(64, '0'),
      author_pubkey: '2'.repeat(64),
      scope: 'room:a8186b53-537d-46ad-a7e7-b6486c58970e',
      d: 'hive-memory:room:a8186b53-537d-46ad-a7e7-b6486c58970e:pr-review',
      topic: 'nvoy',
      claim: 'PR #336 checkpoint',
      evidence: ['nvoy@2222222'],
      as_of_git: '2'.repeat(40),
      created_at: 105,
      expires_at: 500,
      verification: 'consolidated',
      consolidated_by: 'e3'.padEnd(64, '0'),
    },
    {
      event_id: 'e3'.padEnd(64, '0'),
      author_pubkey: '3'.repeat(64),
      scope: 'room:a8186b53-537d-46ad-a7e7-b6486c58970e',
      d: 'hive-memory:room:a8186b53-537d-46ad-a7e7-b6486c58970e:pr-merged',
      topic: 'nvoy',
      claim: 'PR #336 merged',
      evidence: ['nvoy@3333333'],
      as_of_git: '3'.repeat(40),
      created_at: 110,
      expires_at: 500,
      verification: 'accepted',
      supersedes: ['e2'.padEnd(64, '0')],
    },
  ]
  const coh3 = computeCoherence({
    records: [crossAuthorHistory[2]],
    history_records: crossAuthorHistory,
    agent_roster: roster,
    now_sec: 200,
    history_complete: false,
  })
  assert.equal(coh3.history.at(-1).claims, 1, 'current coherence must exclude expired and cross-author consolidated claims')
  assert.equal(coh3.history_complete, false)
  assert.equal(coh3.history_window, 'truncated-5000')

  // Verify historical cross-author consolidation when the superseding claim later expires (so consolidated_by is absent)
  const hist4 = [
    {
      event_id: 'c1'.padEnd(64, '0'),
      author_pubkey: '2'.repeat(64),
      scope: 'room:a8186b53-537d-46ad-a7e7-b6486c58970e',
      d: 'hive-memory:room:a8186b53-537d-46ad-a7e7-b6486c58970e:task-review',
      topic: 'nvoy',
      claim: 'Checkpoint 1',
      evidence: ['nvoy@1111111'],
      as_of_git: '1'.repeat(40),
      created_at: 100,
      expires_at: 1000,
      verification: 'accepted',
    },
    ...Array.from({ length: 3 }, (_, idx) => ({
      event_id: `f${idx}`.padEnd(64, '0'),
      author_pubkey: '1'.repeat(64),
      scope: 'hive:canon',
      d: `hive-memory:hive:canon:p${idx}`,
      topic: 'hive',
      claim: `Canon ${idx}`,
      evidence: ['nvoy@1111111'],
      as_of_git: '1'.repeat(40),
      created_at: 101 + idx,
      expires_at: null,
      verification: 'accepted',
    })),
    {
      event_id: 'c2'.padEnd(64, '0'),
      author_pubkey: '3'.repeat(64),
      scope: 'room:a8186b53-537d-46ad-a7e7-b6486c58970e',
      d: 'hive-memory:room:a8186b53-537d-46ad-a7e7-b6486c58970e:task-status',
      topic: 'nvoy',
      claim: 'Supersedes c1 while active until t=200',
      evidence: ['nvoy@2222222'],
      as_of_git: '2'.repeat(40),
      created_at: 110,
      expires_at: 200,
      verification: 'expired',
      supersedes: ['c1'.padEnd(64, '0')],
    },
    {
      event_id: 'c3'.padEnd(64, '0'),
      author_pubkey: '1'.repeat(64),
      scope: 'hive:canon',
      d: 'hive-memory:hive:canon:p9',
      topic: 'hive',
      claim: 'Later event after c2 expired',
      evidence: ['nvoy@3333333'],
      as_of_git: '3'.repeat(40),
      created_at: 250,
      expires_at: null,
      verification: 'accepted',
    },
  ]
  const coh4 = computeCoherence({
    records: hist4.filter(r => r.verification === 'accepted'),
    history_records: hist4,
    agent_roster: roster,
    now_sec: 300,
  })
  const step5 = coh4.history.find(h => h.events === 5)
  assert.equal(step5.claims, 4, 'at step 5 (t=110), c2 is active and consolidates c1 via supersedes even after c2 later expires')

  // Verify epistemic drift & blind-spot detection: zero-hit queries and silent active writers dip coherence
  const cohDrift = computeCoherence({
    records,
    agent_roster: [
      ...roster,
      { id: 'biggy', pubkey: '4'.repeat(64), is_writer: true },
    ],
    recent_activity: [
      { kind: 'wake', actor: 'biggy' },
      { kind: 'query', actor: 'biggy', count: 2, topic: 'r1' },
      { kind: 'lookup', actor: 'biggy' },
      { kind: 'wake', actor: 'biggy' },
      { kind: 'query', actor: 'mc-claude', count: 0, topic: 'wonder-lab' },
      { kind: 'query', actor: 'mydude', count: 0, topic: 'wonder-lab' },
    ],
    store_state: { write_seq: 6 },
  })
  assert.equal(cohDrift.epistemic_drift.status, 'blind_spot')
  assert.equal(cohDrift.epistemic_drift.zero_hit_queries, 2)
  assert.deepEqual(cohDrift.epistemic_drift.missed_topics, ['wonder-lab'])
  assert.deepEqual(cohDrift.epistemic_drift.silent_active_writers, ['biggy'])
  assert(cohDrift.score < coh.score, `coherence must dip on epistemic blind spots (${cohDrift.score} < ${coh.score})`)

  // Verify fleet recall blindness: when a multi-agent reader roster has blind (0 reads) or lookup-only agents, coherence drops
  const cohBlindFleet = computeCoherence({
    records,
    agent_roster: [
      { id: 'mydude', pubkey: '1'.repeat(64), is_reader: true, is_writer: true },
      { id: 'neil', pubkey: '2'.repeat(64), is_reader: true, is_writer: true },
      { id: 'waggle-dev', pubkey: '3'.repeat(64), is_reader: true, is_writer: true },
      { id: 'djcodex', pubkey: '4'.repeat(64), is_reader: true, is_writer: true },
      { id: 'dennis', pubkey: '5'.repeat(64), is_reader: true, is_writer: true },
      { id: 'kerouac', pubkey: '6'.repeat(64), is_reader: true, is_writer: true },
    ],
    recent_activity: [
      { kind: 'wake', actor: 'mydude' },
      { kind: 'submit', actor: 'mydude' },
      { kind: 'lookup', actor: 'waggle-dev' },
      { kind: 'submit', actor: 'waggle-dev' },
      { kind: 'refused', actor: 'djcodex', code: 'HIVE_MEMORY_INVALID_EVENT' },
    ],
    store_state: { write_seq: 8 },
  })
  assert.equal(cohBlindFleet.epistemic_drift.recall_coverage_pct, 16.7)
  assert.deepEqual(cohBlindFleet.epistemic_drift.lookup_only_writers, ['neil', 'waggle-dev'])
  assert.deepEqual(cohBlindFleet.epistemic_drift.blind_roster_agents, ['djcodex', 'dennis', 'kerouac'])
  assert.equal(cohBlindFleet.epistemic_drift.status, 'blind_spot')
  assert(Array.isArray(cohBlindFleet.epistemic_drift.alerts) && cohBlindFleet.epistemic_drift.alerts.length >= 6)
  assert(cohBlindFleet.epistemic_drift.alerts.some(a => a.category === 'tool_failure' && a.code === 'HIVE_MEMORY_INVALID_EVENT' && a.actor === 'djcodex'))
  assert(cohBlindFleet.epistemic_drift.alerts.some(a => a.category === 'behavioral_noncompliance' && a.code === 'WRITE_WITHOUT_RECALL' && a.actor === 'waggle-dev'))
  assert(cohBlindFleet.epistemic_drift.alerts.some(a => a.category === 'behavioral_noncompliance' && a.code === 'BLIND_ROSTER_SEAT' && a.actor === 'dennis'))
  assert(cohBlindFleet.score < coh.score - 15, `fleet amnesia must significantly lower coherence (${cohBlindFleet.score} vs ${coh.score})`)
})

await test('computeSynapticEfficacy: quantifies 4-axis information distribution, cross-agent handoff velocity, and post-curator projection', () => {
  const emptyEff = computeSynapticEfficacy()
  assert.equal(emptyEff.score, 0)
  assert.deepEqual(emptyEff.axes, { breadth: 0, precision: 0, velocity: 0, reuse: 0 })

  const roster = [
    { id: 'mydude', pubkey: '1'.repeat(64), is_reader: true, is_writer: true },
    { id: 'waggle-dev', pubkey: '2'.repeat(64), is_reader: true, is_writer: true },
    { id: 'dead-rabbit', pubkey: '3'.repeat(64), is_reader: true, is_writer: true },
    { id: 'dennis', pubkey: '4'.repeat(64), is_reader: true, is_writer: true },
  ]
  const records = [
    {
      event_id: 'e1'.padEnd(64, '0'),
      author_pubkey: '2'.repeat(64),
      scope: 'room:a8186b53-537d-46ad-a7e7-b6486c58970e',
      d: 'hive-memory:room:a8186b53-537d-46ad-a7e7-b6486c58970e:nvoy-pr343-owner',
      topic: 'nvoy',
      claim: 'Opened nvoy PR #343 at d30aa219',
      as_of_git: 'd30aa219'.padEnd(40, '0'),
      created_at: 1000,
      expires_at: 5000,
    },
    {
      event_id: 'e2'.padEnd(64, '0'),
      author_pubkey: '1'.repeat(64),
      scope: 'room:a8186b53-537d-46ad-a7e7-b6486c58970e',
      d: 'hive-memory:room:a8186b53-537d-46ad-a7e7-b6486c58970e:nvoy-pr343-review',
      topic: 'nvoy',
      claim: 'Source-approved nvoy PR #343 at d30aa219',
      as_of_git: 'd30aa219'.padEnd(40, '0'),
      created_at: 1120,
      expires_at: 5000,
    },
    {
      event_id: 'e3'.padEnd(64, '0'),
      author_pubkey: '3'.repeat(64),
      scope: 'room:a8186b53-537d-46ad-a7e7-b6486c58970e',
      d: 'hive-memory:room:a8186b53-537d-46ad-a7e7-b6486c58970e:nvoy-343-deployed',
      topic: 'nvoy',
      claim: 'Deployed nvoy #343 on nvoy-fleet',
      as_of_git: 'ff2cf77b'.padEnd(40, '0'),
      created_at: 1240,
      expires_at: null,
    },
  ]
  const activity = [
    { kind: 'wake', actor: 'mydude', count: 5 },
    { kind: 'query', actor: 'mydude', count: 3, topic: 'nvoy' },
    { kind: 'lookup', actor: 'mydude' },
    { kind: 'submit', actor: 'mydude', accepted: true },
    { kind: 'lookup', actor: 'waggle-dev' },
    { kind: 'submit', actor: 'waggle-dev', accepted: true },
    { kind: 'query', actor: 'dead-rabbit', count: 0, topic: 'missing' },
    { kind: 'lookup', actor: 'dead-rabbit' },
    { kind: 'submit', actor: 'dead-rabbit', accepted: true },
  ]
  const eff = computeSynapticEfficacy({
    records,
    agent_roster: roster,
    recent_activity: activity,
    curator_state: { planned_summary: { promotions: 2, distillations: 1 } },
    now_sec: 1300,
  })
  assert(eff.score > 50 && eff.score <= 100)
  assert.equal(eff.velocity.handoff_count, 2, 'detects waggle-dev -> mydude -> dead-rabbit handoffs')
  assert.equal(eff.velocity.median_handoff_min, 2)
  assert.equal(eff.retrieval.query_hit_rate_pct, 50)
  assert.deepEqual(eff.distribution.compliant_writers, ['mydude', 'dead-rabbit'])
  assert.deepEqual(eff.distribution.receipt_only_writers, ['waggle-dev'])
  assert(eff.projected.after_wake_hook_score >= eff.score)
})

await test('computeAgentHealth: classifies 5m active, 5-20m warm, >20m stale, error, and preserves telemetry across rollover', () => {
  const nowSec = 10_000
  const roster = [
    { id: 'mydude', pubkey: '1'.repeat(64), is_reader: true, is_writer: true },
    { id: 'crusty', pubkey: '2'.repeat(64), is_reader: true, is_writer: true },
    { id: 'silent-agent', pubkey: '3'.repeat(64), is_reader: true, is_writer: true },
    { id: 'refused-agent', pubkey: '4'.repeat(64), is_reader: true, is_writer: false },
  ]
  const telemetry = new Map()
  const pass1 = computeAgentHealth({
    agent_roster: roster,
    recent_activity: [
      { kind: 'query', actor: 'mydude', at: nowSec - 120 },
      { kind: 'wake', actor: 'crusty', at: nowSec - 750 },
      { kind: 'refused', actor: 'refused-agent', at: nowSec - 60, code: 'ACL_DENIED' },
    ],
    records: [
      { author_pubkey: '1'.repeat(64), d: 'hive:ops:nvoy:review', created_at: nowSec - 45 },
    ],
    prior_telemetry: telemetry,
    now_sec: nowSec,
  })
  assert.equal(pass1.summary.active_5m, 1)
  assert.equal(pass1.summary.warm_20m, 1)
  assert.equal(pass1.summary.stale, 1)
  assert.equal(pass1.summary.error, 1)
  const byId1 = new Map(pass1.roster.map(a => [a.id, a]))
  assert.equal(byId1.get('mydude').health, 'active')
  assert.equal(byId1.get('mydude').reads_5m, 1)
  assert.equal(byId1.get('mydude').last_write_at, nowSec - 45)
  assert.equal(byId1.get('crusty').health, 'warm')
  assert.equal(byId1.get('silent-agent').health, 'stale')
  assert.equal(byId1.get('refused-agent').health, 'error')

  // Simulate activity ring rollover (empty recent_activity on next poll 30s later): telemetry is preserved
  const pass2 = computeAgentHealth({
    agent_roster: roster,
    recent_activity: [],
    records: [],
    prior_telemetry: telemetry,
    now_sec: nowSec + 30,
  })
  const byId2 = new Map(pass2.roster.map(a => [a.id, a]))
  assert.equal(byId2.get('mydude').health, 'active')
  assert.equal(byId2.get('mydude').last_read_at, nowSec - 120)
  assert.equal(byId2.get('crusty').health, 'warm')
})

await test('computeDreamingTelemetry: groups Gate 8 Class A by scope+topic, restricts shortTtlCount to workflow slugs, and marks estimates', () => {
  const recs = [
    ...Array.from({ length: 5 }, (_, i) => ({
      scope: 'room:1',
      d: `hive-memory:room:1:item-${i}`,
      topic: 'ops',
      claim: `Room 1 ops claim ${i}`,
      created_at: 1000,
      expires_at: 1000 + 86400, // 24h TTL, but NOT a workflow checkpoint slug
    })),
    ...Array.from({ length: 5 }, (_, i) => ({
      scope: 'room:2',
      d: `hive-memory:room:2:item-${i}`,
      topic: 'ops',
      claim: `Room 2 ops claim ${i}`,
      created_at: 1000,
      expires_at: 1000 + 86400,
    })),
    {
      scope: 'room:1',
      d: 'hive-memory:room:1:pr336-status',
      topic: 'nvoy',
      claim: 'PR 336 status checkpoint on 24h TTL',
      created_at: 1000,
      expires_at: 1000 + 86400,
    },
    {
      scope: 'room:1',
      d: 'hive-memory:room:1:pr336-review',
      topic: 'nvoy',
      claim: 'PR 336 review checkpoint on 7d TTL',
      created_at: 1000,
      expires_at: 1000 + 7 * 86400,
    },
    {
      scope: 'room:1',
      d: 'hive-memory:room:1:decision-1',
      topic: 'decisions',
      claim: 'Permanent Class B decision',
      created_at: 1000,
      expires_at: null,
    },
  ]
  const dt = computeDreamingTelemetry(recs)
  assert.equal(dt.estimated_from_visible, true)
  assert.equal(dt.wfCount, 2, 'only -status and -review slugs are workflow checkpoints')
  assert.equal(dt.shortTtlCount, 1, 'shortTtlCount must only count workflow checkpoints with <=48h TTL')
  assert.equal(dt.classBCount, 1)
  const room1Ops = dt.topicList.find(x => x.scope === 'room:1' && x.topic === 'ops')
  const room2Ops = dt.topicList.find(x => x.scope === 'room:2' && x.topic === 'ops')
  assert.equal(room1Ops?.count, 5)
  assert.equal(room1Ops?.ready, false, '5 claims in room:1 must not trigger >8 curation ready')
  assert.equal(room2Ops?.count, 5)
  assert.equal(room2Ops?.ready, false, '5 claims in room:2 must not trigger >8 curation ready')
  assert.equal(dt.display_mode.mode, 'simulated_preview')
  assert.equal(dt.display_mode.is_simulated_preview, true)
  assert.deepEqual(dt.display_mode.components, {
    clusters: 'simulated_preview',
    eigenvalues: 'simulated_preview',
    topic_arcs: 'simulated_preview',
    ghost_sources: 'simulated_preview',
  })
})

await test('resolveDreamDisplayMode & zero-activity fleet recall: distinguishes simulated preview from observed curation and never reports 100% recall without reads', () => {
  const zeroActivityRoster = [
    { id: 'mydude', pubkey: '1'.repeat(64), is_reader: true, is_writer: true },
    { id: 'neil', pubkey: '2'.repeat(64), is_reader: true, is_writer: true },
    { id: 'waggle-dev', pubkey: '3'.repeat(64), is_reader: true, is_writer: true },
    { id: 'biggy', pubkey: '4'.repeat(64), is_reader: true, is_writer: true },
  ]
  const zeroActCoh = computeCoherence({
    records: [
      {
        event_id: 'a'.repeat(64),
        author_pubkey: '1'.repeat(64),
        scope: 'room:1',
        d: 'hive-memory:room:1:test',
        topic: 'nvoy',
        claim: 'Test claim',
        evidence: ['nvoy@1111111'],
        as_of_git: '1'.repeat(40),
        created_at: 1000,
        expires_at: 5000,
      },
    ],
    agent_roster: zeroActivityRoster,
    recent_activity: [],
    store_state: { write_seq: 1 },
  })
  assert.equal(zeroActCoh.epistemic_drift.recall_coverage_pct, 0, 'zero-activity reader fleet must report 0% recall coverage, never 100%')
  assert.equal(zeroActCoh.epistemic_drift.blind_roster_agents.length, 3)
  assert.equal(zeroActCoh.epistemic_drift.lookup_only_writers.length, 1)

  // 1. No persisted curator state and 0 merkle_sources records -> simulated_preview across all 4 components
  const simMode = resolveDreamDisplayMode({
    records: [{ event_id: '1'.repeat(64), d: 'hive-memory:room:1:item', topic: 'nvoy' }],
    curator_state: {
      state_file_present: false,
      last_curated_at: null,
      topic_eigenvectors: [{ axis: 1, canonical_topic: 'nvoy', eigenvalue: 2.1, variance_pct: 50 }],
      topic_reorganizations: [{ from_topic: 'ops', to_topic: 'nvoy', cosine_affinity: 0.72, claim_count: 2 }],
    },
    consolidated_sources: {},
  })
  assert.equal(simMode.mode, 'simulated_preview')
  assert.equal(simMode.is_simulated_preview, true)
  assert.deepEqual(simMode.components, {
    clusters: 'simulated_preview',
    eigenvalues: 'simulated_preview',
    topic_arcs: 'simulated_preview',
    ghost_sources: 'simulated_preview',
  })

  // 2. Persisted curator state + merkle_sources record, but superseded source is missing (synthetic ghost) -> simulated_preview
  const ghostSimMode = resolveDreamDisplayMode({
    records: [
      {
        event_id: '2'.repeat(64),
        d: 'hive-memory:room:1:curated-nvoy',
        topic: 'nvoy',
        merkle_sources: 'f'.repeat(64),
        supersedes: ['missing-src'.padEnd(64, '0')],
      },
    ],
    curator_state: {
      state_file_present: true,
      last_curated_at: 1700000000,
      topic_eigenvectors: [{ axis: 1, canonical_topic: 'nvoy', eigenvalue: 2.1, variance_pct: 50 }],
      topic_reorganizations: [{ from_topic: 'ops', to_topic: 'nvoy', cosine_affinity: 0.72, claim_count: 2 }],
    },
    consolidated_sources: {},
  })
  assert.equal(ghostSimMode.mode, 'simulated_preview')
  assert.equal(ghostSimMode.is_mixed, true)
  assert.equal(ghostSimMode.observed_merkle_count, 1)
  assert.equal(ghostSimMode.components.clusters, 'observed')
  assert.equal(ghostSimMode.components.ghost_sources, 'simulated_preview')
  assert(ghostSimMode.label.includes('MIXED: OBSERVED MERKLE CURATION (1 persisted merkle_sources'), 'mixed state must report persisted merkle_sources count')
  assert(!ghostSimMode.label.includes('no persisted Merkle curation'), 'mixed state must never claim no persisted Merkle curation')

  // 2b. Persisted curator state + merkle_sources record + resolved historical source, but unpersisted poll-recomputed eigens/arcs (simulated: true, persisted: false) -> mixed preview
  const unpersistedSpectralMode = resolveDreamDisplayMode({
    records: [
      {
        event_id: '2'.repeat(64),
        d: 'hive-memory:room:1:curated-nvoy',
        topic: 'nvoy',
        merkle_sources: 'f'.repeat(64),
        supersedes: ['9'.repeat(64)],
      },
    ],
    curator_state: {
      state_file_present: true,
      last_curated_at: 1700000000,
      topic_eigenvectors: [{ axis: 1, canonical_topic: 'nvoy', eigenvalue: 2.1, variance_pct: 50, simulated: true, persisted: false }],
      topic_reorganizations: [{ from_topic: 'ops', to_topic: 'nvoy', cosine_affinity: 0.72, claim_count: 2, simulated: true, persisted: false }],
    },
    consolidated_sources: {
      ['9'.repeat(64)]: { event_id: '9'.repeat(64), d: 'hive-memory:room:1:prior' },
    },
  })
  assert.equal(unpersistedSpectralMode.mode, 'simulated_preview')
  assert.equal(unpersistedSpectralMode.is_mixed, true)
  assert.deepEqual(unpersistedSpectralMode.components, {
    clusters: 'observed',
    eigenvalues: 'simulated_preview',
    topic_arcs: 'simulated_preview',
    ghost_sources: 'observed',
  })
  assert(unpersistedSpectralMode.label.includes('MIXED: OBSERVED MERKLE CURATION (1 persisted merkle_sources: clusters, ghost_sources) + SIMULATED PREVIEW (eigenvalues, topic_arcs)'))

  // 3. Persisted curator state + merkle_sources record + resolved source in consolidated_sources + real eigens & arcs -> observed
  const srcId = '9'.repeat(64)
  const observedMode = resolveDreamDisplayMode({
    records: [
      {
        event_id: '2'.repeat(64),
        d: 'hive-memory:room:1:curated-nvoy',
        topic: 'nvoy',
        merkle_sources: 'f'.repeat(64),
        supersedes: [srcId],
      },
    ],
    curator_state: {
      state_file_present: true,
      last_curated_at: 1700000000,
      topic_eigenvectors: [{ axis: 1, canonical_topic: 'nvoy', eigenvalue: 2.1, variance_pct: 50 }],
      topic_reorganizations: [{ from_topic: 'ops', to_topic: 'nvoy', cosine_affinity: 0.72, claim_count: 2 }],
    },
    consolidated_sources: {
      [srcId]: { event_id: srcId, d: 'hive-memory:room:1:prior' },
    },
  })
  assert.equal(observedMode.mode, 'observed')
  assert.equal(observedMode.is_simulated_preview, false)
  assert.deepEqual(observedMode.components, {
    clusters: 'observed',
    eigenvalues: 'observed',
    topic_arcs: 'observed',
    ghost_sources: 'observed',
  })
})

await test('live integration: memory-viewer polls memory-daemon viewer socket, streams SSE, and refuses non-GET', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-mem-viewer-'))
  const sockDir = join(tmp, 'sock')
  const db = join(tmp, 'memory.sqlite'), ledger = join(tmp, 'ledger.jsonl'), receipt = join(tmp, 'receipt.json')
  const globalChannel = 'a8186b53-537d-46ad-a7e7-b6486c58970e'

  const ownerSk = generateSecretKey()
  const ownerPk = getPublicKey(ownerSk)
  const nowSec = Math.floor(Date.now() / 1000)

  initEmptyStore({ dbPath: db, ledgerPath: ledger })
  recordVerifiedBackup({ receiptPath: receipt, snapshotId: SNAP_ID, writeSeq: 1, at: nowSec })
  const daemon = await startMemoryDaemon({
    dbPath: db,
    ledgerPath: ledger,
    receiptPath: receipt,
    config: {
      memoryGlobalChannelId: globalChannel,
      ownerPubkey: ownerPk,
      maxUnbackedSec: 3600,
      globalWriters: [],
      readers: { viewer: null },
      writers: { owner: { pubkey: ownerPk, perHour: 100 } },
      rooms: {},
    },
    readers: 'viewer',
    writers: 'owner',
    socketDir: sockDir,
    log: () => {},
  })

  const viewer = await startMemoryViewer({
    socketPath: join(sockDir, 'viewer.sock'),
    host: '127.0.0.1',
    port: 0,
    pollMs: 10000,
  })

  try {
    // 1. Check initial GET / and GET /api/state
    const htmlRes = await httpGet(viewer.port, '/')
    assert.equal(htmlRes.status, 200)
    assert(String(htmlRes.headers['content-security-policy']).includes("default-src 'none'"))
    assert(htmlRes.body.includes('Hive Shared Memory'))
    assert(/\.inspect-header \{ display: flex; flex-wrap: wrap;/.test(htmlRes.body) && htmlRes.body.includes('.inspect-actions .badge { white-space: normal; }'), 'a long inspector badge must wrap, not squeeze the title to one letter per line')
    assert(htmlRes.body.includes('READY'))
    assert(htmlRes.body.includes('viewport-fit=cover'))
    assert(htmlRes.body.includes('100dvh'))
    assert(htmlRes.body.includes('id="mobile-dock"'))
    assert(htmlRes.body.includes('id="dock-agents"'))
    assert(htmlRes.body.includes('id="dock-pulses"'))
    assert(htmlRes.body.includes('id="dock-tools"'))
    assert(htmlRes.body.includes('Dream / Time'))
    assert(htmlRes.body.includes('id="dream-bar-status"'))
    assert(htmlRes.body.includes('id="btn-dream-replay"'))
    assert(htmlRes.body.includes('Replay Last Dream'))
    assert(htmlRes.body.includes('id="btn-dream-consolidate"'))
    assert(htmlRes.body.includes('Inspect Curation (Passive)'))
    assert(htmlRes.body.includes('id="btn-dream-triggers"'))
    assert(htmlRes.body.includes('Inspect 3-Trigger State'))
    assert(htmlRes.body.includes('id="btn-dream-coherence"'))
    assert(htmlRes.body.includes('PASSIVE INSPECTION · READ-ONLY'))
    assert(htmlRes.body.includes('merkle_sources digest tags'))
    assert(!htmlRes.body.includes('verified SHA-256 trees'))
    assert(!htmlRes.body.includes('merkle_sources.event_ids'))
    assert(!htmlRes.body.includes('merkle_sources.root'))
    assert(!htmlRes.body.includes('ms.event_ids'))
    assert(!htmlRes.body.includes('ms.root'))
    assert(!htmlRes.body.includes('Sim write'))
    assert(!htmlRes.body.includes('Sim recall'))
    assert(!htmlRes.body.includes('Sim refusal'))
    assert(htmlRes.body.includes('id="btn-zoom-in"'))
    assert(htmlRes.body.includes('inspect-close'))
    assert(!/relay|SYNCED/i.test(htmlRes.body.replace('never synced to a relay', '')))

    const stateRes1 = await httpGet(viewer.port, '/api/state')
    assert.equal(stateRes1.status, 200)
    const state1 = JSON.parse(stateRes1.body)
    assert.equal(state1.connected, true)
    assert.equal(state1.reader, 'viewer')
    assert.equal(state1.authority, null)
    assert.equal(state1.trustedInstruction, false)
    assert.equal(state1.store_state.state, 'READY')
    assert.equal(state1.store_state.write_seq, 1)
    assert.equal(typeof state1.curator_state, 'object')
    assert.equal(state1.curator_state.write_delta, 1)
    assert.equal(state1.curator_state.should_run, false)
    assert.equal(state1.query_answer, 'none')
    assert(!('global_sync' in state1) && !('relays_answered' in state1) && !('grants_checked_at' in state1))
    assert.equal(state1.records.length, 0)
    assert.deepEqual(state1.recent_activity, [])
    assert.deepEqual(state1.agent_roster.map(a => [a.id, a.is_owner]), [['owner', true]])

    // The page reloads whenever the live snapshot's viewer_version differs from its own, so the two must match.
    const pageRes = await httpGet(viewer.port, '/')
    assert.equal(typeof state1.viewer_version, 'string')
    assert(pageRes.body.includes(`var VIEWER_VERSION = '${state1.viewer_version}';`), 'page and snapshot viewer_version must match or the page reloads forever')

    // 2. Non-GET/HEAD requests are refused with 405
    const postRes = await httpGet(viewer.port, '/api/state', 'POST')
    assert.equal(postRes.status, 405)

    // 3. Connect an SSE client to /events and verify live broadcast when a claim is ingested
    const sseMessages = []
    const sseReq = httpRequest({ host: '127.0.0.1', port: viewer.port, path: '/events', method: 'GET' }, res => {
      res.setEncoding('utf8')
      let buf = ''
      res.on('data', chunk => {
        buf += chunk
        let idx
        while ((idx = buf.indexOf('\n\n')) >= 0) {
          const frame = buf.slice(0, idx)
          buf = buf.slice(idx + 2)
          if (frame.startsWith('data: ')) {
            sseMessages.push(JSON.parse(frame.slice(6)))
          }
        }
      })
    })
    sseReq.end()

    // Wait briefly for initial SSE frame
    for (let i = 0; i < 20 && sseMessages.length < 1; i++) {
      await new Promise(r => setTimeout(r, 25))
    }
    assert.equal(sseMessages.length, 1)
    assert.equal(sseMessages[0].records.length, 0)

    // Ingest a signed hive:canon claim from ownerPk with an HTML/script payload to verify escaping
    const claimTemplate = buildClaimTemplate({
      pubkey: ownerPk,
      scope: 'hive:canon',
      slug: 'review-policy',
      topic: 'governance',
      claim: 'Only My Dude approves PRs <script>alert(1)</script>',
      because: 'James clarified the review policy on 2026-11-05',
      evidence: ['nvoy@8aa86b82377aed390257abd5fdc76ac8246b30ff:mcp/tools/memory-daemon.mjs'],
      asOfGit: 'nvoy@8aa86b82377aed390257abd5fdc76ac8246b30ff',
      memoryGlobalChannelId: globalChannel,
      nowSec: nowSec + 1,
    })
    const signedClaim = finalizeEvent(claimTemplate, ownerSk)
    const submitRes = daemon.store.submit({ writer: 'owner', event: signedClaim, expectedPriorId: null })
    assert.equal(submitRes.accepted, true)

    await viewer.pollOnce()

    for (let i = 0; i < 20 && sseMessages.length < 2; i++) {
      await new Promise(r => setTimeout(r, 25))
    }
    assert(sseMessages.length >= 2)
    const latest = sseMessages.at(-1)
    assert.equal(latest.store_state.state, 'READY')
    assert.equal(latest.store_state.write_seq, 2)
    assert.equal(latest.store_state.unbacked_writes, 1)
    assert.equal(latest.scope_counts.canon, 1)
    assert.equal(latest.records.length, 1)
    assert.equal(latest.records[0].authority, null)
    assert.equal(latest.records[0].trustedInstruction, false)
    assert.equal(latest.records[0].d, 'hive-memory:hive:canon:review-policy')
    assert(latest.event_log.some(e => e.kind === 'claim-added'))

    const htmlRes2 = await httpGet(viewer.port, '/')
    assert(!htmlRes2.body.includes('<script>alert(1)</script>'))
    assert(htmlRes2.body.includes('\\u003cscript\\u003ealert(1)\\u003c/script\\u003e'))

    // Verify viewer honors HIVE_MEMORY_CURATOR_STATE_FILE / stateFile override and fails closed on corrupt state file
    const overrideStatePath = join(tmp, 'custom-curator-state.json')
    process.env.HIVE_MEMORY_CURATOR_STATE_FILE = overrideStatePath
    try {
      const parsedFlags = parseViewerFlags(['--socket', join(sockDir, 'viewer.sock'), '--state-file', overrideStatePath, '--listen', '127.0.0.1:0'])
      assert.equal(parsedFlags.stateFile, overrideStatePath)

      const { writeCuratorStateFile } = await import('../mcp/tools/memory-curate.mjs')
      writeCuratorStateFile(overrideStatePath, {
        last_curated_at: nowSec - 120,
        last_curated_write_seq: 2,
        last_ran_at: nowSec - 120,
        last_submitted_count: 1,
      })
      const polledWithOverride = await viewer.pollOnce()
      assert.equal(polledWithOverride.curator_state.state_file, overrideStatePath)
      assert.equal(polledWithOverride.curator_state.state_file_present, true)
      assert.equal(polledWithOverride.curator_state.last_curated_write_seq, 2)
      assert.equal(polledWithOverride.curator_state.write_delta, 0)
      assert(Array.isArray(polledWithOverride.curator_state.planned_clusters), 'curator_state includes planned_clusters for 4-Act Replay')
      assert(
        polledWithOverride.curator_state.topic_eigenvectors.every(e => e.simulated === true && e.persisted === false),
        'poll-recomputed eigenvectors without persisted state entries must be marked simulated: true, persisted: false'
      )
      assert(
        polledWithOverride.curator_state.topic_reorganizations.every(r => r.simulated === true && r.persisted === false),
        'poll-recomputed topic reorganization proposals must be marked simulated: true, persisted: false'
      )
    } finally {
      delete process.env.HIVE_MEMORY_CURATOR_STATE_FILE
    }

    sseReq.destroy()

    // A store that stops being ready answers unknown, never none, and the viewer shows it.
    daemon.store.setConfig(null, new Error('fixture: config withdrawn'))
    const notReady = await viewer.pollOnce()
    assert.equal(notReady.query_answer, 'unknown')
    assert.equal(notReady.records.length, 0)
    assert.notEqual(notReady.store_state.state, 'READY')

    // Verify viewer.stop() closes keep-alive sockets immediately (< 500ms) instead of hanging on SIGTERM.
    const keepAliveReq = httpRequest({
      host: '127.0.0.1',
      port: viewer.port,
      path: '/api/state',
      method: 'GET',
      headers: { Connection: 'keep-alive' },
    })
    keepAliveReq.end()
    await new Promise(resolveResp => keepAliveReq.on('response', res => {
      res.resume()
      res.on('end', resolveResp)
    }))
    const stopStart = Date.now()
    await viewer.stop()
    assert(Date.now() - stopStart < 500, 'viewer.stop() should terminate keep-alive connections quickly')
  } finally {
    await viewer.stop()
    await daemon.close()
    rmSync(tmp, { recursive: true, force: true })
  }
})

await test('daemon activity ring: only the viewer wake carries it, metadata only, inside the viewer ACL, capped', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-mem-activity-'))
  const db = join(tmp, 'memory.sqlite'), ledger = join(tmp, 'ledger.jsonl'), receipt = join(tmp, 'receipt.json')
  const globalChannel = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
  const room = '5b7c1d2e-3f40-4a51-8b62-7c83d94ea5f6'
  const ownerSk = generateSecretKey(), ownerPk = getPublicKey(ownerSk)
  const neilSk = generateSecretKey(), neilPk = getPublicKey(neilSk)
  const nowSec = Math.floor(Date.now() / 1000)

  initEmptyStore({ dbPath: db, ledgerPath: ledger })
  recordVerifiedBackup({ receiptPath: receipt, snapshotId: SNAP_ID, writeSeq: 1, at: nowSec })
  const daemon = await startMemoryDaemon({
    dbPath: db,
    ledgerPath: ledger,
    receiptPath: receipt,
    config: {
      memoryGlobalChannelId: globalChannel,
      ownerPubkey: ownerPk,
      maxUnbackedSec: 3600,
      globalWriters: [],
      readers: { viewer: null, biggy: null },
      writers: { owner: { pubkey: ownerPk, perHour: 100 }, neil: { pubkey: neilPk, perHour: 30 } },
      rooms: { [room]: { members: [neilPk], writers: [neilPk] } },
    },
    readers: 'viewer',
    writers: 'owner',
    socketDir: join(tmp, 'sock'),
    log: () => {},
  })

  const viewer = { kind: 'reader', name: 'viewer' }
  const biggy = { kind: 'reader', name: 'biggy' }
  const activity = { seq: 0, events: [] }
  const call = (binding, name, args, ring = activity) => handleSocketJsonRpc({
    store: daemon.store, binding, nowSec: nowSec + 2, activity: ring,
    message: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } },
  })
  const payload = res => JSON.parse(res.result.content[0].text)
  const claim = (sk, pk, scope, slug) => finalizeEvent(buildClaimTemplate({
    pubkey: pk, scope, slug, topic: 'governance',
    claim: 'SECRET-CLAIM-TEXT', because: 'SECRET-BECAUSE', evidence: ['nvoy@SECRET-EVIDENCE'],
    asOfGit: 'nvoy@8aa86b82377aed390257abd5fdc76ac8246b30ff',
    memoryGlobalChannelId: globalChannel, nowSec: nowSec + 1,
  }), sk)

  try {
    const canon = claim(ownerSk, ownerPk, 'hive:canon', 'review-policy')
    assert.equal(payload(call({ kind: 'writer', name: 'owner' }, 'memory_submit', { event: canon, expected_prior_id: null })).accepted, true)
    const roomed = claim(neilSk, neilPk, `room:${room}`, 'secret-room-plan')
    assert.equal(payload(call({ kind: 'writer', name: 'neil' }, 'memory_submit', { event: roomed, expected_prior_id: null })).accepted, true)

    // Another reader's wake is byte-for-byte what it was without the ring, even if include_telemetry: true is passed.
    const plain = call(biggy, 'memory_wake', {}, null)
    const ringed = call(biggy, 'memory_wake', { include_telemetry: true })
    assert.equal(JSON.stringify(ringed), JSON.stringify(plain))
    assert(!('recent_activity' in payload(ringed)) && !('agent_roster' in payload(ringed)))
    call(biggy, 'memory_query', { topic: 'governance', text: 'SECRET-CLAIM-TEXT' })
    call(biggy, 'memory_query', { scope: 'hive:canon', topic: 'governance' })
    call(biggy, 'memory_submit', { event: canon, expected_prior_id: null })

    const seqBefore = activity.seq
    const wake = payload(call(viewer, 'memory_wake', {}))
    assert.equal(activity.seq, seqBefore, 'the viewer records none of its own calls')
    assert.equal(wake.authority, null)
    const seen = wake.recent_activity
    assert.deepEqual(seen.map(a => a.kind), ['submit', 'submit', 'wake', 'query', 'query', 'refused'])
    for (const a of seen) {
      assert.deepEqual(Object.keys(a), ['seq', 'at', 'kind', 'actor', 'count', 'accepted', 'code', 'event_ids', 'd', 'topic', 'scope'])
    }
    assert(!/SECRET/.test(JSON.stringify(seen)), 'no claim, because, evidence or query text in the ring')
    assert.deepEqual([seen[0].actor, seen[0].d, seen[0].event_ids], ['owner', 'hive-memory:hive:canon:review-policy', [canon.id]])
    assert.deepEqual([seen[1].actor, seen[1].d, seen[1].scope, seen[1].event_ids], ['neil', null, null, []], 'room key stays outside the keyless viewer ACL')
    assert.deepEqual([seen[3].topic, seen[3].scope], [null, null], 'an unscoped query may reach rooms, so its topic stays hidden')
    assert.deepEqual([seen[4].topic, seen[4].scope, seen[4].count], ['governance', 'hive:canon', 1])
    assert.deepEqual([seen[5].accepted, seen[5].code], [false, 'HIVE_MEMORY_READ_ONLY_SOCKET'])

    const roster = Object.fromEntries(wake.agent_roster.map(a => [a.id, a]))
    assert.deepEqual(Object.keys(roster).sort(), ['biggy', 'neil', 'owner'])
    assert.deepEqual([roster.owner.is_owner, roster.owner.used_last_hour, roster.owner.per_hour], [true, 1, 100])
    assert.deepEqual([roster.neil.is_writer, roster.neil.used_last_hour, roster.biggy.is_writer], [true, 1, false])

    for (let i = 0; i < ACTIVITY_MAX + 20; i++) call(biggy, 'memory_wake', {})
    const capped = payload(call(viewer, 'memory_wake', {})).recent_activity
    assert.equal(capped.length, ACTIVITY_MAX)
    assert.equal(capped.at(-1).seq, activity.seq)

    const prev = { store_state: wake.store_state, records: [], recent_activity: seen.map(sanitizeActivity) }
    const next = { ...prev, recent_activity: capped.slice(-2).map(sanitizeActivity) }
    const logged = diffViewerSnapshots(prev, next, nowSec).filter(e => e.kind.startsWith('activity-'))
    assert.deepEqual(logged.map(e => e.kind), ['activity-wake', 'activity-wake'])
    assert(!logged.some(e => /relay|sync/i.test(e.summary)))

    const renderedHtml = renderViewerHtml(next)
    assert(renderedHtml.includes('[REPLAY · READ-ONLY]'), '4-act animation logs must be explicitly read-only replay')
    assert(renderedHtml.includes('SIMULATED PREVIEW'), 'page must label synthetic/fallback clusters, eigenvalues, topic arcs and ghost sources as SIMULATED PREVIEW')
    assert(renderedHtml.includes('SIMULATED PREVIEW CLUSTER') && renderedHtml.includes('SIMULATED PREVIEW EIGENVALUE') && renderedHtml.includes('SIMULATED PREVIEW TOPIC ARC') && renderedHtml.includes('SIMULATED PREVIEW GHOST'), 'all 4 fallback categories must carry explicit SIMULATED PREVIEW labels')
    assert(renderedHtml.includes('buildPreviewDreamClusters'), 'replayLastDream must fall back to buildPreviewDreamClusters when store has 0 merkle_sources records')
    assert(renderedHtml.includes('src.node.isSyntheticGhost || src.node.simulated'), 'Act II only labels synthetic/missing ghosts as SIMULATED GHOST, never resolved historical sources')
    assert(!renderedHtml.includes('src.node.isSourceGhost || src.simulated'), 'Act II must not treat resolved isSourceGhost historical sources as SIMULATED GHOST')
    assert(!renderedHtml.includes('92.4%'), '4-act animation must not contain invented coherence uplift fallback')
  } finally {
    await daemon.close()
    rmSync(tmp, { recursive: true, force: true })
  }
})

await test('the health check status shows saving off, partly off, stale or unreadable as an alert', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'viewer-watch-'))
  try {
    const now = 1794053720
    const write = (o) => { const f = join(tmp, `s${Math.random()}.json`); writeFileSync(f, typeof o === 'string' ? o : JSON.stringify(o)); return f }
    const off = readWatchStatus(write({ at: now, writers: { biggy: 'FENCED', neil: 'FENCED' }, problems: ['saving is OFF'] }), now)
    assert.equal(off.saving, 'OFF')
    assert.match(watchAlert(off, now), /^SAVING IS OFF: all 2 writers/)
    const part = readWatchStatus(write({ at: now, writers: { biggy: 'open', neil: 'FENCED' }, problems: [] }), now)
    assert.equal(watchAlert(part, now), 'Saving is off for neil: their saves are refused')
    const open = readWatchStatus(write({ at: now, writers: { biggy: 'open', neil: 'open' }, problems: [] }), now)
    assert.equal(open.saving, 'open')
    assert.equal(watchAlert(open, now), null)
    const stale = readWatchStatus(write({ at: now - WATCH_STALE_SEC - 60, writers: { biggy: 'open' }, problems: [] }), now)
    assert.match(watchAlert(stale, now), /last reported 16 min ago/)
    const staleOff = join(tmp, 'stale-off.json')
    writeFileSync(staleOff, JSON.stringify({ at: now - WATCH_STALE_SEC - 60, writers: { biggy: 'FENCED', neil: 'FENCED' }, problems: [] }))
    const so = watchView(now, staleOff)
    assert.equal(so.alert, 'The health check last reported 16 min ago (it then said saving was OFF): saving cannot be confirmed',
      'a stale OFF report is not shown as the current state')
    assert.equal(so.hard, false, 'a stale report is amber, not red')
    assert.equal(watchView(now, write({ at: now, writers: { biggy: 'FENCED' }, problems: [] })).hard, true, 'a fresh OFF report is red')
    const old = readWatchStatus(write({ at: now, readers: { hr: 'ok' }, problems: [] }), now)
    assert.match(watchAlert(old, now), /does not report writers/, 'a watch without the writers check is not taken as saving open')
    assert.match(watchAlert(readWatchStatus(join(tmp, 'missing.json'), now), now), /has not reported/)
    assert.match(watchAlert(readWatchStatus(write('not json'), now), now), /has not reported/)
    const odd = readWatchStatus(write({ at: now, writers: { '../x': 'open', biggy: 'yes' }, problems: [7, 'x'.repeat(400)] }), now)
    assert.deepEqual(odd.writers, { biggy: 'FENCED' }, 'odd names are dropped and anything but "open" is fenced')
    assert.equal(odd.problems.length, 1)
    assert.equal(odd.problems[0].length, 300)

    const base = { store_state: { state: 'READY', write_seq: 319 }, records: [], recent_activity: [], connected: true }
    const toOff = diffViewerSnapshots({ ...base, watch: open }, { ...base, watch: off }, now).filter((e) => e.kind === 'alert')
    assert.equal(toOff.length, 1)
    assert.match(toOff[0].summary, /SAVING IS OFF/)
    const back = diffViewerSnapshots({ ...base, watch: off }, { ...base, watch: open }, now).filter((e) => e.kind === 'alert')
    assert.equal(back[0].summary, 'Health check clear: saving is open')
    assert.equal(diffViewerSnapshots({ ...base, watch: open }, { ...base, watch: open }, now).filter((e) => e.kind === 'alert').length, 0)
    assert.match(renderViewerHtml({ ...base, watch: off }), /id="alert-banner"/)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

await test('pollOnce coalesces concurrent polls and reuses cached corpus on unchanged write_seq', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'viewer-coalesce-'))
  const dbPath = join(tmp, 'memory.sqlite')
  const ledgerPath = join(tmp, 'accepted-ledger.jsonl')
  const receiptPath = join(tmp, 'last-verified-backup.json')
  const socketDir = join(tmp, 'sockets')
  const ownerSk = generateSecretKey()
  const ownerPk = getPublicKey(ownerSk)
  const viewerSk = generateSecretKey()
  const viewerPk = getPublicKey(viewerSk)
  const room = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
  const nowSec = Math.floor(Date.now() / 1000)
  initEmptyStore({ dbPath, ledgerPath })
  recordVerifiedBackup({ receiptPath, snapshotId: SNAP_ID, writeSeq: 1, at: nowSec })
  const daemon = await startMemoryDaemon({
    dbPath,
    ledgerPath,
    receiptPath,
    config: {
      memoryGlobalChannelId: room,
      ownerPubkey: ownerPk,
      maxUnbackedSec: 3600,
      globalWriters: [ownerPk],
      canonWriters: [ownerPk],
      readers: { viewer: viewerPk },
      writers: { james: { pubkey: ownerPk, perHour: 30 } },
      rooms: { [room]: { members: [ownerPk, viewerPk], writers: [ownerPk] } },
    },
    readers: 'viewer',
    writers: 'james',
    socketDir,
    log: () => {},
  })
  let viewer = null
  try {
    viewer = await startMemoryViewer({
      socketPath: join(socketDir, 'viewer.sock'),
      host: '127.0.0.1',
      port: 0,
      pollMs: 60000,
    })
    const seq0 = viewer.getState().poll_seq
    const [s1, s2, s3] = await Promise.all([viewer.pollOnce(), viewer.pollOnce(), viewer.pollOnce()])
    assert.equal(s1.poll_seq, seq0 + 1, 'concurrent pollOnce calls must coalesce into one in-flight poll')
    assert.equal(s2.poll_seq, seq0 + 1)
    assert.equal(s3.poll_seq, seq0 + 1)

    const sCached = await viewer.pollOnce({ forceFull: false })
    assert.equal(sCached.poll_seq, seq0 + 2)
    assert.equal(sCached.store_state.write_seq, 1)
    assert(CORPUS_CACHE_TTL_MS >= 300_000, 'CORPUS_CACHE_TTL_MS must be at least 5 minutes to prevent 15s full-history rescan throttling')
    assert.equal(sCached.records, s1.records, 'unchanged write_seq must reuse cached records array')
    assert.equal(sCached.coherence, s1.coherence, 'unchanged write_seq and activity tail must reuse cached coherence')
    assert.equal(sCached.efficacy, s1.efficacy, 'unchanged write_seq and activity tail must reuse cached synaptic efficacy')

    const root1 = await httpGet(viewer.port, '/')
    const root2 = await httpGet(viewer.port, '/')
    assert.equal(root1.status, 200)
    assert.equal(root2.status, 200)
    assert.equal(root1.body, root2.body, 'same poll_seq reuses cached HTML')
    assert(root1.body.includes(`"poll_seq":${seq0 + 2}`))

    const sNext = await viewer.pollOnce({ forceFull: false })
    assert.equal(sNext.poll_seq, seq0 + 3)
    const root3 = await httpGet(viewer.port, '/')
    assert.equal(root3.status, 200)
    assert.notEqual(root3.body, root1.body, 'new poll_seq must invalidate cached HTML and reflect updated state')
    assert(root3.body.includes(`"poll_seq":${seq0 + 3}`))
  } finally {
    if (viewer) await viewer.stop()
    await daemon.close()
    rmSync(tmp, { recursive: true, force: true })
  }
})

await test('Entity-Link Constellation Graph & Above/Below-the-Line Topic Pages in state and Markdown endpoints', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'viewer-topics-'))
  const dbPath = join(tmp, 'memory.sqlite')
  const ledgerPath = join(tmp, 'accepted-ledger.jsonl')
  const receiptPath = join(tmp, 'last-verified-backup.json')
  const socketDir = join(tmp, 'sockets')
  const ownerSk = generateSecretKey()
  const ownerPk = getPublicKey(ownerSk)
  const viewerSk = generateSecretKey()
  const viewerPk = getPublicKey(viewerSk)
  const room = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
  const nowSec = Math.floor(Date.now() / 1000)
  initEmptyStore({ dbPath, ledgerPath })
  recordVerifiedBackup({ receiptPath, snapshotId: SNAP_ID, writeSeq: 1, at: nowSec })
  const daemon = await startMemoryDaemon({
    dbPath,
    ledgerPath,
    receiptPath,
    config: {
      memoryGlobalChannelId: room,
      ownerPubkey: ownerPk,
      maxUnbackedSec: 3600,
      globalWriters: [ownerPk],
      canonWriters: [ownerPk],
      readers: { viewer: viewerPk },
      writers: { james: { pubkey: ownerPk, perHour: 30 } },
      rooms: { [room]: { members: [ownerPk, viewerPk], writers: [ownerPk] } },
    },
    readers: 'viewer',
    writers: 'james',
    socketDir,
    log: () => {},
  })

  const signClaim = (scope, slug, opts = {}) =>
    finalizeEvent(
      buildClaimTemplate({
        pubkey: ownerPk,
        scope,
        slug,
        memoryGlobalChannelId: room,
        topic: opts.topic || 'hive-memory',
        claim: opts.claim,
        because: opts.because || 'viewer topic page test',
        evidence: opts.evidence || ['nvoy@e2cd9ebe:mcp/tools/memory-viewer.mjs'],
        asOfGit: opts.asOfGit || 'e2cd9ebea92579c98cda558d003270941ba50d97',
        ttlSec: opts.ttlSec ?? 86400 * 14,
        nowSec: opts.createdAt || nowSec,
      }),
      ownerSk
    )

  const canonEv = signClaim('hive:canon', 'viewer-canon-rule', {
    ttlSec: 0,
    claim: 'All changes to mcp/tools/memory-viewer.mjs in PR #351 require @mydude approval.',
    createdAt: nowSec - 30,
  })
  const decisionEv = signClaim(`room:${room}`, 'viewer-hybrid-decision', {
    ttlSec: 0,
    claim: 'Shipped Hybrid BM25+Vector RRF and claim_edges in PR #351 with @biggy and @mydude.',
    createdAt: nowSec - 20,
  })
  const statusEv = signClaim(`room:${room}`, 'viewer-pr351-status', {
    ttlSec: 86400 * 14,
    claim: 'Opened PR #351 for mcp/tools/memory-viewer.mjs review by @mydude.',
    createdAt: nowSec - 10,
  })
  daemon.store.submit({ writer: 'james', event: canonEv, expectedPriorId: null, nowSec: nowSec - 30 })
  daemon.store.submit({ writer: 'james', event: decisionEv, expectedPriorId: null, nowSec: nowSec - 20 })
  daemon.store.submit({ writer: 'james', event: statusEv, expectedPriorId: null, nowSec: nowSec - 10 })

  let viewer = null
  try {
    viewer = await startMemoryViewer({
      socketPath: join(socketDir, 'viewer.sock'),
      host: '127.0.0.1',
      port: 0,
      pollMs: 60000,
    })
    const st = viewer.getState()
    assert(Array.isArray(st.constellation_links) && st.constellation_links.length >= 2, 'constellation_links should link claims sharing PR #351 and memory-viewer.mjs')
    assert(st.constellation_links.some(l => l.shared_entities.includes('pr:351')), 'constellation link should include pr:351')
    assert(st.topic_pages && st.topic_pages['hive-memory'], 'topic_pages should include hive-memory')
    assert.equal(st.topic_pages['hive-memory'].counts.above_the_line, 2, 'Canon + Class B decision should be Above the Line')
    assert.equal(st.topic_pages['hive-memory'].counts.below_the_line, 1, 'Class A status claim should be Below the Line')

    const idxRes = await httpGet(viewer.port, '/topics/index.md')
    assert.equal(idxRes.status, 200)
    assert.match(String(idxRes.headers['content-type'] || ''), /^text\/markdown/)
    assert(idxRes.body.includes('#hive-memory'))

    const pageRes = await httpGet(viewer.port, '/topics/hive-memory.md')
    assert.equal(pageRes.status, 200)
    assert.match(String(pageRes.headers['content-type'] || ''), /^text\/markdown/)
    assert(pageRes.body.includes('## Above the Line — Compiled Truth'))
    assert(pageRes.body.includes('## Below the Line — Active Class A Evidence Timeline & Lineage'))
    assert(pageRes.body.includes('viewer-hybrid-decision'))
    assert(pageRes.body.includes('viewer-pr351-status'))

    const malformedRes = await httpGet(viewer.port, '/topics/%')
    assert.equal(malformedRes.status, 400, 'malformed percent-encoded /topics/% must return 400 without crashing')
    const afterMalformedRes = await httpGet(viewer.port, '/topics/index.md')
    assert.equal(afterMalformedRes.status, 200, 'viewer continues serving valid routes after malformed /topics/% request')

    const htmlRes = await httpGet(viewer.port, '/')
    assert.equal(htmlRes.status, 200)
    assert(htmlRes.body.includes('Topic Page · Above / Below the Line'))
    assert(htmlRes.body.includes('Constellation Entity-Link Mesh'))
    assert(htmlRes.body.includes('Nocturnal Dream Story'))
  } finally {
    if (viewer) await viewer.stop()
    await daemon.close()
    rmSync(tmp, { recursive: true, force: true })
  }
})

await test('PR #354 regressions: cached event immutability, pre-curation elapsed_sec, and reader isolation across rebind', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'viewer-pr354-'))
  const dbPath = join(tmp, 'memory.sqlite')
  const ledgerPath = join(tmp, 'accepted-ledger.jsonl')
  const receiptPath = join(tmp, 'last-verified-backup.json')
  const dbPath2 = join(tmp, 'memory2.sqlite')
  const ledgerPath2 = join(tmp, 'accepted-ledger2.jsonl')
  const receiptPath2 = join(tmp, 'last-verified-backup2.json')
  const socketDir = join(tmp, 'sockets')
  const ownerSk = generateSecretKey()
  const ownerPk = getPublicKey(ownerSk)
  const viewerSkA = generateSecretKey()
  const viewerPkA = getPublicKey(viewerSkA)
  const viewerSkB = generateSecretKey()
  const viewerPkB = getPublicKey(viewerSkB)
  const globalRoom = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
  const privateRoom = 'b9297c64-648e-57be-b8f8-c7597d69081f'
  const nowSec = Math.floor(Date.now() / 1000)

  initEmptyStore({ dbPath, ledgerPath })
  recordVerifiedBackup({ receiptPath, snapshotId: SNAP_ID, writeSeq: 1, at: nowSec - 3600 })
  initEmptyStore({ dbPath: dbPath2, ledgerPath: ledgerPath2 })
  recordVerifiedBackup({ receiptPath: receiptPath2, snapshotId: SNAP_ID, writeSeq: 1, at: nowSec - 3600 })

  const baseConfig = readerPk => ({
    memoryGlobalChannelId: globalRoom,
    ownerPubkey: ownerPk,
    maxUnbackedSec: 7200,
    globalWriters: [ownerPk],
    canonWriters: [ownerPk],
    readers: { viewer: readerPk },
    writers: { james: { pubkey: ownerPk, perHour: 30 } },
    rooms: {
      [globalRoom]: { members: [ownerPk, viewerPkA, viewerPkB], writers: [ownerPk] },
      [privateRoom]: { members: [ownerPk, viewerPkA], writers: [ownerPk] },
    },
  })

  let daemon = await startMemoryDaemon({
    dbPath,
    ledgerPath,
    receiptPath,
    config: baseConfig(viewerPkA),
    readers: 'viewer',
    writers: 'james',
    socketDir,
    log: () => {},
  })

  const globalEv = finalizeEvent(
    buildClaimTemplate({
      pubkey: ownerPk,
      scope: `room:${globalRoom}`,
      slug: 'shared-global-claim',
      memoryGlobalChannelId: globalRoom,
      topic: 'hive-memory',
      claim: 'Shared global claim visible to both readers.',
      because: 'PR 354 regression test',
      evidence: ['nvoy@e2cd9ebe:mcp/tools/memory-viewer.mjs'],
      asOfGit: 'e2cd9ebea92579c98cda558d003270941ba50d97',
      ttlSec: 86400 * 14,
      nowSec: nowSec - 3600,
    }),
    ownerSk
  )
  const privateEv = finalizeEvent(
    buildClaimTemplate({
      pubkey: ownerPk,
      scope: `room:${privateRoom}`,
      slug: 'private-room-claim',
      memoryGlobalChannelId: globalRoom,
      topic: 'hive-memory',
      claim: 'Private room claim visible only to reader A.',
      because: 'PR 354 reader isolation test',
      evidence: ['nvoy@e2cd9ebe:mcp/tools/hive_memory_store.mjs'],
      asOfGit: 'e2cd9ebea92579c98cda558d003270941ba50d97',
      ttlSec: 86400 * 14,
      nowSec: nowSec - 3500,
    }),
    ownerSk
  )

  daemon.store.submit({ writer: 'james', event: globalEv, expectedPriorId: null, nowSec: nowSec - 3600 })
  daemon.store.submit({ writer: 'james', event: privateEv, expectedPriorId: null, nowSec: nowSec - 3500 })

  // 1. Verify PARSED_EVENT_CACHE immutability across same-store and cross-store queries
  const q1 = daemon.store.query({ readerPubkey: viewerPkA, format: 'full', nowSec })
  assert.equal(q1.records.length, 2)
  const rec0 = q1.records.find(r => r.event_id === globalEv.id)
  assert(rec0)
  rec0.evidence.push('injected.mjs')
  rec0.claim = 'mutated claim text'

  const q2 = daemon.store.query({
    readerPubkey: viewerPkA,
    format: 'full',
    staleFiles: new Set(['injected.mjs']),
    nowSec,
  })
  const rec0After = q2.records.find(r => r.event_id === globalEv.id)
  assert.deepEqual(rec0After.evidence, ['nvoy@e2cd9ebe:mcp/tools/memory-viewer.mjs'], 'mutating returned evidence array must not pollute PARSED_EVENT_CACHE')
  assert.equal(rec0After.claim, 'Shared global claim visible to both readers.')
  assert.equal(rec0After.stale_warning, null, 'mutated evidence array must not trigger false stale_warning on subsequent query')

  const daemon2 = await startMemoryDaemon({
    dbPath: dbPath2,
    ledgerPath: ledgerPath2,
    receiptPath: receiptPath2,
    config: baseConfig(viewerPkA),
    readers: 'viewer',
    writers: 'james',
    socketDir: join(tmp, 'sockets2'),
    log: () => {},
  })
  try {
    daemon2.store.submit({ writer: 'james', event: globalEv, expectedPriorId: null, nowSec: nowSec - 3600 })
    const qCross = daemon2.store.query({
      readerPubkey: viewerPkA,
      format: 'full',
      staleFiles: new Set(['injected.mjs']),
      nowSec,
    })
    assert.deepEqual(qCross.records[0].evidence, ['nvoy@e2cd9ebe:mcp/tools/memory-viewer.mjs'], 'cross-store instance sharing event ID must not see mutated evidence')
    assert.equal(qCross.records[0].stale_warning, null, 'cross-store instance must not inherit false stale_warning')
  } finally {
    await daemon2.close()
  }

  let viewer = null
  try {
    viewer = await startMemoryViewer({
      socketPath: join(socketDir, 'viewer.sock'),
      host: '127.0.0.1',
      port: 0,
      pollMs: 60000,
    })

    // 2. Verify before-first-curation elapsed_sec stays non-null on cached poll
    const s1 = viewer.getState()
    assert.equal(s1.curator_state.last_curated_at, null)
    assert(typeof s1.curator_state.elapsed_sec === 'number' && s1.curator_state.elapsed_sec >= 3600, `initial elapsed_sec before first curation must be >= 3600, got ${s1.curator_state.elapsed_sec}`)
    assert.equal(s1.reader_pubkey, viewerPkA)
    assert.equal(s1.records.length, 2, 'reader A should see both global and private room claims')

    const sCached = await viewer.pollOnce({ forceFull: false })
    assert(typeof sCached.curator_state.elapsed_sec === 'number' && sCached.curator_state.elapsed_sec >= s1.curator_state.elapsed_sec, `cached poll elapsed_sec before first curation must stay non-null and >= ${s1.curator_state.elapsed_sec}, got ${sCached.curator_state.elapsed_sec}`)

    // 3. Verify reader isolation: rebind viewer.sock to reader B (with unchanged write_seq and current_claims)
    await daemon.close()
    daemon = null

    // Trigger an error poll while daemon is down, then rebind to reader B
    const sErr = await viewer.pollOnce({ forceFull: false })
    assert.equal(sErr.connected, false)

    daemon = await startMemoryDaemon({
      dbPath,
      ledgerPath,
      receiptPath,
      config: baseConfig(viewerPkB),
      readers: 'viewer',
      writers: 'james',
      socketDir,
      log: () => {},
    })

    const sReaderB = await viewer.pollOnce({ forceFull: false })
    assert.equal(sReaderB.connected, true)
    assert.equal(sReaderB.reader_pubkey, viewerPkB)
    assert.equal(sReaderB.records.length, 1, 'reader B must not receive reader A cached private room claim after error + rebind')
    assert.equal(sReaderB.records[0].event_id, globalEv.id)

    // Also test direct rebind from reader A -> reader B without an intermediate failed poll
    await daemon.close()
    daemon = await startMemoryDaemon({
      dbPath,
      ledgerPath,
      receiptPath,
      config: baseConfig(viewerPkA),
      readers: 'viewer',
      writers: 'james',
      socketDir,
      log: () => {},
    })
    const sBackToA = await viewer.pollOnce({ forceFull: false })
    assert.equal(sBackToA.reader_pubkey, viewerPkA)
    assert.equal(sBackToA.records.length, 2, 'direct rebind back to reader A without intermediate error poll must reload reader A corpus')

    await daemon.close()
    daemon = await startMemoryDaemon({
      dbPath,
      ledgerPath,
      receiptPath,
      config: baseConfig(viewerPkB),
      readers: 'viewer',
      writers: 'james',
      socketDir,
      log: () => {},
    })
    const sDirectB = await viewer.pollOnce({ forceFull: false })
    assert.equal(sDirectB.reader_pubkey, viewerPkB)
    assert.equal(sDirectB.records.length, 1, 'direct rebind from reader A to reader B without intermediate error poll must not leak private room claim')

    // 4. Verify 12,000-deep nested extra JSON in an accepted claim does not throw RangeError in parseEventRaw / store.query / viewer.pollOnce
    const deepTmpl = buildClaimTemplate({
      pubkey: ownerPk,
      scope: `room:${globalRoom}`,
      slug: 'deep-nested-extra-claim',
      memoryGlobalChannelId: globalRoom,
      topic: 'hive-memory',
      claim: 'Claim with 12000-deep nested extra field.',
      because: 'PR 354 depth regression test',
      evidence: ['nvoy@e2cd9ebe:mcp/tools/hive_memory_store.mjs'],
      asOfGit: 'e2cd9ebea92579c98cda558d003270941ba50d97',
      ttlSec: 86400 * 14,
      nowSec: nowSec - 3400,
    })
    deepTmpl.content = deepTmpl.content.replace(/\}$/, `,"extra":${'['.repeat(12000)}${']'.repeat(12000)}}`)
    const deepEv = finalizeEvent(deepTmpl, ownerSk)
    const submitDeep = daemon.store.submit({ writer: 'james', event: deepEv, expectedPriorId: null, nowSec: nowSec - 3400 })
    assert.equal(submitDeep.accepted, true, '12000-deep extra claim should be accepted by store.submit')

    const qDeep = daemon.store.query({ readerPubkey: viewerPkB, format: 'full', nowSec })
    assert.equal(qDeep.records.length, 2, 'store.query must succeed without RangeError on 12000-deep extra field')
    assert(qDeep.records.some(r => r.event_id === deepEv.id))

    const sDeep = await viewer.pollOnce({ forceFull: false })
    assert.equal(sDeep.connected, true, 'viewer must stay connected when polling a 12000-deep extra claim')
    assert.equal(sDeep.records.length, 2)

    // 5. Verify rendered client <script> parses cleanly without SyntaxError and preserves regex escapes
    const renderedHtml = renderViewerHtml(sDeep)
    const scriptBlocks = [...renderedHtml.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)]
    assert(scriptBlocks.length >= 2, 'renderViewerHtml must emit initial-state JSON and client JS <script> blocks')
    for (const [, attrs, code] of scriptBlocks) {
      if (attrs.includes('application/json')) {
        assert.doesNotThrow(() => JSON.parse(code), 'initial-state JSON script must be valid JSON')
      } else {
        assert.doesNotThrow(() => new Function(code), 'client <script> block must compile without SyntaxError')
        assert(code.includes('.replace(/\\b(?:https?|file):\\/\\/\\S+/gi'), 'client <script> must preserve escaped URL regex')
      }
    }

    // 6. Verify unreadable/corrupt curator-state.json does not fail viewer pollOnce() or wipe records
    const brokenStatePath = join(tmp, 'broken-curator-state.json')
    writeFileSync(brokenStatePath, '{not-valid-json\n', { mode: 0o600 })
    process.env.HIVE_MEMORY_CURATOR_STATE_FILE = brokenStatePath
    try {
      const sBroken = await viewer.pollOnce({ forceFull: false })
      assert.equal(sBroken.connected, true, 'viewer must stay connected when curator-state.json is unreadable or corrupt')
      assert.equal(sBroken.error, null)
      assert.equal(sBroken.records.length, 2, 'viewer must preserve records when curator-state.json fails to read')
      assert.equal(sBroken.curator_state.state_file_present, false)
      assert(
        typeof sBroken.curator_state.state_file_error === 'string' &&
          sBroken.curator_state.state_file_error.includes('curator state file'),
        'curator_state.state_file_error must record the non-fatal state file error'
      )
    } finally {
      delete process.env.HIVE_MEMORY_CURATOR_STATE_FILE
    }

    // 7. Verify mem-mobile endpoints (/mobile, /api/mobile, /events?mode=mobile) and buildMobileState metadata-only invariant
    const canaryClaim = 'SECRET_CLAIM_PROSE_DO_NOT_LEAK_99182'
    const canaryBecause = 'SECRET_BECAUSE_PROSE_DO_NOT_LEAK_99182'
    const canaryEvidence = 'nvoy@e2cd9ebe:SECRET_EVIDENCE_PATH_99182'
    const canaryEv = finalizeEvent(
      buildClaimTemplate({
        pubkey: ownerPk,
        scope: `room:${globalRoom}`,
        slug: 'canary-mobile-claim',
        memoryGlobalChannelId: globalRoom,
        topic: 'hive-memory',
        claim: canaryClaim,
        because: canaryBecause,
        evidence: [canaryEvidence],
        asOfGit: 'e2cd9ebea92579c98cda558d003270941ba50d97',
        ttlSec: 86400 * 14,
        nowSec: nowSec - 120,
      }),
      ownerSk
    )
    daemon.store.submit({ writer: 'james', event: canaryEv, expectedPriorId: null, nowSec: nowSec - 120 })
    const sAfterCanary = await viewer.pollOnce({ forceFull: true })
    assert(sAfterCanary.records.some(r => r.claim === canaryClaim), 'full desktop state should contain canary claim')

    const mobileState = buildMobileState(sAfterCanary, nowSec)
    assert.equal(mobileState.view_mode, 'mobile_pocket_cortex')
    assert.equal(mobileState.metadata_only, true)
    assert.equal(mobileState.authority, null)
    assert.equal(mobileState.trustedInstruction, false)
    assert.equal(mobileState.velocities.new_memory.writes_1h, 3, 'new_memory velocity 1h must count exact 3 accepted writes without double-counting recent_activity')
    assert.equal(
      mobileState.velocities.new_memory.sparkline_12h.reduce((sum, n) => sum + n, 0),
      3,
      'sparkline_12h tick sum must equal exact deduplicated write count'
    )
    assert.equal(mobileState.velocities.new_memory.sparkline_12h.length, 12)
    assert.equal(mobileState.velocities.recall.sparkline_60m.length, 12)

    // Regression: 1 real write present in records, historyRecords, AND recent_activity (with event_ids[]) + 1 daemon refusal (kind: 'refused')
    const dedupCheck = buildMobileState(
      {
        updatedAt: new Date(nowSec * 1000).toISOString(),
        daemon: { ok: true },
        records: [
          {
            event_id: canaryEv.id,
            d: `room:${globalRoom}:canary-mobile-claim`,
            slug: 'canary-mobile-claim',
            topic: 'hive-memory',
            scope: `room:${globalRoom}`,
            author: 'james',
            pubkey: ownerPk,
            created_at: nowSec - 60,
            ttl_sec: 86400,
            claim: canaryClaim,
          },
        ],
        historyRecords: [
          {
            event_id: canaryEv.id,
            d: `room:${globalRoom}:canary-mobile-claim`,
            slug: 'canary-mobile-claim',
            topic: 'hive-memory',
            scope: `room:${globalRoom}`,
            author: 'james',
            pubkey: ownerPk,
            created_at: nowSec - 60,
          },
        ],
        consolidatedRecords: [],
        recent_activity: [
          {
            seq: 10,
            at: nowSec - 60,
            kind: 'submit',
            actor: 'james',
            d: `room:${globalRoom}:canary-mobile-claim`,
            topic: 'hive-memory',
            event_ids: [canaryEv.id],
            accepted: true,
          },
          {
            seq: 11,
            at: nowSec - 30,
            kind: 'refused',
            actor: 'james',
            code: 'HIVE_MEMORY_PRIOR_MISMATCH',
            d: `room:${globalRoom}:canary-mobile-claim`,
          },
        ],
        agent_heartbeats: [
          {
            actor: 'james',
            last_seen_at: nowSec - 30,
            last_write_at: nowSec - 60,
            last_write_d: `room:${globalRoom}:canary-mobile-claim`,
          },
        ],
      },
      nowSec
    )
    assert.equal(dedupCheck.velocities.new_memory.writes_1h, 1, 'same event in records/historyRecords and recent_activity(event_ids[]) must count as 1 write')
    assert.equal(
      dedupCheck.velocities.new_memory.sparkline_12h.reduce((sum, n) => sum + n, 0),
      1,
      'same event in records/historyRecords and recent_activity(event_ids[]) must produce 1 sparkline tick'
    )
    assert.equal(dedupCheck.velocities.new_memory.refusals_15m, 1, 'daemon kind: refused activity within 15m must increment velocities.new_memory.refusals_15m')
    const jamesRoster = dedupCheck.agents.roster.find(a => a.id === 'james')
    assert(jamesRoster, 'james should appear in agent roster')
    assert.equal(jamesRoster.refusals_15m, 1, 'daemon kind: refused activity within 15m must increment per-agent refusals_15m')
    assert.equal(jamesRoster.last_write_slug, 'canary-mobile-claim')
    assert(typeof mobileState.coherence.score === 'number')
    assert(typeof mobileState.synaptic_efficiency.score === 'number')
    assert.equal(mobileState.backup.last_receipt.snapshot_id, SNAP_ID.slice(0, 12))
    assert.equal(mobileState.backup.last_receipt.write_seq, 1)
    assert(typeof mobileState.backup.age_sec === 'number')
    assert(typeof mobileState.backup.unbacked_writes === 'number' && mobileState.backup.unbacked_writes >= 2)
    assert(Array.isArray(mobileState.agents.roster) && mobileState.agents.roster.length >= 1)
    assert(Array.isArray(mobileState.alerts))
    assert(typeof mobileState.dreams.counts.merkle_syntheses === 'number')

    const serializedMobile = JSON.stringify(mobileState)
    assert(!serializedMobile.includes(canaryClaim), 'buildMobileState must never include claim text')
    assert(!serializedMobile.includes(canaryBecause), 'buildMobileState must never include because text')
    assert(!serializedMobile.includes(canaryEvidence), 'buildMobileState must never include evidence strings')
    assert(!serializedMobile.includes('Shared global claim'), 'buildMobileState must never include any record claim text')

    const apiMobileRes = await httpGet(viewer.port, '/api/mobile')
    assert.equal(apiMobileRes.status, 200)
    assert(String(apiMobileRes.headers['content-type']).includes('application/json'))
    assert(!apiMobileRes.body.includes(canaryClaim), '/api/mobile must never leak claim text')
    assert(!apiMobileRes.body.includes(canaryBecause), '/api/mobile must never leak because text')
    const parsedApiMobile = JSON.parse(apiMobileRes.body)
    assert.equal(parsedApiMobile.metadata_only, true)
    assert.equal(parsedApiMobile.backup.last_receipt.snapshot_id, SNAP_ID.slice(0, 12))
    assert(parsedApiMobile.trends && typeof parsedApiMobile.trends === 'object', '/api/mobile must include trends object')
    assert.equal(parsedApiMobile.trends.window_24h.window, '24h')
    assert.equal(parsedApiMobile.trends.window_7d.window, '7d')
    assert.equal(parsedApiMobile.trends.daily_series.length, 7, 'daily_series must contain 7 calendar days')
    assert.equal(parsedApiMobile.trends.hourly_24h_series.length, 6, 'hourly_24h_series must contain 6 4h buckets')
    assert(typeof parsedApiMobile.trends.lifetime.coherence_score === 'number')
    assert(typeof parsedApiMobile.trends.lifetime.synaptic_efficiency_score === 'number')

    const htmlMobileRes = await httpGet(viewer.port, '/mobile')
    assert.equal(htmlMobileRes.status, 200)
    assert(String(htmlMobileRes.headers['content-type']).includes('text/html'))
    assert(htmlMobileRes.body.includes('Pocket Cortex'))
    assert(htmlMobileRes.body.includes('svg-date-trends'), '/mobile HTML must include date-plotted trend SVG')
    assert(htmlMobileRes.body.includes('Rolling 24h / 7d Trends'), '/mobile HTML must include rolling 24h/7d trends section')
    const mobileHtmlBytes = Buffer.byteLength(htmlMobileRes.body, 'utf8')
    assert(mobileHtmlBytes < 40000, `expected /mobile HTML < 40000 bytes uncompressed, got ${mobileHtmlBytes}`)
    assert(!htmlMobileRes.body.includes(canaryClaim), '/mobile HTML must never leak claim text')
    assert(!htmlMobileRes.body.includes(canaryBecause), '/mobile HTML must never leak because text')
    assert(!/<a\s/i.test(htmlMobileRes.body), '/mobile HTML must never render clickable <a> links')

    const mobileScripts = [...htmlMobileRes.body.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)]
    assert(mobileScripts.length >= 2, 'renderMobileViewerHtml must emit initial-mobile-state JSON and client JS <script> blocks')
    for (const [, attrs, code] of mobileScripts) {
      if (attrs.includes('application/json')) {
        assert.doesNotThrow(() => JSON.parse(code), 'initial-mobile-state JSON script must be valid JSON')
      } else {
        assert.doesNotThrow(() => new Function(code), 'mobile client <script> block must compile without SyntaxError')
      }
    }

    // Verify /events?mode=mobile SSE stream delivers metadata-only JSON
    const sseFrame = await new Promise((resolve, reject) => {
      const req = httpRequest({ host: '127.0.0.1', port: viewer.port, path: '/events?mode=mobile', method: 'GET' }, res => {
        res.setEncoding('utf8')
        let buf = ''
        res.on('data', chunk => {
          buf += chunk
          if (buf.includes('\n\n')) {
            req.destroy()
            resolve({ status: res.statusCode, headers: res.headers, body: buf })
          }
        })
      })
      req.on('error', err => {
        if (err.code !== 'ECONNRESET') reject(err)
      })
      req.end()
    })
    assert.equal(sseFrame.status, 200)
    assert(String(sseFrame.headers['content-type']).includes('text/event-stream'))
    assert(!sseFrame.body.includes(canaryClaim), '/events?mode=mobile must never leak claim text')
    const sseDataJson = sseFrame.body.replace(/^data:\s*/, '').trim()
    const sseData = JSON.parse(sseDataJson)
    assert.equal(sseData.metadata_only, true)
    assert.equal(sseData.view_mode, 'mobile_pocket_cortex')
  } finally {
    if (viewer) await viewer.stop()
    if (daemon) await daemon.close()
    rmSync(tmp, { recursive: true, force: true })
  }
})

await test('computeMemoryTrends: scores rolling 24h and 7d windows by date and quantifies daily signals', () => {
  const nowSec = 1794398400 // 2026-11-11T12:00:00Z
  const daySec = 86400

  // 200 older baseline claims from 14 days ago (simulating a large saturated lifetime corpus)
  const oldClaims = Array.from({ length: 200 }, (_, i) => ({
    id: `old-${i}`,
    d: `room:waggle:nvoy-baseline-${i}`,
    scope: 'room:waggle',
    topic: 'nvoy',
    author: i % 2 === 0 ? 'james' : 'mydude',
    created_at: nowSec - 14 * daySec + i * 10,
    claim: `Baseline claim ${i} on PR #100 and commit abcdef1234`,
    evidence: ['PR #100', 'abcdef1234'],
    as_of_git: 'abcdef1234',
    as_of_evt: i > 0 ? `old-${i - 1}` : null,
    supersedes: [],
    withdrawn: false,
    ttl_sec: 0,
  }))

  // Day -2 (2 days ago): 3 clean grounded claims by 2 authors (high coherence & efficiency)
  const dayMinus2Start = Math.floor((nowSec - 2 * daySec) / daySec) * daySec + 3600
  const dayMinus2Claims = [
    {
      id: 'd2-1',
      d: 'hive:canon:nvoy-rule',
      scope: 'hive:canon',
      topic: 'nvoy',
      author: 'james',
      created_at: dayMinus2Start,
      claim: 'Canon rule on PR #350 and mcp/tools/memory-viewer.mjs',
      evidence: ['PR #350', 'mcp/tools/memory-viewer.mjs'],
      as_of_git: '11223344',
      as_of_evt: null,
      supersedes: [],
      withdrawn: false,
      ttl_sec: 0,
    },
    {
      id: 'd2-2',
      d: 'room:waggle:nvoy-impl',
      scope: 'room:waggle',
      topic: 'nvoy',
      author: 'biggy',
      created_at: dayMinus2Start + 600,
      claim: 'Implemented PR #350 in mcp/tools/memory-viewer.mjs',
      evidence: ['PR #350', 'mcp/tools/memory-viewer.mjs'],
      as_of_git: '11223344',
      as_of_evt: 'd2-1',
      supersedes: [],
      withdrawn: false,
      ttl_sec: 0,
    },
    {
      id: 'd2-3',
      d: 'room:waggle:nvoy-review',
      scope: 'room:waggle',
      topic: 'nvoy',
      author: 'mydude',
      created_at: dayMinus2Start + 1200,
      claim: 'Reviewed PR #350 at 11223344',
      evidence: ['PR #350', '11223344'],
      as_of_git: '11223344',
      as_of_evt: 'd2-2',
      supersedes: [],
      withdrawn: false,
      ttl_sec: 0,
    },
  ]

  // Today (within last 24h):
  // - 2 conflicting claims on the same key by different authors (raises 1 conflict)
  // - 1 resolution claim superseding the conflict (resolves 1 conflict, counts as recall hit)
  // - 1 unanchored silo claim
  const todayStart = Math.floor(nowSec / daySec) * daySec + 3600
  const todayClaims = [
    {
      id: 'td-1',
      d: 'room:waggle:deploy-state',
      scope: 'room:waggle',
      topic: 'herd-infra',
      author: 'biggy',
      created_at: todayStart,
      claim: 'Service state is pending on PR #360',
      evidence: ['PR #360'],
      as_of_git: 'aabbccdd',
      as_of_evt: null,
      supersedes: [],
      withdrawn: false,
      ttl_sec: 86400,
    },
    {
      id: 'td-2',
      d: 'room:waggle:deploy-state',
      scope: 'room:waggle',
      topic: 'herd-infra',
      author: 'neil',
      created_at: todayStart + 300,
      claim: 'Service state is active on PR #360',
      evidence: ['PR #360'],
      as_of_git: 'eeff0011',
      as_of_evt: null,
      supersedes: [],
      withdrawn: false,
      ttl_sec: 86400,
    },
    {
      id: 'td-3',
      d: 'room:waggle:deploy-state',
      scope: 'room:waggle',
      topic: 'herd-infra',
      author: 'dead-rabbit',
      created_at: todayStart + 900,
      claim: 'Verified live deploy on PR #360 after superseding conflict',
      evidence: ['PR #360', 'mcp/tools/memory-viewer.mjs'],
      as_of_git: '99887766',
      as_of_evt: 'td-2',
      supersedes: ['td-1', 'td-2'],
      withdrawn: false,
      ttl_sec: 0,
    },
    {
      id: 'td-4',
      d: 'room:waggle:misc-unanchored',
      scope: 'room:waggle',
      topic: 'BadTopicName',
      author: 'dennis',
      created_at: todayStart + 1200,
      claim: 'Unanchored note without git or event ref',
      evidence: [],
      as_of_git: null,
      as_of_evt: null,
      supersedes: [],
      withdrawn: false,
      ttl_sec: 3600,
    },
  ]

  const allHistory = [...oldClaims, ...dayMinus2Claims, ...todayClaims]
  const activeRecords = [...oldClaims, ...dayMinus2Claims, todayClaims[2], todayClaims[3]]
  const lifetimeCoh = computeCoherence({ records: activeRecords, history_records: allHistory, now_sec: nowSec })
  const lifetimeEff = computeSynapticEfficacy({
    records: activeRecords,
    history_records: allHistory,
    agent_roster: [{ id: 'james' }, { id: 'biggy' }, { id: 'mydude' }, { id: 'neil' }, { id: 'dead-rabbit' }, { id: 'dennis' }],
    now_sec: nowSec,
  })

  const trends = computeMemoryTrends({
    records: activeRecords,
    history_records: allHistory,
    agent_roster: [{ id: 'james' }, { id: 'biggy' }, { id: 'mydude' }, { id: 'neil' }, { id: 'dead-rabbit' }, { id: 'dennis' }],
    recent_activity: [
      { kind: 'query', actor: 'biggy', hits: 3, at: todayStart + 100 },
      { kind: 'query', actor: 'dead-rabbit', hits: 2, at: todayStart + 800 },
    ],
    coherence: lifetimeCoh,
    efficacy: lifetimeEff,
    now_sec: nowSec,
  })

  assert.equal(trends.daily_series.length, 7, 'must produce 7 daily_series points plotted by date')
  assert.equal(trends.daily_series[6].date, '2026-11-11')
  assert.equal(trends.daily_series[6].label, '11-11')
  assert.equal(trends.daily_series[4].date, '2026-11-09')

  // Verify day-to-day signals on today (2026-11-11) and 24h rolling window
  assert.equal(trends.today_signals.new_claims, 4, 'today must record 4 new claims')
  assert.equal(trends.today_signals.conflicts_raised, 1, 'today must record 1 conflict raised (td-2 vs td-1)')
  assert.equal(trends.today_signals.conflicts_resolved, 1, 'today must record 1 conflict resolved (td-3 superseding td-1/td-2)')
  assert.equal(trends.today_signals.active_writers, 4, 'today must record 4 active writers (biggy, neil, dead-rabbit, dennis)')
  assert.equal(trends.today_signals.recall_hits, 2, 'today must count the 2 observed query recall hits')
  assert.equal(trends.today_signals.grounded_writes, 1, 'today must count 1 recall-grounded write (td-3)')

  // Verify 7d window aggregates across Day -2 + Today (3 + 4 = 7 claims)
  assert.equal(trends.window_7d.new_claims, 7, '7d window must exclude the 200 14-day-old claims and count only the 7 claims in 7d')
  assert.equal(trends.window_7d.claims_per_day, 1, '7 claims over 7 days = 1.0/day')
  assert.equal(trends.window_7d.conflicts_raised, 1)
  assert.equal(trends.window_7d.conflicts_resolved, 1)
  assert.equal(trends.window_7d.active_writers, 6, '6 unique writers across the 7d window')

  // Verify rolling scores differ between Day -2 (all clean/grounded/canon) and Today (mixed with conflict & unanchored claim)
  const dayMinus2Pt = trends.daily_series[4]
  const todayPt = trends.daily_series[6]
  assert(
    dayMinus2Pt.coherence_score > todayPt.coherence_score,
    `expected clean Day -2 coherence (${dayMinus2Pt.coherence_score}) > conflicted/unanchored Today coherence (${todayPt.coherence_score})`
  )
  assert.notEqual(
    trends.window_24h.coherence_score,
    trends.lifetime.coherence_score,
    '24h rolling coherence must reflect 24h claims rather than sitting locked to the 200-claim lifetime score'
  )
  assert.equal(trends.lifetime.coherence_score, lifetimeCoh.score, 'lifetime score must be preserved as a number')
  assert.equal(trends.lifetime.synaptic_efficiency_score, lifetimeEff.score, 'lifetime synaptic efficiency score must be preserved')
})

await test('durable SQLite activity_rollups survive >80 ring overflow & daemon restart, mark incomplete buckets, and enforce event-time conflict dates', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'hive-memory-trends-rollups-'))
  try {
    const dbPath = join(dir, 'memory.sqlite')
    const ledgerPath = join(dir, 'accepted-ledger.jsonl')
    const receiptPath = join(dir, 'last-verified-backup.json')
    const sockDir = join(dir, 'sockets')

    const ownerSk = generateSecretKey()
    const ownerPk = getPublicKey(ownerSk)
    const biggySk = generateSecretKey()
    const biggyPk = getPublicKey(biggySk)
    const neilSk = generateSecretKey()
    const neilPk = getPublicKey(neilSk)
    const globalRoom = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
    const nowSec = 1794398400 // 2026-11-11T12:00:00Z
    const daySec = 86400
    const dayMinus2At = Math.floor((nowSec - 2 * daySec) / daySec) * daySec + 3600
    const todayAt = Math.floor(nowSec / daySec) * daySec + 3600

    const config = {
      memoryGlobalChannelId: globalRoom,
      ownerPubkey: ownerPk,
      maxUnbackedSec: 86400 * 30,
      globalWriters: [ownerPk, biggyPk, neilPk],
      canonWriters: [ownerPk],
      readers: {
        viewer: ownerPk,
        biggy: biggyPk,
        neil: neilPk,
      },
      writers: {
        james: { pubkey: ownerPk, perHour: 200, allowSelf: true },
        biggy: { pubkey: biggyPk, perHour: 200, allowSelf: true },
        neil: { pubkey: neilPk, perHour: 200, allowSelf: true },
      },
      rooms: {
        [globalRoom]: {
          members: [ownerPk, biggyPk, neilPk],
          writers: [ownerPk, biggyPk, neilPk],
        },
      },
    }

    initEmptyStore({ dbPath, ledgerPath, nowSec: nowSec - 7 * daySec })
    recordVerifiedBackup({ receiptPath, writeSeq: 1, snapshotId: SNAP_ID, at: dayMinus2At - 60, nowSec })

    let clockSec = dayMinus2At
    let daemon = await startMemoryDaemon({
      dbPath,
      ledgerPath,
      receiptPath,
      config,
      readers: ['viewer', 'biggy', 'neil'],
      writers: ['james', 'biggy', 'neil'],
      socketDir: sockDir,
      now: () => clockSec,
      log: () => {},
    })

    // 1. On Day -2: biggy and neil write conflicting claims on the same fact key
    const evDay2A = finalizeEvent(
      buildClaimTemplate({
        pubkey: biggyPk,
        scope: `room:${globalRoom}`,
        slug: 'gateway-route',
        topic: 'herd-infra',
        claim: 'Gateway route points to upstream A on PR #401',
        because: 'Day -2 initial route',
        evidence: ['PR #401', 'mcp/tools/memory-daemon.mjs'],
        asOfGit: '1111aaaa',
        ttlSec: 0,
        nowSec: dayMinus2At,
        memoryGlobalChannelId: globalRoom,
      }),
      biggySk
    )
    const subA = daemon.store.submit({ writer: 'biggy', event: evDay2A, expectedPriorId: null, nowSec: dayMinus2At })
    assert.equal(subA.accepted, true)

    const evDay2B = finalizeEvent(
      buildClaimTemplate({
        pubkey: neilPk,
        scope: `room:${globalRoom}`,
        slug: 'gateway-route',
        topic: 'herd-infra',
        claim: 'Gateway route points to upstream B on PR #401',
        because: 'Day -2 diverging route',
        evidence: ['PR #401', 'mcp/tools/memory-daemon.mjs'],
        asOfGit: '2222bbbb',
        ttlSec: 0,
        nowSec: dayMinus2At + 120,
        memoryGlobalChannelId: globalRoom,
      }),
      neilSk
    )
    const subB = daemon.store.submit({ writer: 'neil', event: evDay2B, expectedPriorId: null, nowSec: dayMinus2At + 120 })
    assert.equal(subB.accepted, true)
    recordVerifiedBackup({ receiptPath, writeSeq: 3, snapshotId: SNAP_ID, at: todayAt - 60, nowSec })

    // 2. On Today: james resolves the Day -2 conflict by superseding both evDay2A and evDay2B
    const evTodayResolve = finalizeEvent(
      buildClaimTemplate({
        pubkey: ownerPk,
        scope: `room:${globalRoom}`,
        slug: 'gateway-route',
        topic: 'herd-infra',
        claim: 'Gateway route unified on upstream B on PR #401',
        because: 'Resolved Day -2 divergence',
        evidence: ['PR #401', 'mcp/tools/memory-daemon.mjs'],
        asOfGit: '3333cccc',
        asOfEvt: evDay2B.id,
        supersedes: [evDay2A.id, evDay2B.id],
        ttlSec: 0,
        nowSec: todayAt,
        memoryGlobalChannelId: globalRoom,
      }),
      ownerSk
    )
    const subRes = daemon.store.submit({ writer: 'james', event: evTodayResolve, expectedPriorId: null, nowSec: todayAt })
    assert.equal(subRes.accepted, true)
    recordVerifiedBackup({ receiptPath, writeSeq: 4, snapshotId: SNAP_ID, at: todayAt, nowSec })

    // 3. Push 95 recall calls (> ACTIVITY_MAX = 80) across Day -2 (15 queries) and Today (80 queries)
    const activityRing = { seq: 0, started_at: dayMinus2At, events: [] }
    for (let i = 0; i < 15; i++) {
      handleSocketJsonRpc({
        store: daemon.store,
        binding: { kind: 'reader', name: 'biggy' },
        nowSec: dayMinus2At + 300 + i * 10,
        activity: activityRing,
        message: {
          jsonrpc: '2.0',
          id: i + 1,
          method: 'tools/call',
          params: { name: 'memory_query', arguments: { topic: 'herd-infra' } },
        },
      })
    }
    for (let i = 0; i < 80; i++) {
      handleSocketJsonRpc({
        store: daemon.store,
        binding: { kind: 'reader', name: i % 2 === 0 ? 'biggy' : 'neil' },
        nowSec: todayAt + 100 + i * 10,
        activity: activityRing,
        message: {
          jsonrpc: '2.0',
          id: 100 + i,
          method: 'tools/call',
          params: { name: 'memory_query', arguments: { topic: 'herd-infra' } },
        },
      })
    }
    assert.equal(activityRing.seq, 95, '95 total recall events were emitted')
    assert.equal(activityRing.events.length, ACTIVITY_MAX, 'in-memory activity ring is capped at ACTIVITY_MAX (80)')

    // Check viewer wake before restart (ring has overflowed at 80, losing the 15 Day -2 events from RAM)
    const wakeBeforeRestartRes = handleSocketJsonRpc({
      store: daemon.store,
      binding: { kind: 'reader', name: 'viewer' },
      nowSec,
      activity: activityRing,
      message: {
        jsonrpc: '2.0',
        id: 999,
        method: 'tools/call',
        params: { name: 'memory_wake', arguments: {} },
      },
    })
    const wakeBeforeRestart = JSON.parse(wakeBeforeRestartRes.result.content[0].text)
    assert.equal(wakeBeforeRestart.activity_ring.overflowed, true, 'activity_ring must report overflowed: true after >80 events')
    assert.equal(wakeBeforeRestart.activity_rollups.total_hits, 95, 'SQLite activity_rollups must retain all 95 recall hits despite 80-event ring cap')

    // 4. Restart the daemon on the same SQLite DB (in-memory activity ring is wiped to 0 events)
    await daemon.close()
    clockSec = nowSec
    daemon = await startMemoryDaemon({
      dbPath,
      ledgerPath,
      receiptPath,
      config,
      readers: ['viewer', 'biggy', 'neil'],
      writers: ['james', 'biggy', 'neil'],
      socketDir: sockDir,
      now: () => clockSec,
      log: () => {},
    })

    const viewer = await startMemoryViewer({
      socketPath: join(sockDir, 'viewer.sock'),
      host: '127.0.0.1',
      port: 0,
      pollMs: 60000,
    })
    try {
      const mobileState = viewer.getMobileState()
      const tr = mobileState.trends
      assert.equal(mobileState.recent_activity?.length || 0, 0, 'fresh daemon has 0 in-memory recent_activity events')
      assert.equal(tr.recall_telemetry.source, 'sqlite_rollups')
      assert.equal(tr.window_24h.recall_hits, 80, '24h recall_hits must preserve all 80 Today query hits across daemon restart')
      assert.equal(tr.window_7d.recall_hits, 95, '7d recall_hits must preserve all 95 (15 Day -2 + 80 Today) query hits across ring overflow and daemon restart')
      assert.equal(tr.window_24h.recall_coverage, 'complete', '24h window is complete because first rollup was on Day -2')
      assert.equal(tr.window_24h.recall_incomplete, false)
      assert.equal(tr.window_7d.recall_coverage, 'partial', '7d window must be partial because first observed rollup was on Day -2, not 7 days ago (store_initialized_at is ignored)')
      assert.equal(tr.window_7d.recall_incomplete, true)

      // Event-time conflict reproducibility:
      // Even though the conflict on `room:...:gateway-route` is now resolved (so current-head conflict is false),
      // Day -2 must still report conflicts_raised = 1, and Today must report conflicts_resolved = 1.
      const dayMinus2Bucket = tr.daily_series[4]
      const todayBucket = tr.daily_series[6]
      assert.equal(dayMinus2Bucket.conflicts_raised, 1, 'Day -2 must reproducibly record conflicts_raised = 1 at event time')
      assert.equal(dayMinus2Bucket.conflicts_resolved, 0, 'Day -2 must record conflicts_resolved = 0')
      assert.equal(dayMinus2Bucket.recall_hits, 15, 'Day -2 must preserve its 15 recall hits even after 80-event ring overflow and restart')
      assert.equal(todayBucket.conflicts_raised, 0, 'Today must record conflicts_raised = 0')
      assert.equal(todayBucket.conflicts_resolved, 1, 'Today must reproducibly record conflicts_resolved = 1 at event time')
      assert.equal(todayBucket.recall_hits, 80, 'Today must record 80 recall hits')

      // 5. Verify explicit incomplete-bucket marking when telemetry coverage starts mid-window (e.g. ring overflow without SQLite rollups)
      const partialTrends = computeMemoryTrends({
        records: viewer.getState().records,
        history_records: [evDay2A, evDay2B, evTodayResolve],
        recent_activity: [{ kind: 'query', actor: 'biggy', count: 2, at: todayAt + 500 }],
        activity_ring: { seq: 120, cap: 80, retained: 1, overflowed: true, started_at: dayMinus2At, oldest_at: todayAt + 500 },
        activity_rollups: null,
        now_sec: nowSec,
      })
      assert.equal(partialTrends.window_7d.recall_coverage, 'partial', '7d window must be marked partial when ring overflowed and no rollups cover earlier days')
      assert.equal(partialTrends.window_7d.recall_incomplete, true, '7d window must set recall_incomplete: true')
      assert.equal(partialTrends.daily_series[4].recall_coverage, 'unobserved', 'Day -2 bucket prior to oldest retained ring event must be marked unobserved')
      assert.equal(partialTrends.daily_series[4].recall_incomplete, true, 'Day -2 bucket must set recall_incomplete: true')
      assert.equal(partialTrends.daily_series[6].recall_incomplete, true, 'Today bucket starting before oldest_at (todayAt + 500) must also be marked partial/incomplete')

      // 6. Regression: Old store migrated with 0 activity_rollups must NEVER claim recall_coverage = complete from store_initialized_at
      const oldStoreDir = mkdtempSync(join(tmpdir(), 'hive-memory-old-store-mig-'))
      try {
        const oldDbPath = join(oldStoreDir, 'old.sqlite')
        const oldLedgerPath = join(oldStoreDir, 'old-ledger.jsonl')
        const oldReceiptPath = join(oldStoreDir, 'old-receipt.json')
        const oldInitAt = nowSec - 14 * daySec
        initEmptyStore({ dbPath: oldDbPath, ledgerPath: oldLedgerPath, nowSec: oldInitAt })
        recordVerifiedBackup({ receiptPath: oldReceiptPath, writeSeq: 1, snapshotId: SNAP_ID, at: oldInitAt, nowSec })
        const oldStore = new HiveMemoryStore({
          dbPath: oldDbPath,
          ledgerPath: oldLedgerPath,
          receiptPath: oldReceiptPath,
          config: validateAndResolveConfig(config),
          lock: false,
        })
        oldStore.start()
        try {
          const emptyRollups = oldStore.activityRollups({ sinceSec: 0, nowSec })
          assert.equal(emptyRollups.rollups.length, 0)
          assert.equal(emptyRollups.store_initialized_at, oldInitAt)
          assert.equal(emptyRollups.coverage_start_at, null)

          const oldStoreTrends = computeMemoryTrends({
            records: [evDay2A],
            history_records: [evDay2A],
            recent_activity: [],
            activity_rollups: emptyRollups,
            now_sec: nowSec,
          })
          assert.equal(
            oldStoreTrends.window_24h.recall_coverage,
            'unobserved',
            'old store with 0 activity_rollups must return window_24h.recall_coverage = unobserved, never complete'
          )
          assert.equal(oldStoreTrends.window_24h.recall_incomplete, true)
          assert.equal(oldStoreTrends.window_7d.recall_coverage, 'unobserved')
          assert.equal(oldStoreTrends.window_7d.recall_incomplete, true)

          // Even after 1 rollup is recorded 10 minutes ago on the migrated store, 24h coverage is partial (not complete)
          oldStore.recordActivityRollup({ at: nowSec - 600, actor: 'biggy', kind: 'query', count: 2 })
          const postMigRollups = oldStore.activityRollups({ sinceSec: 0, nowSec })
          const postMigTrends = computeMemoryTrends({
            records: [evDay2A],
            history_records: [evDay2A],
            recent_activity: [],
            activity_rollups: postMigRollups,
            now_sec: nowSec,
          })
          assert.equal(postMigTrends.window_24h.recall_coverage, 'partial', '1st rollup 10m ago on old store must mark 24h coverage partial')
          assert.equal(postMigTrends.window_24h.recall_incomplete, true)
          assert.equal(postMigTrends.window_24h.recall_hits, 1)

          // 7. Regression: Window cutting through an hour (partial edge bucket straddling 24h start)
          const midHourNow = 1794400200 // 2026-11-11T12:30:00Z (cuts through 12:00..12:59Z)
          const start24h = midHourNow - 86400 // 2026-11-10T12:30:00Z
          const edgeBucket = Math.floor(start24h / 3600) * 3600 // 2026-11-10T12:00:00Z
          // Record 5 query hits in the straddling hour: 2 before start24h (out-of-window) and 3 after start24h (in-window)
          oldStore.recordActivityRollup({ at: start24h - 1200, actor: 'biggy', kind: 'query', count: 1 })
          oldStore.recordActivityRollup({ at: start24h - 600, actor: 'biggy', kind: 'query', count: 1 })
          oldStore.recordActivityRollup({ at: start24h + 300, actor: 'biggy', kind: 'query', count: 1 })
          oldStore.recordActivityRollup({ at: start24h + 600, actor: 'biggy', kind: 'query', count: 1 })
          oldStore.recordActivityRollup({ at: start24h + 900, actor: 'biggy', kind: 'query', count: 1 })

          const straddleRollups = oldStore.activityRollups({ sinceSec: 0, nowSec: midHourNow })
          const edgeRow = straddleRollups.rollups.find(r => r.hour_bucket === edgeBucket && r.actor === 'biggy' && r.kind === 'query')
          assert.equal(edgeRow.hits, 5, 'hourly bucket itself holds all 5 hits across the full hour')

          const straddleTrends = computeMemoryTrends({
            records: [evDay2A],
            history_records: [evDay2A],
            recent_activity: [],
            activity_rollups: {
              ...straddleRollups,
              rollups: [edgeRow],
            },
            now_sec: midHourNow,
          })
          assert.equal(
            straddleTrends.window_24h.recall_hits,
            3,
            'window cutting through an hour must count only the 3 in-window query hits, never all 5'
          )
          assert.equal(
            straddleTrends.window_24h.recall_coverage,
            'partial',
            'window cutting through a straddling hourly bucket must mark recall_coverage = partial, never complete'
          )
          assert.equal(straddleTrends.window_24h.recall_incomplete, true)
          assert.equal(straddleTrends.window_24h.partial_edge_bucket, true)
          assert(
            straddleTrends.window_24h.observed_coverage_pct < 100,
            `partial edge bucket must report observed_coverage_pct < 100 (got ${straddleTrends.window_24h.observed_coverage_pct})`
          )

          // Coarse hourly rollup row (without per-event samples) straddling 24h start (12:30Z):
          // With 5 hits, first at 12:10Z (start24h - 1200) and last at 12:45Z (start24h + 900),
          // the same coarse row permits different true in-window counts:
          // - History A: 4 hits before 12:30Z (12:10, 12:15, 12:20, 12:25) and 1 hit after 12:30Z (12:45) -> true in-window = 1
          // - History B: 1 hit before 12:30Z (12:10) and 4 hits after 12:30Z (12:35, 12:40, 12:42, 12:45) -> true in-window = 4
          // Sampled rows distinguish History A (1) vs History B (4), while the unsampled coarse row must report
          // only the provable lower bound (1), expose the exact range [1, 4] and unknown_recall_hits = 3, and observed_coverage_pct < 100.
          const historyASamples = [
            [edgeBucket + 600, 1, 1],
            [edgeBucket + 900, 1, 1],
            [edgeBucket + 1200, 1, 1],
            [edgeBucket + 1500, 1, 1],
            [edgeBucket + 2700, 1, 1],
          ]
          const historyBSamples = [
            [edgeBucket + 600, 1, 1],
            [edgeBucket + 2100, 1, 1],
            [edgeBucket + 2400, 1, 1],
            [edgeBucket + 2520, 1, 1],
            [edgeBucket + 2700, 1, 1],
          ]
          const sharedCoarseRow = {
            hour_bucket: edgeBucket,
            actor: 'biggy',
            kind: 'query',
            calls: 5,
            hits: 5,
            records_returned: 5,
            first_at: edgeBucket + 600, // 12:10Z
            last_at: edgeBucket + 2700, // 12:45Z
          }
          const trendsHistoryA = computeMemoryTrends({
            records: [evDay2A],
            history_records: [evDay2A],
            recent_activity: [],
            activity_rollups: {
              coverage_start_at: edgeBucket + 600,
              rollups: [{ ...sharedCoarseRow, samples: historyASamples }],
            },
            now_sec: midHourNow,
          })
          const trendsHistoryB = computeMemoryTrends({
            records: [evDay2A],
            history_records: [evDay2A],
            recent_activity: [],
            activity_rollups: {
              coverage_start_at: edgeBucket + 600,
              rollups: [{ ...sharedCoarseRow, samples: historyBSamples }],
            },
            now_sec: midHourNow,
          })
          assert.equal(trendsHistoryA.window_24h.recall_hits, 1, 'History A true in-window count is 1')
          assert.equal(trendsHistoryB.window_24h.recall_hits, 4, 'History B true in-window count is 4')

          const coarseStraddleTrends = computeMemoryTrends({
            records: [evDay2A],
            history_records: [evDay2A],
            recent_activity: [],
            activity_rollups: {
              coverage_start_at: edgeBucket + 600,
              rollups: [sharedCoarseRow],
            },
            now_sec: midHourNow,
          })
          assert.equal(
            coarseStraddleTrends.window_24h.recall_hits,
            1,
            'unsampled coarse row must report only the provable lower bound (1), never over-estimating 2 when History A has only 1'
          )
          assert.equal(coarseStraddleTrends.window_24h.recall_hits_min, trendsHistoryA.window_24h.recall_hits)
          assert.equal(coarseStraddleTrends.window_24h.recall_hits_max, trendsHistoryB.window_24h.recall_hits)
          assert.deepEqual(coarseStraddleTrends.window_24h.recall_hits_range, [1, 4])
          assert.equal(coarseStraddleTrends.window_24h.unknown_recall_hits, 3)
          assert.equal(coarseStraddleTrends.window_24h.recall_coverage, 'partial')
          assert.equal(coarseStraddleTrends.window_24h.recall_incomplete, true)
          assert.equal(coarseStraddleTrends.window_24h.partial_edge_bucket, true)
          assert(
            coarseStraddleTrends.window_24h.observed_coverage_pct < 100,
            `coarse straddling bucket must report observed_coverage_pct < 100 (got ${coarseStraddleTrends.window_24h.observed_coverage_pct})`
          )

          // 8. Regression: Rollup write failures must be durably persisted and keep the window incomplete across store/daemon restart
          // Record an earlier rollup 2 days ago so the 24h window would otherwise be 'complete'
          oldStore.recordActivityRollup({ at: midHourNow - 2 * daySec, actor: 'biggy', kind: 'query', count: 2 })
          oldStore.hooks = {
            beforeRollupWrite: () => {
              throw new Error('SIMULATED_SQLITE_ROLLUP_FAILURE')
            },
          }
          const okWrite = oldStore.recordActivityRollup({ at: midHourNow - 60, actor: 'neil', kind: 'query', count: 3 })
          assert.equal(okWrite, false, 'simulated rollup write failure must return false')
          const failedRollups = oldStore.activityRollups({ sinceSec: 0, nowSec: midHourNow })
          assert.equal(failedRollups.write_failures, 1, 'activityRollups must report write_failures = 1')
          assert.equal(failedRollups.failure_gaps.length, 1, 'activityRollups must persist a coverage gap row')

          // Close the store and open a brand-new HiveMemoryStore instance on the same SQLite DB (simulating daemon restart)
          oldStore.close()
          const restartedStore = new HiveMemoryStore({
            dbPath: oldDbPath,
            ledgerPath: oldLedgerPath,
            receiptPath: oldReceiptPath,
            config: validateAndResolveConfig(config),
            lock: false,
          })
          restartedStore.start()
          try {
            const postRestartRollups = restartedStore.activityRollups({ sinceSec: 0, nowSec: midHourNow })
            assert.equal(postRestartRollups.write_failures, 1, 'write_failures must survive store/daemon restart')
            assert.equal(postRestartRollups.first_failure_at, midHourNow - 60, 'first_failure_at must survive store/daemon restart')
            assert.equal(postRestartRollups.failure_gaps.length, 1, 'failure_gaps must survive store/daemon restart')

            const failureTrends = computeMemoryTrends({
              records: [evDay2A],
              history_records: [evDay2A],
              recent_activity: [],
              activity_rollups: postRestartRollups,
              now_sec: midHourNow,
            })
            assert.equal(
              failureTrends.window_24h.recall_incomplete,
              true,
              'rollup write failure must keep window_24h.recall_incomplete = true after daemon restart'
            )
            assert.equal(
              failureTrends.window_24h.recall_coverage,
              'partial',
              'rollup write failure must keep window_24h.recall_coverage = partial (never complete) after daemon restart'
            )
            assert(
              failureTrends.window_24h.observed_coverage_pct < 100,
              `window with persisted rollup failure gap must report observed_coverage_pct < 100 (got ${failureTrends.window_24h.observed_coverage_pct})`
            )
            assert.equal(failureTrends.window_24h.rollup_write_failures, 1)
            assert.equal(failureTrends.recall_telemetry.write_failures, 1)
          } finally {
            restartedStore.close()
          }
        } finally {
          oldStore.close()
        }
      } finally {
        rmSync(oldStoreDir, { recursive: true, force: true })
      }
    } finally {
      await viewer.stop()
      await daemon.close()
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

console.log(`\nResults: ${passed} passed, ${failed} failed`)
process.exit(failed > 0 ? 1 : 0)
