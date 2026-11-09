// test/memory-viewer.mjs — Unit and integration tests for mcp/tools/memory-viewer.mjs.

import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { buildClaimTemplate } from '../mcp/tools/memory.mjs'
import { ACTIVITY_MAX, handleSocketJsonRpc, startMemoryDaemon } from '../mcp/tools/memory-daemon.mjs'
import { initEmptyStore, recordVerifiedBackup } from '../mcp/tools/hive_memory_store.mjs'
import {
  computeAgentHealth,
  computeCoherence,
  computeDreamingTelemetry,
  computeSynapticEfficacy,
  diffViewerSnapshots,
  readWatchStatus,
  watchAlert,
  watchView,
  WATCH_STALE_SEC,
  escapeHtml,
  parseListenTarget,
  parseViewerFlags,
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

    const htmlRes = await httpGet(viewer.port, '/')
    assert.equal(htmlRes.status, 200)
    assert(htmlRes.body.includes('Topic Page · Above / Below the Line'))
    assert(htmlRes.body.includes('Constellation Entity-Link Mesh'))
  } finally {
    if (viewer) await viewer.stop()
    await daemon.close()
    rmSync(tmp, { recursive: true, force: true })
  }
})

console.log(`\nResults: ${passed} passed, ${failed} failed`)
process.exit(failed > 0 ? 1 : 0)
