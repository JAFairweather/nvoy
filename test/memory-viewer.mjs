// test/memory-viewer.mjs — Unit and integration tests for mcp/tools/memory-viewer.mjs.

import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { buildClaimTemplate } from '../mcp/tools/memory.mjs'
import { ACTIVITY_MAX, handleSocketJsonRpc, startMemoryDaemon } from '../mcp/tools/memory-daemon.mjs'
import { initEmptyStore, recordVerifiedBackup } from '../mcp/tools/hive_memory_store.mjs'
import {
  diffViewerSnapshots,
  escapeHtml,
  parseListenTarget,
  parseViewerFlags,
  renderViewerHtml,
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
    assert(htmlRes.body.includes('READY'))
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
    assert.equal(state1.query_answer, 'none')
    assert(!('global_sync' in state1) && !('relays_answered' in state1) && !('grants_checked_at' in state1))
    assert.equal(state1.records.length, 0)
    assert.deepEqual(state1.recent_activity, [])
    assert.deepEqual(state1.agent_roster.map(a => [a.id, a.is_owner]), [['owner', true]])

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

    sseReq.destroy()

    // A store that stops being ready answers unknown, never none, and the viewer shows it.
    daemon.store.setConfig(null, new Error('fixture: config withdrawn'))
    const notReady = await viewer.pollOnce()
    assert.equal(notReady.query_answer, 'unknown')
    assert.equal(notReady.records.length, 0)
    assert.notEqual(notReady.store_state.state, 'READY')
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

    // Another reader's wake is byte-for-byte what it was without the ring.
    const plain = call(biggy, 'memory_wake', {}, null)
    const ringed = call(biggy, 'memory_wake', {})
    assert.equal(JSON.stringify(ringed), JSON.stringify(plain))
    assert(!('recent_activity' in payload(ringed)) && !('agent_roster' in payload(ringed)))
    call(biggy, 'memory_query', { topic: 'governance', text: 'SECRET-CLAIM-TEXT' })
    call(biggy, 'memory_submit', { event: canon, expected_prior_id: null })

    const seqBefore = activity.seq
    const wake = payload(call(viewer, 'memory_wake', {}))
    assert.equal(activity.seq, seqBefore, 'the viewer records none of its own calls')
    assert.equal(wake.authority, null)
    const seen = wake.recent_activity
    assert.deepEqual(seen.map(a => a.kind), ['submit', 'submit', 'wake', 'query', 'refused'])
    for (const a of seen) {
      assert.deepEqual(Object.keys(a), ['seq', 'at', 'kind', 'actor', 'count', 'accepted', 'code', 'event_ids', 'd', 'topic', 'scope'])
    }
    assert(!/SECRET/.test(JSON.stringify(seen)), 'no claim, because, evidence or query text in the ring')
    assert.deepEqual([seen[0].actor, seen[0].d, seen[0].event_ids], ['owner', 'hive-memory:hive:canon:review-policy', [canon.id]])
    assert.deepEqual([seen[1].actor, seen[1].d, seen[1].scope, seen[1].event_ids], ['neil', null, null, []], 'room key stays outside the keyless viewer ACL')
    assert.deepEqual([seen[3].topic, seen[3].count], ['governance', 1])
    assert.deepEqual([seen[4].accepted, seen[4].code], [false, 'HIVE_MEMORY_READ_ONLY_SOCKET'])

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
  } finally {
    await daemon.close()
    rmSync(tmp, { recursive: true, force: true })
  }
})

console.log(`\nResults: ${passed} passed, ${failed} failed`)
process.exit(failed > 0 ? 1 : 0)
