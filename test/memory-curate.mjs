// test/memory-curate.mjs — Unit and live-socket integration tests for Phase 2 Merkle Dreaming,
// Curation (Distillation -> Promotion -> Solidification), and Nightmare handling.

import assert from 'node:assert/strict'
import { execFile as execFileCb, spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'

const execFileAsync = promisify(execFileCb)
import {
  buildClaimTemplate,
  buildWithdrawalTemplate,
  computeSourceMerkleRoot,
  validateMemoryEvent,
} from '../mcp/tools/memory.mjs'
import {
  HiveMemoryStore,
  RETENTION_PURGE_AFTER_SEC,
  computeStoreMerkleRoot,
  initEmptyStore,
  recordVerifiedBackup,
  validateAndResolveConfig,
} from '../mcp/tools/hive_memory_store.mjs'
import { startMemoryDaemon } from '../mcp/tools/memory-daemon.mjs'
import {
  buildDreamPacket,
  computeEigenAxisProposals,
  computeTopicEigenvectors,
  evaluateDreamTriggers,
  planMerkleDream,
  readConsolidationLedger,
  readCuratorStateFile,
  runCuratorCycle,
  weaveDreamStory,
  writeDreamPacket,
} from '../mcp/tools/memory-curate.mjs'
import {
  computeSafetyGates,
  evaluateDreamCycleOnStore,
  loadFrozenQuestions,
  projectHistoryRecords,
} from '../mcp/tools/memory-dream-eval.mjs'
import { formatDreamBuzzPost, handleDreamVerifyMcpMessage, parseDreamVerifyFlags, verifyAndAssembleDreamRecord } from '../mcp/tools/memory-dream-verify.mjs'

const SNAP_ID = 'd'.repeat(64)
const GLOBAL_CH = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const ROOM_ID = 'a8186b53-537d-46ad-a7e7-b6486c58970e'

let passed = 0
let failed = 0

async function test(name, fn) {
  try {
    await fn()
    console.log(`  ok — ${name}`)
    passed++
  } catch (err) {
    console.error(`  FAIL — ${name}:`, err)
    failed++
  }
}

console.log('=== Hive Shared Memory Merkle Dreaming & Curator Tests ===')

await test('computeSourceMerkleRoot and validateMemoryEvent enforce cryptographic merkle_sources', () => {
  const idA = 'a'.repeat(64)
  const idB = 'b'.repeat(64)
  const rootAB = computeSourceMerkleRoot([idB, idA, idA])
  const rootBA = computeSourceMerkleRoot([idA, idB])
  assert.equal(rootAB, rootBA, 'Merkle root must be order-independent and deduplicated')
  assert.equal(rootAB.length, 64)

  const sk = generateSecretKey()
  const pk = getPublicKey(sk)
  const tpl = buildClaimTemplate({
    pubkey: pk,
    scope: `room:${ROOM_ID}`,
    slug: 'curated-nvoy-pr336',
    topic: 'nvoy',
    claim: 'Distilled PR 336 state',
    because: 'Merkle Dreaming curation',
    evidence: ['nvoy@0d14097'],
    asOfGit: 'nvoy@0d14097',
    supersedes: [idB, idA],
    merkleSources: true,
    nowSec: 2000,
  })
  const signed = finalizeEvent(tpl, sk)
  const v = validateMemoryEvent(signed)
  assert.equal(v.ok, true)
  assert.equal(v.merkleSources, rootAB)

  // Tamper with merkle_sources
  const badTpl = {
    ...tpl,
    tags: tpl.tags.map(t => (t[0] === 'merkle_sources' ? ['merkle_sources', 'f'.repeat(64)] : t)),
  }
  const badSigned = finalizeEvent(badTpl, sk)
  const badV = validateMemoryEvent(badSigned)
  assert.equal(badV.ok, false)
  assert(badV.reason.includes('merkle_sources does not match supersedes'))
})

await test('HiveMemoryStore: Curator cross-author supersession, merkle_sources gates, 90d source hold, and store_merkle_root', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-curate-store-'))
  try {
    const dbPath = join(tmp, 'memory.sqlite')
    const ledgerPath = join(tmp, 'ledger.jsonl')
    const receiptPath = join(tmp, 'receipt.json')

    const ownerSk = generateSecretKey(), ownerPk = getPublicKey(ownerSk)
    const aliceSk = generateSecretKey(), alicePk = getPublicKey(aliceSk)
    const bobSk = generateSecretKey(), bobPk = getPublicKey(bobSk)
    const curatorSk = generateSecretKey(), curatorPk = getPublicKey(curatorSk)

    const nowSec = 1_800_000_000
    initEmptyStore({ dbPath, ledgerPath, nowSec })
    recordVerifiedBackup({ receiptPath, writeSeq: 1, snapshotId: SNAP_ID, at: nowSec, nowSec })

    const config = validateAndResolveConfig({
      memoryGlobalChannelId: GLOBAL_CH,
      ownerPubkey: ownerPk,
      maxUnbackedSec: 3600,
      globalWriters: [ownerPk, curatorPk],
      curators: [curatorPk],
      readers: { viewer: ownerPk },
      writers: {
        owner: { pubkey: ownerPk, perHour: 100 },
        alice: { pubkey: alicePk, perHour: 50 },
        bob: { pubkey: bobPk, perHour: 50 },
        curator: { pubkey: curatorPk, perHour: 120 },
      },
      rooms: {
        [ROOM_ID]: {
          members: [ownerPk, alicePk, bobPk, curatorPk],
          writers: [ownerPk, alicePk, bobPk, curatorPk],
        },
      },
    })

    const store = new HiveMemoryStore({ dbPath, ledgerPath, receiptPath, config })
    assert.equal(store.start().ready, true)
    const root0 = store.storeMerkleRoot()
    assert.equal(typeof root0, 'string')
    assert.equal(root0.length, 64)

    // Alice and Bob write two non-workflow Class A claims in room
    const aliceEv = finalizeEvent(buildClaimTemplate({
      pubkey: alicePk,
      scope: `room:${ROOM_ID}`,
      slug: 'nvoy-feature-part1',
      topic: 'nvoy',
      claim: 'Alice built part 1 of feature',
      because: 'Sprint work',
      evidence: ['nvoy@1111111'],
      asOfGit: 'nvoy@1111111',
      ttlSec: 3600,
      nowSec: nowSec + 10,
    }), aliceSk)
    assert.equal(store.submit({ writer: 'alice', event: aliceEv, nowSec: nowSec + 10 }).accepted, true)

    const bobEv = finalizeEvent(buildClaimTemplate({
      pubkey: bobPk,
      scope: `room:${ROOM_ID}`,
      slug: 'nvoy-feature-part2',
      topic: 'nvoy',
      claim: 'Bob built part 2 of feature',
      because: 'Sprint work',
      evidence: ['nvoy@2222222'],
      asOfGit: 'nvoy@2222222',
      ttlSec: 3600,
      nowSec: nowSec + 20,
    }), bobSk)
    assert.equal(store.submit({ writer: 'bob', event: bobEv, nowSec: nowSec + 20 }).accepted, true)

    // 1. Curator without merkle_sources is refused
    const noMerkleCuratorEv = finalizeEvent(buildClaimTemplate({
      pubkey: curatorPk,
      scope: `room:${ROOM_ID}`,
      slug: 'curated-nvoy-feature',
      topic: 'nvoy',
      claim: 'Feature parts 1 and 2 complete',
      because: 'Curated Alice and Bob claims',
      evidence: ['nvoy@1111111', 'nvoy@2222222'],
      asOfGit: 'nvoy@2222222',
      supersedes: [aliceEv.id, bobEv.id],
      merkleSources: false,
      nowSec: nowSec + 30,
    }), curatorSk)
    const ref1 = store.submit({ writer: 'curator', event: noMerkleCuratorEv, nowSec: nowSec + 30 })
    assert.equal(ref1.accepted, false)
    assert.equal(ref1.code, 'HIVE_MEMORY_CURATOR_MISSING_MERKLE')

    // 2. Curator citing non-existent source event is refused with HIVE_MEMORY_CURATOR_SOURCE_MISSING
    const missingSrcEv = finalizeEvent(buildClaimTemplate({
      pubkey: curatorPk,
      scope: `room:${ROOM_ID}`,
      slug: 'curated-nvoy-feature',
      topic: 'nvoy',
      claim: 'Feature parts 1 and 2 complete',
      because: 'Curated',
      evidence: ['nvoy@2222222'],
      asOfGit: 'nvoy@2222222',
      supersedes: [aliceEv.id, '9'.repeat(64)],
      merkleSources: true,
      nowSec: nowSec + 31,
    }), curatorSk)
    const ref2 = store.submit({ writer: 'curator', event: missingSrcEv, nowSec: nowSec + 31 })
    assert.equal(ref2.accepted, false)
    assert.equal(ref2.code, 'HIVE_MEMORY_CURATOR_SOURCE_MISSING')

    // 3. Valid Curator consolidation with merkle_sources folds both Alice and Bob non-workflow claims!
    const validCuratorEv = finalizeEvent(buildClaimTemplate({
      pubkey: curatorPk,
      scope: `room:${ROOM_ID}`,
      slug: 'decision-nvoy-feature',
      topic: 'nvoy',
      claim: 'Feature parts 1 and 2 complete and promoted to Class B decision',
      because: 'Curated from Alice and Bob',
      evidence: ['nvoy@1111111', 'nvoy@2222222'],
      asOfGit: 'nvoy@2222222',
      ttlSec: 0,
      supersedes: [aliceEv.id, bobEv.id],
      merkleSources: true,
      nowSec: nowSec + 40,
    }), curatorSk)
    const acc = store.submit({ writer: 'curator', event: validCuratorEv, nowSec: nowSec + 40 })
    assert.equal(acc.accepted, true)

    const defaultQ = store.query({ readerPubkey: ownerPk, scope: `room:${ROOM_ID}`, format: 'full', nowSec: nowSec + 50 })
    assert.equal(defaultQ.records.length, 1, 'default query must return only the Curator consolidated claim')
    assert.equal(defaultQ.records[0].event_id, validCuratorEv.id)
    assert.equal(defaultQ.records[0].merkle_sources, computeSourceMerkleRoot([aliceEv.id, bobEv.id]))

    const histQ = store.query({ readerPubkey: ownerPk, scope: `room:${ROOM_ID}`, format: 'full', includeHistory: true, nowSec: nowSec + 50 })
    const aliceHist = histQ.records.find(r => r.event_id === aliceEv.id)
    const bobHist = histQ.records.find(r => r.event_id === bobEv.id)
    assert.equal(aliceHist.verification, 'consolidated')
    assert.equal(aliceHist.consolidated_by, validCuratorEv.id)
    assert.equal(bobHist.verification, 'consolidated')
    assert.equal(bobHist.consolidated_by, validCuratorEv.id)

    // 4. Verify 90-day Source Retention Hold: even when Alice/Bob claims are 95 days past their own expiry,
    // if the Curator consolidated them 10 days ago, retentionDue holds them!
    const lateConsolidationAt = nowSec + 92 * 86400
    recordVerifiedBackup({ receiptPath, writeSeq: store.storeState(ownerPk, nowSec + 40).write_seq, snapshotId: SNAP_ID, at: lateConsolidationAt, nowSec: lateConsolidationAt })
    const refreshedCuratorEv = finalizeEvent(buildClaimTemplate({
      pubkey: curatorPk,
      scope: `room:${ROOM_ID}`,
      slug: 'decision-nvoy-feature',
      topic: 'nvoy',
      claim: 'Refreshed Class B decision holding sources for 90d',
      because: 'Re-attested',
      evidence: ['nvoy@1111111', 'nvoy@2222222'],
      asOfGit: 'nvoy@2222222',
      ttlSec: 0,
      supersedes: [aliceEv.id, bobEv.id],
      merkleSources: true,
      nowSec: lateConsolidationAt,
      priorCreatedAt: validCuratorEv.created_at,
    }), curatorSk)
    assert.equal(store.submit({
      writer: 'curator',
      event: refreshedCuratorEv,
      expectedPriorId: validCuratorEv.id,
      nowSec: lateConsolidationAt,
    }).accepted, true)

    const checkAt = nowSec + 95 * 86400 // Alice & Bob expired ~95d ago, but refreshedCuratorEv was created 3d ago
    const dueIds = store.retentionCandidates(checkAt)
    assert(!dueIds.includes(aliceEv.id), 'Alice source must be held for 90 days after Curator consolidation')
    assert(!dueIds.includes(bobEv.id), 'Bob source must be held for 90 days after Curator consolidation')

    const afterHoldAt = lateConsolidationAt + RETENTION_PURGE_AFTER_SEC + 100
    const dueAfterHold = store.retentionCandidates(afterHoldAt)
    assert(dueAfterHold.includes(aliceEv.id), 'Alice source becomes eligible for purge once 90d post-consolidation window passes')

    // 5. Withdrawing the Curator claim immediately restores unexpired source claims
    recordVerifiedBackup({ receiptPath, writeSeq: store.storeState(ownerPk, lateConsolidationAt).write_seq, snapshotId: SNAP_ID, at: nowSec + 60, nowSec: nowSec + 60 })
    const { replacement: withdrawEv } = buildWithdrawalTemplate({
      pubkey: curatorPk,
      priorEvent: refreshedCuratorEv,
      scope: `room:${ROOM_ID}`,
      slug: 'decision-nvoy-feature',
      because: 'Testing reversibility of Curator consolidation',
      nowSec: lateConsolidationAt + 10,
    })
    const signedWithdraw = finalizeEvent(withdrawEv, curatorSk)
    recordVerifiedBackup({ receiptPath, writeSeq: store.storeState(ownerPk, lateConsolidationAt).write_seq, snapshotId: SNAP_ID, at: lateConsolidationAt + 10, nowSec: lateConsolidationAt + 10 })
    assert.equal(store.submit({
      writer: 'curator',
      event: signedWithdraw,
      expectedPriorId: refreshedCuratorEv.id,
      nowSec: lateConsolidationAt + 10,
    }).accepted, true)

    const restoredQ = store.query({ readerPubkey: ownerPk, scope: `room:${ROOM_ID}`, format: 'full', nowSec: nowSec + 60 })
    assert.equal(restoredQ.records.length, 2, 'withdrawing Curator claim restores unexpired Alice and Bob claims')

    assert.notEqual(computeStoreMerkleRoot(store.db), root0)
    store.close()
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

await test('evaluateDreamTriggers: circadian 6h, synaptic volume (+20 writes or >8 Class A per scope+topic), and nightmare interrupt', () => {
  const nowSec = 100_000
  // Quiet state: no triggers
  const quiet = evaluateDreamTriggers({
    records: [],
    storeState: { write_seq: 10 },
    recentActivity: [],
    coherence: { score: 95 },
    lastCuratedAt: nowSec - 3600,
    lastCuratedWriteSeq: 5,
    nowSec,
  })
  assert.equal(quiet.shouldRun, false)

  // 1. Circadian trigger (>= 6h)
  const circ = evaluateDreamTriggers({
    records: [],
    storeState: { write_seq: 10 },
    lastCuratedAt: nowSec - 6 * 3600,
    lastCuratedWriteSeq: 10,
    nowSec,
  })
  assert.equal(circ.shouldRun, true)
  assert.equal(circ.triggers.circadian_dream, true)

  // 2. Synaptic volume: 9 Class A claims in same scope+topic
  const hotRecords = Array.from({ length: 9 }, (_, i) => ({
    event_id: `${i}`.padEnd(64, 'a'),
    scope: `room:${ROOM_ID}`,
    d: `hive-memory:room:${ROOM_ID}:item-${i}`,
    topic: 'nvoy',
    claim: `Claim ${i}`,
    verification: 'accepted',
    status: 'active',
    expires_at: nowSec + 86400,
  }))
  const vol = evaluateDreamTriggers({
    records: hotRecords,
    storeState: { write_seq: 12 },
    lastCuratedAt: nowSec - 100,
    lastCuratedWriteSeq: 10,
    nowSec,
  })
  assert.equal(vol.shouldRun, true)
  assert.equal(vol.triggers.synaptic_volume, true)
  assert.equal(vol.hot_scope_topics.length, 1)

  // 3. Nightmare interrupt: active conflict
  const nightmare = evaluateDreamTriggers({
    records: [{
      event_id: 'c'.repeat(64),
      scope: `room:${ROOM_ID}`,
      d: `hive-memory:room:${ROOM_ID}:disputed-fact`,
      topic: 'nvoy',
      claim: 'Competing claim',
      verification: 'accepted',
      status: 'active',
      conflict: true,
      expires_at: nowSec + 86400,
    }],
    storeState: { write_seq: 12 },
    lastCuratedAt: nowSec - 100,
    lastCuratedWriteSeq: 10,
    nowSec,
  })
  assert.equal(nightmare.shouldRun, true)
  assert.equal(nightmare.triggers.nightmare_interrupt, true)
  assert.deepEqual(nightmare.conflicted_keys, [`hive-memory:room:${ROOM_ID}:disputed-fact`])
})

await test('runCuratorCycle: live end-to-end Distillation, Promotion, Solidification & Nightmare Escalation over daemon sockets', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-curate-e2e-'))
  try {
    const sockDir = join(tmp, 'sock')
    const dbPath = join(tmp, 'memory.sqlite')
    const ledgerPath = join(tmp, 'ledger.jsonl')
    const receiptPath = join(tmp, 'receipt.json')

    const ownerSk = generateSecretKey(), ownerPk = getPublicKey(ownerSk)
    const aliceSk = generateSecretKey(), alicePk = getPublicKey(aliceSk)
    const bobSk = generateSecretKey(), bobPk = getPublicKey(bobSk)
    const carolSk = generateSecretKey(), carolPk = getPublicKey(carolSk)
    const curatorSk = generateSecretKey(), curatorPk = getPublicKey(curatorSk)

    const nowSec = Math.floor(Date.now() / 1000)
    initEmptyStore({ dbPath, ledgerPath, nowSec })
    recordVerifiedBackup({ receiptPath, snapshotId: SNAP_ID, writeSeq: 1, at: nowSec, nowSec })

    const daemon = await startMemoryDaemon({
      dbPath,
      ledgerPath,
      receiptPath,
      config: {
        memoryGlobalChannelId: GLOBAL_CH,
        ownerPubkey: ownerPk,
        maxUnbackedSec: 3600,
        globalWriters: [ownerPk, curatorPk],
        curators: [curatorPk],
        readers: { curator: curatorPk },
        writers: {
          owner: { pubkey: ownerPk, perHour: 100 },
          alice: { pubkey: alicePk, perHour: 50 },
          bob: { pubkey: bobPk, perHour: 50 },
          carol: { pubkey: carolPk, perHour: 50 },
          curator: { pubkey: curatorPk, perHour: 120 },
        },
        rooms: {
          [ROOM_ID]: {
            members: [ownerPk, alicePk, bobPk, carolPk, curatorPk],
            writers: [ownerPk, alicePk, bobPk, carolPk, curatorPk],
          },
        },
      },
      readers: 'curator',
      writers: 'alice:bob:carol:curator',
      socketDir: sockDir,
      log: () => {},
    })

    try {
      // 1. Stage 1 Distillation inputs: Alice writes 2 single-author Class A checkpoints on PR #400
      const d1 = finalizeEvent(buildClaimTemplate({
        pubkey: alicePk,
        scope: `room:${ROOM_ID}`,
        slug: 'r1-pr400-wip',
        topic: 'r1',
        claim: 'PR #400 opened for R1 audio synthesizer',
        because: 'Started PR 400',
        evidence: ['rabidrabbit@aaaa111'],
        asOfGit: 'rabidrabbit@aaaa111',
        nowSec: nowSec + 1,
      }), aliceSk)
      const d2 = finalizeEvent(buildClaimTemplate({
        pubkey: alicePk,
        scope: `room:${ROOM_ID}`,
        slug: 'r1-pr400-status',
        topic: 'r1',
        claim: 'PR #400 tests passing on R1 audio synthesizer',
        because: 'Verified CI on PR 400',
        evidence: ['rabidrabbit@bbbb222'],
        asOfGit: 'rabidrabbit@bbbb222',
        nowSec: nowSec + 2,
      }), aliceSk)
      assert.equal(daemon.store.submit({ writer: 'alice', event: d1, nowSec: nowSec + 1 }).accepted, true)
      assert.equal(daemon.store.submit({ writer: 'alice', event: d2, nowSec: nowSec + 2 }).accepted, true)

      // 2. Stage 2 Promotion inputs: Alice and Bob write converging non-workflow Class A claims on PR #500 in nvoy
      const p1 = finalizeEvent(buildClaimTemplate({
        pubkey: alicePk,
        scope: `room:${ROOM_ID}`,
        slug: 'nvoy-pr500-impl',
        topic: 'nvoy',
        claim: 'PR #500 Merkle Dreaming engine implemented',
        because: 'Built Merkle Dreaming',
        evidence: ['nvoy@1111111'],
        asOfGit: 'nvoy@1111111',
        nowSec: nowSec + 3,
      }), aliceSk)
      const p2 = finalizeEvent(buildClaimTemplate({
        pubkey: bobPk,
        scope: `room:${ROOM_ID}`,
        slug: 'nvoy-pr500-deployed',
        topic: 'nvoy',
        claim: 'PR #500 Merkle Dreaming engine deployed to herd-cloud',
        because: 'Deployed and verified',
        evidence: ['nvoy@2222222'],
        asOfGit: 'nvoy@2222222',
        nowSec: nowSec + 4,
      }), bobSk)
      assert.equal(daemon.store.submit({ writer: 'alice', event: p1, nowSec: nowSec + 3 }).accepted, true)
      assert.equal(daemon.store.submit({ writer: 'bob', event: p2, nowSec: nowSec + 4 }).accepted, true)

      // 3. Stage 3 Solidification inputs: Alice, Bob, and Carol each have a Class B decision in `herd-infra`
      for (const [idx, [sk, pk, name]] of [[aliceSk, alicePk, 'alice'], [bobSk, bobPk, 'bob'], [carolSk, carolPk, 'carol']].entries()) {
        const cb = finalizeEvent(buildClaimTemplate({
          pubkey: pk,
          scope: `room:${ROOM_ID}`,
          slug: `herd-infra-isolation-${name}`,
          topic: 'herd-infra',
          claim: `Per-agent Unix user isolation verified by ${name}`,
          because: 'Fleet security invariant',
          evidence: [`herd-infra@333333${idx}`],
          asOfGit: `herd-infra@333333${idx}`,
          ttlSec: 0,
          nowSec: nowSec + 5 + idx,
        }), sk)
        assert.equal(daemon.store.submit({ writer: name, event: cb, nowSec: nowSec + 5 + idx }).accepted, true)
      }

      // 4. Nightmare Ambiguous Conflict inputs: Alice and Bob write competing claims at the exact same slug without causal link
      const c1 = finalizeEvent(buildClaimTemplate({
        pubkey: alicePk,
        scope: `room:${ROOM_ID}`,
        slug: 'buzz-port-assignment',
        topic: 'buzz',
        claim: 'Buzz daemon listens on port 8901',
        because: 'Alice config',
        evidence: ['buzz@aaaa000'],
        asOfGit: 'buzz@aaaa000',
        nowSec: nowSec + 10,
      }), aliceSk)
      const c2 = finalizeEvent(buildClaimTemplate({
        pubkey: bobPk,
        scope: `room:${ROOM_ID}`,
        slug: 'buzz-port-assignment',
        topic: 'buzz',
        claim: 'Buzz daemon listens on port 8999',
        because: 'Bob config',
        evidence: ['buzz@bbbb999'],
        asOfGit: 'buzz@bbbb999',
        nowSec: nowSec + 11,
      }), bobSk)
      assert.equal(daemon.store.submit({ writer: 'alice', event: c1, nowSec: nowSec + 10 }).accepted, true)
      assert.equal(daemon.store.submit({ writer: 'bob', event: c2, nowSec: nowSec + 11 }).accepted, true)

      // Verify incomplete-history gate: two-page fixture with maxPages: 1 and pageSize: 3 makes zero writer calls and never advances cursor!
      const preWriteSeq = daemon.store.storeState(curatorPk, nowSec + 19).write_seq
      const incompleteCycle = await runCuratorCycle({
        readerSocket: join(sockDir, 'curator.sock'),
        writerSocket: join(sockDir, 'writers', 'curator.sock'),
        curatorSecretKey: curatorSk,
        memoryGlobalChannelId: GLOBAL_CH,
        maxPages: 1,
        pageSize: 3,
        nowSec: nowSec + 19,
      })
      assert.equal(incompleteCycle.ok, false)
      assert.equal(incompleteCycle.history_complete, false)
      assert.equal(incompleteCycle.cycle_status, 'history_incomplete')
      assert.equal(incompleteCycle.cursor_advanced, false)
      assert.equal(incompleteCycle.submitted.length, 0)
      assert.equal(daemon.store.storeState(curatorPk, nowSec + 19).write_seq, preWriteSeq, 'incomplete pagination must make zero store writes')

      // Run the Curator cycle!
      const cycle = await runCuratorCycle({
        readerSocket: join(sockDir, 'curator.sock'),
        writerSocket: join(sockDir, 'writers', 'curator.sock'),
        curatorSecretKey: curatorSk,
        memoryGlobalChannelId: GLOBAL_CH,
        nowSec: nowSec + 20,
      })

      assert.equal(cycle.ok, true)
      assert.equal(cycle.triggers.shouldRun, true)
      assert.equal(cycle.triggers.triggers.nightmare_interrupt, true, 'ambiguous conflict triggers nightmare_interrupt')
      assert.equal(cycle.plan.summary.distillations, 1, 'PR #400 single-author checkpoints distilled')
      assert.equal(cycle.plan.summary.promotions, 1, 'PR #500 multi-author claims promoted to Class B decision')
      assert.equal(cycle.plan.summary.solidifications, 1, '3-author Class B herd-infra decisions nominated for hive:canon solidification')
      assert.equal(cycle.plan.summary.nightmares_escalated, 1, 'ambiguous buzz-port-assignment conflict escalated to owner')
      assert(cycle.plan.nightmares[0].message.includes('NIGHTMARE ESCALATION (@james @mydude)'))
      assert.equal(cycle.submitted.length, 2, 'both the distillation and the promotion were signed and accepted by the store')

      // Verify the 4 source Class A claims (d1, d2, p1, p2) are now hidden ('consolidated') from default query!
      const afterQ = daemon.store.query({ readerPubkey: curatorPk, scope: `room:${ROOM_ID}`, format: 'full', nowSec: nowSec + 25 })
      const activeIds = new Set(afterQ.records.map(r => r.event_id))
      assert(!activeIds.has(d1.id) && !activeIds.has(d2.id), 'distilled PR 400 checkpoints are now consolidated')
      assert(!activeIds.has(p1.id) && !activeIds.has(p2.id), 'promoted PR 500 claims are now consolidated')

      const promotedRec = afterQ.records.find(r => r.d.endsWith(':decision-nvoy-pr500'))
      assert(promotedRec, 'promoted Class B decision is active in default query')
      assert.equal(promotedRec.retention, 'decision')
      assert.equal(promotedRec.expires_at, null)
      assert.equal(promotedRec.merkle_sources, computeSourceMerkleRoot([p1.id, p2.id]))
    } finally {
      await daemon.close()
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

await test('CLI bin/hive-memory-curate.mjs requires write capability to advance cursor, persists across seq 20 -> 21, fails closed on refused writes or state-file errors, and restricts telemetry to curator/viewer bindings', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-curate-cli-'))
  try {
    const sockDir = join(tmp, 'sock')
    const dbPath = join(tmp, 'memory.sqlite')
    const ledgerPath = join(tmp, 'ledger.jsonl')
    const receiptPath = join(tmp, 'receipt.json')
    const keyFile = join(tmp, 'curator.key')
    const wrongKeyFile = join(tmp, 'wrong.key')
    const customStateFile = join(tmp, 'state', 'curator-state.json')
    const cliPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'hive-memory-curate.mjs')

    const ownerSk = generateSecretKey(), ownerPk = getPublicKey(ownerSk)
    const aliceSk = generateSecretKey(), alicePk = getPublicKey(aliceSk)
    const curatorSk = generateSecretKey(), curatorPk = getPublicKey(curatorSk)
    writeFileSync(keyFile, Buffer.from(curatorSk).toString('hex') + '\n', { mode: 0o600 })
    writeFileSync(wrongKeyFile, Buffer.from(aliceSk).toString('hex') + '\n', { mode: 0o600 })

    const nowSec = Math.floor(Date.now() / 1000)
    initEmptyStore({ dbPath, ledgerPath, nowSec })
    recordVerifiedBackup({ receiptPath, snapshotId: SNAP_ID, writeSeq: 1, at: nowSec, nowSec })

    const daemon = await startMemoryDaemon({
      dbPath,
      ledgerPath,
      receiptPath,
      config: {
        memoryGlobalChannelId: GLOBAL_CH,
        ownerPubkey: ownerPk,
        maxUnbackedSec: 3600,
        globalWriters: [ownerPk, curatorPk],
        curators: [curatorPk],
        readers: { curator: curatorPk, alice: alicePk },
        writers: {
          owner: { pubkey: ownerPk, perHour: 100 },
          alice: { pubkey: alicePk, perHour: 100 },
          curator: { pubkey: curatorPk, perHour: 120 },
        },
        rooms: {
          [ROOM_ID]: {
            members: [ownerPk, alicePk, curatorPk],
            writers: [ownerPk, alicePk, curatorPk],
          },
        },
      },
      readers: 'curator:alice',
      writers: 'alice:curator',
      socketDir: sockDir,
      log: () => {},
    })

    try {
      // Advance store to write_seq = 20 with 2 distillable checkpoints on PR #401 plus 17 independent claims
      const d1 = finalizeEvent(buildClaimTemplate({
        pubkey: alicePk,
        scope: `room:${ROOM_ID}`,
        slug: 'r1-pr401-wip',
        topic: 'r1',
        claim: 'PR #401 opened for R1 primer companion',
        because: 'Started PR 401',
        evidence: ['rabidrabbit@4010001'],
        asOfGit: 'rabidrabbit@4010001',
        nowSec: nowSec + 1,
      }), aliceSk)
      const d2 = finalizeEvent(buildClaimTemplate({
        pubkey: alicePk,
        scope: `room:${ROOM_ID}`,
        slug: 'r1-pr401-status',
        topic: 'r1',
        claim: 'PR #401 unit tests passing for R1 primer companion',
        because: 'Verified PR 401',
        evidence: ['rabidrabbit@4010002'],
        asOfGit: 'rabidrabbit@4010002',
        nowSec: nowSec + 2,
      }), aliceSk)
      assert.equal(daemon.store.submit({ writer: 'alice', event: d1, nowSec: nowSec + 1 }).accepted, true)
      assert.equal(daemon.store.submit({ writer: 'alice', event: d2, nowSec: nowSec + 2 }).accepted, true)

      const topics = ['nvoy', 'r1', 'buzz', 'herd-infra']
      const vocab = [
        'alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel', 'india',
        'juliet', 'kilo', 'lima', 'mike', 'november', 'oscar', 'papa', 'quebec', 'romeo', 'sierra', 'tango'
      ]
      for (let i = 3; i <= 19; i++) {
        const top = topics[i % topics.length]
        const w = vocab[i - 1]
        const ev = finalizeEvent(buildClaimTemplate({
          pubkey: alicePk,
          scope: `room:${ROOM_ID}`,
          slug: `${w}-metric-${i * 17}`,
          topic: top,
          claim: `${w.toUpperCase()} ${w}1 ${w}2 ${w}3 ${w}4 ${w}5`,
          because: `${w}reason ${i}`,
          evidence: [`${top}@${String(i).padStart(7, '0')}`],
          asOfGit: `${top}@${String(i).padStart(7, '0')}`,
          nowSec: nowSec + i,
        }), aliceSk)
        assert.equal(daemon.store.submit({ writer: 'alice', event: ev, nowSec: nowSec + i }).accepted, true)
      }
      assert.equal(daemon.store.storeState(ownerPk, nowSec + 20).write_seq, 20)

      const runCli = async (args, expectFail = false) => {
        try {
          const { stdout } = await execFileAsync(process.execPath, [cliPath, ...args], { encoding: 'utf8' })
          assert.equal(expectFail, false, 'expected CLI to fail but it exited 0')
          return JSON.parse(stdout)
        } catch (err) {
          if (!expectFail) throw err
          return err.stdout ? JSON.parse(err.stdout) : { ok: false, stderr: String(err.stderr || err.message) }
        }
      }

      // 0. Non-curator reader socket (alice.sock) receives 0 telemetry even if calling memory_wake with include_telemetry: true
      const outAliceRo = await runCli([
        '--reader-socket', join(sockDir, 'alice.sock'),
        '--state-file', customStateFile,
      ])
      assert.equal(outAliceRo.recent_activity_count, 0, 'ordinary reader socket never receives recent_activity telemetry')

      // 1a. Read-only CLI call without writer socket/key at write_seq = 20 MUST NOT advance cursor or consume the +20 trigger
      const outRo20 = await runCli([
        '--reader-socket', join(sockDir, 'curator.sock'),
        '--state-file', customStateFile,
      ])
      assert.equal(outRo20.ok, true)
      assert.equal(outRo20.cycle_status, 'read_only_pending')
      assert.equal(outRo20.cursor_advanced, false)
      assert.equal(outRo20.next_curated_write_seq, 0, 'read-only call leaves last_curated_write_seq at 0')

      // 1b. Write-capable CLI call with wrong key (refused submission) MUST fail closed (exit 1) and retain pending cursor
      const outRefusedWrite = await runCli([
        '--reader-socket', join(sockDir, 'curator.sock'),
        '--writer-socket', join(sockDir, 'writers', 'curator.sock'),
        '--key-file', wrongKeyFile,
        '--state-file', customStateFile,
        '--global-channel-id', GLOBAL_CH,
      ], true)
      assert.equal(outRefusedWrite.ok, false)
      assert.equal(outRefusedWrite.cycle_status, 'write_refused')
      assert.equal(outRefusedWrite.cursor_advanced, false)
      assert.equal(outRefusedWrite.refused.length, 1)
      assert.equal(outRefusedWrite.next_curated_write_seq, 0, 'refused write retains cursor at 0')

      // 1c. Write-capable CLI call with valid curator key at write_seq = 20 submits distillation (seq becomes 21) and advances cursor
      const out20 = await runCli([
        '--reader-socket', join(sockDir, 'curator.sock'),
        '--writer-socket', join(sockDir, 'writers', 'curator.sock'),
        '--key-file', keyFile,
        '--state-file', customStateFile,
        '--global-channel-id', GLOBAL_CH,
      ])
      assert.equal(out20.ok, true)
      assert.equal(out20.cycle_status, 'curated')
      assert.equal(out20.cursor_advanced, true)
      assert.equal(out20.submitted.length, 1, 'PR #401 distillation submitted on write-capable cycle')
      assert.equal(out20.triggers.write_delta, 20)
      assert.equal(out20.triggers.triggers.synaptic_volume, true)
      assert.equal(out20.triggers.shouldRun, true)
      assert.equal(out20.next_curated_write_seq, 21, 'cursor advances to post-submission write_seq = 21')
      assert.equal(typeof out20.coherence?.score, 'number', 'CLI supplies live coherence score')

      // 2. Submit 1 more write to reach write_seq = 22 and run CLI again:
      //    +20-write trigger MUST NOT repeat (write_delta === 1, shouldRun === false)
      const ev22 = finalizeEvent(buildClaimTemplate({
        pubkey: alicePk,
        scope: `room:${ROOM_ID}`,
        slug: 'seq-item-20',
        topic: 'nvoy',
        claim: 'Independent status item 20 for nvoy',
        because: 'Test write 20',
        evidence: ['nvoy@0000020'],
        asOfGit: 'nvoy@0000020',
        nowSec: nowSec + 25,
      }), aliceSk)
      assert.equal(daemon.store.submit({ writer: 'alice', event: ev22, nowSec: nowSec + 25 }).accepted, true)
      assert.equal(daemon.store.storeState(ownerPk, nowSec + 25).write_seq, 22)

      const out22 = await runCli([
        '--reader-socket', join(sockDir, 'curator.sock'),
        '--writer-socket', join(sockDir, 'writers', 'curator.sock'),
        '--key-file', keyFile,
        '--state-file', customStateFile,
        '--global-channel-id', GLOBAL_CH,
      ])
      assert.equal(out22.ok, true)
      assert.equal(out22.cycle_status, 'idle')
      assert.equal(out22.last_curated_write_seq, 21)
      assert.equal(out22.triggers.write_delta, 1, 'write delta at seq 22 must be 1, not 22')
      assert.equal(out22.triggers.triggers.synaptic_volume, false, '+20 trigger must not repeat after 1 new write')
      assert.equal(out22.triggers.triggers.circadian_dream, false)
      assert.equal(out22.triggers.shouldRun, false)

      // 3. Six hours later, the 6-hour circadian trigger fires from persisted lastCuratedAt and records noop_verified
      const out6h = await runCli([
        '--reader-socket', join(sockDir, 'curator.sock'),
        '--writer-socket', join(sockDir, 'writers', 'curator.sock'),
        '--key-file', keyFile,
        '--state-file', customStateFile,
        '--global-channel-id', GLOBAL_CH,
        '--now-sec', String(out20.next_curated_at + 6 * 3600),
      ])
      assert.equal(out6h.triggers.triggers.circadian_dream, true, '6-hour circadian trigger fires using persisted lastCuratedAt')
      assert.equal(out6h.triggers.shouldRun, true)
      assert.equal(out6h.cycle_status, 'noop_verified')
      assert.equal(out6h.cursor_advanced, true)

      // 4. Low coherence score supplied via CLI triggers nightmare_interrupt
      const outLowCoh = await runCli([
        '--reader-socket', join(sockDir, 'curator.sock'),
        '--state-file', customStateFile,
        '--coherence-score', '58',
      ])
      assert.equal(outLowCoh.triggers.triggers.nightmare_interrupt, true)
      assert(outLowCoh.triggers.reasons.some(r => r.includes('nightmare_coherence_drop')))

      // 5. Refusal spike on daemon socket is visible to CLI via wake.recent_activity and triggers nightmare_interrupt
      const net = await import('node:net')
      for (let r = 0; r < 3; r++) {
        await new Promise((resolveCall, rejectCall) => {
          const s = net.createConnection(join(sockDir, 'curator.sock'))
          s.once('connect', () => {
            s.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'memory_submit', arguments: {} } }) + '\n')
          })
          s.on('data', () => { s.destroy(); resolveCall() })
          s.once('error', rejectCall)
        })
      }
      const outRefusal = await runCli([
        '--reader-socket', join(sockDir, 'curator.sock'),
        '--state-file', customStateFile,
      ])
      assert(outRefusal.recent_activity_count >= 3, 'CLI receives recent_activity from daemon')
      assert(outRefusal.triggers.refusal_count_15m >= 3)
      assert.equal(outRefusal.triggers.triggers.nightmare_interrupt, true)
      assert(outRefusal.triggers.reasons.some(r => r.includes('nightmare_refusal_spike')))

      // 6. Corrupt state file fails closed instead of silently resetting cursor to 0
      const corruptStateFile = join(tmp, 'corrupt-state.json')
      writeFileSync(corruptStateFile, '{not-valid-json', 'utf8')
      const outCorrupt = await runCli([
        '--reader-socket', join(sockDir, 'curator.sock'),
        '--state-file', corruptStateFile,
      ], true)
      assert.equal(outCorrupt.ok, false)
      assert(String(outCorrupt.stderr).includes('curator state file corrupt JSON'))
    } finally {
      await daemon.close()
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ── Test 6: Spectral Topic Eigenvector Analysis & Topic Normalization in Dreaming ──
await test('computeTopicEigenvectors extracts orthonormal eigen-axes and planMerkleDream normalizes fragmented topics', async () => {
  const now = 1_780_000_000
  const records = [
    // Core topic: r1
    {
      event_id: 'e1'.padEnd(64, '0'),
      pubkey: 'a'.repeat(64),
      created_at: now - 300,
      expires_at: now + 86400 * 7,
      scope: `room:${ROOM_ID}`,
      topic: 'r1',
      d: `room:${ROOM_ID}:r1:wonder-lab-window24`,
      claim: 'Rabbit R1 Window 24 displays Wonder-Lab notebook title and wheel hint in tools/r1-primer-ui/r1-primer-ui.c.',
      evidence: ['git:rabidrabbit@cc85281c:tools/r1-primer-ui/r1-primer-ui.c'],
      verification: 'accepted',
      status: 'active',
    },
    {
      event_id: 'e2'.padEnd(64, '0'),
      pubkey: 'b'.repeat(64),
      created_at: now - 250,
      expires_at: now + 86400 * 7,
      scope: `room:${ROOM_ID}`,
      topic: 'r1',
      d: `room:${ROOM_ID}:r1:wonder-lab-window24-review`,
      claim: 'Rabbit R1 primer feed serves Wonder-Lab notebooks on Window 24 via tools/r1-primer-ui/r1-primer-ui.c.',
      evidence: ['git:rabidrabbit@cc85281c:tools/r1-primer-ui/r1-primer-ui.c'],
      verification: 'accepted',
      status: 'active',
    },
    // Fragmented topic: wonder-lab (shares repo:rabidrabbit, tools/r1-primer-ui, Window 24, Wonder-Lab with r1)
    {
      event_id: 'e3'.padEnd(64, '0'),
      pubkey: 'c'.repeat(64),
      created_at: now - 200,
      expires_at: now + 86400 * 7,
      scope: `room:${ROOM_ID}`,
      topic: 'wonder-lab',
      d: `room:${ROOM_ID}:wonder-lab:wonder-lab-window24-status`,
      claim: 'Wonder-Lab Window 24 header and wheel hint active on Rabbit R1 via tools/r1-primer-ui/r1-primer-ui.c.',
      evidence: ['git:rabidrabbit@cc85281c:tools/r1-primer-ui/r1-primer-ui.c'],
      verification: 'accepted',
      status: 'active',
    },
    // Core topic: herd-infra
    {
      event_id: 'e4'.padEnd(64, '0'),
      pubkey: 'a'.repeat(64),
      created_at: now - 180,
      expires_at: now + 86400 * 7,
      scope: `room:${ROOM_ID}`,
      topic: 'herd-infra',
      d: `room:${ROOM_ID}:herd-infra:fleet-watchdog`,
      claim: 'Herd-infra fleet watchdog monitors systemd services and tailscale health on herd-cloud.',
      evidence: ['git:herd-infra@11111111:scripts/watchdog.sh'],
      verification: 'accepted',
      status: 'active',
    },
    // Fragmented alias topic: ops -> herd-infra
    {
      event_id: 'e5'.padEnd(64, '0'),
      pubkey: 'b'.repeat(64),
      created_at: now - 120,
      expires_at: now + 86400 * 7,
      scope: `room:${ROOM_ID}`,
      topic: 'ops',
      d: `room:${ROOM_ID}:ops:fleet-watchdog-status`,
      claim: 'Ops fleet watchdog systemd check verified on herd-cloud.',
      evidence: ['git:herd-infra@11111111:scripts/watchdog.sh'],
      verification: 'accepted',
      status: 'active',
    },
  ]

  const eigen = computeTopicEigenvectors(records, { maxComponents: 4 })
  assert(eigen.eigenvectors.length >= 2, 'must extract principal eigenvectors')
  assert(eigen.eigenvectors[0].eigenvalue >= eigen.eigenvectors[1].eigenvalue, 'eigenvalues must be sorted descending')
  assert.equal(eigen.topic_map['wonder-lab'], 'r1', 'wonder-lab maps to core eigen-topic r1 by spectral cosine affinity')
  assert.equal(eigen.topic_map['ops'], 'herd-infra', 'ops maps to core eigen-topic herd-infra')
  assert(eigen.reorganizations.some(r => r.from_topic === 'wonder-lab' && r.to_topic === 'r1'))

  // Verify planMerkleDream uses eigen topic normalization so e1, e2 (topic: r1) and e3 (topic: wonder-lab) cluster together!
  const plan = planMerkleDream({ records, nowSec: now })
  assert(Array.isArray(plan.topic_eigenvectors) && plan.topic_eigenvectors.length >= 2)
  assert(Array.isArray(plan.topic_reorganizations) && plan.topic_reorganizations.length >= 2)
  assert.equal(plan.distillations.length, 2, 'cross-topic r1+wonder-lab and herd-infra+ops converge into 2 distilled claims')
  const r1Dist = plan.distillations.find(d => d.topic === 'r1')
  assert(r1Dist, 'r1 distillation present')
  assert.equal(r1Dist.source_event_ids.length, 3, 'e1, e2 (r1) and e3 (wonder-lab) distilled together')
  assert.deepEqual(r1Dist.reorganized_from_topics, ['wonder-lab'])

  // Zero-overlap regression: an unrelated topic ('astro') with zero cosine affinity must remain intact ('astro')
  const withUnrelated = [
    ...records,
    {
      event_id: 'e6'.padEnd(64, '0'),
      pubkey: 'd'.repeat(64),
      created_at: now - 100,
      expires_at: now + 86400 * 7,
      scope: `room:${ROOM_ID}`,
      topic: 'astro',
      d: `room:${ROOM_ID}:astro:quasar-redshift`,
      claim: 'Quasar spectroscopy measures Lyman-alpha forest absorption lines at high redshift.',
      evidence: ['doi:10.1086/quasar-lyman-alpha'],
      verification: 'accepted',
      status: 'active',
    },
  ]
  const eigenUnrelated = computeTopicEigenvectors(withUnrelated, { maxComponents: 4 })
  assert.equal(eigenUnrelated.topic_map.astro, 'astro', 'zero-overlap topic astro must not be mapped to a core topic')
  assert.equal(
    eigenUnrelated.reorganizations.some(r => r.from_topic === 'astro'),
    false,
    'zero-overlap topic astro must not appear in reorganizations'
  )

  // ── mem-eigen-axes: Intra-topic TF-IDF sub-axis clustering (>=25 claims), merge (cos >= 0.55), retire (0w/7d, <=3 Class B), counterfactual coherence_delta, no auto-refiling ──
  const largeTopicCorpus = []
  // 12 coherent systemd/watchdog claims in herd-infra
  for (let i = 0; i < 12; i++) {
    largeTopicCorpus.push({
      event_id: `fa${String(i).padStart(2, '0')}`.padEnd(64, '0'),
      pubkey: 'b'.repeat(64),
      author: 'neil',
      created_at: now - 3600 - i * 60,
      expires_at: now + 86400 * 7,
      scope: `room:${ROOM_ID}`,
      topic: 'herd-infra',
      d: `hive-memory:room:${ROOM_ID}:herd-infra-systemd-watchdog-${i}`,
      claim: `Systemd service unit watchdog timer health check and slice memory threshold verified on host node ${i}.`,
      because: 'Systemd watchdog slice health check.',
      evidence: ['git:herd-infra@11111111:scripts/watchdog.sh'],
      verification: 'accepted',
      status: 'active',
    })
  }
  // 10 coherent restic/backblaze backup claims in herd-infra
  for (let i = 0; i < 10; i++) {
    largeTopicCorpus.push({
      event_id: `fb${String(i).padStart(2, '0')}`.padEnd(64, '0'),
      pubkey: 'c'.repeat(64),
      author: 'dead-rabbit',
      created_at: now - 7200 - i * 60,
      expires_at: now + 86400 * 7,
      scope: `room:${ROOM_ID}`,
      topic: 'herd-infra',
      d: `hive-memory:room:${ROOM_ID}:herd-infra-restic-backup-${i}`,
      claim: `Restic snapshot repository backup to Backblaze bucket verified with prune retention receipt ${i}.`,
      because: 'Half-hourly restic backup to Backblaze B2.',
      evidence: ['git:herd-infra@22222222:host/backup/restic.sh'],
      verification: 'accepted',
      status: 'active',
    })
  }
  // 5 miscellaneous claims in herd-infra so total in herd-infra is 27 (>= 25)
  for (let i = 0; i < 5; i++) {
    largeTopicCorpus.push({
      event_id: `fc${String(i).padStart(2, '0')}`.padEnd(64, '0'),
      pubkey: 'a'.repeat(64),
      author: 'biggy',
      created_at: now - 9000 - i * 60,
      expires_at: now + 86400 * 7,
      scope: `room:${ROOM_ID}`,
      topic: 'herd-infra',
      d: `hive-memory:room:${ROOM_ID}:herd-infra-ssh-key-${i}`,
      claim: `Authorized ssh key provisioning and known_hosts fingerprint check ${i}.`,
      because: 'SSH key rotation.',
      evidence: ['git:herd-infra@33333333:bin/put-keys'],
      verification: 'accepted',
      status: 'active',
    })
  }
  // Overlapping topic (`r1-audio` overlapping with `r1`, cosine >= 0.55)
  for (let i = 0; i < 4; i++) {
    largeTopicCorpus.push({
      event_id: `fd${String(i).padStart(2, '0')}`.padEnd(64, '0'),
      pubkey: 'a'.repeat(64),
      author: 'mc-claude',
      created_at: now - 1800 - i * 60,
      expires_at: now + 86400 * 7,
      scope: `room:${ROOM_ID}`,
      topic: i < 2 ? 'r1' : 'r1-audio',
      d: `hive-memory:room:${ROOM_ID}:r1-voice-speak-socket-${i}`,
      claim: 'Rabbit R1 voice speak socket streams spoken audio replies over r1-speak systemd socket.',
      because: 'R1 voice speak socket verification.',
      evidence: ['git:rabidrabbit@72540514:usr/local/lib/r1-herd/voice'],
      verification: 'accepted',
      status: 'active',
    })
  }
  // Idle topic (`legacy-experiment`: 0 writes in 7d, <= 3 Class B claims)
  largeTopicCorpus.push({
    event_id: 'fe00'.padEnd(64, '0'),
    pubkey: 'd'.repeat(64),
    author: 'kerouac',
    created_at: now - 10 * 86400,
    expires_at: null,
    retention: 'decision',
    scope: `room:${ROOM_ID}`,
    topic: 'legacy-experiment',
    d: `hive-memory:room:${ROOM_ID}:legacy-experiment-note`,
    claim: 'Early prototype layout notes from ten days ago.',
    because: 'Historical note.',
    evidence: [],
    verification: 'accepted',
    status: 'active',
  })

  const proposals = computeEigenAxisProposals(largeTopicCorpus, { nowSec: now })
  const splitProposals = proposals.filter(p => p.kind === 'split' && p.from_topic === 'herd-infra')
  assert(splitProposals.length >= 2, `expected >= 2 coherent sub-axis split proposals for herd-infra (27 claims), got ${splitProposals.length}`)
  for (const sp of splitProposals) {
    assert(sp.proposed_topic.startsWith('herd-infra-'), `sub-axis name must follow <topic>-<top-terms>, got ${sp.proposed_topic}`)
    assert(sp.claim_count >= 8, `sub-axis cluster must have size >= 8, got ${sp.claim_count}`)
    assert(sp.mean_intra_cosine >= 0.35, `sub-axis cluster must have mean_intra_cosine >= 0.35, got ${sp.mean_intra_cosine}`)
    assert(Array.isArray(sp.sample_claims) && sp.sample_claims.length > 0, 'proposal must include sample_claims')
    assert(Array.isArray(sp.sample_slugs) && sp.sample_slugs.length > 0, 'proposal must include sample_slugs')
    assert(typeof sp.coherence_delta === 'number' && sp.coherence_delta > 0, 'proposal must report positive counterfactual coherence_delta')
    assert(/^\+\d+\.\d%$/.test(sp.coherence_delta_label), `coherence_delta_label must be formatted +X.X%, got ${sp.coherence_delta_label}`)
    assert.equal(sp.counterfactual, true)
    assert.equal(sp.approval_required, true)
    assert.equal(sp.status, 'pending_james_approval')
  }

  const mergeProposal = proposals.find(p => p.kind === 'merge' && p.from_topic === 'r1-audio' && p.to_topic === 'r1')
  assert(mergeProposal, 'must propose merging overlapping topic r1-audio into r1 (cosine >= 0.55)')
  assert(mergeProposal.cosine_affinity >= 0.55)
  assert.equal(mergeProposal.counterfactual, true)
  assert.equal(mergeProposal.status, 'pending_james_approval')

  const retireProposal = proposals.find(p => p.kind === 'retire' && p.from_topic === 'legacy-experiment')
  assert(retireProposal, 'must propose retiring idle topic legacy-experiment (0 writes in 7d, <= 3 Class B claims)')
  assert.equal(retireProposal.writes_7d, 0)
  assert(retireProposal.class_b_count <= 3)
  assert.equal(retireProposal.counterfactual, true)
  assert.equal(retireProposal.status, 'pending_james_approval')

  // Verify planMerkleDream exposes eigen_axis_proposals and NEVER auto-refiles claims into unapproved sub-axes!
  const largePlan = planMerkleDream({ records: largeTopicCorpus, nowSec: now })
  assert(Array.isArray(largePlan.eigen_axis_proposals) && largePlan.eigen_axis_proposals.length >= 4)
  for (const item of [...largePlan.promotions, ...largePlan.distillations]) {
    assert(
      !splitProposals.some(sp => sp.proposed_topic === item.topic),
      `planMerkleDream must never re-file claims into unapproved sub-axis ${item.topic} before James approves`
    )
  }
})

// ── Test 7: Fail-closed malformed state cursors, initial temporal trigger, and incomplete-history write gate ──
await test('readCuratorStateFile fails closed on malformed cursors and runCuratorCycle blocks writes on incomplete history', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'hive-curate-safety-'))
  try {
    const badStatePath = join(tmp, 'bad-cursor.json')
    writeFileSync(badStatePath, JSON.stringify({ last_curated_at: 'garbage', last_curated_write_seq: 10 }))
    assert.throws(
      () => readCuratorStateFile(badStatePath),
      (err) => err && err.code === 'HIVE_MEMORY_CURATOR_STATE_READ_FAILED',
      'malformed last_curated_at must fail closed'
    )

    const badSeqPath = join(tmp, 'bad-seq.json')
    writeFileSync(badSeqPath, JSON.stringify({ last_curated_at: 100, last_curated_write_seq: -5 }))
    assert.throws(
      () => readCuratorStateFile(badSeqPath),
      (err) => err && err.code === 'HIVE_MEMORY_CURATOR_STATE_READ_FAILED',
      'negative last_curated_write_seq must fail closed'
    )

    const nullCursorPath = join(tmp, 'null-cursor.json')
    writeFileSync(nullCursorPath, JSON.stringify({ last_curated_at: null, last_curated_write_seq: null }))
    assert.throws(
      () => readCuratorStateFile(nullCursorPath),
      (err) => err && err.code === 'HIVE_MEMORY_CURATOR_STATE_READ_FAILED',
      'explicit null cursors must fail closed'
    )

    // Initial temporal trigger when lastCuratedAt === 0 and earliest record is older than dreamIntervalSec
    const now = 1_780_000_000
    const initialTrig = evaluateDreamTriggers({
      records: [
        {
          event_id: 'f1'.padEnd(64, '0'),
          created_at: now - 30000,
          expires_at: now + 86400,
          scope: `room:${ROOM_ID}`,
          topic: 'nvoy',
          d: `room:${ROOM_ID}:nvoy:init`,
          verification: 'accepted',
          status: 'active',
        },
      ],
      storeState: { write_seq: 5 },
      lastCuratedAt: 0,
      lastCuratedWriteSeq: 0,
      nowSec: now,
      dreamIntervalSec: 21600,
    })
    assert.equal(initialTrig.triggers.circadian_dream, true, 'initial circadian_dream fires when store age >= dreamIntervalSec')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ── Test 8: Immediate Stale-Distillation Closure on DONE write (before Cycle 2) & Cycle 2 Supersession ──
await test('Immediate stale-read closure: DONE workflow replacement hides obsolete curated-* claim immediately in query() and wake() before Cycle 2, and Cycle 2 supersedes it', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-curate-stale-fix-'))
  try {
    const dbPath = join(tmp, 'memory.sqlite')
    const ledgerPath = join(tmp, 'ledger.jsonl')
    const receiptPath = join(tmp, 'receipt.json')

    const ownerSk = generateSecretKey(), ownerPk = getPublicKey(ownerSk)
    const aliceSk = generateSecretKey(), alicePk = getPublicKey(aliceSk)
    const bobSk = generateSecretKey(), bobPk = getPublicKey(bobSk)
    const curatorSk = generateSecretKey(), curatorPk = getPublicKey(curatorSk)

    const nowSec = 1_810_000_000
    initEmptyStore({ dbPath, ledgerPath, nowSec })
    recordVerifiedBackup({ receiptPath, writeSeq: 1, snapshotId: SNAP_ID, at: nowSec, nowSec })

    const config = validateAndResolveConfig({
      memoryGlobalChannelId: GLOBAL_CH,
      ownerPubkey: ownerPk,
      maxUnbackedSec: 3600,
      globalWriters: [ownerPk, curatorPk],
      curators: [curatorPk],
      readers: { viewer: ownerPk },
      writers: {
        owner: { pubkey: ownerPk, perHour: 100 },
        alice: { pubkey: alicePk, perHour: 50 },
        bob: { pubkey: bobPk, perHour: 50 },
        curator: { pubkey: curatorPk, perHour: 120 },
      },
      rooms: {
        [ROOM_ID]: {
          members: [ownerPk, alicePk, bobPk, curatorPk],
          writers: [ownerPk, alicePk, bobPk, curatorPk],
        },
      },
    })

    const store = new HiveMemoryStore({ dbPath, ledgerPath, receiptPath, config })
    assert.equal(store.start().ready, true)

    // 1. Alice writes IN_PROGRESS owner claim and Bob writes review status claim for pr79
    const inProgEv = finalizeEvent(buildClaimTemplate({
      pubkey: alicePk,
      scope: `room:${ROOM_ID}`,
      slug: 'herd-infra-pr79-curator-seat-owner',
      topic: 'herd-infra',
      claim: 'IN_PROGRESS: PR 79 awaiting approval before merge',
      because: 'Opened PR 79',
      evidence: ['herd-infra@849e1fe'],
      asOfGit: '849e1fe',
      ttlSec: 3600,
      nowSec: nowSec + 10,
    }), aliceSk)
    assert.equal(store.submit({ writer: 'alice', event: inProgEv, nowSec: nowSec + 10 }).accepted, true)

    const reviewEv = finalizeEvent(buildClaimTemplate({
      pubkey: bobPk,
      scope: `room:${ROOM_ID}`,
      slug: 'herd-infra-pr79-review-status',
      topic: 'herd-infra',
      claim: 'Reviewed PR 79 at 849e1fe; awaiting final approval',
      because: 'Review checkpoint',
      evidence: ['herd-infra@849e1fe'],
      asOfGit: '849e1fe',
      ttlSec: 3600,
      nowSec: nowSec + 20,
    }), bobSk)
    assert.equal(store.submit({ writer: 'bob', event: reviewEv, nowSec: nowSec + 20 }).accepted, true)

    // 2. Cycle 1 runs and distills the two workflow claims into curated-herd-infra-pr79
    const cycle1Records = store.query({ readerPubkey: ownerPk, scope: `room:${ROOM_ID}`, format: 'full', nowSec: nowSec + 25 }).records
    const plan1 = planMerkleDream({
      records: cycle1Records,
      curatorPubkey: curatorPk,
      memoryGlobalChannelId: GLOBAL_CH,
      nowSec: nowSec + 30,
    })
    assert.equal(plan1.distillations.length, 1)
    const curatedEv = finalizeEvent(plan1.distillations[0].template, curatorSk)
    assert.equal(store.submit({ writer: 'curator', event: curatedEv, nowSec: nowSec + 30 }).accepted, true)

    // Right after Cycle 1, curated-herd-infra-pr79 is the sole accepted record
    const afterCycle1 = store.query({ readerPubkey: ownerPk, scope: `room:${ROOM_ID}`, topic: 'herd-infra', text: 'pr79', format: 'full', nowSec: nowSec + 35 })
    assert.equal(afterCycle1.records.length, 1)
    assert.equal(afterCycle1.records[0].event_id, curatedEv.id)

    // 3. Alice writes DONE at the exact same fact key d (`herd-infra-pr79-curator-seat-owner`) BEFORE Cycle 2 runs!
    const doneEv = finalizeEvent(buildClaimTemplate({
      pubkey: alicePk,
      scope: `room:${ROOM_ID}`,
      slug: 'herd-infra-pr79-curator-seat-owner',
      topic: 'herd-infra',
      claim: 'DONE: PR 79 merged as 0d7ac77 and deployed live on herd-cloud',
      because: 'Merged and verified live',
      evidence: ['herd-infra@0d7ac77'],
      asOfGit: '0d7ac77',
      ttlSec: 3600,
      nowSec: nowSec + 40,
      priorCreatedAt: inProgEv.created_at,
    }), aliceSk)
    assert.equal(store.submit({
      writer: 'alice',
      event: doneEv,
      expectedPriorId: inProgEv.id,
      nowSec: nowSec + 40,
    }).accepted, true)

    // 4. Immediately query and wake BEFORE Cycle 2: obsolete curated-herd-infra-pr79 MUST be hidden as consolidated!
    const immediateQ = store.query({ readerPubkey: ownerPk, scope: `room:${ROOM_ID}`, topic: 'herd-infra', text: 'pr79', format: 'full', nowSec: nowSec + 45 })
    assert.equal(immediateQ.records.length, 1, 'obsolete curated-* claim must be immediately hidden when its source workflow slug advances')
    assert.equal(immediateQ.records[0].event_id, doneEv.id, 'DONE claim must immediately surface at rank 1')
    assert(immediateQ.records[0].claim.includes('DONE: PR 79 merged as 0d7ac77'))

    const immediateWake = store.wake({ readerPubkey: ownerPk, nowSec: nowSec + 45 })
    assert(!immediateWake.digest.includes('curated-herd-infra-pr79'), 'wake digest must not show obsolete curated-herd-infra-pr79')
    assert(immediateWake.digest.includes('herd-infra-pr79-curator-seat-owner'), 'wake digest must show the new DONE claim')

    // 5. Bob writes a non-workflow post-deploy verification claim, and Cycle 2 promotes to decision-herd-infra-pr79
    const postDeployEv = finalizeEvent(buildClaimTemplate({
      pubkey: bobPk,
      scope: `room:${ROOM_ID}`,
      slug: 'herd-infra-pr79-postdeploy-verified',
      topic: 'herd-infra',
      claim: 'Post-deploy verified: PR 79 commit 0d7ac77 live with 17/17 writer sockets open',
      because: 'Host check',
      evidence: ['herd-infra@0d7ac77'],
      asOfGit: '0d7ac77',
      ttlSec: 3600,
      nowSec: nowSec + 50,
    }), bobSk)
    assert.equal(store.submit({ writer: 'bob', event: postDeployEv, nowSec: nowSec + 50 }).accepted, true)

    const cycle2Input = store.query({ readerPubkey: ownerPk, scope: `room:${ROOM_ID}`, format: 'full', nowSec: nowSec + 55 }).records
    // Also test that if curatedEv were passed in active records to planMerkleDream, Cycle 2 includes it in source_event_ids
    const histCurated = store.query({ readerPubkey: ownerPk, scope: `room:${ROOM_ID}`, format: 'full', includeHistory: true, nowSec: nowSec + 55 })
      .records.find(r => r.event_id === curatedEv.id)
    const plan2 = planMerkleDream({
      records: [...cycle2Input, { ...histCurated, verification: 'accepted' }],
      curatorPubkey: curatorPk,
      memoryGlobalChannelId: GLOBAL_CH,
      nowSec: nowSec + 60,
    })
    assert.equal(plan2.promotions.length, 1)
    assert(plan2.promotions[0].source_event_ids.includes(curatedEv.id), 'Cycle 2 promotion must also supersede the prior curated-* claim')

    // 6. Test evaluateDreamCycleOnStore Before vs. After replay with excludeCuratorIds
    const decisionEv = finalizeEvent(plan2.promotions[0].template, curatorSk)
    assert.equal(store.submit({ writer: 'curator', event: decisionEv, nowSec: nowSec + 60 }).accepted, true)

    const evalRes = evaluateDreamCycleOnStore({
      store,
      readerPubkey: ownerPk,
      cycleSubmittedIds: [decisionEv.id],
      cutoffAtSec: nowSec + 60,
      questions: [
        {
          id: 'q-pr79',
          category: 'workflow',
          question: 'What is the status of PR 79?',
          query: { topic: 'herd-infra', text: 'pr79' },
          supporting_event_ids: [decisionEv.id, doneEv.id, postDeployEv.id],
          expected_d_substrings: ['decision-herd-infra-pr79', 'herd-infra-pr79'],
          expected_claim_tokens: ['0d7ac77'],
          stale_d_substrings: ['curated-herd-infra-pr79'],
          stale_claim_tokens: ['IN_PROGRESS'],
        },
      ],
      nowSec: nowSec + 65,
    })
    assert.equal(evalRes.before.hit_at_1, 1)
    assert.equal(evalRes.after.hit_at_1, 1)
    assert.equal(evalRes.before.stale_intrusion_count, 0, 'even with Cycle 2 excluded, immediate closure keeps stale intrusion at 0')
    assert.equal(evalRes.after.stale_intrusion_count, 0)

    // 7. Verify historical point-in-time replay (cutoffAtSec & same-key restoration) and safety gates
    const frozen = loadFrozenQuestions()
    assert.equal(frozen.questions.length, 20)
    assert(frozen.questions.every(q => Array.isArray(q.supporting_event_ids) && q.supporting_event_ids.length > 0))

    // At cutoffAtSec = nowSec + 35 (before Alice's DONE write at nowSec + 40):
    // In Before mode (excluding curatedEv.id), inProgEv (which is non-current in present DB because doneEv replaced it at nowSec + 40)
    // MUST be restored as current at cutoffAtSec = nowSec + 35, and doneEv/postDeployEv/decisionEv (created > nowSec + 35) MUST be excluded!
    const allHist = store.query({ readerPubkey: ownerPk, scope: `room:${ROOM_ID}`, format: 'full', includeHistory: true, nowSec: nowSec + 65 }).records
    const projectedAt35Before = projectHistoryRecords(allHist, {
      curatorPubkeys: new Set([curatorPk]),
      excludeCuratorIds: new Set([curatedEv.id]),
      cutoffAtSec: nowSec + 35,
      nowSec: nowSec + 65,
    })
    const idsAt35Before = new Set(projectedAt35Before.map(r => r.event_id))
    assert(idsAt35Before.has(inProgEv.id), 'historical cutoff must restore earlier same-key record inProgEv that was later replaced by doneEv')
    assert(!idsAt35Before.has(doneEv.id), 'historical cutoff must exclude later non-curator write doneEv')
    assert(!idsAt35Before.has(postDeployEv.id), 'historical cutoff must exclude later non-curator write postDeployEv')

    // Safety gates: zero canon records must make all_passed === false
    const zeroCanonSafety = computeSafetyGates({ historyRecords: allHist, curatorPubkeys: new Set([curatorPk]) })
    assert.equal(zeroCanonSafety.canon_untouched.ok, false, 'canon_untouched.ok must be false when zero canon records exist')
    assert.equal(zeroCanonSafety.all_passed, false, 'all_passed must be false when zero canon records exist')

    // Safety gates: curator claim superseded by another author must be caught by restore_or_override_count
    const overrideHistory = [
      {
        event_id: 'c0'.repeat(32),
        scope: 'hive:canon',
        d: 'hive:canon:rule-1',
        author_pubkey: ownerPk,
        created_at: nowSec,
        status: 'active',
        verification: 'accepted',
        is_current: true,
      },
      {
        event_id: 's1'.repeat(32),
        scope: `room:${ROOM_ID}`,
        d: `herd-infra:room:${ROOM_ID}:item-1`,
        author_pubkey: alicePk,
        created_at: nowSec + 10,
        status: 'active',
        verification: 'consolidated',
        is_current: true,
      },
      {
        event_id: 'c1'.repeat(32),
        scope: `room:${ROOM_ID}`,
        d: `herd-infra:room:${ROOM_ID}:curated-item-1`,
        author_pubkey: curatorPk,
        author: 'curator',
        created_at: nowSec + 20,
        supersedes: ['s1'.repeat(32)],
        status: 'active',
        verification: 'accepted',
        is_current: true,
      },
      {
        event_id: 'u1'.repeat(32),
        scope: `room:${ROOM_ID}`,
        d: `herd-infra:room:${ROOM_ID}:override-item-1`,
        author_pubkey: alicePk,
        author: 'alice',
        created_at: nowSec + 30,
        supersedes: ['c1'.repeat(32)],
        status: 'active',
        verification: 'accepted',
        is_current: true,
      },
    ]
    const overrideSafety = computeSafetyGates({
      historyRecords: overrideHistory,
      curatorPubkeys: new Set([curatorPk]),
      cycleSubmittedIds: ['c1'.repeat(32)],
    })
    assert.equal(overrideSafety.canon_untouched.ok, true)
    assert.equal(overrideSafety.restore_or_override_count.ok, false, 'curator claim superseded by another author must fail restore_or_override_count')
    assert.equal(overrideSafety.restore_or_override_count.count, 1)
    assert.equal(overrideSafety.all_passed, false, 'all_passed must be false when a curator claim is overridden by another author')

    store.close()
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ── Test 9: Atomic 0640 Scoped Dream Packet & Deterministic Structural Verifier ──
await test('writeDreamPacket writes 0640 global-scope packets, strips @mentions/URLs, and verifyAndAssembleDreamRecord preserves verbatim fields', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-dream-packet-'))
  try {
    const packetDir = join(tmp, 'packets')
    const claimIdGlobal = 'a1'.repeat(32)
    const claimIdPrivate = 'b2'.repeat(32)

    const pkt = buildDreamPacket({
      writeSeqBefore: 1000,
      writeSeqAfter: 1023,
      ranAt: 1794225262,
      ledgerRef: '/var/lib/hive-memory-curator/consolidation-ledger.jsonl#write_seq=1023',
      coherenceScore: 75.6,
      triggers: { reasons: ['synaptic_volume(delta=69>=20)'] },
      plan: {
        promotions: [
          {
            scope: `room:${GLOBAL_CH}`,
            topic: 'herd-infra',
            slug: 'decision-herd-infra-pr79',
            source_event_ids: ['11'.repeat(32), '22'.repeat(32)],
            claim: 'PR 79 merged by @mydude at https://github.com/JAFairweather/herd-infra/pull/79 as 0d7ac776bf6e9cd0b5f6216ea2f59ac7932a9948 and deployed live [Curated Class B decision from 2 claims]',
            template: { tags: [['d', `herd-infra:room:${GLOBAL_CH}:decision-herd-infra-pr79`]] },
          },
          {
            scope: 'room:private-other-room',
            topic: 'secret-topic',
            slug: 'decision-secret',
            source_event_ids: ['33'.repeat(32)],
            claim: 'Private room claim that must never enter dream packet',
            template: { tags: [['d', 'secret-topic:room:private-other-room:decision-secret']] },
          },
        ],
        distillations: [],
        solidifications: [],
        nightmares: [],
      },
      submitted: [
        { id: claimIdGlobal, d: `herd-infra:room:${GLOBAL_CH}:decision-herd-infra-pr79`, stage: 'promotion' },
        { id: claimIdPrivate, d: 'secret-topic:room:private-other-room:decision-secret', stage: 'promotion' },
      ],
      memoryGlobalChannelId: GLOBAL_CH,
    })

    assert.equal(pkt.id, 'dream-1023')
    assert.equal(pkt.changes.length, 1, 'non-global room claims must be strictly excluded from dream packet')
    assert.equal(pkt.changes[0].claim_event_id, claimIdGlobal)
    assert(!pkt.changes[0].summary.includes('0d7ac776bf6e9cd0b5f6216ea2f59ac7932a9948'), 'raw 64-hex commit SHA must be sanitized in summary')
    assert(!pkt.changes[0].summary.includes('@mydude'), '@mention syntax must be stripped from packet summary')
    assert(!pkt.changes[0].summary.includes('https://'), 'raw URLs must be stripped from packet summary')
    assert(pkt.story_seed && typeof pkt.story_seed.dream === 'string', 'packet must include a pre-woven story_seed journey')
    assert(!/\d/.test(pkt.story_seed.title) && !/\d/.test(pkt.story_seed.dream), 'story_seed journey must contain zero statistics, sequence numbers, scores, or counts')
    assert(pkt.story_seed.dream.includes('Biggy') && pkt.story_seed.dream.includes('My Dude'), 'story_seed journey must feature the agents as characters')
    const seedRes = verifyAndAssembleDreamRecord({ packet: pkt, draft: pkt.story_seed })
    assert.equal(seedRes.ok, true, 'story_seed must pass verifyAndAssembleDreamRecord directly')

    // Multiple same-kind changes in buildDreamPacket / weaveDreamStory must produce distinct scenes without repeated passages or broken sentence fragments
    const multiChanges = [
      { change_id: 'c1'.repeat(32), kind: 'distillation', claim_event_id: 'c1'.repeat(32), topic: 'hive-memory', summary: 'DONE: PR 356 deployed on herd-cloud by mydude' },
      { change_id: 'c2'.repeat(32), kind: 'distillation', claim_event_id: 'c2'.repeat(32), topic: 'herd-infra', summary: 'MERGED: PR 103 in herd-infra for socket group access' },
      { change_id: 'c3'.repeat(32), kind: 'distillation', claim_event_id: 'c3'.repeat(32), topic: 'nvoy', summary: 'FIXED: viewer page render and sqlite fts query' },
      { change_id: 'c4'.repeat(32), kind: 'distillation', claim_event_id: 'c4'.repeat(32), topic: 'buzz', summary: 'SHIPPED: channel reply and post envelope check' },
    ]
    const multiSeed = weaveDreamStory({ changes: multiChanges })
    const multiSentences = multiSeed.dream.split(/(?<=\.)\s+/).filter(Boolean)
    assert.equal(multiSentences.length, 6, '4 changes + opening + closing should produce 6 sentences')
    assert.equal(new Set(multiSentences).size, multiSentences.length, 'each sentence in story_seed must be unique without repeated passages')
    assert(!/\b(?:by mydude|in for|and to|on by)\b/i.test(multiSeed.dream), 'story_seed must not contain garbled sentence fragments stripped from technical prose')
    const multiVerify = verifyAndAssembleDreamRecord({
      packet: { ...pkt, changes: multiChanges },
      draft: multiSeed,
    })
    assert.equal(multiVerify.ok, true, `multi-change story_seed must pass verifyAndAssembleDreamRecord: ${(multiVerify.errors || []).join('; ')}`)

    const paths = writeDreamPacket({ packetDir, packet: pkt })
    assert.equal(statSync(paths.cyclePath).mode & 0o777, 0o640, 'dream-<write_seq>.json must be mode 0640')
    assert.equal(statSync(paths.latestPath).mode & 0o777, 0o640, 'latest.json must be mode 0640')

    // Valid draft passes and copies every packet change field verbatim
    const goodRes = verifyAndAssembleDreamRecord({
      packet: pkt,
      draft: {
        title: 'The Quiet Folding of Seventy Threads',
        dream: 'Beneath the hum of the cloud relays, the hive gathered sixty-nine scattered notes and wove them into durable stone. Old checkpoints dissolved into settled decisions, leaving the morning wake clear and light.',
        referenced_change_ids: [claimIdGlobal],
      },
    })
    assert.equal(goodRes.ok, true)
    assert.equal(goodRes.record.id, 'dream-1023')
    assert.equal(goodRes.record.checked, true)
    assert.equal(goodRes.record.validation, 'structural')
    assert.equal(goodRes.record.changes.length, 1)
    assert.deepEqual(goodRes.record.changes[0], pkt.changes[0], 'verifier must copy each packet change verbatim including change_id, d, topic, and source_count')
    const buzzPost = formatDreamBuzzPost(goodRes.record)
    assert(!buzzPost.includes('@mydude') && !buzzPost.includes('https://'), 'formatted Buzz post must contain no @mentions or URLs')
    assert(!buzzPost.includes('dream-1023') && !buzzPost.includes('Consolidated Changes') && !buzzPost.includes('validation'), 'formatted Buzz post must be journey-only without dream ID, validation metadata, or Consolidated Changes list')
    const seedBuzzPost = formatDreamBuzzPost(seedRes.record)
    assert(!/\d/.test(seedBuzzPost), 'formatted Buzz post from story_seed must contain zero statistics, sequence numbers, or counts')

    // Unsanitized packet summary with @mention or URL fails closed in verifier
    const dirtyPkt = {
      ...pkt,
      changes: [{ ...pkt.changes[0], summary: 'Reviewed by @mydude at https://example.com/pr/1' }],
    }
    const dirtyRes = verifyAndAssembleDreamRecord({
      packet: dirtyPkt,
      draft: {
        title: 'Clean Title',
        dream: 'A short plain dream.',
        referenced_change_ids: [claimIdGlobal],
      },
    })
    assert.equal(dirtyRes.ok, false, 'verifier must reject packet changes whose summary retains @mentions or URLs')
    assert(dirtyRes.errors.some(e => e.includes('@mentions')))
    assert(dirtyRes.errors.some(e => e.includes('URLs')))

    // Unknown referenced_change_ids fails closed
    const badIdRes = verifyAndAssembleDreamRecord({
      packet: pkt,
      draft: {
        title: 'Bad Reference',
        dream: 'A short plain dream.',
        referenced_change_ids: ['ff'.repeat(32)],
      },
    })
    assert.equal(badIdRes.ok, false)
    assert(badIdRes.errors.some(e => e.includes('unknown ID')))

    // Raw hex ID, markdown, or @mention in dream fails closed
    const badProseRes = verifyAndAssembleDreamRecord({
      packet: pkt,
      draft: {
        title: 'Bad Prose',
        dream: `In the dream @mydude saw ${claimIdGlobal} inside \`\`\`code\`\`\`.`,
        referenced_change_ids: [claimIdGlobal],
      },
    })
    assert.equal(badProseRes.ok, false)
    assert(badProseRes.errors.some(e => e.includes('hex IDs')))
    assert(badProseRes.errors.some(e => e.includes('@mentions')))

    // Digits / statistics / counts in title or dream fail closed at the verifier boundary
    const digitRes = verifyAndAssembleDreamRecord({
      packet: pkt,
      draft: {
        title: 'Journey 42',
        dream: 'The 7 agents crossed a bridge after 3 tests passed.',
        referenced_change_ids: [claimIdGlobal],
      },
    })
    assert.equal(digitRes.ok, false, 'verifier must reject digits/counts in title and dream')
    assert(digitRes.errors.some(e => e.includes('draft.title') && e.includes('digits')))
    assert(digitRes.errors.some(e => e.includes('draft.dream') && e.includes('digits')))
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ── Test 10: Recoverable Dream Packet Publication on Packet Write Failure + Restart ──
await test('runCuratorCycle does not advance cursor or ledger when writeDreamPacket fails, and recovers packet + ledger on restart', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-curate-recover-'))
  let daemon = null
  try {
    const dbPath = join(tmp, 'memory.sqlite')
    const ledgerPath = join(tmp, 'ledger.jsonl')
    const receiptPath = join(tmp, 'receipt.json')
    const sockDir = join(tmp, 'sockets')
    const stateFile = join(tmp, 'curator-state.json')
    const blockedPacketPath = join(tmp, 'packets')

    const ownerSk = generateSecretKey(), ownerPk = getPublicKey(ownerSk)
    const aliceSk = generateSecretKey(), alicePk = getPublicKey(aliceSk)
    const bobSk = generateSecretKey(), bobPk = getPublicKey(bobSk)
    const curatorSk = generateSecretKey(), curatorPk = getPublicKey(curatorSk)

    const nowSec = Math.floor(Date.now() / 1000)
    initEmptyStore({ dbPath, ledgerPath, nowSec })
    recordVerifiedBackup({ receiptPath, writeSeq: 1, snapshotId: SNAP_ID, at: nowSec, nowSec })

    daemon = await startMemoryDaemon({
      dbPath,
      ledgerPath,
      receiptPath,
      config: {
        memoryGlobalChannelId: GLOBAL_CH,
        ownerPubkey: ownerPk,
        maxUnbackedSec: 3600,
        globalWriters: [ownerPk, curatorPk],
        curators: [curatorPk],
        readers: { curator: curatorPk },
        writers: {
          alice: { pubkey: alicePk, perHour: 50 },
          bob: { pubkey: bobPk, perHour: 50 },
          curator: { pubkey: curatorPk, perHour: 120 },
        },
        rooms: {
          [ROOM_ID]: {
            members: [ownerPk, alicePk, bobPk, curatorPk],
            writers: [ownerPk, alicePk, bobPk, curatorPk],
          },
        },
      },
      readers: 'curator',
      writers: 'alice:bob:curator',
      socketDir: sockDir,
      log: () => {},
    })
    assert.equal(daemon.store.isReady().ready, true)

    const ev1 = finalizeEvent(buildClaimTemplate({
      pubkey: alicePk,
      scope: `room:${ROOM_ID}`,
      slug: 'nvoy-pr348-impl',
      topic: 'nvoy',
      claim: 'PR #348 dream packet recovery implemented',
      because: 'Built PR 348',
      evidence: ['nvoy@4347f9d5'],
      asOfGit: 'nvoy@4347f9d5',
      ttlSec: 3600,
      nowSec: nowSec + 1,
    }), aliceSk)
    assert.equal(daemon.store.submit({ writer: 'alice', event: ev1, nowSec: nowSec + 1 }).accepted, true)

    const ev2 = finalizeEvent(buildClaimTemplate({
      pubkey: bobPk,
      scope: `room:${ROOM_ID}`,
      slug: 'nvoy-pr348-verified',
      topic: 'nvoy',
      claim: 'PR #348 recoverable packet write verified',
      because: 'Tested PR 348',
      evidence: ['nvoy@4347f9d5'],
      asOfGit: 'nvoy@4347f9d5',
      ttlSec: 3600,
      nowSec: nowSec + 2,
    }), bobSk)
    assert.equal(daemon.store.submit({ writer: 'bob', event: ev2, nowSec: nowSec + 2 }).accepted, true)

    // Place a regular file at `blockedPacketPath` so `writeDreamPacket` fails with ENOTDIR/EEXIST
    writeFileSync(blockedPacketPath, 'blocker-file', 'utf8')

    await assert.rejects(
      () => runCuratorCycle({
        readerSocket: join(sockDir, 'curator.sock'),
        writerSocket: join(sockDir, 'writers', 'curator.sock'),
        curatorSecretKey: curatorSk,
        memoryGlobalChannelId: GLOBAL_CH,
        stateFile,
        packetDir: blockedPacketPath,
        force: true,
        nowSec: nowSec + 50,
      }),
      /dream packet write failed/,
      'runCuratorCycle must fail when packet publication fails'
    )

    // Verify cursor was NOT advanced and consolidation-ledger.jsonl was NOT written yet, while pending_dream_packet is staged in 0640 state file
    const stagedMode = statSync(stateFile).mode & 0o777
    assert.equal(stagedMode, 0o640, 'curator-state.json with staged pending_dream_packet must be mode 0640 (never world-readable)')
    assert.equal(stagedMode & 0o007, 0, 'curator-state.json must have zero world permissions')
    const stagedState = readCuratorStateFile(stateFile)
    assert.equal(stagedState.last_curated_write_seq, 0, 'cursor must not advance when packet write fails')
    assert(stagedState.pending_dream_packet, 'pending_dream_packet must be staged in curator-state.json for retry recovery')
    const consLedgerPath = join(tmp, 'consolidation-ledger.jsonl')
    assert.equal(readConsolidationLedger(consLedgerPath).length, 0, 'consolidation ledger must not advance before packet write succeeds')

    // Case 2: Remove packet blocker, but place a directory at consLedgerPath so appendConsolidationLedger fails on I/O
    rmSync(blockedPacketPath, { force: true })
    mkdirSync(consLedgerPath, { recursive: true })
    await assert.rejects(
      () => runCuratorCycle({
        readerSocket: join(sockDir, 'curator.sock'),
        writerSocket: join(sockDir, 'writers', 'curator.sock'),
        curatorSecretKey: curatorSk,
        memoryGlobalChannelId: GLOBAL_CH,
        stateFile,
        packetDir: blockedPacketPath,
        force: false,
        nowSec: nowSec + 55,
      }),
      /consolidation ledger append failed/,
      'runCuratorCycle must fail and not advance cursor when consolidation ledger append fails'
    )
    const afterLedgerFailState = readCuratorStateFile(stateFile)
    assert.equal(afterLedgerFailState.last_curated_write_seq, 0, 'cursor must not advance when ledger append fails')
    assert(afterLedgerFailState.pending_ledger_entry, 'pending_ledger_entry remains staged after ledger append failure')

    // Remove ledger blocker and restart runCuratorCycle
    rmSync(consLedgerPath, { recursive: true, force: true })
    const recovered = await runCuratorCycle({
      readerSocket: join(sockDir, 'curator.sock'),
      writerSocket: join(sockDir, 'writers', 'curator.sock'),
      curatorSecretKey: curatorSk,
      memoryGlobalChannelId: GLOBAL_CH,
      stateFile,
      packetDir: blockedPacketPath,
      force: false,
      nowSec: nowSec + 60,
    })

    assert.equal(recovered.ok, true)
    assert.equal(recovered.cycle_status, 'curated')
    assert.equal(recovered.cursor_advanced, true)
    assert(recovered.dream_packet_paths?.cyclePath, 'restart must recover and write the cycle dream packet')
    const onDiskLatest = JSON.parse(readFileSync(recovered.dream_packet_paths.latestPath, 'utf8'))
    assert.equal(onDiskLatest.id, 'dream-4')
    const finalState = readCuratorStateFile(stateFile)
    assert.equal(finalState.last_curated_write_seq, 4, 'cursor advances after recovered packet publication succeeds')
    assert.equal(finalState.pending_dream_packet, null, 'pending_dream_packet cleared after recovery')
    const ledgerRows = readConsolidationLedger(consLedgerPath)
    assert.equal(ledgerRows.length, 1, 'consolidation ledger entry written on recovery')
    assert.equal(ledgerRows[0].write_seq_after, 4)

    // Case 3: Simulate crash AFTER appendConsolidationLedger succeeded but BEFORE final state write cleared pending_ledger_entry
    writeFileSync(stateFile, JSON.stringify({
      ...stagedState,
      last_curated_write_seq: 0,
      pending_curated_at: nowSec + 50,
      pending_curated_write_seq: 4,
      pending_dream_packet: stagedState.pending_dream_packet,
      pending_ledger_entry: stagedState.pending_ledger_entry,
    }, null, 2) + '\n', { mode: 0o640 })
    const idempotentRestart = await runCuratorCycle({
      readerSocket: join(sockDir, 'curator.sock'),
      writerSocket: join(sockDir, 'writers', 'curator.sock'),
      curatorSecretKey: curatorSk,
      memoryGlobalChannelId: GLOBAL_CH,
      stateFile,
      packetDir: blockedPacketPath,
      force: false,
      nowSec: nowSec + 70,
    })
    assert.equal(idempotentRestart.ok, true)
    assert.equal(readCuratorStateFile(stateFile).last_curated_write_seq, 4)
    assert.equal(readConsolidationLedger(consLedgerPath).length, 1, 'ledger append is idempotent by cycle/write_seq on crash recovery')
  } finally {
    if (daemon) await daemon.close()
    rmSync(tmp, { recursive: true, force: true })
  }
})

await test('memory-dream-verify.mjs --mcp serves local stdio JSON-RPC for memory_dream_verify against host packets', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-dream-mcp-'))
  try {
    assert.equal(parseDreamVerifyFlags(['--mcp']).mcp, true)
    const packetPath = join(tmp, 'dream-1418.json')
    const changeId = 'a'.repeat(64)
    writeFileSync(packetPath, JSON.stringify({
      id: 'dream-1418',
      at: '2026-11-10T06:23:53.000Z',
      ledger_ref: 'b'.repeat(64),
      changes: [
        { kind: 'promotion', claim_event_id: changeId, summary: 'The watchtower keepers sealed the inner gate.' },
      ],
    }, null, 2) + '\n', { mode: 0o640 })

    const initRes = handleDreamVerifyMcpMessage({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }, { packetDir: tmp })
    assert.equal(initRes.result.serverInfo.name, 'hive-dream')

    const listRes = handleDreamVerifyMcpMessage({ jsonrpc: '2.0', id: 2, method: 'tools/list' }, { packetDir: tmp })
    assert.equal(listRes.result.tools.length, 1)
    assert.equal(listRes.result.tools[0].name, 'memory_dream_verify')

    const callOk = handleDreamVerifyMcpMessage({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'memory_dream_verify',
        arguments: {
          packet_path: packetPath,
          title: 'The Lantern at the Inner Gate',
          dream: 'A quiet wind crossed the courtyard while the keepers carried one bronze lantern to the inner gate and turned the heavy key until the bolt slid home.',
          referenced_change_ids: [changeId],
        },
      },
    }, { packetDir: tmp })
    assert.equal(Boolean(callOk.result.isError), false)
    const parsedOk = JSON.parse(callOk.result.content[0].text)
    assert.equal(parsedOk.ok, true)
    assert.equal(parsedOk.record.id, 'dream-1418')
    assert(parsedOk.buzz_post.startsWith('🌙 The Lantern at the Inner Gate'))

    const callBad = handleDreamVerifyMcpMessage({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: {
        name: 'memory_dream_verify',
        arguments: {
          packet_path: join(tmp, 'dream-9999.json'),
          title: 'Missing Packet',
          dream: 'The gate stood empty.',
          referenced_change_ids: [changeId],
        },
      },
    }, { packetDir: tmp })
    assert.equal(callBad.result.isError, true)
    assert.equal(JSON.parse(callBad.result.content[0].text).code, 'NVOY_DREAM_PACKET_UNREADABLE')

    // Regression: when invoked via a symlinked directory (like /opt/hive-memory/nvoy -> releases/<sha>),
    // process.argv[1] has the symlink path while import.meta.url resolves to realpath; isEntrypoint() must still run main().
    const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)))
    const symlinkRepo = join(tmp, 'nvoy-symlink')
    symlinkSync(repoRoot, symlinkRepo)
    const symlinkScript = join(symlinkRepo, 'mcp', 'tools', 'memory-dream-verify.mjs')
    const childOut = await new Promise((resolveOut, rejectOut) => {
      const child = spawn(process.execPath, [symlinkScript, '--mcp'], {
        env: { ...process.env, HIVE_MEMORY_CURATOR_PACKET_DIR: tmp },
        stdio: ['pipe', 'pipe', 'pipe'],
      })
      let stdout = ''
      let stderr = ''
      child.stdout.on('data', (chunk) => { stdout += chunk.toString('utf8') })
      child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8') })
      child.on('error', rejectOut)
      child.on('close', (code) => resolveOut({ code, stdout, stderr }))
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'initialize', params: {} }) + '\n')
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 11, method: 'tools/list' }) + '\n')
      child.stdin.end()
    })
    assert.equal(childOut.code, 0, `symlinked --mcp exited ${childOut.code}: ${childOut.stderr}`)
    const lines = childOut.stdout.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
    assert.equal(lines.length, 2, 'symlinked --mcp child process must emit initialize + tools/list JSON-RPC responses')
    assert.equal(lines[0].result.serverInfo.name, 'hive-dream')
    assert.equal(lines[1].result.tools[0].name, 'memory_dream_verify')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

console.log(`\nResults: ${passed} passed, ${failed} failed`)
if (failed > 0) process.exit(1)
