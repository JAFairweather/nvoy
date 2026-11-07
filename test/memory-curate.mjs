// test/memory-curate.mjs — Unit and live-socket integration tests for Phase 2 Merkle Dreaming,
// Curation (Distillation -> Promotion -> Solidification), and Nightmare handling.

import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
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
  evaluateDreamTriggers,
  planMerkleDream,
  runCuratorCycle,
} from '../mcp/tools/memory-curate.mjs'

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

console.log(`\nResults: ${passed} passed, ${failed} failed`)
if (failed > 0) process.exit(1)
