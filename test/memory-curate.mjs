// test/memory-curate.mjs — Unit and live-socket integration tests for Phase 2 Merkle Dreaming,
// Curation (Distillation -> Promotion -> Solidification), and Nightmare handling.

import assert from 'node:assert/strict'
import { execFile as execFileCb } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
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
  computeTopicEigenvectors,
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
})

console.log(`\nResults: ${passed} passed, ${failed} failed`)
if (failed > 0) process.exit(1)
