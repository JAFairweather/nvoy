// test/memory-public-projection.mjs — Offline allowlisted Public Cortex projection tests (Frontier E1).
// Fake credentials are constructed at runtime so nothing in this file trips a secret scanner.

import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey } from 'nostr-tools/pure'
import { npubEncode, nsecEncode } from 'nostr-tools/nip19'
import {
  DECISION_RETENTION,
  MEMORY_KIND,
  buildClaimTemplate,
  buildWithdrawalTemplate,
  computeSourceMerkleRoot,
} from '../mcp/tools/memory.mjs'
import {
  HiveMemoryStore,
  initEmptyStore,
  recordVerifiedBackup,
  snapshotStore,
  validateAndResolveConfig,
} from '../mcp/tools/hive_memory_store.mjs'
import {
  assertOfflineProjectionPaths,
  finalisePublicProjection,
  projectOfflinePublicCortex,
  publicBoundaryHit,
  renderPublicProjectionHtml,
  validateProjectionAllowlist,
} from '../mcp/tools/memory-public-projection.mjs'

let passes = 0
let fails = 0
const ok = (name, cond, detail = '') => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} — ${name}${cond || !detail ? '' : ` (${detail})`}`)
  if (cond) passes += 1
  else fails += 1
}

const throwsMsg = (fn, re) => {
  try {
    fn()
    return false
  } catch (e) {
    return re ? re.test(String(e?.message || e)) : true
  }
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
const fill = (n, abc = ALNUM, seed = 'e1-proj') => {
  let s = ''
  let i = 0
  while (s.length < n) {
    for (const b of createHash('sha256').update(`${seed}:${i++}`).digest()) {
      s += abc[b % abc.length]
    }
  }
  return s.slice(0, n)
}

const key = () => {
  const sk = generateSecretKey()
  return { sk, pk: getPublicKey(sk) }
}

const owner = key()
const canonWriter = key()
const opsWriter = key()
const agentA = key()
const agentB = key()

const GLOBAL_CH = '11111111-2222-4333-8444-555555555555'
const ROOM_PUBLIC = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const ROOM_PRIVATE = 'b9297c64-648e-47be-b8f8-c7597d69081f'
const T0 = 1794710400
const SNAP_ID = createHash('sha256').update('e1-test-snapshot').digest('hex')

const SECRET_NSEC = nsecEncode(generateSecretKey())
const SECRET_OPENAI = 's' + 'k-proj-' + fill(48, ALNUM + '-_', 'sk')
const SECRET_GHP = 'gh' + 'p_' + fill(36, ALNUM, 'ghp')
const SECRET_BUNKER = 'bun' + 'ker://' + fill(64, '0123456789abcdef', 'bk') + '?secret=' + fill(16, ALNUM, 'bks')
const SECRET_AWS = 'AK' + 'IA' + fill(16, UPPER, 'aws')
const SECRET_RANDOM = createHash('sha256').update('e1-high-entropy-secret').digest('base64url')
const BOUNDARY_NPUB = npubEncode(agentA.pk)
const BOUNDARY_HEX64 = createHash('sha256').update('raw-64-hex-marker').digest('hex')

const runCli = args => new Promise(res => {
  const child = spawn(process.execPath, ['bin/hive-memory-project.mjs', ...args], {
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let stdout = ''
  let stderr = ''
  child.stdout.on('data', d => { stdout += d })
  child.stderr.on('data', d => { stderr += d })
  child.on('close', status => res({ status, stdout, stderr }))
})

const sha256File = p => createHash('sha256').update(readFileSync(p)).digest('hex')

const root = mkdtempSync(join(tmpdir(), 'nvoy-e1-proj-'))

try {
  // --- 1. Static zero-network / no-live-route module checks ---
  const modSrc = readFileSync(resolve('mcp/tools/memory-public-projection.mjs'), 'utf8')
  const binSrc = readFileSync(resolve('bin/hive-memory-project.mjs'), 'utf8')
  const forbiddenImports = /\b(?:import|require)\b[^\n;]*\b(?:node:)?(?:net|http|https|http2|tls|dgram|dns|child_process|worker_threads|ws|buzz_native|grant_relays|nip46|liverelay)\b/
  ok('projection library imports no networking, socket or subprocess modules', !forbiddenImports.test(modSrc))
  ok('projection CLI imports no networking, socket or subprocess modules', !forbiddenImports.test(binSrc))

  // --- 2. Build a signed test store and take an offline SQLite snapshot ---
  const liveSimDir = join(root, 'test-store')
  mkdirSync(liveSimDir)
  const dbPath = join(liveSimDir, 'memory.sqlite')
  const ledgerPath = join(liveSimDir, 'ledger.jsonl')
  const receiptPath = join(liveSimDir, 'receipt.json')

  initEmptyStore({ dbPath, ledgerPath, nowSec: T0 - 100 })
  recordVerifiedBackup({ receiptPath, snapshotId: SNAP_ID, writeSeq: 1, at: T0 - 50 })

  const cfg = validateAndResolveConfig({
    memoryGlobalChannelId: GLOBAL_CH,
    ownerPubkey: owner.pk,
    maxUnbackedSec: 3600,
    globalWriters: [opsWriter.pk],
    canonWriters: [canonWriter.pk],
    curators: [agentA.pk],
    readers: { owner: owner.pk, agenta: agentA.pk, agentb: agentB.pk },
    writers: {
      owner: { pubkey: owner.pk, perHour: 100 },
      canon: { pubkey: canonWriter.pk, perHour: 100 },
      ops: { pubkey: opsWriter.pk, perHour: 100 },
      agenta: { pubkey: agentA.pk, perHour: 100, allowSelf: true },
      agentb: { pubkey: agentB.pk, perHour: 100 },
    },
    rooms: {
      [ROOM_PUBLIC]: { members: [owner.pk, agentA.pk, agentB.pk], writers: [agentA.pk, agentB.pk] },
      [ROOM_PRIVATE]: { members: [owner.pk, agentB.pk], writers: [agentB.pk] },
    },
  })

  const store = new HiveMemoryStore({ dbPath, ledgerPath, receiptPath, config: cfg })
  store.start()

  let tick = 0
  const mkClaim = (signer, scope, slug, opts = {}) => finalizeEvent(buildClaimTemplate({
    pubkey: signer.pk,
    scope,
    slug,
    topic: opts.topic || 'nvoy',
    claim: opts.claim || `claim ${slug}`,
    because: opts.because || 'CANARY_INTERNAL_BECAUSE_PROSE',
    evidence: opts.evidence || ['/home/agent-biggy/nvoy/README.md', `nvoy@${BOUNDARY_HEX64.slice(0, 40)}`],
    asOfGit: opts.asOfGit || '37ae9a55581100fbcee9522b2c2a701df8973c9d',
    ttlSec: opts.ttlSec,
    supersedes: opts.supersedes,
    merkleSources: opts.merkleSources,
    memoryGlobalChannelId: GLOBAL_CH,
    nowSec: opts.nowSec || (T0 + (++tick)),
  }), signer.sk)

  // Allowlisted scope 1: hive:canon — one chosen durable claim (superseded once), one unchosen claim, one withdrawn claim.
  const canonOld = mkClaim(canonWriter, 'hive:canon', 'cortex-architecture', {
    topic: 'hive-memory',
    ttlSec: 0,
    claim: 'CANARY_SUPERSEDED_CLAIM_907 old text that was replaced.',
    nowSec: T0 + 10,
  })
  ok('submit initial canon claim', store.submit({ writer: 'canon', event: canonOld, nowSec: T0 + 10 }).accepted === true)

  const canonChosen = mkClaim(canonWriter, 'hive:canon', 'cortex-architecture', {
    topic: 'hive-memory',
    ttlSec: 0,
    claim: 'CANARY_CHOSEN_CANON_PROSE_900 Cortex is the canonical memory store; public snapshots are generated offline.',
    supersedes: [canonOld.id],
    nowSec: T0 + 20,
  })
  ok('submit superseding chosen canon claim', store.submit({
    writer: 'canon',
    event: canonChosen,
    expectedPriorId: canonOld.id,
    nowSec: T0 + 20,
  }).accepted === true)

  const canonUnchosen = mkClaim(owner, 'hive:canon', 'internal-canon-note', {
    topic: 'nvoy',
    ttlSec: 0,
    claim: 'CANARY_UNCHOSEN_CANON_PROSE_904 internal canon claim.',
    nowSec: T0 + 25,
  })
  ok('submit unchosen canon claim', store.submit({ writer: 'owner', event: canonUnchosen, nowSec: T0 + 25 }).accepted === true)

  const canonToWithdraw = mkClaim(owner, 'hive:canon', 'retired-canon-rule', {
    topic: 'nvoy',
    ttlSec: 0,
    claim: 'CANARY_WITHDRAWN_CLAIM_905 must not appear.',
    nowSec: T0 + 30,
  })
  ok('submit canon claim before withdrawal', store.submit({ writer: 'owner', event: canonToWithdraw, nowSec: T0 + 30 }).accepted === true)
  const canonWithdrawn = finalizeEvent(buildWithdrawalTemplate({
    pubkey: owner.pk,
    priorEvent: canonToWithdraw,
    because: 'superseded rule',
    memoryGlobalChannelId: GLOBAL_CH,
    nowSec: T0 + 31,
  }).replacement, owner.sk)
  ok('withdraw canon claim', store.submit({
    writer: 'owner',
    event: canonWithdrawn,
    expectedPriorId: canonToWithdraw.id,
    nowSec: T0 + 31,
  }).accepted === true)

  // Allowlisted scope 2: room:ROOM_PUBLIC — one curated Class B synthesis (chosen), one unlisted-topic ephemeral claim, one expired claim.
  const roomSourceA = mkClaim(agentB, `room:${ROOM_PUBLIC}`, 'source-note-a', {
    topic: 'nvoy',
    ttlSec: 3600,
    claim: 'CANARY_ROOM_UNCHOSEN_908 ephemeral unchosen room claim.',
    nowSec: T0 + 40,
  })
  ok('submit room ephemeral unchosen claim', store.submit({ writer: 'agentb', event: roomSourceA, nowSec: T0 + 40 }).accepted === true)

  const merkleRoot = computeSourceMerkleRoot([roomSourceA.id])
  const roomCuratedChosen = mkClaim(agentA, `room:${ROOM_PUBLIC}`, 'curated-public-note', {
    topic: 'hive-memory',
    ttlSec: 0,
    supersedes: [roomSourceA.id],
    merkleSources: merkleRoot,
    claim: 'CANARY_CHOSEN_ROOM_PROSE_916 Offline projections carry coarse counts and curated topics only.',
    nowSec: T0 + 45,
  })
  ok('submit curated room chosen decision', store.submit({ writer: 'agenta', event: roomCuratedChosen, nowSec: T0 + 45 }).accepted === true)

  const roomUnlistedTopic = mkClaim(agentB, `room:${ROOM_PUBLIC}`, 'unlisted-topic-claim', {
    topic: 'private-subproject',
    ttlSec: 3600,
    claim: 'CANARY_UNLISTED_TOPIC_PROSE_909 should only increment unlisted_topic_claims.',
    nowSec: T0 + 50,
  })
  ok('submit room claim on uncurated topic', store.submit({ writer: 'agentb', event: roomUnlistedTopic, nowSec: T0 + 50 }).accepted === true)

  // Signed claim on 'private-subproject' whose unsigned SQLite topic column will be tampered to 'nvoy' in the snapshot.
  const roomTamperedTopic = mkClaim(agentB, `room:${ROOM_PUBLIC}`, 'sql-topic-relabel-attempt', {
    topic: 'private-subproject',
    ttlSec: 3600,
    claim: 'CANARY_SQL_TOPIC_RELABEL_917 signed under private-subproject.',
    nowSec: T0 + 52,
  })
  ok('submit room claim for unsigned SQLite topic relabel test',
    store.submit({ writer: 'agentb', event: roomTamperedTopic, nowSec: T0 + 52 }).accepted === true)

  const roomExpired = mkClaim(agentB, `room:${ROOM_PUBLIC}`, 'expired-room-claim', {
    topic: 'nvoy',
    ttlSec: 30,
    claim: 'CANARY_EXPIRED_CLAIM_906 already expired before projection.',
    nowSec: T0 + 55,
  })
  ok('submit short-TTL room claim', store.submit({ writer: 'agentb', event: roomExpired, nowSec: T0 + 55 }).accepted === true)

  // Non-allowlisted scopes (Negative control 1: claims outside allowlist.scopes).
  const opsOutside = mkClaim(opsWriter, 'hive:ops', 'ops-secret-schedule', {
    topic: 'herd-infra',
    ttlSec: 3600,
    claim: 'CANARY_OUTSIDE_OPS_901 unallowlisted hive:ops claim.',
    nowSec: T0 + 60,
  })
  ok('submit unallowlisted hive:ops claim', store.submit({ writer: 'ops', event: opsOutside, nowSec: T0 + 60 }).accepted === true)

  const privateRoomOutside = mkClaim(agentB, `room:${ROOM_PRIVATE}`, 'private-room-plan', {
    topic: 'herd-infra',
    ttlSec: 3600,
    claim: 'CANARY_OUTSIDE_PRIVATE_ROOM_902 unallowlisted room claim.',
    nowSec: T0 + 65,
  })
  ok('submit unallowlisted private room claim', store.submit({ writer: 'agentb', event: privateRoomOutside, nowSec: T0 + 65 }).accepted === true)

  // Claims whose prose mentions paths, hosts, domains, URIs, npubs, and 64-hex (valid internally, must never leak in aggregate-only output).
  const boundaryLeakCases = [
    ['leak-path', 'Config lives at /mnt/snapshots/config.json and /data/cortex.sqlite CANARY_LEAK_PATH_910'],
    ['leak-home', 'Checkout is ~/nest/ops/queue.tsv and ./local/path CANARY_LEAK_HOME_911'],
    ['leak-host', 'Service runs on herd-cloud, bunker.nave.pub and unrecognized.host.invalid CANARY_LEAK_HOST_912'],
    ['leak-npub', `Maintainer key is ${BOUNDARY_NPUB} CANARY_LEAK_NPUB_913`],
    ['leak-hex64', `Raw event id ${BOUNDARY_HEX64} CANARY_LEAK_HEX64_914`],
  ]
  for (const [slug, text] of boundaryLeakCases) {
    const ev = mkClaim(owner, 'hive:canon', slug, { topic: 'nvoy', ttlSec: 0, claim: text })
    ok(`submit boundary-bearing internal canon claim (${slug})`, store.submit({ writer: 'owner', event: ev, nowSec: ev.created_at }).accepted === true)
  }

  // Snapshot the test store offline via snapshotStore (exact offline workflow), then close the store.
  const snapDir = join(root, 'offline-snapshot')
  mkdirSync(snapDir)
  const snapDbPath = join(snapDir, 'snapshot.sqlite')
  const snapLedgerPath = join(snapDir, 'ledger-cut.jsonl')
  await snapshotStore({ dbPath, ledgerPath, snapshotPath: snapDbPath, ledgerCutPath: snapLedgerPath })
  store.close()

  // Seed direct SQLite rows/mutations into a copy of the offline snapshot to test Negative Control 2:
  // secret-shaped strings (nsec, sk-proj, ghp_, bunker://, AKIA, high-entropy token, IP literals),
  // a tampered signature, tampered unsigned SQLite topic/retention metadata, and a personal self:<pubkey> row.
  const seededDbPath = join(snapDir, 'seeded-snapshot.sqlite')
  writeFileSync(seededDbPath, readFileSync(snapDbPath))
  const seedDb = new DatabaseSync(seededDbPath)
  const insertRow = seedDb.prepare(`
    INSERT INTO events (
      id, pubkey, kind, created_at, d, scope, scope_type, room_id, topic,
      status, retention, as_of_git, as_of_evt, exp, raw_json, ingested_at, is_current
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
  `)

  // Tamper unsigned SQLite topic column on a signed 'private-subproject' event -> must be quarantined, NOT counted under 'nvoy'.
  seedDb.prepare('UPDATE events SET topic = ? WHERE id = ?').run('nvoy', roomTamperedTopic.id)

  const signRawSecretEvent = (slug, secretText) => {
    const d = `hive-memory:hive:canon:${slug}`
    const unsigned = {
      kind: MEMORY_KIND,
      created_at: T0 + 90 + (++tick),
      pubkey: owner.pk,
      tags: [
        ['d', d],
        ['s', 'hive:canon'],
        ['h', GLOBAL_CH],
        ['topic', 'nvoy'],
        ['retention', DECISION_RETENTION],
        ['as_of_git', '37ae9a55581100fbcee9522b2c2a701df8973c9d'],
      ],
      content: JSON.stringify({
        status: 'active',
        claim: secretText,
        because: 'seeded negative control',
        evidence: ['test-fixture'],
      }),
    }
    return finalizeEvent(unsigned, owner.sk)
  }

  const secretCases = [
    ['secret-nsec', `CANARY_SECRET_NSEC_921 ${SECRET_NSEC}`],
    ['secret-openai', `CANARY_SECRET_OPENAI_922 ${SECRET_OPENAI}`],
    ['secret-ghp', `CANARY_SECRET_GHP_923 ${SECRET_GHP}`],
    ['secret-bunker', `CANARY_SECRET_BUNKER_924 ${SECRET_BUNKER}`],
    ['secret-aws', `CANARY_SECRET_AWS_925 ${SECRET_AWS}`],
    ['secret-entropy', `CANARY_SECRET_ENTROPY_926 ${SECRET_RANDOM}`],
    ['leak-ip', 'Tailnet endpoint 100.88.14.92 and fd7a:115c:a1e0::42 CANARY_LEAK_IP_915'],
  ]
  for (const [slug, text] of secretCases) {
    const ev = signRawSecretEvent(slug, text)
    insertRow.run(
      ev.id, ev.pubkey, ev.kind, ev.created_at, `hive-memory:hive:canon:${slug}`,
      'hive:canon', 'hive:canon', null, 'nvoy', 'active', 'decision',
      '37ae9a55581100fbcee9522b2c2a701df8973c9d', null, null, JSON.stringify(ev), ev.created_at
    )
  }

  // Tampered signature row sorting BEFORE cortex-architecture with a forged global h UUID:
  // must be quarantined AND must not poison inferredGlobalChannelId for subsequent valid rows.
  const validForTamper = signRawSecretEvent('aaa-tampered-sig', 'CANARY_TAMPERED_SIG_927 clean-looking text with bad sig')
  const tamperedEv = {
    ...JSON.parse(JSON.stringify(validForTamper)),
    tags: validForTamper.tags.map(t => (t[0] === 'h' ? ['h', '99999999-8888-4777-8666-555555555555'] : t)),
    sig: '0'.repeat(128),
  }
  insertRow.run(
    tamperedEv.id, tamperedEv.pubkey, tamperedEv.kind, tamperedEv.created_at,
    'hive-memory:hive:canon:aaa-tampered-sig', 'hive:canon', 'hive:canon', null, 'nvoy',
    'active', 'decision', '37ae9a55581100fbcee9522b2c2a701df8973c9d', null, null,
    JSON.stringify(tamperedEv), tamperedEv.created_at
  )

  // Personal self:<pubkey> row in SQLite (must never be read or counted).
  const selfD = `hive-memory:self:${agentA.pk}:personal-note`
  const selfEv = finalizeEvent({
    kind: MEMORY_KIND,
    created_at: T0 + 120,
    pubkey: agentA.pk,
    tags: [['d', selfD], ['s', `self:${agentA.pk}`], ['topic', 'nvoy'], ['retention', DECISION_RETENTION], ['as_of_git', '37ae9a5']],
    content: JSON.stringify({ status: 'active', claim: 'CANARY_OUTSIDE_SELF_903 private self note', because: 'self', evidence: ['self'] }),
  }, agentA.sk)
  insertRow.run(
    selfEv.id, selfEv.pubkey, selfEv.kind, selfEv.created_at, selfD,
    `self:${agentA.pk}`, 'self', null, 'nvoy', 'active', 'decision',
    '37ae9a5', null, null, JSON.stringify(selfEv), selfEv.created_at
  )
  seedDb.close()

  // --- 3. Run the offline CLI against the seeded test store and check positive + negative controls ---
  // Explicit allowlist.claims restricts WHICH claims are counted in aggregate counts while still emitting ZERO prose.
  const allowlist = {
    scopes: [
      'hive:canon',
      { scope: `room:${ROOM_PUBLIC}`, label: 'public-demo' },
    ],
    topics: ['hive-memory', 'nvoy'],
    claims: [
      'hive-memory:hive:canon:cortex-architecture',
      `hive-memory:room:${ROOM_PUBLIC}:curated-public-note`,
      `hive-memory:room:${ROOM_PUBLIC}:sql-topic-relabel-attempt`,
      ...secretCases.map(([slug]) => `hive-memory:hive:canon:${slug}`),
      'hive-memory:hive:canon:aaa-tampered-sig',
    ],
  }
  const allowlistPath = join(root, 'allowlist.json')
  writeFileSync(allowlistPath, JSON.stringify(allowlist, null, 2))

  const outDir = join(root, 'out-chosen')
  const beforeSha = sha256File(seededDbPath)
  const projectedAt = T0 + 200 // after roomExpired (exp = T0 + 85)

  const cliRes = await runCli(['--db', seededDbPath, '--allowlist', allowlistPath, '--out', outDir, '--now', String(projectedAt)])
  ok('CLI exits 0 on valid allowlisted test store', cliRes.status === 0, cliRes.stderr)
  ok('offline SQLite snapshot file is untouched (strictly read-only)', sha256File(seededDbPath) === beforeSha)

  const jsonRaw = readFileSync(join(outDir, 'cortex-public.json'), 'utf8')
  const htmlRaw = readFileSync(join(outDir, 'index.html'), 'utf8')
  const combinedOut = `${jsonRaw}\n${htmlRaw}\n${cliRes.stdout}\n${cliRes.stderr}`
  const proj = JSON.parse(jsonRaw)

  ok('projection coarse_state is ready and not withheld', proj.coarse_state === 'ready' && proj.withheld === false)
  ok('projection is strictly aggregate-only with no chosen_claims prose or withheld_claims side-channel count',
    !('chosen_claims' in proj) &&
    !('withheld_claims' in proj.counts) &&
    proj.withheld_fields.includes('claim_prose') &&
    proj.withheld_fields.includes('quarantined_row_counts'))
  ok('projection contains ONLY allowlisted scopes',
    JSON.stringify(proj.scopes.map(s => s.scope)) === JSON.stringify(['hive:canon', 'room:public-demo']))
  ok('projection contains ONLY curated allowlisted topics',
    JSON.stringify(proj.topics.map(t => t.topic)) === JSON.stringify(['hive-memory', 'nvoy']))
  ok('allowlist.claims counts only valid chosen claims and unsigned SQLite topic relabel does not increment nvoy',
    proj.counts.active_claims === 2 &&
    proj.counts.durable_decisions === 2 &&
    proj.counts.ephemeral_claims === 0 &&
    proj.counts.curated_syntheses === 1 &&
    proj.counts.unlisted_topic_claims === 0 &&
    proj.topics.find(t => t.topic === 'hive-memory')?.active_claims === 2 &&
    proj.topics.find(t => t.topic === 'nvoy')?.active_claims === 0,
    JSON.stringify(proj.counts))
  // 7 secret-bearing rows + 1 tampered-sig row + 1 tampered SQLite topic row = 9 quarantined rows (local return only, never in public JSON).
  const directChosenRes = projectOfflinePublicCortex({
    dbPath: seededDbPath,
    allowlist,
    outDir: join(root, 'out-chosen-direct'),
    nowSec: projectedAt,
  })
  ok('secret, signature-tampered and SQLite-topic-tampered chosen rows are quarantined locally without public count leak',
    directChosenRes.quarantinedClaims === 9 && !('withheld_claims' in directChosenRes.projection.counts),
    `got ${directChosenRes.quarantinedClaims}`)

  // Negative Control 1: EVERY claim's prose (even chosen canon/room claims!), outside scopes, withdrawn, expired, superseded, IDs & keys are absent.
  const absentCanaries = [
    'CANARY_CHOSEN_CANON_PROSE_900',
    'CANARY_CHOSEN_ROOM_PROSE_916',
    'CANARY_OUTSIDE_OPS_901',
    'CANARY_OUTSIDE_PRIVATE_ROOM_902',
    'CANARY_OUTSIDE_SELF_903',
    'CANARY_UNCHOSEN_CANON_PROSE_904',
    'CANARY_WITHDRAWN_CLAIM_905',
    'CANARY_EXPIRED_CLAIM_906',
    'CANARY_SUPERSEDED_CLAIM_907',
    'CANARY_ROOM_UNCHOSEN_908',
    'CANARY_UNLISTED_TOPIC_PROSE_909',
    'CANARY_SQL_TOPIC_RELABEL_917',
    'CANARY_INTERNAL_BECAUSE_PROSE',
    'private-subproject',
    'hive:ops',
    ROOM_PUBLIC,
    ROOM_PRIVATE,
    GLOBAL_CH,
    owner.pk,
    canonWriter.pk,
    opsWriter.pk,
    agentA.pk,
    agentB.pk,
    canonChosen.id,
    roomCuratedChosen.id,
    'cortex-architecture',
    'curated-public-note',
  ]
  for (const needle of absentCanaries) {
    ok(`claim prose / non-allowlisted / internal artifact absent from all output (${needle.slice(0, 28)})`, !combinedOut.includes(needle))
  }

  // Negative Control 2: every secret-shaped string and boundary-violating string is absent from JSON, HTML, stdout and stderr.
  const absentSecretsAndLeaks = [
    SECRET_NSEC,
    SECRET_OPENAI,
    SECRET_GHP,
    SECRET_BUNKER,
    SECRET_AWS,
    SECRET_RANDOM,
    BOUNDARY_NPUB,
    BOUNDARY_HEX64,
    'CANARY_SECRET_NSEC_921',
    'CANARY_SECRET_OPENAI_922',
    'CANARY_SECRET_GHP_923',
    'CANARY_SECRET_BUNKER_924',
    'CANARY_SECRET_AWS_925',
    'CANARY_SECRET_ENTROPY_926',
    'CANARY_TAMPERED_SIG_927',
    'CANARY_LEAK_PATH_910',
    'CANARY_LEAK_HOME_911',
    'CANARY_LEAK_HOST_912',
    'CANARY_LEAK_NPUB_913',
    'CANARY_LEAK_HEX64_914',
    'CANARY_LEAK_IP_915',
    '100.88.14.92',
    'fd7a:115c:a1e0::42',
    '/mnt/snapshots',
    '/data/cortex.sqlite',
    'herd-cloud',
    'bunker.nave.pub',
    'unrecognized.host.invalid',
  ]
  for (const secret of absentSecretsAndLeaks) {
    ok(`secret or boundary marker absent from all output (${secret.slice(0, 16)}…)`, !combinedOut.includes(secret))
  }

  // Static HTML viewer has no JS, no network connections, no links, and strict CSP.
  ok('static HTML carries strict CSP with script-src none and connect-src none',
    htmlRaw.includes("default-src 'none'") && htmlRaw.includes("script-src 'none'") && htmlRaw.includes("connect-src 'none'"))
  ok('static HTML contains no script tags, fetch, EventSource or anchor links',
    !/<script\b|fetch\s*\(|EventSource|<a\b/i.test(htmlRaw))

  // --- 4. Scope-level aggregate mode (no allowlist.claims) counts all valid active claims in allowlisted scopes with zero prose ---
  const aggAllowlistPath = join(root, 'allowlist-agg.json')
  writeFileSync(aggAllowlistPath, JSON.stringify({
    scopes: ['hive:canon', { scope: `room:${ROOM_PUBLIC}`, label: 'public-demo' }],
    topics: ['hive-memory', 'nvoy'],
  }))
  const aggOutDir = join(root, 'out-agg')
  const aggRes = await runCli(['--db', seededDbPath, '--allowlist', aggAllowlistPath, '--out', aggOutDir, '--now', String(projectedAt)])
  const aggJson = readFileSync(join(aggOutDir, 'cortex-public.json'), 'utf8')
  const aggHtml = readFileSync(join(aggOutDir, 'index.html'), 'utf8')
  const aggParsed = JSON.parse(aggJson)
  // Valid active rows in allowlisted scopes: canonChosen + canonUnchosen + 5 boundaryLeakCases (7 in hive:canon)
  // + roomSourceA + roomCuratedChosen + roomUnlistedTopic (3 in room:public-demo) = 10 active; 9 quarantined locally, never in public JSON.
  ok('scope-level aggregate mode exits 0 with exact aggregate counts and no public withheld_claims count',
    aggRes.status === 0 &&
    !('chosen_claims' in aggParsed) &&
    !('withheld_claims' in aggParsed.counts) &&
    aggParsed.counts.active_claims === 10 &&
    aggParsed.counts.durable_decisions === 8 &&
    aggParsed.counts.ephemeral_claims === 2 &&
    aggParsed.counts.unlisted_topic_claims === 1,
    JSON.stringify(aggParsed.counts))
  ok('scope-level aggregate mode emits zero claim prose, paths or hostnames in JSON and HTML',
    !aggJson.includes('CANARY_') &&
    !aggHtml.includes('CANARY_') &&
    !aggJson.includes('/mnt/snapshots') &&
    !aggJson.includes('bunker.nave.pub'))

  // --- 4b. Private-to-public count side-channel & unsigned SQLite metadata tamper controls ---
  const canonOnlyAllow = { scopes: ['hive:canon'], topics: ['hive-memory', 'nvoy'] }
  const canonOnlyAllowPath = join(root, 'allowlist-canon-only.json')
  writeFileSync(canonOnlyAllowPath, JSON.stringify(canonOnlyAllow))

  const baseCanonOut = join(root, 'out-canon-baseline')
  const baseCanonCli = await runCli(['--db', snapDbPath, '--allowlist', canonOnlyAllowPath, '--out', baseCanonOut, '--now', String(projectedAt)])
  const baseCanonDirect = projectOfflinePublicCortex({
    dbPath: snapDbPath,
    allowlist: canonOnlyAllow,
    outDir: join(root, 'out-canon-baseline-direct'),
    nowSec: projectedAt,
  })
  const baseCanonJson = readFileSync(join(baseCanonOut, 'cortex-public.json'), 'utf8')
  const baseCanonHtml = readFileSync(join(baseCanonOut, 'index.html'), 'utf8')

  // Tamper unsigned SQLite scope/d/scope_type/topic on signed hive:ops, private room, and self rows to 'hive:canon',
  // plus insert a corrupt raw_json row claiming 'hive:canon'. Public JSON, HTML, CLI stdout, and quarantinedClaims must not budge.
  const tamperedPrivateDbPath = join(snapDir, 'tampered-private-scope.sqlite')
  writeFileSync(tamperedPrivateDbPath, readFileSync(snapDbPath))
  const tpDb = new DatabaseSync(tamperedPrivateDbPath)
  tpDb.prepare('UPDATE events SET scope = ?, scope_type = ?, room_id = NULL, d = ?, topic = ? WHERE id = ?')
    .run('hive:canon', 'hive:canon', 'hive-memory:hive:canon:ops-secret-schedule', 'nvoy', opsOutside.id)
  tpDb.prepare('UPDATE events SET scope = ?, scope_type = ?, room_id = NULL, d = ?, topic = ? WHERE id = ?')
    .run('hive:canon', 'hive:canon', 'hive-memory:hive:canon:private-room-plan', 'nvoy', privateRoomOutside.id)
  tpDb.prepare(`
    INSERT INTO events (
      id, pubkey, kind, created_at, d, scope, scope_type, room_id, topic,
      status, retention, as_of_git, as_of_evt, exp, raw_json, ingested_at, is_current
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
  `).run(
    selfEv.id, selfEv.pubkey, selfEv.kind, selfEv.created_at, 'hive-memory:hive:canon:self-disguised',
    'hive:canon', 'hive:canon', null, 'nvoy', 'active', 'decision',
    '37ae9a5', null, null, JSON.stringify(selfEv), selfEv.created_at
  )
  tpDb.prepare(`
    INSERT INTO events (
      id, pubkey, kind, created_at, d, scope, scope_type, room_id, topic,
      status, retention, as_of_git, as_of_evt, exp, raw_json, ingested_at, is_current
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
  `).run(
    'f'.repeat(64), opsWriter.pk, MEMORY_KIND, T0 + 130, 'hive-memory:hive:canon:corrupt-raw-json',
    'hive:canon', 'hive:canon', null, 'nvoy', 'active', 'decision',
    '37ae9a5', null, null, '{corrupt', T0 + 130
  )
  tpDb.close()

  const tamperedCanonOut = join(root, 'out-canon-tampered-private')
  const tamperedCanonCli = await runCli(['--db', tamperedPrivateDbPath, '--allowlist', canonOnlyAllowPath, '--out', tamperedCanonOut, '--now', String(projectedAt)])
  const tamperedCanonDirect = projectOfflinePublicCortex({
    dbPath: tamperedPrivateDbPath,
    allowlist: canonOnlyAllow,
    outDir: join(root, 'out-canon-tampered-private-direct'),
    nowSec: projectedAt,
  })
  ok('signed hive:ops, private-room and self rows with tampered unsigned SQLite scope=hive:canon produce byte-identical public JSON, HTML and CLI output',
    baseCanonCli.status === 0 &&
    tamperedCanonCli.status === 0 &&
    readFileSync(join(tamperedCanonOut, 'cortex-public.json'), 'utf8') === baseCanonJson &&
    readFileSync(join(tamperedCanonOut, 'index.html'), 'utf8') === baseCanonHtml &&
    tamperedCanonCli.stdout === baseCanonCli.stdout)
  ok('out-of-allowlist signed rows with tampered unsigned SQLite scope=hive:canon leave quarantinedClaims at 0',
    baseCanonDirect.quarantinedClaims === 0 && tamperedCanonDirect.quarantinedClaims === 0,
    `got ${tamperedCanonDirect.quarantinedClaims}`)

  // Unchosen secret-bearing canon row when allowlist.claims selects only cortex-architecture -> zero public or diagnostic leak.
  const singleClaimAllow = {
    scopes: ['hive:canon'],
    topics: ['hive-memory', 'nvoy'],
    claims: ['hive-memory:hive:canon:cortex-architecture'],
  }
  const singleClaimBase = projectOfflinePublicCortex({
    dbPath: snapDbPath,
    allowlist: singleClaimAllow,
    outDir: join(root, 'out-single-claim-base'),
    nowSec: projectedAt,
  })
  const singleClaimSeeded = projectOfflinePublicCortex({
    dbPath: seededDbPath,
    allowlist: singleClaimAllow,
    outDir: join(root, 'out-single-claim-seeded'),
    nowSec: projectedAt,
  })
  ok('unchosen secret-bearing rows in allowlisted scope do not alter projection or quarantinedClaims under allowlist.claims',
    JSON.stringify(singleClaimSeeded.projection) === JSON.stringify(singleClaimBase.projection) &&
    singleClaimSeeded.quarantinedClaims === 0)

  // Symmetric tamper (signed hive:canon row with tampered unsigned scope='hive:ops') & NIP-01 is_current resurrection tamper:
  // both must be quarantined and must never resurrect a withdrawn/superseded claim or accept mismatched metadata.
  const resurrectDbPath = join(snapDir, 'tampered-resurrect.sqlite')
  writeFileSync(resurrectDbPath, readFileSync(snapDbPath))
  const resDb = new DatabaseSync(resurrectDbPath)
  resDb.prepare('UPDATE events SET is_current = 0 WHERE id = ?').run(canonWithdrawn.id)
  resDb.prepare('UPDATE events SET is_current = 1 WHERE id = ?').run(canonToWithdraw.id)
  resDb.prepare('UPDATE events SET scope = ?, scope_type = ? WHERE id = ?').run('hive:ops', 'hive:ops', canonUnchosen.id)
  resDb.close()
  const resurrectRes = projectOfflinePublicCortex({
    dbPath: resurrectDbPath,
    allowlist: canonOnlyAllow,
    outDir: join(root, 'out-canon-resurrect'),
    nowSec: projectedAt,
  })
  // Baseline had 7 active hive:canon claims (canonChosen + canonUnchosen + 5 boundaryLeakCases).
  // Resurrected canonToWithdraw is quarantined (+1) rather than counted, and scope-tampered canonUnchosen is quarantined (+1) -> 6 active, 2 quarantined.
  ok('flipping unsigned is_current cannot resurrect a withdrawn claim and tampering signed canon scope to hive:ops quarantines the row',
    resurrectRes.projection.counts.active_claims === 6 && resurrectRes.quarantinedClaims === 2,
    `${JSON.stringify(resurrectRes.projection.counts)} q=${resurrectRes.quarantinedClaims}`)

  // --- 5. Defense-in-depth second-layer output sanitiser negative controls (secrets, paths, unrecognized hosts/URLs) ---
  for (const [label, poison] of [
    ['secret and 64-hex', `leaked ${SECRET_GHP} and ${BOUNDARY_HEX64}`],
    ['ordinary /mnt and /data paths', 'mounted at /mnt/snapshots and /data/cortex.sqlite'],
    ['external relays and unrecognized hosts', 'connects to bunker.nave.pub, relay.nsec.app and https://unrecognized.host.invalid/v1'],
  ]) {
    const poisonedCandidate = {
      version: 1,
      generated_at: '2026-11-15T03:30:00Z',
      coarse_state: 'ready',
      withheld: false,
      counts: { active_claims: 1, durable_decisions: 1, ephemeral_claims: 0, curated_syntheses: 0, unlisted_topic_claims: 0 },
      scopes: [{ scope: poison, active_claims: 1, durable_decisions: 1, ephemeral_claims: 0 }],
      topics: [{ topic: 'nvoy', active_claims: 1, durable_decisions: 1 }],
      withheld_fields: [],
    }
    const finalised = finalisePublicProjection(poisonedCandidate)
    const withheldHtml = renderPublicProjectionHtml(finalised.projection)
    ok(`second-layer output sanitiser withholds candidate poisoned with ${label}`,
      finalised.projection.withheld === true && finalised.projection.coarse_state === 'withheld' && finalised.findings.length >= 1)
    ok(`withheld notice and HTML omit poisoned ${label}`,
      !JSON.stringify(finalised.projection).includes(poison) && !withheldHtml.includes(poison))
  }

  // HTML escaping check against untrusted characters in rendered projection fields.
  const rawHtmlEsc = renderPublicProjectionHtml({
    version: 1,
    generated_at: '2026-11-15T03:30:00Z',
    coarse_state: 'ready',
    withheld: false,
    counts: { active_claims: 1, durable_decisions: 1, ephemeral_claims: 0, curated_syntheses: 0, unlisted_topic_claims: 0 },
    scopes: [{ scope: '<img src=x onerror=alert(1)>', active_claims: 1, durable_decisions: 1, ephemeral_claims: 0 }],
    topics: [{ topic: 'nvoy', active_claims: 1, durable_decisions: 1 }],
    withheld_fields: ['claim_prose'],
  })
  ok('HTML renderer escapes angle brackets and quotes in rendered fields',
    !rawHtmlEsc.includes('<img src=x') && rawHtmlEsc.includes('&lt;img src=x onerror=alert(1)&gt;'))

  // Preplanted symlink defense in --out (both predictable .pid.tmp symlinks and target file symlinks).
  const sentinelPath = join(root, 'sentinel.txt')
  const sentinelContent = 'SENTINEL_MUST_NOT_BE_OVERWRITTEN'
  writeFileSync(sentinelPath, sentinelContent)

  const outPreplantedTmp = join(root, 'out-preplanted-tmp')
  mkdirSync(outPreplantedTmp)
  symlinkSync(sentinelPath, join(outPreplantedTmp, `cortex-public.json.${process.pid}.tmp`))
  symlinkSync(sentinelPath, join(outPreplantedTmp, `index.html.${process.pid}.tmp`))
  projectOfflinePublicCortex({
    dbPath: snapDbPath,
    allowlist: { scopes: ['hive:canon'], topics: ['nvoy'] },
    outDir: outPreplantedTmp,
    nowSec: projectedAt,
  })
  ok('atomic temp write never follows preplanted .pid.tmp symlinks and leaves sentinel untouched',
    readFileSync(sentinelPath, 'utf8') === sentinelContent &&
    existsSync(join(outPreplantedTmp, 'cortex-public.json')))

  const outPreplantedTarget = join(root, 'out-preplanted-target')
  mkdirSync(outPreplantedTarget)
  symlinkSync(sentinelPath, join(outPreplantedTarget, 'cortex-public.json'))
  ok('refuses preplanted target symlink in --out and leaves sentinel untouched',
    throwsMsg(() => projectOfflinePublicCortex({
      dbPath: snapDbPath,
      allowlist: { scopes: ['hive:canon'], topics: ['nvoy'] },
      outDir: outPreplantedTarget,
      nowSec: projectedAt,
    }), /symlink/) && readFileSync(sentinelPath, 'utf8') === sentinelContent)

  // --- 6. Allowlist and live-path refusal controls ---
  ok('refuses personal self:<pubkey> scope in allowlist',
    throwsMsg(() => validateProjectionAllowlist({ scopes: [`self:${agentA.pk}`], topics: ['nvoy'] }), /self scopes/))
  ok('refuses raw room:<uuid> scope without a public label',
    throwsMsg(() => validateProjectionAllowlist({ scopes: [`room:${ROOM_PUBLIC}`], topics: ['nvoy'] }), /require \{ scope, label \}/))
  ok('refuses empty scopes allowlist',
    throwsMsg(() => validateProjectionAllowlist({ scopes: [], topics: ['nvoy'] }), /non-empty/))
  ok('refuses allowlist.claims outside allowlist.scopes',
    throwsMsg(() => validateProjectionAllowlist({
      scopes: ['hive:canon'],
      topics: ['nvoy'],
      claims: ['hive-memory:hive:ops:ops-secret-schedule'],
    }), /outside allowlist\.scopes/))
  ok('refuses live store path /var/lib/hive-memory/memory.sqlite',
    throwsMsg(() => assertOfflineProjectionPaths({
      dbPath: '/var/lib/hive-memory/memory.sqlite',
      outDir: join(root, 'never'),
    }), /forbidden/))
  ok('refuses live daemon socket path /run/hive-memory/viewer.sock',
    throwsMsg(() => assertOfflineProjectionPaths({
      dbPath: '/run/hive-memory/viewer.sock',
      outDir: join(root, 'never'),
    }), /forbidden/))
  ok('refuses live publication path /srv/apps/status',
    throwsMsg(() => assertOfflineProjectionPaths({
      dbPath: seededDbPath,
      outDir: '/srv/apps/status',
    }), /forbidden/))
  ok('refuses remote URI in --db',
    throwsMsg(() => assertOfflineProjectionPaths({
      dbPath: 'https://example.com/memory.sqlite',
      outDir: join(root, 'never'),
    }), /not a URI/))

  const symDb = join(root, 'symlink.sqlite')
  symlinkSync(seededDbPath, symDb)
  ok('refuses symlinked --db snapshot path',
    throwsMsg(() => assertOfflineProjectionPaths({
      dbPath: symDb,
      outDir: join(root, 'never'),
    }), /non-symlink/))

  const badCliLive = await runCli(['--db', '/var/lib/hive-memory/memory.sqlite', '--allowlist', allowlistPath, '--out', join(root, 'never')])
  ok('CLI exits non-zero when pointed at live store path and creates no output dir',
    badCliLive.status !== 0 && !existsSync(join(root, 'never')))

  // Malformed or secret-stuffed --allowlist must never echo secret bytes into stderr/stdout.
  const badJsonAllow = join(root, 'bad-json-allow.json')
  writeFileSync(badJsonAllow, `${SECRET_GHP} not valid json`)
  const badCliJson = await runCli(['--db', seededDbPath, '--allowlist', badJsonAllow, '--out', join(root, 'never-json')])
  ok('CLI rejects malformed --allowlist without echoing secret bytes',
    badCliJson.status !== 0 && !badCliJson.stderr.includes(SECRET_GHP) && !badCliJson.stdout.includes(SECRET_GHP))

  const badTopicAllow = join(root, 'bad-topic-allow.json')
  writeFileSync(badTopicAllow, JSON.stringify({ scopes: ['hive:canon'], topics: [SECRET_OPENAI] }))
  const badCliTopic = await runCli(['--db', seededDbPath, '--allowlist', badTopicAllow, '--out', join(root, 'never-topic')])
  ok('CLI rejects unsafe allowlist topic without echoing secret bytes',
    badCliTopic.status !== 0 && !badCliTopic.stderr.includes(SECRET_OPENAI) && !badCliTopic.stdout.includes(SECRET_OPENAI))

  ok('publicBoundaryHit flags credentials, arbitrary paths, URIs, domains, hosts, IPs, npubs, UUIDs and 64-hex ids',
    publicBoundaryHit(SECRET_NSEC) !== null &&
    publicBoundaryHit('/Users/fairwja/keys') === 'a filesystem path' &&
    publicBoundaryHit('/mnt/snapshots') === 'a filesystem path' &&
    publicBoundaryHit('/data/cortex.sqlite') === 'a filesystem path' &&
    publicBoundaryHit('./local/path') === 'a filesystem path' &&
    publicBoundaryHit('../parent/path') === 'a filesystem path' &&
    publicBoundaryHit('herd-cloud') === 'a network URI or hostname' &&
    publicBoundaryHit('bunker.nave.pub') === 'a network URI or hostname' &&
    publicBoundaryHit('relay.nsec.app') === 'a network URI or hostname' &&
    publicBoundaryHit('unrecognized.host.invalid') === 'a network URI or hostname' &&
    publicBoundaryHit('https://example.org/x') === 'a network URI or hostname' &&
    publicBoundaryHit('service:8795') === 'a network URI or hostname' &&
    publicBoundaryHit('100.88.14.92') !== null &&
    publicBoundaryHit('fd7a:115c:a1e0::42') !== null &&
    publicBoundaryHit(BOUNDARY_NPUB) === 'a Nostr public or event identifier' &&
    publicBoundaryHit(ROOM_PUBLIC) === 'a raw UUID' &&
    publicBoundaryHit(BOUNDARY_HEX64) === 'a full 64-hex key or id' &&
    publicBoundaryHit('Clean coarse summary of 12 decisions') === null)
} finally {
  rmSync(root, { recursive: true, force: true })
}

console.log(`\n${passes}/${passes + fails} passed`)
process.exit(fails ? 1 : 0)
