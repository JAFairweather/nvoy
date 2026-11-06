// test/memory.mjs — acceptance tests for the private Hive memory store (PLANS/HIVE_MEMORY_PRIVATE_STORE.md §5
// tests 2-5, plus the 2026-11-05 review cases). No relay or network connection is opened anywhere.

import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, writeSync,
} from 'node:fs'
import { connect } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import {
  buildClaimTemplate, buildWithdrawalTemplate, checkMemorySecrets, nip01Newer, validateMemoryEvent,
} from '../mcp/tools/memory.mjs'
import {
  HiveMemoryStore, RETENTION_PURGE_AFTER_SEC, acquireStoreLock, initEmptyStore, migrateStoreJson, readLedger, recordVerifiedBackup,
  canRead, restoreSnapshot, snapshotStore, validateAndResolveConfig, writeRefusal,
} from '../mcp/tools/hive_memory_store.mjs'
import { startMemoryDaemon } from '../mcp/tools/memory-daemon.mjs'

let passes = 0, fails = 0
const ok = (name, cond) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} — ${name}`)
  if (cond) passes++; else fails++
}
const throwsCode = (fn, code) => { try { fn(); return false } catch (e) { return e.code === code } }
const throwsCodeAsync = async (fn, code) => { try { await fn(); return false } catch (e) { return e.code === code } }

const key = () => { const sk = generateSecretKey(); return { sk, pk: getPublicKey(sk) } }
const james = key()
const biggy = key()
const crusty = key()
const opsBot = key()
const outsider = key()

const GLOBAL_CH = '11111111-2222-4333-8444-555555555555'
const ROOM_A = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const ROOM_B = 'b9297c64-648e-47be-b8f8-c7597d69081f'
const T0 = 1793822400
const DAY = 86400
const SNAP_ID = createHash('sha256').update('restic snapshot').digest('hex')

const rawConfig = (over = {}) => ({
  memoryGlobalChannelId: GLOBAL_CH,
  ownerPubkey: james.pk,
  maxUnbackedSec: 3600,
  globalWriters: [opsBot.pk],
  readers: { biggy: biggy.pk, crusty: crusty.pk, kiosk: null, owner: james.pk },
  writers: {
    biggy: { pubkey: biggy.pk, perHour: 3 },
    crusty: { pubkey: crusty.pk, perHour: 100 },
    james: { pubkey: james.pk, perHour: 100 },
    ops: { pubkey: opsBot.pk, perHour: 100 },
  },
  rooms: {
    [ROOM_A]: { members: [biggy.pk, crusty.pk, james.pk], writers: [biggy.pk, crusty.pk] },
    [ROOM_B]: { members: [crusty.pk, james.pk], writers: [crusty.pk] },
  },
  ...over,
})
const CFG = validateAndResolveConfig(rawConfig())

let tick = 0
const claim = (signer, scope, slug, opts = {}) => finalizeEvent(buildClaimTemplate({
  pubkey: signer.pk,
  scope,
  slug,
  claim: opts.claim || `claim ${slug} ${++tick}`,
  because: 'observed in the test fixture',
  evidence: ['nvoy@abc1234:README.md'],
  asOfGit: 'abc1234',
  memoryGlobalChannelId: GLOBAL_CH,
  nowSec: T0 + 100 + tick,
  ...opts,
}), signer.sk)
const withdraw = (signer, prior) => finalizeEvent(buildWithdrawalTemplate({
  pubkey: signer.pk, priorEvent: prior, because: 'no longer true', memoryGlobalChannelId: GLOBAL_CH, nowSec: prior.created_at + 1,
}).replacement, signer.sk)
const roomA = `room:${ROOM_A}`
const roomB = `room:${ROOM_B}`

const setup = (name, { at = T0 } = {}) => {
  const dir = mkdtempSync(join(tmpdir(), `hm-${name}-`))
  const p = { dir, db: join(dir, 'memory.sqlite'), ledger: join(dir, 'ledger.jsonl'), receipt: join(dir, 'receipt.json') }
  initEmptyStore({ dbPath: p.db, ledgerPath: p.ledger, nowSec: T0 - 10 })
  recordVerifiedBackup({ receiptPath: p.receipt, snapshotId: SNAP_ID, writeSeq: 1, at })
  return p
}
const open = (p, extra = {}) => {
  const s = new HiveMemoryStore({ dbPath: p.db, ledgerPath: p.ledger, receiptPath: p.receipt, config: CFG, ...extra })
  s.start()
  return s
}
const seqOf = s => s.db.prepare('SELECT write_seq FROM store_meta').get().write_seq
const ledgerSeqs = p => readLedger(p.ledger).lines.map(l => l.rec.seq)
const unknownAnswer = (s, label) => {
  const q = s.query({ readerPubkey: james.pk, scope: 'hive:ops', nowSec: T0 + 200 })
  return q.answer === 'unknown' && q.answer_reason === `store-not-ready:${label}` && q.records.length === 0
}
const runBin = (script, args) => new Promise(res => {
  const child = spawn(process.execPath, [`bin/${script}`, ...args], { stdio: ['ignore', 'pipe', 'pipe'] })
  let stdout = '', stderr = ''
  child.stdout.on('data', c => { stdout += c }); child.stderr.on('data', c => { stderr += c })
  child.on('close', status => res({ status, stdout, stderr }))
})
// herd-infra's --purge-records: <snapshot_id>/accepted-ledger.jsonl for each hive-memory-purge snapshot.
const purgeRecords = (p, name, ...backups) => {
  const dir = join(p.dir, name)
  mkdirSync(dir)
  for (const b of backups) {
    const id = join(dir, createHash('sha256').update(b.dir).digest('hex'))
    mkdirSync(id)
    copyFileSync(b.ledger, join(id, 'accepted-ledger.jsonl'))
  }
  return dir
}
// A verified backup as herd-infra dumps it from restic: memory.sqlite, accepted-ledger.jsonl and SHA256SUMS.
const backupDir = async (p, name) => {
  const dir = join(p.dir, name)
  mkdirSync(dir)
  const snap = join(dir, 'memory.sqlite')
  const out = await snapshotStore({ dbPath: p.db, ledgerPath: p.ledger, snapshotPath: snap, ledgerCutPath: join(dir, 'accepted-ledger.jsonl') })
  const sum = f => `${createHash('sha256').update(readFileSync(join(dir, f))).digest('hex')}  ${f}\n`
  writeFileSync(join(dir, 'SHA256SUMS'), sum('memory.sqlite') + sum('accepted-ledger.jsonl'))
  const ledger = join(dir, 'accepted-ledger.jsonl')
  return { dir, snap, out, ledger, authority: { ledger, purgeRecords: purgeRecords(p, `${name}-purges`) } }
}
const withDb = (path, fn) => { const db = new DatabaseSync(path); try { return fn(db) } finally { db.close() } }

// --- 0. Library: secret guard, retention-class builders and NIP-01 ordering ---
ok('secret guard blocks nsec1', !!checkMemorySecrets('leak nsec1' + 'q'.repeat(52)))
ok('secret guard blocks bunker:// and relay URLs', !!checkMemorySecrets(`bunker://${james.pk}?relay=wss://x.y`) && !!checkMemorySecrets('wss://relay.example.com'))
ok('secret guard allows 64-hex pubkeys, event IDs, and git SHAs', checkMemorySecrets(`author ${james.pk} event ${'f'.repeat(64)} commit waggle@a1b2c3d`) === null)
ok('nip01Newer: newer created_at wins; a same-second tie goes to the lower id',
  nip01Newer({ created_at: 2, id: 'b' }, { created_at: 1, id: 'a' }) && nip01Newer({ created_at: 1, id: 'a' }, { created_at: 1, id: 'b' }) && !nip01Newer({ created_at: 1, id: 'b' }, { created_at: 1, id: 'a' }))

// --- 1. Static: the hive-memory modules never import a relay, grant or Bunker client ---
{
  const files = ['mcp/tools/hive_memory_store.mjs', 'mcp/tools/memory-daemon.mjs', 'mcp/tools/memory.mjs', 'mcp/tools/memory-viewer.mjs',
    'mcp/tools/instance-broker-memory.mjs', 'bin/hive-memory-restore.mjs', 'bin/hive-memory-purge.mjs', 'bin/hive-memory-backup.mjs']
  const banned = /^(ws|.*buzz_native.*|.*grant_relays.*|.*nip46.*|.*liverelay.*)$/
  const hits = files.flatMap(f => [...readFileSync(resolve(import.meta.dirname, '..', f), 'utf8').matchAll(/from '([^']+)'/g)]
    .map(m => m[1]).filter(spec => banned.test(spec.split('/').pop()) || banned.test(spec)).map(spec => `${f}: ${spec}`))
  ok('hive-memory modules import no ws, buzz_native, grant_relays, nip46 or liverelay', hits.length === 0)
  if (hits.length) console.log(hits.join('\n'))
}

// --- 2. Submit boundary, retention classes, backup-stale fence, and CAS (§5 test 2) ---
let rid = 0
const rpcCall = (sockPath, req) => new Promise((resolveRpc, rejectRpc) => {
  const client = connect(sockPath)
  let buf = ''
  client.setEncoding('utf8')
  client.on('error', rejectRpc)
  client.on('data', chunk => {
    buf += chunk
    const nl = buf.indexOf('\n')
    if (nl >= 0) { client.end(); resolveRpc(JSON.parse(buf.slice(0, nl))) }
  })
  client.write(`${JSON.stringify(req)}\n`)
})
const callTool = async (sock, name, args) => {
  const r = await rpcCall(sock, { jsonrpc: '2.0', id: ++rid, method: 'tools/call', params: { name, arguments: args } })
  return r.result ? { ...JSON.parse(r.result.content[0].text), isError: Boolean(r.result.isError) } : r
}

{
  const p = setup('submit')
  let clock = T0 + 10
  const sockDir = join(p.dir, 's')
  const daemon = await startMemoryDaemon({
    dbPath: p.db, ledgerPath: p.ledger, receiptPath: p.receipt, config: rawConfig(), socketDir: sockDir,
    readers: 'biggy:crusty:kiosk:owner', writers: 'biggy:crusty:james:ops', now: () => clock, log: () => {},
  })
  const rd = n => join(sockDir, `${n}.sock`)
  const wr = n => join(sockDir, 'writers', `${n}.sock`)
  ok('store opens in WAL with synchronous = FULL',
    daemon.store.db.prepare('PRAGMA journal_mode').get().journal_mode === 'wal' && daemon.store.db.prepare('PRAGMA synchronous').get().synchronous === 2)

  const listR = await rpcCall(rd('biggy'), { jsonrpc: '2.0', id: 1, method: 'tools/list' })
  const listW = await rpcCall(wr('biggy'), { jsonrpc: '2.0', id: 2, method: 'tools/list' })
  ok('reader socket lists only memory_wake and memory_query; writer socket only lookup and submit',
    listR.result.tools.map(t => t.name).sort().join() === 'memory_query,memory_wake' &&
    listW.result.tools.map(t => t.name).sort().join() === 'memory_lookup_prior,memory_submit')

  const c1 = claim(biggy, roomA, 'deploy-window')
  const roLookup = await callTool(rd('biggy'), 'memory_lookup_prior', { d: `hive-memory:${roomA}:deploy-window` })
  const roSubmit = await callTool(rd('biggy'), 'memory_submit', { event: c1, expected_prior_id: null })
  ok('reader socket refuses memory_lookup_prior and memory_submit (HIVE_MEMORY_READ_ONLY_SOCKET)',
    roLookup.code === 'HIVE_MEMORY_READ_ONLY_SOCKET' && roSubmit.code === 'HIVE_MEMORY_READ_ONLY_SOCKET' && roSubmit.isError)
  const wQuery = await rpcCall(wr('biggy'), { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'memory_query', arguments: {} } })
  ok('writer socket serves no reads (-32601)', wQuery.error?.code === -32601)

  const mismatch = await callTool(wr('biggy'), 'memory_submit', { event: claim(crusty, roomA, 'not-yours'), expected_prior_id: null })
  ok('writer socket refuses an event signed by another key (HIVE_MEMORY_WRITER_MISMATCH)', mismatch.code === 'HIVE_MEMORY_WRITER_MISMATCH')
  const outsideRoom = await callTool(wr('biggy'), 'memory_submit', { event: claim(biggy, roomB, 'other-room'), expected_prior_id: null })
  const outsideLookup = await callTool(wr('biggy'), 'memory_lookup_prior', { d: `hive-memory:${roomB}:other-room` })
  ok('writer socket refuses a room outside rooms.<uuid>.writers for submit and lookup (HIVE_MEMORY_SCOPE_NOT_AUTHORIZED)',
    outsideRoom.code === 'HIVE_MEMORY_SCOPE_NOT_AUTHORIZED' && outsideLookup.code === 'HIVE_MEMORY_SCOPE_NOT_AUTHORIZED')
  const notOwner = await callTool(wr('biggy'), 'memory_submit', { event: claim(biggy, 'hive:canon', 'canon-try', { ttlSec: 0 }), expected_prior_id: null })
  const opsNotGlobal = await callTool(wr('biggy'), 'memory_submit', { event: claim(biggy, 'hive:ops', 'ops-try'), expected_prior_id: null })
  ok('only the owner writes hive:canon and only owner/globalWriters write hive:ops',
    notOwner.code === 'HIVE_MEMORY_SCOPE_NOT_AUTHORIZED' && opsNotGlobal.code === 'HIVE_MEMORY_SCOPE_NOT_AUTHORIZED')
  const selfTry = await callTool(wr('biggy'), 'memory_submit', { event: claim(biggy, `self:${biggy.pk}`, 'mine'), expected_prior_id: null })
  ok('self scopes are refused on a shared writer socket unless allowSelf', selfTry.code === 'HIVE_MEMORY_SCOPE_NOT_AUTHORIZED')

  const first = await callTool(wr('biggy'), 'memory_submit', { event: c1, expected_prior_id: null })
  const replay = await callTool(wr('biggy'), 'memory_submit', { event: c1, expected_prior_id: null })
  const c2 = claim(biggy, roomA, 'second')
  const c3 = claim(biggy, roomA, 'third')
  const r2 = await callTool(wr('biggy'), 'memory_submit', { event: c2, expected_prior_id: null })
  const r3 = await callTool(wr('biggy'), 'memory_submit', { event: c3, expected_prior_id: null })
  const r4 = await callTool(wr('biggy'), 'memory_submit', { event: claim(biggy, roomA, 'fourth'), expected_prior_id: null })
  ok('a duplicate event.id is an idempotent replay', first.accepted && !first.replay && replay.accepted && replay.replay === true)
  ok('the hourly cap (writer_rate_log) admits perHour writes and the replay did not count toward it',
    r2.accepted && r3.accepted && r4.code === 'HIVE_MEMORY_RATE_LIMITED' &&
    daemon.store.db.prepare('SELECT count(*) AS n FROM writer_rate_log WHERE pubkey = ?').get(biggy.pk).n === 3)

  const prior = await callTool(wr('biggy'), 'memory_lookup_prior', { d: `hive-memory:${roomA}:deploy-window` })
  ok('memory_lookup_prior returns only minimum metadata for the bound writer',
    prior.found === true && prior.id === c1.id && Object.keys(prior).filter(k => k !== 'isError').sort().join() === 'created_at,d,found,id,pubkey,scope,status')
  const crustyLookup = await callTool(wr('crusty'), 'memory_lookup_prior', { d: `hive-memory:${roomA}:deploy-window` })
  ok('lookup ignores other authors: crusty sees no prior at biggy\'s fact key', crustyLookup.found === false)

  clock += 1000
  const replacement = claim(crusty, roomA, 'deploy-window', { priorCreatedAt: c1.created_at })
  const casFirst = await callTool(wr('crusty'), 'memory_submit', { event: replacement, expected_prior_id: null })
  const v2 = claim(crusty, roomA, 'deploy-window', { priorCreatedAt: replacement.created_at })
  const stale = await callTool(wr('crusty'), 'memory_submit', { event: v2, expected_prior_id: null })
  const missingArg = await callTool(wr('crusty'), 'memory_submit', { event: v2 })
  const fresh = await callTool(wr('crusty'), 'memory_submit', { event: v2, expected_prior_id: replacement.id })
  ok('a stale expected_prior_id is refused (HIVE_MEMORY_PRIOR_MISMATCH) and the current one is accepted',
    casFirst.accepted && stale.code === 'HIVE_MEMORY_PRIOR_MISMATCH' && missingArg.code === 'HIVE_MEMORY_PRIOR_MISMATCH' && fresh.accepted)
  const older = claim(crusty, roomA, 'deploy-window', { nowSec: T0 + 1 })
  const notNewer = await callTool(wr('crusty'), 'memory_submit', { event: older, expected_prior_id: v2.id })
  ok('an event not newer than the current head is refused (HIVE_MEMORY_NOT_NEWER)', notNewer.code === 'HIVE_MEMORY_NOT_NEWER')
  const wd = withdraw(crusty, v2)
  const wdOk = await callTool(wr('crusty'), 'memory_submit', { event: wd, expected_prior_id: v2.id })
  const wdAgain = await callTool(wr('crusty'), 'memory_submit', { event: withdraw(crusty, wd), expected_prior_id: wd.id })
  ok('a withdrawal replaces the head; withdrawing a withdrawn key is refused (HIVE_MEMORY_NOTHING_TO_WITHDRAW)',
    wdOk.accepted && wdOk.status === 'withdrawn' && wdAgain.code === 'HIVE_MEMORY_NOTHING_TO_WITHDRAW')

  // Retention classes: Class A carries exp and expires; Class B carries ["retention","decision"] and outlives 30 days.
  const classA = claim(james, 'hive:ops', 'status-line', { ttlSec: 1209600 })
  const classB = claim(james, 'hive:ops', 'durable-choice', { ttlSec: 0 })
  ok('Class A (ttl_sec 1209600) carries exp and no retention tag; Class B (ttl_sec 0) carries retention decision and no exp',
    classA.tags.some(t => t[0] === 'exp' && Number(t[1]) === classA.created_at + 1209600) && !classA.tags.some(t => t[0] === 'retention') &&
    classB.tags.some(t => t[0] === 'retention' && t[1] === 'decision') && !classB.tags.some(t => t[0] === 'exp'))
  const accA = await callTool(wr('james'), 'memory_submit', { event: classA, expected_prior_id: null })
  const accB = await callTool(wr('james'), 'memory_submit', { event: classB, expected_prior_id: null })
  const qAt = async (t, slug) => { clock = t; return callTool(rd('owner'), 'memory_query', { d: `hive-memory:hive:ops:${slug}` }) }
  const aLive = await qAt(classA.created_at + 1209599, 'status-line')
  const aGone = await qAt(classA.created_at + 1209601, 'status-line')
  const bLate = await qAt(classB.created_at + 31 * DAY, 'durable-choice')
  ok('Class A is accepted until its TTL and expires after it', accA.accepted && aLive.answer === 'found' && aGone.answer === 'none')
  ok('Class B stays accepted past 30 days', accB.accepted && bLate.answer === 'found' && bLate.records[0].retention === 'decision')
  const both = { kind: 30079, pubkey: opsBot.pk, created_at: T0, content: classA.content, tags: [...classA.tags.filter(t => t[0] !== 'exp'), ['exp', String(T0 + 60)], ['retention', 'decision']] }
  const neither = { kind: 30079, pubkey: opsBot.pk, created_at: T0, content: classA.content, tags: classA.tags.filter(t => t[0] !== 'exp') }
  ok('a hive:ops claim with both exp and retention, or neither, is rejected',
    !validateMemoryEvent(both, { memoryGlobalChannelId: GLOBAL_CH, verifySignature: false }).ok &&
    !validateMemoryEvent(neither, { memoryGlobalChannelId: GLOBAL_CH, verifySignature: false }).ok)
  const signedNeither = finalizeEvent({ kind: 30079, created_at: T0 + 50, content: classA.content, tags: neither.tags }, opsBot.sk)
  clock = T0 + 3000
  const neitherSubmit = await callTool(wr('ops'), 'memory_submit', { event: signedNeither, expected_prior_id: null })
  ok('the service refuses a signed claim with neither retention class (HIVE_MEMORY_INVALID_EVENT)', neitherSubmit.code === 'HIVE_MEMORY_INVALID_EVENT')
  await daemon.close()
}

// Backup-stale fence at maxUnbackedSec 3600 and 7200 (store level; same code path as the daemon).
for (const maxUnbackedSec of [3600, 7200]) {
  const cfg = validateAndResolveConfig(rawConfig({ maxUnbackedSec }))
  const p = setup(`fence${maxUnbackedSec}`)
  const s = open(p, { config: cfg })
  const idle = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'idle-first'), expectedPriorId: null, nowSec: T0 + maxUnbackedSec + 1 })
  ok(`[max ${maxUnbackedSec}] the first write after an idle backup outage (write_seq === receipt.write_seq) is fenced`,
    seqOf(s) === 1 && idle.code === 'HIVE_MEMORY_BACKUP_STALE_WRITES_FENCED')
  const inside = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'inside'), expectedPriorId: null, nowSec: T0 + maxUnbackedSec - 1 })
  ok(`[max ${maxUnbackedSec}] a write inside the window is accepted`, inside.accepted === true)
  const after = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'after-outage'), expectedPriorId: null, nowSec: T0 + maxUnbackedSec + 5 })
  const st = s.storeState(james.pk, T0 + maxUnbackedSec + 5)
  ok(`[max ${maxUnbackedSec}] after an outage past the threshold later writes are fenced while the earlier write stays unbacked`,
    after.code === 'HIVE_MEMORY_BACKUP_STALE_WRITES_FENCED' && st.unbacked_writes === 1 && st.last_backup_age_sec === maxUnbackedSec + 5)
  recordVerifiedBackup({ receiptPath: p.receipt, snapshotId: SNAP_ID, writeSeq: seqOf(s), at: T0 + maxUnbackedSec + 6 })
  const resumed = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'after-backup'), expectedPriorId: null, nowSec: T0 + maxUnbackedSec + 7 })
  ok(`[max ${maxUnbackedSec}] a fresh verified backup reopens writes`, resumed.accepted === true)
  s.close()
}
{
  const p = setup('fence-bad')
  const s = open(p)
  writeFileSync(p.receipt, JSON.stringify({ at: T0, write_seq: 99, snapshot_id: SNAP_ID }))
  const ahead = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'x1'), expectedPriorId: null, nowSec: T0 + 5 })
  writeFileSync(p.receipt, JSON.stringify({ at: T0 + 10000, write_seq: 1, snapshot_id: SNAP_ID }))
  const future = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'x2'), expectedPriorId: null, nowSec: T0 + 5 })
  writeFileSync(p.receipt, JSON.stringify({ at: T0, write_seq: 1 }))
  const noId = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'x4'), expectedPriorId: null, nowSec: T0 + 5 })
  writeFileSync(p.receipt, JSON.stringify({ at: T0, write_seq: 1, snapshot_id: SNAP_ID.slice(0, 8) }))
  const shortId = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'x5'), expectedPriorId: null, nowSec: T0 + 5 })
  rmSync(p.receipt)
  const missing = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'x3'), expectedPriorId: null, nowSec: T0 + 5 })
  ok('a receipt ahead of the store, from the future, without a 64-hex snapshot_id, or missing fences writes',
    [ahead, future, noId, shortId, missing].every(r => r.code === 'HIVE_MEMORY_BACKUP_STALE_WRITES_FENCED'))
  s.close()
}
{
  // The receipt carries the snapshot's time, so a backup verified late still fences from when it was taken.
  const backupCli = args => runBin('hive-memory-backup.mjs', args)
  const p = setup('receipt-at')
  const now = Math.floor(Date.now() / 1000)
  const snap = await backupCli(['snapshot', '--db', p.db, '--ledger', p.ledger, '--out-db', join(p.dir, 'snap.sqlite'), '--out-ledger', join(p.dir, 'snap.ledger')])
  const snapOut = JSON.parse(snap.stdout || '{}')
  ok('backup snapshot prints its write_seq and the snapshot time', snap.status === 0 && snapOut.write_seq === 1 && Math.abs(snapOut.snapshot_at - now) <= 5)
  const late = await backupCli(['record-verified', '--backup-receipt', p.receipt, '--snapshot-id', SNAP_ID, '--write-seq', '1', '--at', String(now - 3601)])
  const lateReceipt = JSON.parse(readFileSync(p.receipt, 'utf8'))
  const s = open(p, { config: validateAndResolveConfig(rawConfig({ maxUnbackedSec: 3600 })) })
  const fenced = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'late-verify', { nowSec: now }), expectedPriorId: null, nowSec: now })
  ok('record-verified --at stores the snapshot time, and a snapshot older than maxUnbackedSec fences writes though it was verified just now',
    late.status === 0 && lateReceipt.at === now - 3601 && fenced.code === 'HIVE_MEMORY_BACKUP_STALE_WRITES_FENCED')
  const fresh = await backupCli(['record-verified', '--backup-receipt', p.receipt, '--snapshot-id', SNAP_ID, '--write-seq', '1', '--at', String(snapOut.snapshot_at)])
  const opened = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'fresh-snapshot', { nowSec: now + 1 }), expectedPriorId: null, nowSec: now + 1 })
  ok('a receipt at the snapshot time printed by snapshot reopens writes', fresh.status === 0 && opened.accepted === true)
  s.close()
  const dflt = await backupCli(['record-verified', '--backup-receipt', p.receipt, '--snapshot-id', SNAP_ID, '--write-seq', '2'])
  ok('record-verified without --at defaults to now', dflt.status === 0 && Math.abs(JSON.parse(readFileSync(p.receipt, 'utf8')).at - now) <= 5)
  const future = await backupCli(['record-verified', '--backup-receipt', p.receipt, '--snapshot-id', SNAP_ID, '--write-seq', '2', '--at', String(now + 3600)])
  const junk = await backupCli(['record-verified', '--backup-receipt', p.receipt, '--snapshot-id', SNAP_ID, '--write-seq', '2', '--at', 'yesterday'])
  ok('record-verified refuses a future or malformed --at and leaves the receipt alone',
    future.status === 1 && /in the future/.test(future.stderr) && junk.status === 2 && JSON.parse(readFileSync(p.receipt, 'utf8')).write_seq === 2)
  ok('the receipt is exactly { at, write_seq, snapshot_id } with the restic id given',
    JSON.stringify(Object.keys(JSON.parse(readFileSync(p.receipt, 'utf8')))) === '["at","write_seq","snapshot_id"]' && JSON.parse(readFileSync(p.receipt, 'utf8')).snapshot_id === SNAP_ID)
  const plain = ['record-verified', '--backup-receipt', p.receipt, '--write-seq', '3']
  const badIds = [[], ['--snapshot-id', SNAP_ID.slice(0, 8)], ['--snapshot-id', SNAP_ID.toUpperCase()], ['--snapshot-id', `${SNAP_ID}0`], ['--snapshot-id', 'latest']]
  const refused = await Promise.all(badIds.map(extra => backupCli([...plain, ...extra])))
  ok('record-verified refuses a missing, short, uppercase, overlong or "latest" --snapshot-id and leaves the receipt alone',
    refused.every(r => r.status === 2 && /--snapshot-id/.test(r.stderr)) && JSON.parse(readFileSync(p.receipt, 'utf8')).write_seq === 2)
  ok('recordVerifiedBackup refuses a malformed snapshot id too',
    throwsCode(() => recordVerifiedBackup({ receiptPath: p.receipt, writeSeq: 3, snapshotId: 'abc' }), 'HIVE_MEMORY_BACKUP_REFUSED'))
}

// --- 3. Crash-boundary reconciliation and persistent readiness (§5 test 3) ---
const crash = () => { throw Object.assign(new Error('simulated crash'), { code: 'SIMULATED_CRASH' }) }

// 3.1 Crash before the SQLite Phase 1 COMMIT, for every op.
{
  const dir = mkdtempSync(join(tmpdir(), 'hm-crash-genesis-'))
  const db = join(dir, 'memory.sqlite'); const ledger = join(dir, 'ledger.jsonl')
  ok('[init] crash before COMMIT: genesis throws and leaves no store', throwsCode(() => initEmptyStore({ dbPath: db, ledgerPath: ledger, hooks: { beforeCommit: crash } }), 'SIMULATED_CRASH'))
  const s = new HiveMemoryStore({ dbPath: db, ledgerPath: ledger, receiptPath: join(dir, 'r.json'), config: CFG, log: () => {} })
  s.start()
  ok('[init] after a pre-COMMIT crash the store is DB_MISSING_OR_UNINITIALIZED and answers unknown',
    s.state === 'DB_MISSING_OR_UNINITIALIZED' && unknownAnswer(s, 'DB_MISSING_OR_UNINITIALIZED') && !existsSync(ledger))
  s.close()
  const again = initEmptyStore({ dbPath: db, ledgerPath: ledger })
  ok('[init] genesis can be rerun after a pre-COMMIT crash', again.writeSeq === 1)
}
{
  const p = setup('crash-pre-submit')
  const s = open(p)
  s.hooks = { beforeCommit: crash }
  const out = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'never'), expectedPriorId: null, nowSec: T0 + 5 })
  s.close()
  const s2 = open(p)
  ok('[submit] crash before COMMIT: rollback, READY at the prior write_seq, caller never saw accepted',
    out.accepted === false && s2.state === 'READY' && seqOf(s2) === 1 && s2.db.prepare('SELECT count(*) AS n FROM events').get().n === 0)
  s2.close()
}
{
  const p = setup('crash-pre-purge')
  const s = open(p)
  const e = claim(james, 'hive:ops', 'purge-me')
  s.submit({ writer: 'james', event: e, expectedPriorId: null, nowSec: T0 + 5 })
  s.hooks = { beforeCommit: crash }
  ok('[purge] crash before COMMIT throws', throwsCode(() => s.hardDelete({ id: e.id, nowSec: T0 + 6 }), 'SIMULATED_CRASH'))
  s.close()
  const s2 = open(p)
  ok('[purge] after a pre-COMMIT crash the event is still there at the prior write_seq',
    s2.state === 'READY' && seqOf(s2) === 2 && Boolean(s2.db.prepare('SELECT 1 FROM events WHERE id = ?').get(e.id)))
  s2.close()
}

// 3.2 Genesis crash after COMMIT with the ledger missing, empty, or holding a partial first line.
for (const variant of ['missing', 'empty', 'partial']) {
  for (const op of ['init', 'cutover']) {
    const dir = mkdtempSync(join(tmpdir(), `hm-genesis-${op}-${variant}-`))
    const db = join(dir, 'memory.sqlite'); const ledger = join(dir, 'ledger.jsonl')
    const hooks = { afterCommit: crash }
    let ids = []
    if (op === 'init') {
      throwsCode(() => initEmptyStore({ dbPath: db, ledgerPath: ledger, hooks }), 'SIMULATED_CRASH')
    } else {
      const storeJson = join(dir, 'store.json')
      const evs = [claim(james, 'hive:canon', 'canon-a', { ttlSec: 0 }), claim(opsBot, 'hive:ops', 'ops-a'), claim(biggy, roomA, 'room-a')]
      ids = evs.map(e => e.id)
      writeFileSync(storeJson, JSON.stringify({ version: 1, entries: evs.map(event => ({ event })) }))
      throwsCode(() => migrateStoreJson({ storeJsonPath: storeJson, dbPath: db, ledgerPath: ledger, config: CFG, hooks }), 'SIMULATED_CRASH')
    }
    const pending = withDb(db, d => d.prepare('SELECT pending_ledger_json FROM store_meta').get().pending_ledger_json)
    if (variant === 'empty') writeFileSync(ledger, '')
    if (variant === 'partial') writeFileSync(ledger, pending.slice(0, 20))
    const s = new HiveMemoryStore({ dbPath: db, ledgerPath: ledger, receiptPath: join(dir, 'r.json'), config: CFG, requireMigratedIds: ids, log: () => {} })
    s.start()
    const lines = readLedger(ledger).lines
    ok(`[${op}] genesis crash with the ledger ${variant}: replays pending_ledger_json and reaches READY at write_seq 1`,
      s.state === 'READY' && seqOf(s) === 1 && lines.length === 1 && lines[0].raw === pending && lines[0].rec.op === op)
    s.close()
  }
}
{
  // Tampering fails closed: a changed pending_ledger_json, or a broken event signature, on genesis replay.
  const dir = mkdtempSync(join(tmpdir(), 'hm-genesis-tamper-'))
  const db = join(dir, 'memory.sqlite'); const ledger = join(dir, 'ledger.jsonl')
  throwsCode(() => initEmptyStore({ dbPath: db, ledgerPath: ledger, hooks: { afterCommit: crash } }), 'SIMULATED_CRASH')
  withDb(db, d => d.prepare("UPDATE store_meta SET pending_ledger_json = json_set(pending_ledger_json, '$.store_id', 'forged')").run())
  const s = new HiveMemoryStore({ dbPath: db, ledgerPath: ledger, receiptPath: join(dir, 'r.json'), config: CFG, log: () => {} })
  s.start()
  ok('[init] a tampered pending_ledger_json fails closed with GENESIS_REPLAY_INVALID', s.state === 'GENESIS_REPLAY_INVALID' && unknownAnswer(s, 'GENESIS_REPLAY_INVALID') && !existsSync(ledger))
  s.close()

  const dir2 = mkdtempSync(join(tmpdir(), 'hm-genesis-sig-'))
  const db2 = join(dir2, 'memory.sqlite'); const ledger2 = join(dir2, 'ledger.jsonl'); const sj = join(dir2, 'store.json')
  const ev = claim(james, 'hive:canon', 'signed', { ttlSec: 0 })
  writeFileSync(sj, JSON.stringify({ version: 1, entries: [{ event: ev }] }))
  throwsCode(() => migrateStoreJson({ storeJsonPath: sj, dbPath: db2, ledgerPath: ledger2, config: CFG, hooks: { afterCommit: crash } }), 'SIMULATED_CRASH')
  const badSig = (ev.sig[0] === 'a' ? 'b' : 'a') + ev.sig.slice(1)
  withDb(db2, d => d.prepare("UPDATE events SET raw_json = json_set(raw_json, '$.sig', ?)").run(badSig))
  const s2 = new HiveMemoryStore({ dbPath: db2, ledgerPath: ledger2, receiptPath: join(dir2, 'r.json'), config: CFG, log: () => {} })
  s2.start()
  ok('[cutover] a broken event signature fails closed with GENESIS_REPLAY_INVALID', s2.state === 'GENESIS_REPLAY_INVALID' && unknownAnswer(s2, 'GENESIS_REPLAY_INVALID'))
  s2.close()
}

// 3.3 Post-genesis crash after COMMIT, before or mid-line during the Phase 2 append.
for (const mode of ['before-append', 'mid-line']) {
  const p = setup(`crash-p2-${mode}`)
  const s = open(p)
  s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'n'), expectedPriorId: null, nowSec: T0 + 5 })
  const e = claim(james, 'hive:ops', 'n-plus-one')
  let out
  if (mode === 'before-append') {
    s.hooks = { afterCommit: crash }
    try { out = s.submit({ writer: 'james', event: e, expectedPriorId: null, nowSec: T0 + 6 }) } catch { out = null }
  } else {
    s.hooks = { ledgerWrite: (fd, data) => { writeSync(fd, data, 0, 17); crash() } }
    out = s.submit({ writer: 'james', event: e, expectedPriorId: null, nowSec: T0 + 6 })
  }
  s.close()
  const torn = readFileSync(p.ledger, 'utf8')
  const s2 = open(p)
  const lines = readLedger(p.ledger).lines
  ok(`[submit] crash after COMMIT (${mode}): no accepted reply, then startup flushes pending_ledger_json and reaches READY at N+1`,
    out?.accepted !== true && (mode === 'mid-line' ? !torn.endsWith('\n') : true) &&
    s2.state === 'READY' && seqOf(s2) === 3 && lines.length === 3 && lines[2].rec.id === e.id)
  s2.close()
}
{
  const p = setup('crash-p2-tamper')
  const s = open(p)
  const e = claim(james, 'hive:ops', 'tampered')
  s.hooks = { afterCommit: crash }
  try { s.submit({ writer: 'james', event: e, expectedPriorId: null, nowSec: T0 + 6 }) } catch { /* simulated crash */ }
  s.close()
  withDb(p.db, d => d.prepare("UPDATE events SET raw_json = json_set(raw_json, '$.content', '{}') WHERE id = ?").run(e.id))
  const s2 = open(p)
  ok('[submit] a pending line whose stored event no longer verifies is not flushed (DB_AHEAD_OF_LEDGER)',
    s2.state === 'DB_AHEAD_OF_LEDGER' && ledgerSeqs(p).length === 1 && unknownAnswer(s2, 'DB_AHEAD_OF_LEDGER'))
  s2.close()
}
{
  const p = setup('crash-p2-purge')
  const s = open(p)
  const e = claim(james, 'hive:ops', 'purge-crash')
  s.submit({ writer: 'james', event: e, expectedPriorId: null, nowSec: T0 + 5 })
  s.hooks = { afterCommit: crash }
  ok('[purge] crash after COMMIT throws before the ledger append', throwsCode(() => s.hardDelete({ id: e.id, nowSec: T0 + 6 }), 'SIMULATED_CRASH'))
  s.close()
  const s2 = open(p)
  const last = readLedger(p.ledger).lines.at(-1).rec
  ok('[purge] startup flushes the pending purge and reaches READY with the event gone',
    s2.state === 'READY' && seqOf(s2) === 3 && last.op === 'purge' && last.purged_ids[0] === e.id && !s2.db.prepare('SELECT 1 FROM events WHERE id = ?').get(e.id))
  s2.close()
}

// 3.4 Missing or empty ledger on an established store, and forced desyncs.
const established = name => {
  const p = setup(name)
  const s = open(p)
  s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'e1'), expectedPriorId: null, nowSec: T0 + 5 })
  s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'e2'), expectedPriorId: null, nowSec: T0 + 6 })
  s.close()
  return p
}
for (const [label, mutate, state] of [
  ['deleted ledger', p => rmSync(p.ledger), 'LEDGER_MISSING_FOR_ESTABLISHED_STORE'],
  ['0-byte ledger', p => writeFileSync(p.ledger, ''), 'LEDGER_MISSING_FOR_ESTABLISHED_STORE'],
  ['dbWriteSeq < ledgerMaxSeq', p => withDb(p.db, d => d.prepare('UPDATE store_meta SET write_seq = 2').run()), 'DB_BEHIND_LEDGER'],
  ['dbWriteSeq > ledgerMaxSeq + 1', p => withDb(p.db, d => d.prepare('UPDATE store_meta SET write_seq = 5').run()), 'DB_AHEAD_OF_LEDGER'],
  ['deleted memory.sqlite', p => rmSync(p.db), 'DB_MISSING_OR_UNINITIALIZED'],
  ['truncated memory.sqlite', p => writeFileSync(p.db, ''), 'DB_MISSING_OR_UNINITIALIZED'],
  ['recreated-empty memory.sqlite', p => { rmSync(p.db); withDb(p.db, d => d.exec('CREATE TABLE x (a)')) }, 'DB_MISSING_OR_UNINITIALIZED'],
  ['a corrupt middle ledger line', p => { const l = readFileSync(p.ledger, 'utf8').split('\n'); l[1] = '{oops'; writeFileSync(p.ledger, l.join('\n')) }, 'LEDGER_CORRUPT'],
  ['another store\'s ledger', p => { const q = established('other-store'); copyFileSync(q.ledger, p.ledger) }, 'STORE_ID_MISMATCH'],
]) {
  const p = established(`desync-${label.replace(/[^a-z0-9]+/gi, '-')}`)
  mutate(p)
  const s = open(p)
  ok(`${label} fails closed with ${state} and answers 'unknown', never 'none'`, s.state === state && unknownAnswer(s, state))
  const w = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'blocked'), expectedPriorId: null, nowSec: T0 + 7 })
  const wake = s.wake({ readerPubkey: james.pk, nowSec: T0 + 7 })
  ok(`${label}: writes are refused and the wake digest withholds claims`, w.code === 'HIVE_MEMORY_STORE_NOT_READY' && wake.records.length === 0 && wake.digest.includes(`store_state: ${state}`))
  s.close()
  if (!existsSync(p.db)) ok(`${label}: startup never creates a database implicitly`, !existsSync(p.db))
}

// 3.4b Canon is a handful of standing decisions; the wake digest shows all of it before room notes take the rest.
// With a fixed 35% canon share, five canon claims of the real length lost the oldest, James's priorities (2026-11-06).
{
  const p = setup('wake-canon')
  const s = open(p)
  const long = n => `${'standing decision '.repeat(18)}${n}`
  const canonEvents = [1, 2, 3, 4, 5].map(n => claim(james, 'hive:canon', `canon-${n}`, { ttlSec: 0, claim: long(n) }))
  for (const ev of canonEvents) s.submit({ writer: 'james', event: ev, expectedPriorId: null, nowSec: T0 + 200 })
  for (let n = 0; n < 40; n++) s.submit({ writer: 'ops', event: claim(opsBot, 'hive:ops', `ops-${n}`, { claim: `${'room note '.repeat(25)}${n}` }), expectedPriorId: null, nowSec: T0 + 200 })
  const wake = s.wake({ readerPubkey: james.pk, nowSec: T0 + 300 })
  ok('the wake digest shows every canon claim, the oldest included, and fills the rest with ops within budget',
    wake.counts.canon_shown === 5 && wake.counts.canon_omitted === 0 && wake.digest.includes('canon-1]') &&
    wake.counts.ops_shown > 0 && wake.counts.ops_omitted > 0 && wake.char_length <= wake.max_chars)
  const tight = s.wake({ readerPubkey: james.pk, maxChars: 1000, nowSec: T0 + 300 })
  ok('a tight budget still keeps room for ops and stays within it', tight.char_length <= 1000 && tight.counts.canon_shown >= 1 && tight.digest.includes('Rank 3'))
  s.close()
}

// 3.5 A failed Phase 2 append moves the store to LEDGER_IO_ERROR and never returns accepted.
{
  const p = setup('ledger-io')
  const s = open(p)
  s.hooks = { ledgerWrite: () => { throw Object.assign(new Error('EIO'), { code: 'EIO' }) } }
  const out = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'io'), expectedPriorId: null, nowSec: T0 + 5 })
  const next = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'io2'), expectedPriorId: null, nowSec: T0 + 6 })
  ok('a failed Phase 2 append returns HIVE_MEMORY_LEDGER_IO_ERROR, never accepted, and the store leaves READY',
    out.accepted === false && out.code === 'HIVE_MEMORY_LEDGER_IO_ERROR' && s.state === 'LEDGER_IO_ERROR' && next.code === 'HIVE_MEMORY_STORE_NOT_READY' && unknownAnswer(s, 'LEDGER_IO_ERROR'))
  s.close()
  const s2 = open(p)
  ok('after the I/O fault clears, startup flushes the committed write and reaches READY', s2.state === 'READY' && seqOf(s2) === 2)
  s2.close()
}

// --- Migration with exact event-ID parity ---
{
  const dir = mkdtempSync(join(tmpdir(), 'hm-migrate-'))
  const db = join(dir, 'memory.sqlite'); const ledger = join(dir, 'ledger.jsonl'); const sj = join(dir, 'store.json')
  const v1 = claim(james, 'hive:canon', 'policy', { ttlSec: 0 })
  const v2 = claim(james, 'hive:canon', 'policy', { ttlSec: 0, priorCreatedAt: v1.created_at })
  const other = claim(crusty, roomB, 'room-note')
  const evs = [v2, v1, other]
  const write = entries => writeFileSync(sj, JSON.stringify({ version: 1, entries: entries.map(event => ({ event })) }))
  write([...evs, claim(outsider, 'hive:ops', 'intruder')])
  ok('migration refuses an entry whose author may not write its scope', throwsCode(() => migrateStoreJson({ storeJsonPath: sj, dbPath: db, ledgerPath: ledger, config: CFG }), 'HIVE_MEMORY_MIGRATION_REFUSED') && !existsSync(db))
  write([...evs, v1])
  ok('migration refuses a duplicate event', throwsCode(() => migrateStoreJson({ storeJsonPath: sj, dbPath: db, ledgerPath: ledger, config: CFG }), 'HIVE_MEMORY_MIGRATION_REFUSED'))
  write(evs)
  ok('migration refuses when a required event id is absent',
    throwsCode(() => migrateStoreJson({ storeJsonPath: sj, dbPath: db, ledgerPath: ledger, config: CFG, requireMigratedIds: ['e'.repeat(64)] }), 'HIVE_MEMORY_MIGRATION_REFUSED'))
  const out = migrateStoreJson({ storeJsonPath: sj, dbPath: db, ledgerPath: ledger, config: CFG, requireMigratedIds: [v1.id, v2.id, other.id], nowSec: T0 })
  const rows = withDb(db, d => d.prepare('SELECT id, is_current FROM events ORDER BY id').all())
  const cut = readLedger(ledger).lines[0].rec
  ok('migration imports exactly the store.json event ids, ledgered as one cutover record',
    rows.map(r => r.id).join() === evs.map(e => e.id).sort().join() && cut.op === 'cutover' && cut.event_ids.join() === evs.map(e => e.id).sort().join())
  ok('migration picks NIP-01 current heads', rows.find(r => r.id === v2.id).is_current === 1 && rows.find(r => r.id === v1.id).is_current === 0)
  ok('migration renames store.json out of the way', !existsSync(sj) && existsSync(out.migratedPath))
  ok('genesis never overwrites an existing store', throwsCode(() => initEmptyStore({ dbPath: db, ledgerPath: ledger }), 'HIVE_MEMORY_GENESIS_REFUSED'))
}

// --- 4. Bidirectional restore reconciliation (§5 test 4) ---
{
  const p = setup('restore-gap')
  const s = open(p)
  const { snap, out: snapOut, authority: auth } = await backupDir(p, 'snap1')
  const priv = claim(crusty, roomB, 'private-note')
  s.submit({ writer: 'crusty', event: priv, expectedPriorId: null, nowSec: T0 + 5 })
  ok('a running daemon holds the store lock, so restore refuses (HIVE_MEMORY_STORE_LOCKED)',
    throwsCode(() => restoreSnapshot({ authority: auth, snapshotPath: snap, dbPath: p.db, ledgerPath: p.ledger, config: CFG, nowSec: T0 + 20 }), 'HIVE_MEMORY_STORE_LOCKED'))
  s.close()
  let gapErr = null
  try { restoreSnapshot({ authority: auth, snapshotPath: snap, dbPath: p.db, ledgerPath: p.ledger, config: CFG, nowSec: T0 + 20 }) } catch (e) { gapErr = e }
  ok('restoring the write_seq 1 snapshot after a write_seq 2 claim fails with HIVE_MEMORY_RESTORE_GAP_DETECTED and reports the gap',
    snapOut.snapshotSeq === 1 && gapErr?.code === 'HIVE_MEMORY_RESTORE_GAP_DETECTED' && gapErr.gap[0].id === priv.id && gapErr.ledgerMaxSeq === 2 && !gapErr.message.includes(JSON.parse(priv.content).claim))
  const live = join(p.dir, 'live.sqlite')
  copyFileSync(p.db, live)
  copyFileSync(snap, p.db)
  const sd = open(p)
  ok('the same snapshot opened directly by the daemon fails closed with DB_BEHIND_LEDGER', sd.state === 'DB_BEHIND_LEDGER' && unknownAnswer(sd, 'DB_BEHIND_LEDGER'))
  sd.close()
  copyFileSync(live, p.db)
  ok('--acknowledge-gap must name the ledger max seq', throwsCode(() => restoreSnapshot({ authority: auth, snapshotPath: snap, dbPath: p.db, ledgerPath: p.ledger, config: CFG, acknowledgeGap: 1, nowSec: T0 + 20 }), 'HIVE_MEMORY_RESTORE_GAP_DETECTED'))
  const restored = restoreSnapshot({ authority: auth, snapshotPath: snap, dbPath: p.db, ledgerPath: p.ledger, config: CFG, acknowledgeGap: 2, nowSec: T0 + 9 })
  const s2 = open(p)
  const last = readLedger(p.ledger).lines.at(-1).rec
  ok('--acknowledge-gap 2 installs the snapshot, records restore-gap-ack, and reaches READY',
    restored.writeSeq === 3 && last.op === 'restore-gap-ack' && last.acked_ids[0] === priv.id && s2.state === 'READY' && seqOf(s2) === 3)
  ok('the acknowledged write stays lost and the fact key is writable again',
    s2.submit({ writer: 'crusty', event: claim(crusty, roomB, 'private-note'), expectedPriorId: null, nowSec: T0 + 10 }).accepted === true)
  s2.close()
}
{
  const p = setup('restore-prepurge')
  const s = open(p)
  const e2 = claim(crusty, roomB, 'to-be-purged')
  s.submit({ writer: 'crusty', event: e2, expectedPriorId: null, nowSec: T0 + 5 })
  const { snap, authority: auth } = await backupDir(p, 'snap2')
  const purged = s.hardDelete({ id: e2.id, nowSec: T0 + 6 })
  s.close()
  ok('hive-memory-purge records op purge at write_seq 3', purged.seq === 3 && readLedger(p.ledger).lines.at(-1).rec.op === 'purge')
  let err = null
  try { restoreSnapshot({ authority: auth, snapshotPath: snap, dbPath: p.db, ledgerPath: p.ledger, config: CFG, nowSec: T0 + 20 }) } catch (e) { err = e }
  ok('restoring the pre-purge write_seq 2 snapshot is refused (HIVE_MEMORY_RESTORE_PRE_PURGE_SNAPSHOT)', err?.code === 'HIVE_MEMORY_RESTORE_PRE_PURGE_SNAPSHOT')
  const live = join(p.dir, 'live.sqlite')
  copyFileSync(p.db, live)
  copyFileSync(snap, p.db)
  const sd = open(p)
  ok('the pre-purge snapshot placed on disk fails closed with DB_HAS_UNEXPECTED_OR_PURGED_EVENTS instead of resurrecting E2',
    sd.state === 'DB_HAS_UNEXPECTED_OR_PURGED_EVENTS' && unknownAnswer(sd, 'DB_HAS_UNEXPECTED_OR_PURGED_EVENTS'))
  sd.close()
  const out = restoreSnapshot({ authority: auth, snapshotPath: snap, dbPath: p.db, ledgerPath: p.ledger, config: CFG, reapplyPurges: true, nowSec: T0 + 20 })
  const s2 = open(p)
  ok('--reapply-purges deletes E2, advances write_seq to 3, and reaches READY',
    out.writeSeq === 3 && s2.state === 'READY' && seqOf(s2) === 3 && !s2.db.prepare('SELECT 1 FROM events WHERE id = ?').get(e2.id))
  s2.close()
  const bytes = Buffer.concat([p.db, `${p.db}-wal`].filter(existsSync).map(f => readFileSync(f)))
  ok('E2 is absent from the SQLite pages after VACUUM (only its id survives, as ledger metadata)',
    !bytes.includes(Buffer.from(e2.sig)) && !bytes.includes(Buffer.from(JSON.parse(e2.content).claim)))
}
{
  const p = setup('restore-refusals')
  const s = open(p)
  s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'r1'), expectedPriorId: null, nowSec: T0 + 5 })
  const { snap, authority: auth } = await backupDir(p, 'snap')
  s.close()
  const extra = join(p.dir, 'extra.sqlite')
  copyFileSync(snap, extra)
  const rogue = claim(james, 'hive:ops', 'never-ledgered')
  withDb(extra, d => d.prepare(`INSERT INTO events (id, pubkey, kind, created_at, d, scope, scope_type, room_id, topic, status, retention, as_of_git, as_of_evt, exp, raw_json, ingested_at, is_current)
    VALUES (?, ?, ?, ?, ?, 'hive:ops', 'hive:ops', NULL, 'never-ledgered', 'active', 'ephemeral', 'abc1234', NULL, NULL, ?, ?, 1)`)
    .run(rogue.id, james.pk, rogue.kind, rogue.created_at, rogue.tags[0][1], JSON.stringify(rogue), T0))
  ok('a snapshot with an event the ledger never recorded is refused (HIVE_MEMORY_RESTORE_UNKNOWN_EVENT)',
    throwsCode(() => restoreSnapshot({ authority: auth, snapshotPath: extra, dbPath: p.db, ledgerPath: p.ledger, config: CFG, reapplyPurges: true, nowSec: T0 + 20 }), 'HIVE_MEMORY_RESTORE_UNKNOWN_EVENT'))
  const ahead = join(p.dir, 'ahead.sqlite')
  copyFileSync(snap, ahead)
  withDb(ahead, d => d.prepare('UPDATE store_meta SET write_seq = 9').run())
  ok('a snapshot ahead of the ledger is refused', throwsCode(() => restoreSnapshot({ authority: auth, snapshotPath: ahead, dbPath: p.db, ledgerPath: p.ledger, config: CFG, nowSec: T0 + 20 }), 'HIVE_MEMORY_RESTORE_SNAPSHOT_AHEAD'))
  const foreign = join(p.dir, 'foreign.sqlite')
  copyFileSync(snap, foreign)
  withDb(foreign, d => d.prepare("UPDATE store_meta SET store_id = 'other'").run())
  ok('a snapshot from another store is refused', throwsCode(() => restoreSnapshot({ authority: auth, snapshotPath: foreign, dbPath: p.db, ledgerPath: p.ledger, config: CFG, nowSec: T0 + 20 }), 'HIVE_MEMORY_RESTORE_STORE_ID_MISMATCH'))
  const forged = join(p.dir, 'forged.sqlite')
  copyFileSync(snap, forged)
  withDb(forged, d => d.prepare("UPDATE events SET raw_json = json_set(raw_json, '$.content', '{}')").run())
  ok('a snapshot with an event that no longer verifies is refused', throwsCode(() => restoreSnapshot({ authority: auth, snapshotPath: forged, dbPath: p.db, ledgerPath: p.ledger, config: CFG, nowSec: T0 + 20 }), 'HIVE_MEMORY_RESTORE_INVALID_EVENT'))
  const same = restoreSnapshot({ authority: auth, snapshotPath: snap, dbPath: p.db, ledgerPath: p.ledger, config: CFG, nowSec: T0 + 20 })
  ok('a snapshot that matches the ledger exactly installs cleanly', same.installed && same.writeSeq === 2)
}
{
  // The restore-gap-ack op at each crash boundary.
  const p = setup('restore-crash')
  const s = open(p)
  const { snap, authority: auth } = await backupDir(p, 'snap')
  const lost = claim(james, 'hive:ops', 'lost')
  s.submit({ writer: 'james', event: lost, expectedPriorId: null, nowSec: T0 + 5 })
  s.close()
  ok('[restore-gap-ack] crash before COMMIT throws',
    throwsCode(() => restoreSnapshot({ authority: auth, snapshotPath: snap, dbPath: p.db, ledgerPath: p.ledger, config: CFG, acknowledgeGap: 2, nowSec: T0 + 20, hooks: { beforeCommit: crash } }), 'SIMULATED_CRASH'))
  const s1 = open(p)
  ok('[restore-gap-ack] after a pre-COMMIT crash the live store is untouched',
    s1.state === 'READY' && seqOf(s1) === 2 && Boolean(s1.db.prepare('SELECT 1 FROM events WHERE id = ?').get(lost.id)))
  s1.close()
  ok('[restore-gap-ack] crash after COMMIT and install, before the ledger append, throws',
    throwsCode(() => restoreSnapshot({ authority: auth, snapshotPath: snap, dbPath: p.db, ledgerPath: p.ledger, config: CFG, acknowledgeGap: 2, nowSec: T0 + 20, hooks: { afterCommit: crash } }), 'SIMULATED_CRASH'))
  const s2 = open(p)
  ok('[restore-gap-ack] startup flushes the pending restore-gap-ack and reaches READY at N+1',
    s2.state === 'READY' && seqOf(s2) === 3 && readLedger(p.ledger).lines.at(-1).rec.op === 'restore-gap-ack')
  s2.close()
}

const loseHost = p => { for (const f of [p.db, `${p.db}-wal`, `${p.db}-shm`, p.ledger, p.receipt]) rmSync(f, { force: true }) }
{
  // Full-host --with-ledger restore of pre-purge snapshot S2 after a verified post-purge snapshot S3 (§5 test 4).
  const p = setup('restore-fullhost')
  const s = open(p)
  const e2 = claim(crusty, roomB, 'to-be-purged')
  s.submit({ writer: 'crusty', event: e2, expectedPriorId: null, nowSec: T0 + 5 })
  const S2 = await backupDir(p, 'S2')
  s.hardDelete({ id: e2.id, nowSec: T0 + 6 })
  const S3 = await backupDir(p, 'S3')
  recordVerifiedBackup({ receiptPath: p.receipt, snapshotId: SNAP_ID, writeSeq: S3.out.snapshotSeq, at: T0 + 7, nowSec: T0 + 7 })
  const staleLocal = join(p.dir, 'local-ledger-at-2.jsonl')
  writeFileSync(staleLocal, readFileSync(join(S2.dir, 'accepted-ledger.jsonl')))
  s.close()
  loseHost(p)
  const full = (extra = {}) => restoreSnapshot({ snapshotPath: S2.snap, dbPath: p.db, ledgerPath: p.ledger, config: CFG, withLedger: true, nowSec: T0 + 20, ...extra })
  ok('a full-host restore with no authority fails closed (HIVE_MEMORY_RESTORE_AUTHORITY_UNAVAILABLE) and installs nothing',
    throwsCode(() => full(), 'HIVE_MEMORY_RESTORE_AUTHORITY_UNAVAILABLE') && !existsSync(p.ledger) && !existsSync(p.db))
  const records = purgeRecords(p, 'purges', S3)
  const torn = join(p.dir, 'torn.jsonl')
  writeFileSync(torn, readFileSync(S3.ledger).subarray(0, -5))
  const gappy = join(p.dir, 'gappy.jsonl')
  writeFileSync(gappy, readFileSync(S3.ledger, 'utf8').split('\n').filter((_, i) => i !== 1).join('\n'))
  const stray = purgeRecords(p, 'stray-purges')
  writeFileSync(join(stray, 'notes.txt'), 'x')
  const unavailable = [
    { ledger: join(p.dir, 'absent.jsonl'), purgeRecords: records }, { ledger: S3.ledger }, { ledger: S3.ledger, purgeRecords: join(p.dir, 'absent') },
    { ledger: torn, purgeRecords: records }, { ledger: gappy, purgeRecords: records }, { ledger: S3.ledger, purgeRecords: stray },
  ]
  ok('a missing, torn or broken-chain authority ledger, or missing or malformed purge records, fails closed (HIVE_MEMORY_RESTORE_AUTHORITY_UNAVAILABLE)',
    unavailable.every(authority => throwsCode(() => full({ authority }), 'HIVE_MEMORY_RESTORE_AUTHORITY_UNAVAILABLE')) && !existsSync(p.ledger))
  ok('a hive-memory-purge ledger ahead of the authority ledger fails closed (HIVE_MEMORY_RESTORE_AUTHORITY_MISMATCH)',
    throwsCode(() => full({ authority: { ledger: S2.ledger, purgeRecords: records } }), 'HIVE_MEMORY_RESTORE_AUTHORITY_MISMATCH') && !existsSync(p.ledger))
  const authority = { ledger: S3.ledger, purgeRecords: records }
  let err = null
  try { full({ authority }) } catch (e) { err = e }
  const installed = readLedger(p.ledger).lines
  ok('restoring S2 with --with-ledger is refused (HIVE_MEMORY_RESTORE_PRE_PURGE_SNAPSHOT) against the write_seq 3 ledger installed from S3, not S2\'s own',
    err?.code === 'HIVE_MEMORY_RESTORE_PRE_PURGE_SNAPSHOT' && installed.length === 3 && installed.at(-1).rec.op === 'purge' &&
    installed.at(-1).rec.purged_ids[0] === e2.id && !existsSync(p.db) && (statSync(p.ledger).mode & 0o777) === 0o600)
  copyFileSync(S2.snap, p.db)
  const sd = open(p)
  ok('S2 placed beside the installed S3 ledger fails closed (DB_HAS_UNEXPECTED_OR_PURGED_EVENTS) instead of resurrecting E2',
    sd.state === 'DB_HAS_UNEXPECTED_OR_PURGED_EVENTS' && unknownAnswer(sd, 'DB_HAS_UNEXPECTED_OR_PURGED_EVENTS'))
  sd.close()
  rmSync(p.db)
  ok('rerunning --with-ledger over the identical ledger it installed is allowed, and refuses S2 again',
    throwsCode(() => full({ authority }), 'HIVE_MEMORY_RESTORE_PRE_PURGE_SNAPSHOT'))
  writeFileSync(p.ledger, readFileSync(staleLocal), { mode: 0o600 })
  ok('--with-ledger never overwrites a different local ledger (HIVE_MEMORY_RESTORE_LEDGER_EXISTS)',
    throwsCode(() => full({ authority, reapplyPurges: true }), 'HIVE_MEMORY_RESTORE_LEDGER_EXISTS'))
  ok('a same-host restore whose local ledger is behind the newest verified backup is refused (HIVE_MEMORY_RESTORE_AUTHORITY_STALE)',
    throwsCode(() => full({ authority, withLedger: false, reapplyPurges: true }), 'HIVE_MEMORY_RESTORE_AUTHORITY_STALE'))
  rmSync(p.ledger)
  const out = full({ authority, reapplyPurges: true })
  const s2 = open(p)
  ok('--with-ledger --reapply-purges deletes E2, advances write_seq to 3, and reaches READY with E2 absent',
    out.writeSeq === 3 && s2.state === 'READY' && seqOf(s2) === 3 && !s2.db.prepare('SELECT 1 FROM events WHERE id = ?').get(e2.id))
  ok('the restored store keeps writers fenced until a verified backup covers the purge (HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE)',
    s2.submit({ writer: 'crusty', event: claim(crusty, roomB, 'after-restore'), expectedPriorId: null, nowSec: T0 + 21 }).code === 'HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE')
  s2.close()
  loseHost(p)
  const cfgPath = join(p.dir, 'config.json')
  writeFileSync(cfgPath, JSON.stringify(rawConfig()))
  const base = ['--snapshot', S2.snap, '--db', p.db, '--ledger', p.ledger, '--config', cfgPath]
  const none = await runBin('hive-memory-restore.mjs', base)
  const auth = ['--authority-ledger', S3.ledger, '--purge-records', records]
  const unknown = await Promise.all([['--authority', S3.dir], ['--purge-authority', S3.dir], ['--reapply-purge'], ['--with-ledger', '--with-ledger']]
    .map(extra => runBin('hive-memory-restore.mjs', [...base, ...auth, ...extra])))
  const refused = await runBin('hive-memory-restore.mjs', [...base, ...auth, '--with-ledger'])
  const done = await runBin('hive-memory-restore.mjs', [...base, ...auth, '--with-ledger', '--reapply-purges'])
  ok('bin/hive-memory-restore: no authority exits 1 (AUTHORITY_UNAVAILABLE), unknown or repeated flags exit 2, S2 is refused, then installs with --reapply-purges',
    none.status === 1 && /HIVE_MEMORY_RESTORE_AUTHORITY_UNAVAILABLE/.test(none.stderr) && unknown.every(r => r.status === 2) &&
    refused.status === 1 && /HIVE_MEMORY_RESTORE_PRE_PURGE_SNAPSHOT/.test(refused.stderr) && done.status === 0 && JSON.parse(done.stdout).write_seq === 3)
}
{
  // A 90-day maintenance purge of E after snapshot S2, then the host is lost before the next scheduled backup.
  const p = setup('restore-maintenance')
  const s = open(p)
  const old = claim(james, 'hive:ops', 'rolling', { ttlSec: 0 })
  const succ = claim(james, 'hive:ops', 'rolling', { ttlSec: 0, priorCreatedAt: old.created_at })
  s.submit({ writer: 'james', event: old, expectedPriorId: null, nowSec: T0 + 50 })
  s.submit({ writer: 'james', event: succ, expectedPriorId: old.id, nowSec: T0 + 51 })
  const now = succ.created_at + RETENTION_PURGE_AFTER_SEC + 1
  const S2 = await backupDir(p, 'S2')
  const purged = s.purgeRetention({ nowSec: now })
  const S3 = await backupDir(p, 'S3')
  s.close()
  loseHost(p)
  const full = extra => restoreSnapshot({ snapshotPath: S2.snap, dbPath: p.db, ledgerPath: p.ledger, config: CFG, authority: { ledger: S3.ledger, purgeRecords: purgeRecords(p, 'purges', S3) }, withLedger: true, nowSec: now + 10, ...extra })
  ok('[maintenance, S3 verified] --with-ledger restore of S2 is refused against S3\'s ledger (HIVE_MEMORY_RESTORE_PRE_PURGE_SNAPSHOT)',
    purged.seq === 4 && throwsCode(() => full(), 'HIVE_MEMORY_RESTORE_PRE_PURGE_SNAPSHOT') && readLedger(p.ledger).lines.length === 4 && !existsSync(p.db))
  loseHost(p)
  const noS3 = (extra = {}) => restoreSnapshot({ snapshotPath: S2.snap, dbPath: p.db, ledgerPath: p.ledger, config: CFG, authority: S2.authority, nowSec: now + 10, ...extra })
  let err = null
  try { noS3({ withLedger: true }) } catch (e) { err = e }
  ok('[maintenance, backup lost with the host] restore of S2, the newest backup, still refuses E past the retention window (HIVE_MEMORY_RESTORE_PRE_PURGE_SNAPSHOT)',
    err?.code === 'HIVE_MEMORY_RESTORE_PRE_PURGE_SNAPSHOT' && /90-day retention/.test(err.message) && !existsSync(p.db))
  const out = noS3({ reapplyPurges: true })
  const last = readLedger(p.ledger).lines.at(-1).rec
  const s2 = open(p)
  ok('[maintenance, backup lost with the host] --reapply-purges re-runs the 90-day purge: E is gone and op purge is recorded at write_seq 4',
    out.writeSeq === 4 && out.retentionPurged[0] === old.id && last.op === 'purge' && last.reason === 'retention' && last.purged_ids[0] === old.id &&
    s2.state === 'READY' && !s2.db.prepare('SELECT 1 FROM events WHERE id = ?').get(old.id))
  ok('[maintenance, backup lost with the host] writers stay fenced until a verified backup covers that purge',
    s2.submit({ writer: 'james', event: claim(james, 'hive:ops', 'after', { nowSec: now + 11 }), expectedPriorId: null, nowSec: now + 11 }).code === 'HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE')
  s2.close()
}
{
  // One restore that both acknowledges a lost write and purges a row past retention stages two ops in one
  // SQLite commit; startup replays both pending lines, and only when they match exactly.
  const combined = async name => {
    const p = setup(name)
    const s = open(p)
    const old = claim(james, 'hive:ops', 'rolling', { ttlSec: 0 })
    const succ = claim(james, 'hive:ops', 'rolling', { ttlSec: 0, priorCreatedAt: old.created_at })
    s.submit({ writer: 'james', event: old, expectedPriorId: null, nowSec: T0 + 50 })
    s.submit({ writer: 'james', event: succ, expectedPriorId: old.id, nowSec: T0 + 51 })
    const S = await backupDir(p, 'S')
    s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'lost'), expectedPriorId: null, nowSec: T0 + 52 })
    s.close()
    const now = succ.created_at + RETENTION_PURGE_AFTER_SEC + 1
    const run = hooks => restoreSnapshot({ snapshotPath: S.snap, dbPath: p.db, ledgerPath: p.ledger, config: CFG, authority: S.authority, acknowledgeGap: 4, reapplyPurges: true, nowSec: now, hooks })
    return { p, run, old }
  }
  const ops = p => readLedger(p.ledger).lines.map(l => l.rec.op).join(',')
  const c = await combined('restore-combined')
  ok('[gap-ack + retention purge] crash after COMMIT and install, before the ledger append, throws with the DB two ahead',
    throwsCode(() => c.run({ afterCommit: crash }), 'SIMULATED_CRASH') && ledgerSeqs(c.p).length === 4 &&
    withDb(c.p.db, d => d.prepare('SELECT write_seq FROM store_meta').get().write_seq) === 6)
  const s1 = open(c.p)
  ok('[gap-ack + retention purge] startup replays both pending lines in order and reaches READY at N+2',
    s1.state === 'READY' && seqOf(s1) === 6 && ops(c.p) === 'init,submit,submit,submit,restore-gap-ack,purge' &&
    !s1.db.prepare('SELECT 1 FROM events WHERE id = ?').get(c.old.id))
  ok('[gap-ack + retention purge] writers stay fenced until a verified backup covers the replayed purge',
    s1.submit({ writer: 'james', event: claim(james, 'hive:ops', 'after', { nowSec: T0 + 60 }), expectedPriorId: null, nowSec: T0 + 60 }).code === 'HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE')
  s1.close()

  const t = await combined('restore-combined-torn')
  ok('[gap-ack + retention purge] a crash mid-append, after the first line lands, throws',
    throwsCode(() => t.run({ ledgerWrite: (fd, data) => { writeSync(fd, data, 0, data.indexOf(10) + 12); crash() } }), 'SIMULATED_CRASH'))
  const s2 = open(t.p)
  ok('[gap-ack + retention purge] startup truncates the torn line, appends only the missing purge, and reaches READY at N+2',
    s2.state === 'READY' && seqOf(s2) === 6 && ops(t.p) === 'init,submit,submit,submit,restore-gap-ack,purge')
  s2.close()

  const tamper = [
    ['a pending list one line short', d => d.prepare("UPDATE store_meta SET pending_ledger_json = substr(pending_ledger_json, instr(pending_ledger_json, char(10)) + 1)").run()],
    ['a pending list whose lines are reordered', d => {
      const [a, b] = d.prepare('SELECT pending_ledger_json AS j FROM store_meta').get().j.split('\n')
      d.prepare('UPDATE store_meta SET pending_ledger_json = ?').run(`${b}\n${a}`)
    }],
    ['a pending purge that names a different row', d => {
      const [a, b] = d.prepare('SELECT pending_ledger_json AS j FROM store_meta').get().j.split('\n')
      d.prepare('UPDATE store_meta SET pending_ledger_json = ?').run(`${a}\n${JSON.stringify({ ...JSON.parse(b), purged_ids: ['ab'.repeat(32)] })}`)
    }],
  ]
  for (const [label, edit] of tamper) {
    const m = await combined(`restore-combined-${tamper.findIndex(x => x[0] === label)}`)
    throwsCode(() => m.run({ afterCommit: crash }), 'SIMULATED_CRASH')
    withDb(m.p.db, edit)
    const s3 = open(m.p)
    ok(`[gap-ack + retention purge] ${label} fails closed (DB_AHEAD_OF_LEDGER) and appends nothing`,
      s3.state === 'DB_AHEAD_OF_LEDGER' && unknownAnswer(s3, 'DB_AHEAD_OF_LEDGER') && ledgerSeqs(m.p).length === 4)
    s3.close()
  }
}

// --- Retention purge and owner hard delete ---
{
  const p = setup('retention')
  const s = open(p)
  const old = claim(james, 'hive:ops', 'rolling', { ttlSec: 0 })
  const succ = claim(james, 'hive:ops', 'rolling', { ttlSec: 0, priorCreatedAt: old.created_at })
  const gone = claim(james, 'hive:ops', 'gone', { ttlSec: 0 })
  const tomb = withdraw(james, gone)
  const shortLived = claim(james, 'hive:ops', 'short', { ttlSec: 60 })
  const keeper = claim(james, 'hive:canon', 'keeper', { ttlSec: 0 })
  for (const [e, prior] of [[old, null], [succ, old.id], [gone, null], [tomb, gone.id], [shortLived, null], [keeper, null]]) {
    s.submit({ writer: 'james', event: e, expectedPriorId: prior, nowSec: T0 + 50 })
  }
  const early = s.retentionCandidates(succ.created_at + RETENTION_PURGE_AFTER_SEC - 10)
  ok('nothing is purged before 90 days past end of life', early.length === 0)
  const now = Math.max(succ.created_at, tomb.created_at, shortLived.created_at + 60) + RETENTION_PURGE_AFTER_SEC + 1
  recordVerifiedBackup({ receiptPath: p.receipt, snapshotId: SNAP_ID, writeSeq: seqOf(s), at: now, nowSec: now })
  const out = s.purgeRetention({ nowSec: now })
  const left = s.db.prepare('SELECT id FROM events').all().map(r => r.id).sort()
  const rate = s.db.prepare('SELECT count(*) AS n FROM writer_rate_log').get().n
  ok('retention purges superseded, withdrawn and expired rows 90 days past end of life, and keeps live decisions',
    out.purged.length === 4 && [old.id, tomb.id, shortLived.id, gone.id].every(id => out.purged.includes(id)) &&
    left.join() === [succ.id, keeper.id].sort().join() && readLedger(p.ledger).lines.at(-1).rec.reason === 'retention')
  ok('retention also prunes writer_rate_log rows older than a day', rate === 0)
  const fenced = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'after-retention', { nowSec: now }), expectedPriorId: null, nowSec: now + 1 })
  ok('the retention purge fences every write until a verified backup covers it (HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE)',
    fenced.code === 'HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE' && s.db.prepare('SELECT last_purge_seq FROM store_meta').get().last_purge_seq === out.seq)
  recordVerifiedBackup({ receiptPath: p.receipt, snapshotId: SNAP_ID, writeSeq: out.seq, at: now + 1, nowSec: now + 1 })
  const purgedAgain = s.submit({ writer: 'james', event: old, expectedPriorId: null, nowSec: now + 1 })
  ok('a purged event is never stored again (HIVE_MEMORY_PURGED_EVENT)', purgedAgain.code === 'HIVE_MEMORY_PURGED_EVENT')
  const hd = s.hardDelete({ d: `hive-memory:hive:canon:keeper`, nowSec: now + 2 })
  ok('owner hard delete by fact key purges every version and records hard-delete', hd.purged[0] === keeper.id && readLedger(p.ledger).lines.at(-1).rec.reason === 'hard-delete')
  ok('hard delete with no match is an error', throwsCode(() => s.hardDelete({ id: 'f'.repeat(64), nowSec: now + 3 }), 'HIVE_MEMORY_PURGE_NO_MATCH'))
  s.close()
  const bytes = readFileSync(p.db)
  ok('a hard-deleted claim leaves no signature or text in the SQLite pages', !bytes.includes(Buffer.from(keeper.sig)) && !bytes.includes(Buffer.from(JSON.parse(keeper.content).claim)))
  const s2 = open(p)
  ok('the store reconciles READY after retention and hard-delete purges', s2.state === 'READY')
  s2.close()
}

{
  // One completion barrier for every op purge (§4.5): the 90-day pass whose immediate backup fails, then a hard delete.
  const p = setup('purge-barrier')
  const cfgPath = join(p.dir, 'config.json')
  writeFileSync(cfgPath, JSON.stringify(rawConfig()))
  const s = open(p)
  const old = claim(james, 'hive:ops', 'rolling', { ttlSec: 0 })
  const succ = claim(james, 'hive:ops', 'rolling', { ttlSec: 0, priorCreatedAt: old.created_at })
  s.submit({ writer: 'james', event: old, expectedPriorId: null, nowSec: T0 + 50 })
  s.submit({ writer: 'james', event: succ, expectedPriorId: old.id, nowSec: T0 + 51 })
  const now = succ.created_at + RETENTION_PURGE_AFTER_SEC + 1
  recordVerifiedBackup({ receiptPath: p.receipt, snapshotId: SNAP_ID, writeSeq: seqOf(s), at: now, nowSec: now })
  const gateArgs = ['gate', '--ledger', p.ledger, '--backup-receipt', p.receipt]
  const open0 = await runBin('hive-memory-backup.mjs', gateArgs)
  ok('the gate opens when a valid receipt covers the ledger head', open0.status === 0 && JSON.parse(open0.stdout).snapshot_id === SNAP_ID)
  const nothing = s.purgeRetention({ nowSec: now - RETENTION_PURGE_AFTER_SEC })
  ok('a retention pass with nothing past the window writes no op purge', nothing.purged.length === 0 && seqOf(s) === 3)
  const out = s.purgeRetention({ nowSec: now })
  const incomplete = await runBin('hive-memory-backup.mjs', gateArgs)
  ok('after the 90-day purge, with its backup not verified, the gate exits 1 with the design\'s HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE report',
    out.seq === 4 && incomplete.status === 1 && incomplete.stderr.includes('HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE: local SQLite and ledger purged at write_seq 4, but off-host B2 backup failed; writers remain FENCED and full-host loss before a verified backup would lack the purge in B2'))
  const refused = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'during-incomplete', { nowSec: now }), expectedPriorId: null, nowSec: now + 1 })
  ok('memory_submit refuses with HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE while lastVerifiedBackup.write_seq < lastPurgeSeq, though the receipt is fresh',
    refused.code === 'HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE')
  const snapArgs = n => ['snapshot', '--db', p.db, '--ledger', p.ledger, '--out-db', join(p.dir, `s${n}.sqlite`), '--out-ledger', join(p.dir, `s${n}.ledger`), '--backup-receipt', p.receipt]
  const snapPurge = JSON.parse((await runBin('hive-memory-backup.mjs', snapArgs(1))).stdout || '{}')
  ok('the next snapshot reports the uncovered purge, so restic tags it hive-memory-purge', snapPurge.purge === true && snapPurge.last_purge_seq === 4 && snapPurge.write_seq === 4)
  recordVerifiedBackup({ receiptPath: p.receipt, snapshotId: SNAP_ID, writeSeq: 4, at: now + 1, nowSec: now + 1 })
  const reopened = await runBin('hive-memory-backup.mjs', gateArgs)
  const accepted = s.submit({ writer: 'james', event: claim(james, 'hive:ops', 'after-verified', { nowSec: now + 2 }), expectedPriorId: null, nowSec: now + 2 })
  ok('a verified backup at the purge write_seq completes it: the gate opens and writes resume', reopened.status === 0 && accepted.accepted === true)
  const behind = await runBin('hive-memory-backup.mjs', gateArgs)
  ok('the gate stays closed while the receipt is behind the ledger head (HIVE_MEMORY_BACKUP_GATE_CLOSED)', behind.status === 1 && /HIVE_MEMORY_BACKUP_GATE_CLOSED/.test(behind.stderr))
  const snapClean = JSON.parse((await runBin('hive-memory-backup.mjs', snapArgs(2))).stdout || '{}')
  ok('a snapshot once the purge is covered no longer asks for the purge tag', snapClean.purge === false && snapClean.last_purge_seq === 4)
  s.close()
  const purgeBase = ['--db', p.db, '--ledger', p.ledger, '--backup-receipt', p.receipt, '--config', cfgPath]
  const typo = await runBin('hive-memory-purge.mjs', [...purgeBase, '--id', succ.id, '--dry-run'])
  ok('bin/hive-memory-purge refuses an unknown flag and purges nothing', typo.status === 2 && /unknown argument --dry-run/.test(typo.stderr) && readLedger(p.ledger).lines.length === 5)
  const hd = await runBin('hive-memory-purge.mjs', [...purgeBase, '--id', succ.id])
  const hdOut = JSON.parse(hd.stdout || '{}')
  const hdSeq = hdOut.write_seq
  ok('bin/hive-memory-purge prints exactly { purged: <count>, write_seq }', JSON.stringify(Object.keys(hdOut)) === '["purged","write_seq"]' && hdOut.purged === 1)
  const hdGate = await runBin('hive-memory-backup.mjs', gateArgs)
  ok('a hard delete through bin/hive-memory-purge goes through the same barrier',
    hd.status === 0 && hdSeq === 6 && hdGate.status === 1 && hdGate.stderr.includes(`HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE: local SQLite and ledger purged at write_seq ${hdSeq},`))
  const s2 = open(p)
  ok('a restarted daemon keeps the barrier: last_purge_seq is in store_meta and the ledger',
    s2.state === 'READY' && s2.submit({ writer: 'james', event: claim(james, 'hive:ops', 'after-restart', { nowSec: now + 3 }), expectedPriorId: null, nowSec: now + 3 }).code === 'HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE')
  s2.close()
  withDb(p.db, d => d.prepare('UPDATE store_meta SET last_purge_seq = 0').run())
  const s3 = open(p)
  ok('a store_meta.last_purge_seq that disagrees with the ledger fails closed (PURGE_SEQ_MISMATCH)', s3.state === 'PURGE_SEQ_MISMATCH' && unknownAnswer(s3, 'PURGE_SEQ_MISMATCH'))
  s3.close()
}

{
  // The daemon never purges on its own: retention runs only through bin/hive-memory-purge --retention (§4.5).
  const p = setup('daemon-no-purge')
  const s = open(p)
  const old = claim(james, 'hive:ops', 'rolling', { ttlSec: 0 })
  const succ = claim(james, 'hive:ops', 'rolling', { ttlSec: 0, priorCreatedAt: old.created_at })
  s.submit({ writer: 'james', event: old, expectedPriorId: null, nowSec: T0 + 50 })
  s.submit({ writer: 'james', event: succ, expectedPriorId: old.id, nowSec: T0 + 51 })
  s.close()
  const cfgPath = join(p.dir, 'config.json')
  writeFileSync(cfgPath, JSON.stringify(rawConfig()))
  const daemon = await startMemoryDaemon({
    dbPath: p.db, ledgerPath: p.ledger, receiptPath: p.receipt, configPath: cfgPath, socketDir: join(p.dir, 's'),
    readers: 'owner', writers: 'james', now: () => succ.created_at + RETENTION_PURGE_AFTER_SEC * 2, retentionIntervalMs: 5, log: () => {},
  })
  await new Promise(r => setTimeout(r, 150))
  const due = daemon.store.retentionCandidates(succ.created_at + RETENTION_PURGE_AFTER_SEC * 2)
  await daemon.close()
  const daemonSrc = readFileSync('mcp/tools/memory-daemon.mjs', 'utf8')
  ok('the daemon never purges on its own, even with rows long past the 90-day window and a short interval asked for',
    due.includes(old.id) && !readLedger(p.ledger).lines.some(l => l.rec.op === 'purge') && !/purgeRetention|hardDelete|retentionTimer|setInterval/.test(daemonSrc))
}

// --- 5. Read ACL, graph traversal, SIGHUP revocation, and the 5,000-claim fixture (§5 test 5) ---
{
  const bad = (over, label) => ok(`validateAndResolveConfig rejects ${label}`, (() => { try { validateAndResolveConfig(rawConfig(over)); return false } catch { return true } })())
  bad({ rooms: { [ROOM_A]: { members: [biggy.pk], writers: [biggy.pk, crusty.pk] } } }, 'room writers that are not a subset of members')
  bad({ ownerPubkey: james.pk.toUpperCase() }, 'an uppercase pubkey')
  bad({ globalWriters: ['abc'] }, 'a short pubkey')
  bad({ readers: { biggy: 'nothex' } }, 'a non-hex reader pubkey')
  bad({ maxUnbackedSec: 0 }, 'a non-positive maxUnbackedSec')
  bad({ relayUrl: 'wss://x' }, 'a leftover relay key')
  bad({ writers: { a: { pubkey: biggy.pk, perHour: 1 }, b: { pubkey: biggy.pk, perHour: 1 } } }, 'two writers sharing a pubkey')
  bad({ rooms: { 'not-a-uuid': { members: [], writers: [] } } }, 'a non-UUID room id')
  bad({ canonWriters: 'abc' }, 'a canonWriters that is not an array')
  bad({ canonWriters: [crusty.pk.toUpperCase()] }, 'an uppercase canonWriters pubkey')
  const plain = validateAndResolveConfig(rawConfig())
  const named = validateAndResolveConfig(rawConfig({ canonWriters: [crusty.pk] }))
  const canonRow = pk => ({ scope_type: 'hive:canon', pubkey: pk })
  ok('canonWriters is optional and grants nothing when absent',
    plain.canonWriters.size === 0 && writeRefusal(plain, null, crusty.pk, { scope: 'hive:canon' }) !== null && !canRead(null, canonRow(crusty.pk), plain))
  ok('a canonWriter writes and is read in hive:canon; other keys still cannot, and hive:ops is unchanged',
    writeRefusal(named, null, crusty.pk, { scope: 'hive:canon' }) === null && canRead(null, canonRow(crusty.pk), named) &&
    writeRefusal(named, null, biggy.pk, { scope: 'hive:canon' }) !== null && !canRead(null, canonRow(biggy.pk), named) &&
    writeRefusal(named, null, james.pk, { scope: 'hive:canon' }) === null && writeRefusal(named, null, crusty.pk, { scope: 'hive:ops' }) !== null)
}
{
  const p = setup('acl')
  const cfgPath = join(p.dir, 'config.json')
  writeFileSync(cfgPath, JSON.stringify(rawConfig()))
  let clock = T0 + 20
  const sockDir = join(p.dir, 's')
  const daemon = await startMemoryDaemon({
    dbPath: p.db, ledgerPath: p.ledger, receiptPath: p.receipt, configPath: cfgPath, socketDir: sockDir,
    readers: 'biggy:crusty:kiosk:owner', writers: 'biggy:crusty:james:ops', now: () => clock, log: () => {},
  })
  const rd = n => join(sockDir, `${n}.sock`)
  const wr = n => join(sockDir, 'writers', `${n}.sock`)
  const x = claim(crusty, roomB, 'secret-plan')
  const xNext = claim(crusty, roomB, 'secret-plan', { priorCreatedAt: x.created_at, supersedes: [x.id] })
  const y = claim(biggy, roomA, 'public-plan', { asOfEvt: x.id, asOfGit: undefined, evidence: [x.id], supersedes: [x.id] })
  const canon = claim(james, 'hive:canon', 'rule', { ttlSec: 0 })
  await callTool(wr('crusty'), 'memory_submit', { event: x, expected_prior_id: null })
  await callTool(wr('crusty'), 'memory_submit', { event: xNext, expected_prior_id: x.id })
  await callTool(wr('biggy'), 'memory_submit', { event: y, expected_prior_id: null })
  await callTool(wr('james'), 'memory_submit', { event: canon, expected_prior_id: null })

  const bq = args => callTool(rd('biggy'), 'memory_query', args)
  const direct = await bq({ scope: roomB })
  const hist = await bq({ scope: roomB, include_history: true })
  const byD = await bq({ d: `hive-memory:${roomB}:secret-plan`, include_history: true })
  const linked = await bq({ linked_to: x.id })
  const lineage = await bq({ supersedes_of: x.id })
  const all = await bq({ include_history: true, limit: 100 })
  ok('ACL: a non-member reader gets nothing for another room on query, history and fact-key reads',
    direct.answer === 'none' && direct.total_matched === 0 && hist.total_matched === 0 && byD.total_matched === 0)
  ok('ACL: counts (total_matched, scope_counts, store_state.current_claims) never include another room',
    !Object.keys(all.scope_counts).includes(roomB) && all.store_state.current_claims === 2 && all.records.every(r => r.scope !== roomB))
  ok('ACL: linked_to and supersedes_of on a hidden target return nothing, not even a count',
    linked.total_matched === 0 && linked.records.length === 0 && lineage.total_matched === 0 && !JSON.stringify(lineage).includes(xNext.id))
  const crustyLineage = await callTool(rd('crusty'), 'memory_query', { supersedes_of: x.id })
  const crustyLinked = await callTool(rd('crusty'), 'memory_query', { linked_to: x.id })
  ok('graph traversal works for a member of both rooms', crustyLineage.records.map(r => r.event_id).sort().join() === [xNext.id, y.id].sort().join() &&
    crustyLinked.records.some(r => r.event_id === y.id))
  const kiosk = await callTool(rd('kiosk'), 'memory_query', { include_history: true })
  ok('a keyless reader sees hive:canon and hive:ops only', kiosk.records.length === 1 && kiosk.records[0].scope === 'hive:canon')
  const ownerWake = await callTool(rd('owner'), 'memory_wake', {})
  const biggyWake = await callTool(rd('biggy'), 'memory_wake', {})
  ok('wake: records carry no authority and the digest excludes rooms the reader is not in',
    ownerWake.records.every(r => r.authority === null && r.trustedInstruction === false) &&
    !biggyWake.digest.includes('secret-plan') && biggyWake.digest.includes('public-plan') && ownerWake.digest.includes('secret-plan'))
  ok('every record is a data envelope (authority null, trustedInstruction false)', all.records.every(r => r.authority === null && r.trustedInstruction === false))

  // SIGHUP: removing crusty from room B drops its live connection and refuses room:B reads.
  const held = connect(rd('crusty'))
  await new Promise(r => held.once('connect', r))
  const closed = new Promise(r => held.once('close', () => r(true)))
  const keep = connect(rd('owner'))
  await new Promise(r => keep.once('connect', r))
  let keepClosed = false
  keep.once('close', () => { keepClosed = true })
  const before = await callTool(rd('crusty'), 'memory_query', { scope: roomB })
  const next = rawConfig()
  next.rooms[ROOM_B] = { members: [james.pk], writers: [] }
  writeFileSync(cfgPath, JSON.stringify(next))
  daemon.reload()
  const dropped = await Promise.race([closed, new Promise(r => setTimeout(() => r(false), 1000))])
  const after = await callTool(rd('crusty'), 'memory_query', { scope: roomB })
  ok('SIGHUP removing a reader from rooms[R].members disconnects its live socket immediately', before.total_matched === 1 && dropped === true)
  ok('SIGHUP: an unaffected reader keeps its connection', keepClosed === false)
  ok('SIGHUP: the removed member\'s room reads are refused afterwards', after.total_matched === 0 && after.answer === 'none')
  const ownerAfter = await callTool(rd('owner'), 'memory_query', { scope: roomB })
  ok('SIGHUP: claims by a removed member are hidden from remaining members too', ownerAfter.total_matched === 0)
  keep.destroy()

  writeFileSync(cfgPath, '{ not json')
  daemon.reload()
  const invalid = await callTool(rd('owner'), 'memory_query', { scope: 'hive:canon' })
  const invalidWrite = await callTool(wr('james'), 'memory_submit', { event: claim(james, 'hive:canon', 'during-invalid', { ttlSec: 0 }), expected_prior_id: null })
  ok('an invalid config on SIGHUP fails closed (CONFIG_INVALID): reads answer unknown and writes are refused',
    daemon.store.state === 'CONFIG_INVALID' && invalid.answer === 'unknown' && invalid.answer_reason === 'store-not-ready:CONFIG_INVALID' && invalidWrite.code === 'HIVE_MEMORY_STORE_NOT_READY')
  writeFileSync(cfgPath, JSON.stringify(rawConfig()))
  daemon.reload()
  const restored = await callTool(rd('owner'), 'memory_query', { scope: 'hive:canon' })
  ok('a valid config on the next SIGHUP reconciles back to READY', daemon.store.state === 'READY' && restored.answer === 'found')
  const unconfigured = rawConfig()
  delete unconfigured.readers.kiosk
  writeFileSync(cfgPath, JSON.stringify(unconfigured))
  daemon.reload()
  const gone = await callTool(rd('kiosk'), 'memory_query', { scope: 'hive:canon' })
  ok('a reader removed from config answers unknown (reader-not-configured)', gone.answer === 'unknown' && gone.answer_reason === 'reader-not-configured' && gone.records.length === 0)
  await daemon.close()
}
{
  // Real fd passing and a real SIGHUP: systemd-style LISTEN_FDS with a reader and a writer.
  const p = setup('sd')
  const cfgPath = join(p.dir, 'config.json')
  writeFileSync(cfgPath, JSON.stringify(rawConfig({ maxUnbackedSec: 10 ** 9 })))
  recordVerifiedBackup({ receiptPath: p.receipt, snapshotId: SNAP_ID, writeSeq: 1, at: Math.floor(Date.now() / 1000) })
  const sock = join(p.dir, 'k.sock'); const wsock = join(p.dir, 'w.sock')
  const child = spawn('python3', ['-c', `
import os, socket, sys
socks = []
for i, path in enumerate(sys.argv[1:3]):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    s.listen(16)
    os.dup2(s.fileno(), 3 + i)
    os.set_inheritable(3 + i, True)
    socks.append(s)
os.environ["LISTEN_PID"] = str(os.getpid())
os.environ["LISTEN_FDS"] = "2"
os.environ["LISTEN_FDNAMES"] = "kiosk:writer.james"
os.execv(sys.argv[3], [sys.argv[3], sys.argv[4], "--db", sys.argv[5], "--ledger", sys.argv[6], "--backup-receipt", sys.argv[7], "--config", sys.argv[8]])
`.trim(), sock, wsock, process.execPath, resolve(import.meta.dirname, '../mcp/tools/memory-daemon.mjs'), p.db, p.ledger, p.receipt, cfgPath],
  { stdio: ['ignore', 'ignore', 'pipe'] })
  let stderr = ''
  child.stderr.on('data', c => { stderr += c })
  let up = false
  for (let i = 0; i < 80 && !up; i++) {
    try { up = Boolean((await rpcCall(sock, { jsonrpc: '2.0', id: 1, method: 'ping' })).result) } catch { await new Promise(r => setTimeout(r, 25)) }
  }
  const sub = await callTool(wsock, 'memory_submit', { event: claim(james, 'hive:canon', 'sd-rule', { ttlSec: 0, nowSec: Math.floor(Date.now() / 1000) }), expected_prior_id: null })
  const q = await callTool(sock, 'memory_query', { scope: 'hive:canon', reader: 'owner', reader_pubkey: james.pk })
  ok('LISTEN_FDS: fd 3 serves as reader kiosk and fd 4 as writer james, ignoring client-supplied identity',
    up && sub.accepted === true && q.reader === 'kiosk' && q.reader_pubkey === null && q.total_matched === 1)
  writeFileSync(cfgPath, 'not json')
  child.kill('SIGHUP')
  let failedClosed = false
  for (let i = 0; i < 40 && !failedClosed; i++) {
    await new Promise(r => setTimeout(r, 25))
    try { failedClosed = (await callTool(sock, 'memory_query', { scope: 'hive:canon' })).answer === 'unknown' } catch { /* reconnecting */ }
  }
  ok('a real SIGHUP with an invalid config fails closed in the running daemon', failedClosed && stderr.includes('CONFIG_INVALID'))
  child.kill('SIGTERM')
  await new Promise(r => child.once('exit', r))
  ok('the daemon releases the store lock on SIGTERM', !existsSync(`${p.db}.lock`))
  const lock = acquireStoreLock(p.db)
  lock.release()
}
{
  // 5,000 claims with multi-hop supersedes and topic links, inserted directly with a consistent cutover ledger.
  const dir = mkdtempSync(join(tmpdir(), 'hm-5k-'))
  const p = { dir, db: join(dir, 'memory.sqlite'), ledger: join(dir, 'ledger.jsonl'), receipt: join(dir, 'receipt.json') }
  const hex = s => createHash('sha256').update(s).digest('hex')
  const ids = []
  initEmptyStore({ dbPath: p.db, ledgerPath: p.ledger, nowSec: T0 })
  rmSync(p.ledger)
  const big = new DatabaseSync(p.db)
  big.exec('BEGIN')
  big.exec('DELETE FROM store_meta')
  const ins = big.prepare(`INSERT INTO events (id, pubkey, kind, created_at, d, scope, scope_type, room_id, topic, status, retention, as_of_git, as_of_evt, exp, raw_json, ingested_at, is_current)
    VALUES (?, ?, 30079, ?, ?, ?, ?, ?, ?, 'active', 'decision', 'abc1234', NULL, NULL, ?, ?, ?)`)
  const link = big.prepare('INSERT INTO links (from_id, relation, target) VALUES (?, ?, ?)')
  const firstOfChain = []
  for (let k = 0; k < 1250; k++) {
    const room = k % 2 === 0
    const scope = room ? roomA : 'hive:ops'
    const author = room ? biggy.pk : james.pk
    const d = `hive-memory:${scope}:fact-${k}`
    const topic = `topic-${k % 50}`
    let prev = null
    for (let v = 0; v < 4; v++) {
      const id = hex(`${k}:${v}`)
      const content = JSON.stringify({ claim: `fact ${k} version ${v}`, because: 'fixture', evidence: ['nvoy@abc1234:README.md'], status: 'active' })
      const raw = JSON.stringify({ id, pubkey: author, kind: 30079, created_at: T0 + k * 10 + v, tags: [['d', d]], content, sig: '0'.repeat(128) })
      ins.run(id, author, T0 + k * 10 + v, d, scope, room ? 'room' : 'hive:ops', room ? ROOM_A : null, topic, raw, T0, v === 3 ? 1 : 0)
      link.run(id, 'topic', topic)
      if (prev) link.run(id, 'supersedes', prev)
      if (v === 0) firstOfChain.push(id)
      prev = id
      ids.push(id)
    }
  }
  const storeId = 'fixture-5k'
  const line = JSON.stringify({ seq: 1, op: 'cutover', store_id: storeId, event_ids: [...ids].sort(), at: T0 })
  big.prepare('INSERT INTO store_meta (singleton, store_id, write_seq, last_event_id, pending_ledger_json, initialized_at) VALUES (1, ?, 1, ?, ?, ?)').run(storeId, ids.at(-1), line, T0)
  big.exec('COMMIT')
  big.close()
  writeFileSync(p.ledger, `${line}\n`)
  recordVerifiedBackup({ receiptPath: p.receipt, snapshotId: SNAP_ID, writeSeq: 1, at: T0 })
  const t0 = performance.now()
  const s = open(p)
  const tOpen = performance.now() - t0
  const timed = fn => { const a = performance.now(); const out = fn(); return [out, performance.now() - a] }
  const [page1, tPage] = timed(() => s.query({ readerPubkey: biggy.pk, limit: 100, nowSec: T0 + 100000 }))
  let cursor = page1.next_cursor
  let seen = page1.returned
  let pages = 1
  let worst = tPage
  while (cursor) {
    const [pg, t] = timed(() => s.query({ readerPubkey: biggy.pk, limit: 100, cursor, nowSec: T0 + 100000 }))
    seen += pg.returned; cursor = pg.next_cursor; pages++; worst = Math.max(worst, t)
  }
  const [topicQ, tTopic] = timed(() => s.query({ readerPubkey: biggy.pk, topic: 'topic-7', includeHistory: true, nowSec: T0 + 100000 }))
  const [chain, tChain] = timed(() => s.query({ readerPubkey: biggy.pk, supersedesOf: firstOfChain[0], includeHistory: true, nowSec: T0 + 100000 }))
  const [kiosk, tKiosk] = timed(() => s.query({ readerPubkey: '', limit: 100, nowSec: T0 + 100000 }))
  const [wake, tWake] = timed(() => s.wake({ readerPubkey: biggy.pk, nowSec: T0 + 100000 }))
  console.log(`  5k fixture: open ${tOpen.toFixed(0)}ms, page ${tPage.toFixed(0)}ms (worst ${worst.toFixed(0)}ms over ${pages} pages), topic ${tTopic.toFixed(0)}ms, 3-hop ${tChain.toFixed(0)}ms, keyless ${tKiosk.toFixed(0)}ms, wake ${tWake.toFixed(0)}ms`)
  ok('5,000 claims: the store reconciles READY against the cutover ledger', s.state === 'READY' && s.db.prepare('SELECT count(*) AS n FROM events').get().n === 5000)
  ok('5,000 claims: pagination walks all 1,250 current claims in pages of at most 100', seen === 1250 && pages === 13 && page1.returned === 100 && page1.total_matched === 1250)
  ok('5,000 claims: a topic query with history returns every version on that topic', topicQ.total_matched === 100)
  ok('5,000 claims: supersedes_of follows at most 3 hops', chain.total_matched === 3)
  ok('5,000 claims: a keyless reader sees only the 625 hive:ops heads', kiosk.total_matched === 625)
  ok('5,000 claims: wake stays within its character budget', wake.char_length <= 6000 && wake.counts.ops_omitted > 0)
  ok('5,000 claims: every query and the wake finish within 1.5 s', Math.max(worst, tTopic, tChain, tKiosk, tWake) < 1500)
  s.close()
}

console.log(`\n${passes} passed, ${fails} failed`)
process.exit(fails ? 1 : 0)
