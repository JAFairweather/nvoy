// Per-seat read log (nvoy #390): one line per reader wake/query/get with the returned fact keys and no text; the viewer is
// skipped; the file is 0640; retention drops old lines and obeys the size cap; a failing log never fails a read.
import assert from 'node:assert/strict'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { buildClaimTemplate } from '../mcp/tools/memory.mjs'
import { handleSocketJsonRpc, startMemoryDaemon } from '../mcp/tools/memory-daemon.mjs'
import { initEmptyStore, recordVerifiedBackup } from '../mcp/tools/hive_memory_store.mjs'
import { READ_LOG_MAX_KEYS, ReadLog } from '../mcp/tools/memory-read-log.mjs'

const SNAP_ID = 'c'.repeat(64)
let passed = 0
let failed = 0
async function test(name, fn) {
  try { await fn(); console.log(`  ok — ${name}`); passed++ } catch (err) { console.error(`  FAIL — ${name}: ${err.message}`); if (err.stack) console.error(err.stack); failed++ }
}
const lines = path => readFileSync(path, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l))

await test('daemon read log: wake, query and get are logged per seat with keys only; the viewer is not', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-read-log-'))
  const db = join(tmp, 'memory.sqlite'), ledger = join(tmp, 'ledger.jsonl'), receipt = join(tmp, 'receipt.json'), logPath = join(tmp, 'logs', 'reads.ndjson')
  const globalChannel = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
  const room = '5b7c1d2e-3f40-4a51-8b62-7c83d94ea5f6'
  const ownerSk = generateSecretKey(), ownerPk = getPublicKey(ownerSk)
  const neilSk = generateSecretKey(), neilPk = getPublicKey(neilSk)
  const dennisPk = getPublicKey(generateSecretKey())
  const nowSec = Math.floor(Date.now() / 1000)
  initEmptyStore({ dbPath: db, ledgerPath: ledger })
  recordVerifiedBackup({ receiptPath: receipt, snapshotId: SNAP_ID, writeSeq: 1, at: nowSec })
  const daemon = await startMemoryDaemon({
    dbPath: db, ledgerPath: ledger, receiptPath: receipt,
    config: {
      memoryGlobalChannelId: globalChannel, ownerPubkey: ownerPk, maxUnbackedSec: 3600, globalWriters: [],
      readers: { viewer: null, dennis: dennisPk, neil: neilPk },
      writers: { owner: { pubkey: ownerPk, perHour: 100 }, neil: { pubkey: neilPk, perHour: 30 } },
      rooms: { [room]: { members: [neilPk], writers: [neilPk] } },
    },
    readers: 'viewer:dennis:neil', writers: 'owner:neil', socketDir: join(tmp, 'sock'), log: () => {},
    readLogPath: logPath, now: () => nowSec + 2,
  })
  const call = (binding, name, args) => handleSocketJsonRpc({
    store: daemon.store, binding, nowSec: nowSec + 2, readLog: daemon.readLog,
    message: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } },
  })
  const payload = res => JSON.parse(res.result.content[0].text)
  const claim = (sk, pk, scope, slug) => finalizeEvent(buildClaimTemplate({
    pubkey: pk, scope, slug, topic: 'governance', claim: 'SECRET-CLAIM-TEXT', because: 'SECRET-BECAUSE', evidence: ['nvoy@SECRET-EVIDENCE'],
    asOfGit: 'nvoy@8aa86b82377aed390257abd5fdc76ac8246b30ff', memoryGlobalChannelId: globalChannel, nowSec: nowSec + 1,
  }), sk)
  try {
    assert.equal((statSync(logPath).mode & 0o777), 0o640, 'log mode')
    const canon = claim(ownerSk, ownerPk, 'hive:canon', 'review-policy')
    assert.equal(payload(call({ kind: 'writer', name: 'owner' }, 'memory_submit', { event: canon, expected_prior_id: null })).accepted, true)
    const roomed = claim(neilSk, neilPk, `room:${room}`, 'secret-room-plan')
    assert.equal(payload(call({ kind: 'writer', name: 'neil' }, 'memory_submit', { event: roomed, expected_prior_id: null })).accepted, true)
    assert.deepEqual(lines(logPath), [], 'writes are not reads: nothing logged yet')

    const dennis = { kind: 'reader', name: 'dennis' }, neil = { kind: 'reader', name: 'neil' }, viewer = { kind: 'reader', name: 'viewer' }
    call(dennis, 'memory_wake', {})
    call(dennis, 'memory_query', { topic: 'governance', text: 'SECRET-QUERY-TEXT' })
    call(dennis, 'memory_query', { d: `hive-memory:hive:canon:review-policy` })
    call(neil, 'memory_query', { scope: `room:${room}`, topic: 'governance' })
    call(neil, 'memory_wake', {})
    call(viewer, 'memory_wake', {})
    call(viewer, 'memory_query', { topic: 'governance' })

    const got = lines(logPath)
    assert.equal(got.length, 5, 'the viewer is not logged')
    assert.deepEqual(got.map(g => [g.seat, g.op]), [['dennis', 'wake'], ['dennis', 'query'], ['dennis', 'get'], ['neil', 'query'], ['neil', 'wake']])
    const canonD = 'hive-memory:hive:canon:review-policy'
    assert(got[0].d.includes(canonD) && got[1].d.includes(canonD) && got[2].d.includes(canonD), 'dennis was shown the canon claim')
    assert(!got[1].d.some(d => d.includes('secret-room-plan')), 'dennis is not a room member: the room claim is not in his log')
    assert(got[3].d.some(d => d.endsWith(':secret-room-plan')) && got[3].n === got[3].d.length && got[3].truncated === false, 'neil was shown his room claim')
    assert(got[4].d.some(d => d.endsWith(':secret-room-plan')) && got[4].d.includes(canonD) && got[4].n === got[4].d.length, 'a wake logs the claims its digest showed, resolved to fact keys')
    assert(!got[0].d.some(d => d.includes('secret-room-plan')), 'dennis wake did not show the room claim')
    assert(got.every(g => g.at === nowSec + 2 && Object.keys(g).sort().join() === 'at,d,n,op,seat,truncated'))
    const raw = readFileSync(logPath, 'utf8')
    for (const secret of ['SECRET-CLAIM-TEXT', 'SECRET-BECAUSE', 'SECRET-EVIDENCE', 'SECRET-QUERY-TEXT']) assert(!raw.includes(secret), `${secret} must not reach the log`)
    assert.equal(daemon.readLog.failures, 0)
  } finally {
    await daemon.close()
    rmSync(tmp, { recursive: true, force: true })
  }
})

await test('no --read-log means no log and no behavior change', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-read-log-off-'))
  const db = join(tmp, 'memory.sqlite'), ledger = join(tmp, 'ledger.jsonl'), receipt = join(tmp, 'receipt.json')
  const ownerPk = getPublicKey(generateSecretKey())
  initEmptyStore({ dbPath: db, ledgerPath: ledger })
  recordVerifiedBackup({ receiptPath: receipt, snapshotId: SNAP_ID, writeSeq: 1, at: Math.floor(Date.now() / 1000) })
  const daemon = await startMemoryDaemon({
    dbPath: db, ledgerPath: ledger, receiptPath: receipt,
    config: { memoryGlobalChannelId: 'a8186b53-537d-46ad-a7e7-b6486c58970e', ownerPubkey: ownerPk, maxUnbackedSec: 3600, globalWriters: [], readers: { dennis: null }, writers: {}, rooms: {} },
    readers: 'dennis', socketDir: join(tmp, 'sock'), log: () => {},
  })
  try {
    assert.equal(daemon.readLog, null)
    const res = handleSocketJsonRpc({ store: daemon.store, binding: { kind: 'reader', name: 'dennis' }, nowSec: 1, readLog: daemon.readLog,
      message: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'memory_wake', arguments: {} } } })
    assert.equal(JSON.parse(res.result.content[0].text).authority, null)
  } finally {
    await daemon.close()
    rmSync(tmp, { recursive: true, force: true })
  }
})

await test('a failing log never fails a read, is counted, and says so once', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-read-log-fail-'))
  const messages = []
  const path = join(tmp, 'reads.ndjson')
  const rl = new ReadLog({ path, log: m => messages.push(m) })
  try {
    assert.equal(rl.record({ seat: 'dennis', op: 'wake', keys: ['a'] }), true)
    rmSync(path)
    mkdirSync(path)                                  // the path is now a directory: every append fails
    assert.equal(rl.record({ seat: 'dennis', op: 'wake', keys: ['a'] }), false)
    assert.equal(rl.record({ seat: 'dennis', op: 'query', keys: [] }), false)
    assert.equal(rl.failures, 2)
    assert.equal(messages.filter(m => m.includes('append failed')).length, 1, 'only the first failure is announced')
    assert.equal(rl.record({ seat: '', op: 'wake', keys: [] }), false, 'a malformed entry is refused, not thrown')
  } finally { rmSync(tmp, { recursive: true, force: true }) }
})

await test('a log path that cannot be opened stops the daemon at start', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-read-log-bad-'))
  const db = join(tmp, 'memory.sqlite'), ledger = join(tmp, 'ledger.jsonl'), receipt = join(tmp, 'receipt.json')
  const ownerPk = getPublicKey(generateSecretKey())
  initEmptyStore({ dbPath: db, ledgerPath: ledger })
  recordVerifiedBackup({ receiptPath: receipt, snapshotId: SNAP_ID, writeSeq: 1, at: Math.floor(Date.now() / 1000) })
  writeFileSync(join(tmp, 'notadir'), 'x')
  try {
    await assert.rejects(startMemoryDaemon({
      dbPath: db, ledgerPath: ledger, receiptPath: receipt,
      config: { memoryGlobalChannelId: 'a8186b53-537d-46ad-a7e7-b6486c58970e', ownerPubkey: ownerPk, maxUnbackedSec: 3600, globalWriters: [], readers: { dennis: null }, writers: {}, rooms: {} },
      readers: 'dennis', socketDir: join(tmp, 'sock'), log: () => {}, readLogPath: join(tmp, 'notadir', 'reads.ndjson'),
    }))
  } finally { rmSync(tmp, { recursive: true, force: true }) }
})

await test('retention: old lines and damaged lines go, new ones stay, mode stays 0640; the size cap drops the oldest', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-read-log-keep-'))
  const path = join(tmp, 'reads.ndjson')
  const day = 86400, now = 1_800_000_000
  const entry = (at, n = 1) => JSON.stringify({ at, seat: 'dennis', op: 'query', n, d: ['k'.repeat(n)], truncated: false })
  writeFileSync(path, [entry(now - 40 * day), 'not json', entry(now - 29 * day), entry(now - 1)].join('\n') + '\n')
  chmodSync(path, 0o640)
  const rl = new ReadLog({ path, retentionDays: 30, now: () => now })
  assert.deepEqual(lines(path).map(l => l.at), [now - 29 * day, now - 1])
  assert.equal(statSync(path).mode & 0o777, 0o640)
  // an hourly prune runs from record(): advance the clock and the 29-day line ages out
  let t = now + 2 * day
  const rl2 = new ReadLog({ path, retentionDays: 30, now: () => t })
  assert.deepEqual(lines(path).map(l => l.at), [now - 1], 'aged out at start')
  rl2.record({ seat: 'neil', op: 'wake', keys: ['a', 'b'] })
  assert.equal(lines(path).at(-1).n, 2)
  t += 40 * day
  rl2.record({ seat: 'neil', op: 'wake', keys: [] })
  assert.deepEqual(lines(path).map(l => l.seat), ['neil'], 'the hourly prune inside record() drops what has aged out')
  // size cap
  writeFileSync(path, Array.from({ length: 200 }, (_, i) => entry(t - 200 + i, 40)).join('\n') + '\n')
  const rl3 = new ReadLog({ path, retentionDays: 30, maxBytes: 4096, now: () => t })
  const kept = lines(path)
  assert(statSync(path).size <= 4096 && kept.length > 0 && kept.length < 200, 'under the cap')
  assert.equal(kept.at(-1).at, t - 1, 'the newest line survives')
  assert.equal(rl3.failures, 0)
  assert.throws(() => new ReadLog({ path, retentionDays: 0 }), /retention/)
  assert.throws(() => new ReadLog({ path, maxBytes: 10 }), /size cap/)
  rmSync(tmp, { recursive: true, force: true })
})

await test('symlinks are never followed: at the log path (refused), and beside it where the old prune named its temp file', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-read-log-link-'))
  const victim = join(tmp, 'victim.txt')
  writeFileSync(victim, 'DO-NOT-TOUCH\n')
  try {
    // a symlink planted at the log path stops the daemon's log from opening at all
    const planted = join(tmp, 'planted.ndjson')
    symlinkSync(victim, planted)
    assert.throws(() => new ReadLog({ path: planted }), /not a regular file/)
    assert.equal(readFileSync(victim, 'utf8'), 'DO-NOT-TOUCH\n')
    // a symlink swapped in after start: the append is refused and counted, and the target is untouched
    const path = join(tmp, 'reads.ndjson')
    const rl = new ReadLog({ path, retentionDays: 30, now: () => 1_800_000_000, log: () => {} })
    assert.equal(rl.record({ seat: 'dennis', op: 'wake', keys: ['a'] }), true)
    rmSync(path)
    symlinkSync(victim, path)
    assert.equal(rl.record({ seat: 'dennis', op: 'wake', keys: ['a'] }), false)
    assert.equal(readFileSync(victim, 'utf8'), 'DO-NOT-TOUCH\n')
    rmSync(path)
    // predictable temp names (the old <path>.tmp-<pid>) planted as symlinks are not opened by a rewrite
    writeFileSync(path, [JSON.stringify({ at: 1, seat: 'x', op: 'wake', n: 0, d: [], truncated: false }), JSON.stringify({ at: 1_800_000_000, seat: 'y', op: 'wake', n: 0, d: [], truncated: false })].join('\n') + '\n')
    chmodSync(path, 0o640)
    symlinkSync(victim, `${path}.tmp-${process.pid}`)
    const rl2 = new ReadLog({ path, retentionDays: 30, now: () => 1_800_000_000, log: () => {} })
    assert.equal(rl2.failures, 0)
    assert.deepEqual(lines(path).map(l => l.seat), ['y'], 'the old line was pruned')
    assert.equal(readFileSync(victim, 'utf8'), 'DO-NOT-TOUCH\n', 'the planted symlink was not followed')
    assert.equal(statSync(path).mode & 0o777, 0o640, 'the rewrite keeps 0640')
    assert.deepEqual(readdirSync(tmp).filter(f => f.includes('.tmp-')), [`reads.ndjson.tmp-${process.pid}`], 'no temp file left behind but the planted one')
  } finally { rmSync(tmp, { recursive: true, force: true }) }
})

await test('a reply with more records than the key cap is logged truncated, with the true count', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'nvoy-read-log-cap-'))
  const path = join(tmp, 'reads.ndjson')
  const rl = new ReadLog({ path })
  const keys = Array.from({ length: READ_LOG_MAX_KEYS + 25 }, (_, i) => `hive-memory:hive:canon:k${i}`)
  assert.equal(rl.record({ seat: 'dennis', op: 'query', keys }), true)
  const [e] = lines(path)
  assert.equal(e.n, READ_LOG_MAX_KEYS + 25)
  assert.equal(e.d.length, READ_LOG_MAX_KEYS)
  assert.equal(e.truncated, true)
  rmSync(tmp, { recursive: true, force: true })
})

console.log(`\nmemory-read-log: ${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
