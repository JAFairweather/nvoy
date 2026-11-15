import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readdirSync, statSync, utimesSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { classify, collect, jsonl, options, run, safeError } from '../bin/q183-admitted-classify.mjs'

const hex = (n, len = 64) => n.toString(16).padStart(len, '0')
const env = n => hex(n)
const req = n => hex(n, 32)
const SECRET_TEXT = 'private message body that must never be printed'
const lines = rows => rows.map(r => (typeof r === 'string' ? r : JSON.stringify(r))).join('\n') + '\n'

function seat() {
  const base = mkdtempSync(join(tmpdir(), 'q183-'))
  const m = { id: 'seat', runtimeDir: join(base, 'run'), stateDir: join(base, 'state'), spoolDir: join(base, 'spool'), deliveryMode: 'notify_only', harness: { runner: 'claude' } }
  for (const d of [m.runtimeDir, m.stateDir, m.spoolDir, join(m.stateDir, 'receipts'), join(m.runtimeDir, 'claude-channel-state')]) mkdirSync(d, { recursive: true })
  const admitted = (n, type = 'admitted-task', at = 1_700_000_000_000 + n * 1000) =>
    ({ type, instance: 'seat', envelope: env(n), authority: { policy_checked_at: at }, messages: [{ content: SECRET_TEXT }] })
  writeFileSync(join(m.runtimeDir, 'admitted-tasks.jsonl'), lines([
    admitted(1), admitted(2), admitted(3), admitted(4), admitted(5), admitted(6, 'verified-notification'), admitted(7), admitted(1),
    '{"broken', { envelope: 'not-hex' },
  ]))
  writeFileSync(join(m.stateDir, 'receipts', `${env(1)}.${req(1)}.used`), '')
  writeFileSync(join(m.stateDir, 'receipts', `${env(5)}.json`), '{}') // admitted only, not answered
  writeFileSync(join(m.runtimeDir, 'reply-requests.jsonl'), lines([
    { type: 'reply-request', id: req(2), instance: 'seat', receipt: env(2), content: SECRET_TEXT },
    { type: 'reply-request', id: req(1), instance: 'seat', receipt: env(1), content: SECRET_TEXT },
  ]))
  writeFileSync(join(m.stateDir, 'terminal-replies.jsonl'), lines([{ version: 1, type: 'terminal-reply', id: req(2), reason: 'x', at: 1 }]))
  writeFileSync(join(m.runtimeDir, 'claude-channel-state/read.jsonl'), lines([{ version: 1, instance: 'seat', envelope: env(3), read_at: 1 }, { envelope: env(1) }]))
  writeFileSync(join(m.runtimeDir, 'codex-app-server-delivered.jsonl'), lines([{ envelope: env(4) }]))
  for (const [name, at] of [[`${env(1)}.inflight.done`, 100], [`${env(9)}.buzz.inflight.done`, 50], [`${env(8)}.pending`, 200], [`${env(7)}.buzz.inflight`, 300], ['stray.txt', 1]]) {
    const p = join(m.spoolDir, name)
    writeFileSync(p, JSON.stringify({ observed_at: at, envelope: name.slice(0, 64) }))
    utimesSync(p, at, at)
  }
  return m
}

test('options parses, and refuses what it does not know', () => {
  assert.deepEqual(options(['--root', '/r', '--instance', 'a', '--instance', 'b', '--harness-home', 'a=/home/a', '--ids', '3']),
    { root: '/r', instances: ['a', 'b'], harnessHomes: { a: '/home/a' }, ids: 3 })
  assert.throws(() => options(['--write']), /unknown option --write/)
  assert.throws(() => options(['--root']), /needs a value/)
  assert.throws(() => options(['--ids', 'x']), /whole number/)
  // Dennis, PR 422: a huge digit string must not become Infinity and unbound the id lists.
  assert.throws(() => options(['--ids', '9'.repeat(400)]), /0 to 1000/)
  assert.throws(() => options(['--ids', '1001']), /0 to 1000/)
  assert.equal(options(['--ids', '1000']).ids, 1000)
  assert.throws(() => options(['--harness-home', 'a=rel']), /absolute/)
})

test('jsonl keeps only picked fields, counts bad lines and treats a missing file as absent', () => {
  const r = jsonl('/x', row => ({ envelope: row.envelope }), () => '{"envelope":"a","content":"c"}\nnope\n\n')
  assert.deepEqual(r, { rows: [{ envelope: 'a' }], bad: 1, missing: false })
  assert.equal(jsonl('/definitely/not/here', x => x).missing, true)
})

test('collect and classify put each admitted envelope in exactly one class', () => {
  const m = seat()
  const { input, sources } = collect(m)
  const out = classify({ ...input, now: Date.parse('2023-11-15T00:00:00Z') })
  const counts = Object.fromEntries(Object.entries(out.classes).map(([k, v]) => [k, v.count]))
  assert.deepEqual(counts, { notification: 1, answered: 1, terminal: 1, read: 1, delivered: 1, unconsumed: 2 })
  assert.equal(out.admitted_rows, 8)
  assert.equal(out.admitted_envelopes, 7)
  assert.deepEqual(out.classes.unconsumed.envelopes, [env(5), env(7)])
  assert.equal(out.classes.unconsumed.oldest_at, new Date(1_700_000_005_000).toISOString())
  assert.ok(out.unconsumed_oldest_age_h > 0)
  assert.deepEqual(out.spool, {
    pending: 1, inflight: 1, done: 2, done_admitted: 1, done_not_admitted: 1,
    oldest_pending_at: new Date(200_000).toISOString(), oldest_done_at: new Date(50_000).toISOString(),
  })
  assert.deepEqual(sources['admitted-tasks'], { rows: 8, bad_lines: 1 })
  assert.equal(sources['codex-harness-delivered'], undefined)
  assert.equal(sources['worker-consumed'], 'absent')
})

test('the codex harness cursor counts only when its home is named', () => {
  const m = seat()
  const home = mkdtempSync(join(tmpdir(), 'q183-home-'))
  mkdirSync(join(home, '.nvoy-harness'))
  writeFileSync(join(home, '.nvoy-harness/delivered.jsonl'), lines([{ envelope: env(5), turn: null, at: 1 }]))
  const out = classify({ ...collect(m, home).input, now: 0 })
  assert.equal(out.classes.delivered.count, 2)
  assert.deepEqual(out.classes.unconsumed.envelopes, [env(7)])
})

test('run prints counts and ids, never content, and writes nothing', () => {
  const m = seat()
  const before = JSON.stringify([m.runtimeDir, m.stateDir, m.spoolDir].map(d => readdirSync(d).map(f => [f, statSync(join(d, f)).mtimeMs])))
  const printed = []
  const seats = run(['--instance', 'seat', '--instance', 'gone', '--ids', '1'], {
    log: line => printed.push(line), now: 0,
    readSeat: (_root, id) => { if (id !== 'seat') throw new Error('no manifest for gone'); return m },
  })
  const text = printed.join('\n')
  assert.ok(!text.includes(SECRET_TEXT))
  assert.ok(!text.includes('content'))
  const parsed = JSON.parse(text)
  assert.equal(parsed.read_only, true)
  assert.equal(parsed.seats.seat.harness, 'claude')
  assert.equal(parsed.seats.seat.delivery_mode, 'notify_only')
  assert.deepEqual(parsed.seats.seat.classes.unconsumed.envelopes, [env(5)])
  assert.deepEqual(seats.gone, { error: 'manifest refused (details withheld)' })
  const after = JSON.stringify([m.runtimeDir, m.stateDir, m.spoolDir].map(d => readdirSync(d).map(f => [f, statSync(join(d, f)).mtimeMs])))
  assert.equal(after, before)
})

test('a seat error never quotes what the parser read (Neil and Dennis, PR 422)', () => {
  const root = mkdtempSync(join(tmpdir(), 'q183-root-'))
  writeFileSync(join(root, 'leaky.json'), '{"id":"leaky","secret_fragment_here": oops}')
  const printed = []
  const seats = run(['--root', root], { log: line => printed.push(line), now: 0 })
  assert.equal(seats.leaky.error, 'manifest is not valid JSON')
  assert.ok(!printed.join('\n').includes('secret_fragment_here'))
  assert.ok(!printed.join('\n').includes('oops'))
  assert.equal(safeError(Object.assign(new Error('x: y'), { code: 'EACCES' }), 'manifest'), 'manifest unreadable (EACCES)')
  assert.equal(safeError(new Error('Unexpected token "s" in {"k":"v"}'), 'manifest'), 'manifest refused (details withheld)')
  assert.equal(safeError(new Error('manifest is not valid JSON: oops'), 'seat files'), 'seat files refused (details withheld)')
  assert.equal(safeError(Object.assign(new Error('sample confidential text'), { code: 'ESECRET' }), 'seat files'), 'seat files refused (details withheld)')
})

test('a colon-free message is never printed either (Neil, PR 422 at 02e257d)', () => {
  for (const stage of ['manifest', 'seat files', 'classify']) assert.equal(safeError(new Error('sample confidential text'), stage), `${stage} refused (details withheld)`)
  const printed = []
  const seats = run(['--instance', 'a', '--instance', 'b'], {
    log: line => printed.push(line), now: 0,
    readSeat: (_root, id) => { if (id === 'a') throw new Error('sample confidential text'); return { runtimeDir: '/x', stateDir: '/x', spoolDir: '/x' } },
    collectSeat: () => { throw new Error('sample confidential text') },
  })
  assert.deepEqual(seats, { a: { error: 'manifest refused (details withheld)' }, b: { error: 'seat files refused (details withheld)' } })
  assert.ok(!printed.join('\n').includes('confidential'))
  // Dennis, PR 422 at 02e257d: nostr-tools quotes a bad npub from the real readManifest path.
  const root = mkdtempSync(join(tmpdir(), 'q183-npub-'))
  writeFileSync(join(root, 'bad.json'), JSON.stringify({ id: 'bad', pubkey: 'npub1qqqqqqqq' }))
  const out = []
  assert.deepEqual(run(['--root', root], { log: line => out.push(line), now: 0 }), { bad: { error: 'manifest refused (details withheld)' } })
  assert.ok(!out.join('\n').includes('npub1'))
})
