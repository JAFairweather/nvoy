// lease-lock.mjs — one live holder, provable across PID namespaces (nvoy#364).
//
//   node test/lease-lock.mjs
//
// The cases that matter are the ones a PID lock gets wrong: two containers on one state volume, each
// PID 1 in its own namespace; a holder whose main thread is blocked past the lease; and every way two
// claimants can race to take a stale lock. Hosts are injected (the real hostname is one value on this
// machine). Every refusal is paired with a legitimate claim that still succeeds.

import assert from 'node:assert'
import { mkdtempSync, writeFileSync, readFileSync, existsSync, utimesSync, unlinkSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { claimLeaseLock, generations } from '../mcp/tools/lease_lock.mjs'

let pass = 0, fail = 0
const t = async (name, fn) => {
  try { await fn(); console.log(`ok   — ${name}`); pass++ }
  catch (e) { console.log(`FAIL — ${name}\n       ${e.message}`); fail++ }
}
const dir = mkdtempSync(join(tmpdir(), 'nvoy-lease-'))
let n = 0
const fresh = () => join(dir, `lock-${++n}`)
const opts = (o = {}) => ({ ttlMs: 2000, onLost: () => {}, ...o })
const top = p => { const g = generations(p); return JSON.parse(readFileSync(g[g.length - 1].file, 'utf8')) }
const gens = p => generations(p).map(g => g.gen)
const age = (file, ms) => { const d = new Date(Date.now() - ms); utimesSync(file, d, d) }
const lockBody = (o = {}) => JSON.stringify({ version: 3, instance: 'i', gen: 1, host: 'container-a', pid: 1, token: 's'.repeat(32), started_at: 1, ...o })
const writeGen = (p, gen, o = {}) => { const f = `${p}.${gen}`; writeFileSync(f, lockBody({ gen, ...o }), { mode: 0o600 }); return f }
const staleGen = (p, gen = 1, o = {}) => { const f = writeGen(p, gen, o); age(f, 60000); return f }
const sleep = ms => new Promise(r => setTimeout(r, ms))

await t('a first claim creates generation 1, naming host, pid and a token', () => {
  const p = fresh(), release = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'A', pid: 1 }))
  const b = top(p)
  assert.deepEqual([b.version, b.instance, b.gen, b.host, b.pid], [3, 'i', 1, 'A', 1])
  assert.match(b.token, /^[0-9a-f]{32}$/)
  release(); assert.deepEqual(gens(p), [])
})

await t('TWO CONTAINERS, both PID 1: the second is refused while the first heartbeats (My Dude, PR 364)', () => {
  const p = fresh()
  const first = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-a', pid: 1 }))
  assert.throws(() => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1 })), /already runs as pid 1 on container-a/)
  assert.equal(top(p).host, 'container-a', 'the live holder\'s lock was not taken')
  first()
})

await t('  …the pair: the same pid on the SAME host is a previous incarnation of this container, so it is taken over', () => {
  const p = fresh(); staleGen(p, 1, { host: 'container-a', pid: 1 })
  const release = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-a', pid: 1 }))
  assert.equal(top(p).gen, 2)
  assert.deepEqual(gens(p), [2], 'the superseded generation was cleared away')
  release()
})

await t('another host whose heartbeat has lapsed is stale and is taken over', () => {
  const p = fresh()
  const first = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-a', pid: 1 }))
  age(generations(p)[0].file, 5000)
  const second = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1 }))
  assert.equal(top(p).host, 'container-b'); assert.equal(top(p).gen, 2)
  second(); first()
})

await t('a heartbeat keeps a lock fresh: after the mtime is aged, a beat renews it', async () => {
  const p = fresh()
  const first = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-a', pid: 1, ttlMs: 1000, beatMs: 100 }))
  age(generations(p)[0].file, 900)
  await sleep(350)
  assert.throws(() => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1, ttlMs: 1000 })), /already runs/)
  first()
})

await t('a holder whose lock is superseded reports lost, instead of carrying on as a second writer', async () => {
  const p = fresh()
  let lost = 0
  const first = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-a', pid: 1, beatMs: 100, onLost: () => { lost++ } }))
  writeGen(p, 2, { host: 'container-b', token: 'b'.repeat(32) })      // someone took generation 2
  await sleep(350)
  assert.ok(lost >= 1)
  first()
  assert.equal(top(p).host, 'container-b', 'the loser\'s release does not remove the winner\'s lock')
})

await t('the exit hook of the loser never removes the winner\'s lock (token and generation checked release)', () => {
  const p = fresh()
  const first = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-a', pid: 1 }))
  age(generations(p)[0].file, 5000)
  const second = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1 }))
  first()
  assert.equal(top(p).host, 'container-b')
  second()
})

await t('same host: a different pid that is gone is stale at once (a killed process does not wait out the lease)', () => {
  const p = fresh(); writeGen(p, 1, { host: 'A', pid: 2 ** 30 })
  const release = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'A', pid: 7 }))
  assert.equal(top(p).pid, 7)
  release()
})

await t('same host: a live different pid running this program is refused', () => {
  const p = fresh(); writeGen(p, 1, { host: 'A', pid: process.pid })
  assert.throws(() => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'A', pid: process.pid + 1 })), /already runs as pid/)
})

await t('same host: a live pid that is NOT this program is a stranger and is taken over', () => {
  const p = fresh(); writeGen(p, 1, { host: 'A', pid: process.pid })
  const release = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'A', pid: process.pid + 1, program: 'instance-broker-daemon.mjs' }))
  assert.equal(top(p).pid, process.pid + 1)
  release()
})

await t('malformed, foreign-instance, old-format and wrong-generation locks fail closed and are left alone', () => {
  for (const content of ['not json', lockBody({ instance: 'other' }), JSON.stringify({ version: 2, instance: 'i', host: 'A', pid: 1, token: 'f'.repeat(32) }),
    lockBody({ pid: 0 }), lockBody({ token: undefined }), lockBody({ gen: 9 })]) {
    const p = fresh(); writeFileSync(`${p}.1`, content, { mode: 0o600 })
    assert.throws(() => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'B', pid: 1 })), /cannot validate|does not bind/)
    assert.equal(readFileSync(`${p}.1`, 'utf8'), content, 'a lock that cannot be validated is left alone')
  }
})

await t('a lock that is a symlink is refused, not followed', () => {
  const target = fresh(), p = fresh()
  writeFileSync(target, lockBody(), { mode: 0o600 }); symlinkSync(target, `${p}.1`)
  assert.throws(() => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'B', pid: 1 })), /cannot validate/)
})

await t('a ttl below one second is refused', () => {
  assert.throws(() => claimLeaseLock(fresh(), 'i', 'daemon', { ttlMs: 10 }), /at least 1000/)
})

// ---- the takeover races (Dennis and My Dude, PR 364) ---------------------------------------------------
// Takeover is one exclusive create of generation n+1; nothing is ever deleted that a live holder might own.
await t('two claimants that both judged the same stale generation: exactly one wins, the other is refused', () => {
  const p = fresh(); staleGen(p, 1)
  let winner = null
  const a = () => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-a2', pid: 1, hooks: { afterRead: () => { winner = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1 })) } } }))
  assert.throws(a, /already runs as pid 1 on container-b/)
  assert.equal(top(p).host, 'container-b')
  winner()
})

await t('a fresh generation installed between the stale read and the takeover survives', () => {
  const p = fresh(); staleGen(p, 1)
  assert.throws(() => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1, hooks: { afterRead: () => { writeGen(p, 2, { host: 'container-c', token: 'f'.repeat(32) }) } } })), /already runs as pid 1 on container-c/)
  assert.equal(top(p).token, 'f'.repeat(32), 'the live holder\'s lock survived')
})

await t('  …the pair: one claimant alone still takes a stale lock over', () => {
  const p = fresh(); staleGen(p, 1)
  const release = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1 }))
  assert.equal(top(p).gen, 2); assert.deepEqual(gens(p), [2])
  release()
})

await t('many claimants racing for one stale lock: exactly one holds it (real processes)', async () => {
  const p = fresh(); staleGen(p, 1)
  const url = new URL('../mcp/tools/lease_lock.mjs', import.meta.url).href
  const script = (host) => `import { claimLeaseLock } from ${JSON.stringify(url)}
    try { claimLeaseLock(${JSON.stringify(p)}, 'i', 'daemon', { ttlMs: 5000, host: ${JSON.stringify(host)}, pid: 1 }); console.log('WON') } catch (e) { console.log('REFUSED') }
    setTimeout(() => process.exit(0), 600)`
  const outs = await Promise.all(Array.from({ length: 6 }, (_, i) => new Promise(res => {
    const c = spawn(process.execPath, ['--input-type=module', '-e', script(`racer-${i}`)], { stdio: ['ignore', 'pipe', 'inherit'] })
    let out = ''; c.stdout.on('data', d => { out += d }); c.on('close', () => res(out.trim()))
  })))
  assert.equal(outs.filter(o => o === 'WON').length, 1, `winners: ${JSON.stringify(outs)}`)
})

// ---- a blocked main thread (My Dude, PR 364) ---------------------------------------------------------------
const children = []
process.on('exit', () => { for (const c of children) try { c.kill('SIGKILL') } catch {} })
const holderChild = (path, host, blockMs, ttlMs = 1000) => {
  const script = `
    import { claimLeaseLock } from ${JSON.stringify(new URL('../mcp/tools/lease_lock.mjs', import.meta.url).href)}
    claimLeaseLock(${JSON.stringify(path)}, 'i', 'daemon', { ttlMs: ${ttlMs}, host: ${JSON.stringify(host)}, pid: 1 })
    console.log('claimed')
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ${blockMs})   // the main thread is blocked, like spawnSync
    console.log('unblocked')
    setInterval(() => {}, 1000)`
  const child = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'inherit'] })
  children.push(child); child.stdout.on('error', () => {})
  let out = ''; child.stdout.on('data', d => { out += d })
  return { child, out: () => out, claimed: () => new Promise(r => { const iv = setInterval(() => { if (out.includes('claimed')) { clearInterval(iv); r() } }, 20) }) }
}

await t('a holder whose main thread is BLOCKED past the lease still holds it: the heartbeat is on its own thread', async () => {
  const p = fresh(), h = holderChild(p, 'container-a', 3500)
  await h.claimed()
  await sleep(2500)
  assert.ok(!h.out().includes('unblocked'), 'the holder is still inside its blocking call')
  assert.throws(() => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1, ttlMs: 1000 })), /already runs as pid 1 on container-a/)
  h.child.kill('SIGKILL')
})

await t('  …the pair: a holder that is really dead (killed, so no heartbeat) does lapse and can be taken over', async () => {
  const p = fresh(), h = holderChild(p, 'container-a', 100)
  await h.claimed()
  h.child.kill('SIGKILL')
  await sleep(1600)
  const taker = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1, ttlMs: 1000 }))
  assert.equal(top(p).host, 'container-b')
  taker()
})

await t('a holder BLOCKED on the main thread whose lock is superseded is stopped by its heartbeat thread', async () => {
  const p = fresh(), h = holderChild(p, 'container-a', 6000)
  await h.claimed()
  const exited = new Promise(r => h.child.on('exit', (code, signal) => r({ code, signal })))
  writeGen(p, 2, { host: 'container-b', token: 'b'.repeat(32) })
  const result = await Promise.race([exited, sleep(4000).then(() => 'still running')])
  assert.notEqual(result, 'still running', 'the blocked holder was ended while its main thread was blocked')
  assert.equal(result.signal, 'SIGTERM')
  assert.equal(top(p).host, 'container-b', 'the new holder\'s lock is untouched')
})

// ---- a failing heartbeat thread must stop the holder (My Dude, PR 364) -----------------------------------------
const tmpWorker = (name, body) => { const f = join(dir, name); writeFileSync(f, body); return new URL(`file://${f}`) }

await t('a heartbeat thread that cannot start means NO lock: the claim throws and leaves nothing behind', () => {
  const p = fresh()
  const workerUrl = tmpWorker('never-ready.mjs', "import { parentPort } from 'node:worker_threads'\nparentPort.on('message', () => {})\n")
  assert.throws(() => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'A', pid: 1, workerUrl, readyMs: 600 })), /did not start; not taking the lock/)
  assert.deepEqual(gens(p), [], 'no lock file was left')
})

await t('  …a thread that dies at startup is the same', () => {
  const p = fresh()
  const workerUrl = tmpWorker('dies.mjs', "throw new Error('boom')\n")
  assert.throws(() => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'A', pid: 1, workerUrl, readyMs: 600 })), /did not start/)
  assert.deepEqual(gens(p), [])
})

await t('a heartbeat thread that dies AFTER starting stops the holder (it does not fall back to a main-loop beat)', async () => {
  const p = fresh()
  const worker = tmpWorker('ready-then-exit.mjs', `import { workerData } from 'node:worker_threads'
    Atomics.store(workerData.ready, 0, 1); Atomics.notify(workerData.ready, 0)
    setTimeout(() => process.exit(0), 300)\n`)
  const script = `import { claimLeaseLock } from ${JSON.stringify(new URL('../mcp/tools/lease_lock.mjs', import.meta.url).href)}
    claimLeaseLock(${JSON.stringify(p)}, 'i', 'daemon', { ttlMs: 1000, host: 'A', pid: 1, workerUrl: new URL(${JSON.stringify(worker.href)}) })
    console.log('running'); setInterval(() => {}, 1000)`
  const c = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'pipe'] })
  children.push(c)
  let err = ''; c.stderr.on('data', d => { err += d })
  const result = await Promise.race([new Promise(r => c.on('exit', (code, signal) => r({ code, signal }))), sleep(4000).then(() => 'still running')])
  assert.notEqual(result, 'still running', 'the holder kept running without a heartbeat')
  assert.equal(result.code, 70)
  assert.match(err, /heartbeat thread exited; stopping/)
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
