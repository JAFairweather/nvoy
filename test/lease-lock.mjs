// lease-lock.mjs — one live holder, provable across PID namespaces (nvoy#364).
//
//   node test/lease-lock.mjs
//
// The cases that matter are the ones a PID lock gets wrong: two containers on one state volume, each
// PID 1 in its own namespace. Hosts are injected (the real hostname is one value on this machine), and
// the "dead holder" case is a different host whose heartbeat has stopped. Every refusal is paired with a
// legitimate claim that still succeeds.

import assert from 'node:assert'
import { mkdtempSync, writeFileSync, readFileSync, existsSync, utimesSync, unlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { claimLeaseLock } from '../mcp/tools/lease_lock.mjs'

let pass = 0, fail = 0
const t = async (name, fn) => {
  try { await fn(); console.log(`ok   — ${name}`); pass++ }
  catch (e) { console.log(`FAIL — ${name}\n       ${e.message}`); fail++ }
}
const dir = mkdtempSync(join(tmpdir(), 'nvoy-lease-'))
let n = 0
const fresh = () => join(dir, `lock-${++n}`)
const opts = (o = {}) => ({ ttlMs: 2000, onLost: () => {}, ...o })
const body = (path) => JSON.parse(readFileSync(path, 'utf8'))
const age = (path, ms) => { const t = new Date(Date.now() - ms); utimesSync(path, t, t) }

await t('a first claim creates the lock, naming host, pid and a token', () => {
  const p = fresh(), release = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'A', pid: 1 }))
  const b = body(p)
  assert.deepEqual([b.version, b.instance, b.host, b.pid], [2, 'i', 'A', 1])
  assert.match(b.token, /^[0-9a-f]{32}$/)
  release(); assert.equal(existsSync(p), false)
})

await t('TWO CONTAINERS, both PID 1: the second is refused while the first heartbeats (My Dude, PR 364)', () => {
  const p = fresh()
  const first = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-a', pid: 1 }))
  assert.throws(() => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1 })), /already runs as pid 1 on container-a/)
  assert.equal(body(p).host, 'container-a', 'the live holder\'s lock was not taken')
  first()
})

await t('  …the pair: the same pid on the SAME host is a previous incarnation of this container, so it is reclaimed', () => {
  const p = fresh()
  writeFileSync(p, JSON.stringify({ version: 2, instance: 'i', host: 'container-a', pid: 1, token: 'a'.repeat(32), started_at: 1 }), { mode: 0o600 })
  const release = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-a', pid: 1 }))
  assert.notEqual(body(p).token, 'a'.repeat(32))
  release()
})

await t('another host whose heartbeat has lapsed is stale and is reclaimed', () => {
  const p = fresh()
  const first = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-a', pid: 1 }))
  age(p, 5000)                                           // the heartbeat stopped five seconds ago; ttl is two
  const second = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1 }))
  assert.equal(body(p).host, 'container-b')
  second(); first()
})

await t('a heartbeat keeps a lock fresh: after the mtime is aged, a beat renews it', async () => {
  const p = fresh()
  const first = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-a', pid: 1, ttlMs: 1000, beatMs: 100 }))
  age(p, 900)
  await new Promise(r => setTimeout(r, 350))
  assert.throws(() => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1, ttlMs: 1000 })), /already runs/)
  first()
})

await t('a holder that finds its token gone reports lost and stops beating, instead of carrying on as a second writer', async () => {
  const p = fresh()
  let lost = 0
  const first = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-a', pid: 1, beatMs: 100, onLost: () => { lost++ } }))
  writeFileSync(p, JSON.stringify({ version: 2, instance: 'i', host: 'container-b', pid: 1, token: 'b'.repeat(32), started_at: 1 }))
  await new Promise(r => setTimeout(r, 350))
  assert.ok(lost >= 1)
  first()
  assert.equal(body(p).host, 'container-b', 'releasing after losing the lock does not delete the new holder\'s lock')
})

await t('the exit hook of the loser never unlinks the winner\'s lock (token-checked release)', () => {
  const p = fresh()
  const first = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-a', pid: 1 }))
  age(p, 5000)
  const second = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1 }))
  first()                                                // the stale one finally exits
  assert.equal(existsSync(p), true)
  assert.equal(body(p).host, 'container-b')
  second()
})

await t('same host: a different pid that is gone is stale at once (a killed process does not wait out the lease)', () => {
  const p = fresh()
  writeFileSync(p, JSON.stringify({ version: 2, instance: 'i', host: 'A', pid: 2 ** 30, token: 'c'.repeat(32), started_at: 1 }), { mode: 0o600 })
  const release = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'A', pid: 7 }))
  assert.equal(body(p).pid, 7)
  release()
})

await t('same host: a live different pid running this program is refused', () => {
  const p = fresh()
  writeFileSync(p, JSON.stringify({ version: 2, instance: 'i', host: 'A', pid: process.pid, token: 'd'.repeat(32), started_at: 1 }), { mode: 0o600 })
  assert.throws(() => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'A', pid: process.pid + 1 })), /already runs as pid/)
})

await t('same host: a live pid that is NOT this program is a stranger and is reclaimed', () => {
  const p = fresh()
  writeFileSync(p, JSON.stringify({ version: 2, instance: 'i', host: 'A', pid: process.pid, token: 'e'.repeat(32), started_at: 1 }), { mode: 0o600 })
  const release = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'A', pid: process.pid + 1, program: 'instance-broker-daemon.mjs' }))
  assert.equal(body(p).pid, process.pid + 1)
  release()
})

await t('malformed, foreign-instance, old-format and symlinked locks fail closed', () => {
  for (const content of ['not json', JSON.stringify({ version: 2, instance: 'other', host: 'A', pid: 1, token: 'f'.repeat(32) }),
    JSON.stringify({ version: 1, instance: 'i', pid: 1 }), JSON.stringify({ version: 2, instance: 'i', host: 'A', pid: 0, token: 'f'.repeat(32) }),
    JSON.stringify({ version: 2, instance: 'i', host: 'A', pid: 1 })]) {
    const p = fresh(); writeFileSync(p, content, { mode: 0o600 })
    assert.throws(() => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'B', pid: 1 })), /cannot validate|does not bind/)
    assert.equal(readFileSync(p, 'utf8'), content, 'a lock that cannot be validated is left alone')
  }
})

// My Dude, PR 364: the daemon blocks its main thread in spawnSync (90 s timeout). A main-loop heartbeat
// would lapse under a LIVE holder and let another container take the lock. These run the holder in a
// child that blocks its main thread past the lease, as a slow broker child does.
const { spawn } = await import('node:child_process')
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
  children.push(child)
  child.stdout.on('error', () => {})
  let out = ''
  child.stdout.on('data', d => { out += d })
  return { child, out: () => out, claimed: () => new Promise(r => { const iv = setInterval(() => { if (out.includes('claimed')) { clearInterval(iv); r() } }, 20) }) }
}

await t('a holder whose main thread is BLOCKED past the lease still holds it: the heartbeat is on its own thread', async () => {
  const p = fresh(), h = holderChild(p, 'container-a', 3500)
  await h.claimed()
  await new Promise(r => setTimeout(r, 2500))            // 2.5x the 1s lease, and the holder is still blocked
  assert.ok(!h.out().includes('unblocked'), 'the holder is still inside its blocking call')
  assert.throws(() => claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1, ttlMs: 1000 })), /already runs as pid 1 on container-a/)
  h.child.kill('SIGKILL')
})

await t('  …the pair: a holder that is really dead (killed, so no heartbeat) does lapse and can be taken over', async () => {
  const p = fresh(), h = holderChild(p, 'container-a', 100)
  await h.claimed()
  h.child.kill('SIGKILL')
  await new Promise(r => setTimeout(r, 1600))
  const taker = claimLeaseLock(p, 'i', 'daemon', opts({ host: 'container-b', pid: 1, ttlMs: 1000 }))
  assert.equal(body(p).host, 'container-b')
  taker()
})

await t('a holder BLOCKED on the main thread whose lock is taken over is stopped by its heartbeat thread, not left as a second writer', async () => {
  const p = fresh(), h = holderChild(p, 'container-a', 6000)
  await h.claimed()
  const exited = new Promise(r => h.child.on('exit', (code, signal) => r({ code, signal })))
  writeFileSync(p, JSON.stringify({ version: 2, instance: 'i', host: 'container-b', pid: 1, token: 'b'.repeat(32), started_at: Date.now() }))
  const result = await Promise.race([exited, new Promise(r => setTimeout(() => r('still running'), 4000))])
  assert.notEqual(result, 'still running', 'the blocked holder was ended while its main thread was blocked')
  assert.equal(result.signal, 'SIGTERM')
  assert.equal(body(p).host, 'container-b', 'the new holder\'s lock is untouched')
})

await t('a lock that is a symlink is refused, not followed', async () => {
  const { symlinkSync } = await import('node:fs')
  const target = fresh(), link = fresh()
  writeFileSync(target, JSON.stringify({ version: 2, instance: 'i', host: 'A', pid: 1, token: 'f'.repeat(32) }), { mode: 0o600 })
  symlinkSync(target, link)
  assert.throws(() => claimLeaseLock(link, 'i', 'daemon', opts({ host: 'B', pid: 1 })), /cannot validate/)
})

await t('a ttl below one second is refused', () => {
  assert.throws(() => claimLeaseLock(fresh(), 'i', 'daemon', { ttlMs: 10 }), /at least 1000/)
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
