// daemon-instance-lock.mjs — one identity may have exactly one live draining daemon (#156).
//
// Two daemons on one spool duplicate proposal announcements, double the relay queries per tick, and
// put two writers on one terminal-reply log — and before this lock, neither objected. Under a
// supervisor with restart policies that stops being an operator slip and becomes routine: a restart
// overlapping a slow stop, a compose recreate, a deploy tick.
//
// The refusal assertions here are each paired with one proving a legitimate start still gets
// through, because a lock that refuses everything and a lock that refuses duplicates fail
// identically under a one-sided test — and "refuses to start" is indistinguishable from "is broken"
// if it is the only thing ever asserted.
//
//   node test/daemon-instance-lock.mjs

import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, unlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawn, spawnSync } from 'node:child_process'

let passed = 0, failed = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passed++ : failed++ }

const root = mkdtempSync(join(tmpdir(), 'nvoy-daemon-lock-'))
const manifests = join(root, 'instances')
const stateDir = join(root, 'state'), spoolDir = join(root, 'spool'), runtimeDir = join(root, 'runtime')
for (const d of [manifests, stateDir, spoolDir, runtimeDir]) mkdirSync(d, { recursive: true })
const uid = process.getuid(), gid = process.getgid()
const ID = 'lock-test'
const manifest = {
  version: 1, id: ID, pubkey: '1'.repeat(64), broker_mode: 'local',
  state_dir: stateDir, runtime_dir: runtimeDir, spool_dir: spoolDir,
  bunker_uri_ref: '/etc/nvoy/test.bunker', bunker_client_ref: '/etc/nvoy/test.client',
  worker_enabled: false, delivery_mode: 'notify_only',
  broker_adapter_gid: gid, worker_handoff_gid: gid + 1,
  watcher_uid: uid + 11, broker_uid: uid + 12, adapter_uid: uid + 13, worker_uid: uid,
  grantors: ['2'.repeat(64)], relays: ['wss://nos.lol'],
}
writeFileSync(join(manifests, `${ID}.json`), JSON.stringify(manifest))
const credential = join(root, 'broker.cred')
writeFileSync(credential, 'not-a-real-credential', { mode: 0o600 })

const daemon = resolve('mcp/tools/instance-broker-daemon.mjs')
const lockPath = join(stateDir, 'broker-daemon.lock')
const LIVE = /already runs as pid/

// The daemon drains forever once it holds the lock, so a start that GETS PAST the lock is observed
// as "did not print the lock refusal" plus the lock now naming this start — not as a clean exit.
// NVOY_LOCK_HOSTNAME stands in for "which container": each Compose broker container has a private PID
// namespace over the shared state volume, so two of them can both be PID 1, and the real hostname is
// one value on this machine.
const envFor = (host, extra = {}) => ({
  ...process.env, NVOY_INSTANCE_ROOT: manifests, NVOY_BROKER_CREDENTIAL: credential,
  NVOY_BROKER_LOCK_TTL_MS: '1000', NVOY_LOCK_HOSTNAME: host, ...extra,
})
function run (host = 'container-b') {
  const r = spawnSync(process.execPath, [daemon, '--instance', ID], { env: envFor(host), encoding: 'utf8', timeout: 4000, killSignal: 'SIGKILL' })
  return { err: (r.stderr || '') + (r.stdout || ''), status: r.status }
}
const startHolder = (host) => spawn(process.execPath, [daemon, '--instance', ID], { env: envFor(host), stdio: 'ignore' })
const writeLock = body => writeFileSync(lockPath, typeof body === 'string' ? body : JSON.stringify(body), { mode: 0o600 })
const clear = () => { if (existsSync(lockPath)) unlinkSync(lockPath) }
const lockJson = () => { try { return JSON.parse(readFileSync(lockPath, 'utf8')) } catch { return null } }
const waitFor = async (fn, ms = 4000) => { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await new Promise(r => setTimeout(r, 50)) } return false }
const v2 = (o = {}) => ({ version: 2, instance: ID, host: 'container-a', pid: 1, token: 'a'.repeat(32), started_at: Date.now(), ...o })

// ---- the positive control, stated before any refusal ------------------------------------------
clear()
const clean = run('container-a')
ok('with no lock present, the daemon starts and claims it', !LIVE.test(clean.err) && existsSync(lockPath))
const claimed = lockJson()
ok('the claimed lock records version, this instance, a host, a real pid and a token',
  claimed?.version === 2 && claimed?.instance === ID && claimed?.host === 'container-a' &&
  Number.isInteger(claimed?.pid) && claimed?.pid > 0 && /^[0-9a-f]{32}$/.test(claimed?.token || ''))

// ---- TWO CONTAINERS on one state volume (My Dude / Dennis, PR 364) -----------------------------
// A real daemon in "container-a" holds the lock and keeps its lease fresh. A second daemon in
// "container-b" must be refused — by the lease, not by anything PID-shaped, because a real second
// container would have a private PID namespace in which nothing about the first is visible.
clear()
const holderA = startHolder('container-a')
ok('a real daemon in container-a claims the lock', await waitFor(() => lockJson()?.host === 'container-a'))
const holderPid = lockJson()?.pid, holderToken = lockJson()?.token
const dup = run('container-b')
ok('a second daemon in another container is refused while the first heartbeats', LIVE.test(dup.err) && dup.status !== 0)
ok('the refusal is loud: it names the holder\'s pid and host', new RegExp(`pid ${holderPid} on container-a`).test(dup.err))
ok('PAIR: the live holder\'s lock is left intact, not stolen', lockJson()?.token === holderToken)
await new Promise(r => setTimeout(r, 1500))             // longer than the 1s lease: only the heartbeat keeps it alive
const dup2 = run('container-b')
ok('…and still refused after a full lease has passed, because the holder keeps beating', LIVE.test(dup2.err) && lockJson()?.token === holderToken)
holderA.kill('SIGKILL')                                 // no clean release: the lock is left behind
await new Promise(r => setTimeout(r, 1700))             // the heartbeat stops; the lease lapses
const takeover = run('container-b')
ok('PAIR: once the holder dies and its lease lapses, the other container starts', !LIVE.test(takeover.err) && lockJson()?.host === 'container-b')

// ---- the same container restarting: its own previous lock is stale at once ---------------------
clear(); writeLock(v2({ host: 'container-a', pid: 2 ** 30 }))
const restart = run('container-a')
ok('same container, previous pid gone: reclaimed immediately, no lease wait', !LIVE.test(restart.err) && lockJson()?.pid !== 2 ** 30)

// ---- malformed locks fail closed ---------------------------------------------------------------
for (const [name, body] of [
  ['unparseable', 'this is not json'],
  ['a lock naming another instance', v2({ instance: 'someone-else' })],
  ['a lock with no usable pid', v2({ pid: 0 })],
  ['a lock of an old or unknown version', { ...v2(), version: 1 }],
  ['a lock with no token', (() => { const { token, ...rest } = v2(); return rest })()],
]) {
  clear(); writeLock(body)
  const r = run('container-b')
  ok(`fails closed on ${name}`, /cannot validate|does not bind/.test(r.err) && r.status !== 0)
}
clear()
const again = run('container-b')
ok('PAIR: with the malformed locks cleared, a legitimate daemon still starts', !LIVE.test(again.err) && lockJson()?.host === 'container-b')

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
