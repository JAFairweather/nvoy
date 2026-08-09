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
import { spawnSync } from 'node:child_process'

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
// as "did not print the lock refusal" plus the lock now naming a different pid — not as a clean
// exit, which would never come.
function run () {
  const r = spawnSync(process.execPath, [daemon, '--instance', ID], {
    env: { ...process.env, NVOY_INSTANCE_ROOT: manifests, NVOY_BROKER_CREDENTIAL: credential },
    encoding: 'utf8', timeout: 4000, killSignal: 'SIGKILL',
  })
  return { err: (r.stderr || '') + (r.stdout || ''), status: r.status }
}
const writeLock = body => writeFileSync(lockPath, typeof body === 'string' ? body : JSON.stringify(body), { mode: 0o600 })
const clear = () => { if (existsSync(lockPath)) unlinkSync(lockPath) }
// Never throw while reading the lock: under a disarmed-lock negative control there is no file, and
// a test that CRASHES at the first failure hides every assertion after it. Fail, report, continue.
const lockJson = () => { try { return JSON.parse(readFileSync(lockPath, 'utf8')) } catch { return null } }

// ---- the positive control, stated before any refusal ------------------------------------------
clear()
const clean = run()
ok('with no lock present, the daemon starts and claims it', !LIVE.test(clean.err) && existsSync(lockPath))
const claimed = lockJson()
ok('the claimed lock records version, this instance, and a real pid',
  claimed?.version === 1 && claimed?.instance === ID && Number.isInteger(claimed?.pid) && claimed?.pid > 0)

// ---- a live holder is refused, and refused LOUDLY ---------------------------------------------
// process.pid is this test runner — demonstrably alive, which is the whole point.
clear(); writeLock({ version: 1, instance: ID, pid: process.pid, started_at: Date.now() })
const dup = run()
ok('refuses to start when a live daemon already holds the lock', LIVE.test(dup.err))
ok('the refusal is loud — it names the holding pid and exits non-zero',
  new RegExp(`already runs as pid ${process.pid}`).test(dup.err) && dup.status !== 0)
ok('PAIR: the live holder\'s lock is left intact, not stolen', lockJson()?.pid === process.pid)

// ---- a stale lock is reclaimed rather than becoming its own outage ----------------------------
// A pid that cannot exist: reclaiming must depend on liveness, not on the file being absent.
clear(); writeLock({ version: 1, instance: ID, pid: 2 ** 30, started_at: Date.now() })
const stale = run()
ok('reclaims a lock whose recorded pid is gone (a killed process must not lock the identity out)',
  !LIVE.test(stale.err))
ok('PAIR: the reclaimed lock now names the new holder, not the dead pid',
  Number.isInteger(lockJson()?.pid) && lockJson()?.pid !== 2 ** 30)

// ---- malformed and foreign locks fail closed --------------------------------------------------
for (const [label, body, want] of [
  ['unparseable', 'not json at all', /cannot validate existing broker daemon lock/],
  ['a lock naming another instance', { version: 1, instance: 'someone-else', pid: process.pid, started_at: 1 }, /does not bind this instance/],
  ['a lock with no usable pid', { version: 1, instance: ID, pid: 'nope', started_at: 1 }, /does not bind this instance/],
  ['a lock of an unknown version', { version: 99, instance: ID, pid: process.pid, started_at: 1 }, /does not bind this instance/],
]) {
  clear(); writeLock(body)
  const r = run()
  ok(`fails closed on ${label}`, want.test(r.err))
}

// ---- and the pair: after all that, a clean start still works ----------------------------------
clear()
const again = run()
ok('PAIR: with the malformed locks cleared, a legitimate daemon still starts',
  !LIVE.test(again.err) && existsSync(lockPath))

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
