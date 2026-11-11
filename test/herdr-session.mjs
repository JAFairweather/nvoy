// A herdr session stopped during its launch: the launcher execs the agent, so the session is known only by the
// pid it writes and the start time recorded with it. A stop that arrives before start() returns, whether before
// or after the pid appears, still ends the session, and so does an exit handler's kill() in the same gap,
// even before the pane has run the launcher at all.
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn, spawnSync } from 'node:child_process'
import { herdrSession } from '../mcp/tools/harness_herdr.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const root = mkdtempSync(join(tmpdir(), 'nvoy-hsess-'))
const sleep = ms => new Promise(done => setTimeout(done, ms))
// Running, not a zombie waiting to be reaped.
const alive = pid => !!pid && /^[^Z]/.test((spawnSync('ps', ['-o', 'stat=', '-p', String(pid)], { encoding: 'utf8' }).stdout || '').trim())
const leftovers = []

// A pane that runs what is typed as its own job, the way an interactive shell does (see fake-herdr.mjs),
// after `delay` seconds, as a busy pane might.
function fakePane(delay = 0) {
  const pane = { ran: 0 }
  pane.herdr = {
    pane: () => 'w1:p1', close() {}, keys() {}, read: () => '', agent: () => null, name() {},
    run(_, command) { pane.ran++; spawn('/bin/sh', ['-c', (delay ? `sleep ${delay}; ` : '') + 'exec ' + command], { detached: true, stdio: 'ignore' }).unref() },
  }
  return pane
}

async function launch(label, when, delay = 0) {
  const dir = mkdtempSync(join(root, label + '-'))
  const pane = fakePane(delay)
  const session = herdrSession({ herdr: pane.herdr, name: 'test', dir, cwd: dir, launchMs: 5000 })
  const pidFile = join(dir, 'session.pid'), startFile = join(dir, 'session.start')
  const starting = session.start({ command: ['sleep', '60'], env: { PATH: process.env.PATH } }).catch(error => error)
  let inGap = false
  for (const until = Date.now() + 5000; Date.now() < until; await sleep(1)) {
    if (when === 'typed' && pane.ran) { inGap = !existsSync(pidFile); break }
    if (when === 'pid' && existsSync(pidFile) && session.pid()) { inGap = !existsSync(startFile); break }
  }
  return { session, starting, inGap, pid: () => session.pid() }
}

// The gap is a few milliseconds wide; try until a stop lands inside it.
async function inGap(label, when, stopWith) {
  for (let attempt = 0; attempt < 20; attempt++) {
    const run = await launch(`${label}${attempt}`, when)
    if (!run.inGap) { await run.starting; await run.session.stop(); continue }
    await stopWith(run.session)
    await run.starting
    const pid = run.pid()
    leftovers.push(pid)
    for (let i = 0; i < 50 && alive(pid); i++) await sleep(20)
    return { hit: true, pid, dead: !!pid && !alive(pid) }
  }
  return { hit: false }
}

const afterPid = await inGap('afterpid', 'pid', session => session.stop())
ok('a stop after the launcher writes its pid, before start() records it, ends the session', afterPid.hit && afterPid.dead)
const beforePid = await inGap('beforepid', 'typed', session => session.stop())
ok('a stop after the launcher is typed, before its pid appears, waits for it and ends the session', beforePid.hit && beforePid.dead)
const killed = await inGap('kill', 'pid', session => session.kill())
ok('an exit handler\'s kill() in the same gap ends the session too', killed.hit && killed.dead)

// An exit handler cannot wait for start(), and its process is gone once kill() returns: the launch must
// end whether its pid appears during kill() or only after kill() has given up waiting for it.
for (const [label, delay] of [['exitsoon', 0.3], ['exitlate', 2.5]]) {
  const run = await launch(label, 'typed', delay)
  const before = !run.pid()
  run.session.kill()
  await run.starting
  const pid = run.pid()
  leftovers.push(pid)
  for (let i = 0; i < 50 && alive(pid); i++) await sleep(20)
  ok(`an exit handler's kill() before the pane runs the launcher (${delay} s late) ends the launch`, before && !!pid && !alive(pid))
}

const plain = await launch('plain', 'pid')
await plain.starting
const plainPid = plain.pid()
ok('a session that started is alive and not dead to its supervisor', alive(plainPid) && !plain.session.dead().dead)
await plain.session.stop()
ok('a stop after start() ends it, and the supervisor sees it gone', !alive(plainPid) && plain.session.dead().status === 'gone')

for (const pid of leftovers) try { process.kill(-Number(pid), 'SIGKILL') } catch {}
rmSync(root, { recursive: true, force: true })
console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
