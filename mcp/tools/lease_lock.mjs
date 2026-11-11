// lease_lock.mjs — one live holder per lock, provable ACROSS containers (nvoy#364).
//
// pid_lock.mjs decides liveness from a PID, which means nothing across PID namespaces: the broker
// Compose service gives each container a private PID namespace over a SHARED state volume, so two
// overlapping broker containers can both be PID 1. So the holder proves it is alive the way every
// container can see: it keeps touching its lock file, and a lock is live while that mtime is fresh.
//
// The lock is a sequence of GENERATION files, `<path>.<n>`. The current lock is the highest n. Taking a
// lock over means creating `<path>.<n+1>` with O_EXCL, and that create is the only compare-and-swap: of
// any number of claimants that judged generation n stale, exactly one creates n+1, and nobody ever
// deletes a file someone else might be relying on. (An earlier shape, read a stale lock and unlink its
// path, let a claimant delete a fresh lock installed in between; a mutex file to serialise that needed its
// own stale-break, which raced the same way.) Older generations are only garbage, removed afterwards.
//
//   other host  → live while the highest generation's mtime is younger than ttlMs
//   same host   → this very pid is a previous incarnation of us (pid 1 after a restart): stale;
//                 another pid: alive and running this program → live; gone → stale (no lease wait)
//
// A holder whose generation has been superseded has lost the lock: its beat thread ends the whole process
// (see lease_beat_worker.mjs) rather than let it run on as a second writer.

import { closeSync, lstatSync, openSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { hostname } from 'node:os'
import { Worker } from 'node:worker_threads'
import { basename, dirname } from 'node:path'

const VERSION = 3

function mayHold(pid, instance, program, procRoot) {
  if (!program) return true
  let argv
  try { argv = readFileSync(`${procRoot}/${pid}/cmdline`, 'utf8').split('\0') } catch { return true }
  const at = argv.indexOf('--instance')
  return argv.some(arg => basename(arg) === program) && at >= 0 && argv[at + 1] === instance
}

/** The generation files of a lock, ascending: [{ gen, file }]. */
export function generations(path) {
  const dir = dirname(path), prefix = `${basename(path)}.`
  let names
  try { names = readdirSync(dir) } catch { return [] }
  return names.filter(n => n.startsWith(prefix) && /^\d+$/.test(n.slice(prefix.length)))
    .map(n => ({ gen: Number(n.slice(prefix.length)), file: `${dir}/${n}` })).sort((a, b) => a.gen - b.gen)
}

export function claimLeaseLock(path, instance, holder, {
  ttlMs = 15000, beatMs = Math.max(250, Math.floor(ttlMs / 3)), host = hostname(), pid = process.pid,
  now = () => Date.now(), program = '', procRoot = '/proc', probe = p => process.kill(p, 0),
  onLost = null, hooks = {}, workerUrl = new URL('./lease_beat_worker.mjs', import.meta.url), readyMs = 5000,
} = {}) {
  if (!Number.isInteger(ttlMs) || ttlMs < 1000) throw new Error('lock ttl must be at least 1000 ms')
  const token = randomBytes(16).toString('hex')

  // Decide about the CURRENT lock: 'none' (no file), 'stale' (may be superseded), or throw a refusal.
  const judge = () => {
    const all = generations(path)
    if (!all.length) return { verdict: 'none', gen: 0 }
    const top = all[all.length - 1]
    let stat, prior
    try {
      stat = lstatSync(top.file)
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('lock is not a regular file')
      prior = JSON.parse(readFileSync(top.file, 'utf8'))
    } catch (error) {
      if (error.code === 'ENOENT') return { verdict: 'none', gen: top.gen }
      throw new Error(`cannot validate existing ${holder} lock: ${error.message}`)
    }
    if (prior?.version !== VERSION || prior?.instance !== instance || prior?.gen !== top.gen || !Number.isInteger(prior?.pid) ||
        prior.pid < 1 || typeof prior?.host !== 'string' || !prior.host || typeof prior?.token !== 'string') {
      throw new Error(`${holder} lock does not bind this instance`)
    }
    const age = now() - stat.mtimeMs
    if (prior.host !== host) {
      if (age < ttlMs) throw new Error(`${holder} already runs as pid ${prior.pid} on ${prior.host} (heartbeat ${Math.max(0, Math.round(age / 1000))}s ago)`)
      return { verdict: 'stale', gen: top.gen }
    }
    if (prior.pid === pid) return { verdict: 'stale', gen: top.gen }      // a previous incarnation of this container
    try {
      probe(prior.pid)
      if (mayHold(prior.pid, instance, program, procRoot)) throw new Error(`${holder} already runs as pid ${prior.pid}`)
    } catch (error) {
      if (error.code === 'ESRCH') return { verdict: 'stale', gen: top.gen }
      if (error.code === 'EPERM' && !mayHold(prior.pid, instance, program, procRoot)) return { verdict: 'stale', gen: top.gen }
      throw error
    }
    return { verdict: 'stale', gen: top.gen }
  }

  // The one atomic step: create generation `gen` exclusively. False if someone else already did.
  const create = gen => {
    const file = `${path}.${gen}`
    try {
      const fd = openSync(file, 'wx', 0o600)
      writeFileSync(fd, JSON.stringify({ version: VERSION, instance, gen, host, pid, token, started_at: now() }))
      closeSync(fd)
      return file
    } catch (error) { if (error.code === 'EEXIST') return null; throw error }
  }

  let myGen = 0, myFile = null
  const first = judge()
  if (first.verdict !== 'none') hooks.afterRead?.()
  for (let attempt = 0; attempt < 3 && !myFile; attempt++) {
    const seen = attempt === 0 ? first : judge()                  // a lost race re-judges: the winner is fresh, so this refuses
    myFile = create(seen.gen + 1)
    if (myFile) myGen = seen.gen + 1
  }
  if (!myFile) throw new Error(`${holder} lock was claimed by another process while taking it over`)
  for (const old of generations(path)) if (old.gen < myGen) { try { unlinkSync(old.file) } catch {} }   // superseded: only garbage

  const mine = () => {
    try {
      if (JSON.parse(readFileSync(myFile, 'utf8')).token !== token) return false
      const all = generations(path)
      return all.length > 0 && all[all.length - 1].gen === myGen
    } catch { return false }
  }
  const lostHere = () => {
    if (onLost) onLost()
    else { console.error(`${holder} lock was taken over; stopping so there is never a second writer`); process.exit(70) }
  }

  // The beat runs on its own thread: the daemon blocks its main thread in spawnSync for up to 90 s, and a
  // main-loop timer would lapse the lease under a LIVE holder. The worker also ends the whole process if the
  // lock is superseded or if the worker itself fails (it cannot be allowed to die quietly and leave a lease
  // lapsing under a running holder). It must prove it can beat BEFORE we return: a worker that cannot start
  // means no lock, so the daemon does not start.
  const ready = new Int32Array(new SharedArrayBuffer(4))
  const worker = new Worker(workerUrl, {
    workerData: { path, file: myFile, gen: myGen, token, beatMs, killOnLost: !onLost, ready }, execArgv: [],
  })
  let released = false
  worker.on('message', message => { if (message?.lost) lostHere() })
  worker.on('error', error => {
    if (released) return
    console.error(`${holder} lease heartbeat thread failed (${error.message}); stopping rather than run without a lease`)
    process.exit(70)
  })
  worker.on('exit', () => {
    if (released) return
    console.error(`${holder} lease heartbeat thread exited; stopping rather than run without a lease`)
    process.exit(70)
  })
  worker.unref()
  const release = () => {
    released = true
    try { worker.postMessage('stop') } catch {}
    worker.terminate().catch(() => {})
    try { if (mine()) unlinkSync(myFile) } catch {}
  }
  Atomics.wait(ready, 0, 0, readyMs)                                 // 1 once the worker has made its first beat
  if (Atomics.load(ready, 0) !== 1) {
    release()
    try { unlinkSync(myFile) } catch {}
    throw new Error(`${holder} lease heartbeat thread did not start; not taking the lock`)
  }
  return release
}
