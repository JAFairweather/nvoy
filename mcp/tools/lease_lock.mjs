// lease_lock.mjs — one live holder per lock file, provable ACROSS containers (nvoy#364).
//
// pid_lock.mjs decides liveness from a PID, which is only meaningful inside one PID namespace. The
// broker Compose service gives each container a private PID namespace over a SHARED state volume, so
// two overlapping broker containers can both run Node as PID 1: "that PID is this very process" would
// then let the second container steal the first's live lock, and /proc in one container cannot say
// anything about a holder in another.
//
// So the holder proves it is alive the one way every container can see: it keeps touching the lock
// file. A lock is live while its mtime is fresh, whatever PID or host it names. Only when the lock was
// written by THIS host (same hostname = same container, so the same PID namespace) is a PID check
// meaningful, and then it can reclaim a dead holder at once instead of waiting out the lease:
//
//   other host  → live while mtime is younger than ttlMs; stale only once the heartbeat has lapsed
//   same host   → this very pid is a previous incarnation of us (pid 1 after a restart): stale;
//                 another pid: alive and running this program → live; gone → stale
//
// The lease costs a restart after a hard kill up to ttlMs, once; it buys exclusivity that does not
// depend on any PID. A holder that finds its token gone (it stalled past the lease and was reclaimed)
// stops rather than carry on as a second writer.

import { closeSync, lstatSync, openSync, readFileSync, unlinkSync, utimesSync, writeFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { Worker } from 'node:worker_threads'
import { hostname } from 'node:os'
import { basename } from 'node:path'

const VERSION = 2

function mayHold(pid, instance, program, procRoot) {
  if (!program) return true
  let argv
  try { argv = readFileSync(`${procRoot}/${pid}/cmdline`, 'utf8').split('\0') } catch { return true }
  const at = argv.indexOf('--instance')
  return argv.some(arg => basename(arg) === program) && at >= 0 && argv[at + 1] === instance
}

export function claimLeaseLock(path, instance, holder, {
  ttlMs = 15000, beatMs = Math.max(250, Math.floor(ttlMs / 3)), host = hostname(), pid = process.pid,
  now = () => Date.now(), program = '', procRoot = '/proc', probe = p => process.kill(p, 0),
  onLost = null,
} = {}) {
  if (!Number.isInteger(ttlMs) || ttlMs < 1000) throw new Error('lock ttl must be at least 1000 ms')
  const token = randomBytes(16).toString('hex')
  const body = () => JSON.stringify({ version: VERSION, instance, host, pid, token, started_at: now() })

  const create = () => {
    try {
      const fd = openSync(path, 'wx', 0o600)
      writeFileSync(fd, body())
      closeSync(fd)
      return true
    } catch (error) { if (error.code === 'EEXIST') return false; throw error }
  }

  if (!create()) {
    let stat, prior
    try {
      stat = lstatSync(path)
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('lock is not a regular file')
      prior = JSON.parse(readFileSync(path, 'utf8'))
    } catch (error) { throw new Error(`cannot validate existing ${holder} lock: ${error.message}`) }
    if (prior?.version !== VERSION || prior?.instance !== instance || !Number.isInteger(prior?.pid) || prior.pid < 1 ||
        typeof prior?.host !== 'string' || !prior.host || typeof prior?.token !== 'string') {
      throw new Error(`${holder} lock does not bind this instance`)
    }
    const age = now() - stat.mtimeMs
    let live
    if (prior.host !== host) {
      live = age < ttlMs
      if (live) throw new Error(`${holder} already runs as pid ${prior.pid} on ${prior.host} (heartbeat ${Math.max(0, Math.round(age / 1000))}s ago)`)
    } else if (prior.pid === pid) {
      live = false                                   // a previous incarnation of this container
    } else {
      try {
        probe(prior.pid)
        live = mayHold(prior.pid, instance, program, procRoot)
      } catch (error) {
        if (error.code === 'ESRCH') live = false
        else if (error.code === 'EPERM' && !mayHold(prior.pid, instance, program, procRoot)) live = false
        else throw error
      }
      if (live) throw new Error(`${holder} already runs as pid ${prior.pid}`)
    }
    unlinkSync(path)
    if (!create()) throw new Error(`${holder} lock was claimed by another process while reclaiming it`)
  }

  const mine = () => { try { return JSON.parse(readFileSync(path, 'utf8')).token === token } catch { return false } }
  // The beat runs on its own thread (lease_beat_worker.mjs): the daemon blocks its main thread in
  // spawnSync for up to 90 s, and a main-loop timer would lapse the lease under a LIVE holder. With no
  // custom onLost, the worker ends the whole process itself when the lock is found taken, because a
  // blocked main thread cannot. A custom onLost (tests, embedding) is called from the main thread instead.
  // execArgv is cleared: a worker inherits the parent's (an `--input-type` eval flag makes it refuse to load).
  const worker = new Worker(new URL('./lease_beat_worker.mjs', import.meta.url), {
    workerData: { path, token, beatMs, killOnLost: !onLost }, execArgv: [],
  })
  const lostHere = () => {
    if (onLost) onLost()
    else { console.error(`${holder} lock was taken over; stopping so there is never a second writer`); process.exit(70) }
  }
  worker.on('message', message => { if (message?.lost) lostHere() })
  // A beat thread that cannot run must not leave the lease silently lapsing under a live holder: say so,
  // and fall back to a main-loop beat (which is the weaker form this exists to improve on).
  let fallback = null
  worker.on('error', error => {
    console.error(`${holder} lease heartbeat thread failed (${error.message}); falling back to the main loop`)
    fallback = setInterval(() => {
      if (!mine()) { clearInterval(fallback); lostHere(); return }
      try { const t = new Date(); utimesSync(path, t, t) } catch {}
    }, beatMs)
    fallback.unref()
  })
  worker.unref()
  return () => { clearInterval(fallback); try { worker.postMessage('stop') } catch {} ; worker.terminate().catch(() => {}); try { if (mine()) unlinkSync(path) } catch {} }
}
