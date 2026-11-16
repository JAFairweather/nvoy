// One live holder per lock file, the rule claude-channel.mjs applies to its channel.lock: create
// exclusively; reclaim only a lock whose recorded PID is demonstrably gone or recycled; fail closed
// on a malformed or foreign lock. A lock naming this very process is stale (#217): PIDs restart in a
// new container, so "that PID is alive" can be only this process looking at itself.
//
// `program` goes one step further for a lock that only ever one program holds, in one container:
// where /proc shows what the recorded PID runs, a PID running anything but that program for this
// instance is a stranger that inherited the number, and the lock is stale. The feed lock outlives
// an adapter container, and its PID can name a live, unrelated process in the next one.

import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { closeSync, lstatSync, openSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { basename } from 'node:path'

// True unless /proc shows the PID running something other than `program --instance <instance>`.
function mayHold(pid, instance, program, procRoot) {
  if (!program) return true
  let argv
  try { argv = readFileSync(`${procRoot}/${pid}/cmdline`, 'utf8').split('\0') } catch { return true }
  const at = argv.indexOf('--instance')
  return argv.some(arg => basename(arg) === program) && at >= 0 && argv[at + 1] === instance
}

// /proc/<pid>/stat field 22 is the process start in clock ticks after boot. The boot ID plus these
// ticks identifies the holder even when a new container reuses its PID and command line (#206).
function startTicks(pid, procRoot) {
  try {
    const stat = readFileSync(`${procRoot}/${pid}/stat`, 'utf8')
    const end = stat.lastIndexOf(')')
    if (end < 0) return null
    const ticks = stat.slice(end + 2).trim().split(/\s+/)[19]
    return /^\d+$/.test(ticks || '') ? ticks : null
  } catch { return null }
}

function processIdentity(pid, procRoot) {
  const ticks = startTicks(pid, procRoot)
  if (!ticks) return null
  try {
    const boot = readFileSync(`${procRoot}/sys/kernel/random/boot_id`, 'utf8').trim()
    return /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(boot) ? { boot, ticks } : null
  } catch { return null }
}

// Old lock records carry only a wall-clock timestamp. A PID allocated well after that timestamp
// cannot be their holder either. The boot time has one-second precision, so require a two-second
// gap. If the timestamp or any part of the Linux evidence is missing, keep the lock.
function startedAfterLock(pid, recordedAt, procRoot) {
  if (!Number.isSafeInteger(recordedAt) || recordedAt < 946684800000 || recordedAt > Date.now() + 600000) return false
  try {
    const ticks = Number(startTicks(pid, procRoot))
    const boot = Number(readFileSync(`${procRoot}/stat`, 'utf8').match(/^btime (\d+)$/m)?.[1])
    const hz = Number(execFileSync('/usr/bin/getconf', ['CLK_TCK'], { encoding: 'utf8', timeout: 1000 }).trim())
    if (!Number.isSafeInteger(ticks) || ticks < 1 || !Number.isSafeInteger(boot) || boot < 1 || !Number.isSafeInteger(hz) || hz < 1) return false
    return boot * 1000 + ticks * 1000 / hz > recordedAt + 2000
  } catch { return false }
}

// `probe` is the liveness check, process.kill(pid, 0) by default; tests pass one to force an errno.
export function claimPidLock(path, instance, holder, { program = '', procRoot = '/proc', probe = pid => process.kill(pid, 0) } = {}) {
  try {
    const fd = openSync(path, 'wx', 0o600)
    const nonce = randomBytes(16).toString('hex')
    const identity = processIdentity(process.pid, procRoot)
    writeFileSync(fd, JSON.stringify({ version: 1, instance, pid: process.pid, started_at: Date.now(), nonce,
      ...(identity ? { process_identity: identity } : {}) }))
    closeSync(fd)
    return () => { try { if (JSON.parse(readFileSync(path, 'utf8')).nonce === nonce) unlinkSync(path) } catch {} }
  } catch (error) { if (error.code !== 'EEXIST') throw error }
  let prior
  try {
    const stat = lstatSync(path)
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('lock is not a regular file')
    prior = JSON.parse(readFileSync(path, 'utf8'))
  } catch (error) { throw new Error(`cannot validate existing ${holder} lock: ${error.message}`) }
  if (prior?.version !== 1 || prior?.instance !== instance || !Number.isInteger(prior?.pid) || prior.pid < 1) throw new Error(`${holder} lock does not bind this instance`)
  if (Object.hasOwn(prior, 'process_identity') && (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(prior.process_identity?.boot || '') ||
      !/^\d+$/.test(prior.process_identity.ticks || ''))) throw new Error(`${holder} lock has an invalid process identity`)
  if (prior.pid !== process.pid) {
    let gone = false, denied = null
    try { probe(prior.pid) } catch (error) {
      if (error.code === 'ESRCH') gone = true
      else if (error.code === 'EPERM') denied = error
      else throw error
    }
    const current = gone ? null : processIdentity(prior.pid, procRoot)
    const recycled = prior.process_identity ? current && (prior.process_identity.boot !== current.boot || prior.process_identity.ticks !== current.ticks) :
      startedAfterLock(prior.pid, prior.started_at, procRoot)
    if (!gone && !recycled && mayHold(prior.pid, instance, program, procRoot)) {
      if (denied) throw denied
      throw new Error(`${holder} already runs as pid ${prior.pid}`)
    }
  }
  unlinkSync(path)
  return claimPidLock(path, instance, holder, { program, procRoot, probe })
}
