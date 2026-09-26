// One live holder per lock file, the rule claude-channel.mjs applies to its channel.lock: create
// exclusively; reclaim only a lock whose recorded PID is demonstrably gone; fail closed on a
// malformed or foreign lock. A lock naming this very process is stale (#217): PIDs restart in a new
// container, so "that PID is alive" can be only this process looking at itself.
//
// `program` goes one step further for a lock that only ever one program holds, in one container:
// where /proc shows what the recorded PID runs, a PID running anything but that program for this
// instance is a stranger that inherited the number, and the lock is stale. The feed lock outlives
// an adapter container, and its PID can name a live, unrelated process in the next one.

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

export function claimPidLock(path, instance, holder, { program = '', procRoot = '/proc' } = {}) {
  try {
    const fd = openSync(path, 'wx', 0o600)
    writeFileSync(fd, JSON.stringify({ version: 1, instance, pid: process.pid, started_at: Date.now() }))
    closeSync(fd)
    return () => { try { if (JSON.parse(readFileSync(path, 'utf8')).pid === process.pid) unlinkSync(path) } catch {} }
  } catch (error) { if (error.code !== 'EEXIST') throw error }
  let prior
  try {
    const stat = lstatSync(path)
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('lock is not a regular file')
    prior = JSON.parse(readFileSync(path, 'utf8'))
  } catch (error) { throw new Error(`cannot validate existing ${holder} lock: ${error.message}`) }
  if (prior?.version !== 1 || prior?.instance !== instance || !Number.isInteger(prior?.pid) || prior.pid < 1) throw new Error(`${holder} lock does not bind this instance`)
  if (prior.pid !== process.pid) try { process.kill(prior.pid, 0); if (mayHold(prior.pid, instance, program, procRoot)) throw new Error(`${holder} already runs as pid ${prior.pid}`) }
  catch (error) { if (error.code !== 'ESRCH' && !(error.code === 'EPERM' && !mayHold(prior.pid, instance, program, procRoot))) throw error }
  unlinkSync(path)
  return claimPidLock(path, instance, holder, { program, procRoot })
}
