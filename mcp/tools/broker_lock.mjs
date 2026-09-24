// One broker owns one state root at a time. A stale lock is reclaimable only if its recorded PID
// is demonstrably gone; a malformed or foreign lock fails closed rather than guessing. Shared by
// every keyed deliver path (wrapped and native), so they serialize on the same file.

import { readFileSync, lstatSync, mkdirSync, openSync, writeFileSync, closeSync, unlinkSync } from 'node:fs'
import { resolve } from 'node:path'

export function claimBrokerLock(manifest, die) {
  mkdirSync(manifest.stateDir, { recursive: true, mode: 0o700 })
  const lockPath = resolve(manifest.stateDir, 'broker.lock')
  const claim = () => {
    try {
      const fd = openSync(lockPath, 'wx', 0o600)
      writeFileSync(fd, JSON.stringify({ pid: process.pid, instance: manifest.id, started_at: Date.now() }))
      closeSync(fd)
      return
    } catch (e) {
      if (e.code !== 'EEXIST') die(`cannot claim broker lock: ${e.message}`)
    }
    let prior
    try {
      const st = lstatSync(lockPath)
      if (!st.isFile() || st.isSymbolicLink()) die('broker lock is not a regular file')
      prior = JSON.parse(readFileSync(lockPath, 'utf8'))
    } catch (e) { die(`cannot validate existing broker lock: ${e.message}`) }
    if (prior.instance !== manifest.id || !Number.isInteger(prior.pid) || prior.pid < 1) die('broker lock does not bind this instance')
    try { process.kill(prior.pid, 0); die(`broker already running as pid ${prior.pid}`) }
    catch (e) { if (e.code !== 'ESRCH') die(`cannot establish whether existing broker is alive: ${e.message}`) }
    try { unlinkSync(lockPath) } catch (e) { die(`cannot reclaim stale broker lock: ${e.message}`) }
    claim()
  }
  claim()
  process.on('exit', () => { try { unlinkSync(lockPath) } catch {} })
}
