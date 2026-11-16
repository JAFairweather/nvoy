// lease_beat_worker.mjs — the lease lock's heartbeat, on its OWN thread (nvoy#364).
//
// The daemon makes blocking calls (spawnSync with a 90 s timeout) on its main thread, which stops that
// thread's event loop and every timer on it. A heartbeat on the main loop would lapse during any child
// that runs past the lease, and another container would then take the lock while this one is still
// working. This thread has its own loop, so the beat continues while the main thread is blocked, and it
// ends the process itself when the lock is lost: a blocked main thread cannot run onLost.
//
// Failure here must stop the holder, not leave it running without a lease: any uncaught error in this
// thread kills the whole process.
import { parentPort, workerData } from 'node:worker_threads'
import { readdirSync, readFileSync, utimesSync } from 'node:fs'
import { basename, dirname } from 'node:path'

const { path, file, gen, token, beatMs, killOnLost, ready } = workerData
const die = () => { try { process.kill(process.pid, 'SIGKILL') } catch {} }
process.on('uncaughtException', die)
process.on('unhandledRejection', die)

const highest = () => {
  const dir = dirname(path), prefix = `${basename(path)}.`
  return readdirSync(dir).filter(n => n.startsWith(prefix) && /^\d+$/.test(n.slice(prefix.length)))
    .map(n => Number(n.slice(prefix.length))).reduce((a, b) => Math.max(a, b), 0)
}
let lost = false
const tick = () => {
  if (lost) return
  let mine = false
  try { mine = JSON.parse(readFileSync(file, 'utf8')).token === token && highest() === gen } catch { mine = false }
  if (!mine) {
    lost = true
    parentPort.postMessage({ lost: true })
    if (killOnLost) {
      // A default SIGTERM ends the whole process even while its main thread is inside spawnSync; if
      // something has handled it, SIGKILL follows.
      try { process.kill(process.pid, 'SIGTERM') } catch {}
      setTimeout(die, 3000)
    }
    return
  }
  try { const t = new Date(); utimesSync(file, t, t) } catch { /* a missed beat is retried; a lapsed lease is what the others see */ }
}
tick()                                              // the first beat, then tell the parent it may proceed
Atomics.store(ready, 0, lost ? 2 : 1); Atomics.notify(ready, 0)
const timer = setInterval(tick, beatMs)
parentPort.on('message', message => { if (message === 'stop') { clearInterval(timer); parentPort.close() } })
