// lease_beat_worker.mjs — the lease lock's heartbeat, on its OWN thread (nvoy#364).
//
// The daemon makes blocking calls (spawnSync with a 90 s timeout) on its main thread, which stops that
// thread's event loop and every timer on it. A heartbeat on the main loop would lapse during any child
// that runs past the lease, and another container would then take the lock while this one is still
// working. This thread has its own loop, so the beat continues while the main thread is blocked, and it
// can end the process itself if the lock is found taken: a blocked main thread cannot run onLost.
import { parentPort, workerData } from 'node:worker_threads'
import { readFileSync, utimesSync } from 'node:fs'

const { path, token, beatMs, killOnLost } = workerData
let lost = false
const tick = () => {
  if (lost) return
  let mine = false
  try { mine = JSON.parse(readFileSync(path, 'utf8')).token === token } catch { mine = false }
  if (!mine) {
    lost = true
    parentPort.postMessage({ lost: true })
    if (killOnLost) {
      // A default SIGTERM ends the whole process even while its main thread is inside spawnSync; if
      // something has handled it, SIGKILL follows.
      try { process.kill(process.pid, 'SIGTERM') } catch {}
      setTimeout(() => { try { process.kill(process.pid, 'SIGKILL') } catch {} }, 3000)
    }
    return
  }
  try { const t = new Date(); utimesSync(path, t, t) } catch { /* a missed beat is retried; a lapsed lease is what the others see */ }
}
const timer = setInterval(tick, beatMs)
parentPort.on('message', message => { if (message === 'stop') { clearInterval(timer); parentPort.close() } })
