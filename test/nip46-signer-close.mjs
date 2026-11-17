// nip46-signer-close.mjs — close() leaves no relay socket behind, so a one-shot process exits (q-310).
//
// hive-memory-curator hung three times after a finished cycle ("cursor advanced", then never exited): the unit stayed
// "activating" until stopped by hand. nostr-tools' relay close() only closes a socket that is already OPEN. A socket that
// is still connecting when the signer closes (or one the pool gave up on after its 3 s connect timeout) is dropped from
// the pool, then opens later and stays open, holding the event loop for good. The curator's unit runs at CPUQuota=25%,
// where a slow TLS handshake is likely.
//
// Each case runs in a child with a stand-in WebSocket that opens late and, once open, holds the event loop like a real
// socket until it is closed. After the late open has had its chance, the child counts sockets still open: it must be 0.
// (The old signer left 1, and that child never exited; the pool's own publish and EOSE timers are bounded at 4.4 s.)

import assert from 'node:assert'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const signerUrl = new URL('../mcp/tools/nip46-signer.mjs', import.meta.url).href
const poolUrl = import.meta.resolve('nostr-tools/pool')
let n = 0, failed = 0
const check = (name, cond, detail = '') => { n++; console.log(`${cond ? 'PASS' : 'FAIL'}  ${String(n).padStart(2)}. ${name}${cond ? '' : ` ${detail}`}`); if (!cond) failed = 1 }

const child = (openAfterMs, closeAtMs) => `
const live = new Set()
class LateSocket {
  static CONNECTING = 0; static OPEN = 1; static CLOSING = 2; static CLOSED = 3
  constructor(url) {
    this.url = url; this.readyState = 0
    this.opening = setTimeout(() => {
      this.readyState = 1
      this.live = setInterval(() => {}, 1000)       // an open socket keeps the process alive, as a real one does
      live.add(this)
      this.onopen?.()
    }, ${openAfterMs})
  }
  send() {}
  close() {
    clearTimeout(this.opening); clearInterval(this.live); live.delete(this)
    if (this.readyState === 3) return
    this.readyState = 3
    setImmediate(() => this.onclose?.({ code: 1000 }))
  }
}
globalThis.WebSocket = LateSocket
const { makeBunkerSigner } = await import(${JSON.stringify(signerUrl)})
await import(${JSON.stringify(poolUrl)})
const uri = 'bunker://' + 'ab'.repeat(32) + '?relay=wss%3A%2F%2Frelay.example&secret=test'
const signer = makeBunkerSigner(uri, '11'.repeat(32), { idleMs: 5 })
signer.getPublicKey().catch(() => {})
setTimeout(() => { signer.close(); console.log('closed') }, ${closeAtMs})
setTimeout(() => { console.log('live=' + live.size); process.exit(0) }, ${Math.max(openAfterMs, closeAtMs) + 500})
`

function runs(name, openAfterMs, closeAtMs) {
  const t0 = Date.now()
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', child(openAfterMs, closeAtMs)],
    { encoding: 'utf8', timeout: 30000, cwd: fileURLToPath(new URL('..', import.meta.url)) })
  const took = Date.now() - t0
  check(name, r.status === 0 && /closed/.test(r.stdout) && /live=0/.test(r.stdout),
    `(status ${r.status}, ${took} ms, stdout ${JSON.stringify(r.stdout)}, stderr ${String(r.stderr).slice(0, 300)})`)
}

// A socket still connecting when close() is called: it must not open later and stay open.
runs('close() while the relay socket is connecting: no socket is left open', 300, 50)
// A socket the pool gave up on (its 3 s connect timeout) and then opened: the signer still closes it.
runs('close() after the pool timed out a slow connect: no socket is left open', 3500, 3200)
// Control: an already-open socket closes as before.
runs('close() with the relay socket open: no socket is left open', 10, 200)

assert.strictEqual(failed, 0, 'nip46 signer close left a socket open')
console.log(`nip46-signer-close: ${n} checks passed`)
