// The watcher's whole job is to notice. It failed at exactly that: sockets stayed ESTABLISHED
// while the subscriptions behind them served nothing, and live wake envelopes were lost with no
// error anywhere — the process looked healthy and the log was silent. A source-level assertion
// that a ping timer exists would not have caught it, so this drives the real binary against a
// stub relay and asserts the property: after the connection is recycled, a NEW envelope still
// reaches the marker spool.
//
// Both directions are asserted, because a watcher that re-records everything on every refresh
// and one that records nothing are equally broken: an envelope already seen must NOT produce a
// second marker when the relay replays it on the fresh connection.
import { WebSocketServer } from 'ws'
import { mkdtempSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawn } from 'node:child_process'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const sleep = ms => new Promise(r => setTimeout(r, ms))

const root = mkdtempSync(join(tmpdir(), 'nvoy-wake-'))
const markerDir = join(root, 'spool')
const recipient = 'a'.repeat(64)
const ENVELOPE_A = '1'.repeat(64)
const ENVELOPE_B = '2'.repeat(64)

// A stub relay that answers REQ with EOSE and lets the test push events on demand. It counts
// connections, which is how "the watcher gave up on a dead subscription" is observed.
const sockets = []
const server = new WebSocketServer({ host: '127.0.0.1', port: 0 })
server.on('connection', ws => {
  sockets.push(ws)
  ws.on('message', raw => {
    let m; try { m = JSON.parse(raw.toString()) } catch { return }
    if (m[0] === 'REQ') ws.send(JSON.stringify(['EOSE', m[1]]))
  })
})
await new Promise(r => server.on('listening', r))
const url = `ws://127.0.0.1:${server.address().port}`

// Never throw on a missing connection: a watcher that failed to reconnect must report every
// remaining assertion as failed, not abort the run and leave the rest unreported.
const emit = (index, id) => sockets[index]?.send(JSON.stringify(['EVENT', 'wake', {
  id, kind: 1059, pubkey: 'b'.repeat(64), created_at: 1, tags: [['p', recipient]], content: 'x', sig: 'c'.repeat(128) }]))

const markers = () => { try { return readdirSync(markerDir).filter(n => n.endsWith('.pending')) } catch { return [] } }
const waitFor = async (predicate, ms = 8000) => {
  for (let waited = 0; waited < ms; waited += 100) { if (predicate()) return true; await sleep(100) }
  return false
}

const watcher = spawn(process.execPath, [
  resolve('mcp/tools/keyless-wake-watcher.mjs'),
  '--recipient', recipient,
  '--marker-dir', markerDir, '--marker-gid', String(process.getgid()),
  '--seen-path', join(root, 'seen.log'), '--queue-path', join(root, 'queue.jsonl'),
], { env: { ...process.env, NVOY_NSEC: '', NVOY_RELAYS: url, WAKE_PING_MS: '400', WAKE_REFRESH_MS: '1500' },
     stdio: ['ignore', 'pipe', 'pipe'] })
let log = ''
watcher.stdout.on('data', d => { log += d })
watcher.stderr.on('data', d => { log += d })

try {
  ok('the watcher subscribes to the relay', await waitFor(() => sockets.length >= 1))

  emit(0, ENVELOPE_A)
  ok('an envelope on the first connection is recorded', await waitFor(() => markers().includes(`${ENVELOPE_A}.pending`)))

  // The failure this suite exists for: the first connection is now stale. A watcher that trusts
  // an ESTABLISHED socket never opens a second one, and every later envelope is lost in silence.
  ok('a stale subscription is replaced rather than trusted', await waitFor(() => sockets.length >= 2))
  ok('the replacement is announced rather than silent', /refreshing subscription|closed/.test(log))

  emit(1, ENVELOPE_B)
  ok('an envelope arriving after the refresh still reaches the spool',
    await waitFor(() => markers().includes(`${ENVELOPE_B}.pending`)))

  // The mirror. Relays replay their window on every fresh REQ, so without dedup across
  // reconnects the refresh above would re-wake the agent for mail it has already handled.
  emit(1, ENVELOPE_A)
  await sleep(600)
  ok('a replayed envelope does not produce a second marker', markers().length === 2)
} finally {
  watcher.kill('SIGKILL')
  server.close()
  for (const ws of sockets) ws.terminate()
}

console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
