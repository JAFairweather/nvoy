// The Buzz watcher's login pacing (status S0, fix 4). A login costs a Bunker signature, so a
// subscription refresh must not log in again, only one login may be in flight, and a relay that
// keeps dropping the socket must meet a growing, jittered delay rather than a reconnect a second.
import { WebSocketServer } from 'ws'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { existsSync, mkdirSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { loginBackoff, singleFlight } from '../mcp/tools/login_backoff.mjs'
import { serveAuthOracle } from '../mcp/tools/buzz_native.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const sleep = ms => new Promise(r => setTimeout(r, ms))
const until = async (fn, ms = 8000) => { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(50) } return false }

// --- the backoff ---
{
  const low = loginBackoff({ random: () => 0 }), high = loginBackoff({ random: () => 1 })
  const lows = Array.from({ length: 12 }, () => low.next()), highs = Array.from({ length: 12 }, () => high.next())
  ok('the first retry waits between half the base and the base', lows[0] === 500 && highs[0] === 1000)
  ok('each failure doubles the delay', lows[1] === 1000 && lows[2] === 2000 && highs[3] === 8000)
  ok('the delay is capped at five minutes', Math.max(...highs) === 300000 && highs.at(-1) === 300000 && lows.at(-1) === 150000)
  const b = loginBackoff({ random: () => 1, stableMs: 1000 })
  b.next(); b.next(); b.next()
  b.sessionEnded(999)
  ok('a session that dropped quickly does not reset the backoff', b.next() === 8000)
  b.sessionEnded(1000)
  ok('a session that stayed up resets it', b.next() === 1000)
  const jittered = new Set(Array.from({ length: 50 }, () => loginBackoff().next()))
  ok('the delay is jittered, so watchers do not reconnect in lockstep', jittered.size > 10 && [...jittered].every(d => d >= 500 && d <= 1000))
}

// --- single flight ---
{
  let calls = 0, release
  const login = singleFlight(() => { calls++; return new Promise(r => { release = r }) })
  const a = login(), b = login()
  await sleep(0)
  ok('a second login while one is in flight shares it', a === b && calls === 1)
  release('session'); ok('both callers get the one session', (await a) === 'session' && (await b) === 'session')
  login(); await sleep(0)
  ok('a settled login does not block the next one', calls === 2)
  release('again')
  const failing = singleFlight(() => { calls++; throw new Error('refused') })
  const errs = await Promise.allSettled([failing(), failing()])
  ok('a failed login is shared too, and then cleared', errs.every(e => e.status === 'rejected') && calls === 3)
  await failing().catch(() => {})
  ok('after a failure the next call tries again', calls === 4)
}

// --- the watcher, against a Buzz-shaped relay that counts logins ---
const CH = '3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607'
const agentSk = generateSecretKey(), agent = getPublicKey(agentSk)
const humanSk = generateSecretKey()
const stats = { auths: 0, reqs: 0, closes: 0 }
let dropAfterEose = false
const live = new Set()
const http = createServer((req, res) => { res.writeHead(404); res.end() })
await new Promise(r => http.listen(0, '127.0.0.1', r))
const RELAY = `ws://127.0.0.1:${http.address().port}`
const wss = new WebSocketServer({ server: http })
wss.on('connection', ws => {
  const challenge = Buffer.from(generateSecretKey()).toString('hex'), subs = new Map()
  let authed = false
  ws.send(JSON.stringify(['AUTH', challenge]))
  const deliver = ev => { for (const [id, f] of subs) if (ev.tags.some(t => t[0] === 'p' && f['#p']?.includes(t[1]))) ws.send(JSON.stringify(['EVENT', id, ev])) }
  live.add(deliver); ws.on('close', () => live.delete(deliver))
  ws.on('message', raw => {
    const m = JSON.parse(raw.toString())
    if (m[0] === 'AUTH') {
      stats.auths++
      authed = verifyEvent(m[1]) && m[1].tags.some(t => t[0] === 'challenge' && t[1] === challenge)
      return ws.send(JSON.stringify(['OK', m[1].id, authed, '']))
    }
    if (m[0] === 'REQ') {
      if (!authed) return ws.send(JSON.stringify(['CLOSED', m[1], 'auth-required']))
      // Counted: the message subscription. Each refresh also re-reads the agent's own threads (#280).
      if (m[2]['#p']) stats.reqs++
      subs.set(m[1], m[2])
      ws.send(JSON.stringify(['EOSE', m[1]]))
      if (dropAfterEose) setTimeout(() => ws.terminate(), 50)
      return
    }
    if (m[0] === 'CLOSE') { if (subs.get(m[1])?.['#p']) stats.closes++; subs.delete(m[1]) }
  })
})

const root = mkdtempSync(join(tmpdir(), 'nvoy-watcher-login-'))
const spool = join(root, 'spool'); mkdirSync(spool)
const gid = process.getgid()
const oracleSock = join(spool, 'buzz-auth.sock')
const oracle = await serveAuthOracle({ socketPath: oracleSock, relay: RELAY, pubkey: agent, gid,
  signer: { getPublicKey: async () => agent, signEvent: async t => finalizeEvent(t, agentSk) } })
let log = ''
const startWatcher = env => {
  const child = spawn(process.execPath, ['mcp/tools/buzz-wake-watcher.mjs', '--recipient', agent, '--relay', RELAY, '--channels', CH,
    '--auth-socket', oracleSock, '--marker-dir', spool, '--marker-gid', String(gid)],
  { env: { PATH: process.env.PATH, WAKE_PING_MS: '200', ...env }, stdio: ['ignore', 'pipe', 'pipe'] })
  child.stdout.on('data', c => { log += c }); child.stderr.on('data', c => { log += c })
  return child
}

let watcher = startWatcher({ WAKE_REFRESH_MS: '300' })
ok('the watcher logs in and listens', await until(() => /listening on 1 channel/.test(log)))
ok('it refreshes its subscription several times', await until(() => stats.reqs >= 4))
ok('a refresh costs no login: one AUTH across every refresh', stats.auths === 1)
ok('each refresh closes the subscription it replaces', stats.closes >= stats.reqs - 2)
ok('the refresh says it stayed on the same login', /refreshing subscription on the same login/.test(log))
const mention = finalizeEvent({ kind: 9, created_at: Math.floor(Date.now() / 1000), content: 'still hearing?', tags: [['h', CH], ['p', agent]] }, humanSk)
for (const deliver of live) deliver(mention)
ok('a mention after several refreshes is still heard', await until(() => existsSync(join(spool, `${mention.id}.buzz.pending`))))
watcher.kill(); await sleep(100)

// A relay that accepts the login and then drops the socket: the old code reset its backoff on
// EOSE and reconnected every second, forever.
dropAfterEose = true; log = ''
const authsBefore = stats.auths
watcher = startWatcher({})
ok('a flapping relay is retried', await until(() => (log.match(/reconnecting in \d+ms/g) || []).length >= 3, 12000))
watcher.kill()
const delays = [...log.matchAll(/reconnecting in (\d+)ms/g)].map(m => Number(m[1]))
ok('the delay grows after each drop, from about a second', delays[0] >= 500 && delays[0] <= 1000 && delays[1] >= 1000 && delays[2] >= 2000)
ok('a flapping relay costs one login per reconnect, no more', stats.auths - authsBefore === delays.length + 1 || stats.auths - authsBefore === delays.length)

oracle.close(); wss.close(); http.close()
console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
