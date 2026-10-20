#!/usr/bin/env node
// buzz-wake-watcher.mjs — keyless native ears on a Buzz community relay (salvage plan 2.3).
//
// The Buzz relay reads nothing to a connection that has not logged in as a member, so this
// watcher logs in as the agent, but it holds no key: the one signature it needs per connection
// comes from the broker's AUTH oracle, which will sign a fresh relay login and nothing else.
// It subscribes to the configured channels for messages that tag this identity, and for each one
// that nativeMention accepts it leaves an opaque `<event>.buzz.pending` marker. The marker is a
// hint only; the keyed broker re-fetches the event and decides, on the author's live grant,
// whether it is a task.

import { appendFileSync, chmodSync, chownSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { authOracleSigner, nativeMention, normalizeBuzzRelay, openBuzzSession, validChannel } from './buzz_native.mjs'
import { loginBackoff, singleFlight } from './login_backoff.mjs'

const arg = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const die = msg => { console.error(`buzz-wake: ${msg}`); process.exit(1) }
const HEX64 = /^[0-9a-f]{64}$/
const me = arg('--recipient').toLowerCase()
let relay
try { relay = normalizeBuzzRelay(arg('--relay')) } catch (e) { die(e.message) }
const channels = arg('--channels').split(',').filter(Boolean)
const authSocket = arg('--auth-socket')
const markerDir = arg('--marker-dir')
const markerGid = Number(arg('--marker-gid'))
const seenPath = arg('--seen-path') || resolve(markerDir, 'buzz-wake-seen.log')
const sincePath = arg('--since-path') || resolve(markerDir, 'buzz-wake-since')
if (!HEX64.test(me) || !channels.length || !channels.every(validChannel) || !authSocket || !markerDir || !Number.isInteger(markerGid) || markerGid < 0)
  die('usage: --recipient <hex> --relay <wss://…> --channels <uuid,…> --auth-socket <path> --marker-dir <dir> --marker-gid <gid>')

const interval = (name, fallback) => { const v = Number(process.env[name]); return Number.isFinite(v) && v >= 100 ? v : fallback }
const PING_MS = interval('WAKE_PING_MS', 30_000)
const REFRESH_MS = interval('WAKE_REFRESH_MS', 20 * 60 * 1000)
const RETRY_MAX_MS = interval('WAKE_RETRY_MAX_MS', 5 * 60 * 1000)
const STABLE_MS = interval('WAKE_STABLE_MS', 2 * 60 * 1000)
// A refreshed subscription that has not reached EOSE by then is treated as a dead session.
const EOSE_MS = interval('WAKE_EOSE_MS', 30_000)
// Replay overlap on reconnect. Buzz stamps created_at from the author's clock, so a message can
// land a little "in the past"; the seen log makes the overlap free.
const OVERLAP_S = 600

const SEEN_CAP = 100_000, SEEN_RETAIN = 90_000
const seen = new Set()
try { for (const line of readFileSync(seenPath, 'utf8').split('\n')) if (HEX64.test(line)) seen.add(line) } catch { /* first run */ }
// The watermark is the last moment this watcher was known to be caught up, so a restart after an
// outage replays exactly the gap. It starts at "now" on a first run — native ears begin hearing
// when they are switched on, and never turn a channel's history into a burst of tasks — and that
// first "now" is persisted at once, or a watcher that died before its first EOSE would restart
// from a later "now" and lose whatever arrived in between.
const caughtUp = () => {
  since = Math.floor(Date.now() / 1000)
  try { writeFileSync(sincePath, `${since}\n`) } catch (e) { console.error(`buzz-wake: watermark write failed: ${e.message}`) }
}
let since = 0
try { const v = Number(readFileSync(sincePath, 'utf8').trim()); if (Number.isSafeInteger(v) && v > 0) since = v } catch { /* first run */ }
if (!since) caughtUp()

// The marker is written BEFORE the seen log, so an I/O failure retries the event instead of
// suppressing it; `wx` makes a replay of an already-marked event a no-op.
function record(ev) {
  if (seen.has(ev.id)) return
  const mention = nativeMention(ev, { me, channels })
  if (!mention) return
  try {
    mkdirSync(markerDir, { recursive: true, mode: 0o770 })
    const p = resolve(markerDir, `${ev.id}.buzz.pending`)
    writeFileSync(p, JSON.stringify({ observed_at: Date.now(), envelope: ev.id }) + '\n', { flag: 'wx', mode: 0o660 })
    chownSync(p, -1, markerGid); chmodSync(p, 0o660)
  } catch (e) { if (e.code !== 'EEXIST') return console.error(`buzz-wake: marker write failed: ${e.message}`) }
  seen.add(ev.id)
  try { mkdirSync(dirname(seenPath), { recursive: true }); appendFileSync(seenPath, ev.id + '\n') } catch (e) { console.error(`buzz-wake: seen write failed: ${e.message}`) }
  if (seen.size > SEEN_CAP) { const keep = [...seen].slice(-SEEN_RETAIN); seen.clear(); keep.forEach(x => seen.add(x)); try { writeFileSync(seenPath, keep.join('\n') + '\n') } catch { /* next append retries */ } }
  console.log(`buzz-wake: mention ${ev.id.slice(0, 12)}… in ${mention.channel.slice(0, 8)} marked`)
}

const signer = authOracleSigner({ socketPath: authSocket, pubkey: me })
const backoff = loginBackoff({ maxMs: RETRY_MAX_MS, stableMs: STABLE_MS })
const login = singleFlight(() => openBuzzSession({ relay, signer, pingMs: PING_MS }))
async function run() {
  let session
  try { session = await login() }
  catch (e) {
    const delay = backoff.next()
    console.error(`buzz-wake: ${relay} login failed (${e.message}) — retrying in ${delay}ms`)
    return void setTimeout(run, delay)
  }
  const openedAt = Date.now()
  let heartbeat = null, eoseTimer = null, unsubscribe = null
  // The subscription is refreshed in place on the logged-in socket, so a relay that answers pings
  // while serving nothing cannot keep us subscribed to nothing — and a refresh costs no login.
  const subscribe = () => {
    unsubscribe?.()
    clearTimeout(eoseTimer)
    eoseTimer = setTimeout(() => { console.error(`buzz-wake: ${relay} subscription reached no EOSE`); session.close() }, EOSE_MS)
    unsubscribe = session.subscribe([{ kinds: [9], '#h': channels, '#p': [me], since: Math.max(0, since - OVERLAP_S) }], {
      onEvent: ev => { try { record(ev) } catch (e) { console.error(`buzz-wake: event skipped: ${e.message}`) } },
      onEose: () => {
        clearTimeout(eoseTimer); caughtUp()
        heartbeat ??= setInterval(caughtUp, 60_000)
        console.log(`buzz-wake: listening on ${channels.length} channel(s) as ${me.slice(0, 12)}…`) },
      onClosed: reason => { console.error(`buzz-wake: subscription closed by relay: ${reason || 'no reason'}`); session.close() },
    })
  }
  try { subscribe() } catch (e) { console.error(`buzz-wake: subscribe failed: ${e.message}`); session.close() }
  const refresh = setInterval(() => {
    console.log(`buzz-wake: ${relay} refreshing subscription on the same login`)
    try { subscribe() } catch (e) { console.error(`buzz-wake: resubscribe failed: ${e.message}`); session.close() }
  }, REFRESH_MS)
  const reason = await session.closed
  clearInterval(refresh); clearInterval(heartbeat); clearTimeout(eoseTimer)
  backoff.sessionEnded(Date.now() - openedAt)
  const delay = backoff.next()
  console.error(`buzz-wake: ${relay} ${reason} — reconnecting in ${delay}ms`)
  setTimeout(run, delay)
}
run()
