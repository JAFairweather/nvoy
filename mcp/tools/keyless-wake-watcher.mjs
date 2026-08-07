#!/usr/bin/env node
// keyless-wake-watcher.mjs — watch the cleartext outer p-tag of NIP-59 mail.
//
// This process deliberately has NO nsec. It can say only that an envelope for one
// public key reached a relay; it cannot decrypt it, identify its sender, or turn its
// contents into a prompt. The keyed agent runtime must run attention.mjs to decrypt
// and apply the live task-grant gate before presenting anything to an agent.
//
//   WAKE_RECIPIENT=npub1... node tools/keyless-wake-watcher.mjs [--dry-run]
//
// The optional WAKE_COMMAND is an owner-installed fixed command. It is invoked with
// an empty environment addition and no message-derived argv/stdin. A command that
// needs text, a sender, or a secret does not belong here.

import WebSocket from 'ws'
import { appendFileSync, mkdirSync, readFileSync, writeFileSync, chownSync, chmodSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { homedir } from 'node:os'
import { decode } from 'nostr-tools/nip19'
import { spawn } from 'node:child_process'

const arg = (name, fallback = '') => { const i = process.argv.indexOf(name); return i < 0 ? fallback : process.argv[i + 1] }
const die = msg => { console.error(`keyless-wake: ${msg}`); process.exit(1) }
const rawRecipient = arg('--recipient', process.env.WAKE_RECIPIENT || '')
const recipient = rawRecipient.startsWith('npub1') ? decode(rawRecipient).data : rawRecipient.toLowerCase()
if (!/^[0-9a-f]{64}$/.test(recipient)) die('set WAKE_RECIPIENT (npub or 64-hex public key)')
if (process.env.NVOY_NSEC) die('refusing to start while NVOY_NSEC is set — this watcher must stay keyless')

const relays = (process.env.NVOY_RELAYS?.split(',') || ['wss://nos.lol', 'wss://relay.primal.net', 'wss://relay.ditto.pub'])
  .map(x => x.trim()).filter(Boolean)
const DRY = process.argv.includes('--dry-run')
const cooldown = Number(arg('--cooldown', '90')) * 1000
const baselineExisting = process.argv.includes('--baseline-existing')
const exitAfterBaseline = process.argv.includes('--exit-after-baseline')
const statePath = arg('--seen-path', resolve(homedir(), '.nvoy', 'keyless-wake-seen.log'))
const queuePath = arg('--queue-path', resolve(homedir(), '.nvoy', 'keyless-wake-queue.jsonl'))
const markerDir = arg('--marker-dir', '')
const markerGid = Number(arg('--marker-gid', ''))
if (markerDir && (!Number.isInteger(markerGid) || markerGid < 0)) die('--marker-dir requires a non-negative --marker-gid')
const command = process.env.WAKE_COMMAND || ''
// NIP-59 envelopes are backdated, so a time watermark cannot replace exact IDs. Keep a bounded
// 48-hour replay set large enough for hostile-but-plausible traffic and fail a first baseline
// closed rather than silently truncating it into later false wakes.
const SEEN_CAP = 100_000
const SEEN_RETAIN = 90_000
const seen = new Set()
try { for (const line of readFileSync(statePath, 'utf8').split('\n')) if (/^[0-9a-f]{64}$/.test(line)) seen.add(line) } catch { /* first run */ }
const mark = id => {
  if (seen.has(id)) return false
  seen.add(id)
  try { mkdirSync(dirname(statePath), { recursive: true }); appendFileSync(statePath, id + '\n') } catch (e) { console.error(`keyless-wake: seen write failed: ${e.message}`); return false }
  if (seen.size > SEEN_CAP) { const keep = [...seen].slice(-SEEN_RETAIN); seen.clear(); keep.forEach(x => seen.add(x)); try { writeFileSync(statePath, keep.join('\n') + '\n') } catch {} }
  return true
}
let lastWake = 0
const baselineRelays = baselineExisting ? new Set(relays) : null
let baselined = 0
const baselineTimer = baselineExisting
  ? setTimeout(() => die(`baseline timed out waiting for EOSE from ${[...baselineRelays].join(', ')}`), 30_000)
  : null
baselineTimer?.unref()
function baseline(id) {
  if (seen.has(id)) return
  if (seen.size >= SEEN_CAP) die(`baseline exceeds the ${SEEN_CAP}-envelope safety bound; no live delivery was enabled`)
  if (mark(id)) baselined++
}
function finishBaseline(url) {
  if (!baselineRelays?.delete(url) || baselineRelays.size) return
  clearTimeout(baselineTimer)
  console.log(`keyless-wake: baseline complete — ${baselined} existing envelope(s) archived; live delivery begins now`)
  if (exitAfterBaseline) setTimeout(() => process.exit(0), 25)
}
function record(id) {
  const now = Date.now()
  // Milliseconds are intentional. A cold relay catch-up can deliver hundreds of historical
  // wraps in the same second; the broker uses this opaque observation timestamp to put a
  // genuinely new arrival ahead of that backlog without inspecting a sender or plaintext.
  const marker = { observed_at: now, envelope: id }
  // The per-envelope marker is the authoritative watcher→broker handoff. It is written BEFORE
  // the seen log, so an I/O failure causes the relay event to be retried rather than suppressed.
  if (markerDir) {
    try { mkdirSync(markerDir, { recursive: true, mode: 0o770 }); chownSync(markerDir, -1, markerGid); chmodSync(markerDir, 0o770); const p = resolve(markerDir, `${id}.pending`); writeFileSync(p, JSON.stringify(marker) + '\n', { flag: 'wx', mode: 0o660 }); chownSync(p, -1, markerGid); chmodSync(p, 0o660) }
    catch (e) { if (e.code !== 'EEXIST') { console.error(`keyless-wake: marker write failed: ${e.message}`); return false } }
  }
  try { mkdirSync(dirname(queuePath), { recursive: true }); appendFileSync(queuePath, JSON.stringify(marker) + '\n') }
  catch (e) { if (!markerDir) { console.error(`keyless-wake: queue write failed: ${e.message}`); return false } }
  console.log(`keyless-wake: envelope ${id.slice(0, 12)}… recorded — keyed runtime must run attention.mjs`)
  // Every observed envelope is durable. Cooldown applies only to the optional *notification*;
  // applying it to queueing loses authorised arrivals forever once the seen log has advanced.
  if (now - lastWake < cooldown) return true
  lastWake = now
  if (!command || DRY) return true
  // The fixed command receives no arrival data. Its own runtime owns its signer and chooses
  // whether to read the queue, then attention.mjs makes the authorisation decision.
  const child = spawn(command, [], { shell: true, stdio: 'ignore', detached: true })
  child.unref()
  return true
}
// A subscription can die while its TCP socket stays ESTABLISHED: the host sleeps, the relay
// drops the REQ, a middlebox half-opens the connection — no close, no error, just silence.
// From the outside that is indistinguishable from a quiet channel, and it has already cost this
// watcher live wake envelopes. So liveness is proven rather than assumed: ping on an interval
// and terminate a socket that stops answering, and recycle every connection periodically, so a
// relay that answers pings while serving nothing cannot keep us subscribed to nothing. Replay
// after a refresh is bounded by the `#p` filter and deduplicated by `seen`, so it cannot
// manufacture a second wake for an envelope already recorded.
// Overridable so the reconnect behaviour can be exercised in seconds by a test rather than
// asserted by reading the source; neither value carries authority over what is delivered.
const interval = (name, fallback) => { const v = Number(process.env[name]); return Number.isFinite(v) && v >= 100 ? v : fallback }
const PING_MS = interval('WAKE_PING_MS', 30_000)
const REFRESH_MS = interval('WAKE_REFRESH_MS', 20 * 60 * 1000)
function connect(url) {
  const relay = url.replace(/^wss?:\/\//, '')
  const open = () => {
    let ws, alive = true, retired = false, planned = false
    const timers = []
    // 'close' follows 'error', and a terminate() scheduled here lands there too, so the
    // reconnect must be single-shot or every fault doubles the number of live sockets.
    // A planned refresh reconnects at once: backing off would leave the watcher deaf for ten
    // seconds every refresh, which is the very failure this recycle exists to prevent.
    const reopen = reason => {
      if (retired) return
      retired = true
      timers.forEach(clearInterval)
      const delay = planned ? 250 : 10_000
      console.error(`keyless-wake: ${relay} ${reason} — reconnecting in ${delay}ms`)
      setTimeout(open, delay)
    }
    try { ws = new WebSocket(url) } catch (e) { return reopen(`could not be opened (${e.message})`) }
    ws.on('open', () => {
      ws.send(JSON.stringify(['REQ', 'wake', { kinds: [1059], '#p': [recipient], since: Math.floor(Date.now() / 1000) - 172920 } ]))
      timers.push(setInterval(() => {
        if (!alive) return ws.terminate()   // the previous ping went unanswered
        alive = false
        try { ws.ping() } catch { ws.terminate() }
      }, PING_MS))
      // Baselining is a one-shot pass that exits on EOSE; recycling it would re-arm its timeout.
      if (!baselineRelays) timers.push(setInterval(() => { console.log(`keyless-wake: ${relay} refreshing subscription`); planned = true; ws.terminate() }, REFRESH_MS))
    })
    ws.on('pong', () => { alive = true })
    ws.on('message', data => {
      alive = true
      try {
        const m = JSON.parse(data.toString())
        if (m[0] === 'EOSE') return finishBaseline(url)
        if (m[0] !== 'EVENT' || !m[2]?.id || seen.has(m[2].id)) return
        if (baselineRelays?.has(url)) baseline(m[2].id)
        else if (record(m[2].id)) mark(m[2].id)
      } catch {}
    })
    ws.on('close', () => reopen('closed'))
    ws.on('error', e => console.error(`keyless-wake: ${relay} socket error: ${e.message}`))
  }
  open()
}
for (const relay of relays) connect(relay)
console.log(`keyless-wake: watching ${relays.length} relay(s) for ${recipient.slice(0, 12)}…${baselineExisting ? ' (baselining existing wraps)' : DRY ? ' (dry-run)' : ''}`)
