// buzz_native.mjs — speak to a Buzz community relay AS the agent's own key, with no carrier.
//
// The salvage plan's Phase 2: an external agent joins a Buzz community the way OpenClaw does —
// its pubkey is a relay member, it answers the relay's NIP-42 challenge as itself, and it posts
// kind:9 channel messages under its own name. The difference from OpenClaw is custody: the
// signer here is anything with { getPublicKey, signEvent }, which in the runtime is the NIP-46
// Bunker, so the key never sits beside the code that speaks.
//
// Wire facts this encodes (block/buzz main; see the PR for source lines):
//   - the relay sends ["AUTH", challenge] on connect and closes the socket if AUTH has not
//     succeeded within 5s, so a Bunker must be warm BEFORE connecting;
//   - one AUTH attempt per socket — a refusal is final, reconnect to retry;
//   - the 22242 relay tag is wss://<community host>, no path;
//   - every channel event and every REQ filter must carry #h, otherwise the relay treats the
//     subscription as community-wide and channel events never arrive — silently. We refuse such
//     a filter locally rather than wait for nothing.

import WebSocket from 'ws'
import net from 'node:net'
import { chmodSync, chownSync, unlinkSync } from 'node:fs'
import { verifyEvent } from 'nostr-tools/pure'

const HEX64 = /^[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]'])
export const CHANNEL_KINDS = Object.freeze([9, 40002])
// nostr-tools caches a passed verification on the event object under a symbol, and object spread
// copies it — so a tampered copy of a verified event would verify. Check a clean copy of the fields.
const verified = (ev, verify = verifyEvent) => {
  const { id, pubkey, created_at, kind, tags, content, sig } = ev || {}
  return verify({ id, pubkey, created_at, kind, tags, content, sig })
}
const tagValues = (ev, name) => (Array.isArray(ev?.tags) ? ev.tags : []).filter(t => t?.[0] === name).map(t => t[1])

// The origin Buzz compares the AUTH relay tag against. Plaintext ws:// is accepted only for a
// loopback test relay; anything reachable over a network must be wss://.
export function normalizeBuzzRelay(value) {
  let url
  try { url = new URL(String(value || '').trim()) } catch { throw new Error('Buzz relay must be a URL like wss://<community host>') }
  const secure = url.protocol === 'wss:', loopback = url.protocol === 'ws:' && LOOPBACK.has(url.hostname)
  if (!secure && !loopback) throw new Error('Buzz relay must be wss:// (ws:// only on loopback)')
  if ((url.pathname && url.pathname !== '/') || url.search || url.hash || url.username || url.password)
    throw new Error('Buzz relay is an origin only — no path, query or credentials')
  return `${url.protocol}//${url.host}`
}

export const validChannel = value => UUID.test(String(value || ''))

export const authTemplate = (relay, challenge, now = Math.floor(Date.now() / 1000)) =>
  ({ kind: 22242, created_at: now, content: '', tags: [['relay', normalizeBuzzRelay(relay)], ['challenge', String(challenge)]] })

// What a signing oracle may agree to sign on a keyless watcher's behalf: exactly a 22242 for
// this community relay, fresh, with no extra tags. Anything wider would let whoever can reach
// the oracle obtain a login for another relay, or smuggle an NIP-OA owner attestation.
export function checkAuthTemplate(ev, { relay, now = Math.floor(Date.now() / 1000) }) {
  const want = normalizeBuzzRelay(relay)
  if (!ev || typeof ev !== 'object' || Array.isArray(ev)) return 'not an event template'
  if (Object.keys(ev).some(k => !['kind', 'created_at', 'content', 'tags', 'pubkey'].includes(k))) return 'unexpected field'
  if (ev.kind !== 22242) return 'kind must be 22242'
  if (ev.content !== '') return 'content must be empty'
  if (!Number.isSafeInteger(ev.created_at) || Math.abs(ev.created_at - now) > 60) return 'created_at outside ±60s'
  if (!Array.isArray(ev.tags) || ev.tags.length !== 2) return 'tags must be exactly relay and challenge'
  const [relayTag, challengeTag] = ev.tags
  if (relayTag?.length !== 2 || relayTag[0] !== 'relay' || relayTag[1] !== want) return 'relay tag is not this community relay'
  if (challengeTag?.length !== 2 || challengeTag[0] !== 'challenge' || !/^[\x21-\x7e]{8,256}$/.test(String(challengeTag[1]))) return 'malformed challenge'
  return null
}

// A reply that threads the way Buzz clients do: root = the parent's root marker, else its reply
// marker, else the parent itself. The mention travels as a p tag — Buzz never resolves @text, so
// a reply without it reaches no one.
export function channelReply({ channel, parent, content, now = Math.floor(Date.now() / 1000) }) {
  if (!validChannel(channel)) throw new Error('channel must be a UUID')
  if (!parent || !HEX64.test(String(parent.id)) || !HEX64.test(String(parent.pubkey))) throw new Error('reply needs the verified parent event')
  if (typeof content !== 'string' || !content.trim()) throw new Error('empty reply')
  const marked = marker => (parent.tags || []).find(t => t?.[0] === 'e' && t[3] === marker && HEX64.test(String(t[1])))?.[1]
  const root = marked('root') || marked('reply') || parent.id
  const tags = [['h', channel]]
  if (root !== parent.id) tags.push(['e', root, '', 'root'])
  tags.push(['e', parent.id, '', 'reply'], ['p', parent.pubkey])
  return { kind: 9, created_at: now, content, tags }
}

// Is this a message addressed to `me` in one of `channels`? Returns the facts admission needs,
// or null. Desktop tags an off-channel mention ["mention", pk] instead of ["p", pk]; both count.
export function nativeMention(ev, { me, channels, now = Math.floor(Date.now() / 1000), verify = verifyEvent }) {
  if (!ev || !CHANNEL_KINDS.includes(ev.kind) || !HEX64.test(String(ev.pubkey)) || ev.pubkey === me) return null
  if (!Number.isSafeInteger(ev.created_at) || ev.created_at > now + 900) return null
  const h = tagValues(ev, 'h')
  if (h.length !== 1 || !channels.includes(h[0])) return null
  if (![...tagValues(ev, 'p'), ...tagValues(ev, 'mention')].includes(me)) return null
  if (!verified(ev, verify)) return null
  return { channel: h[0], author: ev.pubkey, event_id: ev.id, created_at: ev.created_at }
}

// One authenticated connection. `signer` is { getPublicKey(), signEvent(template) }; the pubkey
// is resolved BEFORE the socket opens, both to warm a Bunker inside the 5s window and so a
// signer that answers for a different key is caught before anything is sent. `pingMs` makes a
// long-lived session prove it is alive: a socket that stops answering pings is terminated, so a
// half-open connection surfaces as `closed` instead of as a quiet channel.
export async function openBuzzSession({ relay, signer, timeoutMs = 10000, pingMs = 0, WS = WebSocket }) {
  const url = normalizeBuzzRelay(relay)
  const me = String(await signer.getPublicKey()).toLowerCase()
  if (!HEX64.test(me)) throw new Error('signer returned no usable pubkey')
  const ws = new WS(url)
  const waiters = new Map(), subs = new Map(), live = new Map()
  let challenge, onChallenge, closedWith, pinger, resolveClosed
  const closed = new Promise(resolve => { resolveClosed = resolve })
  const fail = reason => {
    closedWith ??= reason
    clearInterval(pinger)
    for (const w of waiters.values()) w.reject(new Error(closedWith))
    for (const s of subs.values()) s.reject(new Error(closedWith))
    waiters.clear(); subs.clear(); live.clear(); onChallenge?.reject(new Error(closedWith))
    resolveClosed(closedWith)
  }
  ws.on('message', raw => {
    let m; try { m = JSON.parse(raw.toString()) } catch { return }
    if (m[0] === 'AUTH' && typeof m[1] === 'string') { challenge = m[1]; onChallenge?.resolve(m[1]) }
    else if (m[0] === 'OK') { const w = waiters.get(m[1]); if (w) { waiters.delete(m[1]); w.resolve({ accepted: m[2] === true, message: String(m[3] || '') }) } }
    else if (m[0] === 'EVENT') { const l = live.get(m[1]); if (l) l.onEvent(m[2]); else subs.get(m[1])?.events.push(m[2]) }
    else if (m[0] === 'EOSE') { const l = live.get(m[1]); if (l) l.onEose?.(); else { const s = subs.get(m[1]); if (s) { subs.delete(m[1]); s.resolve(s.events) } } }
    else if (m[0] === 'CLOSED') {
      const l = live.get(m[1])
      if (l) { live.delete(m[1]); l.onClosed?.(String(m[2] || '')) }
      else { const s = subs.get(m[1]); if (s) { subs.delete(m[1]); s.reject(new Error(`subscription closed: ${m[2] || ''}`)) } }
    }
  })
  ws.on('close', () => fail('relay closed the connection'))
  ws.on('error', e => fail(`relay connection error: ${e.message}`))
  const bounded = (promise, what) => {
    let timer
    return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${what} timed out`)), timeoutMs) })])
      .finally(() => clearTimeout(timer))
  }
  const send = frame => { if (closedWith) throw new Error(closedWith); ws.send(JSON.stringify(frame)) }
  // Send, THEN arm the wait: a reply can only arrive on a later tick, and arming first would leave
  // a timer behind when send throws on a closed socket — one that later rejects with no one listening.
  const sendAndAwaitOk = (frame, id) => { send(frame); return bounded(new Promise((resolve, reject) => waiters.set(id, { resolve, reject })), 'relay OK') }
  const close = () => { closedWith ??= 'session closed'; try { ws.close() } catch { /* already gone */ } }
  const needsChannels = filters => !filters.length || filters.some(f => !Array.isArray(f?.['#h']) || !f['#h'].length || !f['#h'].every(validChannel))

  try {
    const c = challenge ?? await bounded(new Promise((resolve, reject) => { onChallenge = { resolve, reject } }), 'AUTH challenge')
    const auth = await signer.signEvent(authTemplate(url, c))
    if (auth?.pubkey !== me || auth.kind !== 22242 || !verified(auth)) throw new Error('signer returned an AUTH event that is not ours')
    const verdict = await sendAndAwaitOk(['AUTH', auth], auth.id)
    if (!verdict.accepted) throw new Error(`AUTH refused: ${verdict.message || '(no reason)'}`)
  } catch (error) { close(); throw error }

  if (pingMs > 0) {
    let alive = true
    ws.on('pong', () => { alive = true })
    pinger = setInterval(() => {
      if (!alive) return ws.terminate()
      alive = false
      try { ws.ping() } catch { ws.terminate() }
    }, pingMs)
  }

  let n = 0
  // Publish an event that is already signed. The caller persists it first, so a retry resends the
  // same id instead of authoring a second message; resolves only on the relay's OK.
  const publishSigned = async ev => {
    if (ev?.pubkey !== me || !verified(ev)) throw new Error('refusing to publish an event that is not ours')
    if (CHANNEL_KINDS.includes(ev.kind) && tagValues(ev, 'h').length !== 1) throw new Error('channel event needs exactly one h tag')
    return { event: ev, ...(await sendAndAwaitOk(['EVENT', ev], ev.id)) }
  }
  return Object.freeze({
    pubkey: me, relay: url, close, closed,
    publishSigned,
    // Sign and publish; resolves only on the relay's OK, and reports its refusal verbatim.
    async publish(template) { return publishSigned(await signer.signEvent(template)) },
    // Stored events up to EOSE. Every filter must name its channels, or Buzz answers with nothing.
    async fetch(...filters) {
      if (needsChannels(filters)) throw new Error('every Buzz filter needs #h channel UUIDs — without it the relay returns nothing')
      const id = `q${++n}`
      send(['REQ', id, ...filters])
      const pending = bounded(new Promise((resolve, reject) => subs.set(id, { events: [], resolve, reject })), 'REQ')
      try { return await pending } finally { if (!closedWith) try { send(['CLOSE', id]) } catch { /* closing anyway */ } }
    },
    // A subscription that stays open past EOSE. Events arrive unverified: the caller decides what
    // an event means (nativeMention verifies it) — this only routes frames.
    subscribe(filters, { onEvent, onEose, onClosed }) {
      if (needsChannels(filters)) throw new Error('every Buzz filter needs #h channel UUIDs — without it the relay returns nothing')
      const id = `s${++n}`
      live.set(id, { onEvent, onEose, onClosed })
      send(['REQ', id, ...filters])
      return () => { if (live.delete(id) && !closedWith) try { send(['CLOSE', id]) } catch { /* closing anyway */ } }
    },
  })
}

// --- The AUTH oracle. ---------------------------------------------------------------------------
// A keyless watcher must log in to the relay as the agent to hear its mentions, and a login is a
// signature. The broker lends it exactly that and nothing more: one socket, one JSON line per
// request, checkAuthTemplate on every template, and a rate bound. The watcher never sees a key or
// a Bunker credential, and a template that is not a fresh 22242 for this relay is refused.
export function serveAuthOracle({ socketPath, relay, signer, pubkey, gid = -1, maxPerMinute = 30, now = () => Math.floor(Date.now() / 1000) }) {
  const want = normalizeBuzzRelay(relay)
  if (!HEX64.test(String(pubkey))) throw new Error('oracle needs the manifest pubkey')
  let windowStart = Date.now(), used = 0
  const server = net.createServer(socket => {
    let buffer = '', handled = false
    socket.setEncoding('utf8')
    socket.setTimeout(10000, () => socket.destroy())
    socket.on('error', () => {})
    socket.on('data', async chunk => {
      if (handled) return
      buffer += chunk
      if (buffer.length > 4096) return socket.destroy()
      if (!buffer.includes('\n')) return
      handled = true // one request per connection: bytes after the first line are never a second template
      const answer = obj => { try { socket.end(JSON.stringify(obj) + '\n') } catch { /* peer gone */ } }
      let template; try { template = JSON.parse(buffer.split('\n')[0]) } catch { return answer({ error: 'malformed request' }) }
      const refused = checkAuthTemplate(template, { relay: want, now: now() })
      if (refused) return answer({ error: refused })
      if (Date.now() - windowStart > 60000) { windowStart = Date.now(); used = 0 }
      if (++used > maxPerMinute) return answer({ error: 'rate limited' })
      try {
        const ev = await signer.signEvent({ kind: 22242, created_at: template.created_at, content: '', tags: template.tags })
        if (ev?.pubkey !== pubkey || ev.kind !== 22242 || JSON.stringify(ev.tags) !== JSON.stringify(template.tags) || !verified(ev)) return answer({ error: 'signer returned a different event' })
        answer({ event: ev })
      } catch (e) { answer({ error: `signer: ${e.message}` }) }
    })
  })
  try { unlinkSync(socketPath) } catch { /* no stale socket */ }
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(socketPath, () => {
      try { if (gid >= 0) chownSync(socketPath, -1, gid); chmodSync(socketPath, 0o660) } catch (e) { server.close(); return reject(e) }
      resolve(server)
    })
  })
}

// The watcher's side: a signer that knows its own pubkey from the manifest and can obtain nothing
// but an AUTH signature, by asking the broker's oracle.
export function authOracleSigner({ socketPath, pubkey, timeoutMs = 4000 }) {
  const me = String(pubkey).toLowerCase()
  return Object.freeze({
    getPublicKey: async () => me,
    signEvent: template => new Promise((resolve, reject) => {
      const socket = net.createConnection(socketPath)
      let buffer = ''
      const timer = setTimeout(() => { socket.destroy(); reject(new Error('AUTH oracle timed out')) }, timeoutMs)
      socket.setEncoding('utf8')
      socket.on('error', e => { clearTimeout(timer); reject(new Error(`AUTH oracle unavailable: ${e.message}`)) })
      socket.on('connect', () => socket.write(JSON.stringify(template) + '\n'))
      socket.on('data', chunk => {
        buffer += chunk
        if (!buffer.includes('\n')) return
        clearTimeout(timer); socket.end()
        let reply; try { reply = JSON.parse(buffer.split('\n')[0]) } catch { return reject(new Error('AUTH oracle reply is malformed')) }
        if (reply.error) return reject(new Error(`AUTH oracle refused: ${reply.error}`))
        if (reply.event?.pubkey !== me || !verified(reply.event)) return reject(new Error('AUTH oracle returned an event that is not ours'))
        resolve(reply.event)
      })
    }),
  })
}
