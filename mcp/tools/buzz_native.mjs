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
import { HOP_TAG } from './agent_limits.mjs'
export { nativeGrant } from './admission.mjs'

const HEX64 = /^[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]'])
export const CHANNEL_KINDS = Object.freeze([9, 40002])
// Relay-signed membership notices: 44100 added, 44101 removed (block/buzz NOSTR.md "Membership
// Notifications"). They carry no channel scope, so they are the one stream read without #h.
export const MEMBERSHIP_KINDS = Object.freeze([44100, 44101])
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
// a reply without it reaches no one. `hop` is the parent's nvoy-hop + 1 (agent_limits.mjs).
export function channelReply({ channel, parent, content, hop = 1, mentions = [], now = Math.floor(Date.now() / 1000) }) {
  if (!validChannel(channel)) throw new Error('channel must be a UUID')
  if (!parent || !HEX64.test(String(parent.id)) || !HEX64.test(String(parent.pubkey))) throw new Error('reply needs the verified parent event')
  if (typeof content !== 'string' || !content.trim()) throw new Error('empty reply')
  if (!Number.isSafeInteger(hop) || hop < 1) throw new Error('hop must be a positive integer')
  if (!Array.isArray(mentions) || !mentions.every(p => HEX64.test(String(p))) || new Set(mentions).size !== mentions.length) throw new Error('mentions must be distinct hex pubkeys')
  const marked = marker => (parent.tags || []).find(t => t?.[0] === 'e' && t[3] === marker && HEX64.test(String(t[1])))?.[1]
  const root = marked('root') || marked('reply') || parent.id
  const tags = [['h', channel]]
  if (root !== parent.id) tags.push(['e', root, '', 'root'])
  tags.push(['e', parent.id, '', 'reply'], ['p', parent.pubkey], ...mentions.filter(p => p !== parent.pubkey).map(p => ['p', p]), [HOP_TAG, String(hop)])
  return { kind: 9, created_at: now, content, tags }
}

// A conversation the identity starts: top level, so no e tags, and hop 1. Each mention is a p tag.
export function channelPost({ channel, content, mentions = [], now = Math.floor(Date.now() / 1000) }) {
  if (!validChannel(channel)) throw new Error('channel must be a UUID')
  if (typeof content !== 'string' || !content.trim()) throw new Error('empty post')
  if (!Array.isArray(mentions) || !mentions.every(p => HEX64.test(String(p))) || new Set(mentions).size !== mentions.length) throw new Error('mentions must be distinct hex pubkeys')
  return { kind: 9, created_at: now, content, tags: [['h', channel], ...mentions.map(p => ['p', p]), [HOP_TAG, '1']] }
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

// The conversation around an admitted message, so the agent can follow the room it was asked in
// (#245). Background only: context carries no authority, whoever wrote it. One fetch asks for the
// channel's last messages before the source, the thread's root, and the thread's replies.
export const CONTEXT_LIMIT = 30
const CONTEXT_MESSAGE_BYTES = 4000, CONTEXT_BYTES = 48 * 1024
const threadRoot = ev => {
  const marked = marker => (ev.tags || []).find(t => t?.[0] === 'e' && t[3] === marker && HEX64.test(String(t[1])))?.[1]
  return marked('root') || marked('reply') || ev.id
}
export function contextFilters(source) {
  const h = tagValues(source, 'h')
  if (h.length !== 1 || !validChannel(h[0]) || !Number.isSafeInteger(source.created_at)) return null
  const root = threadRoot(source)
  return [{ kinds: [9], '#h': h, until: source.created_at, limit: CONTEXT_LIMIT + 1 },
    ...(root !== source.id ? [{ kinds: [9], '#h': h, ids: [root] }] : []),
    { kinds: [9], '#h': h, '#e': [root] }]
}
export function channelContext(events, { source, names = {}, limit = CONTEXT_LIMIT, verify = verifyEvent, now = Math.floor(Date.now() / 1000) }) {
  const [channel] = tagValues(source, 'h'), root = threadRoot(source), byId = new Map()
  for (const ev of Array.isArray(events) ? events : []) {
    if (ev?.kind !== 9 || ev.id === source.id || byId.has(ev.id) || !HEX64.test(String(ev.id)) || !HEX64.test(String(ev.pubkey)) ||
        !Number.isSafeInteger(ev.created_at) || ev.created_at > source.created_at || typeof ev.content !== 'string') continue
    const h = tagValues(ev, 'h')
    if (h.length !== 1 || h[0] !== channel || !verified(ev, verify)) continue
    byId.set(ev.id, ev)
  }
  // The thread first, then the most recent channel messages, until the count or byte budget is spent.
  const inThread = ev => ev.id === root || threadRoot(ev) === root
  const ranked = [...byId.values()].sort((a, b) => (inThread(b) - inThread(a)) || (b.created_at - a.created_at))
  const kept = []
  let bytes = 0
  for (const ev of ranked) {
    if (kept.length >= limit) break
    let content = ev.content
    if (Buffer.byteLength(content) > CONTEXT_MESSAGE_BYTES) content = `${Buffer.from(content).subarray(0, CONTEXT_MESSAGE_BYTES).toString().replace(/�+$/, '')}…`
    if (bytes + Buffer.byteLength(content) > CONTEXT_BYTES) break
    bytes += Buffer.byteLength(content)
    const replyTo = (ev.tags || []).find(t => t?.[0] === 'e' && t[3] === 'reply' && HEX64.test(String(t[1])))?.[1]
    const name = names[ev.pubkey]
    kept.push({ from: ev.pubkey, ...(name ? { name } : {}), at: ev.created_at, content, event_id: ev.id, ...(replyTo ? { reply_to: replyTo } : {}) })
  }
  return { channel, fetched_at: now, messages: kept.sort((a, b) => a.at - b.at) }
}

// A Buzz DM is a channel like any other — kind:9 with an h tag, and clients p-tag every participant
// — so what makes it a DM is its channel type, `dm`. The relay stamps that type as the first t tag
// on the channel's 39000 and on every 44100/44101 notice about it, and a client cannot submit a
// notice of its own (block/buzz NOSTR.md, NIP-CL). The relay also refuses a notice filter whose #p
// is anyone but the reader, so this one asks only about `me`.
export const dmNoticeFilter = me => ({ kinds: [...MEMBERSHIP_KINDS], '#p': [me], '#t': ['dm'] })

// The DM channels `me` is in now: the newest signed notice for each channel decides, and a removal
// stamped in the same second as an add wins, so a tie leaves the identity listening to less.
export function dmChannels(notices, { me, verify = verifyEvent }) {
  const latest = new Map()
  const usable = (Array.isArray(notices) ? notices : []).filter(ev => MEMBERSHIP_KINDS.includes(ev?.kind) &&
    Number.isSafeInteger(ev.created_at) && tagValues(ev, 'p').includes(me) && tagValues(ev, 't')[0] === 'dm' &&
    tagValues(ev, 'h').length === 1 && validChannel(tagValues(ev, 'h')[0]) && verified(ev, verify))
  usable.sort((a, b) => a.created_at - b.created_at || a.kind - b.kind)
  for (const ev of usable) latest.set(tagValues(ev, 'h')[0], ev.kind === MEMBERSHIP_KINDS[0])
  return [...latest].filter(([, member]) => member).map(([channel]) => channel).sort()
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
  // A membership-notice filter is the one exception, and only for our own notices.
  const notices = f => Array.isArray(f?.kinds) && f.kinds.length && f.kinds.every(k => MEMBERSHIP_KINDS.includes(k)) &&
    Array.isArray(f['#p']) && f['#p'].length === 1 && f['#p'][0] === me && f['#h'] === undefined
  const ownProfile = f => Array.isArray(f?.kinds) && f.kinds.length === 1 && f.kinds[0] === 0 &&
    Array.isArray(f?.authors) && f.authors.length === 1 && f.authors[0] === me && f['#h'] === undefined &&
    Number.isInteger(f.limit) && f.limit === 1
  const needsChannels = filters => !filters.length || filters.some(f => !notices(f) && !ownProfile(f) &&
    (!Array.isArray(f?.['#h']) || !f['#h'].length || !f['#h'].every(validChannel)))

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
    // Stored events up to EOSE. Channel filters need #h; the two narrow exceptions are our own
    // membership notices and our own latest kind-0 profile.
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
