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
// signer that answers for a different key is caught before anything is sent.
export async function openBuzzSession({ relay, signer, timeoutMs = 10000, WS = WebSocket }) {
  const url = normalizeBuzzRelay(relay)
  const me = String(await signer.getPublicKey()).toLowerCase()
  if (!HEX64.test(me)) throw new Error('signer returned no usable pubkey')
  const ws = new WS(url)
  const waiters = new Map(), subs = new Map()
  let challenge, onChallenge, closedWith
  const fail = reason => {
    closedWith ??= reason
    for (const w of waiters.values()) w.reject(new Error(closedWith))
    for (const s of subs.values()) s.reject(new Error(closedWith))
    waiters.clear(); subs.clear(); onChallenge?.reject(new Error(closedWith))
  }
  ws.on('message', raw => {
    let m; try { m = JSON.parse(raw.toString()) } catch { return }
    if (m[0] === 'AUTH' && typeof m[1] === 'string') { challenge = m[1]; onChallenge?.resolve(m[1]) }
    else if (m[0] === 'OK') { const w = waiters.get(m[1]); if (w) { waiters.delete(m[1]); w.resolve({ accepted: m[2] === true, message: String(m[3] || '') }) } }
    else if (m[0] === 'EVENT') subs.get(m[1])?.events.push(m[2])
    else if (m[0] === 'EOSE') { const s = subs.get(m[1]); if (s) { subs.delete(m[1]); s.resolve(s.events) } }
    else if (m[0] === 'CLOSED') { const s = subs.get(m[1]); if (s) { subs.delete(m[1]); s.reject(new Error(`subscription closed: ${m[2] || ''}`)) } }
  })
  ws.on('close', () => fail('relay closed the connection'))
  ws.on('error', e => fail(`relay connection error: ${e.message}`))
  const bounded = (promise, what) => {
    let timer
    return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${what} timed out`)), timeoutMs) })])
      .finally(() => clearTimeout(timer))
  }
  const send = frame => { if (closedWith) throw new Error(closedWith); ws.send(JSON.stringify(frame)) }
  const awaitOk = id => bounded(new Promise((resolve, reject) => waiters.set(id, { resolve, reject })), 'relay OK')
  const close = () => { closedWith ??= 'session closed'; try { ws.close() } catch { /* already gone */ } }

  try {
    const c = challenge ?? await bounded(new Promise((resolve, reject) => { onChallenge = { resolve, reject } }), 'AUTH challenge')
    const auth = await signer.signEvent(authTemplate(url, c))
    if (auth?.pubkey !== me || auth.kind !== 22242 || !verified(auth)) throw new Error('signer returned an AUTH event that is not ours')
    const pending = awaitOk(auth.id)
    send(['AUTH', auth])
    const verdict = await pending
    if (!verdict.accepted) throw new Error(`AUTH refused: ${verdict.message || '(no reason)'}`)
  } catch (error) { close(); throw error }

  let n = 0
  return Object.freeze({
    pubkey: me, relay: url, close,
    // Sign and publish; resolves only on the relay's OK, and reports its refusal verbatim.
    async publish(template) {
      const ev = await signer.signEvent(template)
      if (ev?.pubkey !== me || !verified(ev)) throw new Error('signer returned an event that is not ours')
      if (CHANNEL_KINDS.includes(ev.kind) && tagValues(ev, 'h').length !== 1) throw new Error('channel event needs exactly one h tag')
      const pending = awaitOk(ev.id)
      send(['EVENT', ev])
      return { event: ev, ...(await pending) }
    },
    // Stored events up to EOSE. Every filter must name its channels, or Buzz answers with nothing.
    async fetch(...filters) {
      if (!filters.length || filters.some(f => !Array.isArray(f?.['#h']) || !f['#h'].length || !f['#h'].every(validChannel)))
        throw new Error('every Buzz filter needs #h channel UUIDs — without it the relay returns nothing')
      const id = `q${++n}`
      const pending = bounded(new Promise((resolve, reject) => subs.set(id, { events: [], resolve, reject })), 'REQ')
      send(['REQ', id, ...filters])
      try { return await pending } finally { if (!closedWith) try { send(['CLOSE', id]) } catch { /* closing anyway */ } }
    },
  })
}
