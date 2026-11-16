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
import { credentialIn } from './outbound_secrets.mjs'
export { nativeGrant } from './admission.mjs'

const HEX64 = /^[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]'])
export const CHANNEL_KINDS = Object.freeze([9, 40002])
// Buzz closes unauthenticated connections after 5s; bound AUTH signing inside that window.
export const BUZZ_AUTH_TIMEOUT_MS = 4500
// Refresh unpublished direct Buzz events before Buzz's ±15 min timestamp window rejects them (q-144).
export const BUZZ_FRESH_WINDOW_SEC = 600
export const isTransientBuzzError = error =>
  /relay closed the connection|relay connection error|session closed|timed out|shared Buzz session/i.test(String(error?.message || error || ''))
export const isStaleTimestampRefusal = message =>
  /^invalid:.*(?:timestamp|created_at|too old|too far|stale|expired)/i.test(String(message || ''))
const cleanCloseReason = raw => {
  const s = String(raw || '').replace(/[^\x20-\x7e]/g, '').trim().slice(0, 120)
  return s && credentialIn(s) ? '[withheld]' : s
}
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

// A reply, as Buzz classifies one (NIP-CW, Top-level Classification): a marked `reply` e tag. A tag marked `root`
// alone, or an unmarked one, only refers to a thread; it does not answer in it (Murphy's Law, PR 281 review).
export const isReply = ev => (Array.isArray(ev?.tags) ? ev.tags : []).some(t => t?.[0] === 'e' && t[3] === 'reply' && HEX64.test(String(t[1])))
// Desktop tags an off-channel mention ["mention", pk] instead of ["p", pk]; both count.
export const mentionsOf = (ev, me) => [...tagValues(ev, 'p'), ...tagValues(ev, 'mention')].includes(me)

export const threadRoot = ev => {
  const marked = marker => (ev.tags || []).find(t => t?.[0] === 'e' && t[3] === marker && HEX64.test(String(t[1])))?.[1]
  return marked('root') || marked('reply') || ev.id
}

// Is this a message addressed to `me` in one of `channels`? Returns the facts admission needs,
// or null. Desktop tags an off-channel mention ["mention", pk] instead of ["p", pk]; both count.
// A reply anywhere in a thread `me` started (one of `threads`, from ownRoots) is addressed too,
// mention or not, so a reviewer's verdict reaches whoever asked (#280). Addressed is not authorised: the
// author still needs a grant.
export function nativeMention(ev, { me, channels, threads = [], now = Math.floor(Date.now() / 1000), verify = verifyEvent }) {
  if (!ev || !CHANNEL_KINDS.includes(ev.kind) || !HEX64.test(String(ev.pubkey)) || ev.pubkey === me) return null
  if (!Number.isSafeInteger(ev.created_at) || ev.created_at > now + 900) return null
  const h = tagValues(ev, 'h')
  if (h.length !== 1 || !channels.includes(h[0])) return null
  const addressed = mentionsOf(ev, me) ? 'mention'
    : isReply(ev) && threadRoot(ev) !== ev.id && threads.some(t => t.id === threadRoot(ev) && t.channel === h[0]) ? 'own-thread' : null
  if (!addressed || !verified(ev, verify)) return null
  return { channel: h[0], author: ev.pubkey, event_id: ev.id, created_at: ev.created_at, addressed }
}

// The threads `me` started: its own signed top-level messages in `channels`, as { id, channel }.
export function ownRoots(events, { me, channels, verify = verifyEvent }) {
  return (Array.isArray(events) ? events : []).filter(ev => ev?.kind === 9 && ev.pubkey === me && HEX64.test(String(ev.id)) &&
    threadRoot(ev) === ev.id && tagValues(ev, 'h').length === 1 && channels.includes(tagValues(ev, 'h')[0]) && verified(ev, verify))
    .map(ev => ({ id: ev.id, channel: tagValues(ev, 'h')[0] }))
}

// The conversation around an admitted message, so the agent can follow the room it was asked in
// (#245). Background only: context carries no authority, whoever wrote it. One fetch asks for the
// channel's last messages before the source, the thread's root, and the thread's replies.
export const CONTEXT_LIMIT = 30
const CONTEXT_MESSAGE_BYTES = 4000, CONTEXT_BYTES = 48 * 1024
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

function buzzFiltersNeedChannels(filters, me) {
  // A membership-notice filter is the one exception, and only for our own notices.
  const notices = f => Array.isArray(f?.kinds) && f.kinds.length && f.kinds.every(k => MEMBERSHIP_KINDS.includes(k)) &&
    Array.isArray(f['#p']) && f['#p'].length === 1 && f['#p'][0] === me && f['#h'] === undefined
  const ownProfile = f => Array.isArray(f?.kinds) && f.kinds.length === 1 && f.kinds[0] === 0 &&
    Array.isArray(f?.authors) && f.authors.length === 1 && f.authors[0] === me && f['#h'] === undefined &&
    Number.isInteger(f.limit) && f.limit === 1
  // Our own latest kind 30078 at one d tag: the relay stores it with no channel, so #h finds nothing.
  const ownAppData = f => Array.isArray(f?.kinds) && f.kinds.length === 1 && f.kinds[0] === 30078 &&
    Array.isArray(f?.authors) && f.authors.length === 1 && f.authors[0] === me && f['#h'] === undefined &&
    Array.isArray(f['#d']) && f['#d'].length === 1 && typeof f['#d'][0] === 'string' && f.limit === 1
  // Room members' kind-0 profiles, for their mention names (#321): kind 0 only, 1..100 exact keys, nothing else.
  const profiles = f => f && Object.keys(f).every(k => k === 'kinds' || k === 'authors') && Array.isArray(f.kinds) &&
    f.kinds.length === 1 && f.kinds[0] === 0 && Array.isArray(f.authors) && f.authors.length >= 1 && f.authors.length <= 100 &&
    f.authors.every(a => /^[0-9a-f]{64}$/.test(String(a)))
  return !Array.isArray(filters) || !filters.length || filters.some(f => !notices(f) && !ownProfile(f) && !ownAppData(f) && !profiles(f) &&
    (!Array.isArray(f?.['#h']) || !f['#h'].length || !f['#h'].every(validChannel)))
}

// One authenticated connection. `signer` is { getPublicKey(), signEvent(template) }; the pubkey
// is resolved BEFORE the socket opens, both to warm a Bunker inside the 5s window and so a
// signer that answers for a different key is caught before anything is sent. `pingMs` makes a
// long-lived session prove it is alive: a socket that stops answering pings is terminated, so a
// half-open connection surfaces as `closed` instead of as a quiet channel.
export async function openBuzzSession({
  relay, signer, timeoutMs = 10000, authTimeoutMs = BUZZ_AUTH_TIMEOUT_MS, pingMs = 0, WS = WebSocket,
  socketPath = process.env.NVOY_BUZZ_SESSION_SOCK || '', onPhase = null,
}) {
  const url = normalizeBuzzRelay(relay)
  if (socketPath && WS === WebSocket) {
    try {
      return await openSharedBuzzClient({ socketPath, relay: url, signer, timeoutMs, onPhase })
    } catch (e) {
      if (!e?.unavailable || !signer || process.env.NVOY_BUZZ_SESSION_REQUIRED === '1') throw e
      onPhase?.({ event: 'shared_fallback', reason: e.message })
    }
  }
  const t0 = Date.now()
  let phase = 'pubkey', closeCode = null, closeReason = ''
  const phases = {}
  const me = String(await signer.getPublicKey()).toLowerCase()
  phases.pubkey_ms = Date.now() - t0
  if (!HEX64.test(me)) throw new Error('signer returned no usable pubkey')
  phase = 'ws_connect'
  const wsStart = Date.now()
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
  ws.on?.('open', () => {
    phases.ws_open_ms = Date.now() - wsStart
    if (phase === 'ws_connect') phase = 'auth_challenge'
  })
  ws.on('message', raw => {
    let m; try { m = JSON.parse(raw.toString()) } catch { return }
    if (m[0] === 'AUTH' && typeof m[1] === 'string') { challenge = m[1]; onChallenge?.resolve(m[1]) }
    else if (m[0] === 'OK') { const w = waiters.get(m[1]); if (w) { waiters.delete(m[1]); w.resolve({ accepted: m[2] === true, message: String(m[3] || '') }) } }
    else if (m[0] === 'EVENT') { const l = live.get(m[1]); if (l) l.onEvent(m[2]); else subs.get(m[1])?.events.push(m[2]) }
    else if (m[0] === 'COUNT') { const s = subs.get(m[1]); if (s?.count) { subs.delete(m[1]); s.resolve(m[2]) } }
    else if (m[0] === 'EOSE') { const l = live.get(m[1]); if (l) l.onEose?.(); else { const s = subs.get(m[1]); if (s) { subs.delete(m[1]); s.resolve(s.events) } } }
    else if (m[0] === 'CLOSED') {
      const l = live.get(m[1])
      if (l) { live.delete(m[1]); l.onClosed?.(String(m[2] || '')) }
      else { const s = subs.get(m[1]); if (s) { subs.delete(m[1]); s.reject(new Error(`subscription closed: ${m[2] || ''}`)) } }
    }
  })
  ws.on('close', (code, reasonBuf) => {
    closeCode = Number.isInteger(code) ? code : null
    closeReason = cleanCloseReason(reasonBuf)
    const elapsed = Date.now() - t0
    const detail = [
      closeCode !== null ? `code=${closeCode}` : '',
      closeReason ? `reason=${JSON.stringify(closeReason)}` : '',
      `phase=${phase}`,
      `elapsed=${elapsed}ms`,
    ].filter(Boolean).join(' ')
    if (closedWith !== 'session closed') {
      onPhase?.({ event: 'close', phase, close_code: closeCode, close_reason: closeReason, elapsed_ms: elapsed, ...phases })
    }
    fail(`relay closed the connection (${detail})`)
  })
  ws.on('error', e => fail(`relay connection error: ${e.message}`))
  const boundedMs = (promise, what, limitMs = timeoutMs) => {
    let timer
    return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${what} timed out (${limitMs}ms)`)), limitMs) })])
      .finally(() => clearTimeout(timer))
  }
  const bounded = (promise, what) => boundedMs(promise, what, timeoutMs)
  const send = frame => { if (closedWith) throw new Error(closedWith); ws.send(JSON.stringify(frame)) }
  // Send, THEN arm the wait: a reply can only arrive on a later tick, and arming first would leave
  // a timer behind when send throws on a closed socket — one that later rejects with no one listening.
  const sendAndAwaitOk = (frame, id) => { send(frame); return bounded(new Promise((resolve, reject) => waiters.set(id, { resolve, reject })), 'relay OK') }
  const close = () => { closedWith ??= 'session closed'; try { ws.close() } catch { /* already gone */ } }
  const needsChannels = filters => buzzFiltersNeedChannels(filters, me)

  try {
    phase = 'auth_challenge'
    const cStart = Date.now()
    const c = challenge ?? await bounded(new Promise((resolve, reject) => { onChallenge = { resolve, reject } }), 'AUTH challenge')
    phases.challenge_ms = Date.now() - cStart
    phase = 'auth_sign'
    const sStart = Date.now()
    const authLimit = Math.max(1, Math.min(timeoutMs, authTimeoutMs))
    const auth = await boundedMs(signer.signEvent(authTemplate(url, c)), 'AUTH sign', authLimit)
    phases.auth_sign_ms = Date.now() - sStart
    if (auth?.pubkey !== me || auth.kind !== 22242 || !verified(auth)) throw new Error('signer returned an AUTH event that is not ours')
    phase = 'auth_ok'
    const okStart = Date.now()
    const verdict = await sendAndAwaitOk(['AUTH', auth], auth.id)
    phases.auth_ok_ms = Date.now() - okStart
    if (!verdict.accepted) throw new Error(`AUTH refused: ${verdict.message || '(no reason)'}`)
    phases.total_auth_ms = Date.now() - t0
    phase = 'ready'
    onPhase?.({ event: 'auth_ok', ...phases })
  } catch (error) {
    error.buzzMeta ??= { op: 'auth', phase, close_code: closeCode, close_reason: closeReason, elapsed_ms: Date.now() - t0, ...phases }
    onPhase?.({ event: 'auth_error', phase, close_code: closeCode, close_reason: closeReason, elapsed_ms: Date.now() - t0, error: error.message, ...phases })
    close()
    throw error
  }

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
    const opStart = Date.now()
    let sent = false
    phase = 'publish'
    try {
      send(['EVENT', ev])
      sent = true
      const res = await bounded(new Promise((resolve, reject) => waiters.set(ev.id, { resolve, reject })), 'relay OK')
      const publish_ms = Date.now() - opStart
      phase = 'ready'
      onPhase?.({ event: 'publish', kind: ev.kind, accepted: res.accepted, publish_ms })
      return { event: ev, ...res, publish_ms }
    } catch (error) {
      const publish_ms = Date.now() - opStart
      error.buzzMeta = { op: 'publish', kind: ev.kind, sent, publish_ms, close_code: closeCode, close_reason: closeReason, phase, ...phases }
      onPhase?.({ event: 'publish_error', kind: ev.kind, sent, publish_ms, close_code: closeCode, close_reason: closeReason, error: error.message })
      throw error
    }
  }
  return Object.freeze({
    pubkey: me, relay: url, close, closed,
    publishSigned,
    // Sign and publish; resolves only on the relay's OK, and reports its refusal verbatim.
    async publish(template) { return publishSigned(await signer.signEvent(template)) },
    // Stored events up to EOSE. Channel filters need #h; the narrow exceptions are our own
    // membership notices, our own latest kind-0 profile and our own latest kind 30078 at one d tag.
    async fetch(...filters) {
      if (needsChannels(filters)) throw new Error('every Buzz filter needs #h channel UUIDs — without it the relay returns nothing')
      const id = `q${++n}`
      const opStart = Date.now()
      phase = 'req'
      try {
        send(['REQ', id, ...filters])
        const pending = bounded(new Promise((resolve, reject) => subs.set(id, { events: [], resolve, reject })), 'REQ')
        const events = await pending
        const req_ms = Date.now() - opStart
        phase = 'ready'
        onPhase?.({ event: 'fetch', count: events.length, req_ms })
        return events
      } catch (error) {
        const req_ms = Date.now() - opStart
        error.buzzMeta = { op: 'fetch', req_ms, close_code: closeCode, close_reason: closeReason, phase, ...phases }
        onPhase?.({ event: 'fetch_error', req_ms, close_code: closeCode, close_reason: closeReason, error: error.message })
        throw error
      } finally { if (!closedWith) try { send(['CLOSE', id]) } catch { /* closing anyway */ } }
    },
    // NIP-45 COUNT over the same filters as fetch: { count, approximate? } exactly as the relay sent it.
    // Rejects on CLOSED, timeout or a reply that is not a non-negative integer count.
    async count(...filters) {
      if (needsChannels(filters)) throw new Error('every Buzz filter needs #h channel UUIDs — without it the relay returns nothing')
      const id = `c${++n}`
      phase = 'count'
      try {
        send(['COUNT', id, ...filters])
        const res = await bounded(new Promise((resolve, reject) => subs.set(id, { events: [], count: true, resolve, reject })), 'COUNT')
        if (!Number.isSafeInteger(res?.count) || res.count < 0) throw new Error('relay COUNT reply has no usable count')
        phase = 'ready'
        return { count: res.count, ...(res.approximate === true ? { approximate: true } : {}) }
      } finally { subs.delete(id) }
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

// --- Broker-shared Buzz session (q-150). --------------------------------------------------------
// Short-lived broker children (reply, post, rooms, native delivery, profile, status) run every
// second to five minutes. Opening a fresh Buzz WebSocket per child costs a get_public_key and a
// kind 22242 AUTH signature every time. The broker instead keeps one authenticated Buzz session in
// its private stateDir (mode 0600, broker-only) and multiplexes fetch and publishSigned over it.
const MAX_CLIENT_BYTES = 256 * 1024
const MAX_SERVER_BYTES = 4 * 1024 * 1024

export function formatBuzzPhase(id, p) {
  const code = p.close_code !== null && p.close_code !== undefined ? p.close_code : 'none'
  const reason = p.close_reason ? ` close_reason=${JSON.stringify(p.close_reason)}` : ''
  if (p.event === 'auth_ok')
    return `session#${id} ready pubkey_ms=${p.pubkey_ms ?? -1} ws_open_ms=${p.ws_open_ms ?? -1} challenge_ms=${p.challenge_ms ?? -1} auth_sign_ms=${p.auth_sign_ms ?? -1} auth_ok_ms=${p.auth_ok_ms ?? -1} total_auth_ms=${p.total_auth_ms ?? -1}`
  if (p.event === 'auth_error')
    return `session#${id} auth_error phase=${p.phase} pubkey_ms=${p.pubkey_ms ?? -1} ws_open_ms=${p.ws_open_ms ?? -1} challenge_ms=${p.challenge_ms ?? -1} auth_sign_ms=${p.auth_sign_ms ?? -1} auth_ok_ms=${p.auth_ok_ms ?? -1} close_code=${code}${reason} error=${JSON.stringify(cleanCloseReason(p.error))}`
  if (p.event === 'close')
    return `session#${id} closed phase=${p.phase} age_ms=${p.elapsed_ms ?? -1} close_code=${code}${reason}`
  if (p.event === 'fetch_error')
    return `session#${id} fetch_error req_ms=${p.req_ms ?? -1} close_code=${code}${reason} error=${JSON.stringify(cleanCloseReason(p.error))}`
  if (p.event === 'publish_error')
    return `session#${id} publish_error kind=${p.kind} sent=${Boolean(p.sent)} publish_ms=${p.publish_ms ?? -1} close_code=${code}${reason} error=${JSON.stringify(cleanCloseReason(p.error))}`
  return null
}

export function serveBuzzSession({
  socketPath, relay, signer, pubkey, timeoutMs = 10000, authTimeoutMs = BUZZ_AUTH_TIMEOUT_MS,
  pingMs = 25000, WS = WebSocket, log = null,
}) {
  const want = normalizeBuzzRelay(relay)
  const me = String(pubkey || '').toLowerCase()
  if (!HEX64.test(me)) throw new Error('Buzz session server needs the manifest pubkey')
  let current = null, currentId = 0, opening = null, nextId = 0, stopped = false
  const emit = (id, p) => { const line = formatBuzzPhase(id, p); if (line) log?.(line) }
  const drop = s => { if (current === s) current = null; try { s?.close() } catch { /* gone */ } }

  async function acquire() {
    if (stopped) throw new Error('shared Buzz session server stopped')
    if (current) return { session: current, reused: true, sessionId: currentId }
    if (opening) {
      const s = await opening
      return { session: s, reused: true, sessionId: currentId }
    }
    const id = ++nextId
    const p = (async () => {
      const s = await openBuzzSession({
        relay: want, signer, timeoutMs, authTimeoutMs, pingMs, WS, socketPath: '',
        onPhase: info => emit(id, info),
      })
      if (s.pubkey !== me) { s.close(); throw new Error('signer does not match manifest pubkey') }
      if (stopped) { s.close(); throw new Error('shared Buzz session server stopped') }
      current = s; currentId = id
      s.closed.then(() => { if (current === s) current = null })
      return s
    })()
    opening = p
    try {
      const s = await p
      return { session: s, reused: false, sessionId: id }
    } finally {
      if (opening === p) opening = null
    }
  }

  const server = net.createServer(socket => {
    let buffer = ''
    socket.setEncoding('utf8')
    socket.setTimeout(Math.max(120000, timeoutMs * 3), () => socket.destroy())
    socket.on('error', () => {})
    const answer = obj => { if (!socket.destroyed) try { socket.write(JSON.stringify(obj) + '\n') } catch { /* peer gone */ } }
    const handle = async msg => {
      const id = msg?.id
      if (!Number.isSafeInteger(id)) return socket.destroy()
      try {
        if (msg.op === 'hello') {
          if (normalizeBuzzRelay(msg.relay) !== want) return answer({ id, ok: false, error: 'Buzz relay does not match this broker session' })
          const { reused, sessionId } = await acquire()
          return answer({ id, ok: true, pubkey: me, relay: want, reused, sessionId })
        }
        if (msg.op === 'fetch') {
          if (buzzFiltersNeedChannels(msg.filters, me))
            return answer({ id, ok: false, error: 'every Buzz filter needs #h channel UUIDs — without it the relay returns nothing' })
          let { session, reused, sessionId } = await acquire()
          try {
            return answer({ id, ok: true, events: await session.fetch(...msg.filters), meta: { reused, sessionId } })
          } catch (err) {
            if (isTransientBuzzError(err)) drop(session)
            if (reused && isTransientBuzzError(err)) {
              log?.(`session#${sessionId} closed on reused fetch; reconnecting once`)
              ;({ session, sessionId } = await acquire())
              return answer({ id, ok: true, events: await session.fetch(...msg.filters), meta: { reused: false, reconnected: true, sessionId } })
            }
            return answer({ id, ok: false, error: err.message, meta: { ...(err.buzzMeta || {}), reused, sessionId } })
          }
        }
        if (msg.op === 'publishSigned') {
          const ev = msg.event
          if (ev?.pubkey !== me || !verified(ev)) return answer({ id, ok: false, error: 'refusing to publish an event that is not ours' })
          if (CHANNEL_KINDS.includes(ev.kind) && tagValues(ev, 'h').length !== 1) return answer({ id, ok: false, error: 'channel event needs exactly one h tag' })
          let { session, reused, sessionId } = await acquire()
          try {
            const res = await session.publishSigned(ev)
            return answer({ id, ok: true, accepted: res.accepted, message: res.message, meta: { publish_ms: res.publish_ms, reused, sessionId } })
          } catch (err) {
            if (isTransientBuzzError(err)) drop(session)
            if (reused && err?.buzzMeta?.sent === false && isTransientBuzzError(err)) {
              log?.(`session#${sessionId} closed before publish write; reconnecting once`)
              ;({ session, sessionId } = await acquire())
              const res = await session.publishSigned(ev)
              return answer({ id, ok: true, accepted: res.accepted, message: res.message, meta: { publish_ms: res.publish_ms, reused: false, reconnected: true, sessionId } })
            }
            return answer({ id, ok: false, error: err.message, meta: { ...(err.buzzMeta || {}), reused, sessionId } })
          }
        }
        return answer({ id, ok: false, error: 'unknown Buzz session op' })
      } catch (err) {
        return answer({ id, ok: false, error: err.message, meta: err.buzzMeta || null })
      }
    }
    socket.on('data', chunk => {
      buffer += chunk
      if (buffer.length > MAX_CLIENT_BYTES) return socket.destroy()
      let nl
      while ((nl = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, nl)
        buffer = buffer.slice(nl + 1)
        if (!line.trim()) continue
        let msg
        try { msg = JSON.parse(line) } catch { return socket.destroy() }
        handle(msg)
      }
    })
  })
  server.on('close', () => {
    stopped = true
    drop(current)
    try { unlinkSync(socketPath) } catch { /* gone */ }
  })
  try { unlinkSync(socketPath) } catch { /* no stale socket */ }
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(socketPath, () => {
      try { chmodSync(socketPath, 0o600) } catch (e) { server.close(); return reject(e) }
      resolve(server)
    })
  })
}

async function connectUnixWithRetry(socketPath, waitMs) {
  const deadline = Date.now() + waitMs
  for (;;) {
    try {
      return await new Promise((resolve, reject) => {
        const s = net.createConnection(socketPath)
        const onErr = e => { s.destroy(); reject(e) }
        s.once('error', onErr)
        s.once('connect', () => { s.removeListener('error', onErr); resolve(s) })
      })
    } catch (e) {
      if (!['ENOENT', 'ECONNREFUSED', 'EAGAIN'].includes(e?.code) || Date.now() + 40 > deadline) {
        const err = new Error(`shared Buzz session unavailable: ${e?.code || e?.message || e}`)
        err.unavailable = true
        throw err
      }
      await new Promise(r => setTimeout(r, 40))
    }
  }
}

export async function openSharedBuzzClient({ socketPath, relay, signer = null, timeoutMs = 10000, onPhase = null }) {
  const url = normalizeBuzzRelay(relay)
  const socket = await connectUnixWithRetry(socketPath, Math.min(600, timeoutMs))
  socket.setEncoding('utf8')
  let buffer = '', nextId = 0, closedWith = null, resolveClosed
  const closed = new Promise(resolve => { resolveClosed = resolve })
  const waiters = new Map()
  const failAll = reason => {
    closedWith ??= reason
    for (const w of waiters.values()) { clearTimeout(w.timer); w.reject(new Error(closedWith)) }
    waiters.clear()
    resolveClosed(closedWith)
  }
  socket.on('close', () => failAll('shared Buzz session closed'))
  socket.on('error', e => failAll(`shared Buzz session error: ${e.message}`))
  socket.on('data', chunk => {
    buffer += chunk
    if (buffer.length > MAX_SERVER_BYTES) { socket.destroy(); return failAll('shared Buzz session frame exceeded limit') }
    let nl
    while ((nl = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, nl)
      buffer = buffer.slice(nl + 1)
      if (!line.trim()) continue
      let msg
      try { msg = JSON.parse(line) } catch { socket.destroy(); return failAll('shared Buzz session reply is malformed') }
      const w = waiters.get(msg.id)
      if (!w) continue
      waiters.delete(msg.id)
      clearTimeout(w.timer)
      if (msg.ok) w.resolve(msg)
      else {
        const err = new Error(String(msg.error || 'shared Buzz session failed'))
        if (msg.meta) err.buzzMeta = msg.meta
        w.reject(err)
      }
    }
  })
  const rpc = payload => {
    if (closedWith) return Promise.reject(new Error(closedWith))
    const id = ++nextId
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        waiters.delete(id)
        reject(new Error(`${payload.op} timed out`))
      }, timeoutMs + 2500)
      waiters.set(id, { resolve, reject, timer })
      try { socket.write(JSON.stringify({ id, ...payload }) + '\n') }
      catch (e) { waiters.delete(id); clearTimeout(timer); reject(e) }
    })
  }
  const close = () => {
    closedWith ??= 'session closed'
    try { socket.end(); socket.destroy() } catch { /* gone */ }
    failAll(closedWith)
  }
  let hello
  try {
    hello = await rpc({ op: 'hello', relay: url })
  } catch (e) {
    close()
    throw e
  }
  const me = String(hello.pubkey || '').toLowerCase()
  if (!HEX64.test(me)) { close(); throw new Error('shared Buzz session returned no usable pubkey') }
  onPhase?.({ event: 'shared_hello', reused: Boolean(hello.reused), session_id: hello.sessionId })
  const publishSigned = async ev => {
    if (ev?.pubkey !== me || !verified(ev)) throw new Error('refusing to publish an event that is not ours')
    if (CHANNEL_KINDS.includes(ev.kind) && tagValues(ev, 'h').length !== 1) throw new Error('channel event needs exactly one h tag')
    const res = await rpc({ op: 'publishSigned', event: ev })
    return { event: ev, accepted: res.accepted === true, message: String(res.message || ''), ...(res.meta || {}) }
  }
  return Object.freeze({
    pubkey: me, relay: url, close, closed,
    publishSigned,
    async publish(template) {
      if (!signer) throw new Error('shared Buzz client requires a signer for publish()')
      return publishSigned(await signer.signEvent(template))
    },
    async fetch(...filters) {
      if (buzzFiltersNeedChannels(filters, me)) throw new Error('every Buzz filter needs #h channel UUIDs — without it the relay returns nothing')
      const res = await rpc({ op: 'fetch', filters })
      return res.events
    },
    subscribe() { throw new Error('long-lived subscriptions must open a dedicated Buzz WebSocket') },
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
