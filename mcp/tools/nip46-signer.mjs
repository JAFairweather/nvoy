// nip46-signer.mjs — minimal Bunker signer for the supervised broker.
// Identity nsecs stay in the Bunker. The client transport key is distinct from the identity;
// it is a broker-only connection credential, not passed to watcher/adapter/worker.

import { randomUUID } from 'node:crypto'
import { finalizeEvent, getPublicKey, nip44 } from 'nostr-tools'
import { SimplePool } from 'nostr-tools/pool'
import { secretKey } from './secret_key.mjs'

const BUNKER = /^bunker:\/\/([0-9a-f]{64})/i
// clientNsec is an nsec or 64-char hex, as identity.ts reads the same key, so no caller has to
// convert (10-24: two broker paths still failed on a hex key after #248 encoded it in one).
// `options.clientSource` names where clientNsec came from, for an error that must not quote it.
export function makeBunkerSigner(uriText, clientNsec, options = {}) {
  const match = BUNKER.exec(String(uriText || '').trim())
  if (!match) throw new Error('invalid bunker URI')
  const uri = new URL(uriText)
  const relays = [...new Set(uri.searchParams.getAll('relay').filter(v => /^wss:\/\//.test(v)))]
  if (!relays.length) throw new Error('bunker URI needs at least one wss relay')
  const pubkey = match[1].toLowerCase(), secret = uri.searchParams.get('secret') || ''
  const clientKey = secretKey(clientNsec, options.clientSource || 'NIP-46 client credential'), clientPubkey = getPublicKey(clientKey)
  const conversation = nip44.v2.utils.getConversationKey(clientKey, pubkey)
  // Every relay socket this signer opens is tracked and closed by disconnect(), whatever state it is in. nostr-tools'
  // relay close() only closes a socket that is already OPEN: one still connecting (or one the pool gave up on after its
  // connect timeout) was dropped, opened later and stayed open, so a one-shot process never exited (q-310: the curator
  // hung "activating" after a finished cycle). A caller's own pool keeps its own sockets.
  const sockets = new Set()
  const pool = options.pool || new SimplePool({ websocketImplementation: trackedWebSocket(options.WebSocket || globalThis.WebSocket, sockets) })
  const pending = new Map()
  const idleMs = Number.isSafeInteger(options.idleMs) && options.idleMs >= 0 ? options.idleMs : 250
  let subscribed = false, subscription, connected, idleTimer, closed = false
  const disconnect = () => {
    clearTimeout(idleTimer); idleTimer = undefined
    try { subscription?.close() } catch { /* best-effort subscription cleanup */ }
    subscription = undefined; subscribed = false; connected = undefined
    try { pool.close(relays) } catch { /* best-effort socket cleanup */ }
    for (const ws of [...sockets]) shut(ws, sockets)
  }
  const idleClose = () => {
    if (closed || pending.size || idleTimer) return
    idleTimer = setTimeout(disconnect, idleMs)
    idleTimer.unref?.()
  }
  const subscribe = () => {
    if (closed) throw new Error('nip46 signer closed')
    clearTimeout(idleTimer); idleTimer = undefined
    if (subscribed) return; subscribed = true
    // When every relay drops this subscription (a connect that failed or timed out, a socket that closed), forget it,
    // so the next call subscribes again instead of waiting on a subscription that no relay holds (A4, 14 Nov: a
    // throttled curator's reconnect failed silently and its sign_event waited out the full 60 s).
    const sub = subscription = pool.subscribeMany(relays, { kinds: [24133], authors: [pubkey], '#p': [clientPubkey] }, { onclose() {
      if (subscription === sub) { subscription = undefined; subscribed = false }
    }, onevent(event) {
      try { const m = JSON.parse(nip44.v2.decrypt(event.content, conversation)); const p = pending.get(m.id); if (!p) return
        pending.delete(m.id); clearTimeout(p.timer)
        m.error ? p.reject(new Error(`bunker: ${m.error}`)) : p.resolve(m.result)
        idleClose()
      } catch { /* unrelated event */ }
    } })
  }
  const rpc = (method, params, timeout = 60000) => new Promise((resolve, reject) => {
    subscribe(); const id = randomUUID()
    const timer = setTimeout(() => {
      if (pending.delete(id)) reject(new Error(`nip46 ${method} timed out`))
      idleClose()
    }, timeout)
    // A pending RPC is real work and its bounded timeout must keep a one-shot process alive.
    // Only the idle transport-close timer is unref'd; a successful response clears this timer.
    pending.set(id, { resolve, reject, timer })
    const event = finalizeEvent({ kind: 24133, created_at: Math.floor(Date.now() / 1000), tags: [['p', pubkey]],
      content: nip44.v2.encrypt(JSON.stringify({ id, method, params }), conversation) }, clientKey)
    const fail = error => { if (!pending.delete(id)) return; clearTimeout(timer); reject(error); idleClose() }
    let sent
    try { sent = pool.publish(relays, event) } catch (error) { fail(error); return }
    // A request that reached no relay can never be answered, so say so now rather than after the full timeout.
    // SimplePool resolves (not rejects) a relay it could not connect to, with 'connection failure: …'; a relay
    // that answered OK false rejects. A publish timeout is not proof the event was lost, so it keeps waiting.
    void Promise.allSettled(sent).then(results => {
      const lost = results.map(r => r.status === 'fulfilled'
        ? (typeof r.value === 'string' && r.value.startsWith('connection failure') ? r.value : null)
        : (/publish timed out/.test(String(r.reason?.message || r.reason)) ? null : String(r.reason?.message || r.reason)))
      if (lost.length && lost.every(Boolean)) fail(new Error(`nip46 ${method}: no relay took the request (${lost.join('; ').slice(0, 200)})`))
    })
  })
  // A refused connect is tolerated: a client the Bunker already knows may be refused a repeat connect
  // (a spent pairing secret) and still be served. But when a later call then fails, the refusal is the
  // likely cause (an unpaired client gets 'Unknown client'), so that call's error names it. Only the
  // fact is kept, never the Bunker's own rejection text: a reply may echo the pairing secret it refused.
  let connectRefusal
  const ready = () => (connected ??= (connectRefusal = undefined,
    rpc('connect', [pubkey, secret], 15000).catch(error => {
      connectRefusal = /^nip46 connect timed out$/.test(error?.message || '') ? 'connect got no answer from the Bunker' : 'the Bunker refused connect'
      return 'active'
    })))
  const call = async (method, params) => {
    await ready()
    try { return await rpc(method, params) } catch (error) {
      if (!connectRefusal) throw error
      throw new Error(`${error?.message || error} (${connectRefusal} too; this client may not be paired, so re-pair it)`)
    }
  }
  const close = () => {
    closed = true
    for (const { reject, timer } of pending.values()) { clearTimeout(timer); reject(new Error('nip46 signer closed')) }
    pending.clear()
    disconnect()
  }
  // One get_public_key per session: callers ask before every action (and openBuzzSession asks again),
  // and each ask is a Bunker request. A successful answer is kept; a failure is not, so the next call
  // asks again.
  let publicKey
  const askPublicKey = () => (publicKey ??= call('get_public_key', []).catch(error => { publicKey = undefined; throw error }))
  return Object.freeze({ pubkey, close, getPublicKey: askPublicKey,
    async nip44Decrypt(peer, ciphertext) { return call('nip44_decrypt', [peer, ciphertext]) },
    async nip44Encrypt(peer, plaintext) { return call('nip44_encrypt', [peer, plaintext]) },
    async signEvent(event) { return JSON.parse(await call('sign_event', [JSON.stringify(event)])) } })
}

// A WebSocket class that records each socket it makes in `sockets`; disconnect() closes and forgets them.
function trackedWebSocket(Base, sockets) {
  if (typeof Base !== 'function') return Base
  return class TrackedWebSocket extends Base {
    constructor(...args) { super(...args); sockets.add(this) }
  }
}

// Close a socket in any state and forget it. A WebSocket may be closed while CONNECTING; should the platform open it
// anyway, it is closed again the moment it opens.
function shut(ws, sockets) {
  sockets.delete(ws)
  try {
    if (ws.readyState === 0 && typeof ws.addEventListener === 'function') ws.addEventListener('open', () => { try { ws.close() } catch { /* already closing */ } })
    if (ws.readyState === 0 || ws.readyState === 1) ws.close()
  } catch { /* best-effort socket cleanup */ }
}
