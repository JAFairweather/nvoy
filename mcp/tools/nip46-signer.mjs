// nip46-signer.mjs — minimal Bunker signer for the supervised broker.
// Identity nsecs stay in the Bunker. The client transport key is distinct from the identity;
// it is a broker-only connection credential, not passed to watcher/adapter/worker.

import { randomUUID } from 'node:crypto'
import { finalizeEvent, getPublicKey, nip19, nip44 } from 'nostr-tools'
import { SimplePool } from 'nostr-tools/pool'

const BUNKER = /^bunker:\/\/([0-9a-f]{64})/i
const nsec = raw => {
  const { type, data } = nip19.decode(String(raw || '').trim())
  if (type !== 'nsec') throw new Error('NIP-46 client credential must be nsec1…')
  return data
}

export function makeBunkerSigner(uriText, clientNsec, options = {}) {
  const match = BUNKER.exec(String(uriText || '').trim())
  if (!match) throw new Error('invalid bunker URI')
  const uri = new URL(uriText)
  const relays = [...new Set(uri.searchParams.getAll('relay').filter(v => /^wss:\/\//.test(v)))]
  if (!relays.length) throw new Error('bunker URI needs at least one wss relay')
  const pubkey = match[1].toLowerCase(), secret = uri.searchParams.get('secret') || ''
  const clientKey = nsec(clientNsec), clientPubkey = getPublicKey(clientKey)
  const conversation = nip44.v2.utils.getConversationKey(clientKey, pubkey)
  const pool = options.pool || new SimplePool(), pending = new Map()
  const idleMs = Number.isSafeInteger(options.idleMs) && options.idleMs >= 0 ? options.idleMs : 250
  let subscribed = false, subscription, connected, idleTimer, closed = false
  const disconnect = () => {
    clearTimeout(idleTimer); idleTimer = undefined
    try { subscription?.close() } catch { /* best-effort subscription cleanup */ }
    subscription = undefined; subscribed = false; connected = undefined
    try { pool.close(relays) } catch { /* best-effort socket cleanup */ }
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
    subscription = pool.subscribeMany(relays, { kinds: [24133], authors: [pubkey], '#p': [clientPubkey] }, { onevent(event) {
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
    try { void Promise.allSettled(pool.publish(relays, event)) }
    catch (error) { clearTimeout(timer); pending.delete(id); reject(error); idleClose() }
  })
  const ready = () => (connected ??= rpc('connect', [pubkey, secret], 15000).catch(() => 'active'))
  const close = () => {
    closed = true
    for (const { reject, timer } of pending.values()) { clearTimeout(timer); reject(new Error('nip46 signer closed')) }
    pending.clear()
    disconnect()
  }
  return Object.freeze({ pubkey, close, async getPublicKey() { await ready(); return rpc('get_public_key', []) },
    async nip44Decrypt(peer, ciphertext) { await ready(); return rpc('nip44_decrypt', [peer, ciphertext]) },
    async nip44Encrypt(peer, plaintext) { await ready(); return rpc('nip44_encrypt', [peer, plaintext]) },
    async signEvent(event) { await ready(); return JSON.parse(await rpc('sign_event', [JSON.stringify(event)])) } })
}
