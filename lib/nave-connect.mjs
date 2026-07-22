// vendored from JAFairweather/luke @ 359087f — do not edit; npm run sync-connect
// nave-connect — the shared sign-in module (#56). ONE signer interface across
// every Nave app, four ways to produce it:
//   • nip07         — a browser extension (Alby/nos2x), desktop
//   • nip46         — a bunker (remote signer) over relays, from a bunker:// you hold
//   • nostrconnect  — the REVERSE pairing: we mint the link, you paste it into
//                     the signer's "Connect app". The iPhone path (no extension,
//                     nothing to copy off the phone first).
//   • local         — a raw nsec held in the tab (dev / fallback)
// Every signer exposes the SAME shape, so app code never branches on method:
//   { kind, getPublicKey(): Promise<hex>, signEvent(t): Promise<event>,
//     nip44Encrypt?(pk,pt), nip44Decrypt?(pk,ct), close?() }
//
// Canonical source lives here; the browser consoles (nvoy, nact) vendor a copy
// alongside their vendored nostr-tools (same pattern as nact/assets/vendor).
import { getPublicKey as pkFromSk, finalizeEvent, generateSecretKey, nip04, nip44, nip19 } from 'nostr-tools'
import { SimplePool } from 'nostr-tools/pool'
import { BunkerSigner, parseBunkerInput, createNostrConnectURI } from 'nostr-tools/nip46'

const toHex = (u8) => Array.from(u8, b => b.toString(16).padStart(2, '0')).join('')
const fromHex = (s) => Uint8Array.from(s.match(/../g), h => parseInt(h, 16))

// --- NIP-07 (desktop extension) ---
export function nip07Signer(win = (typeof window !== 'undefined' ? window : undefined)) {
  const n = win?.nostr
  if (!n) throw new Error('no NIP-07 extension (window.nostr) present')
  let pub = null
  return {
    kind: 'nip07',
    getPublicKey: async () => {
      if (pub) return pub
      // Explicit connect ceremony: extensions that expose enable() (Alby)
      // raise their trust/permission dialog HERE — the user picks the trust
      // level before any key or signature is requested, matching the rest of
      // the ecosystem's connect UX (and this project's consent posture).
      // Standard NIP-07 extensions without enable() keep their own lazy
      // per-call prompts. A decline aborts the sign-in cleanly.
      if (typeof n.enable === 'function') {
        try { await n.enable() }
        catch { throw new Error('extension connection declined') }
      }
      return (pub = await n.getPublicKey())
    },
    signEvent: (e) => n.signEvent(e),
    nip44Encrypt: (pk, pt) => n.nip44.encrypt(pk, pt),
    nip44Decrypt: (pk, ct) => n.nip44.decrypt(pk, ct),
  }
}

// --- local nsec (dev / fallback) ---
export function localSigner(sk) {
  const pub = pkFromSk(sk)
  return {
    kind: 'local',
    getPublicKey: async () => pub,
    signEvent: async (e) => finalizeEvent({ ...e, pubkey: pub }, sk),
  }
}

// --- NIP-46 (bunker — the iPhone path) ---
// bunkerInput: a bunker:// URI from the Bunker46 dashboard. clientSecret (hex):
// persist the ephemeral client key so a reload re-pairs to the SAME bunker
// session instead of prompting again. Connect is lazy (first use), so building
// the signer is cheap. _BunkerSigner/_parseBunkerInput are injectable for tests.
export function nip46Signer(bunkerInput, {
  clientSecret, onAuthUrl,
  _BunkerSigner = BunkerSigner, _parseBunkerInput = parseBunkerInput,
} = {}) {
  const local = clientSecret ? fromHex(clientSecret) : generateSecretKey()
  let signer = null, pk = null
  async function ready() {
    if (signer) return signer
    const pointer = await _parseBunkerInput(bunkerInput)
    if (!pointer) throw new Error('nip46Signer: not a valid bunker:// / nostrconnect:// URI')
    signer = new _BunkerSigner(local, pointer, { onauth: onAuthUrl })
    await signer.connect()
    pk = await signer.getPublicKey()
    return signer
  }
  return {
    kind: 'nip46',
    clientSecretHex: toHex(local),   // persist in `remember` to keep the pairing
    getPublicKey: async () => { await ready(); return pk },
    signEvent: async (e) => { await ready(); return signer.signEvent(e) },
    nip44Encrypt: async (p, t) => { await ready(); return signer.nip44Encrypt(p, t) },
    nip44Decrypt: async (p, c) => { await ready(); return signer.nip44Decrypt(p, c) },
    close: async () => { try { await signer?.close?.() } catch { /* best effort */ } },
  }
}

// --- nostrconnect:// (reverse pairing — the iPhone path) ---
//
// Promoted from nact's control plane, which ran it in production while the rest
// of the ecosystem used the stock handshake. It is the more forgiving of the
// two, and the differences below are not stylistic — each one is a bug that bit
// a real signer:
//
//   1. We do NOT use BunkerSigner.fromURI. It only accepts `result === secret`
//      and NIP-44, and hangs forever when a signer (nsec.app, notably) acks with
//      `result:"ack"` or encrypts with NIP-04. We accept either encryption and
//      any non-error result, learn the signer's pubkey from the ack, and then
//      hand off to fromBunker — which needs no second connect.
//   2. The subscription filter carries NO `since`. The ack's created_at is
//      stamped by the SIGNER's clock; when the browser's clock ran even slightly
//      fast, the relay dropped the ack server-side and we saw zero events.
//      `limit: 0` means "no stored history, stream new events" and is
//      clock-skew-proof.
//   3. The relay reachability probe runs AFTER the real subscription is live, so
//      it cannot race it, and a failing probe is informational — the signer
//      publishes its ack to every relay in the URI, so any one reaching it wins.
//
// Async by nature: the ceremony IS the connection, so this resolves only once
// the signer has paired. `onUri` fires immediately with the link to display;
// `onLog` streams diagnostics (the difference between "no ack" and "no relay").
//
// The resolved signer carries `bunkerUri` — a bunker:// pointer synthesized from
// the completed handshake — so a caller can persist it as an ordinary nip46
// session and reconnect on reload without re-pairing.
export const NOSTR_CONNECT_RELAYS = [
  'wss://relay.nsec.app', 'wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net',
]

export async function nostrConnectSigner({
  relays = NOSTR_CONNECT_RELAYS,
  appName = 'Nave', appUrl, perms = ['sign_event:27235', 'get_public_key'],
  clientSecret, onUri, onLog, timeoutMs = 175000, pubkeyTimeoutMs = 20000,
  _pool, _BunkerSigner = BunkerSigner, _createNostrConnectURI = createNostrConnectURI,
  _nip44 = nip44, _nip04 = nip04, _generateSecretKey = generateSecretKey,
} = {}) {
  const log = (m) => { try { onLog?.(m) } catch { /* diagnostics never break sign-in */ } }
  const sk = clientSecret ? fromHex(clientSecret) : _generateSecretKey()
  const clientPubkey = pkFromSk(sk)
  const secret = toHex(_generateSecretKey())
  const uri = _createNostrConnectURI({ clientPubkey, relays, secret, perms, name: appName, url: appUrl })
  try { onUri?.(uri) } catch { /* the caller's display is its own problem */ }
  log(`client pubkey ${clientPubkey.slice(0, 10)}…  secret ${secret.slice(0, 6)}…`)

  const pool = _pool || new SimplePool()
  const ownsPool = !_pool
  let seen = 0

  const signerPubkey = await new Promise((resolve, reject) => {
    log('subscribing for the ack (kind 24133 → us)…')
    const sub = pool.subscribe(relays, { kinds: [24133], '#p': [clientPubkey], limit: 0 }, {
      onevent: async (ev) => {
        seen++
        let plain = null, enc = 'none'
        try { plain = _nip44.decrypt(ev.content, _nip44.getConversationKey(sk, ev.pubkey)); enc = 'nip44' }
        catch {
          try { plain = await _nip04.decrypt(sk, ev.pubkey, ev.content); enc = 'nip04' }
          catch { log(`event #${seen} from ${ev.pubkey.slice(0, 8)}… — decrypt FAILED (both)`); return }
        }
        let resp; try { resp = JSON.parse(plain) } catch { log(`event #${seen} ${enc} — not JSON`); return }
        log(`event #${seen} ${enc} result=${JSON.stringify(resp.result)}${resp.error ? ` error=${resp.error}` : ''}`)
        if (resp && (resp.result === secret || resp.result === 'ack' || (resp.result && !resp.error))) {
          try { sub.close() } catch { /* already closed */ }
          log(`handshake OK — signer ${ev.pubkey.slice(0, 10)}…`)
          resolve(ev.pubkey)
        }
      },
    })
    // Informational only, and deliberately after the subscription above.
    for (const r of relays) {
      Promise.resolve(pool.ensureRelay(r))
        .then(() => log(`relay reachable   ${r}`))
        .catch(e => log(`relay unreachable ${r} — ${e?.message || e}`))
    }
    setTimeout(() => {
      try { sub.close() } catch { /* already closed */ }
      reject(new Error(`no connect handshake from the signer (${seen} events seen). ` +
        (seen ? 'The signer answered but never acked — try generating a fresh link.'
              : 'Zero events: at least one relay must report reachable above, and the signer must list this app under its connected apps.')))
    }, timeoutMs)
  }).catch(e => { if (ownsPool) { try { pool.close(relays) } catch { /* best effort */ } } throw e })

  log('building signer, asking get_public_key…')
  const pointer = { pubkey: signerPubkey, relays, secret }
  const signer = _BunkerSigner.fromBunker(sk, pointer, { pool })
  const pk = await Promise.race([
    signer.getPublicKey(),
    new Promise((_, rej) => setTimeout(() => rej(new Error('signer paired but never answered get_public_key')), pubkeyTimeoutMs)),
  ])
  log(`got pubkey ${pk.slice(0, 10)}… — connected.`)

  return {
    // A nostrconnect pairing IS a NIP-46 session — only the direction of the
    // introduction differed. Reporting nip46 keeps the titlebar badge, the
    // session format, and every downstream branch identical.
    kind: 'nip46',
    via: 'nostrconnect',
    clientSecretHex: toHex(sk),
    bunkerUri: `bunker://${signerPubkey}?${relays.map(r => `relay=${encodeURIComponent(r)}`).join('&')}&secret=${secret}`,
    getPublicKey: async () => pk,
    npub: nip19.npubEncode(pk),
    signEvent: (e) => signer.signEvent(e),
    nip44Encrypt: (p, t) => signer.nip44Encrypt(p, t),
    nip44Decrypt: (p, c) => signer.nip44Decrypt(p, c),
    close: async () => {
      try { await signer?.close?.() } catch { /* best effort */ }
      if (ownsPool) { try { pool.close(relays) } catch { /* best effort */ } }
    },
  }
}

// --- session persistence for the app's `remember` slot ---
// nip07 → just 'nip07'. nip46 → the bunker URI + client key so a reload
// reconnects without re-scanning. A bare hex string is the legacy nvoy "local"
// remember (a stored nsec), preserved for back-compat.
export function serializeSession(kind, data = {}) {
  if (kind === 'nip07') return 'nip07'
  if (kind === 'nip46') return 'nip46:' + JSON.stringify({ uri: data.uri, cs: data.clientSecretHex })
  throw new Error(`serializeSession: unsupported kind ${kind}`)
}
export function parseSession(saved) {
  if (!saved) return null
  if (saved === 'nip07') return { kind: 'nip07' }
  if (saved.startsWith('nip46:')) {
    const { uri, cs } = JSON.parse(saved.slice(6))
    return { kind: 'nip46', uri, clientSecret: cs }
  }
  return { kind: 'local', hexKey: saved }   // legacy: raw hex nsec in `remember`
}

// Rebuild a signer from a parsed session. `local` returns null — the app rebuilds
// it from its own key material (possibly behind a NIP-49 unlock), not from here.
export function signerFromSession(sess, opts = {}) {
  if (!sess) return null
  if (sess.kind === 'nip07') return nip07Signer(opts.win)
  if (sess.kind === 'nip46') return nip46Signer(sess.uri, { clientSecret: sess.clientSecret, ...opts })
  return null
}
