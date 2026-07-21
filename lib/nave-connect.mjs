// vendored from JAFairweather/luke @ 29c6926 — do not edit; npm run sync-connect
// nave-connect — the shared sign-in module (#56). ONE signer interface across
// every Nave app, three ways to produce it:
//   • nip07  — a browser extension (Alby/nos2x), desktop
//   • nip46  — a bunker (remote signer) over relays — the iPhone / no-extension path
//   • local  — a raw nsec held in the tab (dev / fallback)
// Every signer exposes the SAME shape, so app code never branches on method:
//   { kind, getPublicKey(): Promise<hex>, signEvent(t): Promise<event>,
//     nip44Encrypt?(pk,pt), nip44Decrypt?(pk,ct), close?() }
//
// Canonical source lives here; the browser consoles (nvoy, nact) vendor a copy
// alongside their vendored nostr-tools (same pattern as nact/assets/vendor).
import { getPublicKey as pkFromSk, finalizeEvent, generateSecretKey } from 'nostr-tools'
import { BunkerSigner, parseBunkerInput } from 'nostr-tools/nip46'

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
