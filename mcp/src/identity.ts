// identity.ts — agent keypair / signer management (spec §6.1).
//
// Sources, in precedence order:
//   1. --ephemeral flag           fresh keypair per boot (demos, CI)
//   2. NVOY_SIGNER=nip46          remote signer: the key lives in a bunker
//      + NVOY_BUNKER_URI          (bunker://<pubkey>?relay=…&secret=…). The key
//                                 is NEVER on this host — signing goes over
//                                 NIP-46. The scope (which kinds may be signed,
//                                 rate limits) is enforced by the bunker's
//                                 connection token, not here. (nvoy#30)
//   3. NVOY_NSEC env              nsec1... bech32 or 64-char hex
//   4. NVOY_NCRYPTSEC_FILE env    file containing ncryptsec1..., decrypted
//      with NVOY_NCRYPTSEC_PASSPHRASE (NIP-49)
//
// The agent's npub is its address: it is what a delegator grants to.
//
// Everything downstream signs/encrypts through `identity.signer` (the nipxx
// signer shape: getPublicKey / signEvent / nip44Encrypt / nip44Decrypt, all
// async). For local backends that is a thin wrapper over the raw key; for
// nip46 it is the remote bunker. `secretKey` is present ONLY for local
// backends — code that needs a raw key (nip59 wrapEvent, grant issuance,
// outbox writes, notice sends) must guard on its absence and refuse cleanly
// under a remote signer (a drafter reads grants + emits drafts; it does not
// issue). See requireLocalKey().

import { readFileSync } from 'node:fs'
import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { decrypt as nip49Decrypt } from 'nostr-tools/nip49'
import { BunkerSigner } from 'nostr-tools/nip46'
import { SimplePool } from 'nostr-tools/pool'
// The nipxx local-signer wrapper is the shared contract for the local path.
// @ts-ignore — vendored .mjs, no types
import { localSigner as nipxxLocalSigner } from '../lib/nipxx.mjs'

/** The nipxx-compatible signer: what every sign/encrypt/decrypt path consumes. */
export interface Signer {
  getPublicKey(): Promise<string>
  signEvent(event: any): Promise<any>
  nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string>
  nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string>
}

export interface Identity {
  /** The signer every path uses. Local backends wrap the key; nip46 is remote. */
  signer: Signer
  /** Present ONLY for local backends; undefined under a remote (nip46) signer. */
  secretKey?: Uint8Array
  pubkey: string
  npub: string
  source: 'ephemeral' | 'env' | 'ncryptsec' | 'nip46'
}

const HEX64 = /^[0-9a-f]{64}$/i

function decodeNsec(raw: string): Uint8Array {
  const s = raw.trim()
  if (HEX64.test(s)) return Uint8Array.from(Buffer.from(s, 'hex'))
  const { type, data } = nip19.decode(s)
  if (type !== 'nsec') throw new Error(`NVOY_NSEC: expected nsec1... or 64-char hex, got ${type}`)
  return data as Uint8Array
}

/**
 * Guard for operations that genuinely need a raw local key (nip59 wrapEvent,
 * grant issuance, outbox writes, notice sends). Under a remote signer these
 * are refused with a clear reason rather than crashing on an undefined key —
 * the nip46 (drafter) deployment reads grants and emits drafts, it does not
 * issue. `op` names the operation for the error.
 */
export function requireLocalKey(identity: Identity, op: string): Uint8Array {
  if (!identity.secretKey) {
    throw new Error(`${op} requires a local signing key; this runtime uses a remote (NIP-46) signer — that operation is not available in remote-signer mode`)
  }
  return identity.secretKey
}

/** Build the remote (NIP-46) signer from a bunker URI. The identity pubkey is
 *  the URI host (read synchronously, so loadIdentity stays sync); the
 *  BunkerSigner is built + connected lazily on first sign/encrypt (fromURI is
 *  async). A fresh client key is the NIP-46 TRANSPORT key (not the signing
 *  identity) — throwaway per boot. */
const BUNKER_PUBKEY = /^bunker:\/\/([0-9a-f]{64})/i
function makeNip46(bunkerUri: string): { signer: Signer; pubkey: string } {
  const m = BUNKER_PUBKEY.exec(bunkerUri.trim())
  if (!m) throw new Error('NVOY_BUNKER_URI is not a valid bunker://<64-hex-pubkey>?… connection string')
  const pubkey = m[1].toLowerCase()
  const pool = new SimplePool()
  const clientKey = generateSecretKey() // transport key — not the signing identity
  let bunkerP: Promise<any> | null = null
  const ensure = () => (bunkerP ??= BunkerSigner.fromURI(clientKey, bunkerUri, { pool }))
  const signer: Signer = {
    getPublicKey: async () => (await ensure()).getPublicKey(),
    signEvent: async (event) => (await ensure()).signEvent(event),
    nip44Encrypt: async (pk, pt) => (await ensure()).nip44Encrypt(pk, pt),
    nip44Decrypt: async (pk, ct) => (await ensure()).nip44Decrypt(pk, ct),
  }
  return { signer, pubkey }
}

export function loadIdentity(
  argv: string[] = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env,
): Identity {
  // Remote signer: the key is off-host. Selected explicitly (NVOY_SIGNER=nip46),
  // or implied when only a bunker URI is present, so it never shadows a local key.
  const wantsNip46 = /^nip46$/i.test(env.NVOY_SIGNER || '') ||
    (!!env.NVOY_BUNKER_URI && !env.NVOY_NSEC && !env.NVOY_NCRYPTSEC_FILE && !argv.includes('--ephemeral'))
  if (wantsNip46) {
    if (!env.NVOY_BUNKER_URI) throw new Error('NVOY_SIGNER=nip46 requires NVOY_BUNKER_URI (bunker://…)')
    const { signer, pubkey } = makeNip46(env.NVOY_BUNKER_URI)
    return { signer, pubkey, npub: nip19.npubEncode(pubkey), source: 'nip46' }
  }

  let secretKey: Uint8Array
  let source: Identity['source']

  if (argv.includes('--ephemeral')) {
    secretKey = generateSecretKey()
    source = 'ephemeral'
  } else if (env.NVOY_NSEC) {
    secretKey = decodeNsec(env.NVOY_NSEC)
    source = 'env'
  } else if (env.NVOY_NCRYPTSEC_FILE) {
    const ncryptsec = readFileSync(env.NVOY_NCRYPTSEC_FILE, 'utf8').trim()
    const passphrase = env.NVOY_NCRYPTSEC_PASSPHRASE
    if (!passphrase) throw new Error('NVOY_NCRYPTSEC_FILE is set but NVOY_NCRYPTSEC_PASSPHRASE is not')
    secretKey = nip49Decrypt(ncryptsec, passphrase)
    source = 'ncryptsec'
  } else {
    throw new Error(
      'no agent identity: set NVOY_NSEC, or NVOY_NCRYPTSEC_FILE + NVOY_NCRYPTSEC_PASSPHRASE, or NVOY_SIGNER=nip46 + NVOY_BUNKER_URI, or pass --ephemeral',
    )
  }

  const pubkey = getPublicKey(secretKey)
  const signer = nipxxLocalSigner(secretKey) as Signer
  return { signer, secretKey, pubkey, npub: nip19.npubEncode(pubkey), source }
}

/** Default relay set; override with NVOY_RELAYS (comma-separated). */
export const DEFAULT_RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net']

export function loadRelays(env: NodeJS.ProcessEnv = process.env): string[] {
  const raw = env.NVOY_RELAYS
  if (!raw) return DEFAULT_RELAYS
  const urls = raw.split(',').map(s => s.trim()).filter(Boolean)
  if (urls.length === 0) return DEFAULT_RELAYS
  return urls
}
