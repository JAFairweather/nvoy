// identity.ts — agent keypair management (spec §6.1).
//
// Sources, in precedence order:
//   1. --ephemeral flag           fresh keypair per boot (demos, CI)
//   2. NVOY_NSEC env              nsec1... bech32 or 64-char hex
//   3. NVOY_NCRYPTSEC_FILE env    file containing ncryptsec1..., decrypted
//      with NVOY_NCRYPTSEC_PASSPHRASE (NIP-49)
//
// The agent's npub is its address: it is what a delegator grants to.

import { readFileSync } from 'node:fs'
import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { decrypt as nip49Decrypt } from 'nostr-tools/nip49'

export interface Identity {
  secretKey: Uint8Array
  pubkey: string
  npub: string
  source: 'ephemeral' | 'env' | 'ncryptsec'
}

const HEX64 = /^[0-9a-f]{64}$/i

function decodeNsec(raw: string): Uint8Array {
  const s = raw.trim()
  if (HEX64.test(s)) return Uint8Array.from(Buffer.from(s, 'hex'))
  const { type, data } = nip19.decode(s)
  if (type !== 'nsec') throw new Error(`NVOY_NSEC: expected nsec1... or 64-char hex, got ${type}`)
  return data as Uint8Array
}

export function loadIdentity(
  argv: string[] = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env,
): Identity {
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
      'no agent identity: set NVOY_NSEC, or NVOY_NCRYPTSEC_FILE + NVOY_NCRYPTSEC_PASSPHRASE, or pass --ephemeral',
    )
  }

  const pubkey = getPublicKey(secretKey)
  return { secretKey, pubkey, npub: nip19.npubEncode(pubkey), source }
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
