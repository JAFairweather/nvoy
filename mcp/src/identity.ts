// identity.ts — agent keypair / signer management (spec §6.1).
//
// Sources, in precedence order:
//   1. --ephemeral flag           fresh keypair per boot (demos, CI)
//   2. NVOY_SIGNER=nip46          remote signer: the key lives in a bunker
//      + NVOY_BUNKER_URI_FILE     a mode-0600 file containing the pairing URI. The key
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

import { randomUUID } from 'node:crypto'
import { closeSync, constants as fsConstants, fstatSync, openSync, readFileSync } from 'node:fs'
import { finalizeEvent, generateSecretKey, getPublicKey, nip19, nip44 } from 'nostr-tools'
import { decrypt as nip49Decrypt } from 'nostr-tools/nip49'
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
 *  connection is made lazily on first RPC.
 *
 *  Hand-rolled NIP-46 client (2026-07-24, replacing BunkerSigner) — three
 *  wire-proven incompatibilities with Bunker46 (see luke#27 for the debug):
 *    1. the transport key must be STABLE (NVOY_NIP46_CLIENT_NSEC): the bunker
 *       binds the connection to the client pubkey, so a throwaway-per-boot key
 *       looks like a stranger with an expired invite and hangs forever;
 *    2. Bunker46 answers in nip44; nostr-tools' BunkerSigner listens in nip04
 *       and never hears the replies;
 *    3. this nostr-tools subscribeMany takes a SINGLE filter object — an
 *       array of filters silently matches nothing. */
const BUNKER_PUBKEY = /^bunker:\/\/([0-9a-f]{64})/i

// A bunker URI has a bearer pairing secret. It is configuration, but it is not
// harmless configuration: never accept a symlink or a file other local users
// can read, and do not require it to be placed in an MCP config literal.  This
// validates the *opened descriptor*, rather than lstat(path) then reopening the
// path: a writable parent directory could otherwise swap the checked file for a
// symlink in between those operations.
function readPrivateFile(path: string, name: string): string {
  let fd: number
  try { fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW) }
  catch { throw new Error(`${name} file cannot be read as a regular non-symlink file`) }
  try {
    const stat = fstatSync(fd)
    if (!stat.isFile()) throw new Error(`${name} file must be a regular file, not a symlink`)
    if (stat.mode & 0o077) throw new Error(`${name} file must not be group/world-readable (chmod 600)`)
    // `fd` pins the verified inode even if its directory entry changes after open.
    const value = readFileSync(fd, 'utf8').trim()
    if (!value) throw new Error(`${name} file is empty`)
    return value
  } finally { closeSync(fd) }
}

/** Resolve a NIP-46 URI without putting its bearer secret in an env literal.
 *  Direct env support is retained only for old deployments; ambiguous sources
 *  are refused rather than silently choosing one. */
export function loadBunkerUri(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const raw = env.NVOY_BUNKER_URI?.trim()
  const file = env.NVOY_BUNKER_URI_FILE?.trim()
  if (raw && file) throw new Error('set only one of NVOY_BUNKER_URI or NVOY_BUNKER_URI_FILE')
  return file ? readPrivateFile(file, 'NVOY_BUNKER_URI') : raw || undefined
}

function loadNip46ClientKey(env: NodeJS.ProcessEnv): Uint8Array {
  const raw = env.NVOY_NIP46_CLIENT_NSEC?.trim()
  const file = env.NVOY_NIP46_CLIENT_NSEC_FILE?.trim()
  if (raw && file) throw new Error('set only one of NVOY_NIP46_CLIENT_NSEC or NVOY_NIP46_CLIENT_NSEC_FILE')
  return raw ? decodeNsec(raw) : file ? decodeNsec(readPrivateFile(file, 'NVOY_NIP46_CLIENT_NSEC')) : generateSecretKey()
}

function makeNip46(bunkerUri: string, env: NodeJS.ProcessEnv = process.env): { signer: Signer; pubkey: string } {
  const m = BUNKER_PUBKEY.exec(bunkerUri.trim())
  if (!m) throw new Error('NVOY_BUNKER_URI is not a valid bunker://<64-hex-pubkey>?… connection string')
  const pubkey = m[1].toLowerCase()
  const uri = new URL(bunkerUri.trim())
  const relays = [...new Set(uri.searchParams.getAll('relay'))]
  if (!relays.length) throw new Error('NVOY_BUNKER_URI carries no ?relay= — the signer would have nowhere to listen')
  const secret = uri.searchParams.get('secret') ?? ''
  const clientKey = loadNip46ClientKey(env)
  const clientPk = getPublicKey(clientKey)
  const convKey = nip44.v2.utils.getConversationKey(clientKey, pubkey)
  const pool = new SimplePool()
  const pending = new Map<string, { resolve: (v: string) => void; reject: (e: Error) => void }>()
  let subbed = false
  let connectedP: Promise<string> | null = null
  const ensureSub = () => {
    if (subbed) return
    subbed = true
    // single filter object, NOT an array — see note above
    pool.subscribeMany(relays, { kinds: [24133], authors: [pubkey], '#p': [clientPk] }, {
      onevent(e) {
        try {
          const msg = JSON.parse(nip44.v2.decrypt(e.content, convKey))
          const p = pending.get(msg.id)
          if (!p) return
          pending.delete(msg.id)
          if (msg.error) p.reject(new Error(`bunker: ${msg.error}`))
          else p.resolve(msg.result)
        } catch { /* not addressed to this session */ }
      },
    })
  }
  const rpc = (method: string, params: string[], timeoutMs = 60_000) =>
    new Promise<string>((resolve, reject) => {
      ensureSub()
      const id = randomUUID()
      pending.set(id, { resolve, reject })
      const ev = finalizeEvent({
        kind: 24133,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['p', pubkey]],
        content: nip44.v2.encrypt(JSON.stringify({ id, method, params }), convKey),
      }, clientKey)
      void Promise.allSettled(pool.publish(relays, ev))
      setTimeout(() => {
        if (pending.delete(id)) reject(new Error(`nip46 ${method} timed out after ${timeoutMs}ms`))
      }, timeoutMs)
    })
  // connect is best-effort: a fresh pairing needs it (the URI secret
  // auto-creates the connection), an established one answers RPCs without it —
  // a stale secret must never block an ACTIVE pairing.
  const ready = () => (connectedP ??= rpc('connect', [pubkey, secret], 15_000).catch(() => 'ack'))
  // get_public_key is asked ONCE per pairing. The answer cannot change for the life of
  // the connection, and every gift-wrap unwrap used to pay a bunker round trip for it
  // (#170). Deliberately NOT seeded from the URI-parsed `pubkey` above: that value is
  // the unverified claim #338 exists to check, and seeding it would make the check
  // compare the claim against itself. The first caller is bindIdentity at boot, so what
  // gets memoised is the confirmed answer. A FAILED call is not cached — a bunker that
  // was briefly unreachable must not leave the process permanently unable to ask.
  let publicKeyP: Promise<string> | null = null
  const signer: Signer = {
    getPublicKey: async () => {
      publicKeyP ??= (async () => { await ready(); return rpc('get_public_key', []) })()
      try {
        return await publicKeyP
      } catch (e) {
        publicKeyP = null
        throw e
      }
    },
    signEvent: async (event) => { await ready(); return JSON.parse(await rpc('sign_event', [JSON.stringify(event)])) },
    nip44Encrypt: async (pk, pt) => { await ready(); return rpc('nip44_encrypt', [pk, pt]) },
    nip44Decrypt: async (pk, ct) => { await ready(); return rpc('nip44_decrypt', [pk, ct]) },
  }
  return { signer, pubkey }
}

export function loadIdentity(
  argv: string[] = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env,
): Identity {
  const bunkerUri = loadBunkerUri(env)
  // Remote signer: the key is off-host. Selected explicitly (NVOY_SIGNER=nip46),
  // or implied when only a bunker URI is present, so it never shadows a local key.
  const wantsNip46 = /^nip46$/i.test(env.NVOY_SIGNER || '') ||
    (!!bunkerUri && !env.NVOY_NSEC && !env.NVOY_NCRYPTSEC_FILE && !argv.includes('--ephemeral'))
  if (wantsNip46) {
    if (!bunkerUri) throw new Error('NVOY_SIGNER=nip46 requires NVOY_BUNKER_URI_FILE (or legacy NVOY_BUNKER_URI)')
    const { signer, pubkey } = makeNip46(bunkerUri, env)
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
      'no agent identity: set NVOY_NSEC, or NVOY_NCRYPTSEC_FILE + NVOY_NCRYPTSEC_PASSPHRASE, or NVOY_SIGNER=nip46 + NVOY_BUNKER_URI_FILE, or pass --ephemeral',
    )
  }

  const pubkey = getPublicKey(secretKey)
  const signer = nipxxLocalSigner(secretKey) as Signer
  return { signer, secretKey, pubkey, npub: nip19.npubEncode(pubkey), source }
}

/**
 * Bind the process to the identity it is ALLOWED to be, before it can act (#338).
 *
 * Two identity claims exist and nothing compared them:
 *
 *   1. `identity.pubkey` — for a bunker, PARSED OUT OF THE URI. It is a claim made by a
 *      configuration file, and `nvoy_whoami` reports it verbatim.
 *   2. what the signer actually signs as — the bunker's own `get_public_key`.
 *
 * When a shared server's credential env points at one identity while a session believes it is
 * another, whoami answers with #1 and every signature is authored by #2. That is #338 exactly: a
 * remote agent's whoami returned a DIFFERENT agent's identity. Nothing was broken enough to fail;
 * the two answers simply came from different places.
 *
 * So: ask the signer who it is and refuse if it disagrees with the claim. This is a cold read-back
 * of identity — the same discipline as reading a published event back rather than trusting the OK.
 *
 * `NVOY_EXPECTED_PUBKEY` is the second half, and it is what makes a shared server safe to register
 * per-agent: the operator DECLARES which identity this process may be, and a process that resolves
 * to anyone else refuses to start rather than acting as them.
 *
 * It throws rather than warning. A server that cannot confirm which identity it holds must not act
 * as any of them — being unable to check is not the same as being fine.
 */
export async function bindIdentity(
  identity: Identity,
  env: NodeJS.ProcessEnv = process.env,
): Promise<Identity> {
  const claimed = String(identity.pubkey || '').toLowerCase()
  if (!HEX64.test(claimed)) throw new Error('identity has no usable public key; refusing to act')

  let resolved: string
  try {
    resolved = String(await identity.signer.getPublicKey() || '').toLowerCase()
  } catch (e) {
    // Do NOT fall through to the claim. An unreachable bunker means the identity is unconfirmed,
    // and an unconfirmed identity is the precise condition this check exists to refuse.
    throw new Error(
      `could not ask the signer which identity it holds (${(e as Error).message}) — refusing to act ` +
      'as an unconfirmed identity',
    )
  }
  if (!HEX64.test(resolved)) throw new Error('signer did not report a public key; refusing to act')
  if (resolved !== claimed) {
    throw new Error(
      `identity mismatch: configuration claims ${claimed.slice(0, 12)}… but the signer signs as ` +
      `${resolved.slice(0, 12)}…. whoami would report one and every signature would carry the ` +
      'other (#338). Refusing to act.',
    )
  }

  const declared = String(env.NVOY_EXPECTED_PUBKEY || '').trim().toLowerCase()
  if (declared) {
    if (!HEX64.test(declared)) throw new Error('NVOY_EXPECTED_PUBKEY must be a 64-character hex public key')
    if (declared !== resolved) {
      throw new Error(
        `bound to ${declared.slice(0, 12)}… but this signer is ${resolved.slice(0, 12)}… — ` +
        'refusing to act as another agent',
      )
    }
  }
  return identity
}

/** Default relay set; override with NVOY_RELAYS (comma-separated). */
export const DEFAULT_RELAYS = ['wss://nos.lol', 'wss://relay.primal.net']

export function loadRelays(env: NodeJS.ProcessEnv = process.env): string[] {
  const raw = env.NVOY_RELAYS
  if (!raw) return DEFAULT_RELAYS
  const urls = raw.split(',').map(s => s.trim()).filter(Boolean)
  if (urls.length === 0) return DEFAULT_RELAYS
  return urls
}
