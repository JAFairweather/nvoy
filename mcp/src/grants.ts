// grants.ts — Grant Index sync: receive gift-wrapped 440 grants, carry the
// nvoy terms, detect supersession, track detected revocations (spec §6.3).
//
// Deviation from "just call lib.receiveGrants", recorded: the vendored lib's
// receiveGrants() parses only { scope_key, scope_name } out of the rumor
// content — it predates the nvoy terms extension and drops it. This module
// therefore unwraps the gift wraps itself, using nostr-tools primitives and
// mirroring the lib's authenticated unwrap exactly (verify the kind-13 seal's
// signature, require rumor.pubkey === seal.pubkey — nostr-tools' own
// nip59.unwrapEvent skips both checks, so it is NOT used). Supersession
// (latestGrants) stays the vendored lib's.

import { nip19, verifyEvent } from 'nostr-tools'
// @ts-ignore — vendored .mjs, no types
import { KIND_DATA_SET, KIND_GRANT, latestGrants, localSigner, type RelayLike } from '../lib/nipxx.mjs'
import type { Signer } from './identity.js'

/** Accept a raw key (back-compat) or a signer (nip46). Uint8Array → local. */
type KeyOrSigner = Uint8Array | Signer
const toSigner = (k: KeyOrSigner): Signer => (k instanceof Uint8Array ? (localSigner(k) as Signer) : k)
import { parseTerms, termsStatus, type GrantStatus, type NvoyTerms } from './terms.js'

/** Grant Revocation notice (NIP-DA optional courtesy rumor, gift-wrapped). */
export const KIND_REVOCATION = 441

/** A detected revocation for (publisher, scope): every held grant at or
 *  below `generation` is dead. Runtime state — grants re-materialized from
 *  relay wraps get re-decorated (and their keys re-zeroized) on every
 *  GrantStore refresh. A later re-grant with a higher v supersedes it. */
export interface RevocationRecord {
  generation: number
  /** kind-441 notice content (parsed JSON or raw string), null if silent. */
  notice: unknown
  detected_at: number // unix seconds
}

/** A relinquishment this agent performed (§6.6 phase 1): the key material
 *  for (publisher, scope) at or below `generation` was destroyed locally.
 *  Runtime state, like revocations; a re-grant with higher v supersedes. */
export interface RelinquishRecord {
  generation: number
  destroyed_at: number // unix seconds
  reason?: string
}

export interface HeldGrant {
  publisher: string // hex pubkey of the delegator
  scopeId: string // the 30440 `d` tag
  scopeName?: string
  relayHint?: string
  generation: number // `v` — scope key generation this grant unlocks
  scopeKey: Uint8Array
  issuedAt: number
  /** NIP-40 style expiration tag on the rumor, if present (advisory). */
  expiration?: number
  /** Parsed nvoy terms; null = vanilla NIP-DA grant. */
  terms: NvoyTerms | null
  /** Set when this grant's scope key was rotated past it (§6.3). The
   *  scopeKey is zeroized the moment this is set. */
  revoked?: RevocationRecord
  /** Set when this agent relinquished the grant (§6.6). The scopeKey is
   *  zeroized the moment this is set. */
  relinquished?: RelinquishRecord
}

const b64decode = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0))

/**
 * Unwrap every gift wrap addressed to this key and return the authenticated
 * rumors of the wanted kinds. Malformed or unauthenticated wraps are skipped,
 * never fatal — anyone can address a 1059 to us.
 */
async function unwrapRumors(relay: RelayLike, key: KeyOrSigner, kinds: number[]): Promise<any[]> {
  const signer = toSigner(key)
  const pub = await signer.getPublicKey()
  const wraps = await relay.query({ kinds: [1059], '#p': [pub] })

  const rumors: any[] = []
  for (const wrap of wraps) {
    try {
      // Signer-driven unwrap: nip44Decrypt handles the conversation key (a raw
      // key locally, a remote NIP-46 call under a bunker signer). Matches the
      // nipxx giftUnwrap ceremony.
      const seal = JSON.parse(await signer.nip44Decrypt(wrap.pubkey, wrap.content))
      if (seal.kind !== 13 || !verifyEvent(seal)) continue // unauthenticated seal
      const rumor = JSON.parse(await signer.nip44Decrypt(seal.pubkey, seal.content))
      if (rumor.pubkey !== seal.pubkey) continue // sender impersonation
      if (kinds.includes(rumor.kind)) rumors.push(rumor)
    } catch {
      continue
    }
  }
  return rumors
}

/** Collect, authenticate, and parse all grants gift-wrapped to this key. */
export async function receiveGrants(relay: RelayLike, key: KeyOrSigner): Promise<HeldGrant[]> {
  const rumors = await unwrapRumors(relay, key, [KIND_GRANT])
  const grants: HeldGrant[] = []
  for (const rumor of rumors) {
    try {
      const aTag = rumor.tags.find((t: string[]) => t[0] === 'a')
      const [kind, publisher, scopeId] = String(aTag[1]).split(':')
      if (Number(kind) !== KIND_DATA_SET || publisher !== rumor.pubkey) continue
      const content = JSON.parse(rumor.content)
      const expiration = rumor.tags.find((t: string[]) => t[0] === 'expiration')?.[1]
      grants.push({
        publisher,
        scopeId,
        scopeName: typeof content.scope_name === 'string' ? content.scope_name : undefined,
        relayHint: aTag[2] || undefined,
        generation: Number(rumor.tags.find((t: string[]) => t[0] === 'v')?.[1] ?? 0),
        scopeKey: b64decode(content.scope_key),
        issuedAt: rumor.created_at,
        expiration: expiration !== undefined ? Number(expiration) : undefined,
        terms: parseTerms(content),
      })
    } catch {
      continue
    }
  }
  return grants
}

/**
 * Look for a gift-wrapped kind-441 revocation notice for (publisher, scope)
 * addressed to this agent. Authenticated like grants: the notice only counts
 * if the sealed sender IS the scope's publisher. Returns the newest match,
 * or null (silent revocation is a publisher's right — absence proves nothing).
 */
export async function findRevocationNotice(
  relay: RelayLike,
  key: KeyOrSigner,
  publisher: string,
  scopeId: string,
): Promise<{ content: unknown; noticed_at: number } | null> {
  const address = `${KIND_DATA_SET}:${publisher}:${scopeId}`
  const rumors = await unwrapRumors(relay, key, [KIND_REVOCATION])
  let best: { content: unknown; noticed_at: number } | null = null
  for (const rumor of rumors) {
    if (rumor.pubkey !== publisher) continue
    const aTag = rumor.tags?.find?.((t: string[]) => t[0] === 'a')
    if (!aTag || aTag[1] !== address) continue
    let content: unknown = rumor.content === '' ? null : rumor.content
    try {
      content = JSON.parse(rumor.content)
    } catch {
      /* keep raw string */
    }
    if (!best || rumor.created_at > best.noticed_at) best = { content, noticed_at: rumor.created_at }
  }
  return best
}

export { latestGrants }

/**
 * revoked-detected | relinquished | expired | active. Revocation is a
 * verified fact about the key material and outranks everything; a
 * relinquishment is this runtime's own destruction record and outranks the
 * soft expiry terms.
 */
export function grantStatus(g: HeldGrant, nowSec = Math.floor(Date.now() / 1000)): GrantStatus {
  if (g.revoked) return 'revoked-detected'
  if (g.relinquished) return 'relinquished'
  if (g.terms?.expires_at !== undefined) return termsStatus(g.terms, nowSec)
  if (g.expiration !== undefined && g.expiration <= nowSec) return 'expired'
  return 'active'
}

/**
 * The server's view of its held grants: re-queries wraps with a small TTL
 * cache (grants can arrive at any time; a miss forces refresh once).
 * Detected revocations persist across refreshes: re-materialized grants at
 * or below the revoked generation are re-decorated and their scope keys
 * zeroized immediately (the wrap on the relay necessarily still yields the
 * key during unwrap — we drop it the same tick, and never serve it).
 */
export class GrantStore {
  private cache: HeldGrant[] | null = null
  private fetchedAt = 0
  private revocations = new Map<string, RevocationRecord>()
  private relinquishments = new Map<string, RelinquishRecord>()

  constructor(
    private relay: RelayLike,
    private key: KeyOrSigner,
    private ttlMs = 60_000,
  ) {}

  async list(opts: { maxAgeMs?: number } = {}): Promise<HeldGrant[]> {
    const maxAge = opts.maxAgeMs ?? this.ttlMs
    if (this.cache === null || Date.now() - this.fetchedAt > maxAge) {
      this.cache = latestGrants(await receiveGrants(this.relay, this.key))
      this.fetchedAt = Date.now()
      for (const g of this.cache) this.applyRevocation(g)
    }
    return this.cache
  }

  /** Find one grant; on a miss, force one refresh (it may have just arrived). */
  async find(authorPubkey: string, scopeId: string): Promise<HeldGrant | undefined> {
    const match = (g: HeldGrant) => g.publisher === authorPubkey && g.scopeId === scopeId
    let g = (await this.list()).find(match)
    if (!g) g = (await this.list({ maxAgeMs: 0 })).find(match)
    return g
  }

  /**
   * Record a verified revocation (§6.3) and zeroize the dead key material
   * held right now. A subsequent re-grant with generation > `generation`
   * comes back active.
   */
  markRevoked(publisher: string, scopeId: string, generation: number, notice: unknown): RevocationRecord {
    const key = `${publisher}:${scopeId}`
    const prev = this.revocations.get(key)
    const record: RevocationRecord =
      prev && prev.generation >= generation
        ? prev
        : { generation, notice, detected_at: Math.floor(Date.now() / 1000) }
    this.revocations.set(key, record)
    for (const g of this.cache ?? []) this.applyRevocation(g)
    return record
  }

  /**
   * Record a relinquishment (§6.6 phase 1) and zeroize the key material held
   * right now. Like revocations, runtime-only and re-applied on every refresh
   * (the wrap on the relay still yields the key during unwrap — we drop it
   * the same tick). A re-grant with generation > `generation` comes back
   * active: the delegator re-delegating IS the renewal path.
   */
  markRelinquished(publisher: string, scopeId: string, generation: number, destroyedAt: number, reason?: string): RelinquishRecord {
    const key = `${publisher}:${scopeId}`
    const prev = this.relinquishments.get(key)
    const record: RelinquishRecord =
      prev && prev.generation >= generation
        ? prev
        : { generation, destroyed_at: destroyedAt, ...(reason ? { reason } : {}) }
    this.relinquishments.set(key, record)
    for (const g of this.cache ?? []) this.applyRevocation(g)
    return record
  }

  /** Zeroize every held scope key (shutdown path — spec §5). */
  zeroizeAll(): void {
    for (const g of this.cache ?? []) g.scopeKey.fill(0)
    this.cache = null
  }

  private applyRevocation(g: HeldGrant): void {
    const key = `${g.publisher}:${g.scopeId}`
    const rec = this.revocations.get(key)
    if (rec && g.generation <= rec.generation) {
      g.revoked = rec
      g.scopeKey.fill(0) // real zeroization — it's bytes, not a JS string
    }
    const rel = this.relinquishments.get(key)
    if (rel && g.generation <= rel.generation) {
      g.relinquished = rel
      g.scopeKey.fill(0)
    }
  }
}

/** Accept npub1... or 64-char hex; return hex. */
export function toHexPubkey(author: string): string {
  const s = author.trim()
  if (/^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase()
  const { type, data } = nip19.decode(s)
  if (type !== 'npub') throw new Error(`expected npub or hex pubkey, got ${type}`)
  return data as string
}
