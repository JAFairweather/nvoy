// grants.ts — Grant Index sync: receive gift-wrapped 440 grants, carry the
// nvoy terms, detect supersession.
//
// Deviation from "just call lib.receiveGrants", recorded: the vendored lib's
// receiveGrants() parses only { scope_key, scope_name } out of the rumor
// content — it predates the nvoy terms extension and drops it. This module
// therefore unwraps the gift wraps itself, using nostr-tools primitives and
// mirroring the lib's authenticated unwrap exactly (verify the kind-13 seal's
// signature, require rumor.pubkey === seal.pubkey — nostr-tools' own
// nip59.unwrapEvent skips both checks, so it is NOT used). Supersession
// (latestGrants) stays the vendored lib's.

import { getPublicKey, nip19, nip44, verifyEvent } from 'nostr-tools'
import { KIND_DATA_SET, KIND_GRANT, latestGrants, type RelayLike } from '../../lib/nipxx.mjs'
import { parseTerms, termsStatus, type GrantStatus, type NvoyTerms } from './terms.js'

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
}

const b64decode = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0))

/**
 * Collect, authenticate, and parse all grants gift-wrapped to this key.
 * Malformed or unauthenticated wraps are skipped, never fatal — anyone can
 * address a 1059 to us.
 */
export async function receiveGrants(relay: RelayLike, secretKey: Uint8Array): Promise<HeldGrant[]> {
  const pub = getPublicKey(secretKey)
  const conv = (pk: string) => nip44.v2.utils.getConversationKey(secretKey, pk)
  const wraps = await relay.query({ kinds: [1059], '#p': [pub] })

  const grants: HeldGrant[] = []
  for (const wrap of wraps) {
    let rumor: any
    try {
      const seal = JSON.parse(nip44.v2.decrypt(wrap.content, conv(wrap.pubkey)))
      if (seal.kind !== 13 || !verifyEvent(seal)) continue // unauthenticated seal
      rumor = JSON.parse(nip44.v2.decrypt(seal.content, conv(seal.pubkey)))
      if (rumor.pubkey !== seal.pubkey) continue // sender impersonation
    } catch {
      continue
    }
    if (rumor.kind !== KIND_GRANT) continue

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

export { latestGrants }

/**
 * active | expired, from the nvoy terms' expires_at or (fallback) the
 * rumor's NIP-40 expiration tag. 'revoked-detected' arrives in M2.
 */
export function grantStatus(g: HeldGrant, nowSec = Math.floor(Date.now() / 1000)): GrantStatus {
  if (g.terms?.expires_at !== undefined) return termsStatus(g.terms, nowSec)
  if (g.expiration !== undefined && g.expiration <= nowSec) return 'expired'
  return 'active'
}

/**
 * The server's view of its held grants: re-queries wraps with a small TTL
 * cache (grants can arrive at any time; a miss forces refresh once).
 */
export class GrantStore {
  private cache: HeldGrant[] | null = null
  private fetchedAt = 0

  constructor(
    private relay: RelayLike,
    private secretKey: Uint8Array,
    private ttlMs = 60_000,
  ) {}

  async list(opts: { maxAgeMs?: number } = {}): Promise<HeldGrant[]> {
    const maxAge = opts.maxAgeMs ?? this.ttlMs
    if (this.cache === null || Date.now() - this.fetchedAt > maxAge) {
      this.cache = latestGrants(await receiveGrants(this.relay, this.secretKey))
      this.fetchedAt = Date.now()
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
}

/** Accept npub1... or 64-char hex; return hex. */
export function toHexPubkey(author: string): string {
  const s = author.trim()
  if (/^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase()
  const { type, data } = nip19.decode(s)
  if (type !== 'npub') throw new Error(`expected npub or hex pubkey, got ${type}`)
  return data as string
}
