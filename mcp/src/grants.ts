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
 * Remembers what a gift wrap unwrapped to, keyed on the wrap's event id.
 *
 * A gift wrap is immutable and addressed to exactly one key, so its plaintext cannot
 * change — re-decrypting one is pure waste. Under a NIP-46 bunker it is not cheap
 * waste: each unwrap is TWO remote signing calls, so an idle server was spending 2N
 * bunker RPCs a minute for the life of the process, where N is every wrap the identity
 * had ever received and only grows (#170).
 *
 * It holds plaintext, so it lives under the same no_persist rule as everything else
 * (spec §5): in memory only, never written — and, the part that actually matters,
 * evicted the moment the grant it carries is revoked or relinquished. A zeroized
 * scopeKey sitting next to a live base64 copy of the same key in a cache is a
 * zeroization that does not zeroize.
 */
export class UnwrapMemo {
  /** wrap id → the authenticated rumor, or null for "this wrap yields nothing". */
  private byWrap = new Map<string, any | null>()

  constructor(private limit = 2_000) {}

  has(wrapId: string): boolean {
    return this.byWrap.has(wrapId)
  }

  get(wrapId: string): any | null {
    return this.byWrap.get(wrapId) ?? null
  }

  set(wrapId: string, rumor: any | null): void {
    // Crude bound, deliberately: overflowing costs one re-unwrap cycle, whereas a memo
    // that grows without limit is a slower version of the defect it was written to fix.
    if (this.byWrap.size >= this.limit) this.byWrap.clear()
    this.byWrap.set(wrapId, rumor)
  }

  /** Drop every remembered rumor the predicate matches. Returns how many went. */
  forget(match: (rumor: any) => boolean): number {
    let dropped = 0
    for (const [id, rumor] of this.byWrap) {
      if (rumor && match(rumor)) {
        this.byWrap.delete(id)
        dropped++
      }
    }
    return dropped
  }

  clear(): void {
    this.byWrap.clear()
  }

  get size(): number {
    return this.byWrap.size
  }
}

/**
 * Unwrap every gift wrap addressed to this key and return the authenticated
 * rumors of the wanted kinds. Malformed or unauthenticated wraps are skipped,
 * never fatal — anyone can address a 1059 to us.
 */
async function unwrapRumors(
  relay: RelayLike,
  key: KeyOrSigner,
  kinds: number[],
  memo?: UnwrapMemo,
): Promise<any[]> {
  const signer = toSigner(key)
  const pub = await signer.getPublicKey()
  const wraps = await relay.query({ kinds: [1059], '#p': [pub] })

  const rumors: any[] = []
  for (const wrap of wraps) {
    const id = typeof wrap.id === 'string' ? wrap.id : null
    if (id && memo?.has(id)) {
      const known = memo.get(id)
      if (known && kinds.includes(known.kind)) rumors.push(known)
      continue
    }

    let rumor: any = null
    try {
      // Signer-driven unwrap: nip44Decrypt handles the conversation key (a raw
      // key locally, a remote NIP-46 call under a bunker signer). Matches the
      // nipxx giftUnwrap ceremony.
      const seal = JSON.parse(await signer.nip44Decrypt(wrap.pubkey, wrap.content))
      if (seal.kind === 13 && verifyEvent(seal)) {
        // unauthenticated seals fall through as null
        const inner = JSON.parse(await signer.nip44Decrypt(seal.pubkey, seal.content))
        if (inner.pubkey === seal.pubkey) rumor = inner // else: sender impersonation
      }
    } catch {
      rumor = null
    }

    // Remember the OUTCOME, whether or not this caller wanted the kind. The two callers
    // want different kinds out of the same mailbox, so a memo that only remembered
    // wanted rumors would leave whichever ran second re-decrypting everything.
    if (id) memo?.set(id, rumor)
    if (rumor && kinds.includes(rumor.kind)) rumors.push(rumor)
  }
  return rumors
}

/** Collect, authenticate, and parse all grants gift-wrapped to this key. */
export async function receiveGrants(
  relay: RelayLike,
  key: KeyOrSigner,
  memo?: UnwrapMemo,
): Promise<HeldGrant[]> {
  const rumors = await unwrapRumors(relay, key, [KIND_GRANT], memo)
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
  memo?: UnwrapMemo,
): Promise<{ content: unknown; noticed_at: number } | null> {
  const address = `${KIND_DATA_SET}:${publisher}:${scopeId}`
  const rumors = await unwrapRumors(relay, key, [KIND_REVOCATION], memo)
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
  /** Shared by every unwrap this store drives, so one mailbox is decrypted once (#170). */
  readonly memo = new UnwrapMemo()

  constructor(
    private relay: RelayLike,
    private key: KeyOrSigner,
    private ttlMs = 60_000,
  ) {}

  async list(opts: { maxAgeMs?: number } = {}): Promise<HeldGrant[]> {
    const maxAge = opts.maxAgeMs ?? this.ttlMs
    // `maxAge <= 0` is tested separately, not left to the subtraction: find() passes 0 to
    // MEAN "do not use the cache", and within the same millisecond `Date.now() - fetchedAt
    // > 0` is false — so the forced refresh silently did not happen for any caller quick
    // enough to hit the same tick, and a grant that had just arrived stayed unfound.
    if (this.cache === null || maxAge <= 0 || Date.now() - this.fetchedAt > maxAge) {
      this.cache = latestGrants(await receiveGrants(this.relay, this.key, this.memo))
      this.fetchedAt = Date.now()
      for (const g of this.cache) this.applyRevocation(g)
    }
    return this.cache
  }

  /**
   * The grants this process is holding RIGHT NOW: no relay query, no unwrap, no bunker.
   *
   * For callers that act on held key material rather than on the delegator's current
   * intent — the auto_relinquish sweeper is the one. Relinquishment destroys the local
   * copy of a scope key, and this cache IS the local copy: a grant that has never been
   * unwrapped is one this process holds no key for, so there is nothing to destroy.
   * Paying a full mailbox unwrap on a timer to rediscover that, forever, was #170.
   */
  peek(): HeldGrant[] {
    return this.cache ?? []
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
    this.forgetMemoised(publisher, scopeId, record.generation)
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
    this.forgetMemoised(publisher, scopeId, record.generation)
    return record
  }

  /**
   * Drop the remembered plaintext of a grant whose key material was just zeroized.
   * Without this the memo would still hold the base64 scope_key for a grant whose
   * Uint8Array we had just filled with zeros — a zeroization that does not zeroize.
   * The wrap stays on the relay either way; what we control is our own copy.
   */
  private forgetMemoised(publisher: string, scopeId: string, generation: number): void {
    const address = `${KIND_DATA_SET}:${publisher}:${scopeId}`
    this.memo.forget(r => {
      if (r.kind !== KIND_GRANT || r.pubkey !== publisher) return false
      if (r.tags?.find?.((t: string[]) => t[0] === 'a')?.[1] !== address) return false
      return Number(r.tags.find((t: string[]) => t[0] === 'v')?.[1] ?? 0) <= generation
    })
  }

  /** Zeroize every held scope key (shutdown path — spec §5). */
  zeroizeAll(): void {
    for (const g of this.cache ?? []) g.scopeKey.fill(0)
    this.cache = null
    this.memo.clear() // plaintext lives here too — shutdown must not leave it behind
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
