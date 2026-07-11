// terms.ts — parse/validate nvoy terms objects (spec §4).
//
// A 440 grant payload MAY carry an nvoy terms object alongside the standard
// fields (scope_key, scope_name). Vanilla NIP-DA clients ignore it; Nvoy
// runtimes honor it. Every term is a compliance guarantee, not cryptography —
// parsing is therefore deliberately tolerant: an absent or malformed terms
// object degrades to a vanilla grant (terms = null), never to an error.
//
// Accepted carrier shapes (the spec's example is ambiguous between them):
//   nested:  { scope_key, scope_name, "nvoy": { "nvoy": 1, "purpose": ... } }
//   flat:    { scope_key, scope_name, "nvoy": 1, "purpose": ... }
// Nvoy's own delegation tooling emits the nested form.

export interface NvoyTerms {
  /** Terms format version. Currently 1. */
  nvoy: number
  /** Human-readable contract line; shown in the ledger, logged by runtimes. */
  purpose?: string
  /** Soft expiry (unix seconds) honored by the runtime. Hard expiry is the
   *  delegator console's TTL rotation, never agent cooperation. */
  expires_at?: number
  /** Serve scope data to model context only — no disk, no logs, no stores. */
  no_persist?: boolean
  /** Audit term: runtime refuses to re-wrap keys for third parties. */
  redelegate?: boolean
  /** Delegator would like results granted back via the agent's outbox. */
  reply_scope_requested?: boolean
  /** Delegator contact npub for claim/renewal/relinquish notices. */
  contact?: string
  /** Relinquish automatically on task completion / at expires_at (§6.6). */
  auto_relinquish?: boolean
}

const isObject = (x: unknown): x is Record<string, unknown> =>
  typeof x === 'object' && x !== null && !Array.isArray(x)

/** Copy a field only if it has the expected primitive type — wrong-typed
 *  fields are dropped, not fatal (tolerant reader). */
function take<T extends 'string' | 'number' | 'boolean'>(
  src: Record<string, unknown>, key: keyof NvoyTerms, type: T,
): unknown {
  const v = src[key]
  return typeof v === type ? v : undefined
}

/**
 * Extract the nvoy terms from a decoded grant content object.
 * Returns null for vanilla grants (no terms, or terms too malformed to trust).
 */
export function parseTerms(content: unknown): NvoyTerms | null {
  if (!isObject(content)) return null
  let carrier: Record<string, unknown>
  if (isObject(content.nvoy)) {
    carrier = content.nvoy // nested form; version may live inside
  } else if (typeof content.nvoy === 'number') {
    carrier = content // flat form; the payload itself carries the terms
  } else {
    return null
  }
  const version = typeof carrier.nvoy === 'number' ? carrier.nvoy : 1
  const terms: NvoyTerms = {
    nvoy: version,
    purpose: take(carrier, 'purpose', 'string') as string | undefined,
    expires_at: take(carrier, 'expires_at', 'number') as number | undefined,
    no_persist: take(carrier, 'no_persist', 'boolean') as boolean | undefined,
    redelegate: take(carrier, 'redelegate', 'boolean') as boolean | undefined,
    reply_scope_requested: take(carrier, 'reply_scope_requested', 'boolean') as boolean | undefined,
    contact: take(carrier, 'contact', 'string') as string | undefined,
    auto_relinquish: take(carrier, 'auto_relinquish', 'boolean') as boolean | undefined,
  }
  // drop undefined keys so serialized terms stay clean
  for (const k of Object.keys(terms) as (keyof NvoyTerms)[])
    if (terms[k] === undefined) delete terms[k]
  return terms
}

/** Grant status: active | expired (per expires_at, soft — runtime honors it)
 *  | revoked-detected (v-supersession verified against a fresh 30440, §6.3). */
export type GrantStatus = 'active' | 'expired' | 'revoked-detected'

export function termsStatus(terms: NvoyTerms | null, nowSec = Math.floor(Date.now() / 1000)): GrantStatus {
  if (terms?.expires_at !== undefined && terms.expires_at <= nowSec) return 'expired'
  return 'active'
}
