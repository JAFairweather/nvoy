// drafts.ts — draft offers for the Director's desk (nvoy#28; nact#37's
// delivery half under M7). Where the Outbox is ONE mutable scope per
// delegator (results, live-updated in place), a draft is the opposite shape:
// a FRESH scope per offer, granted once, withdrawable by tombstone — the
// wire Ngage's desk consumes (`draft:` namespace, one card per scope,
// rotation = withdrawn).
//
// This service signs because it custodies the runtime identity's key (the
// M7 cutover moved the Nactor's nsec here as NVOY_NSEC); the keyless runtime
// asks over the same network-isolated listener as every other tool. The
// namespace guard is deliberate: this desk mints DRAFT OFFERS — a scope_name
// outside `draft:` is refused, so the tool can never be bent into a generic
// sign-anything grant mint.
//
// The ledger is session-memory only, matching the runtime's own raised
// ledger: an offer is a session artifact (the grants themselves live on the
// relays), and a restart forgetting how to withdraw an old draft is honest —
// the Director's Pass button remains, and a fresh raise supersedes.

import {
  KIND_DATA_SET, newScopeKey, publishScope, grant,
  type RelayLike,
} from '../lib/nipxx.mjs'
import type { Identity } from './identity.js'

interface DraftRecord {
  generation: number
  grantee: string
}

/** Opaque scope id — same alphabet/derivation as the Outbox's (semantic
 *  names in `d` tags leak disclosure structure to relays). */
const opaqueScopeId = () =>
  [...crypto.getRandomValues(new Uint8Array(12))].map(b => 'abcdefghijklmnopqrstuvwxyz234567'[b % 32]).join('')

export class DraftDesk {
  private records = new Map<string, DraftRecord>() // scopeId → record

  constructor(
    private relay: RelayLike,
    private identity: Identity,
  ) {}

  /** Publish one draft offer: fresh scope + key, granted to the grantee.
   *  scope_name must live in the `draft:` namespace (guarded by the caller
   *  too — belt and suspenders at the signing boundary). */
  async publish(granteePubkey: string, payload: Record<string, unknown>, scopeName?: string) {
    const scopeId = opaqueScopeId()
    const name = scopeName ?? `draft:post/${scopeId.slice(0, 8)}`
    if (!name.startsWith('draft:')) throw new Error(`scope_name '${name}' is outside the draft: namespace — this desk mints draft offers only`)
    const scopeKey = newScopeKey()
    await publishScope(this.relay, this.identity.signer, { scopeId, generation: 1, scopeKey, payload })
    await grant(this.relay, this.identity.signer, granteePubkey, { scopeId, generation: 1, scopeKey, scopeName: name })
    this.records.set(scopeId, { generation: 1, grantee: granteePubkey })
    return { scopeId, generation: 1, scopeName: name }
  }

  /** Withdraw an offer minted this session: tombstone by SUPERSESSION —
   *  empty payload under a fresh key granted to no one, bumped generation.
   *  Replacement is destruction on NIP-01 relays, and the desk shows the
   *  draft withdrawn either way; deliberately NOT nipxx.deleteScope, whose
   *  advisory NIP-09 kind-5 would grow the relay's pinned event-kind surface
   *  (30440/1059/10440 — the observer invariant in mcp-conformance).
   *  Idempotent. */
  async withdraw(scopeId: string) {
    const rec = this.records.get(scopeId)
    if (!rec) return null
    if (rec.generation > 1) return { scopeId, generation: rec.generation }   // already tombstoned
    await publishScope(this.relay, this.identity.signer,
      { scopeId, generation: rec.generation + 1, scopeKey: newScopeKey(), payload: {} })
    rec.generation += 1
    return { scopeId, generation: rec.generation }
  }

  /** The session ledger (ids + generations only — payloads are not retained). */
  list() {
    return [...this.records.entries()].map(([scopeId, r]) => ({ scopeId, ...r }))
  }
}

export const DRAFT_KIND = KIND_DATA_SET
