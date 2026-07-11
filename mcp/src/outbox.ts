// outbox.ts — the agent's own 30440 for results (spec §6.5): outputs come
// home over the same primitive pointing the other way. One outbox scope per
// delegator (opaque d, agent-held scope key); the first write publishes and
// grants it back to the delegator, later writes republish under the same key
// — live update, no re-grant needed.
//
// Key persistence (decision recorded in CLAUDE.md): for a persistent agent
// identity (NVOY_NSEC / ncryptsec) the outbox scope keys live in the agent's
// OWN kind-10440 Grant Index — encrypted to self on the relays, recoverable
// from the agent nsec alone, zero disk writes (the no_persist discipline
// stays intact; these are the agent's own keys, not delegated data). For an
// --ephemeral identity the record is memory-only: a throwaway key's index
// would be unrecoverable ciphertext noise on the relays.

import { wrapEvent } from 'nostr-tools/nip59'
import {
  KIND_DATA_SET, KIND_GRANT, newScopeKey, publishScope,
  loadGrantIndex, saveGrantIndex, toIssuedEntry, fromIssuedEntry,
  type RelayLike,
} from '../../lib/nipxx.mjs'
import type { Identity } from './identity.js'

interface OutboxRecord {
  scopeId: string
  generation: number
  scopeKey: Uint8Array
}

/** Opaque scope id — semantic names in `d` tags leak disclosure structure. */
const opaqueScopeId = () =>
  [...crypto.getRandomValues(new Uint8Array(6))].map(b => 'abcdefghijklmnopqrstuvwxyz234567'[b % 32]).join('')

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))

export class Outbox {
  private records = new Map<string, OutboxRecord>() // delegator pubkey → record
  private index: Record<string, unknown> | null = null
  private loaded = false
  readonly persist: boolean

  constructor(
    private relay: RelayLike,
    private identity: Identity,
  ) {
    this.persist = identity.source !== 'ephemeral'
  }

  /** Recover outbox records from the agent's own Grant Index (persistent
   *  identities only) — issued entries keyed by the nvoy_outbox map. */
  private async ensureLoaded(): Promise<void> {
    if (this.loaded) return
    this.loaded = true
    if (!this.persist) {
      this.index = null
      return
    }
    const index = (await loadGrantIndex(this.relay, this.identity.secretKey)) as Record<string, unknown>
    this.index = index
    const map = (index.nvoy_outbox ?? {}) as Record<string, string>
    const issued = Array.isArray(index.issued) ? index.issued : []
    for (const [delegator, scopeId] of Object.entries(map)) {
      const entry = issued.find((e: { scope?: string }) => e?.scope === scopeId)
      if (!entry) continue
      const rec = fromIssuedEntry(entry)
      this.records.set(delegator, { scopeId: rec.scopeId, generation: rec.generation, scopeKey: rec.scopeKey })
    }
  }

  private async save(): Promise<void> {
    if (!this.persist) return
    const index = this.index ?? { issued: [], received: [] }
    const outboxScopes = new Set([...this.records.values()].map(r => r.scopeId))
    const issued = (Array.isArray(index.issued) ? index.issued : [])
      .filter((e: { scope?: string }) => !outboxScopes.has(e?.scope ?? ''))
    for (const [delegator, rec] of this.records)
      issued.push(toIssuedEntry(
        { scopeId: rec.scopeId, scopeName: 'agent output', generation: rec.generation, scopeKey: rec.scopeKey },
        [delegator],
      ))
    index.issued = issued
    index.nvoy_outbox = Object.fromEntries([...this.records].map(([delegator, r]) => [delegator, r.scopeId]))
    this.index = index
    await saveGrantIndex(this.relay, this.identity.secretKey, index as { issued: unknown[]; received: unknown[] })
  }

  /** Grant the outbox scope back to the delegator (§6.5) — the standard 440
   *  rumor with an nvoy terms object naming its purpose. */
  private async grantBack(delegatorPub: string, rec: OutboxRecord): Promise<void> {
    const rumor = {
      kind: KIND_GRANT,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['a', `${KIND_DATA_SET}:${this.identity.pubkey}:${rec.scopeId}`],
        ['v', String(rec.generation)],
      ],
      content: JSON.stringify({
        scope_key: b64(rec.scopeKey),
        scope_name: 'agent output',
        nvoy: { nvoy: 1, purpose: 'agent output' },
      }),
    }
    const wrap = wrapEvent(rumor, this.identity.secretKey, delegatorPub)
    await this.relay.publish(wrap)
  }

  /**
   * Upsert this agent's output scope for `delegatorPub`: publish the payload
   * (first write creates scope + grants it back; later writes republish under
   * the same key — the delegator's next dereference sees the new content).
   */
  async write(
    delegatorPub: string,
    payload: Record<string, unknown>,
  ): Promise<{ scopeId: string; generation: number; firstWrite: boolean; persisted: boolean }> {
    await this.ensureLoaded()
    let rec = this.records.get(delegatorPub)
    const firstWrite = !rec
    if (!rec) {
      rec = { scopeId: opaqueScopeId(), generation: 1, scopeKey: newScopeKey() }
      this.records.set(delegatorPub, rec)
    }
    await publishScope(this.relay, this.identity.secretKey, {
      scopeId: rec.scopeId, generation: rec.generation, scopeKey: rec.scopeKey, payload,
    })
    if (firstWrite) {
      await this.grantBack(delegatorPub, rec)
      await this.save()
    }
    return { scopeId: rec.scopeId, generation: rec.generation, firstWrite, persisted: this.persist }
  }

  /** Zeroize outbox key material (shutdown hygiene — persistent identities
   *  recover them from their own Grant Index). */
  zeroizeAll(): void {
    for (const rec of this.records.values()) rec.scopeKey.fill(0)
    this.records.clear()
  }
}
