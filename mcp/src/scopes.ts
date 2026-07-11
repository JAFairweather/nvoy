// scopes.ts — dereference and decrypt scoped data sets (spec §5).
//
// Stateless-dereference contract: delegated data is working context, never
// state. Reads go through a short memory-only TTL cache (default 60s);
// max_age: 0 forces a fresh relay fetch. Full no_persist enforcement
// (zeroization, log interception conformance) lands in M2; nothing here
// writes scope plaintext anywhere but this in-memory map even now.

import { fetchScope, type RelayLike, type ScopeFetchResult } from '../../lib/nipxx.mjs'
import type { HeldGrant } from './grants.js'

export interface ScopeReadResult extends ScopeFetchResult {
  /** unix seconds when this payload was actually fetched from relays */
  fetched_at: number
}

interface CacheEntry {
  at: number // ms
  result: ScopeReadResult
}

export class ScopeCache {
  private entries = new Map<string, CacheEntry>()

  constructor(
    private relay: RelayLike,
    private ttlMs = 60_000,
  ) {}

  /**
   * Read a scope through the cache.
   * `maxAgeSec` (tool input max_age) caps acceptable staleness in seconds;
   * 0 forces a relay fetch. Default is the cache TTL.
   */
  async read(grant: HeldGrant, opts: { maxAgeSec?: number } = {}): Promise<ScopeReadResult> {
    const key = `${grant.publisher}:${grant.scopeId}`
    const maxAgeMs = opts.maxAgeSec !== undefined ? opts.maxAgeSec * 1000 : this.ttlMs
    const hit = this.entries.get(key)
    if (maxAgeMs > 0 && hit && Date.now() - hit.at < Math.min(maxAgeMs, this.ttlMs)) return hit.result

    const result: ScopeReadResult = {
      ...(await fetchScope(this.relay, grant)),
      fetched_at: Math.floor(Date.now() / 1000),
    }
    this.entries.set(key, { at: Date.now(), result })
    return result
  }

  invalidate(publisher: string, scopeId: string): void {
    this.entries.delete(`${publisher}:${scopeId}`)
  }

  clear(): void {
    this.entries.clear()
  }
}
