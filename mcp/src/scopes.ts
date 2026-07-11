// scopes.ts — dereference and decrypt scoped data sets (spec §5).
//
// Stateless-dereference contract: delegated data is working context, never
// state. Reads go through a short memory-only TTL cache (default 60s);
// max_age: 0 forces a fresh relay fetch. Failed reads (stale/missing) are
// never cached — a revocation check must always see a live fetch.
//
// no_persist discipline (spec §5), applied to EVERY entry (uniform is
// strictly safer than per-terms): plaintext lives only in this Map; expired
// entries are scrubbed by a sweeper, not merely skipped; destroy() scrubs
// everything on shutdown. Zeroization honesty: JS strings are immutable, so
// "scrub" for decoded JSON means dropping every reference and letting GC
// reclaim it — the 32-byte scope keys (in grants.ts) are genuinely
// overwritten. Disclosed here per family convention.

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
  private sweeper: NodeJS.Timeout

  constructor(
    private relay: RelayLike,
    private ttlMs = 60_000,
    sweepMs = 15_000,
  ) {
    // Scrub expired plaintext even if nobody reads again. unref() so an idle
    // sweeper never keeps the process alive (tests, CLI one-shots).
    this.sweeper = setInterval(() => this.sweep(), sweepMs)
    this.sweeper.unref?.()
  }

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
    if (result.status === 'ok') this.entries.set(key, { at: Date.now(), result })
    else this.entries.delete(key) // failed reads are never cached; drop any prior plaintext
    return result
  }

  /** Drop the entry without scrubbing (plain cache invalidation). */
  invalidate(publisher: string, scopeId: string): void {
    this.entries.delete(`${publisher}:${scopeId}`)
  }

  /** Scrub cached plaintext for one scope (revocation path, §6.3). */
  zeroize(publisher: string, scopeId: string): void {
    const key = `${publisher}:${scopeId}`
    const entry = this.entries.get(key)
    if (entry) scrub(entry)
    this.entries.delete(key)
  }

  /** Scrub everything; used on shutdown and by tests. */
  clear(): void {
    for (const entry of this.entries.values()) scrub(entry)
    this.entries.clear()
  }

  /** Shutdown: scrub all plaintext and stop the sweeper. */
  destroy(): void {
    clearInterval(this.sweeper)
    this.clear()
  }

  private sweep(): void {
    const cutoff = Date.now() - this.ttlMs
    for (const [key, entry] of this.entries) {
      if (entry.at < cutoff) {
        scrub(entry)
        this.entries.delete(key)
      }
    }
  }
}

/** Best-effort plaintext scrub — sever every reference we hold. */
function scrub(entry: CacheEntry): void {
  const r = entry.result as unknown as Record<string, unknown>
  if (r && typeof r === 'object') {
    if (r.data && typeof r.data === 'object') for (const k of Object.keys(r.data)) delete (r.data as any)[k]
    delete r.data
  }
  ;(entry as any).result = null
}
