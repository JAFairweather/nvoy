// vendored from JAFairweather/nostr-scoped-data-grants @ 681a462 — do not edit; npm run sync-lib
// liverelay.mjs — the same publish/query interface as relay.mjs, backed by
// nostr-tools SimplePool against real public relays. The protocol code in
// nipxx.mjs is untouched; only the transport changes.

import { SimplePool, useWebSocketImplementation } from 'nostr-tools/pool'

// Node >= 21 ships a global WebSocket; older versions need the ws package.
if (typeof WebSocket === 'undefined') {
  const { default: WS } = await import('ws')
  useWebSocketImplementation(WS)
}

export class LiveRelay {
  constructor(urls) {
    this.urls = urls
    this.pool = new SimplePool()
  }

  /** Publish to all relays; resolve when at least one relay ACKs.
   *  Some relays rate-limit by never replying, so each publish races an
   *  8s timeout — a silent relay counts as a rejection, not a hang. */
  async publish(event) {
    const timeout = () => new Promise((_, rej) =>
      setTimeout(() => rej(new Error('timeout: relay never replied')), 8000))
    const results = await Promise.allSettled(
      this.pool.publish(this.urls, event).map(p => Promise.race([p, timeout()])))
    const acks = results.filter(r => r.status === 'fulfilled').length
    const rejections = results
      .filter(r => r.status === 'rejected')
      .map(r => String(r.reason).slice(0, 60))
    if (acks === 0) throw new Error(`no relay accepted kind ${event.kind}: ${rejections.join(' | ')}`)
    return { acks, of: this.urls.length, rejections }
  }

  /** Query all relays, newest first, deduplicated by event id. */
  async query(filter) {
    const events = await this.pool.querySync(this.urls, filter, { maxWait: 4000 })
    const seen = new Set()
    return events
      .filter(e => !seen.has(e.id) && seen.add(e.id))
      .sort((a, b) => b.created_at - a.created_at)
  }

  close() { this.pool.close(this.urls) }
}

/** Wrap the synchronous in-memory relay in the same async interface. */
export class LocalRelay {
  constructor(inner) { this.inner = inner }
  async publish(event) { this.inner.publish(event); return { acks: 1, of: 1, rejections: [] } }
  async query(filter) { return this.inner.query(filter) }
  close() {}
}
