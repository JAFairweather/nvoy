// vendored from JAFairweather/nostr-scoped-data-grants @ 681a462 — do not edit; npm run sync-lib
// relay.mjs — a ~40-line in-memory relay implementing just enough NIP-01:
// event storage, filter queries, and replacement semantics for addressable
// events. The protocol needs NOTHING more from a relay — which is the point.
// Swap this for a SimplePool against wss:// relays and the demo is unchanged.

import { matchFilter, verifyEvent } from 'nostr-tools'

const isAddressable = (kind) => kind >= 30000 && kind < 40000
const isReplaceable = (kind) => kind === 0 || kind === 3 || (kind >= 10000 && kind < 20000)
const dTag = (event) => event.tags.find(t => t[0] === 'd')?.[1] ?? ''

// NIP-01 replacement identity: kind+pubkey+d for addressable events,
// kind+pubkey for replaceable ones, none for regular events.
const replaceKey = (e) =>
  isAddressable(e.kind) ? `${e.kind}:${e.pubkey}:${dTag(e)}`
  : isReplaceable(e.kind) ? `${e.kind}:${e.pubkey}`
  : null

export class Relay {
  events = []

  publish(event) {
    if (!verifyEvent(event)) throw new Error('invalid signature')
    const key = replaceKey(event)
    if (key) this.events = this.events.filter(e => replaceKey(e) !== key)
    this.events.push(event)
  }

  query(filter) {
    return this.events
      .filter(e => matchFilter(filter, e))
      .sort((a, b) => b.created_at - a.created_at)
  }

  /** What an adversarial relay operator actually learns. */
  observerView() {
    return this.events.map(e => ({
      kind: e.kind,
      pubkey: e.pubkey.slice(0, 8) + '…',
      d: dTag(e) || undefined,
      bytes: e.content.length,
      content_preview: e.content.slice(0, 40) + '…',
    }))
  }
}
