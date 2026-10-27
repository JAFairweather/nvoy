// The relays that grants are read from, defined once (waggle#613 C3).
//
// Grants are issued to four relays (console/config.mjs DEFAULT_RELAYS), but every broker read them
// only from its manifest's `relays`, and five of the six fleet manifests leave out relay.nave.pub.
// Probed 2026-10-27 for the owner's 440/441s: relay.nave.pub 73/37, relay.ditto.pub 70/37,
// nos.lol 44/24, relay.primal.net 16/0. The relay holding the most was the one most brokers never
// asked, and a read that reached only primal would see revoked grants as live (all four agents
// went deaf on 2026-10-19 when nos.lol evicted theirs). So the grant read is the union of this set
// and whatever relays the caller was given, unless the caller pins its own set (below).
//
// No imports: the console and the bridge can vendor this file as it stands.

export const GRANT_RELAYS = ['wss://relay.nave.pub', 'wss://relay.ditto.pub', 'wss://nos.lol', 'wss://relay.primal.net']

const loopback = url => /^wss?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?(\/|$)/.test(url)
const clean = urls => [...new Set(urls.map(url => String(url).trim()).filter(Boolean))]

// The grant relays come first, then any extra ones the caller names. Two cases keep the caller's set
// exactly: an explicit `override` (a comma list, e.g. NVOY_GRANT_RELAYS), and a set made only of
// loopback relays, which is a local test and must not reach the public network.
export function grantReadRelays(relays = [], override = '') {
  if (override) return clean(String(override).split(','))
  const given = clean(relays)
  if (given.length && given.every(loopback)) return given
  return clean([...GRANT_RELAYS, ...given])
}
