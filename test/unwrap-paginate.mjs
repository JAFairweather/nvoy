// nvoy#9 offline proof: unwrapRumors must survive relay default caps.
//
//   node test/unwrap-paginate.mjs
//
// The failure this pins: gift-wrap created_at is fuzzed up to 2 days back, so
// a FRESH access request can sort below dozens of older wraps; a single
// un-limited query returns a relay's newest-N and the request silently never
// surfaces. The fix paginates with `until` until exhaustion. Real NIP-59
// wraps, real nip44, real signatures; the relay is a fake that enforces a
// newest-N cap the way real relays do.
import assert from 'node:assert'
import { finalizeEvent, generateSecretKey, getPublicKey, nip44 } from 'nostr-tools'
import { unwrapRumors, receiveNotices } from '../console/nvoygrant.mjs'

const DIRECTOR_SK = generateSecretKey()
const DIRECTOR = getPublicKey(DIRECTOR_SK)
const now = Math.floor(Date.now() / 1000)

// A real double-layer wrap: rumor (unsigned) → kind-13 seal (sender-signed,
// nip44 sender→recipient) → kind-1059 wrap (ephemeral-signed, nip44 eph→recipient).
function wrapTo(recipient, rumorKind, content, createdAt, senderSk = generateSecretKey()) {
  const senderPk = getPublicKey(senderSk)
  const rumor = { pubkey: senderPk, created_at: createdAt, kind: rumorKind, tags: [], content }
  const seal = finalizeEvent({
    kind: 13, created_at: createdAt,
    tags: [], content: nip44.v2.encrypt(JSON.stringify(rumor), nip44.v2.utils.getConversationKey(senderSk, recipient)),
  }, senderSk)
  const ephSk = generateSecretKey()
  return finalizeEvent({
    kind: 1059, created_at: createdAt,
    tags: [['p', recipient]],
    content: nip44.v2.encrypt(JSON.stringify(seal), nip44.v2.utils.getConversationKey(ephSk, recipient)),
  }, ephSk)
}

// A relay that behaves like a capped public relay: honors #p/kinds/until, then
// returns only the newest `cap` matches regardless of the requested limit.
function cappedRelay(events, cap) {
  return {
    queries: 0,
    async query(filter) {
      this.queries++
      let out = events.filter(e =>
        (!filter.kinds || filter.kinds.includes(e.kind)) &&
        (!filter['#p'] || e.tags.some(t => t[0] === 'p' && filter['#p'].includes(t[1]))) &&
        (!filter.until || e.created_at <= filter.until))
      out.sort((a, b) => b.created_at - a.created_at)
      return out.slice(0, Math.min(cap, filter.limit ?? cap))
    },
  }
}

const signer = {
  getPublicKey: async () => DIRECTOR,
  nip44Decrypt: async (pk, ct) => nip44.v2.decrypt(ct, nip44.v2.utils.getConversationKey(DIRECTOR_SK, pk)),
}

let n = 0, pass = 0
const t = async (name, fn) => { n++; try { await fn(); pass++; console.log(`ok - ${name}`) } catch (e) { console.error(`FAIL - ${name}\n   ${e.stack || e.message}`) } }

await t('the nvoy#9 repro: a back-fuzzed fresh request buried under a relay cap STILL surfaces', async () => {
  const events = []
  // 120 older chaff wraps (index self-copies, delegations…) with RECENT timestamps
  for (let i = 0; i < 120; i++) events.push(wrapTo(DIRECTOR, 999, JSON.stringify({ chaff: i }), now - i * 60))
  // the fresh access request, created_at fuzzed ~2 days into the past — sorts LAST
  events.push(wrapTo(DIRECTOR, 24440, JSON.stringify({ type: 'access_request', purpose: 'credential:google' }), now - 2 * 86400 + 300))
  const relay = cappedRelay(events, 100)   // relay caps every response at newest-100

  // The OLD behavior (one un-paginated page) provably loses it:
  const onePage = await relay.query({ kinds: [1059], '#p': [DIRECTOR] })
  assert.equal(onePage.length, 100, 'a single query returns only the cap')

  // The fixed reader walks past the cap and finds it:
  const stats = {}
  const rumors = await unwrapRumors(relay, signer, [24440], stats)
  assert.equal(rumors.length, 1, 'the buried access request is recovered')
  assert.equal(stats.wraps, 121, 'pagination saw every wrap')
  assert.ok(relay.queries > 1, 'more than one page was fetched')
})

await t('pagination terminates on an empty tail and dedups repeated events', async () => {
  const events = [wrapTo(DIRECTOR, 24440, JSON.stringify({ type: 'access_request', purpose: 'x' }), now)]
  const relay = cappedRelay(events, 100)
  const stats = {}
  const rumors = await unwrapRumors(relay, signer, [24440], stats)
  assert.equal(rumors.length, 1)
  assert.equal(stats.wraps, 1)
  assert.ok(relay.queries <= 2, 'one full page + one empty tail at most')
})

await t('undecryptable wraps are COUNTED, not silently dropped (mechanism 2)', async () => {
  const good = wrapTo(DIRECTOR, 24440, JSON.stringify({ type: 'access_request', purpose: 'ok' }), now)
  const garbage = { ...wrapTo(DIRECTOR, 24440, 'x', now - 10), content: 'not-even-nip44' }
  const relay = cappedRelay([good, garbage], 100)
  const stats = {}
  const rumors = await unwrapRumors(relay, signer, [24440], stats)
  assert.equal(rumors.length, 1)
  assert.equal(stats.undecryptable, 1, 'the unopenable wrap is visible in stats')
})

await t('receiveNotices threads stats through to the console surface', async () => {
  const req = wrapTo(DIRECTOR, 24440, JSON.stringify({ type: 'access_request', purpose: 'credential:google' }), now)
  const relay = cappedRelay([req], 100)
  const stats = {}
  const notices = await receiveNotices(relay, signer, stats)
  assert.equal(notices.accessRequests.length, 1)
  assert.equal(stats.undecryptable, 0)
})

console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
