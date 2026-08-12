// unwrap-memo.mjs — a gift wrap is decrypted once, and a dead grant's plaintext dies with
// its key (#170).
//
//   node test/unwrap-memo.mjs
//
// The defect: a gift wrap is immutable, but every refresh re-decrypted the whole mailbox.
// Under a NIP-46 bunker each unwrap is TWO remote signing calls, so an idle server spent
// 2N bunker RPCs a minute forever, where N is every wrap the identity ever received and
// only grows. Observed at 254k bunker actions/day across six idle sessions.
//
// Caching plaintext is not free, so this suite has to hold two properties at once, and a
// test for either one alone is passed by a broken implementation:
//
//   1. The memo must not lose data — a warm read returns what a cold read returned, and a
//      NEW wrap is still decrypted. A memo that froze the first answer passes "no extra
//      decrypts" perfectly, which is why the new-wrap control below is not optional.
//   2. The memo must not outlive the key. Revocation zeroizes a scopeKey Uint8Array; if
//      the memo still held the base64 of that same key, the zeroization would zeroize
//      nothing. Asserted in both directions — the revoked grant's entry goes, the
//      untouched grant's entry stays.
//
// Real NIP-59 wraps, real nip44, real signatures. The signer counts its own calls, because
// the whole defect is invisible unless you count remote calls.

import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { finalizeEvent, generateSecretKey, getPublicKey, nip44 } from 'nostr-tools'
import { GrantStore, UnwrapMemo, findRevocationNotice, receiveGrants } from '../mcp/dist/grants.js'
import { sweepAutoRelinquish } from '../mcp/dist/app.js'

const KIND_GRANT = 440
const KIND_REVOCATION = 441
const KIND_DATA_SET = 30440

const AGENT_SK = generateSecretKey()
const AGENT = getPublicKey(AGENT_SK)
const PUB_SK = generateSecretKey()
const PUB = getPublicKey(PUB_SK)
const now = Math.floor(Date.now() / 1000)

const b64 = bytes => btoa(String.fromCharCode(...bytes))

/** rumor (unsigned) → kind-13 seal (sender-signed) → kind-1059 wrap (ephemeral-signed). */
function wrapTo(recipient, senderSk, rumorKind, tags, content, createdAt = now) {
  const senderPk = getPublicKey(senderSk)
  const rumor = { pubkey: senderPk, created_at: createdAt, kind: rumorKind, tags, content }
  const seal = finalizeEvent({
    kind: 13,
    created_at: createdAt,
    tags: [],
    content: nip44.v2.encrypt(JSON.stringify(rumor), nip44.v2.utils.getConversationKey(senderSk, recipient)),
  }, senderSk)
  const ephSk = generateSecretKey()
  return finalizeEvent({
    kind: 1059,
    created_at: createdAt,
    tags: [['p', recipient]],
    content: nip44.v2.encrypt(JSON.stringify(seal), nip44.v2.utils.getConversationKey(ephSk, recipient)),
  }, ephSk)
}

const grantWrap = (scopeId, generation, scopeKey) => wrapTo(
  AGENT, PUB_SK, KIND_GRANT,
  [['a', `${KIND_DATA_SET}:${PUB}:${scopeId}`], ['v', String(generation)], ['p', AGENT]],
  JSON.stringify({ scope_key: b64(scopeKey), scope_name: `scope ${scopeId}` }),
)

const ALPHA_KEY = new Uint8Array(32).fill(0xa1)
const BETA_KEY = new Uint8Array(32).fill(0xb2)
const GAMMA_KEY = new Uint8Array(32).fill(0xc3)

const alphaWrap = grantWrap('alpha', 1, ALPHA_KEY)
const betaWrap = grantWrap('beta', 1, BETA_KEY)
const revokeWrap = wrapTo(AGENT, PUB_SK, KIND_REVOCATION,
  [['a', `${KIND_DATA_SET}:${PUB}:alpha`]], JSON.stringify({ reason: 'rotated' }))
// A wrap nobody can open — it must be remembered as "yields nothing", not retried forever.
const junkWrap = { ...wrapTo(AGENT, PUB_SK, KIND_GRANT, [], 'x'), content: 'not-even-nip44' }

function countingSigner() {
  const s = {
    decrypts: 0,
    pubkeyCalls: 0,
    getPublicKey: async () => { s.pubkeyCalls++; return AGENT },
    nip44Decrypt: async (pk, ct) => {
      s.decrypts++
      return nip44.v2.decrypt(ct, nip44.v2.utils.getConversationKey(AGENT_SK, pk))
    },
    nip44Encrypt: async () => '',
    signEvent: async e => e,
  }
  return s
}

function relayOf(events) {
  return {
    queries: 0,
    events,
    async query(filter) {
      this.queries++
      return this.events.filter(e =>
        (!filter.kinds || filter.kinds.includes(e.kind)) &&
        (!filter['#p'] || e.tags.some(t => t[0] === 'p' && filter['#p'].includes(t[1]))))
    },
  }
}

let n = 0, pass = 0
const t = async (name, fn) => {
  n++
  try { await fn(); pass++; console.log(`ok - ${name}`) }
  catch (e) { console.error(`FAIL - ${name}\n   ${e.stack || e.message}`) }
}

// ---- property 1: the memo must not lose data -----------------------------------------
// The legitimate read is asserted FIRST and in full, so nothing below can pass vacuously.

await t('a cold read returns every grant, with the right key material', async () => {
  const relay = relayOf([alphaWrap, betaWrap, revokeWrap, junkWrap])
  const grants = await receiveGrants(relay, countingSigner(), new UnwrapMemo())
  assert.equal(grants.length, 2, 'both grants surface')
  const alpha = grants.find(g => g.scopeId === 'alpha')
  assert.ok(alpha, 'alpha is present')
  assert.deepEqual([...alpha.scopeKey], [...ALPHA_KEY], 'and carries its real scope key')
})

await t('a warm read returns the SAME grants and asks the signer for nothing', async () => {
  const relay = relayOf([alphaWrap, betaWrap, revokeWrap, junkWrap])
  const signer = countingSigner()
  const memo = new UnwrapMemo()

  const cold = await receiveGrants(relay, signer, memo)
  const coldDecrypts = signer.decrypts
  assert.ok(coldDecrypts > 0, 'the cold read really did decrypt (guards the rest of this test)')

  const warm = await receiveGrants(relay, signer, memo)
  assert.equal(signer.decrypts, coldDecrypts, 'the warm read cost ZERO further decrypts')
  assert.deepEqual(warm.map(g => g.scopeId).sort(), cold.map(g => g.scopeId).sort(),
    'and lost nothing — same grants')
  assert.deepEqual([...warm.find(g => g.scopeId === 'beta').scopeKey], [...BETA_KEY],
    'including the key material, not just the ids')
})

await t('NEGATIVE CONTROL: a wrap that arrives later IS decrypted', async () => {
  // Without this, a memo that simply froze its first answer would pass the test above
  // perfectly while silently never seeing new mail again.
  const relay = relayOf([alphaWrap, betaWrap])
  const signer = countingSigner()
  const memo = new UnwrapMemo()

  const first = await receiveGrants(relay, signer, memo)
  assert.equal(first.length, 2)
  const before = signer.decrypts

  relay.events.push(grantWrap('gamma', 1, GAMMA_KEY))
  const second = await receiveGrants(relay, signer, memo)

  assert.equal(second.length, 3, 'the new grant surfaces')
  assert.deepEqual([...second.find(g => g.scopeId === 'gamma').scopeKey], [...GAMMA_KEY])
  assert.equal(signer.decrypts - before, 2, 'and cost exactly the new wrap: seal + rumor, nothing else')
})

await t('an unopenable wrap is remembered as unopenable, not retried on every pass', async () => {
  const relay = relayOf([junkWrap])
  const signer = countingSigner()
  const memo = new UnwrapMemo()
  await receiveGrants(relay, signer, memo)
  const after = signer.decrypts
  await receiveGrants(relay, signer, memo)
  assert.equal(signer.decrypts, after, 'the second pass did not try it again')
})

await t('two callers wanting different kinds share one decryption of the mailbox', async () => {
  // The reason the memo records the OUTCOME rather than only the wanted rumors: grants and
  // revocation notices are read off the same mailbox by different callers. A memo keyed on
  // "was this useful to me" leaves whichever runs second re-decrypting everything.
  const relay = relayOf([alphaWrap, betaWrap, revokeWrap, junkWrap])
  const signer = countingSigner()
  const memo = new UnwrapMemo()

  await receiveGrants(relay, signer, memo)
  const afterGrants = signer.decrypts

  const notice = await findRevocationNotice(relay, signer, PUB, 'alpha', memo)
  assert.ok(notice, 'the 441 for alpha is still found')
  assert.equal(notice.content.reason, 'rotated', 'and its content is intact')
  assert.equal(signer.decrypts, afterGrants, 'and it cost ZERO further decrypts')

  // Both directions: the memo must not manufacture a notice that was never sent.
  assert.equal(await findRevocationNotice(relay, signer, PUB, 'beta', memo), null,
    'a scope with no notice still reports none')
})

// ---- property 2: the memo must not outlive the key -----------------------------------

await t('revocation drops the revoked grant plaintext and KEEPS the untouched one', async () => {
  const relay = relayOf([alphaWrap, betaWrap, revokeWrap, junkWrap])
  const signer = countingSigner()
  const store = new GrantStore(relay, signer)

  const grants = await store.list()
  assert.equal(grants.length, 2, 'both held before revocation')
  assert.ok(store.memo.has(alphaWrap.id) && store.memo.has(betaWrap.id),
    'both are memoised to begin with (guards the assertions below)')

  store.markRevoked(PUB, 'alpha', 1, { reason: 'rotated' })

  assert.equal(store.memo.has(alphaWrap.id), false,
    'the revoked grant plaintext is GONE — otherwise zeroizing its Uint8Array zeroizes nothing')
  assert.equal(store.memo.has(betaWrap.id), true,
    'and an unrelated grant is untouched — this is eviction, not a panic clear')
  assert.deepEqual([...grants.find(g => g.scopeId === 'alpha').scopeKey], [...new Uint8Array(32)],
    'the key bytes really were zeroized')
})

await t('…and the eviction is real: only the revoked wrap is decrypted again', async () => {
  const relay = relayOf([alphaWrap, betaWrap, revokeWrap, junkWrap])
  const signer = countingSigner()
  const store = new GrantStore(relay, signer)
  await store.list()
  store.markRevoked(PUB, 'alpha', 1, null)

  const before = signer.decrypts
  await store.list({ maxAgeMs: 0 })
  assert.equal(signer.decrypts - before, 2,
    'exactly one wrap re-decrypted (seal + rumor) — beta and the junk stayed remembered')
  // The count above proves the wrap is re-decrypted; it does not ask where the plaintext
  // went. It went back into the memo: forgetMemoised is one-shot, applyRevocation is
  // replayed every refresh. Without forgetAllDead() the eviction happens and is undone.
  assert.equal(store.memo.has(alphaWrap.id), false, 'and the refresh did not put it back')
  assert.equal(store.memo.has(betaWrap.id), true,
    'while a LIVE grant is still memoised — the replay forgets the dead, not everything')
})

await t('…and a relinquished grant is not put back either — the key we said we destroyed', async () => {
  // Sharper than revocation: relinquishGrant publishes a notice stating destroyed_at, so a
  // memo refill leaves the process holding a live base64 copy of a key the delegator has
  // been told is gone.
  const relay = relayOf([alphaWrap, betaWrap, junkWrap])
  const store = new GrantStore(relay, countingSigner())
  await store.list()
  store.markRelinquished(PUB, 'beta', 1, Math.floor(Date.now() / 1000), 'test')
  assert.equal(store.memo.has(betaWrap.id), false, 'forgotten on the mark')

  await store.list({ maxAgeMs: 0 })
  assert.equal(store.memo.has(betaWrap.id), false, 'and still forgotten after a refresh')
  assert.equal(store.memo.has(alphaWrap.id), true, 'and only that one — alpha is untouched')
})

await t('find() forcing a refresh is not a race with the millisecond clock', async () => {
  // maxAgeMs:0 means "do not use the cache". It was implemented as `now - fetchedAt > 0`,
  // which is FALSE inside the same millisecond — so find()'s documented "on a miss, force
  // one refresh (it may have just arrived)" silently did nothing for any caller fast
  // enough, and the grant that had just arrived stayed unfound. Found by the eviction test
  // above, which is fast enough to land in the same tick.
  const relay = relayOf([alphaWrap])
  const store = new GrantStore(relay, countingSigner())
  await store.list()
  const queriesAfterCold = relay.queries

  relay.events.push(betaWrap)
  const found = await store.find(PUB, 'beta')          // same millisecond as the list above
  assert.ok(found, 'a grant that arrived after the cache filled is still found')
  assert.ok(relay.queries > queriesAfterCold, 'because the forced refresh actually queried')

  // Both directions: the ordinary TTL path must still be allowed to serve from cache,
  // or "always refresh" is not a fix, it is the removal of the cache.
  const before = relay.queries
  await store.list()
  assert.equal(relay.queries, before, 'a default-TTL read inside the window does NOT re-query')
})

await t('relinquishment evicts too, and shutdown leaves nothing behind', async () => {
  const relay = relayOf([alphaWrap, betaWrap, revokeWrap, junkWrap])
  const store = new GrantStore(relay, countingSigner())
  await store.list()

  store.markRelinquished(PUB, 'beta', 1, now, 'test')
  assert.equal(store.memo.has(betaWrap.id), false, 'a relinquished grant is forgotten as well')
  assert.equal(store.memo.has(alphaWrap.id), true, 'and only that one')

  assert.ok(store.memo.size > 0, 'there is something to clear (guards the next line)')
  store.zeroizeAll()
  assert.equal(store.memo.size, 0, 'shutdown clears the plaintext memo, not just the key cache')
})

await t('the memo is bounded — it cannot become the leak it was written to prevent', async () => {
  const memo = new UnwrapMemo(4)
  for (let i = 0; i < 20; i++) memo.set(`wrap-${i}`, { kind: KIND_GRANT, pubkey: PUB, tags: [] })
  assert.ok(memo.size <= 4, `size stayed within the limit (was ${memo.size})`)
})

// ---- property 3: an idle server does no work ------------------------------------------

await t('the sweeper reads only what is HELD — no relay query, no decrypt', async () => {
  // The #170 loop: a 30s timer against a 60s cache TTL forced a full mailbox unwrap every
  // 60 seconds for the life of the process, whether or not any grant could expire.
  const exploding = {
    query: async () => { throw new Error('sweeper queried the relay') },
    publish: async () => { throw new Error('sweeper published') },
  }
  const signer = {
    getPublicKey: async () => { throw new Error('sweeper asked the signer for a pubkey') },
    nip44Decrypt: async () => { throw new Error('sweeper decrypted') },
  }
  const store = new GrantStore(exploding, signer)
  const ctx = {
    identity: { pubkey: AGENT, npub: 'npub-test', source: 'nip46', signer },
    relay: exploding,
    grantStore: store,
    scopeCache: { zeroize: () => {} },
    log: () => {},
  }

  // Nothing materialized: the process holds no key, so there is nothing to destroy.
  assert.equal(await sweepAutoRelinquish(ctx), 0, 'an idle sweep does nothing and throws nothing')

  // Both directions — it must still relinquish what IS held, or "does no work" is just broken.
  const expired = {
    publisher: PUB, scopeId: 'alpha', generation: 1, scopeKey: new Uint8Array(32).fill(7),
    issuedAt: now - 100, terms: { auto_relinquish: true, expires_at: now - 10 },
  }
  const live = {
    publisher: PUB, scopeId: 'beta', generation: 1, scopeKey: new Uint8Array(32).fill(9),
    issuedAt: now, terms: { auto_relinquish: true, expires_at: now + 3600 },
  }
  store.cache = [expired, live]

  assert.equal(await sweepAutoRelinquish(ctx), 1, 'the expired held grant IS relinquished')
  assert.ok(expired.relinquished, 'and marked as such')
  assert.equal(live.relinquished, undefined, 'while an unexpired grant is left alone')
})

// ---- property 4: get_public_key is asked once, and a failure is not cached -------------
// Structural: makeNip46 is not exported and drives a live SimplePool, so the memo is
// asserted at the source. Noted as structural rather than dressed up as behavioural.

await t('makeNip46 memoises get_public_key instead of asking on every unwrap', async () => {
  const src = readFileSync(new URL('../mcp/src/identity.ts', import.meta.url), 'utf8')
  assert.match(src, /publicKeyP \?\?= /, 'the RPC is memoised')
  assert.match(src, /publicKeyP = null/, 'and a failed call clears the memo rather than poisoning it')
  assert.equal((src.match(/rpc\('get_public_key'/g) || []).length, 1,
    'there is exactly one place that asks the bunker')
})

await t('…and the memo is NOT seeded from the URI-parsed claim (that would void #338)', async () => {
  // bindIdentity compares the configured claim against what the signer reports. Seeding the
  // memo from the claim would make it compare the claim with itself and always agree.
  const src = readFileSync(new URL('../mcp/src/identity.ts', import.meta.url), 'utf8')
  assert.doesNotMatch(src, /publicKeyP\s*=\s*Promise\.resolve\(pubkey\)/,
    'the parsed pubkey is never used as the memoised answer')
})

console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
