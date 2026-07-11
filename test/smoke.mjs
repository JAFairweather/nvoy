// smoke.mjs — PASS/FAIL assertions over the M1 read path, driving the same
// compiled mcp/dist modules the server runs. Default: in-memory relay.
// `--live` runs the delegate→receive→read flow against real public relays
// with throwaway keys (observer/cache-count assertions are local-only).
//
//   node test/smoke.mjs          # local, full assertion set
//   node test/smoke.mjs --live   # live relays, protocol subset

import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { newScopeKey, publishScope, loadGrantIndex, saveGrantIndex, toIssuedEntry, fromIssuedEntry } from '../lib/nipxx.mjs'
import { Relay } from '../lib/relay.mjs'
import { LiveRelay, LocalRelay } from '../lib/liverelay.mjs'
import { grantWithTerms, opaqueScopeId, TRAVEL_PREFERENCES } from './nvoygrant.mjs'
import { receiveGrants, latestGrants, grantStatus, GrantStore } from '../mcp/dist/grants.js'
import { ScopeCache } from '../mcp/dist/scopes.js'
import { parseTerms } from '../mcp/dist/terms.js'

const LIVE = process.argv.includes('--live')
const RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net']

let n = 0, failed = 0
const check = (name, cond) => {
  n++
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${String(n).padStart(2)}. ${name}`)
  if (!cond) failed = 1
}
const settle = () => LIVE ? new Promise(r => setTimeout(r, 1500)) : Promise.resolve()

// ------------------------------------------------------------------- setup

const inMem = LIVE ? null : new Relay()
const relay = LIVE ? new LiveRelay(RELAYS) : new LocalRelay(inMem)
// count relay queries so cache behavior is observable
let queries = 0
const counted = { publish: e => relay.publish(e), query: f => (queries++, relay.query(f)) }

const delegatorSk = generateSecretKey()
const delegatorPub = getPublicKey(delegatorSk)
const agentSk = generateSecretKey()
const agentPub = getPublicKey(agentSk)

const scopeId = opaqueScopeId()
const scopeKey = newScopeKey()
const now = Math.floor(Date.now() / 1000)
const terms = {
  purpose: 'Plan travel within stated preferences',
  expires_at: now + 7 * 24 * 3600,
  no_persist: true,
  redelegate: false,
  contact: nip19.npubEncode(delegatorPub),
  auto_relinquish: false,
}

// ------------------------------------------------- 1. delegate → agent sees

await publishScope(relay, delegatorSk, { scopeId, generation: 1, scopeKey, payload: TRAVEL_PREFERENCES })
await grantWithTerms(relay, delegatorSk, agentPub, {
  scopeId, generation: 1, scopeKey, scopeName: 'travel-preferences', terms,
})
await settle()

const grants = latestGrants(await receiveGrants(relay, agentSk))
const g = grants.find(x => x.publisher === delegatorPub && x.scopeId === scopeId)
check('agent receives the grant (unwrapped, seal-verified)', !!g)
check('grant carries publisher/scope/generation', g && g.generation === 1 && g.scopeName === 'travel-preferences')
check('nvoy terms parsed: purpose + no_persist + auto_relinquish',
  g && g.terms?.purpose === terms.purpose && g.terms?.no_persist === true && g.terms?.auto_relinquish === false)
check('grant status is active (expires_at in the future)', g && grantStatus(g) === 'active')

// ------------------------------------------------------------ 2. scope read

const cache = new ScopeCache(counted)
const read1 = await cache.read(g)
check('scope_read returns decrypted payload', read1.status === 'ok' && read1.data?.fields?.seat === 'aisle')
check('scope_read reports generation + fetched_at', read1.generation === 1 && typeof read1.fetched_at === 'number')

const qBefore = queries
const read2 = await cache.read(g)
check('second read within TTL is served from memory cache', queries === qBefore && read2.status === 'ok')
await cache.read(g, { maxAgeSec: 0 })
check('max_age:0 forces a fresh relay fetch', queries === qBefore + 1)

// ------------------------------------------------------------ 3. live update

const updated = { ...TRAVEL_PREFERENCES, fields: { ...TRAVEL_PREFERENCES.fields, seat: 'window' } }
await publishScope(relay, delegatorSk, { scopeId, generation: 1, scopeKey, payload: updated })
await settle()
const read3 = await cache.read(g, { maxAgeSec: 0 })
check('publisher update visible on next forced-fresh read (no re-grant)', read3.data?.fields?.seat === 'window')

// ---------------------------------------------------------- 4. expiry status

const expiredScopeId = opaqueScopeId()
const expiredKey = newScopeKey()
await publishScope(relay, delegatorSk, { scopeId: expiredScopeId, generation: 1, scopeKey: expiredKey, payload: { name: 'stale', fields: {} } })
await grantWithTerms(relay, delegatorSk, agentPub, {
  scopeId: expiredScopeId, generation: 1, scopeKey: expiredKey, scopeName: 'expired-demo',
  terms: { purpose: 'already lapsed', expires_at: now - 3600 },
})
await settle()
const grants2 = latestGrants(await receiveGrants(relay, agentSk))
const gExp = grants2.find(x => x.scopeId === expiredScopeId)
check('expired grant detected: status per expires_at', gExp && grantStatus(gExp) === 'expired')
check('active grant unaffected by sibling expiry', grantStatus(grants2.find(x => x.scopeId === scopeId)) === 'active')

// ------------------------------------------- 5. vanilla + malformed terms

const vanillaScopeId = opaqueScopeId()
const vanillaKey = newScopeKey()
await publishScope(relay, delegatorSk, { scopeId: vanillaScopeId, generation: 1, scopeKey: vanillaKey, payload: { name: 'vanilla', fields: {} } })
await grantWithTerms(relay, delegatorSk, agentPub, {
  scopeId: vanillaScopeId, generation: 1, scopeKey: vanillaKey, scopeName: 'vanilla', // no terms
})
await settle()
const gVan = latestGrants(await receiveGrants(relay, agentSk)).find(x => x.scopeId === vanillaScopeId)
check('vanilla grant (no terms) held with terms=null, active', gVan && gVan.terms === null && grantStatus(gVan) === 'active')
check('malformed terms tolerated as vanilla', parseTerms({ scope_key: 'x', nvoy: 'garbage' }) === null
  && parseTerms('not an object') === null
  && parseTerms({ nvoy: { nvoy: 1, purpose: 42, no_persist: true } })?.purpose === undefined)
check('flat terms carrier shape accepted', parseTerms({ scope_key: 'x', nvoy: 1, purpose: 'p' })?.purpose === 'p')

// -------------------------------------------------------- 6. grant index

const index = await loadGrantIndex(relay, delegatorSk)
index.issued.push(toIssuedEntry({ scopeId, scopeName: 'travel-preferences', generation: 1, scopeKey }, [agentPub]))
await saveGrantIndex(relay, delegatorSk, index)
await settle()
const recovered = await loadGrantIndex(relay, delegatorSk)
const entry = recovered.issued.map(fromIssuedEntry).find(e => e.scopeId === scopeId)
check('delegator Grant Index round-trips (rotation-ready record)',
  entry && entry.generation === 1 && entry.grantees.includes(agentPub))

// ------------------------------------------------ 7. adversarial observer

if (!LIVE) {
  const view = inMem.observerView()
  const kinds = new Set(view.map(e => e.kind))
  check('observer: no kind-440 grant ever hits the relay', !kinds.has(440))
  check('observer: only 30440/1059/10440 present', [...kinds].every(k => [30440, 1059, 10440].includes(k)))
  const wraps = inMem.query({ kinds: [1059] })
  check('observer: wrap senders are ephemeral (delegator pubkey never linked to agent)',
    wraps.every(w => w.pubkey !== delegatorPub && w.pubkey !== agentPub))
  const blob = JSON.stringify(view)
  check('observer: no plaintext or terms leak in stored content',
    !blob.includes('aisle') && !blob.includes('travel') && !blob.includes('Plan travel') && !blob.includes('no_persist'))
  check('observer: scope ids are opaque, no semantic d tags',
    view.filter(e => e.kind === 30440).every(e => /^[a-z2-7]{6}$/.test(e.d)))
} else {
  // live: prove the ciphertext-only property on what we can fetch back
  const [ev] = await relay.query({ kinds: [30440], authors: [delegatorPub], '#d': [scopeId] })
  check('observer(live): stored 30440 content is ciphertext', !!ev && !ev.content.includes('aisle'))
  const wraps = await relay.query({ kinds: [1059], '#p': [agentPub] })
  check('observer(live): grant delivered via ephemeral-keyed wrap', wraps.length > 0 && wraps.every(w => w.pubkey !== delegatorPub))
}

// ------------------------------------------------------- 8. GrantStore find

const store = new GrantStore(relay, agentSk)
const found = await store.find(delegatorPub, scopeId)
check('GrantStore.find resolves grant for scope_read path', !!found && found.generation === 1)

relay.close?.()
console.log(failed ? `\n${LIVE ? 'LIVE ' : ''}SMOKE: FAIL` : `\n${LIVE ? 'LIVE ' : ''}SMOKE: ALL ${n} PASS`)
process.exit(failed)
