// regrant.mjs — hierarchical re-grant prototype + revocation-cascade semantics
// (nvoy#1: the Quill linchpin — nave.pub docs/quill.md §5, integration review Q1).
//
// Proves the one-hop `user (Director) → central (grantee + sub-issuer) → leaf
// (instance)` chain end-to-end, fully offline, against BOTH receivers: the
// vendored protocol lib and the built MCP grantee path (mcp/dist/grants.js —
// what a Quill actually runs).
//
// THE SEMANTICS THIS FILE PINS (the answer to "does rotating the mid key kill
// descendant grants?") — there are two re-grant mechanisms and they cascade
// differently:
//
// 1. DERIVED-SCOPE SUB-GRANT (the sub-issuer model — the one that works).
//    The central identity publishes ITS OWN scope (it is the publisher and
//    the rumor author; every conforming receiver accepts) whose payload it
//    derives — possibly NARROWED (attenuation) — from what it read upstream,
//    and grants that to the leaf under its own terms.
//    · Attenuation: possible — the leaf sees only the narrowed payload and
//      never holds the root scope key (least privilege by construction).
//    · Per-leaf revocation: central rotates its derived key past one leaf;
//      the root chain is untouched.
//    · Root revocation (the cascade question): rotating the ROOT key cuts
//      central off, but does NOT cryptographically kill the leaf — the leaf
//      still reads central's derived scope, which holds data as of central's
//      LAST successful upstream read. The cascade is RUNTIME-MEDIATED: a
//      compliant sub-issuer, on finding its source stale/missing, MUST rotate
//      its derived scopes with no survivors (and may tombstone + send 441
//      notices). Staleness is bounded by the sub-issuer's sweep interval,
//      and by leaf-grant TTLs as defense in depth.
//
// 2. KEY RE-WRAP (re-gifting the SAME scope key). The mid authors a 440 rumor
//    whose `a` tag points at the ROOT publisher's scope.
//    · Conforming receivers REJECT it: the grantee path (mcp grants.ts, the
//      console) drops any grant where a-tag publisher ≠ rumor author. The
//      base protocol lib accepts it (it neither checks nor exposes the rumor
//      author — a spec follow-up recorded in FUTURE.md).
//    · Where it is accepted, the cascade IS cryptographic — one root rotation
//      strands every holder of the old key at once, including re-wraps the
//      delegator never knew existed. But attenuation is impossible (same key
//      = whole payload), the delegator cannot see or revoke an individual
//      re-wrapped grantee, and `redelegate:false` forbids it only as an audit
//      term. Re-wrap is therefore NOT the hierarchy mechanism; the console's
//      "＋ grant to another identity" is the DELEGATOR adding a grantee to
//      its own scope (author = publisher — accepted), not a grantee re-issuing.
//
// Terms on the chain (review Q1): the root grant carries redelegate:true (the
// Director allows the central to sub-issue); each leaf grant carries
// redelegate:false so the tree stops there. Enforcement of redelegate on a
// non-compliant runtime is an audit term (non-cryptographic, disclosed
// honestly) — terms end-to-end is nvoy#6, out of scope here.

import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { wrapEvent } from 'nostr-tools/nip59'
import {
  KIND_DATA_SET, newScopeKey, publishScope, rotateScope, fetchScope,
  receiveGrants as libReceiveGrants, latestGrants as libLatestGrants,
} from '../lib/nipxx.mjs'
import { Relay } from '../lib/relay.mjs'
import { LocalRelay } from '../lib/liverelay.mjs'
import { grantWithTerms, opaqueScopeId, TRAVEL_PREFERENCES } from './nvoygrant.mjs'
import { rotateWithTerms } from '../console/nvoygrant.mjs'
import { receiveGrants as mcpReceiveGrants, latestGrants as mcpLatestGrants } from '../mcp/dist/grants.js'

let n = 0, failed = 0
const check = (name, cond) => {
  n++
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${String(n).padStart(2)}. ${name}`)
  if (!cond) failed = 1
}

const relay = new LocalRelay(new Relay())
const b64 = (bytes) => btoa(String.fromCharCode(...bytes))

// The cast: user → central → two leaves.
const director = generateSecretKey(); const directorPub = getPublicKey(director)
const central = generateSecretKey(); const centralPub = getPublicKey(central)
const leafA = generateSecretKey(); const leafAPub = getPublicKey(leafA)
const leafB = generateSecretKey(); const leafBPub = getPublicKey(leafB)

// A grantee's current view of one scope, via the CONFORMING receiver (the
// same modules the MCP server serves Quill with): unwrap → newest per scope
// → dereference.
async function readAs(sk, publisher, scopeId) {
  const grants = mcpLatestGrants(await mcpReceiveGrants(relay, sk))
    .filter(g => g.publisher === publisher && g.scopeId === scopeId)
  if (!grants.length) return { status: 'no-grant' }
  const res = await fetchScope(relay, grants[0])
  return { ...res, terms: grants[0].terms ?? null }
}

// ---------------------------------------------------------------- 1. root grant

const rootId = opaqueScopeId()
let rootGen = 1
const rootKey = newScopeKey()
await publishScope(relay, director, { scopeId: rootId, generation: rootGen, scopeKey: rootKey, payload: TRAVEL_PREFERENCES })
await grantWithTerms(relay, director, centralPub, {
  scopeId: rootId, generation: rootGen, scopeKey: rootKey, scopeName: 'travel-preferences',
  terms: { purpose: 'Plan travel within stated preferences', no_persist: true, redelegate: true, auto_relinquish: false },
})

let atCentral = await readAs(central, directorPub, rootId)
check('user → central: central reads the root scope (conforming receiver)', atCentral.status === 'ok')
check('root data intact at central', atCentral.data?.fields?.seat === 'aisle')
check('root grant carries redelegate:true (the Director allows sub-issuance)', atCentral.terms?.redelegate === true)

// ------------------------------------------ 2. derived-scope sub-grant (attenuated)

// Central sub-issues from WHAT IT READ, narrowed: booking needs seat/airlines/
// airport — not loyalty numbers, not budget, not dietary. Attenuation is a
// payload projection, decided by the sub-issuer.
const narrowed = {
  name: 'Travel preferences (booking subset)',
  fields: (({ seat, airlines, home_airport }) => ({ seat, airlines, home_airport }))(atCentral.data.fields),
}
const subId = opaqueScopeId()
let subGen = 1
let subKey = newScopeKey()
const leafTerms = { purpose: 'Book one itinerary within the stated subset', no_persist: true, redelegate: false, auto_relinquish: true }
await publishScope(relay, central, { scopeId: subId, generation: subGen, scopeKey: subKey, payload: narrowed })
await grantWithTerms(relay, central, leafAPub, { scopeId: subId, generation: subGen, scopeKey: subKey, scopeName: 'travel-preferences/booking', terms: leafTerms })
await grantWithTerms(relay, central, leafBPub, { scopeId: subId, generation: subGen, scopeKey: subKey, scopeName: 'travel-preferences/booking', terms: leafTerms })

let atLeafA = await readAs(leafA, centralPub, subId)
check('central → leaf: leaf reads the derived scope (conforming receiver accepts — publisher IS the rumor author)', atLeafA.status === 'ok')
check('attenuation: narrowed fields present', atLeafA.data?.fields?.home_airport === 'YYZ')
check('attenuation: withheld fields absent (loyalty never reaches the leaf)', atLeafA.data?.fields?.loyalty === undefined)
check('leaf grant carries redelegate:false (the tree stops here)', atLeafA.terms?.redelegate === false)
const leafARoot = mcpLatestGrants(await mcpReceiveGrants(relay, leafA)).filter(g => g.scopeId === rootId)
check('least privilege: leaf holds NO grant on the root scope (never sees the root key)', leafARoot.length === 0)

// -------------------------------------------------- 3. per-leaf revocation

// Central revokes leafB only: rotate the DERIVED key, re-grant leafA under its
// original terms. The root chain is untouched.
const r1 = await rotateWithTerms(relay, central, {
  scopeId: subId, generation: subGen, payload: narrowed, scopeName: 'travel-preferences/booking',
  survivors: [{ pub: leafAPub, terms: leafTerms }],
})
subGen = r1.generation; subKey = r1.scopeKey

check('central revokes ONE instance: leafB is stale after the derived-key rotation', (await readAs(leafB, centralPub, subId)).status === 'stale')
check('…while leafA (survivor) still reads, re-granted at the new generation', (await readAs(leafA, centralPub, subId)).status === 'ok')
check('…and the root chain is untouched (central still reads the root)', (await readAs(central, directorPub, rootId)).status === 'ok')

// ------------------------------- 4. root rotation — the mid-key cascade question

// The Director revokes central: rotate the ROOT key with no survivors.
await rotateScope(relay, director, { scopeId: rootId, generation: rootGen, payload: TRAVEL_PREFERENCES, scopeName: 'travel-preferences', survivors: [] })
rootGen++

atCentral = await readAs(central, directorPub, rootId)
check('Director revokes central: central\'s next root read is stale (cut off)', atCentral.status === 'stale')

// THE FINDING: the leaf is NOT cryptographically killed by the root rotation —
// it still reads central's derived scope (central's last upstream snapshot).
atLeafA = await readAs(leafA, centralPub, subId)
check('cascade is NOT cryptographic: leaf still reads the derived scope after the root rotation', atLeafA.status === 'ok')

// THE OBLIGATION: a compliant sub-issuer, on detecting its source revoked,
// rotates its derived scopes with no survivors. This is the runtime-mediated
// cascade — the sweep that makes "Director revokes central → the fleet dies"
// true, bounded by the sub-issuer's re-read interval.
if (atCentral.status === 'stale' || atCentral.status === 'missing') {
  await rotateWithTerms(relay, central, {
    scopeId: subId, generation: subGen, payload: {}, scopeName: 'travel-preferences/booking', survivors: [],
  })
  subGen++
}
check('cascade completes via the sub-issuer\'s obligation: leaf is stale after central\'s no-survivor rotation', (await readAs(leafA, centralPub, subId)).status === 'stale')

// ------------------------------------- 5. key re-wrap — the rejected mechanism

// Fresh root scope; central re-gifts the ROOT key itself to leafB: a 440 rumor
// AUTHORED by central whose `a` tag points at the DIRECTOR's scope.
const root2Id = opaqueScopeId()
const root2Key = newScopeKey()
await publishScope(relay, director, { scopeId: root2Id, generation: 1, scopeKey: root2Key, payload: TRAVEL_PREFERENCES })
await grantWithTerms(relay, director, centralPub, { scopeId: root2Id, generation: 1, scopeKey: root2Key, scopeName: 'travel-preferences', terms: { purpose: 'root2', redelegate: true } })

const rewrapRumor = {
  pubkey: centralPub,
  kind: 440,
  created_at: Math.floor(Date.now() / 1000),
  tags: [['a', `${KIND_DATA_SET}:${directorPub}:${root2Id}`, ''], ['v', '1']],
  content: JSON.stringify({ scope_key: b64(root2Key), scope_name: 'travel-preferences' }),
}
await relay.publish(wrapEvent(rewrapRumor, central, leafBPub))

const mcpView = mcpLatestGrants(await mcpReceiveGrants(relay, leafB)).filter(g => g.scopeId === root2Id)
check('conforming receiver REJECTS the re-wrap (a-tag publisher ≠ rumor author)', mcpView.length === 0)

const libView = libLatestGrants(await libReceiveGrants(relay, leafB)).filter(g => g.scopeId === root2Id)
check('base protocol lib accepts the re-wrap (no author check — spec follow-up, FUTURE.md)', libView.length === 1)
check('…and where accepted it dereferences the ROOT scope: full payload, no attenuation possible', (await fetchScope(relay, libView[0])).data?.fields?.loyalty !== undefined)

// Where re-wrap exists (base-lib level), the cascade IS cryptographic: one
// root rotation strands every holder of the old key — including re-wrapped
// grantees the Director never knew about.
await rotateScope(relay, director, { scopeId: root2Id, generation: 1, payload: TRAVEL_PREFERENCES, scopeName: 'travel-preferences', survivors: [] })
check('root rotation instantly strands the re-wrapped grantee (cryptographic cascade where re-wrap exists)', (await fetchScope(relay, libView[0])).status === 'stale')

console.log(failed
  ? '\nREGRANT PROTOTYPE: FAILURES — see above'
  : `\nREGRANT PROTOTYPE: all ${n} checks pass — one-hop user→central→instance chain proven
end-to-end against the conforming (MCP) receiver; cascade semantics pinned:
derived-scope sub-grants attenuate + revoke per-leaf, root revocation cascades
via the sub-issuer's rotation obligation (bounded by its sweep interval);
key re-wrap is rejected by conforming receivers and remains an audit-term
violation under redelegate:false.`)
process.exit(failed)
