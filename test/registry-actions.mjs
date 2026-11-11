// registry-actions.mjs — fault injection for the registry panel's write actions (nvoy#363).
//
//   node test/registry-actions.mjs
//
// The panel's handlers are thin DOM glue over console/registry-actions.mjs; these cases drive that module
// with a relay and a save that fail at chosen steps. The property under test is the same everywhere: once
// the irreversible step (a signed event the relays hold) has happened, nothing after it may be reported
// as "nothing changed", the in-memory index keeps the repair state, and the outcome says what is live and
// what is unsaved. Each failure case is paired with a clean run of the same action.

import assert from 'node:assert'
import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { localSigner, newScopeKey, publishScope, toIssuedEntry } from '../lib/nipxx.mjs'
import { Relay } from '../lib/relay.mjs'
import { LocalRelay } from '../lib/liverelay.mjs'
import { buildProjection, planProjectionPublish, REGISTRY_PROJECTION_FIELD, REGISTRY_SCOPE } from '../console/registry.mjs'
import { confirmReadBack, reverifyProjection, grantRead, revokeRead } from '../console/registry-actions.mjs'
import { opaqueScopeId } from '../console/nvoygrant.mjs'

let pass = 0, fail = 0
const t = async (name, fn) => {
  try { await fn(); console.log(`ok   — ${name}`); pass++ }
  catch (e) { console.log(`FAIL — ${name}\n       ${e.message}`); fail++ }
}

const sk = generateSecretKey(), me = getPublicKey(sk), signer = localSigner(sk)
const H = [generateSecretKey(), generateSecretKey(), generateSecretKey()].map(getPublicKey)
const payload = buildProjection({ nvoy_agents: H.map(pub => ({ pub, added_at: 1 })) }, { now: 1 }).payload

// failWhen(event) → true makes that publish throw. Wraps (kind 1059) are grants and notices.
const relayWith = (failWhen = () => false) => {
  const inner = new LocalRelay(new Relay())
  let wraps = 0
  Object.defineProperty(inner, 'wraps', { get: () => wraps })
  return Object.assign(inner, {
    async publish(event) {
      if (event.kind === 1059) wraps++
      if (failWhen(event, wraps)) throw new Error('relay refused')
      return LocalRelay.prototype.publish.call(inner, event)
    },
  })
}

const seed = async (relay, { verified = false, holders = H } = {}) => {
  const scopeId = opaqueScopeId(), scopeKey = newScopeKey()
  await publishScope(relay, signer, { scopeId, generation: 1, scopeKey, payload })
  const index = {
    issued: [toIssuedEntry({ scopeId, scopeName: REGISTRY_SCOPE, generation: 1, scopeKey }, holders)],
    [REGISTRY_PROJECTION_FIELD]: { scopeId, scopeName: REGISTRY_SCOPE, generation: 1, at: 1, payload, verified },
  }
  return { scopeId, index }
}
const ctxFor = (relay, index, { save = async () => {} } = {}) => ({
  relay, signer, me, index, relayHint: '', now: () => 7, save,
  terms: () => ({ purpose: 'read the registry', no_persist: true, redelegate: false }),
  name: (pub) => `agent-${pub.slice(0, 4)}`,
})
const rec = (index) => index[REGISTRY_PROJECTION_FIELD]
const planFor = (index) => planProjectionPublish(index, rec(index).payload)

// ------------------------------------------------ Check read-back (reverify)
await t('read-back that reads and saves records verified, and the plan is then settled', async () => {
  const relay = relayWith(), { index } = await seed(relay)
  const r = await reverifyProjection(ctxFor(relay, index), planFor(index))
  assert.equal(r.outcome, 'verified')
  assert.equal(rec(index).verified, true)
  assert.equal(planFor(index).action, 'none')
})

await t('read-back that reads but whose SAVE fails stays re-verifiable (Dennis/My Dude, PR 363)', async () => {
  const relay = relayWith(), { index } = await seed(relay)
  const r = await reverifyProjection(ctxFor(relay, index, { save: async () => { throw new Error('save failed') } }), planFor(index))
  assert.equal(r.outcome, 'verified-unsaved')
  assert.match(r.message, /NOT recorded as verified/)
  assert.equal(rec(index).verified, false, 'the flag is not left true while it is unsaved')
  assert.equal(planFor(index).action, 'reverify', 'so the retry button the message points at still works')
})

await t('read-back that does not read leaves the record unverified and says so', async () => {
  const relay = relayWith(), { index } = await seed(relay)
  index.issued[0].key = btoa(String.fromCharCode(...newScopeKey()))   // a key the published scope was not sealed with
  const r = await reverifyProjection(ctxFor(relay, index), { scopeId: index.issued[0].scope, generation: 1 })
  assert.equal(r.outcome, 'unreadable')
  assert.equal(rec(index).verified, false)
})

await t('a relay error during read-back is "does not read back", not a thrown failure', async () => {
  const relay = relayWith(); const { index, scopeId } = await seed(relay)
  relay.query = async () => { throw new Error('relay down') }
  const r = await confirmReadBack(ctxFor(relay, index), { scopeId, generation: 1, scopeKey: new Uint8Array(32) })
  assert.equal(r.readable, false)
  assert.match(r.status, /relay down/)
})

// ------------------------------------------------ Grant read
await t('a clean Grant read records the holder and the ledger row', async () => {
  const relay = relayWith(), { index, scopeId } = await seed(relay, { holders: [] })
  const r = await grantRead(ctxFor(relay, index), H[0], scopeId)
  assert.equal(r.outcome, 'granted')
  assert.deepEqual(index.issued[0].grantees, [H[0]])
  assert.ok(index.nvoy_ledger?.length >= 1)
})

await t('Grant read whose PUBLISH fails is "nothing changed", and records nothing', async () => {
  const relay = relayWith(e => e.kind === 1059), { index, scopeId } = await seed(relay, { holders: [] })
  const r = await grantRead(ctxFor(relay, index), H[0], scopeId)
  assert.equal(r.outcome, 'failed')
  assert.match(r.message, /^nothing changed/)
  assert.deepEqual(index.issued[0].grantees ?? [], [])
})

await t('Grant read whose SAVE fails after the gift wrap is out is NOT "nothing changed" (My Dude, PR 363)', async () => {
  const relay = relayWith(), { index, scopeId } = await seed(relay, { holders: [] })
  const r = await grantRead(ctxFor(relay, index, { save: async () => { throw new Error('save failed') } }), H[0], scopeId)
  assert.equal(r.outcome, 'granted-unsaved')
  assert.doesNotMatch(r.message, /nothing changed/)
  assert.match(r.message, /grant is out/)
  assert.match(r.message, /do not grant again/)
  assert.deepEqual(index.issued[0].grantees, [H[0]], 'the in-memory index keeps the repair state')
  assert.equal(relay.wraps, 1)
})

// ------------------------------------------------ Revoke
await t('a clean Revoke rotates, drops the revoked holder, and the new generation is unverified', async () => {
  const relay = relayWith(), { index, scopeId } = await seed(relay, { verified: true })
  const r = await revokeRead(ctxFor(relay, index), H[0], scopeId, payload)
  assert.equal(r.outcome, 'revoked')
  assert.equal(index.issued[0].v, 2)
  assert.ok(!index.issued[0].grantees.includes(H[0]))
  assert.equal(rec(index).verified, false)
  assert.match(r.message, /Check read-back/)
})

await t('Revoke whose notice fails still records the rotation and says the notice failed', async () => {
  // Survivors get the first two wraps; the third (the notice to the revoked holder) is refused.
  const relay = relayWith((e, n) => n === 3), { index, scopeId } = await seed(relay)
  const r = await revokeRead(ctxFor(relay, index), H[0], scopeId, payload)
  assert.equal(r.outcome, 'revoked')
  assert.match(r.message, /courtesy notice could not be sent/)
  assert.equal(index.issued[0].v, 2)
})

await t('Revoke whose final SAVE fails is live-but-unsaved, never "nothing changed"', async () => {
  const relay = relayWith(), { index, scopeId } = await seed(relay)
  let calls = 0
  const r = await revokeRead(ctxFor(relay, index, { save: async () => { if (++calls > 1) throw new Error('save failed') } }), H[0], scopeId, payload)
  assert.equal(r.saved, false)
  assert.doesNotMatch(r.message, /nothing changed/)
  assert.match(r.message, /WARNING: v2 is live/)
  assert.equal(index.issued[0].v, 2)
})

await t('Revoke where a survivor grant fails is partial, names who waits, and the revoked holder is not recorded', async () => {
  const relay = relayWith((e, n) => n === 2), { index, scopeId } = await seed(relay)
  const r = await revokeRead(ctxFor(relay, index), H[0], scopeId, payload)
  assert.equal(r.outcome, 'revoked-partial')
  assert.match(r.message, /Still waiting/)
  assert.ok(!index.issued[0].grantees.includes(H[0]))
})

await t('Revoke where nothing is published is "nothing changed" and leaves the index as it was', async () => {
  const relay = relayWith(), { index, scopeId } = await seed(relay)
  relay.publish = async () => { throw new Error('relay down') }
  const r = await revokeRead(ctxFor(relay, index), H[0], scopeId, payload)
  assert.equal(r.outcome, 'failed')
  assert.match(r.message, /^nothing changed/)
  assert.equal(index.issued[0].v, 1)
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
