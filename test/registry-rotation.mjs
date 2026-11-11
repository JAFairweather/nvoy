// registry-rotation.mjs — the registry projection's rotation must not strand its own key (nvoy#363).
//
//   node test/registry-rotation.mjs
//
// A rotation is publish-then-grant. Once the new 30440 lands it REPLACES the old generation, and the new
// scope key exists only in memory. These cases fail the steps AFTER the publish — a survivor's grant, the
// index save — and assert the key was still recorded and the outcome reported as partial, not as "nothing
// changed". Every failure case is paired with a clean run that completes, so a rotateProjection that
// always reports partial would not pass.

import assert from 'node:assert'
import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { localSigner, newScopeKey, publishScope, fetchScope, fromIssuedEntry, toIssuedEntry } from '../lib/nipxx.mjs'
import { Relay } from '../lib/relay.mjs'
import { LocalRelay } from '../lib/liverelay.mjs'
import { buildProjection, planProjectionPublish, registryButton, REGISTRY_PROJECTION_FIELD, REGISTRY_SCOPE } from '../console/registry.mjs'
import { rotateProjection } from '../console/registry-rotate.mjs'
import { opaqueScopeId } from '../console/nvoygrant.mjs'

let pass = 0, fail = 0
const t = async (name, fn) => {
  try { await fn(); console.log(`ok   — ${name}`); pass++ }
  catch (e) { console.log(`FAIL — ${name}\n       ${e.message}`); fail++ }
}

const sk = generateSecretKey(), me = getPublicKey(sk), signer = localSigner(sk)
const H = [generateSecretKey(), generateSecretKey(), generateSecretKey()].map(getPublicKey)
const payload = (n) => buildProjection({ nvoy_agents: H.slice(0, n).map(pub => ({ pub, added_at: 1 })) }, { now: 1 }).payload
const survivors = H.map(pub => ({ pub, terms: null }))

// A relay that accepts everything until told to refuse a gift wrap (kind 1059) after N of them.
const flakyRelay = (refuseGrantAfter = Infinity) => {
  const inner = new LocalRelay(new Relay())
  let grants = 0
  Object.defineProperty(inner, 'grantAttempts', { get: () => grants })   // a live view; Object.assign would copy the 0
  return Object.assign(inner, {
    async publish(event) {
      if (event.kind === 1059 && ++grants > refuseGrantAfter) throw new Error('relay refused the grant')
      return LocalRelay.prototype.publish.call(inner, event)
    },
  })
}

// Seed: the projection published at v1, with all three holders.
const seed = async (relay) => {
  const scopeId = opaqueScopeId(), scopeKey = newScopeKey()
  await publishScope(relay, signer, { scopeId, generation: 1, scopeKey, payload: payload(2) })
  const index = {
    issued: [toIssuedEntry({ scopeId, scopeName: REGISTRY_SCOPE, generation: 1, scopeKey }, H)],
    [REGISTRY_PROJECTION_FIELD]: { scopeId, scopeName: REGISTRY_SCOPE, generation: 1, at: 1, payload: payload(2), verified: true },
  }
  return { scopeId, index }
}
const rotate = (relay, ctx, extra = {}) => rotateProjection({
  relay, signer, index: ctx.index, scopeId: ctx.scopeId, scopeName: REGISTRY_SCOPE, from: 1,
  payload: payload(3), survivors, now: () => 42, ...extra,
})
const issuedOf = (ctx) => fromIssuedEntry(ctx.index.issued.find(e => e.scope === ctx.scopeId))

await t('a clean rotation completes, records the new key and every holder', async () => {
  const relay = flakyRelay(), ctx = await seed(relay)
  let saves = 0
  const out = await rotate(relay, ctx, { save: async () => { saves++ } })
  assert.equal(out.status, 'complete')
  const rec = issuedOf(ctx)
  assert.equal(rec.generation, 2)
  assert.deepEqual([...rec.grantees].sort(), [...H].sort())
  assert.ok(saves >= 2, 'saved before the grants and again after')
  assert.equal((await fetchScope(relay, { publisher: me, scopeId: ctx.scopeId, generation: 2, scopeKey: rec.scopeKey })).status, 'ok')
})

await t('a survivor grant that fails does NOT strand the key: it is recorded, and the outcome is partial', async () => {
  const relay = flakyRelay(1), ctx = await seed(relay)      // the second grant is refused
  const out = await rotate(relay, ctx, { save: async () => {} })
  assert.equal(out.status, 'partial')
  assert.equal(out.regranted.length, 1)
  assert.equal(out.pending.length, 2, 'who is still waiting is named')
  const rec = issuedOf(ctx)
  assert.equal(rec.generation, 2, 'the index follows the generation that is now live')
  assert.equal(rec.grantees.length, 1, 'only the holder who actually got v2 is recorded as holding it')
  assert.equal((await fetchScope(relay, { publisher: me, scopeId: ctx.scopeId, generation: 2, scopeKey: rec.scopeKey })).status, 'ok',
    'the recorded key reads the live generation')
  assert.equal(ctx.index[REGISTRY_PROJECTION_FIELD].generation, 2)
})

await t('the key is saved BEFORE the first grant, so a grant failure cannot precede it', async () => {
  const relay = flakyRelay(0), ctx = await seed(relay)      // the very first grant is refused
  const seen = []
  const out = await rotate(relay, ctx, { save: async () => { seen.push({ v: issuedOf(ctx).generation, grants: relay.grantAttempts }) } })
  assert.deepEqual(seen[0], { v: 2, grants: 0 }, 'the first save carried v2 before ANY grant was attempted')
  assert.equal(out.status, 'partial')
  assert.equal(out.regranted.length, 0)
})

await t('a failing save is retried at the end and reported, not swallowed', async () => {
  const relay = flakyRelay(1), ctx = await seed(relay)
  let calls = 0
  const out = await rotate(relay, ctx, { save: async () => { calls++; throw new Error('index save failed') } })
  assert.equal(out.status, 'partial')
  assert.equal(out.saved, false, 'the caller is told the index never saved')
  assert.equal(issuedOf(ctx).generation, 2, 'it is still recorded in memory for the caller to retry')
  assert.ok(calls >= 2)
})

await t('a rotation clears a stale verified:true — the new generation has not been read back (My Dude, PR 363)', async () => {
  const relay = flakyRelay(), ctx = await seed(relay)             // seeded record says verified: true at v1
  assert.equal(ctx.index[REGISTRY_PROJECTION_FIELD].verified, true)
  // A Revoke-style call: no `verified` argument at all.
  const out = await rotate(relay, ctx, { save: async () => {} })
  assert.equal(out.status, 'complete')
  assert.equal(ctx.index[REGISTRY_PROJECTION_FIELD].generation, 2)
  assert.equal(ctx.index[REGISTRY_PROJECTION_FIELD].verified, false, 'v2 must not inherit v1\'s verified:true')
  // ...and that unverified record, with an unchanged roster, is exactly what Check read-back handles.
  const plan = planProjectionPublish(ctx.index, ctx.index[REGISTRY_PROJECTION_FIELD].payload)
  assert.equal(plan.action, 'reverify')
  assert.equal(plan.generation, 2)
})

await t('  …and a partial rotation is unverified too', async () => {
  const relay = flakyRelay(1), ctx = await seed(relay)
  await rotate(relay, ctx, { save: async () => {} })
  assert.equal(ctx.index[REGISTRY_PROJECTION_FIELD].verified, false)
})

await t('a FINAL save that fails does not turn a live rotation into an error', async () => {
  const relay = flakyRelay(), ctx = await seed(relay)
  let calls = 0
  // Succeeds before the grants (the key is saved), then fails every later save.
  const out = await rotate(relay, ctx, { save: async () => { if (++calls > 1) throw new Error('final save failed') } })
  assert.equal(out.status, 'complete', 'v2 is out and every holder was re-granted')
  assert.equal(out.saved, false, 'but the caller is told the index was not saved')
  assert.equal(issuedOf(ctx).generation, 2)
  assert.equal(issuedOf(ctx).grantees.length, H.length)
})

await t('  …and when the final save succeeds the outcome says so', async () => {
  const relay = flakyRelay(), ctx = await seed(relay)
  assert.equal((await rotate(relay, ctx, { save: async () => {} })).saved, true)
})

await t('nothing published: the error propagates and the index is untouched', async () => {
  const relay = flakyRelay(), ctx = await seed(relay)
  relay.publish = async () => { throw new Error('relay down') }
  await assert.rejects(() => rotate(relay, ctx, { save: async () => {} }), /relay down/)
  assert.equal(issuedOf(ctx).generation, 1)
})

await t('unverified + unchanged roster is a re-verify, not a dead end (My Dude, PR 363)', () => {
  const pl = payload(2)
  const idx = { issued: [{ scope: 'opaque', v: 3, key: 'a2V5', grantees: [] }],
    [REGISTRY_PROJECTION_FIELD]: { scopeId: 'opaque', payload: pl, verified: false } }
  const plan = planProjectionPublish(idx, pl)
  assert.equal(plan.action, 'reverify')
  assert.equal(plan.generation, 3)
  const btn = registryButton(plan, idx[REGISTRY_PROJECTION_FIELD])
  assert.equal(btn.disabled, false, 'the operator can act')
  assert.match(btn.label, /read-back/i)
})

await t('  …a VERIFIED unchanged roster stays refused, and the button is disabled', () => {
  const pl = payload(2)
  const idx = { issued: [{ scope: 'opaque', v: 3, key: 'a2V5' }], [REGISTRY_PROJECTION_FIELD]: { scopeId: 'opaque', payload: pl, verified: true } }
  const plan = planProjectionPublish(idx, pl)
  assert.equal(plan.action, 'none')
  assert.equal(registryButton(plan, idx[REGISTRY_PROJECTION_FIELD]).disabled, true)
})

await t('  …an unverified publish whose key cannot be recovered is BLOCKED, not re-verified blind', () => {
  const pl = payload(2)
  for (const issued of [[], [{ scope: 'opaque', v: 3 }], [{ scope: 'opaque', key: 'a2V5' }], [{ scope: 'opaque', v: 0, key: 'a2V5' }]]) {
    const plan = planProjectionPublish({ issued, [REGISTRY_PROJECTION_FIELD]: { scopeId: 'opaque', payload: pl, verified: false } }, pl)
    assert.equal(plan.action, 'blocked')
    assert.match(plan.why, /Nothing was signed/)
  }
})

await t('  …an unverified publish with a CHANGED roster still rotates', () => {
  const idx = { issued: [{ scope: 'opaque', v: 3, key: 'a2V5', grantees: [H[0]] }],
    [REGISTRY_PROJECTION_FIELD]: { scopeId: 'opaque', payload: payload(2), verified: false } }
  assert.equal(planProjectionPublish(idx, payload(3)).action, 'rotate')
})

await t('a first publish and a changed roster keep their normal buttons', () => {
  assert.deepEqual([registryButton({ action: 'publish' }, null).label, registryButton({ action: 'publish' }, null).disabled], ['Publish projection', false])
  assert.deepEqual([registryButton({ action: 'rotate' }, {}).label, registryButton({ action: 'rotate' }, {}).disabled], ['Republish projection', false])
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
