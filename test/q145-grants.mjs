import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { anchorGapsAreRecoverable, brokerGapsAreSafeOrRecoverable, deliveryPlan, JAMES, missingBrokerGrantsAreEnded, parseCorrections, pendingCorrections, publishAndReadBack, assertSignerOwner, signCorrection, signingOrder, unsignedCorrection } from '../bin/q145-grants.mjs'
import { scopeHash } from '../mcp/tools/grant_fold.mjs'

const TARGET = 'a'.repeat(64)
const HOLDER = 'b'.repeat(64)
const row = operation => ({ operation, target: 'fleet:test', target_pubkey: TARGET, holder: 'buzz:test', holder_pubkey: HOLDER, grant_id: 'c'.repeat(64) })
const corrections = readFileSync(new URL('../docs/Q145_GRANT_CORRECTIONS.tsv', import.meta.url), 'utf8')
const grant = (operation, id) => ({ id, kind: 440, pubkey: JAMES, tags: [
  ['p', HOLDER], ['da-scope', scopeHash(TARGET, 'abcd'), 'abcd'],
  ['da-cap', operation === 'grant-task' ? 'task' : 'mention'],
  ...(operation === 'grant-mention' ? [['name', 'test']] : []),
] })
const revoke = id => ({ id, kind: 441, pubkey: JAMES, tags: [['e', row('revoke-task').grant_id]] })
const foldFixture = events => {
  const live = new Map(), mentions = []
  for (const event of events) {
    if (event.kind !== 440 || event.id === row('revoke-task').grant_id) continue
    const cap = event.tags.find(t => t[0] === 'da-cap')?.[1]
    if (cap === 'task') live.set(HOLDER, new Map([['task', { grantId: event.id }]]))
    if (cap === 'mention') mentions.push({ pubkey: HOLDER, name: 'test', grantId: event.id })
  }
  return { live, mentions }
}

function relay(initial = []) {
  const events = new Map(initial.map(e => [e.id, e]))
  const calls = []
  return {
    events, calls, failOnce: false,
    async publish(event) {
      calls.push(event)
      if (this.failOnce) { this.failOnce = false; throw new Error('relay did not accept event') }
      events.set(event.id, event)
    },
    async query({ ids }) { return ids.map(id => events.get(id)).filter(Boolean) },
  }
}

for (const [operation, missingSide, event] of [
  ['grant-task', 'broker', grant('grant-task', 'task-event')],
  ['grant-task', 'anchor', grant('grant-task', 'task-anchor-event')],
  ['grant-mention', 'anchor', grant('grant-mention', 'mention-event')],
  ['revoke-task', 'broker', revoke('revoke-event')],
  ['revoke-task', 'anchor', revoke('revoke-anchor-event')],
]) {
  test(`rerun republishes the same signed ${operation} when ${missingSide} missed it`, async () => {
    const source = grant('grant-task', row('revoke-task').grant_id)
    const baseline = operation === 'revoke-task' ? [source] : []
    const anchor = relay(baseline)
    const broker = relay(baseline)
    const needAnchor = missingSide === 'anchor'
    ;(needAnchor ? anchor : broker).failOnce = true
    await assert.rejects(() => publishAndReadBack(event, [anchor, broker], true, true, () => true), /not readable/)
    const correction = row(operation)
    const anchorEvents = [...anchor.events.values()], brokerEvents = [...broker.events.values()]
    const sourceEvents = [...anchorEvents, ...brokerEvents]
    const anchorPending = pendingCorrections([correction], anchorEvents, sourceEvents, foldFixture).includes(correction)
    const brokerPending = pendingCorrections([correction], brokerEvents, sourceEvents, foldFixture).includes(correction)
    assert.equal(anchorPending, needAnchor)
    assert.equal(brokerPending, !needAnchor)
    const plan = deliveryPlan(correction, anchorPending, brokerPending, anchorEvents, brokerEvents, foldFixture)
    assert.strictEqual(plan.signed, event)
    assert.equal(brokerGapsAreSafeOrRecoverable(anchorEvents, needAnchor ? [] : [event.id], [plan]), true)
    assert.equal(anchorGapsAreRecoverable(new Set(anchorEvents.map(e => e.id)), brokerEvents, [plan]), true)
    await publishAndReadBack(plan.signed, [anchor, broker], plan.needAnchor, plan.needBroker, () => true)
    assert.equal(anchor.events.has(event.id) && broker.events.has(event.id), true)
    assert.equal(anchor.calls.length, needAnchor ? 2 : 1)
    assert.equal(broker.calls.length, needAnchor ? 1 : 2)
    assert.strictEqual((needAnchor ? anchor.calls[1] : broker.calls[1]), event)
  })
}

test('correction table has reviewed shape and rejects changed header, duplicate and first row', () => {
  const rows = parseCorrections(corrections)
  assert.equal(rows.length, 213)
  assert.deepEqual(rows.reduce((counts, item) => { counts[item.operation] = (counts[item.operation] || 0) + 1; return counts }, {}), {
    'grant-task': 97, 'grant-mention': 67, 'revoke-task': 6, 'respond-to-add': 41, 'respond-to-remove': 2,
  })
  assert.throws(() => parseCorrections(corrections.replace('operation\t', 'action\t')), /header/)
  const [header, first] = corrections.split('\n')
  assert.throws(() => parseCorrections(`${header}\n${first}\n${first}\n`), /duplicate/)
  assert.throws(() => parseCorrections(corrections.replace(first, first.replace('fleet:dj-codex', 'fleet:other'))), /not first/)
})

test('pending corrections skip already live grants and revokes, and reject a mismatched revoke source', () => {
  const task = grant('grant-task', 'task-live')
  const source = grant('grant-task', row('revoke-task').grant_id)
  const ended = revoke('revoke-live')
  assert.deepEqual(pendingCorrections([row('grant-task')], [task], [task], foldFixture), [])
  assert.deepEqual(pendingCorrections([row('revoke-task')], [source, ended], [source, ended], foldFixture), [])
  const wrongHolder = { ...source, tags: source.tags.map(t => t[0] === 'p' ? ['p', TARGET] : t) }
  assert.throws(() => pendingCorrections([row('revoke-task')], [wrongHolder], [wrongHolder], foldFixture), /source does not match/)
})

test('unsigned grant, mention and revoke shapes; host operations cannot be signed', () => {
  const task = unsignedCorrection(row('grant-task'), 123, 'abcd')
  assert.equal(task.kind, 440)
  assert.deepEqual(task.tags, [['p', HOLDER], ['da-scope', scopeHash(TARGET, 'abcd'), 'abcd'], ['da-cap', 'task']])
  const mention = unsignedCorrection(row('grant-mention'), 123, 'abcd')
  assert.deepEqual(mention.tags.at(-1), ['name', 'test'])
  const ended = unsignedCorrection(row('revoke-task'), 123)
  assert.deepEqual(ended, { kind: 441, created_at: 123, tags: [['e', row('revoke-task').grant_id]], content: '' })
  assert.throws(() => unsignedCorrection(row('respond-to-add')), /host config/)
})

test('signing requires James and rejects a signer that changes the draft', async () => {
  let calls = 0
  const wrong = { getPublicKey: async () => TARGET, signEvent: async () => { calls++; return {} } }
  await assert.rejects(() => assertSignerOwner(wrong), /not James/)
  assert.equal(calls, 0)
  const altered = { getPublicKey: async () => JAMES, signEvent: async draft => ({ ...draft, pubkey: JAMES, tags: [...draft.tags, ['unexpected', '1']] }) }
  await assertSignerOwner(altered)
  await assert.rejects(() => signCorrection(row('grant-task'), altered, () => true), /changed/)
})

test('signing order keeps grants ahead of revokes', () => {
  const plans = [row('revoke-task'), row('grant-mention'), row('grant-task')].map(item => ({ row: item }))
  assert.deepEqual(signingOrder(plans).map(p => p.row.operation), ['grant-mention', 'grant-task', 'revoke-task'])
})

test('unrelated live broker gap still blocks signing', () => {
  assert.equal(brokerGapsAreSafeOrRecoverable([grant('grant-task', 'unrelated')], ['unrelated'], []), false)
})

test('unrelated broker-only event blocks signing', () => {
  assert.equal(anchorGapsAreRecoverable(new Set(), [grant('grant-task', 'unrelated')], []), false)
})

test('broker gaps are safe only when every absent event is an ended grant', () => {
  const grant = { id: 'grant', kind: 440 }
  const revoke = { id: 'revoke', kind: 441, pubkey: '4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d', tags: [['e', grant.id]] }
  assert.deepEqual(missingBrokerGrantsAreEnded([grant, revoke], new Set([revoke.id])), { missing: [grant.id], safe: true })
  assert.equal(missingBrokerGrantsAreEnded([grant], new Set()).safe, false)
  assert.equal(missingBrokerGrantsAreEnded([grant, revoke], new Set([grant.id])).safe, false)
})
