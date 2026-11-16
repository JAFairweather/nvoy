import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { PassThrough } from 'node:stream'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools'
import { anchorGapsAreRecoverable, brokerGapsAreSafeOrRecoverable, deliveryPlan, JAMES, missingBrokerGrantsAreEnded, parseCorrections, pendingCorrections, publishAndReadBack, assertSignerOwner, signCorrection, signingOrder, unsignedCorrection, options, selectBatch, assertBatchUnblocked, nextBatch, previewLines, confirmApply, run } from '../bin/q145-grants.mjs'
import { foldGrants, scopeHash } from '../mcp/tools/grant_fold.mjs'

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

test('signing order puts revokes first, then task, then mention, TSV order within each', () => {
  const plans = [row('grant-mention'), row('grant-task'), row('revoke-task'), { ...row('grant-task'), holder: 'buzz:second' }].map(item => ({ row: item }))
  assert.deepEqual(signingOrder(plans).map(p => `${p.row.operation}:${p.row.holder}`),
    ['revoke-task:buzz:test', 'grant-task:buzz:test', 'grant-task:buzz:second', 'grant-mention:buzz:test'])
})

test('options: --apply needs a known --batch and both credential paths', () => {
  assert.throws(() => options(['--apply', '--bunker-uri-file', 'u', '--bunker-client-file', 'c']), /--apply needs --batch/)
  assert.throws(() => options(['--batch', 'all']), /unknown batch all/)
  assert.throws(() => options(['--batch']), /--batch needs a value/)
  assert.throws(() => options(['--batch', '--apply']), /--batch needs a value/)
  assert.throws(() => options(['--apply', '--batch', 'revokes']), /Bunker URI and client file paths/)
  assert.equal(options(['--batch', 'task']).apply, false)
  assert.equal(options(['--apply', '--batch', 'mention', '--bunker-uri-file', 'u', '--bunker-client-file', 'c']).batch, 'mention')
})

test('a later batch is blocked while an earlier one has any pending row, including one to redeliver', () => {
  const plan = (operation, signed) => ({ row: row(operation), signed, needAnchor: true, needBroker: !signed })
  const plans = [plan('grant-mention'), plan('grant-task'), plan('revoke-task', { id: 'd'.repeat(64) })]
  assert.equal(nextBatch(plans), 'revokes')
  const revokes = selectBatch(plans, 'revokes')
  assert.deepEqual(revokes.blockedBy, {})
  assert.deepEqual(revokes.selected.map(p => p.row.operation), ['revoke-task'])
  assert.doesNotThrow(() => assertBatchUnblocked(revokes))
  assert.throws(() => assertBatchUnblocked(selectBatch(plans, 'task')), /batch task blocked: earlier batch still pending \(1 revoke-task\)/)
  assert.throws(() => assertBatchUnblocked(selectBatch(plans, 'mention')), /1 revoke-task, 1 grant-task|1 grant-task, 1 revoke-task/)
  const later = plans.filter(p => p.row.operation === 'grant-mention')
  assert.equal(nextBatch(later), 'mention')
  assert.doesNotThrow(() => assertBatchUnblocked(selectBatch(later, 'mention')))
  assert.equal(nextBatch([]), null)
  assert.throws(() => selectBatch(plans, 'everything'), /unknown batch/)
})

test('preview lists every row with full keys, IDs, action and sides', () => {
  const lines = previewLines([
    { row: row('revoke-task'), signed: null, needAnchor: true, needBroker: true },
    { row: row('grant-task'), signed: { id: 'e'.repeat(64) }, needAnchor: false, needBroker: true },
    { row: row('grant-mention'), signed: null, needAnchor: true, needBroker: false },
  ])
  assert.equal(lines.length, 3)
  for (const line of lines) assert.match(line, new RegExp(`holder=buzz:test ${HOLDER} target=fleet:test ${TARGET}`))
  assert.match(lines[0], new RegExp(`^1/3 revoke-task .* ends=${'c'.repeat(64)} sign=new to=anchor\\+broker$`))
  assert.match(lines[1], new RegExp(`^2/3 grant-task .* deliver-existing=${'e'.repeat(64)} to=broker$`))
  assert.match(lines[2], /^3\/3 grant-mention .* name=test sign=new to=anchor$/)
})

test('typed confirmation names the batch and count', async () => {
  const answer = async text => {
    const input = new PassThrough(); input.isTTY = true
    const output = new PassThrough()
    const done = confirmApply('revokes', 6, input, output)
    input.end(`${text}\n`)
    return done
  }
  await answer('APPLY revokes 6')
  await assert.rejects(() => answer('APPLY 6'), /did not match/)
  await assert.rejects(() => answer('APPLY task 6'), /did not match/)
  await assert.rejects(() => confirmApply('revokes', 6, new PassThrough()), /interactive terminal/)
})

test('unrelated live broker gap still blocks signing', () => {
  assert.equal(brokerGapsAreSafeOrRecoverable([grant('grant-task', 'unrelated')], ['unrelated'], []), false)
})

test('unrelated broker-only event blocks signing', () => {
  assert.equal(anchorGapsAreRecoverable(new Set(), [grant('grant-task', 'unrelated')], []), false)
})

test('real grant fold recovers a signed broker-only 440 by its grant ID', async () => {
  const key = generateSecretKey(), grantor = getPublicKey(key)
  const correction = row('grant-task')
  const signed = finalizeEvent(unsignedCorrection(correction, Math.floor(Date.now() / 1000), 'abcd'), key)
  const realFold = (events, options) => foldGrants(events, { ...options, grantors: [grantor] })
  const anchor = relay(), broker = relay([signed])
  const anchorEvents = [...anchor.events.values()], brokerEvents = [...broker.events.values()]
  const anchorPending = pendingCorrections([correction], anchorEvents, brokerEvents, realFold).includes(correction)
  const brokerPending = pendingCorrections([correction], brokerEvents, brokerEvents, realFold).includes(correction)
  assert.equal(anchorPending, true)
  assert.equal(brokerPending, false)
  const plan = deliveryPlan(correction, anchorPending, brokerPending, anchorEvents, brokerEvents, realFold)
  assert.equal(plan.signed.id, signed.id)
  await publishAndReadBack(plan.signed, [anchor, broker], plan.needAnchor, plan.needBroker)
  assert.equal(anchor.events.has(signed.id), true)
  assert.equal(broker.calls.length, 0)
})

test('broker gaps are safe only when every absent event is an ended grant', () => {
  const grant = { id: 'grant', kind: 440 }
  const revoke = { id: 'revoke', kind: 441, pubkey: '4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d', tags: [['e', grant.id]] }
  assert.deepEqual(missingBrokerGrantsAreEnded([grant, revoke], new Set([revoke.id])), { missing: [grant.id], safe: true })
  assert.equal(missingBrokerGrantsAreEnded([grant], new Set()).safe, false)
  assert.equal(missingBrokerGrantsAreEnded([grant, revoke], new Set([grant.id])).safe, false)
})

// End to end through run(): fake relays, a scope-aware fixture fold and a fake
// Bunker. Signatures are not checked (isValid) so events can carry James's key.
const NEIL = '1'.repeat(64), DJ = '2'.repeat(64), HR = '3'.repeat(64), MENTIONER = '4'.repeat(64)
const OLD_GRANT = '5'.repeat(64)
const TSV = ['operation\ttarget\ttarget_pubkey\tholder\tholder_pubkey\tgrant_id',
  `grant-task\tfleet:dj-codex\t${DJ}\tbuzz:neil\t${NEIL}\t-`,
  `revoke-task\tfleet:dj-codex\t${DJ}\tbuzz:hr\t${HR}\t${OLD_GRANT}`,
  `grant-mention\tfleet:dj-codex\t${DJ}\tbuzz:pal\t${MENTIONER}\t-`,
  `respond-to-add\tfleet:dj-codex\t${DJ}\tbuzz:neil\t${NEIL}\t-`].join('\n') + '\n'
const scopedFold = (events, { me }) => {
  const ended = new Set(events.filter(e => e.kind === 441).flatMap(e => e.tags.filter(t => t[0] === 'e').map(t => t[1])))
  const live = new Map(), mentions = []
  for (const e of events) {
    if (e.kind !== 440 || ended.has(e.id)) continue
    const scope = e.tags.find(t => t[0] === 'da-scope')
    if (!scope || scopeHash(me, scope[2]) !== scope[1]) continue
    const holder = e.tags.find(t => t[0] === 'p')[1], cap = e.tags.find(t => t[0] === 'da-cap')[1]
    if (cap === 'mention') mentions.push({ pubkey: holder, name: e.tags.find(t => t[0] === 'name')?.[1], grantId: e.id })
    else live.set(holder, new Map([[cap, { grantId: e.id }]]))
  }
  return { live, mentions }
}
function world() {
  const filler = Array.from({ length: 200 }, (_, i) => ({ id: `f${String(i).padStart(63, '0')}`, kind: 441, pubkey: JAMES, tags: [['e', `x${i}`]] }))
  const old = { id: OLD_GRANT, kind: 440, pubkey: JAMES, tags: [['p', HR], ['da-scope', scopeHash(DJ, 'ab'), 'ab'], ['da-cap', 'task']] }
  const relays = [0, 1, 2, 3].map(() => {
    const events = new Map([...filler, old].map(e => [e.id, e]))
    return { events, published: [], async publish(e) { this.published.push(e); events.set(e.id, e) },
      async query(f) { return f.ids ? f.ids.map(id => events.get(id)).filter(Boolean) : [...events.values()] }, close() {} }
  })
  const trace = []
  let n = 0
  const signer = { getPublicKey: async () => JAMES, signEvent: async draft => { trace.push(`sign:${draft.kind}`); return { ...draft, pubkey: JAMES, id: `s${String(++n).padStart(63, '0')}`, sig: 'x' } }, close() {} }
  const deps = { relays, readText: () => TSV, isValid: () => true, fold: scopedFold,
    confirm: async (batch, count) => { trace.push(`confirm:${batch}:${count}`) },
    openSigner: () => { trace.push('open-signer'); return signer },
    log: line => trace.push(line) }
  return { relays, trace, deps }
}
const APPLY = batch => ['--apply', '--batch', batch, '--bunker-uri-file', 'u', '--bunker-client-file', 'c']

test('run: a later batch refuses before confirmation or signer while revokes are pending', async () => {
  for (const batch of ['task', 'mention']) {
    const { trace, deps } = world()
    await assert.rejects(() => run(APPLY(batch), deps), new RegExp(`batch ${batch} blocked: earlier batch still pending`))
    assert.equal(trace.some(t => t.startsWith('confirm') || t === 'open-signer' || t.startsWith('sign')), false)
  }
})

test('run: batches sign in order, each previewed in full before its typed confirm, and read back', async () => {
  const { relays, trace, deps } = world()
  await run(['--batch', 'revokes'], deps)
  assert.equal(JSON.parse(trace[0]).next_batch, 'revokes')
  assert.equal(trace.some(t => t === 'open-signer' || t.startsWith('confirm')), false)
  assert.match(trace.at(-1), new RegExp(`^1/1 revoke-task holder=buzz:hr ${HR} target=fleet:dj-codex ${DJ} ends=${OLD_GRANT} sign=new to=anchor\\+broker$`))

  for (const [batch, kind, expected] of [['revokes', 441, 1], ['task', 440, 1], ['mention', 440, 1]]) {
    trace.length = 0
    await run(APPLY(batch), deps)
    const preview = trace.findIndex(t => t.startsWith(`Preview, batch ${batch}: ${expected} rows`))
    const confirm = trace.indexOf(`confirm:${batch}:${expected}`)
    assert.ok(preview >= 0 && confirm > preview + expected, `${batch}: preview rows precede confirm`)
    assert.ok(trace.indexOf('open-signer') > confirm, `${batch}: signer opens only after confirm`)
    assert.deepEqual(trace.filter(t => t.startsWith('sign:')), [`sign:${kind}`])
    assert.equal(JSON.parse(trace.at(-1)).delivered, expected)
  }
  const last = relays[0].published.at(-1)
  assert.deepEqual(last.tags.at(-1), ['name', 'pal'])
  for (const relay of relays) assert.equal(relay.published.length, 3)

  trace.length = 0
  await run(['--batch', 'mention'], deps)
  const summary = JSON.parse(trace[0])
  assert.deepEqual(summary.pending, { 'respond-to-add': 1 })
  assert.equal(summary.next_batch, null)
  assert.equal(summary.batch_rows, 0)
})

test('run: a one-sided revoke is redelivered as the same event, never re-signed', async () => {
  const { relays, trace, deps } = world()
  const signedRevoke = { id: 'r'.repeat(64), kind: 441, pubkey: JAMES, created_at: 1, content: '', tags: [['e', OLD_GRANT]] }
  relays[2].events.set(signedRevoke.id, signedRevoke)
  await assert.rejects(() => run(APPLY('task'), deps), /blocked: earlier batch still pending \(1 revoke-task\)/)
  trace.length = 0
  await run(APPLY('revokes'), deps)
  assert.ok(trace.some(t => t.endsWith(`deliver-existing=${signedRevoke.id} to=anchor`)))
  assert.equal(trace.some(t => t.startsWith('sign:')), false)
  assert.strictEqual(relays[0].published[0], signedRevoke)
  assert.equal(relays[2].published.length, 0)
})
