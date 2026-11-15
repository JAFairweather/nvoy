#!/usr/bin/env node
// James-run q-145 reconciliation. Dry-run is the default. No signer is opened
// until --apply, and only James's NIP-46 Bunker may sign. Signing runs one
// batch at a time (--batch revokes|task|mention), in that order: a later batch
// refuses while an earlier one still has a pending row on either side.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'
import { createInterface } from 'node:readline/promises'
import { verifyEvent } from 'nostr-tools'
import { LiveRelay } from '../lib/liverelay.mjs'
import { GRANT_RELAYS } from '../mcp/tools/grant_relays.mjs'
import { foldGrants, scopeHash } from '../mcp/tools/grant_fold.mjs'
import { makeBunkerSigner } from '../mcp/tools/nip46-signer.mjs'

export const JAMES = '4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'
const HEX = /^[0-9a-f]{64}$/
const CORRECTIONS = fileURLToPath(new URL('../docs/Q145_GRANT_CORRECTIONS.tsv', import.meta.url))
const FIELD = ['operation', 'target', 'target_pubkey', 'holder', 'holder_pubkey', 'grant_id']
const RELAY_RESULT_CAP = 500

export function parseCorrections(text) {
  const lines = text.replace(/\r?\n$/, '').split(/\r?\n/).map(line => line.split('\t'))
  if (JSON.stringify(lines.shift()) !== JSON.stringify(FIELD)) throw new Error('correction header changed')
  const rows = lines.map((v, index) => {
    if (v.length !== FIELD.length) throw new Error(`correction row ${index + 2} has wrong field count`)
    const row = Object.fromEntries(FIELD.map((f, i) => [f, v[i]]))
    if (!['grant-task', 'grant-mention', 'revoke-task', 'respond-to-add', 'respond-to-remove'].includes(row.operation) || !HEX.test(row.target_pubkey) || !HEX.test(row.holder_pubkey)) throw new Error(`invalid correction row ${index + 2}`)
    if (row.operation === 'revoke-task' ? !HEX.test(row.grant_id) : row.grant_id !== '-') throw new Error(`invalid grant ID on row ${index + 2}`)
    return row
  })
  if (!rows.length || rows[0].operation !== 'grant-task' || rows[0].target !== 'fleet:dj-codex' || rows[0].holder !== 'buzz:neil') throw new Error('Neil to DJ Codex is not first')
  const unique = new Set(rows.map(r => `${r.operation}:${r.target_pubkey}:${r.holder_pubkey}:${r.grant_id}`))
  if (unique.size !== rows.length) throw new Error('duplicate correction row')
  return rows
}

const tag = (event, name) => event.tags.find(t => t[0] === name)
const revoked = (events) => new Set(events.filter(e => e.kind === 441 && e.pubkey === JAMES).flatMap(e => e.tags.filter(t => t[0] === 'e').map(t => t[1])))
export function missingBrokerGrantsAreEnded(anchor, brokerIds) {
  const ended = revoked(anchor)
  const missing = anchor.filter(e => !brokerIds.has(e.id))
  return { missing: missing.map(e => e.id), safe: missing.every(e => e.kind === 440 && ended.has(e.id)) }
}
export function pendingCorrections(rows, events, sourceEvents = events, foldEvents = foldGrants) {
  const revokedIds = revoked(events)
  const eventById = new Map(sourceEvents.map(e => [e.id, e]))
  const folds = new Map()
  const fold = target => {
    if (!folds.has(target)) folds.set(target, foldEvents(events, { me: target, grantors: [JAMES] }))
    return folds.get(target)
  }
  return rows.filter(row => {
    if (row.operation.startsWith('respond-to-')) return true // host config, never a signing action
    if (row.operation === 'revoke-task') {
      const source = eventById.get(row.grant_id)
      if (!source || source.kind !== 440 || source.pubkey !== JAMES || tag(source, 'p')?.[1] !== row.holder_pubkey || tag(source, 'da-cap')?.[1] !== 'task') throw new Error(`revocation source does not match ${row.grant_id}`)
      const scope = tag(source, 'da-scope')
      if (!scope || scopeHash(row.target_pubkey, scope[2]) !== scope[1]) throw new Error(`revocation scope does not match ${row.grant_id}`)
      return !revokedIds.has(row.grant_id)
    }
    const effective = fold(row.target_pubkey)
    if (row.operation === 'grant-task') return !effective.live.get(row.holder_pubkey)?.has('task')
    return !effective.mentions.some(m => m.pubkey === row.holder_pubkey)
  })
}

// The two sides must be folded separately. A signed event on only one side is
// work to deliver, not a completed correction or permission to sign again.
export function deliveryPlan(row, anchorPending, brokerPending, anchor, broker, fold = foldGrants) {
  if (!anchorPending && !brokerPending) return null
  const completedSide = anchorPending ? broker : anchor
  let signed
  if (row.operation === 'revoke-task') {
    signed = completedSide.find(e => e.kind === 441 && e.pubkey === JAMES && e.tags.some(t => t[0] === 'e' && t[1] === row.grant_id))
  } else {
    const cap = row.operation === 'grant-task' ? 'task' : 'mention'
    const effective = fold(completedSide, { me: row.target_pubkey, grantors: [JAMES] })
    const id = cap === 'task' ? effective.live.get(row.holder_pubkey)?.get('task')?.grantId
      : effective.mentions.find(m => m.pubkey === row.holder_pubkey && m.name === row.holder.split(':').at(-1))?.grantId
    signed = completedSide.find(e => e.id === id)
  }
  // A one-sided completed row must have the signed event that completed it.
  if (anchorPending !== brokerPending && !signed) throw new Error(`cannot recover signed correction for ${row.operation} ${row.holder} -> ${row.target}`)
  return { row, signed, needAnchor: anchorPending, needBroker: brokerPending }
}

export function brokerGapsAreSafeOrRecoverable(anchor, missingIds, plans) {
  const ended = revoked(anchor)
  const recoverable = new Set(plans.filter(p => p.needBroker && p.signed).map(p => p.signed.id))
  const anchorById = new Map(anchor.map(e => [e.id, e]))
  return missingIds.every(id =>
    (anchorById.get(id)?.kind === 440 && ended.has(id)) || recoverable.has(id))
}

export function anchorGapsAreRecoverable(anchorIds, broker, plans) {
  const recoverable = new Set(plans.filter(p => p.needAnchor && p.signed).map(p => p.signed.id))
  return broker.filter(e => !anchorIds.has(e.id)).every(e => recoverable.has(e.id))
}

export async function publishAndReadBack(signed, relays, needAnchor, needBroker, isValid = verifyEvent) {
  const destinations = relays.map((relay, i) => ({ relay, i })).filter(({ i }) => i === 0 ? needAnchor : needBroker)
  await Promise.allSettled(destinations.map(({ relay }) => relay.publish(signed)))
  const reads = await Promise.allSettled(relays.map(relay => relay.query({ ids: [signed.id], limit: 1 })))
  const has = reads.map(result => result.status === 'fulfilled' && result.value.some(e => e.id === signed.id && isValid(e)))
  if (!has[0] || !has.slice(1).some(Boolean)) throw new Error('signed correction was not readable from anchor and broker relays')
}

export const BATCHES = Object.freeze({ revokes: 'revoke-task', task: 'grant-task', mention: 'grant-mention' })
const BATCH_ORDER = ['revokes', 'task', 'mention']
const OPERATION_RANK = new Map(BATCH_ORDER.map((batch, i) => [BATCHES[batch], i]))

// Revokes first, then task grants, then mention grants; TSV order within each.
export function signingOrder(plans) {
  return plans.map((plan, i) => ({ plan, i }))
    .sort((a, b) => (OPERATION_RANK.get(a.plan.row.operation) - OPERATION_RANK.get(b.plan.row.operation)) || a.i - b.i)
    .map(x => x.plan)
}

export function nextBatch(plans) {
  return BATCH_ORDER.find(batch => plans.some(p => p.row.operation === BATCHES[batch])) || null
}

// Select one batch. blockedBy counts the pending rows of earlier batches,
// including one-sided signed events still to deliver.
export function selectBatch(plans, batch) {
  if (!Object.hasOwn(BATCHES, batch)) throw new Error(`unknown batch ${batch}; use revokes, task or mention`)
  const earlier = new Set(BATCH_ORDER.slice(0, BATCH_ORDER.indexOf(batch)).map(b => BATCHES[b]))
  const blockedBy = {}
  for (const p of plans) if (earlier.has(p.row.operation)) blockedBy[p.row.operation] = (blockedBy[p.row.operation] || 0) + 1
  return { batch, selected: signingOrder(plans.filter(p => p.row.operation === BATCHES[batch])), blockedBy }
}

export function assertBatchUnblocked({ batch, blockedBy }) {
  const pending = Object.entries(blockedBy).map(([op, n]) => `${n} ${op}`)
  if (pending.length) throw new Error(`batch ${batch} blocked: earlier batch still pending (${pending.join(', ')})`)
}

const sides = plan => plan.needAnchor && plan.needBroker ? 'anchor+broker' : plan.needAnchor ? 'anchor' : 'broker'

// One line per row, with every full key and ID James checks against the TSV.
export function previewLines(selected) {
  return selected.map((plan, i) => {
    const { row } = plan
    const parts = [`${i + 1}/${selected.length}`, row.operation,
      `holder=${row.holder} ${row.holder_pubkey}`, `target=${row.target} ${row.target_pubkey}`]
    if (row.operation === 'revoke-task') parts.push(`ends=${row.grant_id}`)
    if (row.operation === 'grant-mention') parts.push(`name=${row.holder.split(':').at(-1)}`)
    parts.push(plan.signed ? `deliver-existing=${plan.signed.id}` : 'sign=new', `to=${sides(plan)}`)
    return parts.join(' ')
  })
}

export async function assertSignerOwner(signer) {
  if (await signer.getPublicKey() !== JAMES) throw new Error('Bunker signer is not James')
}

export async function signCorrection(row, signer, isValid = verifyEvent) {
  const draft = unsignedCorrection(row)
  const signed = await signer.signEvent(draft)
  if (!isValid(signed) || signed.pubkey !== JAMES || signed.kind !== draft.kind || signed.created_at !== draft.created_at || signed.content !== draft.content || JSON.stringify(signed.tags) !== JSON.stringify(draft.tags)) throw new Error('Bunker changed the reviewed correction')
  return signed
}

export async function confirmApply(batch, count, input = process.stdin, output = process.stdout) {
  if (!input.isTTY) throw new Error('--apply requires an interactive terminal')
  const prompt = createInterface({ input, output })
  try {
    const phrase = `APPLY ${batch} ${count}`
    const answer = await prompt.question(`Type ${phrase} to deliver the ${count} ${batch} rows listed above: `)
    if (answer.trim() !== phrase) throw new Error('apply confirmation did not match')
  } finally { prompt.close() }
}

export function unsignedCorrection(row, at = Math.floor(Date.now() / 1000), salt = randomBytes(16).toString('hex')) {
  if (row.operation === 'revoke-task') return { kind: 441, created_at: at, tags: [['e', row.grant_id]], content: '' }
  if (!['grant-task', 'grant-mention'].includes(row.operation)) throw new Error('host config is not a NIP-DA grant')
  const tags = [['p', row.holder_pubkey], ['da-scope', scopeHash(row.target_pubkey, salt), salt], ['da-cap', row.operation === 'grant-task' ? 'task' : 'mention']]
  if (row.operation === 'grant-mention') tags.push(['name', row.holder.split(':').at(-1)])
  return { kind: 440, created_at: at, tags, content: '' }
}

export function options(argv) {
  const out = { apply: false, corrections: CORRECTIONS }
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i]
    if (key === '--apply') out.apply = true
    else if (['--corrections', '--bunker-uri-file', '--bunker-client-file', '--batch'].includes(key)) {
      const value = argv[++i]
      if (!value || value.startsWith('--')) throw new Error(`${key} needs a value`)
      out[key.slice(2)] = value
    } else throw new Error(`unknown option ${key}`)
  }
  if (out.batch !== undefined && !Object.hasOwn(BATCHES, out.batch)) throw new Error(`unknown batch ${out.batch}; use revokes, task or mention`)
  if (out.apply && !out.batch) throw new Error('--apply needs --batch revokes, task or mention')
  if (out.apply && (!out['bunker-uri-file'] || !out['bunker-client-file'])) throw new Error('--apply needs Bunker URI and client file paths')
  return out
}

async function readEvents(relay, isValid = verifyEvent) {
  const events = await relay.query({ kinds: [440, 441], authors: [JAMES], limit: 1000 })
  if (events.length >= RELAY_RESULT_CAP) throw new Error(`grant relay returned ${events.length} events; possible result cap, refusing incomplete fold`)
  return events.filter(e => e.pubkey === JAMES && (e.kind === 440 || e.kind === 441) && isValid(e))
}

// deps exist for tests: the relays, signature check, fold, confirmation,
// signer factory and output. main() passes the live ones.
export async function run(argv, deps = {}) {
  const opts = options(argv)
  const {
    relays = GRANT_RELAYS.map(url => new LiveRelay([url])),
    readText = path => readFileSync(path, 'utf8'),
    isValid = verifyEvent,
    fold = foldGrants,
    confirm = confirmApply,
    openSigner = () => makeBunkerSigner(readText(opts['bunker-uri-file']).trim(), readText(opts['bunker-client-file']).trim(), { idleMs: 30000 }),
    log = line => console.log(line),
  } = deps
  const rows = parseCorrections(readText(opts.corrections))
  let signer
  try {
    const anchor = await readEvents(relays[0], isValid)
    const brokerReads = await Promise.all(relays.slice(1).map(relay => readEvents(relay, isValid)))
    if (anchor.length < 200) throw new Error('relay.nave.pub returned fewer than the audited 200 events')
    const brokerIds = new Set(brokerReads.flat().map(e => e.id))
    const brokerGap = missingBrokerGrantsAreEnded(anchor, brokerIds)
    const broker = brokerReads.flat()
    const sourceEvents = [...new Map([...anchor, ...broker].map(e => [e.id, e])).values()]
    const anchorPending = new Set(pendingCorrections(rows, anchor, sourceEvents, fold))
    const brokerPending = new Set(pendingCorrections(rows, broker, sourceEvents, fold))
    const pending = rows.filter(row => anchorPending.has(row) || brokerPending.has(row))
    const plans = signingOrder(pending.filter(row => !row.operation.startsWith('respond-to-'))
      .map(row => deliveryPlan(row, anchorPending.has(row), brokerPending.has(row), anchor, broker, fold)))
    const brokerGapsSafeOrRecoverable = brokerGapsAreSafeOrRecoverable(anchor, brokerGap.missing, plans)
    const anchorIds = new Set(anchor.map(e => e.id))
    const brokerOnly = broker.filter(e => !anchorIds.has(e.id)).map(e => e.id)
    const anchorGapsRecoverable = anchorGapsAreRecoverable(anchorIds, broker, plans)
    const counts = pending.reduce((out, row) => { out[row.operation] = (out[row.operation] || 0) + 1; return out }, {})
    const selection = opts.batch ? selectBatch(plans, opts.batch) : null
    log(JSON.stringify({ anchor_events: anchor.length, broker_relay_events: brokerReads.map(x => x.length), missing_on_all_broker_relays: brokerGap.missing, missing_broker_events_are_revoked_grants: brokerGap.safe, broker_gaps_safe_or_recoverable: brokerGapsSafeOrRecoverable, missing_on_anchor: brokerOnly, anchor_gaps_recoverable: anchorGapsRecoverable, pending: counts, signed_events_to_republish: plans.filter(p => p.signed).length, next_batch: nextBatch(plans), first: pending[0] && `${pending[0].holder} -> ${pending[0].target}`, ...(selection && { batch: selection.batch, batch_rows: selection.selected.length, batch_blocked_by: selection.blockedBy }) }, null, 2))
    if (selection) {
      log(`Preview, batch ${selection.batch}: ${selection.selected.length} rows`)
      for (const line of previewLines(selection.selected)) log(line)
    }
    if (!opts.apply) return
    if (!brokerGapsSafeOrRecoverable) throw new Error('broker relay union is missing a live grant or revoke outside the reviewed corrections; repair relays before signing')
    if (!anchorGapsRecoverable) throw new Error('anchor is missing a grant or revoke outside the reviewed corrections; repair relays before signing')
    assertBatchUnblocked(selection)
    const batchPlans = selection.selected
    if (!batchPlans.length) {
      log(`No pending ${selection.batch} rows; nothing to sign. Host config operations stay separate.`)
      return
    }
    log(`Batch ${selection.batch}: ${batchPlans.length} deliveries; new signatures: ${batchPlans.filter(p => !p.signed).length}; recovered signed events: ${batchPlans.filter(p => p.signed).length}`)
    await confirm(selection.batch, batchPlans.length)
    signer = openSigner()
    await assertSignerOwner(signer)
    let deliveredCount = 0
    let newlySigned = 0
    for (const plan of batchPlans) {
      const { row } = plan
      let { signed } = plan
      if (!signed) {
        signed = await signCorrection(row, signer, isValid)
        newlySigned++
      }
      await publishAndReadBack(signed, relays, plan.needAnchor, plan.needBroker, isValid)
      deliveredCount++
      log(`${deliveredCount}/${batchPlans.length}: ${row.operation} ${row.holder} -> ${row.target} read back as ${signed.id}`)
    }
    log(JSON.stringify({ batch: selection.batch, delivered: deliveredCount, newly_signed: newlySigned, next: 'rerun the dry-run; this batch must be absent from pending', result: 'signed events read back on the anchor and a broker relay' }))
  } finally {
    try { signer?.close?.() } catch {}
    for (const relay of relays) relay.close?.()
  }
}

async function main() {
  await run(process.argv.slice(2))
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch(error => {
  if (!process.argv.includes('--apply')) console.error(`q145-grants dry-run failed: ${error?.message || error}`)
  else {
    const message = String(error?.message || '')
    const safe = /^(Bunker signer is not James|Bunker changed the reviewed correction|signed correction was not readable from anchor and broker relays|cannot recover signed correction for |grant relay returned \d+ events; possible result cap|anchor is missing a grant or revoke|broker relay union is missing a live grant or revoke|--apply requires an interactive terminal|apply confirmation did not match|relay\.nave\.pub returned fewer than the audited 200 events|batch \w+ blocked: earlier batch still pending|--apply needs |unknown batch |unknown option |--[a-z-]+ needs a value)/.test(message)
    console.error(`q145-grants stopped. No further events were signed. ${safe ? message : 'Inspect the relay/Bunker for the failure.'} Rerun the dry-run before apply.`)
  }
  process.exitCode = 1
})
