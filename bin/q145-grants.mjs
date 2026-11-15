#!/usr/bin/env node
// James-run q-145 reconciliation. Dry-run is the default. No signer is opened
// until --apply, and only James's NIP-46 Bunker may sign.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'
import { verifyEvent } from 'nostr-tools'
import { LiveRelay } from '../lib/liverelay.mjs'
import { GRANT_RELAYS } from '../mcp/tools/grant_relays.mjs'
import { foldGrants, scopeHash } from '../mcp/tools/grant_fold.mjs'
import { makeBunkerSigner } from '../mcp/tools/nip46-signer.mjs'

export const JAMES = '4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'
const HEX = /^[0-9a-f]{64}$/
const CORRECTIONS = fileURLToPath(new URL('../docs/Q145_GRANT_CORRECTIONS.tsv', import.meta.url))
const FIELD = ['operation', 'target', 'target_pubkey', 'holder', 'holder_pubkey', 'grant_id']

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
export function pendingCorrections(rows, events) {
  const revokedIds = revoked(events)
  const eventById = new Map(events.map(e => [e.id, e]))
  const folds = new Map()
  const fold = target => {
    if (!folds.has(target)) folds.set(target, foldGrants(events, { me: target, grantors: [JAMES] }))
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

export function unsignedCorrection(row, at = Math.floor(Date.now() / 1000), salt = randomBytes(16).toString('hex')) {
  if (row.operation === 'revoke-task') return { kind: 441, created_at: at, tags: [['e', row.grant_id]], content: '' }
  if (!['grant-task', 'grant-mention'].includes(row.operation)) throw new Error('host config is not a NIP-DA grant')
  const tags = [['p', row.holder_pubkey], ['da-scope', scopeHash(row.target_pubkey, salt), salt], ['da-cap', row.operation === 'grant-task' ? 'task' : 'mention']]
  if (row.operation === 'grant-mention') tags.push(['name', row.holder.split(':').at(-1)])
  return { kind: 440, created_at: at, tags, content: '' }
}

function options(argv) {
  const out = { apply: false, corrections: CORRECTIONS }
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i]
    if (key === '--apply') out.apply = true
    else if (['--corrections', '--bunker-uri-file', '--bunker-client-file'].includes(key)) out[key.slice(2)] = argv[++i]
    else throw new Error(`unknown option ${key}`)
  }
  if (out.apply && (!out['bunker-uri-file'] || !out['bunker-client-file'])) throw new Error('--apply needs Bunker URI and client file paths')
  return out
}

async function readEvents(relay) {
  const events = await relay.query({ kinds: [440, 441], authors: [JAMES], limit: 1000 })
  return events.filter(e => e.pubkey === JAMES && (e.kind === 440 || e.kind === 441) && verifyEvent(e))
}

async function main() {
  const opts = options(process.argv.slice(2))
  const rows = parseCorrections(readFileSync(opts.corrections, 'utf8'))
  const relays = GRANT_RELAYS.map(url => new LiveRelay([url]))
  let signer
  try {
    const anchor = await readEvents(relays[0])
    const brokerReads = await Promise.all(relays.slice(1).map(readEvents))
    if (anchor.length < 200) throw new Error('relay.nave.pub returned fewer than the audited 200 events')
    const brokerIds = new Set(brokerReads.flat().map(e => e.id))
    const brokerGap = missingBrokerGrantsAreEnded(anchor, brokerIds)
    const events = [...new Map([...anchor, ...brokerReads.flat()].map(e => [e.id, e])).values()]
    const pending = pendingCorrections(rows, events)
    const counts = pending.reduce((out, row) => { out[row.operation] = (out[row.operation] || 0) + 1; return out }, {})
    console.log(JSON.stringify({ anchor_events: anchor.length, broker_relay_events: brokerReads.map(x => x.length), missing_on_all_broker_relays: brokerGap.missing, missing_broker_events_are_revoked_grants: brokerGap.safe, pending: counts, first: pending[0] && `${pending[0].holder} -> ${pending[0].target}` }, null, 2))
    if (!opts.apply) return
    if (!brokerGap.safe) throw new Error('broker relay union is missing a live grant or revoke; repair relays before signing')
    signer = makeBunkerSigner(readFileSync(opts['bunker-uri-file'], 'utf8').trim(), readFileSync(opts['bunker-client-file'], 'utf8').trim(), { idleMs: 30000 })
    if (await signer.getPublicKey() !== JAMES) throw new Error('Bunker signer is not James')
    let signedCount = 0
    for (const row of pending) {
      if (row.operation.startsWith('respond-to-')) continue
      const draft = unsignedCorrection(row)
      const signed = await signer.signEvent(draft)
      if (!verifyEvent(signed) || signed.pubkey !== JAMES || signed.kind !== draft.kind || signed.created_at !== draft.created_at || signed.content !== draft.content || JSON.stringify(signed.tags) !== JSON.stringify(draft.tags)) throw new Error('Bunker changed the reviewed correction')
      // Each event must reach the anchor and a relay the fleet actually reads.
      const published = await Promise.allSettled(relays.map(relay => relay.publish(signed)))
      if (published[0].status !== 'fulfilled' || published.slice(1).every(p => p.status !== 'fulfilled')) throw new Error('the correction did not reach anchor and broker relays')
      const reads = await Promise.all(relays.map(relay => relay.query({ ids: [signed.id], limit: 1 })))
      if (!reads[0].some(e => e.id === signed.id && verifyEvent(e)) || reads.slice(1).every(v => !v.some(e => e.id === signed.id && verifyEvent(e)))) throw new Error('signed correction was not readable from anchor and broker relays')
      signedCount++
      console.log(`${signedCount}: ${row.operation} ${row.holder} -> ${row.target} read back as ${signed.id}`)
    }
    console.log(JSON.stringify({ signed: signedCount, host_config_operations: pending.filter(r => r.operation.startsWith('respond-to-')).length, result: 'signed events read back; host config remains separate' }))
  } finally {
    try { signer?.close?.() } catch {}
    for (const relay of relays) relay.close()
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch(error => {
  if (!process.argv.includes('--apply')) console.error(`q145-grants dry-run failed: ${error?.message || error}`)
  else console.error('q145-grants stopped. No further events were signed. Inspect the relay/Bunker and rerun; dry-run is the default.')
  process.exitCode = 1
})
