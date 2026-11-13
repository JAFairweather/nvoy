// Onboarding delegate, Part 1 piece 1 (waggle docs/DESIGN_ONBOARDING_DELEGATE.md, "Fleet changes"):
// discovery of the owners' live `onboard` grants, cold and fail closed, and both fetch paths reading
// live delegates as authors. Accepting a delegate's request is not this piece; it is refused as today.
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { scopeHash } from '../mcp/tools/grant_fold.mjs'
import { delegateAuthors, foldOnboardGrants, grantFilter, liveGrantFor, quorumOf, readOnboardGrants, ONBOARD_CAP } from '../mcp/tools/onboard_delegate.mjs'
import { watchTick } from '../mcp/tools/onboard_watch.mjs'
import { onboard } from '../mcp/tools/onboard_run.mjs'

let n = 0
const ok = (cond, name) => { assert.ok(cond, name); n++; console.log(`ok   ${name}`) }
const verify = ev => { try { return verifyEvent(ev) } catch { return false } }
const owner = generateSecretKey(), ownerHex = getPublicKey(owner)
const other = generateSecretKey(), otherHex = getPublicKey(other)
const delegate = getPublicKey(generateSecretKey()), delegate2 = getPublicKey(generateSecretKey())
const now = 1_800_000_000
const salt = 'ab'.repeat(16)
const grant = (key, to, { cap = ONBOARD_CAP, scopeOf = getPublicKey(key), at = now - 100, extra = [] } = {}) => finalizeEvent({ kind: 440, created_at: at, content: '',
  tags: [['p', to], ['da-cap', cap], ['da-scope', scopeHash(scopeOf, salt), salt], ['policy', 'terms-v3'], ['age', 'confirmed'], ...extra] }, key)
const revoke = (key, id, at = now - 50) => finalizeEvent({ kind: 441, created_at: at, content: '', tags: [['e', id]] }, key)
const fold = (events, grantors = [ownerHex]) => foldOnboardGrants(events, { grantors, verify, scopeHash, nowSec: now })

// ── The fold ──────────────────────────────────────────────────────────────────────────────────
const g = grant(owner, delegate)
let r = fold([g])
ok(r.live.get(delegate)?.[0]?.grantId === g.id && r.live.get(delegate)[0].grantor === ownerHex, 'a live onboard grant from an owner names its delegate')
ok(r.live.get(delegate)[0].policy === 'terms-v3' && r.live.get(delegate)[0].age === 'confirmed', 'the consent tags are carried as signed, for the parser to judge')
ok(fold([grant(owner, delegate, { cap: 'task' })]).live.size === 0, 'a task grant is not an onboard grant')
ok(fold([grant(other, delegate)]).live.size === 0, 'a grant from a key that is not an owner counts for nothing')
ok(fold([grant(owner, delegate, { scopeOf: otherHex })]).live.size === 0, "a grant scoped to another key's hive is not this owner's")
ok(fold([grant(owner, ownerHex)]).live.size === 0, 'an owner cannot grant itself')
ok(fold([grant(owner, 'not-hex')]).live.size === 0, 'a delegate that is not a public key is ignored')
ok(fold([grant(owner, delegate, { extra: [['expiration', String(now - 1)]] })]).live.size === 0, 'an expired grant is not live')
ok(fold([grant(owner, delegate, { extra: [['expiration', 'soon']] })]).live.size === 0, 'a malformed expiration is treated as expired')
const forged = { ...g, tags: [...g.tags, ['x', 'y']] }
r = fold([forged])
ok(r.live.size === 0 && r.rejected === 1, 'an edited grant fails verification and is counted as rejected')
ok(fold([g, revoke(owner, g.id)]).live.size === 0, "the grantor's 441 revokes the grant")
ok(fold([g, revoke(owner, g.id, now - 10_000)]).live.size === 0, 'a 441 dated before its grant still revokes it: order never comes from created_at')
ok(fold([revoke(owner, g.id, now + 10_000), g]).live.size === 0, 'and the order the events arrive in does not matter')
ok(fold([g, revoke(other, g.id)], [ownerHex, otherHex]).live.size === 1, "another owner's 441 cannot revoke this owner's grant")
const g2 = grant(owner, delegate, { at: now - 10 })
r = fold([g, g2, revoke(owner, g.id)])
ok(r.live.get(delegate).length === 1 && r.live.get(delegate)[0].grantId === g2.id, 'revoking one grant leaves a second live one')
r = fold([g, g2])
ok(r.live.get(delegate)[0].grantId === g2.id, 'grants to one delegate come newest first')

// ── The cold read, fail closed ──────────────────────────────────────────────────────────────────
ok(quorumOf(4) === 3 && quorumOf(3) === 2 && quorumOf(1) === 1, 'a quorum is more than half of the relays asked')
ok(JSON.stringify(grantFilter([ownerHex, ownerHex])) === JSON.stringify({ kinds: [440, 441], authors: [ownerHex] }), 'the read asks for grants and revocations from the owners only')
const urls = ['wss://a', 'wss://b', 'wss://c', 'wss://d']
const relaysWith = map => async (url, filter) => {
  assert.deepEqual(filter.kinds, [440, 441])
  const x = map[url]
  if (x instanceof Error) throw x
  return x || { answered: false, complete: false, events: [] }
}
const full = events => ({ answered: true, complete: true, events })
const part = events => ({ answered: true, complete: false, events })
const readWith = map => readOnboardGrants({ urls, grantors: [ownerHex], verify, scopeHash, nowSec: now, read: relaysWith(map) })
let s = await readWith({ 'wss://a': full([g]), 'wss://b': full([g]), 'wss://c': full([]) })
ok(s.known && s.live.has(delegate) && s.complete === 3, 'three of four relays read in full: the grant state is known')
s = await readWith({ 'wss://a': full([g]), 'wss://b': full([g]), 'wss://c': part([g]), 'wss://d': part([g]) })
ok(!s.known && s.live.size === 0 && /only 2 of 4/.test(s.reason), 'two full reads of four: unknown, and the grants it did see are not live')
ok(delegateAuthors(s).length === 0 && liveGrantFor(s, delegate, [ownerHex]) === null, 'unknown adds no author and backs no request')
s = await readWith({ 'wss://a': full([g]), 'wss://b': full([g]), 'wss://c': full([g]), 'wss://d': part([revoke(owner, g.id)]) })
ok(s.known && s.live.size === 0, 'a 441 seen only on a relay that answered in part still revokes')
s = await readWith({ 'wss://a': full([]), 'wss://b': full([]), 'wss://c': full([]), 'wss://d': part([g]) })
ok(s.known && s.live.size === 0, 'a grant seen only on a partial read is not live, even with a quorum of complete reads')
s = await readWith({ 'wss://a': full([g]), 'wss://b': full([]), 'wss://c': full([]), 'wss://d': part([g]) })
ok(s.known && s.live.has(delegate), 'the same grant on a complete read is live')
s = await readWith({ 'wss://a': full([g]), 'wss://b': new Error('socket'), 'wss://c': full([g]), 'wss://d': full([]) })
ok(s.known && s.live.has(delegate), 'a relay that throws counts as not answering, and three full reads still make a quorum')
s = await readOnboardGrants({ urls: [], grantors: [ownerHex], verify, scopeHash, read: relaysWith({}) })
ok(!s.known && s.reason === 'no grant relay', 'no grant relay is unknown, never "no grants"')
s = await readOnboardGrants({ urls, grantors: [], verify, scopeHash, read: relaysWith({}) })
ok(!s.known && s.reason === 'no owner', 'no owner is unknown too')

s = await readWith({ 'wss://a': full([g, grant(other, delegate2)]), 'wss://b': full([]), 'wss://c': full([]) })
ok(liveGrantFor(s, delegate, [ownerHex])?.grantId === g.id, "a delegate's live grant is found for the template's grantors")
ok(liveGrantFor(s, delegate, [otherHex]) === null, "but not for a template whose grantors did not grant it")
ok(delegateAuthors(s).join() === delegate, 'only live delegates become authors; a grant from a non-owner adds none')

// ── Both fetch paths read live delegates as authors ────────────────────────────────────────────
const tmp = mkdtempSync(join(tmpdir(), 'nvoy-onboard-delegate-'))
const root = join(tmp, 'instances'), stateDir = join(tmp, 'state'), out = join(tmp, 'staged'), creds = join(tmp, 'creds')
for (const dir of [root, out, creds]) mkdirSync(dir, { recursive: true })
const dir = join(tmp, 'var', 'crystalclaude')
for (const sub of ['state', 'run', 'spool']) mkdirSync(join(dir, sub), { recursive: true })
writeFileSync(join(root, 'crystalclaude.json'), JSON.stringify({ id: 'crystalclaude', pubkey: getPublicKey(generateSecretKey()), grantors: [ownerHex],
  relays: ['wss://relay.example'], buzz: { relay: 'wss://buzz.example', channels: ['00000000-0000-4000-8000-000000000000'] }, broker_mode: 'local',
  bunker_uri_ref: join(creds, 'c.bunker-uri'), bunker_client_ref: join(creds, 'c.nip46-client'), delivery_mode: 'notify_only', worker_enabled: false,
  state_dir: join(dir, 'state'), runtime_dir: join(dir, 'run'), spool_dir: join(dir, 'spool'),
  broker_adapter_gid: 4001, worker_handoff_gid: 4002, watcher_uid: 4003, broker_uid: 4004, adapter_uid: 4005, worker_uid: 4006 }))
const known = { known: true, live: new Map([[delegate, [{ grantId: g.id, grantor: ownerHex, delegate }]]]) }
const unknown = { known: false, live: new Map(), reason: 'only 1 of 4 grant relays read in full; 3 needed' }
const logs = []
let asked = null, seen = null
await watchTick({ root, out, stateDir, runner: {}, verify, log: line => logs.push(line),
  readDelegates: async args => { asked = args; return known },
  fetchAll: async args => { seen = args; return [] } })
ok(asked?.owners?.join() === ownerHex && seen.delegates.join() === delegate, 'the watch tick reads the owners\' grants and fetches its live delegates\' requests')
logs.length = 0
await watchTick({ root, out, stateDir, runner: {}, verify, log: line => logs.push(line),
  readDelegates: async () => unknown, fetchAll: async args => { seen = args; return [] } })
ok(seen.delegates.length === 0 && logs.some(l => /grant state unknown \(only 1 of 4/.test(l)), 'an unknown grant state adds no delegate, and the tick says so')
await watchTick({ root, out, stateDir, runner: {}, verify, log: () => {}, fetchAll: async args => { seen = args; return [] } })
ok(Array.isArray(seen.delegates) && seen.delegates.length === 0, 'without a grant reader the tick reads owners only, as before')

let fetched = null
await assert.rejects(onboard({ command: 'show', name: 'newagent', root, out, stateDir, verify, log: () => {},
  readDelegates: async () => known, fetchEvents: async args => { fetched = args; return [] } }))
ok(fetched?.delegates?.join() === delegate && fetched.owners.join() === ownerHex, "a run's per-name fetch reads live delegates too, from its own fresh grant read")
await assert.rejects(onboard({ command: 'show', name: 'newagent', root, out, stateDir, verify, log: () => {},
  readDelegates: async () => unknown, fetchEvents: async args => { fetched = args; return [] } }))
ok(fetched.delegates.length === 0, 'and reads none when the grant state is unknown')

// A delegate's request is fetched but not yet accepted: authorization is the next piece, so for now it
// is refused exactly as any non-grantor's request is.
const dkey = generateSecretKey(), dhex = getPublicKey(dkey)
const dreq = finalizeEvent({ kind: 30078, created_at: Math.floor(Date.now() / 1000), content: '', tags: [['d', 'nvoy-onboard/newagent/add_agent'], ['op', 'add_agent'],
  ['p', getPublicKey(generateSecretKey())], ['harness', 'claude-code'], ['like', 'crystalclaude']] }, dkey)
const liveD = { known: true, live: new Map([[dhex, [{ grantId: g.id, grantor: ownerHex, delegate: dhex }]]]) }
await assert.rejects(onboard({ command: 'show', name: 'newagent', root, out, stateDir, verify, log: () => {},
  readDelegates: async () => liveD, fetchEvents: async () => [dreq] }), err => err.code === 'ONBOARD_NOT_OWNER')
ok(true, "a live delegate's request is read, and still refused as not a grantor until authorization lands")

console.log(`\nonboard-delegate: ${n} passed`)
