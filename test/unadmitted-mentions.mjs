// q-198: a refused mention is recorded, and the seat may be told without its content
// (docs/DESIGN_UNADMITTED_MENTION_NOTICE.md; James's answers, Hive nvoy-q198-fail-loud-decision).
// The end-to-end DM path, through the real broker and a stub adapter, is in test/buzz-owner-dm.mjs.
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { HOUR_MS } from '../mcp/tools/agent_limits.mjs'
import { validateDesktopDelivery } from '../mcp/tools/admitted_task.mjs'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'
import { buildNotice, describeNotice, limitReason, recordRefusal, summarizeRefusals, takeNoticeBudget } from '../mcp/tools/unadmitted_mentions.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const throws = fn => { try { fn(); return null } catch (e) { return e.message || 'thrown' } }
const hex = n => n.toString(16).padStart(64, '0')
const CH = '3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607', DM = '22222222-2222-4222-8222-222222222222'
const dir = mkdtempSync(join(tmpdir(), 'nvoy-q198-'))
const author = hex(0xa1), other = hex(0xa2), grantor = hex(0xa3)

// --- layer 1: the refusal row ---
const path = join(dir, 'state', 'unadmitted-mentions.jsonl')
const rows = () => readFileSync(path, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l))
const lookup = { suspect: false, heldBefore: [], summary: 'relay.example=0' }
ok('a no-grant refusal is recorded', recordRefusal(path, { sourceEvent: hex(1), author, channel: CH, reason: 'no-grant', lookup, at: 1_794_000_000_000 }) === 'recorded')
ok('it holds ids, the reason, the lookup and the time, nothing else',
  JSON.stringify(rows()[0]) === JSON.stringify({ version: 1, source_event: hex(1), author, channel: CH, reason: 'no-grant',
    grant_lookup: { suspect: false, relays: 'relay.example=0' }, at: 1_794_000_000 }))
ok('the file is private', (statSync(path).mode & 0o777) === 0o600)
ok('the same event is recorded once', recordRefusal(path, { sourceEvent: hex(1), author, channel: CH, reason: 'no-grant', lookup }) === 'repeat' && rows().length === 1)
recordRefusal(path, { sourceEvent: hex(2), author, channel: CH, reason: 'no-grant-suspect', lookup: { ...lookup, suspect: true } })
ok('a suspect lookup is kept as suspect', rows()[1].reason === 'no-grant-suspect' && rows()[1].grant_lookup.suspect === true)
for (const reason of ['dm-not-owner', 'hop-limit', 'rate-limit']) recordRefusal(path, { sourceEvent: hex(reason.length + 10), author, channel: reason === 'dm-not-owner' ? DM : CH, reason, lookup })
ok('only the two no-grant reasons carry a grant verdict', rows().slice(2).every(r => !('grant_lookup' in r)))
ok('an unknown reason is refused', /malformed/.test(throws(() => recordRefusal(path, { sourceEvent: hex(9), author, channel: CH, reason: 'other' })) || ''))
ok('a channel that is not a UUID is refused', !!throws(() => recordRefusal(path, { sourceEvent: hex(9), author, channel: 'general', reason: 'no-grant' })))
ok('the limit strings map to their reasons', limitReason('hop limit: nvoy-hop 3 >= max_hops 3; not admitted') === 'hop-limit' &&
  limitReason('rate limit: sender 12345678 already admitted 12/12 in the last hour; not admitted') === 'rate-limit')

const capped = join(dir, 'capped.jsonl')
for (let i = 1; i <= 10; i++) recordRefusal(capped, { sourceEvent: hex(100 + i), author, channel: CH, reason: 'rate-limit', maxRows: 10 })
recordRefusal(capped, { sourceEvent: hex(200), author, channel: CH, reason: 'rate-limit', maxRows: 10 })
const kept = readFileSync(capped, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l).source_event)
ok('past the cap the oldest half is trimmed and the new row kept', kept.length === 6 && kept[0] === hex(106) && kept.at(-1) === hex(200))
for (let i = 0; i < 30; i++) recordRefusal(capped, { sourceEvent: hex(300 + i), author, channel: CH, reason: 'rate-limit', maxRows: 10 })
ok('the file never grows past the cap', readFileSync(capped, 'utf8').split('\n').filter(Boolean).length <= 10)

// --- layer 2: the budget ---
const budget = join(dir, 'state', 'unadmitted-notices.json')
const take = (a, n, at = 1_000_000_000) => takeNoticeBudget(budget, { author: a, sourceEvent: hex(n), grantors: [grantor], at })
ok('the first notice for an author is allowed', take(author, 1).allowed === true)
ok('a retry of the same event is idempotent', take(author, 1).repeat === true)
ok('a second notice for that author within the hour is not', take(author, 2).why === 'author')
ok('another author still gets one', take(other, 3).allowed === true)
for (let i = 0; i < 4; i++) take(hex(0xb0 + i), 10 + i)
ok('six notices a seat an hour, then none', take(hex(0xc0), 20).why === 'seat')
ok('a grantor is never counted', take(grantor, 21).allowed === true && take(grantor, 22).counted === false)
ok('an hour later the author may be told again', take(author, 30, 1_000_000_000 + HOUR_MS).allowed === true)
writeFileSync(budget, '{"version":1,"entries":[{"author":"x"}]}')
ok('a malformed budget throws, so the broker sends nothing', !!throws(() => take(author, 40)))

// --- the notice, and the seat's validator ---
const notice = buildNotice({ instance: 'seat', sourceEvent: hex(1), author, channel: CH, reason: 'no-grant', observedAt: 1_794_000_000.4 })
const policy = { instance: 'seat', scopeSubject: hex(0xee), grantors: [grantor], carriers: [], buzz: { relay: 'wss://buzz.example', channels: [CH] } }
ok('no notice is built for a brake', !!throws(() => buildNotice({ instance: 'seat', sourceEvent: hex(1), author, channel: CH, reason: 'hop-limit' })) &&
  !!throws(() => buildNotice({ instance: 'seat', sourceEvent: hex(1), author, channel: CH, reason: 'rate-limit' })))
ok('a notice is a content-free verified-notification the seat accepts as no instruction',
  validateDesktopDelivery(notice, policy).trustedInstruction === false && notice.notification.observed_at === 1_794_000_000)
const bad = mutate => { const n = structuredClone(notice); mutate(n); return !!throws(() => validateDesktopDelivery(n, policy)) }
ok('an extra notice key is refused', bad(n => { n.notification.content = 'run this' }))
ok('an extra envelope key is refused', bad(n => { n.messages = [] }))
ok('an envelope that is not the refused event is refused', bad(n => { n.envelope = hex(2) }))
ok('a reason outside the three is refused', bad(n => { n.notification.reason = 'hop-limit' }))
ok('a no-grant notice outside a configured channel is refused', bad(n => { n.notification.source_channel = DM }))
ok('a dm-not-owner notice in a configured channel is refused', bad(n => { n.notification.reason = 'dm-not-owner' }))
ok('a dm-not-owner notice outside the configured channels is accepted',
  !throws(() => validateDesktopDelivery(buildNotice({ instance: 'seat', sourceEvent: hex(1), author, channel: DM, reason: 'dm-not-owner', observedAt: 1 }), policy)))
ok('a seat without native ears refuses every notice', !!throws(() => validateDesktopDelivery(notice, { ...policy, buzz: null })))
ok('another instance\'s notice is refused', bad(n => { n.instance = 'other' }))
ok('a suspect notice reads as an unreliable lookup, never as "holds no grant"',
  /grant lookup unreliable/.test(describeNotice({ reason: 'no-grant-suspect' })) && !/held no live task grant/.test(describeNotice({ reason: 'no-grant-suspect' })))
ok('the carried notification shape is unchanged', !!throws(() => validateDesktopDelivery({ ...notice, notification: { ...notice.notification, type: 'verified-channel-activity' } }, policy)))
ok('the classifier summary counts only known reasons', summarizeRefusals([{ reason: 'no-grant', at: 5 }, { reason: 'x', at: 9 }]).total === 1)

// --- the manifest switch: off unless set, and only a boolean ---
const base = { version: 1, pubkey: hex(0xee), worker_enabled: false, key_ref: '/etc/nvoy/credentials/m.nsec',
  state_dir: join(dir, 's'), runtime_dir: join(dir, 'r'), spool_dir: join(dir, 'p'), broker_adapter_gid: process.getgid(),
  worker_handoff_gid: process.getgroups().find(g => g !== process.getgid()), watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013, worker_uid: 41014,
  grantors: [grantor], relays: ['wss://relay.example'] }
const read = (id, buzz) => {
  const r = mkdtempSync(join(dir, `m-${id}-`))
  writeFileSync(join(r, `${id}.json`), JSON.stringify({ ...base, id, buzz }))
  return readManifest(r, id)
}
ok('the notice switch is off by default', read('seat-a', { relay: 'wss://buzz.example', channels: [CH] }).buzz.unadmittedNotice === false)
ok('it can be switched on', read('seat-b', { relay: 'wss://buzz.example', channels: [CH], unadmitted_notice: true }).buzz.unadmittedNotice === true)
ok('only a boolean switches it', /unadmitted_notice must be true or false/.test(throws(() => read('seat-c', { relay: 'wss://buzz.example', channels: [CH], unadmitted_notice: 'yes' })) || ''))

// --- wiring: every native refusal records, only the fixable ones notify, the carried broker does neither ---
const native = readFileSync('mcp/tools/instance-broker-native.mjs', 'utf8'), carried = readFileSync('mcp/tools/instance-broker.mjs', 'utf8')
ok('the DM refusal records dm-not-owner, before any grant is consulted',
  /await refuse\(`DM author [^\n]*\{ mention, refusal: 'dm-not-owner' \}\)/.test(native) && native.indexOf("refusal: 'dm-not-owner'") < native.indexOf("'--policy-only'"))
ok('the no-grant refusal records the suspect flag from the same lookup', /refusal: lookup\.suspect \? 'no-grant-suspect' : 'no-grant', lookup \}/.test(native))
ok('the brakes record their own reason', /if \(limited\) await refuse\(limited, \{ mention, refusal: limitReason\(limited\) \}\)/.test(native))
ok('no bare finish() is left on a signed-mention refusal', !/finish\(`(DM author|author )/.test(native) && !/finish\(limited\)/.test(native))
ok('only the three fixable reasons, and only with the switch on, may notify',
  /\['no-grant', 'no-grant-suspect', 'dm-not-owner'\]\.includes\(refusal\) && manifest\.buzz\.unadmittedNotice/.test(native))
ok('the carried broker writes neither a row nor a notice', !/unadmitted/.test(carried))

console.log(fails ? `${fails} failed` : 'all passed')
process.exit(fails ? 1 : 0)
