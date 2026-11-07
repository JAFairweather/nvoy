// Phase B (#323): one watch tick runs every unfinished request through the same steps as `run`, and
// the owner learns of it only through receipts sealed to them and signed by the runner key.
import assert from 'node:assert/strict'
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, copyFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { v2 as nip44 } from 'nostr-tools/nip44'
import { SETUP_KIND } from '../mcp/tools/onboard_request.mjs'
import { WRITERS_D, WRITERS_KIND, writerVerdict } from '../mcp/tools/onboard_run.mjs'
import { pendingRequests, readPages, watchTick, HEARTBEAT_MS } from '../mcp/tools/onboard_watch.mjs'
import { RECEIPT_KIND, receiptD } from '../mcp/tools/onboard_receipt.mjs'

const tmp = mkdtempSync(join(tmpdir(), 'nvoy-onboard-watch-'))
const root = join(tmp, 'instances'), out = join(tmp, 'staged'), stateDir = join(tmp, 'state'), creds = join(tmp, 'creds')
for (const dir of [root, out, creds]) mkdirSync(dir, { recursive: true })
const owner = generateSecretKey(), ownerHex = getPublicKey(owner), stranger = generateSecretKey()
const runnerKey = generateSecretKey(), runnerHex = getPublicKey(runnerKey)
const agent = getPublicKey(generateSecretKey()), agent2 = getPublicKey(generateSecretKey())
const channel = '00000000-0000-4000-8000-000000000000'
let uid = 3000
const raw = (id, pubkey, extra = {}) => {
  const dir = join(tmp, 'var', id)
  for (const name of ['state', 'run', 'spool']) mkdirSync(join(dir, name), { recursive: true })
  uid += 10
  return { id, pubkey, grantors: [ownerHex], relays: ['wss://relay.example'], buzz: { relay: 'wss://buzz.example', channels: [channel] },
    broker_mode: 'local', bunker_uri_ref: join(creds, `${id}.bunker-uri`), bunker_client_ref: join(creds, `${id}.nip46-client`),
    delivery_mode: 'notify_only', worker_enabled: false, state_dir: join(dir, 'state'), runtime_dir: join(dir, 'run'), spool_dir: join(dir, 'spool'),
    broker_adapter_gid: uid, worker_handoff_gid: uid + 1, watcher_uid: uid + 2, broker_uid: uid + 3, adapter_uid: uid + 4, worker_uid: uid + 5, ...extra }
}
const pi = raw('pi-dog', getPublicKey(generateSecretKey()), { may_post: { channels: [channel], per_hour: 4, mention: [] } })
const crystal = raw('crystalclaude', getPublicKey(generateSecretKey()))
for (const manifest of [pi, crystal]) writeFileSync(join(root, `${manifest.id}.json`), JSON.stringify(manifest))
const piBefore = readFileSync(join(root, 'pi-dog.json'), 'utf8')

const KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0' + 'a'.repeat(40) + ' curator@box'
const at = Math.floor(Date.now() / 1000)
const signAs = (key, tags, created_at = at) => finalizeEvent({ kind: SETUP_KIND, created_at, content: '', tags }, key)
const addFor = (name, pubkey, created_at = at, extra = []) => signAs(owner, [['d', `nvoy-onboard/${name}/add_agent`], ['op', 'add_agent'], ['p', pubkey],
  ['harness', 'claude-code'], ['like', 'crystalclaude'], ['giver', pi.pubkey], ['room', channel], ...extra], created_at)
const add = addFor('curator', agent)
const bind = signAs(owner, [['d', 'nvoy-onboard/curator/bind_runtime'], ['op', 'bind_runtime'], ['p', agent], ['harness', 'claude-code'],
  ['like', 'crystalclaude'], ['channel_key', KEY]])

// Fake tools that make the state each real tool makes.
const calls = [], keys = { curator: agent }
const runTool = (tool, args) => {
  const op = args[0], id = args[args.indexOf('--id') + 1]
  calls.push(`${op} ${id}`)
  if (op === 'allocate') { writeFileSync(join(out, `${id}.json`), JSON.stringify(raw(id, keys[id] || agent2))); return 0 }
  if (op === 'check') return 0
  if (op === 'apply') { copyFileSync(join(out, `${id}.json`), join(root, `${id}.json`)); return 0 }
  throw new Error(`unexpected tool ${tool} ${op}`)
}
// The owner approves on the second tick. The link is a stand-in with a one-time secret in it.
const LINK = 'nostrconnect://' + 'ef'.repeat(32) + '?relay=wss%3A%2F%2Frelay.example&secret=only-once'
let approved = false, pairs = 0
const pair = async ({ name, onUri }) => {
  pairs++
  onUri(LINK, at + 300)
  if (!approved) return 1
  writeFileSync(join(creds, `${name}.bunker-uri`), 'x'); writeFileSync(join(creds, `${name}.nip46-client`), 'x')
  return 0
}
const runnerSigner = key => ({
  nip44Encrypt: async (peer, text) => nip44.encrypt(text, nip44.utils.getConversationKey(key, peer)),
  signEvent: async template => finalizeEvent(template, key),
})
const open = event => JSON.parse(nip44.decrypt(event.content, nip44.utils.getConversationKey(owner, runnerHex)))
const runner = { id: 'nvoy-onboard', pubkey: runnerHex, authorizedKeys: join(tmp, 'authorized_keys') }
const install = { instance: 'curator', ssh_target: 'root@fleet.example', host_key: KEY.split(' ').slice(0, 2).join(' '), commit: 'c0ffee'.repeat(6) + 'c0ff' }
const verify = event => { try { return verifyEvent(event) } catch { return false } }
// As a relay hands it over: plain JSON, without nostr-tools' cached verdict from signing.
const wire = event => JSON.parse(JSON.stringify(event))

let events = [add], writers = { answered: true, events: [] }, published = [], clock = Date.now(), lines = []
const tick = (extra = {}) => watchTick({ root, out, stateDir, runner, verify, pair, runTool,
  fetchAll: async () => events, fetchEvents: async () => events,
  joinWith: () => ({ signer: {}, open: async () => { throw new Error('AUTH refused: not a member') }, close() {} }),
  readWriters: async () => writers, publish: async event => { published.push(event); return [{ relay: 'wss://relay.nave.pub', accepted: true }] },
  signer: runnerSigner(runnerKey), installFor: () => install, now: () => clock, log: line => lines.push(line), ...extra })
const steps = event => Object.fromEntries(open(event).steps.map(row => [row.step, row.state]))

// The queue: newest verified add_agent per name, oldest first, without finished or refused ones.
const older = addFor('archivist', agent2, at - 50), forged = wire({ ...addFor('curator', agent, at + 99), sig: '00'.repeat(64) })
const bindOnly = [bind]
assert.deepEqual(pendingRequests([add, older, forged, ...bindOnly], { verify, finished: new Set(), refused: new Set() }), [{ name: 'archivist', id: older.id }, { name: 'curator', id: add.id }])
assert.deepEqual(pendingRequests([add, older], { verify, finished: new Set([older.id]), refused: new Set([add.id]) }), [])

// Tick 1: staged, then the pairing waits. The link reaches the owner only sealed, in a runner-signed receipt.
let result = await tick()
assert.deepEqual(result.ran.map(r => r.name), ['curator'])
assert.equal(pairs, 1)
const withLink = published.filter(event => open(event).pairing)
assert.equal(withLink.length, 1, 'the link goes out once, as soon as it is made')
const sealed = withLink[0]
assert.ok(verifyEvent(sealed)); assert.equal(sealed.pubkey, runnerHex); assert.equal(sealed.kind, RECEIPT_KIND)
assert.deepEqual(sealed.tags.map(tag => tag[0]), ['d', 'p', 'e', 'expiration'])
assert.equal(sealed.tags[0][1], receiptD(add.id)); assert.equal(sealed.tags[1][1], ownerHex); assert.equal(sealed.tags[2][1], add.id)
assert.equal(open(sealed).pairing.uri, LINK); assert.equal(open(sealed).pairing.expires_at, at + 300)
assert.deepEqual(open(sealed).install, install, 'once staged, the receipt carries the install details')
for (const event of published) {
  const text = JSON.stringify(event)
  for (const secret of ['nostrconnect', 'only-once', 'fleet.example', 'curator']) assert.ok(!text.includes(secret), `${secret} is never in the clear`)
  assert.throws(() => nip44.decrypt(event.content, nip44.utils.getConversationKey(stranger, runnerHex)))
}
assert.ok(lines.every(line => !line.includes('nostrconnect') && !line.includes('only-once')), 'the link is never logged')
assert.deepEqual(steps(published.at(-1)), { staged: 'done', paired: 'pending' })

// Once the wait for the owner ends, the next receipt withdraws the spent link.
assert.equal(open(published.at(-1)).pairing, undefined)
// Tick 2: a new link while the new wait runs, then withdrawn again.
const before = published.length
clock += 30_000
await tick()
assert.equal(pairs, 2, 'an unapproved link is replaced by a new one each tick')
assert.deepEqual(published.slice(before).map(event => Boolean(open(event).pairing)), [true, false])

// Tick 3: approved. Paired and checked, then waits on the box's bind_runtime. The link is dropped.
approved = true
clock += 30_000
await tick()
assert.equal(open(published.at(-1)).pairing, undefined)
assert.deepEqual(steps(published.at(-1)), { staged: 'done', paired: 'done', checked: 'done', started: 'pending' })
let created = published.map(event => event.created_at)
assert.deepEqual(created, [...created].sort((a, b) => a - b), 'each receipt is newer than the last')

// A run again re-words the paired row ("both credential files are seated"); that goes out once. After
// that nothing changes: no receipt until the heartbeat, then one.
clock += 30_000; await tick()
let count = published.length
clock += 30_000; await tick(); assert.equal(published.length, count)
clock += HEARTBEAT_MS; await tick(); assert.equal(published.length, count + 1)

// Tick: the box binds. Installed; the giver outside a shared room stays pending and is never rewritten.
events = [add, bind]
clock += 30_000
await tick()
let last = steps(published.at(-1))
assert.equal(last.started, 'done'); assert.equal(last.givers, 'pending')
assert.equal(readFileSync(join(root, 'pi-dog.json'), 'utf8'), piBefore, 'watch never rewrites a giver')
assert.equal(existsSync(join(tmp, 'root')), false)
assert.ok(!calls.some(call => call.startsWith('allocate') && calls.indexOf(call) !== calls.lastIndexOf(call)), 'staged once')

// The relay writer step follows the owner's newest stored list, and only one that verifies.
const list = (key, keys, created_at = at) => finalizeEvent({ kind: WRITERS_KIND, created_at, content: '', tags: [['d', WRITERS_D], ...keys.map(k => ['p', k])] }, key)
assert.equal(last['relay writer'], 'pending')
const verdict = read => writerVerdict(read, { owners: [ownerHex], pubkey: agent, verify })[0]
assert.equal(verdict({ answered: false }), 'pending')
assert.equal(verdict({ answered: true, events: [list(stranger, [agent])] }), 'pending', 'a list by anyone but the owner does not count')
assert.equal(verdict({ answered: true, events: [wire({ ...list(owner, [agent]), sig: '00'.repeat(64) })] }), 'pending', 'a list that does not verify does not count')
assert.equal(verdict({ answered: true, events: [list(owner, [agent], at), list(owner, [pi.pubkey], at + 5)] }), 'pending', 'only the newest list counts')
writers = { answered: true, events: [list(owner, [pi.pubkey], at), list(owner, [pi.pubkey, agent], at + 5)] }
clock += 30_000
await tick()
assert.equal(steps(published.at(-1))['relay writer'], 'done')

// A finished request is skipped: nothing runs and nothing is published.
appendFileSync(join(stateDir, 'requests.jsonl'), JSON.stringify({ id: add.id, name: 'curator', op: 'add_agent', at: clock, finished: true }) + '\n')
count = published.length; const callCount = calls.length
clock += HEARTBEAT_MS * 2
assert.deepEqual((await tick()).ran, [])
assert.equal(published.length, count); assert.equal(calls.length, callCount)

// A request that does not qualify is set aside by id and not retried; a newer one for the name is.
const bad = addFor('archivist', agent2, at + 10, [['harness', 'not-a-harness']])
events = [bad]
result = await tick()
assert.ok(result.ran[0].refused)
result = await tick()
assert.deepEqual(result.ran, [], 'the refused request is not retried')
// A failure that is not a refusal (no relay answered, a crash) is retried next tick.
const flaky = addFor('librarian', getPublicKey(generateSecretKey()), at + 20)
events = [bad, flaky]
result = await tick({ fetchEvents: async () => { throw new Error('socket hang up') } })
assert.ok(result.ran.find(r => r.name === 'librarian').error)
result = await tick({ fetchEvents: async () => { throw new Error('socket hang up') } })
assert.ok(result.ran.find(r => r.name === 'librarian'), 'tried again')

// A runner connection that signs as some other key publishes nothing.
const freshState = join(tmp, 'state2')
count = published.length
events = [addFor('scribe', getPublicKey(generateSecretKey()), at + 30)]
approved = false
await tick({ stateDir: freshState, signer: runnerSigner(stranger) })
assert.equal(published.length, count)
assert.ok(lines.some(line => /signs as another key/.test(line)))

// A request that ends with every step done is marked finished only once the receipt saying so is out.
// Here the last publish is refused; the next tick sends it and only then finishes the request.
const keeper = getPublicKey(generateSecretKey()); keys.keeper = keeper
const keeperAdd = signAs(owner, [['d', 'nvoy-onboard/keeper/add_agent'], ['op', 'add_agent'], ['p', keeper], ['harness', 'claude-code'], ['like', 'crystalclaude']], at + 40)
const keeperBind = signAs(owner, [['d', 'nvoy-onboard/keeper/bind_runtime'], ['op', 'bind_runtime'], ['p', keeper], ['harness', 'claude-code'],
  ['like', 'crystalclaude'], ['channel_key', KEY]], at + 41)
const keeperState = join(tmp, 'state3'), member = { joinWith: () => ({ signer: {}, open: async () => ({ close() {} }), close() {} }) }
events = [keeperAdd, keeperBind]; writers = { answered: true, events: [list(owner, [keeper], at + 42)] }; approved = true
const allDone = event => { const all = Object.values(steps(event)); return all.length === 9 && all.every(state => state === 'done') }
let refuseFinal = true
const flakyPublish = async event => {
  if (refuseFinal && allDone(event)) return [{ relay: 'wss://relay.nave.pub', accepted: false, message: 'blocked: try later' }]
  published.push(event); return [{ relay: 'wss://relay.nave.pub', accepted: true }]
}
const finishedIds = () => readFileSync(join(keeperState, 'requests.jsonl'), 'utf8').split('\n').filter(Boolean).map(JSON.parse).filter(row => row.finished).map(row => row.id)
lines = []
await tick({ ...member, stateDir: keeperState, publish: flakyPublish })
assert.deepEqual(finishedIds(), [], 'not finished while the owner has not seen it finished')
assert.ok(lines.some(line => /next run sends the receipt again/.test(line)))
assert.equal(allDone(published.at(-1)), false, 'the last accepted receipt is not the finished one')
refuseFinal = false; count = published.length
clock += 30_000
const again = await tick({ ...member, stateDir: keeperState, publish: flakyPublish })
assert.deepEqual(again.ran.map(r => r.name), ['keeper'], 'the next tick takes it up again')
assert.ok(published.length > count)
assert.ok(allDone(published.at(-1)), 'the owner now has the finished receipt')
assert.deepEqual(finishedIds(), [keeperAdd.id])
count = published.length; clock += HEARTBEAT_MS * 2
assert.deepEqual((await tick({ ...member, stateDir: keeperState, publish: flakyPublish })).ran, [], 'and then it is skipped')
assert.equal(published.length, count)

// Owner events are read page by page, so newer ones never push an unfinished add out of a window.
const held = Array.from({ length: 357 }, (_, n) => ({ id: `e${n}`, created_at: 1000 + Math.floor(n / 7) }))
const relayOf = (all, cap = Infinity, failAfter = Infinity) => { let asked = 0; return async (url, filter) => {
  if (++asked > failAfter) return { answered: false, events: [] }
  const hit = all.filter(e => (filter.until === undefined || e.created_at <= filter.until) && (filter.since === undefined || e.created_at >= filter.since))
    .sort((a, b) => b.created_at - a.created_at)
  return { answered: true, events: hit.slice(0, Math.min(filter.limit ?? Infinity, cap)) }
} }
const ids = read => read.events.map(e => e.id).sort()
assert.deepEqual(ids(await readPages(relayOf(held), 'wss://x', {}, { page: 50 })), held.map(e => e.id).sort(), 'every event, past any one page')
assert.deepEqual(ids(await readPages(relayOf(held), 'wss://x', { since: 1040 }, { page: 50 })), held.filter(e => e.created_at >= 1040).map(e => e.id).sort())
const sameSecond = Array.from({ length: 30 }, (_, n) => ({ id: `s${n}`, created_at: 5 }))
assert.equal((await readPages(relayOf(sameSecond), 'wss://x', {}, { page: 10 })).events.length, 10, 'a full second past the page size ends the walk, not a loop')
const partial = await readPages(relayOf(held, Infinity, 2), 'wss://x', {}, { page: 50 })
assert.equal(partial.answered, true); assert.ok(partial.events.length >= 50 && partial.events.length < held.length, 'a relay that stops answering keeps what it gave')
assert.equal((await readPages(relayOf(held, Infinity, 0), 'wss://x', {})).answered, false)

// The operator's run reads the same writer list as watch, so its relay writer step can be done too.
const cli = readFileSync(new URL('../mcp/tools/nvoy-onboard.mjs', import.meta.url), 'utf8')
const runCall = cli.slice(cli.lastIndexOf('await onboard({'))
assert.match(runCall.slice(0, runCall.indexOf('})')), /readWriters: writersFrom\(/, 'run reads the owner\'s writer list')
assert.match(runCall.slice(0, runCall.indexOf('})')), /\bverify\b/, 'and verifies it')
assert.doesNotMatch(cli, /limit: 500/, 'no fixed window of owner events')

// No trusted owner yet: nothing is read.
const empty = join(tmp, 'empty'); mkdirSync(empty)
assert.deepEqual((await tick({ root: empty, fetchAll: async () => { throw new Error('read with no owner') } })).ran, [])

assert.ok(readdirSync(stateDir).some(file => file.endsWith('.receipt.json')))
rmSync(tmp, { recursive: true, force: true })
console.log('onboard-watch: queue newest-first per name and oldest-first overall, link sealed to the owner and never logged, receipts only on change or heartbeat, givers never rewritten, relay writer from the owner\'s newest verified list, finished and refused requests skipped, transient failures retried, wrong runner key publishes nothing pass')
