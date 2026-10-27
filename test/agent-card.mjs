// The agent card (waggle#613 C1): an allowlisted projection of the manifest, signed by the agent's
// own key, published to the card relays and read back from each, re-signed only when it changes.
import { strict as assert } from 'node:assert'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { WebSocketServer } from 'ws'
import { generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'
import { agentCard, cardDigest, cardDue, cardRelays, relaysOwed, CARD_D, CARD_KIND, CARD_REFRESH_MS } from '../mcp/tools/agent_card.mjs'

const secret = generateSecretKey(), pubkey = getPublicKey(secret)
const grantor = getPublicKey(generateSecretKey()), peer = getPublicKey(generateSecretKey())
const channel = '00000000-0000-4000-8000-000000000000'
const root = mkdtempSync(join(tmpdir(), 'nvoy-agent-card-'))

// A relay that stores what it accepts and answers address queries; `refuse` makes it say no.
async function relay(options = { refuse: false }) {
  const server = createServer((request, response) => { response.writeHead(404); response.end() })
  await new Promise(done => server.listen(0, '127.0.0.1', done))
  const stored = [], url = `ws://127.0.0.1:${server.address().port}`
  new WebSocketServer({ server }).on('connection', socket => socket.on('message', raw => {
    const frame = JSON.parse(raw.toString())
    if (frame[0] === 'EVENT') {
      const refuse = options.refuse
      if (!refuse && verifyEvent(frame[1])) stored.push(frame[1])
      socket.send(JSON.stringify(['OK', frame[1].id, !refuse, refuse ? 'blocked: test relay' : '']))
    }
    if (frame[0] === 'REQ') {
      const f = frame[2]
      for (const event of stored.filter(e => f.kinds.includes(e.kind) && f.authors.includes(e.pubkey) &&
        e.tags.some(t => t[0] === 'd' && f['#d'].includes(t[1]))).slice(-1)) socket.send(JSON.stringify(['EVENT', frame[1], event]))
      socket.send(JSON.stringify(['EOSE', frame[1]]))
    }
  }))
  return { url, stored, options, close: () => server.close() }
}

function fixture(id, extra = {}) {
  const directory = join(root, id)
  for (const name of ['instances', 'state', 'run', 'spool']) mkdirSync(join(directory, name), { recursive: true })
  const raw = { id, pubkey, grantors: [grantor], relays: ['wss://relay.example'], buzz: { relay: 'wss://buzz.example', channels: [channel] },
    broker_mode: 'local', key_ref: '/etc/nvoy/credentials/seat.nsec', delivery_mode: 'notify_only', worker_enabled: false,
    state_dir: join(directory, 'state'), runtime_dir: join(directory, 'run'), spool_dir: join(directory, 'spool'),
    broker_adapter_gid: 1001, worker_handoff_gid: 1002, watcher_uid: 1001, broker_uid: 1002, adapter_uid: 1003, worker_uid: 1004,
    may_post: { channels: [channel], per_hour: 5, mention: [{ name: 'peer', pubkey: peer }] },
    may_set_profile: { kind: 0, pubkey, grant_id: 'cd'.repeat(32) },
    harness: { runner: 'codex', credential_ref: '/etc/nvoy/credentials/seat-codex.json', model: 'gpt-5.6' }, agent_card: true, ...extra }
  writeFileSync(join(directory, 'instances', `${id}.json`), JSON.stringify(raw))
  return { root: join(directory, 'instances'), directory, load: () => readManifest(join(directory, 'instances'), id) }
}

// The manifest switch: off by default, a boolean, and only where a local broker can sign.
assert.equal(fixture('default', { agent_card: undefined }).load().agentCard, false)
assert.throws(() => fixture('not-bool', { agent_card: 'yes' }).load(), /agent_card must be true or false/)
assert.throws(() => fixture('no-buzz', { buzz: undefined, may_post: undefined, may_set_profile: undefined }).load(), /agent_card requires a buzz block/)

// The public card is coarse: counts and limits, no channel id, key, holding, model or grant id.
const seat = fixture('seat'), manifest = seat.load()
const card = agentCard(manifest, { release: 'a'.repeat(40) })
assert.deepEqual(Object.keys(card), ['version', 'instance', 'pubkey', 'release', 'grantors', 'relays', 'may_post', 'may_set_profile',
  'agent_limits', 'delivery_mode', 'harness', 'summary', 'withheld', 'not_reported'])
assert.deepEqual(card.grantors, [grantor])
assert.deepEqual(card.may_post, { channels: 1, per_hour: 5, mentions: 1 })
assert.deepEqual(card.may_set_profile, { per_day: 1 })
assert.deepEqual(card.harness, { runner: 'codex' })
assert(card.withheld.includes('channel ids') && card.not_reported.includes('last reply'))
const text = JSON.stringify(card)
for (const hidden of ['/etc/nvoy', root, 'buzz.example', 'seat.nsec', 'seat-codex', channel, peer, 'peer', 'gpt-5.6', 'cd'.repeat(32)])
  assert(!text.includes(hidden), `card leaks ${hidden}`)
assert.equal(card.summary, 'It replies to work it is given; it may start a message in 1 channel, at most 5 an hour, mentioning up to' +
  ' 1 named participant; it may set its own profile, at most 1 a day; a chain of agent messages stops at 3 hops, and at most 12' +
  ' messages an hour from one sender are admitted.')

// Due when new, changed or stale; current otherwise. Owed relays are the ones that have not read it back.
const now = Date.now(), last = { event: { id: 'x' }, digest: cardDigest(card), at: now }
assert.equal(cardDue(card, null, now), true)
assert.equal(cardDue(card, last, now + 60000), false)
assert.equal(cardDue({ ...card, grantors: [] }, last, now), true)
assert.equal(cardDue(card, last, now + CARD_REFRESH_MS), true)
assert.deepEqual(relaysOwed(['wss://a', 'wss://b', 'wss://c'], { relays: [{ relay: 'wss://a', read_back: true }, { relay: 'wss://b', read_back: false }] }), ['wss://b', 'wss://c'])
assert.deepEqual(cardRelays(''), ['wss://relay.nave.pub'])
assert.deepEqual(cardRelays('ws://x, ws://y,ws://x'), ['ws://x', 'ws://y'])

// End to end: two relays read it back and one refuses. The refusal is retried with the SAME signed
// event each run until that relay reads it back; nothing is re-signed to retry.
const good = await relay(), other = await relay(), bad = await relay({ refuse: true })
const live = fixture('live')
const credential = join(root, 'credential')
writeFileSync(credential, Buffer.from(secret).toString('hex'))
const statePath = join(live.directory, 'state', 'agent-card.json')
function run(relays) {
  return new Promise(done => {
    const child = spawn(process.execPath, ['mcp/tools/instance-broker-card.mjs', '--instance', 'live'],
      { cwd: new URL('..', import.meta.url).pathname, env: { ...process.env, NVOY_INSTANCE_ROOT: live.root, NVOY_BROKER_CREDENTIAL: credential, NVOY_CARD_RELAYS: relays.join(',') } })
    let out = '', err = ''
    child.stdout.on('data', c => { out += c }); child.stderr.on('data', c => { err += c })
    child.on('exit', code => done({ code, report: out.trim() ? JSON.parse(out.trim()) : null, err: err.trim() }))
  })
}
const all = [good.url, other.url, bad.url]
const first = await run(all)
assert.equal(first.code, 1, first.err)
assert.equal(first.report.card, 'incomplete')
assert.deepEqual(first.report.read_back, [good.url, other.url])
assert(first.report.missing[0].startsWith(`${bad.url}: blocked`))
const event = good.stored[0]
assert(verifyEvent(event) && event.pubkey === pubkey && event.kind === CARD_KIND && event.tags[0][1] === CARD_D)
assert.equal(JSON.parse(event.content).instance, 'live')
let saved = JSON.parse(readFileSync(statePath, 'utf8'))
assert.equal(saved.event.id, event.id)
assert.deepEqual(saved.relays.map(r => [r.relay, r.accepted, r.read_back]), [[good.url, true, true], [other.url, true, true], [bad.url, false, false]])

const second = await run(all)
assert.equal(second.code, 1)
assert.equal(second.report.event_id, event.id, 'a retry sends the same event')
assert.equal(good.stored.length + other.stored.length, 2, 'relays that read it back are not sent it again')

bad.options.refuse = false
const third = await run(all)
assert.equal(third.code, 0, third.err)
assert.equal(third.report.card, 'published')
assert.equal(bad.stored[0].id, event.id, 'the recovered relay gets the same signed event')
const fourth = await run(all)
assert.deepEqual(fourth.report, { card: 'current', event_id: event.id })
assert.equal(good.stored.length + other.stored.length + bad.stored.length, 3)

// A new card relay is owed the current event without a new signature.
const late = await relay()
const fifth = await run([...all, late.url])
assert.equal(fifth.code, 0, fifth.err)
assert.equal(late.stored[0].id, event.id)

for (const r of [good, other, bad, late]) r.close()
console.log('ok agent card: coarse public projection, signed by the agent, retried per relay with the same event until read back')
process.exit(0)
