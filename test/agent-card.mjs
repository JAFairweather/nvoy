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
import { agentCard, cardDigest, cardDue, cardRelays, CARD_D, CARD_KIND, CARD_REFRESH_MS } from '../mcp/tools/agent_card.mjs'
import { GRANT_RELAYS } from '../mcp/tools/grant_relays.mjs'

const secret = generateSecretKey(), pubkey = getPublicKey(secret)
const grantor = getPublicKey(generateSecretKey()), peer = getPublicKey(generateSecretKey())
const channel = '00000000-0000-4000-8000-000000000000'
const root = mkdtempSync(join(tmpdir(), 'nvoy-agent-card-'))

// A relay that stores what it accepts and answers address queries; `refuse` makes it say no.
async function relay({ refuse = false } = {}) {
  const server = createServer((request, response) => { response.writeHead(404); response.end() })
  await new Promise(done => server.listen(0, '127.0.0.1', done))
  const stored = [], url = `ws://127.0.0.1:${server.address().port}`
  new WebSocketServer({ server }).on('connection', socket => socket.on('message', raw => {
    const frame = JSON.parse(raw.toString())
    if (frame[0] === 'EVENT') {
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
  return { url, stored, close: () => server.close() }
}

function fixture(id, extra = {}) {
  const directory = join(root, id)
  for (const name of ['instances', 'state', 'run', 'spool']) mkdirSync(join(directory, name), { recursive: true })
  const raw = { id, pubkey, grantors: [grantor], relays: ['wss://relay.example'], buzz: { relay: 'wss://buzz.example', channels: [channel] },
    broker_mode: 'local', key_ref: '/etc/nvoy/credentials/seat.nsec', delivery_mode: 'notify_only', worker_enabled: false,
    state_dir: join(directory, 'state'), runtime_dir: join(directory, 'run'), spool_dir: join(directory, 'spool'),
    broker_adapter_gid: 1001, worker_handoff_gid: 1002, watcher_uid: 1001, broker_uid: 1002, adapter_uid: 1003, worker_uid: 1004,
    may_post: { channels: [channel], per_hour: 5, mention: [{ name: 'peer', pubkey: peer }] },
    harness: { runner: 'codex', credential_ref: '/etc/nvoy/credentials/seat-codex.json', model: 'gpt-5.6' }, agent_card: true, ...extra }
  writeFileSync(join(directory, 'instances', `${id}.json`), JSON.stringify(raw))
  return { root: join(directory, 'instances'), directory, load: () => readManifest(join(directory, 'instances'), id) }
}

// The manifest switch: off by default, a boolean, and only where a local broker can sign.
assert.equal(fixture('default', { agent_card: undefined }).load().agentCard, false)
assert.throws(() => fixture('not-bool', { agent_card: 'yes' }).load(), /agent_card must be true or false/)
assert.throws(() => fixture('no-buzz', { buzz: undefined, may_post: undefined }).load(), /agent_card requires a buzz block/)

// The card is the allowlist and nothing else: no credential path, uid, directory or Buzz relay address.
const seat = fixture('seat'), manifest = seat.load()
const card = agentCard(manifest, { release: 'a'.repeat(40) })
assert.deepEqual(Object.keys(card), ['version', 'instance', 'pubkey', 'release', 'grantors', 'carriers', 'relays', 'buzz_channels',
  'may_post', 'may_set_profile', 'agent_limits', 'delivery_mode', 'harness', 'holdings', 'summary'])
assert.deepEqual(card.grantors, [grantor])
assert.deepEqual(card.may_post, { channels: [channel], per_hour: 5, mention: [{ name: 'peer', pubkey: peer }] })
assert.deepEqual(card.harness, { runner: 'codex', model: 'gpt-5.6' })
assert.deepEqual(card.holdings.map(h => h.name), ['nostr identity', 'codex harness login'])
const text = JSON.stringify(card)
for (const hidden of ['/etc/nvoy', root, 'buzz.example', 'seat.nsec', 'seat-codex']) assert(!text.includes(hidden), `card leaks ${hidden}`)
assert(card.summary.startsWith('What this identity may do'))

// Due when new, changed or stale; current otherwise.
const now = Date.now(), last = { digest: cardDigest(card), at: now }
assert.equal(cardDue(card, null, now), true)
assert.equal(cardDue(card, last, now + 60000), false)
assert.equal(cardDue({ ...card, grantors: [] }, last, now), true)
assert.equal(cardDue(card, last, now + CARD_REFRESH_MS), true)
// Public relays get the shared grant set; loopback-only sets stay local.
assert.deepEqual(cardRelays(manifest, ''), [...GRANT_RELAYS, 'wss://relay.example'])

// End to end: two relays take the card, one refuses; the record names each, and a rerun is a no-op.
const good = await relay(), other = await relay(), bad = await relay({ refuse: true })
const live = fixture('live')
const credential = join(root, 'credential')
writeFileSync(credential, Buffer.from(secret).toString('hex'))
function run(env = {}) {
  return new Promise(done => {
    const child = spawn(process.execPath, ['mcp/tools/instance-broker-card.mjs', '--instance', 'live'],
      { cwd: new URL('..', import.meta.url).pathname, env: { ...process.env, NVOY_INSTANCE_ROOT: live.root, NVOY_BROKER_CREDENTIAL: credential, NVOY_GRANT_RELAYS: [good.url, other.url, bad.url].join(','), ...env } })
    let out = '', err = ''
    child.stdout.on('data', c => { out += c }); child.stderr.on('data', c => { err += c })
    child.on('exit', code => done({ code, out: out.trim(), err: err.trim() }))
  })
}
const first = await run()
assert.equal(first.code, 0, first.err)
const report = JSON.parse(first.out)
assert.equal(report.card, 'published')
assert.deepEqual(report.read_back, [good.url, other.url])
assert.equal(report.missing.length, 1)
assert(report.missing[0].startsWith(bad.url))
const event = good.stored[0]
assert(verifyEvent(event) && event.pubkey === pubkey && event.kind === CARD_KIND && event.tags[0][1] === CARD_D)
assert.equal(JSON.parse(event.content).instance, 'live')
const record = JSON.parse(readFileSync(join(live.directory, 'state', 'agent-card.json'), 'utf8'))
assert.equal(record.event_id, event.id)
assert.deepEqual(record.relays.map(r => [r.accepted, r.read_back]), [[true, true], [true, true], [false, false]])
const second = await run()
assert.equal(second.code, 0, second.err)
assert.deepEqual(JSON.parse(second.out), { card: 'current', event_id: event.id })
assert.equal(good.stored.length, 1, 'an unchanged card is not re-signed')

// No relay reads it back: nothing is recorded and the run fails, so the daemon tries again.
const lonely = fixture('lonely')
const failed = await new Promise(done => {
  const child = spawn(process.execPath, ['mcp/tools/instance-broker-card.mjs', '--instance', 'lonely'],
    { cwd: new URL('..', import.meta.url).pathname, env: { ...process.env, NVOY_INSTANCE_ROOT: lonely.root, NVOY_BROKER_CREDENTIAL: credential, NVOY_GRANT_RELAYS: bad.url } })
  let out = ''
  child.stdout.on('data', c => { out += c })
  child.on('exit', code => done({ code, out }))
})
assert.equal(failed.code, 1)
assert.equal(JSON.parse(failed.out).card, 'unconfirmed')
assert.throws(() => readFileSync(join(lonely.directory, 'state', 'agent-card.json')), /ENOENT/)

for (const r of [good, other, bad]) r.close()
console.log('ok agent card: allowlisted, signed by the agent, read back per relay, re-signed only when due')
process.exit(0)
