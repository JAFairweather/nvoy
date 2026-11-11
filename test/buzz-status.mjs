// Native Buzz status reactions: 👀 when the broker admits a mention, 💬 when the keyless reader
// first opens it, both removed (NIP-09) when the reply lands or the turn goes stale. The shapes
// are Buzz's own runner's: a kind 7 with exactly one e tag, a kind 5 naming the reaction. Only the
// broker signs, only for its own admitted source events, and only deletes what it published.
import { WebSocketServer } from 'ws'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'
import { openBuzzSession } from '../mcp/tools/buzz_native.mjs'
import { STATUS, STATUS_STALE_MS, classifyFailure, createStatusKeeper, parseStatusFact, parseStatusRequest, recordStatusAdmission,
  recordStatusReplied, requestWorkingStatus, statusDeletionTemplate, statusPaths, statusReactionTemplate } from '../mcp/tools/buzz_status.mjs'

let passed = 0, failed = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passed++ : failed++ }
const sleep = ms => new Promise(r => setTimeout(r, ms))
const until = async (fn, ms = 8000) => { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(50) } return false }
const throws = fn => { try { fn(); return null } catch (e) { return e.message } }

const CH = '3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607', OTHER = '00000000-0000-4000-8000-000000000000'
const agentSk = generateSecretKey(), agent = getPublicKey(agentSk)
const humanSk = generateSecretKey(), human = getPublicKey(humanSk)
const local = sk => ({ getPublicKey: async () => getPublicKey(sk), signEvent: async t => finalizeEvent(t, sk) })
const uid = process.getuid(), gid = process.getgid()
const root = mkdtempSync(join(tmpdir(), 'nvoy-buzz-status-'))
const fixture = (id, extra = {}, buzz = { relay: 'wss://buzz.example', channels: [CH] }) => {
  const dir = join(root, id)
  for (const d of ['instances', 'state', 'run', 'spool']) mkdirSync(join(dir, d), { recursive: true, mode: 0o700 })
  const raw = { version: 1, id, pubkey: agent, broker_mode: 'local', state_dir: join(dir, 'state'), runtime_dir: join(dir, 'run'),
    spool_dir: join(dir, 'spool'), bunker_uri_ref: '/etc/nvoy/test.bunker', bunker_client_ref: '/etc/nvoy/test.client', worker_enabled: false,
    delivery_mode: 'notify_only', broker_adapter_gid: gid, worker_handoff_gid: gid + 1, watcher_uid: uid + 11, broker_uid: uid + 12,
    adapter_uid: uid + 13, worker_uid: uid, grantors: ['2'.repeat(64)], relays: ['wss://nos.lol'], ...(buzz ? { buzz } : {}), ...extra }
  writeFileSync(join(dir, 'instances', `${id}.json`), JSON.stringify(raw))
  return { dir, instances: join(dir, 'instances'), manifest: () => readManifest(join(dir, 'instances'), id) }
}

// --- wire shapes ---
const target = 'a'.repeat(64)
const seen = statusReactionTemplate(target, 'seen', 1)
ok('👀 is a kind 7 with exactly one e tag and nothing else', seen.kind === 7 && seen.content === '\u{1F440}' && JSON.stringify(seen.tags) === JSON.stringify([['e', target]]))
ok('💬 is the same shape', statusReactionTemplate(target, 'working', 1).content === '\u{1F4AC}' && statusReactionTemplate(target, 'working', 1).tags.length === 1)
ok('a removal is a kind 5 naming only the reaction', JSON.stringify(statusDeletionTemplate('b'.repeat(64), 1)) === JSON.stringify({ kind: 5, created_at: 1, content: '', tags: [['e', 'b'.repeat(64)]] }))
ok('no free-form emoji', !!throws(() => statusReactionTemplate(target, '🔥')) && !!throws(() => statusReactionTemplate(target, 'toString')))
ok('no target that is not an event id', !!throws(() => statusReactionTemplate('general', 'seen')))

// --- manifest switch ---
ok('status reactions default on with a buzz block', fixture('default').manifest().buzz.statusReactions === true)
ok('an owner can switch them off', fixture('off', {}, { relay: 'wss://buzz.example', channels: [CH], status_reactions: false }).manifest().buzz.statusReactions === false)
ok('a non-boolean switch is refused', /status_reactions must be true or false/.test(throws(fixture('bad', {}, { relay: 'wss://buzz.example', channels: [CH], status_reactions: 'yes' }).manifest) || ''))
ok('no buzz block, no status', fixture('none', {}, null).manifest().buzz === null)

// --- the keyless request is one envelope, nothing else ---
const on = fixture('on').manifest()
const envelope = 'c'.repeat(64)
const req = extra => JSON.stringify({ version: 1, type: 'status-request', instance: 'on', envelope, state: 'working', ...extra })
ok('a well-formed working request names its envelope', parseStatusRequest(req(), on) === envelope)
ok('a request cannot pick the emoji', parseStatusRequest(req({ emoji: '🔥' }), on) === null)
ok('a request cannot pick the target', parseStatusRequest(req({ target }), on) === null)
ok('a request cannot claim "seen" — only the broker decides that', parseStatusRequest(req({ state: 'seen' }), on) === null)
ok('a request for another instance is ignored', parseStatusRequest(req({ instance: 'other' }), on) === null)
const factLine = channel => JSON.stringify({ version: 1, fact: 'admitted', envelope, target, channel, at: 1 })
ok('a fact outside the manifest channels is ignored', parseStatusFact(factLine(OTHER), on) === null && parseStatusFact(factLine(CH), on)?.target === target)

const v3 = { type: 'admitted-task', envelope, authority: { version: 3, source_event: envelope, reply_channel: CH }, messages: [{}] }
const paths = statusPaths(on)
ok('the reader never creates the status queue', requestWorkingStatus(on, v3) === false && !existsSync(paths.requests))
writeFileSync(paths.requests, '', { mode: 0o640 })
ok('a v3 Buzz instruction asks for 💬', requestWorkingStatus(on, v3) === true && parseStatusRequest(readFileSync(paths.requests, 'utf8').trim(), on) === envelope)
writeFileSync(paths.requests, '')
ok('data-only, notifications and foreign channels ask for nothing',
  !requestWorkingStatus(on, { ...v3, authority: null }) && !requestWorkingStatus(on, { ...v3, type: 'verified-notification' }) &&
  !requestWorkingStatus(on, { ...v3, authority: { ...v3.authority, reply_channel: OTHER } }) && readFileSync(paths.requests, 'utf8') === '')
ok('a switched-off manifest records nothing', recordStatusAdmission(fixture('off2', {}, { relay: 'wss://buzz.example', channels: [CH], status_reactions: false }).manifest(), { envelope, target, channel: CH }) === false)
ok('an admission outside the Buzz channels records nothing', recordStatusAdmission(on, { envelope, target, channel: OTHER }) === false && !existsSync(paths.facts))

ok('failures are classes, not text', classifyFailure(new Error('bunker: kind 7 not permitted')) === 'bunker-refused' &&
  classifyFailure(new Error('nip46 sign_event timed out')) === 'signer-timeout' && classifyFailure(new Error('relay OK timed out')) === 'relay-timeout' &&
  classifyFailure(new Error('relay connection error: ECONNREFUSED')) === 'relay-unavailable')

// --- the keeper, on a fake clock and a fake session ---
function harness(id, { signer = local(agentSk), openSession } = {}) {
  const fx = fixture(id), manifest = fx.manifest()
  let clock = 1_800_000_000_000
  const published = [], logs = []
  const session = { publishSigned: async ev => { published.push(ev); return { accepted: true } }, close() {}, closed: new Promise(() => {}) }
  const make = () => createStatusKeeper({ manifest, signer, now: () => clock, log: l => logs.push(l), openSession: openSession || (async () => session) })
  return { manifest, published, logs, make, tick: ms => { clock += ms }, now: () => clock }
}
const fact = (h, extra = {}) => ({ fact: 'admitted', envelope, target, channel: CH, at: h.now(), ...extra })

{
  const h = harness('keeper')
  let k = h.make()
  await k.step({ facts: [fact(h)] })
  const [eyes] = h.published
  ok('admission puts 👀 on the source event, signed by the identity', h.published.length === 1 && eyes.kind === 7 && eyes.content === STATUS.seen &&
    eyes.pubkey === agent && JSON.stringify(eyes.tags) === JSON.stringify([['e', target]]) && verifyEvent({ ...eyes }))
  await k.step({ facts: [fact(h)] })
  ok('a replayed admission reacts once', h.published.length === 1)
  await k.step({ requests: ['d'.repeat(64)] })
  ok('a request for an envelope the broker never admitted does nothing', h.published.length === 1)
  await k.step({ requests: [envelope] })
  const speech = h.published[1]
  ok('the first read puts 💬 on the same event', h.published.length === 2 && speech.kind === 7 && speech.content === STATUS.working && speech.tags[0][1] === target)
  await k.step({ requests: [envelope] })
  ok('a second read reacts once', h.published.length === 2)
  k = h.make()
  await k.step({ facts: [fact(h)], requests: [envelope] })
  ok('a restarted keeper neither re-reacts nor forgets', h.published.length === 2 && k.snapshot().envelopes[envelope].working.event.id === speech.id)
  await k.step({ facts: [{ fact: 'replied', envelope, at: h.now() }] })
  const deletions = h.published.slice(2)
  ok('the reply removes both, one kind 5 per reaction it published', deletions.length === 2 && deletions.every(d => d.kind === 5 && d.pubkey === agent && d.tags.length === 1) &&
    deletions.map(d => d.tags[0][1]).sort().join() === [eyes.id, speech.id].sort().join())
  await k.step({ facts: [{ fact: 'replied', envelope, at: h.now() }], requests: [envelope] })
  ok('after the reply nothing is re-added or re-deleted', h.published.length === 4)
  ok('nothing logged on the happy path', h.logs.length === 0)
  h.tick(25 * 60 * 60 * 1000); await k.step()
  ok('cleared entries are pruned after a day', !(envelope in k.snapshot().envelopes))
  await k.step({ facts: [fact(h, { at: h.now() - STATUS_STALE_MS - 1 })] })
  ok('an admission older than a live turn is history, not a mention', h.published.length === 4)
}
{
  const h = harness('stale')
  const k = h.make()
  await k.step({ facts: [fact(h)], requests: [envelope] })
  h.tick(STATUS_STALE_MS + 1000); await k.step()
  ok('a turn that never replies is cleared by the sweep', h.published.length === 4 && h.published.slice(2).every(e => e.kind === 5) && k.snapshot().envelopes[envelope].cleared_by === 'stale')
}
{
  const h = harness('early')
  const k = h.make()
  await k.step({ requests: [envelope] })
  await k.step({ facts: [fact(h)] })
  ok('a read that races ahead of the admission fact still gets 💬, after 👀', h.published.map(e => e.content).join() === [STATUS.seen, STATUS.working].join())
}
{
  const refusing = { getPublicKey: async () => agent, signEvent: async () => { throw new Error('bunker: permission denied for kind 7') } }
  const h = harness('refused', { signer: refusing })
  const k = h.make()
  await k.step({ facts: [fact(h)], requests: [envelope] })
  await k.step({ facts: [fact(h, { envelope: 'e'.repeat(64) })] })
  const told = h.logs.filter(l => /Bunker refused kind 7 — widen the pairing's permissions/.test(l))
  ok('a Bunker refusal publishes nothing and is explained once', h.published.length === 0 && told.length === 1)
  ok('each failed transition is one classed line, no content', h.logs.filter(l => /^status\[.+\] [0-9a-f]{12} failed: bunker-refused$/.test(l)).length === 3)
}
{
  let opens = 0
  const h = harness('down', { openSession: async () => { opens++; throw new Error('relay connection error: ECONNREFUSED') } })
  const k = h.make()
  await k.step({ facts: [fact(h)] })
  ok('a relay outage is logged by class and does not throw', h.logs.some(l => /status\[👀\] c{12} failed: relay-unavailable/.test(l)))
  h.tick(STATUS_STALE_MS + 1000)
  for (let i = 0; i < 5; i++) await k.step()
  const d = k.snapshot().envelopes[envelope].deletions
  ok('an uncertain 👀 is still removed, and removal retries are bounded', d.length === 1 && d[0].attempts === 3 && opens === 4)
}
{
  const h = harness('liar', { signer: { getPublicKey: async () => agent, signEvent: async t => finalizeEvent({ ...t, content: '🔥' }, agentSk) } })
  const k = h.make()
  await k.step({ facts: [fact(h)] })
  ok('a signer that returns a different event is not published', h.published.length === 0)
}

// --- where the keyed processes record their facts ---
const src = f => readFileSync(`mcp/tools/${f}`, 'utf8')
const nativeSrc = src('instance-broker-native.mjs'), carrySrc = src('instance-broker.mjs'), replySrc = src('instance-broker-reply.mjs')
const daemonSrc = src('instance-broker-daemon.mjs'), initSrc = src('instance-runtime-init.mjs')
ok('native admission records 👀 only after the adapter acknowledged, for the verified event in its channel',
  /ack\.type !== 'ack'[\s\S]*completeChannelSource[\s\S]*recordStatusAdmission\(manifest, \{ envelope: eventId, target: eventId, channel: mention\.channel \}\)/.test(nativeSrc))
ok('carried admission records 👀 after acknowledgement, on the original Buzz source event',
  /ack\.type !== 'ack'[\s\S]*if \(channelCarry\) \{\s*try \{ recordStatusAdmission\(manifest, \{ envelope, target: receipt\.source_event, channel: receipt\.reply_channel \}\)/.test(carrySrc))
ok('a status fact failure never fails a delivery', /recordStatusAdmission[^\n]*\n\s*catch \(e\) \{ console\.error/.test(nativeSrc) && /recordStatusAdmission[^\n]*\n\s*catch \(e\) \{ console\.error/.test(carrySrc))
ok('the reply records "replied" only after the relay accepted it and the receipt was consumed',
  /renameSync\(receiptInflight, receiptUsed\) \} catch \(e\) \{ die\(`published[\s\S]*if \(channelReplyPath\) \{\s*try \{ recordStatusReplied/.test(replySrc))
ok('the daemon supervises the keeper only when the manifest enables it', /if \(manifest\.buzz\?\.statusReactions\) supervise\('instance-broker-status\.mjs'/.test(daemonSrc))
ok('the installer provisions the request queue worker-writable, broker-group-readable',
  /status-requests\.jsonl`, m\.workerUid, m\.brokerAdapterGid, 0o640/.test(initSrc))

// --- end to end: the keeper process against a Buzz-shaped relay ---
const members = new Set([agent, human]), stored = []
const http = createServer((req, res) => { res.writeHead(404); res.end() })
await new Promise(r => http.listen(0, '127.0.0.1', r))
const RELAY = `ws://127.0.0.1:${http.address().port}`
const wss = new WebSocketServer({ server: http })
wss.on('connection', ws => {
  const challenge = Buffer.from(generateSecretKey()).toString('hex')
  let authed = null
  ws.send(JSON.stringify(['AUTH', challenge]))
  ws.on('message', raw => {
    const m = JSON.parse(raw.toString())
    if (m[0] === 'AUTH') {
      const ev = m[1], tag = n => ev.tags.find(t => t[0] === n)?.[1]
      if (!(verifyEvent(ev) && tag('challenge') === challenge && tag('relay') === RELAY && members.has(ev.pubkey))) return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted']))
      authed = ev.pubkey
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
    if (m[0] !== 'EVENT') return
    const ev = m[1], e = ev.tags.filter(t => t[0] === 'e')
    // As Buzz: a reaction or deletion carries one e tag and derives its channel from the target.
    const shaped = [7, 5].includes(ev.kind) ? e.length === 1 && ev.tags.length === 1 && stored.some(s => s.id === e[0][1]) : ev.tags.some(t => t[0] === 'h')
    if (!authed || ev.pubkey !== authed || !verifyEvent(ev) || !shaped) return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted']))
    stored.push(ev)
    ws.send(JSON.stringify(['OK', ev.id, true, '']))
  })
})
const s = await openBuzzSession({ relay: RELAY, signer: local(humanSk) })
const mention = (await s.publish({ kind: 9, created_at: Math.floor(Date.now() / 1000), content: 'agent, status?', tags: [['h', CH], ['p', agent]] })).event
s.close()

const e2e = fixture('e2e', {}, { relay: RELAY, channels: [CH] }), em = e2e.manifest()
const credential = join(root, 'agent.key'); writeFileSync(credential, Buffer.from(agentSk).toString('hex'), { mode: 0o600 })
writeFileSync(statusPaths(em).requests, '', { mode: 0o640 })
let out = ''
const keeper = spawn(process.execPath, ['mcp/tools/instance-broker-status.mjs', '--instance', 'e2e'],
  { env: { PATH: process.env.PATH, NVOY_INSTANCE_ROOT: e2e.instances, NVOY_BROKER_CREDENTIAL: credential }, stdio: ['ignore', 'pipe', 'pipe'] })
keeper.stdout.on('data', c => { out += c }); keeper.stderr.on('data', c => { out += c })
ok('the keeper starts as the broker identity', await until(() => /keeping status reactions for e2e/.test(out)))
const mine = kind => stored.filter(ev => ev.pubkey === agent && ev.kind === kind)
recordStatusAdmission(em, { envelope: mention.id, target: mention.id, channel: CH })
ok('the relay accepts 👀 on the mention', await until(() => mine(7).some(ev => ev.content === STATUS.seen && ev.tags[0][1] === mention.id)))

// The Codex channel reader asks for 💬 on the first read only.
const task = { type: 'admitted-task', instance: 'e2e', envelope: mention.id, received_at: Date.now(),
  authority: { version: 3, type: 'scoped-instruction', sender: human, grant_id: '7'.repeat(64), grantor: '2'.repeat(64), cap: 'task',
    scope_subject: agent, policy_checked_at: Date.now(), source_event: mention.id, reply_channel: CH },
  messages: [{ from: human, at: mention.created_at, content: mention.content, event_id: mention.id, kind: 9 }] }
writeFileSync(join(e2e.dir, 'run', 'admitted-tasks.jsonl'), JSON.stringify(task) + '\n')
writeFileSync(join(e2e.dir, 'run', 'reply-requests.jsonl'), '')
mkdirSync(join(e2e.dir, 'run', 'codex-mcp-state'))
const client = new Client({ name: 'status-test', version: '0.1.0' })
await client.connect(new StdioClientTransport({ command: process.execPath, args: [resolve('mcp/tools/codex-channel-mcp.mjs'), '--instance', 'e2e'],
  env: { ...process.env, NVOY_INSTANCE_ROOT: e2e.instances }, stderr: 'pipe' }))
await client.callTool({ name: 'nvoy_channel_read', arguments: { envelope: mention.id } })
await client.callTool({ name: 'nvoy_channel_read', arguments: { envelope: mention.id } })
await client.close()
const asked = readFileSync(statusPaths(em).requests, 'utf8').trim().split('\n').filter(Boolean)
ok('the Codex reader asks once, naming only the envelope', asked.length === 1 && parseStatusRequest(asked[0], em) === mention.id)
ok('the relay accepts 💬 on the mention', await until(() => mine(7).some(ev => ev.content === STATUS.working && ev.tags[0][1] === mention.id)))

// The Claude channel reader does the same on its first read.
writeFileSync(statusPaths(em).requests, '')
mkdirSync(join(e2e.dir, 'run', 'claude-channel-state'))
const claude = new Client({ name: 'status-test-claude', version: '0.1.0' })
await claude.connect(new StdioClientTransport({ command: process.execPath, args: [resolve('mcp/tools/claude-channel.mjs'), '--instance', 'e2e'],
  env: { ...process.env, NVOY_INSTANCE_ROOT: e2e.instances }, stderr: 'pipe' }))
await claude.callTool({ name: 'nvoy_channel_list', arguments: {} })
await claude.callTool({ name: 'nvoy_channel_read', arguments: { envelope: mention.id } })
await claude.callTool({ name: 'nvoy_channel_read', arguments: { envelope: mention.id } })
await claude.close()
const claudeAsked = readFileSync(statusPaths(em).requests, 'utf8').trim().split('\n').filter(Boolean)
ok('the Claude reader asks once, naming only the envelope', claudeAsked.length === 1 && parseStatusRequest(claudeAsked[0], em) === mention.id)
await sleep(1500)
ok('a second reader\'s request does not react twice', mine(7).length === 2)

recordStatusReplied(em, { envelope: mention.id })
ok('the reply removes both reactions from the relay', await until(() => mine(5).length === 2) &&
  mine(5).map(ev => ev.tags[0][1]).sort().join() === mine(7).map(ev => ev.id).sort().join())
ok('nothing was logged as a failure', !/failed/.test(out))
keeper.kill('SIGTERM')
await until(() => keeper.exitCode !== null)
ok('the keeper releases its lock on stop', !existsSync(statusPaths(em).lock))

wss.close(); http.close()
console.log(`\n${passed}/${passed + failed} passed`)
process.exit(failed ? 1 : 0)
