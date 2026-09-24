// Native ears and mouth on a Buzz relay (salvage plan 2.3): the keyless watcher logs in through
// the broker's AUTH oracle and marks mentions; the keyed broker re-fetches, admits on the author's
// own grant, and answers with a kind:9. The stub relay keeps subscriptions open past EOSE and
// honours #h, #p, ids, kinds and since, as Buzz does, so a watcher that hears nothing fails here.
import { WebSocketServer } from 'ws'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import net from 'node:net'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { authOracleSigner, channelReply, openBuzzSession, serveAuthOracle } from '../mcp/tools/buzz_native.mjs'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'
import { validateAdmittedTask } from '../mcp/tools/admitted_task.mjs'
import { validateOutboundRecord } from '../mcp/tools/outbound_record.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const sleep = ms => new Promise(r => setTimeout(r, ms))
const now = () => Math.floor(Date.now() / 1000)
const until = async (fn, ms = 5000) => { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(50) } return false }
const throws = fn => { try { fn(); return null } catch (e) { return e.message } }

const CH = '3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607', OTHER = '00000000-0000-4000-8000-000000000000'
const agentSk = generateSecretKey(), agent = getPublicKey(agentSk)
const humanSk = generateSecretKey(), human = getPublicKey(humanSk)
const local = sk => ({ getPublicKey: async () => getPublicKey(sk), signEvent: async t => finalizeEvent(t, sk) })

// --- a Buzz-shaped relay with live subscriptions ---
const members = new Set([agent, human]), stored = [], sockets = []
const matches = (f, ev) => {
  const vals = n => ev.tags.filter(t => t[0] === n).map(t => t[1])
  return f['#h'].some(h => vals('h').includes(h)) && (!f.ids || f.ids.includes(ev.id)) && (!f.kinds || f.kinds.includes(ev.kind)) &&
    (!f['#p'] || f['#p'].some(p => vals('p').includes(p))) && (!f.since || ev.created_at >= f.since)
}
const http = createServer((req, res) => { res.writeHead(404); res.end() })
await new Promise(r => http.listen(0, '127.0.0.1', r))
const RELAY = `ws://127.0.0.1:${http.address().port}`
const server = new WebSocketServer({ server: http })
server.on('connection', ws => {
  sockets.push(ws)
  const challenge = Buffer.from(generateSecretKey()).toString('hex'), live = new Map()
  let authed = null
  ws.send(JSON.stringify(['AUTH', challenge]))
  ws.on('message', raw => {
    const m = JSON.parse(raw.toString())
    if (m[0] === 'AUTH') {
      const ev = m[1], tag = n => ev.tags.find(t => t[0] === n)?.[1]
      if (!(verifyEvent(ev) && ev.kind === 22242 && tag('challenge') === challenge && tag('relay') === RELAY)) return ws.send(JSON.stringify(['OK', ev.id, false, 'auth-required: invalid auth event']))
      if (!members.has(ev.pubkey)) return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted: not a relay member']))
      authed = ev.pubkey
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
    if (m[0] === 'EVENT') {
      const ev = m[1]
      if (!authed || ev.pubkey !== authed || !ev.tags.some(t => t[0] === 'h') || !verifyEvent(ev)) return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted']))
      stored.push(ev)
      ws.send(JSON.stringify(['OK', ev.id, true, '']))
      for (const peer of server.clients) peer.emit('stored', ev)
      return
    }
    if (m[0] === 'REQ') {
      if (!authed) return ws.send(JSON.stringify(['CLOSED', m[1], 'auth-required: authenticate first']))
      const filters = m.slice(2)
      if (filters.some(f => !f['#h'])) return ws.send(JSON.stringify(['EOSE', m[1]]))
      for (const ev of stored) if (filters.some(f => matches(f, ev))) ws.send(JSON.stringify(['EVENT', m[1], ev]))
      live.set(m[1], filters)
      return ws.send(JSON.stringify(['EOSE', m[1]]))
    }
    if (m[0] === 'CLOSE') live.delete(m[1])
  })
  ws.on('stored', ev => { for (const [id, filters] of live) if (filters.some(f => matches(f, ev))) ws.send(JSON.stringify(['EVENT', id, ev])) })
})
const post = async (sk, template) => {
  const s = await openBuzzSession({ relay: RELAY, signer: local(sk) })
  try { return (await s.publish({ created_at: now(), content: '', ...template })).event } finally { s.close() }
}

// --- the manifest's buzz block ---
const root = mkdtempSync(join(tmpdir(), 'nvoy-buzz-ears-'))
// One root per fixture: the collision check reads every manifest beside the one it loads, and
// these fixtures deliberately share an identity and include invalid ones.
const rootFor = id => join(root, 'instances', id)
const gid = process.getgid(), otherGid = process.getgroups().find(g => g !== gid)
const baseManifest = { version: 1, id: 'ears', pubkey: agent, worker_enabled: false, key_ref: '/etc/nvoy/credentials/ears.nsec',
  state_dir: join(root, 'state'), runtime_dir: join(root, 'run'), spool_dir: join(root, 'spool'),
  broker_adapter_gid: gid, worker_handoff_gid: otherGid, watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013, worker_uid: 41014,
  grantors: ['4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'], relays: ['wss://127.0.0.1:1'] }
for (const d of ['state', 'run', 'spool']) mkdirSync(join(root, d), { mode: 0o700 })
const manifestWith = (id, extra) => {
  mkdirSync(rootFor(id), { recursive: true })
  writeFileSync(join(rootFor(id), `${id}.json`), JSON.stringify({ ...baseManifest, id, ...extra }))
  return () => readManifest(rootFor(id), id)
}
ok('a manifest without a buzz block has no native ears', manifestWith('plain', {})().buzz === null)
const parsed = manifestWith('ears', { buzz: { relay: RELAY, channels: [CH.toUpperCase()] } })()
ok('a buzz block parses to its relay origin and lower-cased channels', parsed.buzz.relay === RELAY && parsed.buzz.channels[0] === CH)
ok('a buzz block is frozen', Object.isFrozen(parsed.buzz) && Object.isFrozen(parsed.buzz.channels))
ok('duplicate channels are refused', /distinct channel UUIDs/.test(throws(manifestWith('dup', { buzz: { relay: RELAY, channels: [CH, CH] } })) || ''))
ok('a non-UUID channel is refused', /distinct channel UUIDs/.test(throws(manifestWith('nouuid', { buzz: { relay: RELAY, channels: ['general'] } })) || ''))
ok('a plaintext off-loopback relay is refused', /buzz\.relay/.test(throws(manifestWith('plainrelay', { buzz: { relay: 'ws://buzz.example', channels: [CH] } })) || ''))
ok('a relay with a path is refused', /buzz\.relay/.test(throws(manifestWith('pathrelay', { buzz: { relay: 'wss://buzz.example/x', channels: [CH] } })) || ''))

// --- the AUTH oracle ---
let signed = 0
const counting = { getPublicKey: async () => agent, signEvent: async t => { signed++; return finalizeEvent(t, agentSk) } }
const oracleSock = join(root, 'spool', 'buzz-auth.sock')
const oracle = await serveAuthOracle({ socketPath: oracleSock, relay: RELAY, signer: counting, pubkey: agent, gid })
ok('the oracle socket is group read-write and nothing else', (statSync(oracleSock).mode & 0o777) === 0o660 && statSync(oracleSock).gid === gid)
const session = await openBuzzSession({ relay: RELAY, signer: authOracleSigner({ socketPath: oracleSock, pubkey: agent }) })
ok('a keyless session logs in as the agent through the oracle', session.pubkey === agent)
session.close()
const ask = lines => new Promise(resolve => {
  const s = net.createConnection(oracleSock); let buf = ''
  s.on('connect', () => s.write(lines)); s.on('data', c => { buf += c }); s.on('end', () => resolve(buf)); s.on('error', () => resolve(buf))
})
const good = { kind: 22242, created_at: now(), content: '', tags: [['relay', RELAY], ['challenge', 'challenge-abcdef']] }
const refused = async (why, template) => ok(`the oracle refuses ${why}`, /"error"/.test(await ask(JSON.stringify(template) + '\n')))
await refused('a note', { ...good, kind: 1 })
await refused('another relay', { ...good, tags: [['relay', 'wss://elsewhere.example'], good.tags[1]] })
await refused('a smuggled NIP-OA auth tag', { ...good, tags: [...good.tags, ['auth', 'a'.repeat(64), 'kind=9', 'b'.repeat(128)]] })
await refused('a stale login', { ...good, created_at: now() - 3600 })
await refused('content', { ...good, content: 'sign me' })
ok('the oracle refuses a malformed line', /malformed/.test(await ask('not json\n')))
const before = signed
const two = await ask(JSON.stringify(good) + '\n' + JSON.stringify({ ...good, tags: [good.tags[0], ['challenge', 'second-challenge']] }) + '\n')
ok('two templates on one connection get one signature', signed === before + 1 && two.trim().split('\n').length === 1 && /challenge-abcdef/.test(two))
oracle.close()
const tightSock = join(root, 'tight.sock')
const tight = await serveAuthOracle({ socketPath: tightSock, relay: RELAY, signer: counting, pubkey: agent, maxPerMinute: 2 })
const tightAsk = () => new Promise(resolve => { const s = net.createConnection(tightSock); let b = ''; s.on('connect', () => s.write(JSON.stringify(good) + '\n')); s.on('data', c => { b += c }); s.on('end', () => resolve(b)) })
await tightAsk(); await tightAsk()
ok('the oracle is rate bounded', /rate limited/.test(await tightAsk()))
tight.close()
const wrongKey = await serveAuthOracle({ socketPath: join(root, 'wrong.sock'), relay: RELAY, signer: local(humanSk), pubkey: agent })
ok('an oracle whose signer answers for another key returns nothing usable',
  /different event/.test(await new Promise(resolve => { const s = net.createConnection(join(root, 'wrong.sock')); let b = ''; s.on('connect', () => s.write(JSON.stringify(good) + '\n')); s.on('data', c => { b += c }); s.on('end', () => resolve(b)) })))
wrongKey.close()

// --- the keyless watcher, end to end ---
const liveOracle = await serveAuthOracle({ socketPath: oracleSock, relay: RELAY, signer: local(agentSk), pubkey: agent, gid })
const spool = join(root, 'spool')
let watcherLog = ''
const startWatcher = (socketPath = oracleSock) => {
  const child = spawn(process.execPath, ['mcp/tools/buzz-wake-watcher.mjs', '--recipient', agent, '--relay', RELAY, '--channels', CH,
    '--auth-socket', socketPath, '--marker-dir', spool, '--marker-gid', String(gid)],
  { env: { PATH: process.env.PATH, WAKE_PING_MS: '200', WAKE_RETRY_MAX_MS: '400' }, stdio: ['ignore', 'pipe', 'pipe'] })
  child.stdout.on('data', c => { watcherLog += c }); child.stderr.on('data', c => { watcherLog += c })
  return child
}
const pendingFor = id => join(spool, `${id}.buzz.pending`)
let watcher = startWatcher()
ok('the watcher logs in and listens', await until(() => /listening on 1 channel/.test(watcherLog)))
const mention = await post(humanSk, { kind: 9, content: 'agent, what is the status?', tags: [['h', CH], ['p', agent]] })
ok('a mention of the agent leaves a marker', await until(() => existsSync(pendingFor(mention.id))))
const marker = JSON.parse(readFileSync(pendingFor(mention.id), 'utf8'))
ok('the marker is opaque: only the event id and when it was heard', Object.keys(marker).sort().join() === 'envelope,observed_at' && marker.envelope === mention.id)
ok('the marker is group-writable for the broker', (statSync(pendingFor(mention.id)).mode & 0o777) === 0o660)
const chatter = await post(humanSk, { kind: 9, content: 'no mention here', tags: [['h', CH]] })
const self = await post(agentSk, { kind: 9, content: 'talking to myself', tags: [['h', CH], ['p', agent]] })
const elsewhere = await post(humanSk, { kind: 9, content: 'other room', tags: [['h', OTHER], ['p', agent]] })
await sleep(400)
ok('a message that does not tag the agent leaves no marker', !existsSync(pendingFor(chatter.id)))
ok('the agent\'s own message leaves no marker', !existsSync(pendingFor(self.id)))
ok('a mention in an unconfigured channel leaves no marker', !existsSync(pendingFor(elsewhere.id)))
ok('the watermark is persisted', Number(readFileSync(join(spool, 'buzz-wake-since'), 'utf8')) >= mention.created_at)
for (const ws of sockets) ws.terminate()
ok('a dropped connection is re-established', await until(() => (watcherLog.match(/listening on 1 channel/g) || []).length >= 2))
const second = await post(humanSk, { kind: 9, content: 'still there?', tags: [['h', CH], ['p', agent]] })
ok('a mention after a reconnect is heard', await until(() => existsSync(pendingFor(second.id))))
watcher.kill(); await sleep(100)
// The broker consumes a marker by renaming it; a restart replays the overlap window, and the seen
// log must stop that replay from waking the agent twice.
renameSync(pendingFor(mention.id), join(spool, `${mention.id}.buzz.inflight.done`))
watcher = startWatcher()
ok('the restarted watcher listens again', await until(() => (watcherLog.match(/listening on 1 channel/g) || []).length >= 3))
await sleep(300)
ok('a replayed mention is not marked twice', !existsSync(pendingFor(mention.id)))
watcher.kill()
watcherLog = ''
watcher = startWatcher(join(root, 'no-oracle.sock'))
ok('without an oracle the watcher reports a failed login and keeps retrying', await until(() => (watcherLog.match(/login failed/g) || []).length >= 2) && watcher.exitCode === null)
watcher.kill()
liveOracle.close()

// --- the keyed native deliver: everything decided before a grant is consulted ---
const credential = join(root, 'agent.key'); writeFileSync(credential, Buffer.from(agentSk).toString('hex'), { mode: 0o600 })
// Asynchronous on purpose: the stub relay runs on this process's event loop, and spawnSync would
// stall it for exactly as long as the child waits on it.
const run = (args, env) => new Promise(resolve => {
  const child = spawn(process.execPath, args, { env: { PATH: process.env.PATH, ...env }, stdio: ['ignore', 'pipe', 'pipe'] })
  let stdout = '', stderr = ''
  child.stdout.on('data', c => { stdout += c }); child.stderr.on('data', c => { stderr += c })
  child.on('exit', status => resolve({ status, stdout, stderr }))
})
const deliver = (id, event) => run(['mcp/tools/instance-broker-native.mjs', 'deliver', '--instance', id, '--event', event],
  { NVOY_INSTANCE_ROOT: rootFor(id), NVOY_BROKER_CREDENTIAL: credential })
const plant = id => writeFileSync(pendingFor(id), JSON.stringify({ observed_at: Date.now(), envelope: id }) + '\n', { mode: 0o660 })
plant(chatter.id)
let r = await deliver('ears', chatter.id)
ok('a stored message that does not mention the agent is terminal, not a task', r.status === 0 && /not a signed mention/.test(r.stderr) && existsSync(join(spool, `${chatter.id}.buzz.inflight.done`)))
const ghost = 'f'.repeat(64); plant(ghost)
r = await deliver('ears', ghost)
ok('an event the relay does not hold in a configured channel is terminal', r.status === 0 && /not stored/.test(r.stderr) && existsSync(join(spool, `${ghost}.buzz.inflight.done`)))
plant(elsewhere.id)
r = await deliver('ears', elsewhere.id)
ok('a mention from an unconfigured channel is never fetched into admission', r.status === 0 && existsSync(join(spool, `${elsewhere.id}.buzz.inflight.done`)))
plant(second.id)
r = await deliver('ears', second.id)
ok('with no relay answering for grants, a real mention is requeued, not consumed', r.status === 75 && /policy unavailable|policy check failed/.test(r.stderr) && existsSync(pendingFor(second.id)))
ok('no receipt exists before a grant was seen', !existsSync(join(root, 'state', 'receipts', `${second.id}.json`)))
ok('the broker lock is released on exit', !existsSync(join(root, 'state', 'broker.lock')))
manifestWith('down', { buzz: { relay: 'ws://127.0.0.1:1', channels: [CH] } })
plant(second.id.replace(/.$/, '0'))
r = await deliver('down', second.id.replace(/.$/, '0'))
ok('a Buzz relay outage requeues the marker', r.status === 75 && existsSync(pendingFor(second.id.replace(/.$/, '0'))))
const liar = 'e'.repeat(64)
writeFileSync(pendingFor(liar), JSON.stringify({ observed_at: 1, envelope: 'd'.repeat(64) }))
r = await deliver('ears', liar)
ok('a marker that names a different event is refused', r.status === 1 && /does not bind/.test(r.stderr))
r = await deliver('plain', mention.id)
ok('a manifest without a buzz block cannot deliver natively', r.status === 1 && /no buzz block/.test(r.stderr))

// --- v3 authority: the author's own signature, one message, a configured channel ---
const grant = 'a'.repeat(64), grantor = baseManifest.grantors[0]
const task = (authority, messages) => ({ type: 'admitted-task', instance: 'ears', envelope: mention.id, authority,
  messages: messages ?? [{ from: human, at: mention.created_at, content: mention.content, event_id: mention.id, kind: 9 }] })
const v3 = { version: 3, type: 'scoped-instruction', sender: human, grant_id: grant, grantor, cap: 'task', scope_subject: agent,
  policy_checked_at: Date.now(), source_event: mention.id, reply_channel: CH }
const policy = { instance: 'ears', scopeSubject: agent, grantors: [grantor], buzz: parsed.buzz }
ok('a v3 admission is a trusted instruction', validateAdmittedTask(task(v3), policy).trustedInstruction === true)
ok('v3 is refused on an instance with no buzz block', !!throws(() => validateAdmittedTask(task(v3), { ...policy, buzz: null })))
ok('v3 is refused for an unconfigured channel', !!throws(() => validateAdmittedTask(task({ ...v3, reply_channel: OTHER }), policy)))
ok('v3 is refused when the envelope is not the source event', !!throws(() => validateAdmittedTask({ ...task(v3), envelope: 'b'.repeat(64) }, policy)))
ok('v3 is refused with a second message', !!throws(() => validateAdmittedTask(task(v3, [task(v3).messages[0], task(v3).messages[0]]), policy)))
ok('v3 is refused for a message someone else wrote', !!throws(() => validateAdmittedTask(task(v3, [{ ...task(v3).messages[0], from: agent }]), policy)))
ok('v3 is refused with carrier fields smuggled in', !!throws(() => validateAdmittedTask(task({ ...v3, carrier: human }), policy)))

// --- v3 outbound record: the frozen kind:9 is the fingerprint ---
const unsigned = { pubkey: agent, ...channelReply({ channel: CH, parent: mention, content: 'all green' }) }
const base = { version: 3, request_digest: 'b'.repeat(64), request_id: 'c'.repeat(32), fingerprint: getEventHash(unsigned), unsigned_event: unsigned }
const signedReply = finalizeEvent({ ...unsigned }, agentSk)
const check = rec => throws(() => validateOutboundRecord(rec))
ok('an unenacted native proposal is valid', check({ ...base, event: null, published: false }) === null)
ok('a native reply enacted directly is valid', check({ ...base, event: signedReply, enactment: 'buzz-native-direct', published: false }) === null)
ok('a native reply cannot borrow the carry enactment', /unknown enactment/.test(check({ ...base, event: signedReply, enactment: 'channel-carry-direct', published: false }) || ''))
ok('a native reply naming both paths is refused', /two enactment paths/.test(check({ ...base, event: signedReply, enactment: 'buzz-native-direct', approval_id: 'd'.repeat(64), published: false }) || ''))
ok('a signed event that is not the frozen one is refused', /frozen channel reply/.test(check({ ...base, event: finalizeEvent({ ...unsigned, content: 'something else' }, agentSk), enactment: 'buzz-native-direct', published: false }) || ''))
ok('a frozen reply with no h tag is refused', /kind:9 channel reply/.test(check({ ...base, unsigned_event: { ...unsigned, tags: unsigned.tags.filter(t => t[0] !== 'h') }, event: null, published: false }) || ''))
ok('the reply threads to the mention and tags its author', unsigned.tags.some(t => t[0] === 'e' && t[1] === mention.id && t[3] === 'reply') && unsigned.tags.some(t => t[0] === 'p' && t[1] === human))

// --- the reply actuator refuses a native receipt outside its channels before opening a signer ---
mkdirSync(join(root, 'state', 'receipts'), { recursive: true, mode: 0o700 })
const requestId = '1'.repeat(32)
writeFileSync(join(root, 'run', 'reply-requests.jsonl'), JSON.stringify({ version: 1, type: 'reply-request', id: requestId, instance: 'ears', receipt: mention.id, content: 'hi' }) + '\n')
writeFileSync(join(root, 'state', 'receipts', `${mention.id}.json`), JSON.stringify({ version: 3, mode: 'buzz-native', instance: 'ears', broker: agent,
  envelope: mention.id, sender: human, grant_id: grant, grantor, cap: 'task', source_event: mention.id, reply_channel: OTHER, reply_root: mention.id,
  admitted_at: Date.now(), expires_at: Date.now() + 300000 }), { mode: 0o600 })
r = await run(['mcp/tools/instance-broker-reply.mjs', '--instance', 'ears', '--request', requestId, '--prepare'],
  { NVOY_INSTANCE_ROOT: rootFor('ears'), NVOY_BROKER_CREDENTIAL: credential })
ok('a native receipt for an unconfigured channel is refused', r.status === 1 && /not bound to a configured channel/.test(r.stderr))

server.close(); http.close()
console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
