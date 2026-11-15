// q-150 + q-144: one reused authenticated Buzz session per broker across child processes,
// per-attempt phase & WebSocket close-code logging with a <5s AUTH signing bound, and immediate
// fresh re-sign on transient relay close or stale frozen timestamp without double-publishing.
import { WebSocketServer } from 'ws'
import { spawn, spawnSync } from 'node:child_process'
import { createServer } from 'node:http'
import { createServer as createTlsServer } from 'node:https'
import net from 'node:net'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { nsecEncode } from 'nostr-tools/nip19'
import { channelPost, channelReply, formatBuzzPhase, openBuzzSession, serveBuzzSession } from '../mcp/tools/buzz_native.mjs'
import { STALE_POST_TERMINAL_LINE } from '../mcp/tools/agent_post.mjs'
import { scopeHash } from '../mcp/tools/grant_fold.mjs'
import { MEMBERS_KIND } from '../mcp/tools/room_roster.mjs'
import { replyRequestDigest, validateOutboundRecord } from '../mcp/tools/outbound_record.mjs'
import { terminalReplyReason } from '../mcp/tools/reply_retry.mjs'

let fails = 0, passes = 0
const ok = (name, value, detail = '') => {
  console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}${!value && detail ? ` (${detail})` : ''}`)
  value ? passes++ : fails++
}
const sleep = ms => new Promise(r => setTimeout(r, ms))
const now = () => Math.floor(Date.now() / 1000)
const hex = n => randomBytes(n).toString('hex')
const rejects = async p => { try { await p; return null } catch (e) { return e } }

const CH = '3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607'
const agentSk = generateSecretKey(), agent = getPublicKey(agentSk)
const grantorSk = generateSecretKey(), grantor = getPublicKey(grantorSk)
const humanSk = generateSecretKey(), human = getPublicKey(humanSk)
const roomPeerSk = generateSecretKey(), roomPeer = getPublicKey(roomPeerSk)
const extPeerSk = generateSecretKey(), extPeer = getPublicKey(extPeerSk)
const relaySignerSk = generateSecretKey(), relaySigner = getPublicKey(relaySignerSk)

const localSigner = (sk, counts = null) => ({
  getPublicKey: async () => { if (counts) counts.pubkey++; return getPublicKey(sk) },
  signEvent: async t => {
    if (counts) { counts.sign++; if (t.kind === 22242) counts.auth++ }
    return finalizeEvent(t, sk)
  },
})

// --- Stub Buzz relay with configurable close codes, timestamp window, and publish-drop hooks ---
const relayState = {
  connections: 0,
  authOk: 0,
  publishAttempts: 0,
  stored: [],
  lists: [],
  profiles: [],
  sockets: new Set(),
  dropNextPublish: false,
  storeThenDropNextPublish: false,
  staleRefuseNextPublish: false,
  onPublishAttempt: null,
  refuseParentIds: new Set(),
  enforceTimestampWindow: true,
}
const matches = (f, ev) => {
  const vals = n => (ev.tags || []).filter(t => t[0] === n).map(t => t[1])
  if (f.kinds && !f.kinds.includes(ev.kind)) return false
  if (f.ids && !f.ids.includes(ev.id)) return false
  if (f.authors && !f.authors.includes(ev.pubkey)) return false
  if (f['#d'] && !f['#d'].some(d => vals('d').includes(d))) return false
  if (f['#h'] && !f['#h'].some(h => vals('h').includes(h))) return false
  if (f['#p'] && !f['#p'].some(p => vals('p').includes(p))) return false
  if (f['#e'] && !f['#e'].some(e => vals('e').includes(e))) return false
  if (f['#t'] && !f['#t'].some(t => vals('t').includes(t))) return false
  if (f.until !== undefined && ev.created_at > f.until) return false
  if (f.since !== undefined && ev.created_at < f.since) return false
  return true
}

const http = createServer((req, res) => { res.writeHead(404); res.end() })
await new Promise(r => http.listen(0, '127.0.0.1', r))
const RELAY = `ws://127.0.0.1:${http.address().port}`
const wss = new WebSocketServer({ server: http })
wss.on('connection', ws => {
  relayState.connections++
  relayState.sockets.add(ws)
  ws.on('close', () => relayState.sockets.delete(ws))
  const challenge = hex(32)
  let authed = null
  ws.send(JSON.stringify(['AUTH', challenge]))
  ws.on('message', raw => {
    const m = JSON.parse(raw.toString())
    if (m[0] === 'AUTH') {
      const ev = m[1], tag = n => ev.tags.find(t => t[0] === n)?.[1]
      if (!(verifyEvent(ev) && ev.kind === 22242 && tag('challenge') === challenge && tag('relay') === RELAY && ev.pubkey === agent))
        return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted: auth failed']))
      authed = ev.pubkey
      relayState.authOk++
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
    if (m[0] === 'REQ') {
      if (!authed) return ws.send(JSON.stringify(['CLOSED', m[1], 'auth-required: authenticate first']))
      const all = [...relayState.lists, ...relayState.profiles, ...relayState.stored]
      for (const f of m.slice(2)) {
        let hits = all.filter(ev => matches(f, ev))
        if (Number.isInteger(f.limit)) hits = hits.slice(-f.limit)
        for (const ev of hits) ws.send(JSON.stringify(['EVENT', m[1], ev]))
      }
      return ws.send(JSON.stringify(['EOSE', m[1]]))
    }
    if (m[0] === 'EVENT') {
      const ev = m[1]
      if (!authed || ev.pubkey !== authed || !verifyEvent(ev))
        return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted']))
      relayState.publishAttempts++
      if (typeof relayState.onPublishAttempt === 'function') {
        const hook = relayState.onPublishAttempt
        relayState.onPublishAttempt = null
        hook(ev, ws)
      }
      if (relayState.dropNextPublish) {
        relayState.dropNextPublish = false
        return ws.terminate()
      }
      if (relayState.storeThenDropNextPublish) {
        relayState.storeThenDropNextPublish = false
        if (!relayState.stored.some(s => s.id === ev.id)) relayState.stored.push(ev)
        return ws.terminate()
      }
      if (relayState.staleRefuseNextPublish) {
        relayState.staleRefuseNextPublish = false
        return ws.send(JSON.stringify(['OK', ev.id, false, 'invalid: event timestamp too far from server time']))
      }
      const replyParent = (ev.tags || []).find(t => t[0] === 'e' && t[3] === 'reply')?.[1]
      if (replyParent && relayState.refuseParentIds.has(replyParent))
        return ws.send(JSON.stringify(['OK', ev.id, false, 'invalid: reply parent not found']))
      if (relayState.enforceTimestampWindow && Math.abs(ev.created_at - now()) > 900)
        return ws.send(JSON.stringify(['OK', ev.id, false, 'invalid: event timestamp too far from server time']))
      if (!relayState.stored.some(s => s.id === ev.id)) relayState.stored.push(ev)
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
  })
})

// --- Part 1: phase timings, <5s AUTH signing bound, and close code/reason logging ---
const phases = []
const direct = await openBuzzSession({ relay: RELAY, signer: localSigner(agentSk), socketPath: '', onPhase: p => phases.push(p) })
const fetchedEmpty = await direct.fetch({ kinds: [9], '#h': [CH], limit: 1 })
ok('direct session records auth_ok and fetch phase timings',
  fetchedEmpty.length === 0 && phases.some(p => p.event === 'auth_ok' && Number.isFinite(p.pubkey_ms) && Number.isFinite(p.challenge_ms) && Number.isFinite(p.auth_sign_ms) && Number.isFinite(p.auth_ok_ms)) &&
  phases.some(p => p.event === 'fetch' && Number.isFinite(p.req_ms)))

const closePromise = rejects(new Promise((_, rej) => direct.closed.then(r => rej(new Error(r)))))
for (const ws of relayState.sockets) ws.close(4008, 'auth deadline exceeded')
const closeErr = await closePromise
ok('WebSocket close code, sanitized reason, and phase are surfaced instead of discarded',
  /relay closed the connection/.test(closeErr?.message || '') && /code=4008/.test(closeErr?.message || '') &&
  /reason="auth deadline exceeded"/.test(closeErr?.message || '') && /phase=ready/.test(closeErr?.message || ''))

const fakeSecret = nsecEncode(generateSecretKey())
const leakLine = formatBuzzPhase(1, { event: 'auth_error', phase: 'auth_sign', close_code: 4009, close_reason: '', error: `bad ${fakeSecret}` })
ok('phase formatter redacts accidental credential material in error strings',
  leakLine.includes('close_code=4009') && !leakLine.includes(fakeSecret.slice(5, 25)))

const slowAuthStart = Date.now()
const slowSigner = {
  getPublicKey: async () => agent,
  signEvent: async t => { await sleep(400); return finalizeEvent(t, agentSk) },
}
const authTimeoutErr = await rejects(openBuzzSession({ relay: RELAY, signer: slowSigner, timeoutMs: 5000, authTimeoutMs: 120, socketPath: '' }))
const authTimeoutElapsed = Date.now() - slowAuthStart
ok('AUTH signing is bounded by authTimeoutMs inside the 5s Buzz window',
  /AUTH sign timed out \(120ms\)/.test(authTimeoutErr?.message || '') && authTimeoutElapsed < 1000)
await sleep(350)

// --- Fixture: TLS grant relay + broker runtime + shared Buzz session server ---
const root = mkdtempSync(join(tmpdir(), 'nvoy-buzz-reuse-'))
const certDir = join(root, 'tls'); mkdirSync(certDir)
const tls = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
  '-keyout', join(certDir, 'key.pem'), '-out', join(certDir, 'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'], { encoding: 'utf8' })
if (tls.status !== 0) throw new Error('openssl could not make test certificate')

const grantSalt = hex(16)
const taskGrant = finalizeEvent({
  kind: 440, created_at: now() - 30, content: '',
  tags: [['p', human], ['da-scope', scopeHash(agent, grantSalt), grantSalt], ['da-cap', 'task']],
}, grantorSk)
const extMentionGrant = finalizeEvent({
  kind: 440, created_at: now() - 30, content: '',
  tags: [['p', extPeer], ['da-scope', scopeHash(agent, grantSalt), grantSalt], ['da-cap', 'mention'], ['name', 'extpeer']],
}, grantorSk)
const grantEvents = [taskGrant]
const grantServer = createTlsServer({ key: readFileSync(join(certDir, 'key.pem')), cert: readFileSync(join(certDir, 'cert.pem')) }, (q, r) => { r.writeHead(404); r.end() })
await new Promise(done => grantServer.listen(0, '127.0.0.1', done))
new WebSocketServer({ server: grantServer }).on('connection', ws => ws.on('message', raw => {
  const m = JSON.parse(raw.toString())
  if (m[0] === 'REQ') {
    for (const ev of grantEvents) {
      if (m.slice(2).some(f => (!f.kinds || f.kinds.includes(ev.kind)) && (!f.authors || f.authors.includes(ev.pubkey)))) {
        ws.send(JSON.stringify(['EVENT', m[1], ev]))
      }
    }
    ws.send(JSON.stringify(['EOSE', m[1]]))
  }
}))
const GRANTS = `wss://127.0.0.1:${grantServer.address().port}`

const preload = join(root, 'trust.mjs')
writeFileSync(preload, `import { createRequire, syncBuiltinESMExports } from 'node:module'
const cp = createRequire(import.meta.url)('node:child_process'), spawnSync = cp.spawnSync
cp.spawnSync = (file, args, options = {}) => spawnSync(file, args, { ...options, env: { ...options.env, NODE_EXTRA_CA_CERTS: process.env.NODE_EXTRA_CA_CERTS } })
syncBuiltinESMExports()
`)

const instances = join(root, 'instances'), state = join(root, 'state'), run = join(root, 'run'), spool = join(root, 'spool')
for (const d of [instances, state, run, spool, join(state, 'receipts'), join(state, 'outbound'), join(state, 'posts')]) mkdirSync(d, { recursive: true, mode: 0o700 })
for (const f of ['post-requests.jsonl', 'reply-requests.jsonl', 'mention-rooms.json', 'mention-grants.json']) writeFileSync(join(run, f), '', { mode: 0o640 })
const gid = process.getgid(), uid = process.getuid()
writeFileSync(join(instances, 'seat.json'), JSON.stringify({
  version: 1, id: 'seat', pubkey: agent, broker_mode: 'local', key_ref: '/etc/nvoy/credentials/seat.nsec',
  worker_enabled: false, delivery_mode: 'notify_only',
  state_dir: state, runtime_dir: run, spool_dir: spool,
  broker_adapter_gid: gid, worker_handoff_gid: gid + 1, watcher_uid: uid + 11, broker_uid: uid + 12, adapter_uid: uid + 13, worker_uid: uid + 14,
  grantors: [grantor], relays: [GRANTS],
  buzz: { relay: RELAY, channels: [CH], relay_signer: relaySigner },
  may_post: { channels: [CH], per_hour: 30, mention: [{ name: 'human', pubkey: human }], mention_rooms: true },
}))
const credential = join(root, 'agent.key')
writeFileSync(credential, Buffer.from(agentSk).toString('hex'), { mode: 0o600 })

// Stub adapter ack socket for instance-broker-native.mjs
const admittedTasks = []
const adapterServer = net.createServer(sock => {
  let buf = ''
  sock.setEncoding('utf8')
  sock.on('data', c => {
    buf += c
    if (!buf.includes('\n')) return
    admittedTasks.push(JSON.parse(buf.split('\n')[0]))
    sock.end(JSON.stringify({ type: 'ack', instance: 'seat' }) + '\n')
  })
})
await new Promise(r => adapterServer.listen(join(run, 'adapter.sock'), r))

// Seed room roster + profile + an inbound human mention on the stub Buzz relay
relayState.lists = [finalizeEvent({
  kind: MEMBERS_KIND, created_at: now(), content: '',
  tags: [['d', CH], ['h', CH], ['p', agent], ['p', human], ['p', roomPeer]],
}, relaySignerSk)]
relayState.profiles = [finalizeEvent({ kind: 0, created_at: now(), content: JSON.stringify({ name: 'roompeer' }), tags: [] }, roomPeerSk)]
const inboundMention = finalizeEvent({ kind: 9, created_at: now(), content: 'please check session reuse', tags: [['h', CH], ['p', agent]] }, humanSk)
relayState.stored.push(inboundMention)

// --- Part 2: shared broker Buzz session reuses 1 WebSocket + 1 AUTH across all broker children ---
relayState.connections = 0
relayState.authOk = 0
const counts = { pubkey: 0, sign: 0, auth: 0 }
const sessionLogs = []
const sessionSock = join(state, 'buzz-session.sock')
const sharedServer = await serveBuzzSession({
  socketPath: sessionSock, relay: RELAY, signer: localSigner(agentSk, counts), pubkey: agent,
  log: line => sessionLogs.push(line),
})
ok('shared Buzz session socket in stateDir is mode 0600 (broker-only)', (statSync(sessionSock).mode & 0o777) === 0o600)

// Five concurrent cold clients share a single WebSocket + AUTH handshake
const concurrent = await Promise.all(Array.from({ length: 5 }, () => openBuzzSession({ relay: RELAY, socketPath: sessionSock })))
for (const c of concurrent) c.close()
ok('concurrent cold callers share a single Buzz WebSocket and AUTH signature',
  relayState.connections === 1 && relayState.authOk === 1 && counts.auth === 1,
  `connections=${relayState.connections} auth=${counts.auth}`)

const runBroker = args => new Promise(done => {
  const child = spawn(process.execPath, ['--import', preload, ...args], {
    env: {
      PATH: process.env.PATH,
      NODE_EXTRA_CA_CERTS: join(certDir, 'cert.pem'),
      NVOY_INSTANCE_ROOT: instances,
      NVOY_BROKER_CREDENTIAL: credential,
      NVOY_BUZZ_SESSION_SOCK: sessionSock,
      NVOY_BUZZ_SESSION_REQUIRED: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let stdout = '', stderr = ''
  child.stdout.on('data', d => { stdout += d }); child.stderr.on('data', d => { stderr += d })
  child.on('exit', status => done({ status, stdout, stderr }))
})

// 1) instance-broker-rooms.mjs
const roomsRes = await runBroker(['mcp/tools/instance-broker-rooms.mjs', '--instance', 'seat'])
ok('instance-broker-rooms refreshes roster over the shared session', roomsRes.status === 0, roomsRes.stderr)

// 2) instance-broker-post.mjs (with room-derived mention -> confirmRoom + publishSigned)
const postId1 = hex(16)
writeFileSync(join(run, 'post-requests.jsonl'), JSON.stringify({
  version: 1, type: 'post-request', id: postId1, instance: 'seat', channel: CH,
  mention: [roomPeer], content: 'shared session post', requested_at: Date.now(),
}) + '\n')
const postRes1 = await runBroker(['mcp/tools/instance-broker-post.mjs', '--instance', 'seat', '--request', postId1])
ok('instance-broker-post confirms room member and publishes over the shared session',
  postRes1.status === 0 && relayState.stored.some(e => e.content === 'shared session post'), postRes1.stderr)

// 3) instance-broker-native.mjs (fetches DM notices, mention, and context)
writeFileSync(join(spool, `${inboundMention.id}.buzz.pending`), JSON.stringify({ envelope: inboundMention.id, observed_at: Date.now() }) + '\n')
const nativeRes = await runBroker(['mcp/tools/instance-broker-native.mjs', 'deliver', '--instance', 'seat', '--event', inboundMention.id])
ok('instance-broker-native delivers mention over the shared session',
  nativeRes.status === 0 && admittedTasks.length === 1 && existsSync(join(state, 'receipts', `${inboundMention.id}.json`)), nativeRes.stderr)

// 4) instance-broker-reply.mjs --prepare + --direct (with room-derived mention -> 3 session opens!)
const replyId1 = hex(16)
writeFileSync(join(run, 'reply-requests.jsonl'), JSON.stringify({
  version: 1, type: 'reply-request', id: replyId1, instance: 'seat',
  receipt: inboundMention.id, content: 'shared session reply', mention: [roomPeer],
}) + '\n')
const prepRes1 = await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', replyId1, '--prepare'])
const dirRes1 = await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', replyId1, '--direct'])
ok('instance-broker-reply --prepare and --direct enact over the shared session',
  prepRes1.status === 0 && dirRes1.status === 0 && relayState.stored.some(e => e.content === 'shared session reply'),
  `${prepRes1.stderr} | ${dirRes1.stderr}`)

ok('all five broker child runs (rooms, post, native, reply prepare + direct) used ONE WebSocket and ONE AUTH signature',
  relayState.connections === 1 && relayState.authOk === 1 && counts.auth === 1,
  `connections=${relayState.connections} authOk=${relayState.authOk} authSigns=${counts.auth}`)

// Reconnect on relay socket drop during idle, with close code & reason logged
for (const ws of relayState.sockets) ws.close(4001, 'idle drop')
await sleep(80)
const roomsAfterDrop = await runBroker(['mcp/tools/instance-broker-rooms.mjs', '--instance', 'seat'])
ok('shared session logs close code/reason on drop and reconnects cleanly on next child call',
  roomsAfterDrop.status === 0 && relayState.connections === 2 && counts.auth === 2 &&
  sessionLogs.some(l => l.includes('close_code=4001') && l.includes('close_reason="idle drop"')),
  sessionLogs.join(' | '))

// Daemon source wiring check
const daemonSrc = readFileSync('mcp/tools/instance-broker-daemon.mjs', 'utf8')
ok('instance-broker-daemon exports NVOY_BUZZ_SESSION_SOCK and supervises instance-broker-buzz.mjs',
  /NVOY_BUZZ_SESSION_SOCK/.test(daemonSrc) && /if \(manifest\.buzz\) supervise\('instance-broker-buzz\.mjs'/.test(daemonSrc))

// --- Part 3 + q-144: immediate re-sign on close or stale timestamp, with zero double-publish ---
const makeReceipt = msgContent => {
  const src = finalizeEvent({ kind: 9, created_at: now(), content: msgContent, tags: [['h', CH], ['p', agent]] }, humanSk)
  relayState.stored.push(src)
  writeFileSync(join(state, 'receipts', `${src.id}.json`), JSON.stringify({
    version: 3, mode: 'buzz-native', instance: 'seat', broker: agent, envelope: src.id,
    sender: human, grant_id: taskGrant.id, grantor, cap: 'task',
    source_event: src.id, reply_channel: CH, reply_root: src.id, hop: 1,
    admitted_at: Date.now(), expires_at: Date.now() + 300000,
  }), { mode: 0o600 })
  return src
}
const appendReplyRequest = (id, receipt, content, mention = undefined) => {
  const row = { version: 1, type: 'reply-request', id, instance: 'seat', receipt, content, ...(mention ? { mention } : {}) }
  writeFileSync(join(run, 'reply-requests.jsonl'), readFileSync(join(run, 'reply-requests.jsonl'), 'utf8') + JSON.stringify(row) + '\n')
  return row
}
const appendPostRequest = (id, content, mention = [human]) => {
  const row = { version: 1, type: 'post-request', id, instance: 'seat', channel: CH, mention, content, requested_at: Date.now() }
  writeFileSync(join(run, 'post-requests.jsonl'), readFileSync(join(run, 'post-requests.jsonl'), 'utf8') + JSON.stringify(row) + '\n')
  return row
}

// 3a) Relay closes on first publish without storing -> immediate re-sign & retry succeeds in one run
{
  const src = makeReceipt('trigger close on reply'), reqId = hex(16)
  appendReplyRequest(reqId, src.id, 'reply survives transient close')
  await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', reqId, '--prepare'])
  relayState.dropNextPublish = true
  const res = await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', reqId, '--direct'])
  const landed = relayState.stored.filter(e => e.content === 'reply survives transient close')
  const rec = JSON.parse(readFileSync(join(state, 'outbound', `${reqId}.json`), 'utf8'))
  ok('reply closed mid-publish reconnects, re-signs, and lands in the same run',
    res.status === 0 && landed.length === 1 && rec.published === true && rec.event.id === landed[0].id &&
    validateOutboundRecord(rec).published === true, res.stderr)
}

// 3b) Relay stores event THEN closes before OK -> reconnect detects stored id and does NOT double-publish
{
  const src = makeReceipt('trigger store-then-close on reply'), reqId = hex(16)
  appendReplyRequest(reqId, src.id, 'reply never duplicates after store-then-close')
  await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', reqId, '--prepare'])
  relayState.storeThenDropNextPublish = true
  const res = await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', reqId, '--direct'])
  const landed = relayState.stored.filter(e => e.content === 'reply never duplicates after store-then-close')
  ok('reply stored just before socket close is detected on reconnect and never double-published',
    res.status === 0 && landed.length === 1, `count=${landed.length} stderr=${res.stderr}`)
}

// 3c) Post closed mid-publish holds frozen event for retry over shared session, and refuses retry if mention grant is revoked
{
  const postCloseId = hex(16)
  appendPostRequest(postCloseId, 'post survives transient close')
  relayState.dropNextPublish = true
  const res1 = await runBroker(['mcp/tools/instance-broker-post.mjs', '--instance', 'seat', '--request', postCloseId])
  const frozenRec = JSON.parse(readFileSync(join(state, 'posts', `${postCloseId}.json`), 'utf8'))
  const res1Retry = await runBroker(['mcp/tools/instance-broker-post.mjs', '--instance', 'seat', '--request', postCloseId])
  const landed1 = relayState.stored.filter(e => e.content === 'post survives transient close')
  ok('post closed mid-publish holds its frozen event id and republishes identically on retry over the shared session',
    res1.status === 1 && /remains retryable/.test(res1.stderr) &&
    res1Retry.status === 0 && landed1.length === 1 && landed1[0].id === frozenRec.event.id,
    `${res1.stderr} | ${res1Retry.stderr}`)

  grantEvents.push(extMentionGrant)
  const postRevokeId = hex(16)
  appendPostRequest(postRevokeId, 'post refused after mention grant revoked', [extPeer])
  relayState.dropNextPublish = true
  const resDrop = await runBroker(['mcp/tools/instance-broker-post.mjs', '--instance', 'seat', '--request', postRevokeId])
  const revokeExt = finalizeEvent({ kind: 441, created_at: now(), content: '', tags: [['e', extMentionGrant.id]] }, grantorSk)
  grantEvents.push(revokeExt)
  const resRevoked = await runBroker(['mcp/tools/instance-broker-post.mjs', '--instance', 'seat', '--request', postRevokeId])
  const landedRevoked = relayState.stored.filter(e => e.content === 'post refused after mention grant revoked')
  ok('post held across transient close refuses terminally on retry when its dynamic mention grant was revoked',
    resDrop.status === 1 && resRevoked.status === 1 && /post refused: .* is not on may_post\.mention/.test(resRevoked.stderr) &&
    landedRevoked.length === 0, `${resDrop.stderr} | ${resRevoked.stderr}`)
  grantEvents.length = 1 // restore [taskGrant]
}

// 3d) q-144: stale frozen direct reply (>15 min old) re-signs with fresh created_at instead of dying invalid-frozen-reply
{
  const src = makeReceipt('q-144 stale reply parent'), reqId = hex(16)
  const row = appendReplyRequest(reqId, src.id, 'q-144 stale reply cured')
  const staleAt = now() - 1200 // 20 minutes old -> outside Buzz's ±15m window
  const staleUnsigned = { pubkey: agent, ...channelReply({ channel: CH, parent: src, content: row.content, hop: 2, now: staleAt }) }
  const staleSigned = finalizeEvent({ ...staleUnsigned }, agentSk)
  writeFileSync(join(state, 'outbound', `${reqId}.json`), JSON.stringify({
    version: 3, request_digest: replyRequestDigest(row), request_id: reqId,
    fingerprint: getEventHash(staleUnsigned), unsigned_event: staleUnsigned,
    event: staleSigned, enactment: 'buzz-native-direct', published: false,
  }), { mode: 0o600 })
  const res = await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', reqId, '--direct'])
  const landed = relayState.stored.filter(e => e.content === 'q-144 stale reply cured')
  const updated = JSON.parse(readFileSync(join(state, 'outbound', `${reqId}.json`), 'utf8'))
  ok('q-144: a 20-minute-old unpublished direct Buzz reply re-signs with fresh timestamp and publishes cleanly',
    res.status === 0 && landed.length === 1 && landed[0].id !== staleSigned.id &&
    Math.abs(landed[0].created_at - now()) < 30 && updated.published === true && updated.event.id === landed[0].id,
    res.stderr)
}

// 3e) q-169 compatibility: stale frozen post (>=30 min old) stays strictly frozen and fails terminally without re-signing
{
  const postStaleId = hex(16)
  const row = appendPostRequest(postStaleId, 'q-169 stale post stays frozen')
  const staleAt = now() - 2100
  const staleUnsigned = { pubkey: agent, ...channelPost({ channel: CH, content: row.content, mentions: row.mention, now: staleAt }) }
  const staleSigned = finalizeEvent({ ...staleUnsigned }, agentSk)
  const beforeBytes = JSON.stringify({
    version: 1, request_id: postStaleId, request_digest: replyRequestDigest(row),
    fingerprint: getEventHash(staleUnsigned), unsigned_event: staleUnsigned, event: staleSigned, published: false,
  })
  writeFileSync(join(state, 'posts', `${postStaleId}.json`), beforeBytes, { mode: 0o600 })
  const res = await runBroker(['mcp/tools/instance-broker-post.mjs', '--instance', 'seat', '--request', postStaleId])
  const landed = relayState.stored.filter(e => e.content === 'q-169 stale post stays frozen')
  ok('a 35-minute-old frozen Buzz post is never re-signed and fails terminally with STALE_POST_TERMINAL_LINE',
    res.status === 1 && res.stderr.includes(STALE_POST_TERMINAL_LINE) && landed.length === 0 &&
    readFileSync(join(state, 'posts', `${postStaleId}.json`), 'utf8') === beforeBytes,
    res.stderr)
}

// 3f) Non-timestamp invalid: (deleted parent) remains terminal parent-gone without looping
{
  const src = makeReceipt('deleted parent mention'), reqId = hex(16)
  appendReplyRequest(reqId, src.id, 'reply to deleted parent')
  await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', reqId, '--prepare'])
  relayState.refuseParentIds.add(src.id)
  const res = await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', reqId, '--direct'])
  ok('a deleted parent (invalid: reply parent not found) still fails terminally as parent-gone',
    res.status === 1 && /Buzz rejected the frozen channel reply as invalid/.test(res.stderr) &&
    terminalReplyReason(res.stderr) === 'parent-gone', res.stderr)
}

// 3g) q-179: sender task grant revoked mid-invocation before replacement signature refuses without signing or publishing
{
  const src = makeReceipt('q-179 sender grant revoked mid-flight'), reqId = hex(16)
  appendReplyRequest(reqId, src.id, 'must not re-sign after task grant revocation')
  await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', reqId, '--prepare'])
  const attemptsBefore = relayState.publishAttempts
  let firstAttemptId = ''
  relayState.dropNextPublish = true
  relayState.onPublishAttempt = ev => {
    firstAttemptId = ev.id
    grantEvents.push(finalizeEvent({ kind: 441, created_at: now(), content: '', tags: [['e', taskGrant.id]] }, grantorSk))
  }
  const res = await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', reqId, '--direct'])
  grantEvents.length = 1 // restore [taskGrant]
  const landed = relayState.stored.filter(e => e.content === 'must not re-sign after task grant revocation')
  const afterRec = JSON.parse(readFileSync(join(state, 'outbound', `${reqId}.json`), 'utf8'))
  ok('q-179: revoking the sender task grant mid-invocation blocks replacement signing and fails terminally as grant-no-longer-live',
    res.status === 1 && /admission receipt no longer has a live matching grant chain/.test(res.stderr) &&
    terminalReplyReason(res.stderr) === 'grant-no-longer-live' &&
    relayState.publishAttempts - attemptsBefore === 1 && landed.length === 0 &&
    afterRec.published === false && afterRec.event?.id === firstAttemptId,
    `status=${res.status} attempts=${relayState.publishAttempts - attemptsBefore} landed=${landed.length} stderr=${res.stderr}`)
}

// 3h) q-179: dynamic mention grant revoked mid-invocation before stale-timestamp replacement signature refuses without signing
{
  grantEvents.push(extMentionGrant)
  const src = makeReceipt('q-179 dynamic mention grant revoked mid-flight'), reqId = hex(16)
  appendReplyRequest(reqId, src.id, 'must not re-sign after mention grant revocation', [extPeer])
  await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', reqId, '--prepare'])
  const attemptsBefore = relayState.publishAttempts
  let firstAttemptId = ''
  relayState.staleRefuseNextPublish = true
  relayState.onPublishAttempt = ev => {
    firstAttemptId = ev.id
    grantEvents.push(finalizeEvent({ kind: 441, created_at: now(), content: '', tags: [['e', extMentionGrant.id]] }, grantorSk))
  }
  const res = await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', reqId, '--direct'])
  grantEvents.length = 1 // restore [taskGrant]
  const landed = relayState.stored.filter(e => e.content === 'must not re-sign after mention grant revocation')
  const afterRec = JSON.parse(readFileSync(join(state, 'outbound', `${reqId}.json`), 'utf8'))
  ok('q-179: revoking a dynamic mention grant mid-invocation blocks replacement signing and refuses terminally',
    res.status === 1 && /reply refused: .* is not on may_post\.mention/.test(res.stderr) &&
    relayState.publishAttempts - attemptsBefore === 1 && landed.length === 0 &&
    afterRec.published === false && afterRec.event?.id === firstAttemptId,
    `status=${res.status} attempts=${relayState.publishAttempts - attemptsBefore} landed=${landed.length} stderr=${res.stderr}`)
}

// 3i) q-179: room-derived mention peer leaving room mid-invocation before stale-timestamp replacement signature refuses without signing
{
  const src = makeReceipt('q-179 room peer leaves mid-flight'), reqId = hex(16)
  appendReplyRequest(reqId, src.id, 'must not re-sign after room member leaves', [roomPeer])
  await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', reqId, '--prepare'])
  const savedLists = relayState.lists
  const attemptsBefore = relayState.publishAttempts
  let firstAttemptId = ''
  relayState.staleRefuseNextPublish = true
  relayState.onPublishAttempt = ev => {
    firstAttemptId = ev.id
    relayState.lists = [finalizeEvent({
      kind: MEMBERS_KIND, created_at: now() + 1, content: '',
      tags: [['d', CH], ['h', CH], ['p', agent], ['p', human]],
    }, relaySignerSk)]
  }
  const res = await runBroker(['mcp/tools/instance-broker-reply.mjs', '--instance', 'seat', '--request', reqId, '--direct'])
  relayState.lists = savedLists
  const landed = relayState.stored.filter(e => e.content === 'must not re-sign after room member leaves')
  const afterRec = JSON.parse(readFileSync(join(state, 'outbound', `${reqId}.json`), 'utf8'))
  ok('q-179: room-derived mention leaving the room mid-invocation blocks replacement signing and refuses terminally',
    res.status === 1 && /reply refused: .* is not on may_post\.mention or in room/.test(res.stderr) &&
    relayState.publishAttempts - attemptsBefore === 1 && landed.length === 0 &&
    afterRec.published === false && afterRec.event?.id === firstAttemptId,
    `status=${res.status} attempts=${relayState.publishAttempts - attemptsBefore} landed=${landed.length} stderr=${res.stderr}`)
}

sharedServer.close()
adapterServer.close()
grantServer.close()
for (const ws of relayState.sockets) ws.terminate()
wss.close()
http.close()

console.log(fails ? `\nbuzz-session-reuse: ${fails} FAILED` : `\nbuzz-session-reuse: all ${passes} passed`)
process.exit(fails ? 1 : 0)
