// Owner-only Buzz DMs. A Buzz DM is a private channel of type `dm` that no manifest can list, so the
// watcher follows the relay's membership notices to find it, and in a DM only the owner — a manifest
// grantor, on the owner's own live grant — may task the identity. Not another agent, not a grant
// holder, not a stranger. The stub relay signs 44100/44101 notices with its own key, p-gates them,
// honours #t, and shows a DM's messages only to its members, as Buzz does.
import { WebSocketServer } from 'ws'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { MEMBERSHIP_KINDS, channelReply, dmChannels, dmNoticeFilter, nativeGrant, openBuzzSession, serveAuthOracle } from '../mcp/tools/buzz_native.mjs'
import { validateAdmittedTask } from '../mcp/tools/admitted_task.mjs'

let fails = 0, passes = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passes++ : fails++ }
const sleep = ms => new Promise(r => setTimeout(r, ms))
const now = () => Math.floor(Date.now() / 1000)
const until = async (fn, ms = 5000) => { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(50) } return false }
const throws = fn => { try { fn(); return null } catch (e) { return e.message } }

const CH = '3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607'
const DM_OLD = '11111111-1111-4111-8111-111111111111', DM_NEW = '22222222-2222-4222-8222-222222222222'
const DM_AGENTS = '33333333-3333-4333-8333-333333333333', DM_ELSEWHERE = '44444444-4444-4444-8444-444444444444'
const DM_GRANTEE = '55555555-5555-4555-8555-555555555555'
const key = () => { const sk = generateSecretKey(); return { sk, pk: getPublicKey(sk) } }
const agent = key(), owner = key(), myDude = key(), grantee = key(), stranger = key(), relayKey = key()
const local = sk => ({ getPublicKey: async () => getPublicKey(sk), signEvent: async t => finalizeEvent(t, sk) })

// --- pure: which channels are this identity's DMs ---
const notice = (kind, channel, target, { type = 'dm', at = now(), sk = relayKey.sk } = {}) =>
  finalizeEvent({ kind, created_at: at, content: '', tags: [['p', target], ['h', channel], ['t', type]] }, sk)
const me = agent.pk
ok('the notice filter asks only for our own DM notices', JSON.stringify(dmNoticeFilter(me)) === JSON.stringify({ kinds: [44100, 44101], '#p': [me], '#t': ['dm'] }))
ok('an added notice makes a DM', dmChannels([notice(44100, DM_OLD, me)], { me }).join() === DM_OLD)
ok('a later removal ends it', dmChannels([notice(44100, DM_OLD, me, { at: 10 }), notice(44101, DM_OLD, me, { at: 20 })], { me }).length === 0)
ok('a later re-add restores it, whatever order the relay sent them in',
  dmChannels([notice(44100, DM_OLD, me, { at: 30 }), notice(44100, DM_OLD, me, { at: 10 }), notice(44101, DM_OLD, me, { at: 20 })], { me }).join() === DM_OLD)
ok('a removal in the same second as an add wins', dmChannels([notice(44101, DM_OLD, me, { at: 10 }), notice(44100, DM_OLD, me, { at: 10 })], { me }).length === 0)
ok('a stream channel notice is not a DM', dmChannels([notice(44100, CH, me, { type: 'stream' })], { me }).length === 0)
ok('a notice about someone else is not our DM', dmChannels([notice(44100, DM_OLD, owner.pk)], { me }).length === 0)
const tampered = { ...notice(44100, DM_OLD, me) }; tampered.tags = [['p', me], ['h', DM_NEW], ['t', 'dm']]
ok('a notice whose signature does not cover its tags is ignored', dmChannels([tampered], { me }).length === 0)
ok('a notice with two h tags is ignored', dmChannels([finalizeEvent({ kind: 44100, created_at: now(), content: '', tags: [['p', me], ['h', DM_OLD], ['h', DM_NEW], ['t', 'dm']] }, relayKey.sk)], { me }).length === 0)
ok('a channel message is not a notice', dmChannels([finalizeEvent({ kind: 9, created_at: now(), content: '', tags: [['p', me], ['h', DM_OLD], ['t', 'dm']] }, relayKey.sk)], { me }).length === 0)

// --- pure: who may task the identity, in a channel and in a DM ---
const grantors = [owner.pk]
const g = (pubkey, cap = 'task', grantor = owner.pk) => ({ pubkey, cap, grant_id: Buffer.from(generateSecretKey()).toString('hex'), grantor })
const grants = [g(owner.pk, 'task+act'), g(myDude.pk), g(grantee.pk), g(grantee.pk, 'task', stranger.pk)]
ok('an owner DM is admitted on the owner\'s own live grant', nativeGrant({ author: owner.pk, dm: true, grants, grantors })?.grant_id === grants[0].grant_id)
ok('a DM from another agent is refused, though it holds a task grant', nativeGrant({ author: myDude.pk, dm: true, grants, grantors }) === null)
ok('a DM from a grant holder who is not the owner is refused', nativeGrant({ author: grantee.pk, dm: true, grants, grantors }) === null)
ok('a DM from a stranger is refused', nativeGrant({ author: stranger.pk, dm: true, grants, grantors }) === null)
ok('an owner DM with no live grant is refused: a revocation silences a DM too', nativeGrant({ author: owner.pk, dm: true, grants: grants.slice(1), grantors }) === null)
ok('in a channel, a grant holder is admitted as before', nativeGrant({ author: myDude.pk, dm: false, grants, grantors })?.grant_id === grants[1].grant_id)
ok('in a channel, a grant from a non-grantor still counts for nothing', nativeGrant({ author: grantee.pk, dm: false, grants: [grants[3]], grantors }) === null)
ok('in a channel, a stranger with no grant is refused as before', nativeGrant({ author: stranger.pk, dm: false, grants, grantors }) === null)
ok('task+act is preferred over task, as before', nativeGrant({ author: grantee.pk, dm: false, grants: [g(grantee.pk), g(grantee.pk, 'task+act')], grantors })?.cap === 'task+act')

// --- a Buzz-shaped relay with DMs ---
const members = new Set([agent.pk, owner.pk, myDude.pk, grantee.pk, stranger.pk]), stored = [], dmMembers = new Map()
const vals = (ev, n) => ev.tags.filter(t => t[0] === n).map(t => t[1])
const matches = (f, ev) => (!f['#h'] || f['#h'].some(h => vals(ev, 'h').includes(h))) && (!f.ids || f.ids.includes(ev.id)) &&
  (!f.kinds || f.kinds.includes(ev.kind)) && (!f['#p'] || f['#p'].some(p => vals(ev, 'p').includes(p))) &&
  (!f['#t'] || f['#t'].some(t => vals(ev, 't').includes(t))) && (!f.since || ev.created_at >= f.since)
const visible = (ev, reader) => MEMBERSHIP_KINDS.includes(ev.kind) ? vals(ev, 'p').includes(reader)
  : !dmMembers.has(vals(ev, 'h')[0]) || dmMembers.get(vals(ev, 'h')[0]).has(reader)
const http = createServer((req, res) => { res.writeHead(404); res.end() })
await new Promise(r => http.listen(0, '127.0.0.1', r))
const RELAY = `ws://127.0.0.1:${http.address().port}`
const server = new WebSocketServer({ server: http })
const broadcast = ev => { for (const peer of server.clients) peer.emit('stored', ev) }
server.on('connection', ws => {
  const challenge = Buffer.from(generateSecretKey()).toString('hex'), live = new Map()
  let authed = null
  ws.send(JSON.stringify(['AUTH', challenge]))
  ws.on('message', raw => {
    const m = JSON.parse(raw.toString())
    if (m[0] === 'AUTH') {
      const ev = m[1], tag = n => ev.tags.find(t => t[0] === n)?.[1]
      if (!(verifyEvent(ev) && ev.kind === 22242 && tag('challenge') === challenge && tag('relay') === RELAY && members.has(ev.pubkey))) return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted']))
      authed = ev.pubkey
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
    if (m[0] === 'EVENT') {
      const ev = m[1], h = vals(ev, 'h')[0]
      if (!authed || ev.pubkey !== authed || !h || MEMBERSHIP_KINDS.includes(ev.kind) || !verifyEvent(ev) ||
          (dmMembers.has(h) && !dmMembers.get(h).has(authed))) return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted']))
      stored.push(ev)
      ws.send(JSON.stringify(['OK', ev.id, true, '']))
      return broadcast(ev)
    }
    if (m[0] === 'REQ') {
      if (!authed) return ws.send(JSON.stringify(['CLOSED', m[1], 'auth-required: authenticate first']))
      const filters = m.slice(2)
      if (filters.some(f => !f['#h'] && !(f.kinds?.every(k => MEMBERSHIP_KINDS.includes(k)) && f['#p']?.length && f['#p'].every(p => p === authed))))
        return ws.send(JSON.stringify(['CLOSED', m[1], 'restricted: p-gated events require #p matching your pubkey']))
      for (const ev of stored) if (visible(ev, authed) && filters.some(f => matches(f, ev))) ws.send(JSON.stringify(['EVENT', m[1], ev]))
      live.set(m[1], filters)
      return ws.send(JSON.stringify(['EOSE', m[1]]))
    }
    if (m[0] === 'CLOSE') live.delete(m[1])
  })
  ws.on('stored', ev => { for (const [id, filters] of live) if (visible(ev, authed) && filters.some(f => matches(f, ev))) ws.send(JSON.stringify(['EVENT', id, ev])) })
})
// The relay opens a DM by recording its members and telling each one, as Buzz's 44100 does.
const openDm = (channel, people) => {
  dmMembers.set(channel, new Set(people))
  for (const pk of people) { const ev = notice(44100, channel, pk); stored.push(ev); broadcast(ev) }
}
const leaveDm = (channel, pk) => { dmMembers.get(channel).delete(pk); const ev = notice(44101, channel, pk); stored.push(ev); broadcast(ev) }
// Clients p-tag every other participant in a DM (block/buzz desktop messageMentionPubkeys.ts).
const say = async (who, channel, content) => {
  const s = await openBuzzSession({ relay: RELAY, signer: local(who.sk) })
  const tags = [['h', channel], ...[...(dmMembers.get(channel) || [agent.pk])].filter(p => p !== who.pk).map(p => ['p', p])]
  try { return (await s.publish({ kind: 9, created_at: now(), content, tags })).event } finally { s.close() }
}

const session = await openBuzzSession({ relay: RELAY, signer: local(agent.sk) })
ok('a session will read its own membership notices with no #h', Array.isArray(await session.fetch(dmNoticeFilter(agent.pk))))
ok('a session refuses to ask for someone else\'s notices', /needs #h/.test(await session.fetch(dmNoticeFilter(owner.pk)).then(() => '', e => e.message)))
ok('a session still refuses any other filter without #h', /needs #h/.test(await session.fetch({ kinds: [9], '#p': [agent.pk] }).then(() => '', e => e.message)))
session.close()

// --- the keyless watcher hears the owner's DMs, including one opened after it started ---
const root = mkdtempSync(join(tmpdir(), 'nvoy-owner-dm-'))
for (const d of ['state', 'run', 'spool']) mkdirSync(join(root, d), { mode: 0o700 })
const spool = join(root, 'spool'), gid = process.getgid(), otherGid = process.getgroups().find(x => x !== gid)
const oracleSock = join(spool, 'buzz-auth.sock')
const oracle = await serveAuthOracle({ socketPath: oracleSock, relay: RELAY, signer: local(agent.sk), pubkey: agent.pk, gid })
const pendingFor = id => join(spool, `${id}.buzz.pending`)
let log = ''
const watch = extra => {
  const child = spawn(process.execPath, ['mcp/tools/buzz-wake-watcher.mjs', '--recipient', agent.pk, '--relay', RELAY, '--channels', CH, ...extra,
    '--auth-socket', oracleSock, '--marker-dir', spool, '--marker-gid', String(gid)],
  { env: { PATH: process.env.PATH, WAKE_PING_MS: '200', WAKE_RETRY_MAX_MS: '400' }, stdio: ['ignore', 'pipe', 'pipe'] })
  child.stdout.on('data', c => { log += c }); child.stderr.on('data', c => { log += c })
  return child
}
openDm(DM_OLD, [owner.pk, agent.pk])
let watcher = watch(['--owners', owner.pk])
ok('the watcher finds the DM that already existed', await until(() => /listening on 1 channel\(s\) and 1 DM\(s\)/.test(log)))
const ownerOld = await say(owner, DM_OLD, 'are you there?')
ok('an owner DM leaves a marker', await until(() => existsSync(pendingFor(ownerOld.id))))
openDm(DM_NEW, [owner.pk, agent.pk])
ok('a DM opened after start is picked up', await until(() => /listening on 1 channel\(s\) and 2 DM\(s\)/.test(log)))
const ownerNew = await say(owner, DM_NEW, 'a new conversation')
ok('an owner message in the new DM leaves a marker', await until(() => existsSync(pendingFor(ownerNew.id))))
openDm(DM_AGENTS, [myDude.pk, agent.pk])
ok('a DM another agent opened is followed too', await until(() => /and 3 DM\(s\)/.test(log)))
const dudeDm = await say(myDude, DM_AGENTS, 'agent to agent')
openDm(DM_GRANTEE, [owner.pk, grantee.pk, agent.pk])
await until(() => /and 4 DM\(s\)/.test(log))
const granteeDm = await say(grantee, DM_GRANTEE, 'I hold a grant')
const channelMention = await say(stranger, CH, 'channel mention from a stranger')
ok('a channel mention is marked for the broker exactly as before', await until(() => existsSync(pendingFor(channelMention.id))))
await sleep(300)
ok('a DM from another agent leaves no marker', !existsSync(pendingFor(dudeDm.id)))
ok('a DM from a grant holder who is not the owner leaves no marker', !existsSync(pendingFor(granteeDm.id)))
leaveDm(DM_AGENTS, agent.pk)
ok('a removal notice drops the DM', await until(() => /and 3 DM\(s\)/.test(log.split(/and 4 DM\(s\)/).pop())))
watcher.kill(); await sleep(100)
log = ''
watcher = watch([])
ok('without --owners the watcher listens to its channels only', await until(() => /listening on 1 channel\(s\) and 0 DM\(s\)/.test(log)))
const unheard = await say(owner, DM_OLD, 'no owners configured')
await sleep(300)
ok('and an owner DM leaves no marker', !existsSync(pendingFor(unheard.id)))
watcher.kill()
oracle.close()

// --- the keyed broker decides on its own read; a marker is only a hint ---
const manifest = { version: 1, id: 'dm', pubkey: agent.pk, worker_enabled: false, key_ref: '/etc/nvoy/credentials/dm.nsec',
  state_dir: join(root, 'state'), runtime_dir: join(root, 'run'), spool_dir: spool,
  broker_adapter_gid: gid, worker_handoff_gid: otherGid, watcher_uid: 41011, broker_uid: 41012, adapter_uid: 41013, worker_uid: 41014,
  grantors: [owner.pk], relays: ['wss://127.0.0.1:1'], buzz: { relay: RELAY, channels: [CH] } }
const instances = join(root, 'instances'); mkdirSync(instances)
writeFileSync(join(instances, 'dm.json'), JSON.stringify(manifest))
const credential = join(root, 'agent.key'); writeFileSync(credential, Buffer.from(agent.sk).toString('hex'), { mode: 0o600 })
const run = (args, env) => new Promise(resolve => {
  const child = spawn(process.execPath, args, { env: { PATH: process.env.PATH, NVOY_INSTANCE_ROOT: instances, NVOY_BROKER_CREDENTIAL: credential, ...env }, stdio: ['ignore', 'pipe', 'pipe'] })
  let stdout = '', stderr = ''
  child.stdout.on('data', c => { stdout += c }); child.stderr.on('data', c => { stderr += c })
  child.on('exit', status => resolve({ status, stdout, stderr }))
})
const plant = id => writeFileSync(pendingFor(id), JSON.stringify({ observed_at: Date.now(), envelope: id }) + '\n', { mode: 0o660 })
const deliver = id => { plant(id); return run(['mcp/tools/instance-broker-native.mjs', 'deliver', '--instance', 'dm', '--event', id]) }
const receiptFor = id => join(root, 'state', 'receipts', `${id}.json`)
const refusedDm = (r, id) => r.status === 0 && /is not this identity's owner; heard as data only/.test(r.stderr) &&
  existsSync(join(spool, `${id}.buzz.inflight.done`)) && !existsSync(receiptFor(id))
// A forged marker for a DM the agent has since left still names an event the agent can no longer read.
await sleep(1100) // a re-add in the same second as the removal would lose the tie, by design
openDm(DM_AGENTS, [myDude.pk, agent.pk])
const dudeAgain = await say(myDude, DM_AGENTS, 'forged marker for this one')
let r = await deliver(dudeAgain.id)
ok('a forged marker for another agent\'s DM is refused by the broker before any grant is consulted', refusedDm(r, dudeAgain.id))
r = await deliver(granteeDm.id)
ok('a forged marker for a grant holder\'s DM is refused by the broker before any grant is consulted', refusedDm(r, granteeDm.id))
openDm(DM_ELSEWHERE, [owner.pk, myDude.pk])
const notOurs = await say(owner, DM_ELSEWHERE, `@agent ${agent.pk}`)
r = await deliver(notOurs.id)
ok('an owner message in a DM the identity is not in is never fetched', r.status === 0 && /not stored/.test(r.stderr) && !existsSync(receiptFor(notOurs.id)))
r = await deliver(ownerNew.id)
ok('an owner DM passes the owner gate and waits on the live grant, not consumed', r.status === 75 && /policy unavailable|policy check failed/.test(r.stderr) && existsSync(pendingFor(ownerNew.id)))
r = await deliver(channelMention.id)
ok('a channel mention from a non-owner still goes to the live grant check, as before', r.status === 75 && /policy unavailable|policy check failed/.test(r.stderr))

// --- keyless boundaries: a DM authority is the owner's, in a DM, or it is nothing ---
const dmTask = (authority, from = authority.sender) => ({ type: 'admitted-task', instance: 'dm', envelope: ownerNew.id, authority,
  messages: [{ from, at: ownerNew.created_at, content: ownerNew.content, event_id: ownerNew.id, kind: 9 }] })
const v3dm = { version: 3, type: 'scoped-instruction', sender: owner.pk, grant_id: 'a'.repeat(64), grantor: owner.pk, cap: 'task',
  scope_subject: agent.pk, policy_checked_at: Date.now(), source_event: ownerNew.id, reply_channel: DM_NEW, dm: true }
const policy = { instance: 'dm', scopeSubject: agent.pk, grantors: [owner.pk], buzz: { relay: RELAY, channels: [CH] } }
ok('an owner DM authority is a trusted instruction', validateAdmittedTask(dmTask(v3dm), policy).trustedInstruction === true)
ok('a DM authority for anyone but the owner is refused', !!throws(() => validateAdmittedTask(dmTask({ ...v3dm, sender: myDude.pk }), policy)))
ok('a DM authority is refused where the grantors are unknown', !!throws(() => validateAdmittedTask(dmTask(v3dm), { ...policy, grantors: [] })))
ok('an unconfigured channel without the dm mark is still refused', !!throws(() => validateAdmittedTask(dmTask({ ...v3dm, dm: undefined }), policy)))
ok('a dm mark that is not exactly true is refused', !!throws(() => validateAdmittedTask(dmTask({ ...v3dm, dm: 'yes' }), policy)))
ok('a configured channel cannot be passed off as a DM', !!throws(() => validateAdmittedTask(dmTask({ ...v3dm, reply_channel: CH }), policy)))
ok('a DM authority is refused on an instance with no buzz block', !!throws(() => validateAdmittedTask(dmTask(v3dm), { ...policy, buzz: null })))

// --- the reply: in that DM, to the owner, through the same secret filter ---
const reply = channelReply({ channel: DM_NEW, parent: ownerNew, content: 'here' })
ok('the frozen DM reply stays in the DM and tags the owner', reply.tags.filter(t => t[0] === 'h').map(t => t[1]).join() === DM_NEW && reply.tags.some(t => t[0] === 'p' && t[1] === owner.pk))
mkdirSync(join(root, 'state', 'receipts'), { recursive: true, mode: 0o700 })
const ask = (n, receipt, row = {}) => {
  const source = String(n).repeat(64), id = String(n).repeat(32)
  writeFileSync(receiptFor(source), JSON.stringify({ version: 3, mode: 'buzz-native', instance: 'dm', broker: agent.pk, envelope: source,
    sender: owner.pk, grant_id: 'a'.repeat(64), grantor: owner.pk, cap: 'task', source_event: source, reply_channel: DM_NEW, reply_root: source,
    admitted_at: Date.now(), expires_at: Date.now() + 300000, dm: true, ...receipt }), { mode: 0o600 })
  writeFileSync(join(root, 'run', 'reply-requests.jsonl'), JSON.stringify({ version: 1, type: 'reply-request', id, instance: 'dm', receipt: source, content: `reply ${n}`, ...row }) + '\n', { flag: 'a' })
  return run(['mcp/tools/instance-broker-reply.mjs', '--instance', 'dm', '--request', id, '--prepare'])
}
r = await ask(1, { sender: myDude.pk })
ok('a DM receipt for anyone but the owner is refused before the signer opens', r.status === 1 && /not bound to a DM from this identity's owner/.test(r.stderr))
r = await ask(2, { reply_channel: CH })
ok('a DM receipt cannot point its reply at a configured channel', r.status === 1 && /not bound to a DM/.test(r.stderr))
r = await ask(3, { dm: false, reply_channel: DM_NEW })
ok('a native receipt for an unconfigured channel without the dm mark is refused as before', r.status === 1 && /not bound to a configured channel/.test(r.stderr))
r = await ask(4, {}, { mention: [myDude.pk] })
ok('a DM reply mentions no one', r.status === 1 && /a DM reply mentions no one/.test(r.stderr))
const token = 'gh' + 'o_' + 'R2d4F6h8J0l2N4p6R8t0V2x4Z6b8D0f2H4j6'
r = await ask(5, {}, { content: `here you go ${token}` })
ok('the outbound secret filter still refuses a credential in a DM reply, without echoing it',
  r.status === 1 && /withheld: looks like a credential/.test(r.stderr) && !(r.stdout + r.stderr).includes(token))
r = await ask(6, {})
ok('an owner DM receipt is bound, and goes on to the live grant recheck', r.status === 1 && !/not bound/.test(r.stderr) && /live grant|live matching grant/.test(r.stderr))

server.close(); http.close()
console.log(`\n${passes}/${passes + fails} passed`)
process.exit(fails ? 1 : 0)
