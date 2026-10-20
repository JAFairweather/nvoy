// Agents starting conversations, and the brakes on agents directing agents: the may_post and
// agent_limits manifest blocks, nvoy_channel_post end to end against a Buzz-shaped relay, the
// nvoy-hop tag and its admission limit, the per-sender admission cap, and NIP-40 grant expiry.
import { WebSocketServer } from 'ws'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'
import { channelPost, channelReply } from '../mcp/tools/buzz_native.mjs'
import { verifyChannelTaskCarry } from '../mcp/tools/channel_task_carry.mjs'
import { HOUR_MS, MALFORMED_HOP, admissionLimit, grantExpired, hopFromJson, hopOf, nextHop, slideWindow } from '../mcp/tools/agent_limits.mjs'
import { queuePost, resolvePost, resolveReplyMention } from '../mcp/tools/agent_post.mjs'
import { isTerminalReplyFailure } from '../mcp/tools/reply_retry.mjs'

let fails = 0, passes = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passes++ : fails++ }
const throws = fn => { try { fn(); return '' } catch (e) { return e.message } }
const now = () => Math.floor(Date.now() / 1000)
const run = (args, env) => new Promise(resolve => {
  const child = spawn(process.execPath, args, { env: { PATH: process.env.PATH, ...env }, stdio: ['ignore', 'pipe', 'pipe'] })
  let stdout = '', stderr = ''
  child.stdout.on('data', c => { stdout += c }); child.stderr.on('data', c => { stderr += c })
  child.on('exit', status => resolve({ status, stdout, stderr }))
})

const CH = '3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607', CH2 = '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d', OTHER = '00000000-0000-4000-8000-000000000000'
const agentSk = generateSecretKey(), agent = getPublicKey(agentSk)
const dennis = getPublicKey(generateSecretKey()), neil = getPublicKey(generateSecretKey()), stranger = getPublicKey(generateSecretKey())
const grantorSk = generateSecretKey(), grantor = getPublicKey(grantorSk)

// --- a Buzz-shaped relay: NIP-42 for members, kind:9 needs an h tag, stores what it accepts ---
const stored = []
const http = createServer((req, res) => { res.writeHead(404); res.end() })
await new Promise(r => http.listen(0, '127.0.0.1', r))
const RELAY = `ws://127.0.0.1:${http.address().port}`
const buzz = new WebSocketServer({ server: http })
buzz.on('connection', ws => {
  const challenge = Buffer.from(generateSecretKey()).toString('hex')
  let authed = null
  ws.send(JSON.stringify(['AUTH', challenge]))
  ws.on('message', raw => {
    const m = JSON.parse(raw.toString())
    if (m[0] === 'AUTH') {
      const ev = m[1], tag = n => ev.tags.find(t => t[0] === n)?.[1]
      if (!(verifyEvent(ev) && tag('challenge') === challenge && tag('relay') === RELAY && ev.pubkey === agent)) return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted']))
      authed = ev.pubkey
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
    if (m[0] === 'EVENT') {
      const ev = m[1]
      if (!authed || ev.pubkey !== authed || !ev.tags.some(t => t[0] === 'h') || !verifyEvent(ev)) return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted']))
      if (!stored.some(s => s.id === ev.id)) stored.push(ev)
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
  })
})

// --- manifests: one root per fixture, since the collision check reads every manifest beside it ---
const root = mkdtempSync(join(tmpdir(), 'nvoy-agent-post-'))
const gid = process.getgid(), uid = process.getuid()
const base = id => ({ version: 1, id, pubkey: agent, broker_mode: 'local', key_ref: '/etc/nvoy/credentials/agent.nsec',
  worker_enabled: false, delivery_mode: 'notify_only',
  state_dir: join(root, id, 'state'), runtime_dir: join(root, id, 'run'), spool_dir: join(root, id, 'spool'),
  broker_adapter_gid: gid, worker_handoff_gid: gid + 1, watcher_uid: uid + 11, broker_uid: uid + 12, adapter_uid: uid + 13, worker_uid: uid + 14,
  grantors: [grantor], relays: ['wss://127.0.0.1:1'], buzz: { relay: RELAY, channels: [CH, CH2] } })
const fixture = (id, extra = {}, drop = []) => {
  const m = { ...base(id), ...extra }
  for (const key of drop) delete m[key]
  mkdirSync(join(root, id, 'instances'), { recursive: true })
  for (const d of ['state', 'run', 'spool']) mkdirSync(join(root, id, d), { recursive: true })
  writeFileSync(join(root, id, 'instances', `${id}.json`), JSON.stringify(m))
  return { root: join(root, id, 'instances'), load: () => readManifest(join(root, id, 'instances'), id), run: join(root, id, 'run'), state: join(root, id, 'state') }
}
const mayPost = { channels: [CH], per_hour: 5, mention: [dennis, { name: 'neil', pubkey: neil }] }

// --- 1. manifest validation ---
const plain = fixture('plain').load()
ok('no may_post means the identity may only reply', plain.mayPost === null)
ok('agent_limits defaults to max_hops 3 and 12 per sender per hour', plain.agentLimits.maxHops === 3 && plain.agentLimits.perSenderPerHour === 12)
const poster = fixture('poster', { may_post: { ...mayPost, channels: [CH.toUpperCase()] } }).load()
ok('may_post parses to lower-cased channels, its cap, and an allowlist of keys and names',
  poster.mayPost.channels.join() === CH && poster.mayPost.perHour === 5 &&
  poster.mayPost.mention[0].pubkey === dennis && poster.mayPost.mention[0].name === null && poster.mayPost.mention[1].name === 'neil')
ok('may_post is frozen', Object.isFrozen(poster.mayPost) && Object.isFrozen(poster.mayPost.mention) && Object.isFrozen(poster.mayPost.mention[1]))
ok('mention may be omitted, leaving an empty allowlist', fixture('nomention', { may_post: { channels: [CH], per_hour: 1 } }).load().mayPost.mention.length === 0)
const tuned = fixture('tuned', { agent_limits: { max_hops: 2 } }).load()
ok('agent_limits tunes one field and defaults the other', tuned.agentLimits.maxHops === 2 && tuned.agentLimits.perSenderPerHour === 12)
const refused = (why, extra, pattern, drop) => ok(`the manifest is refused with ${why}`, pattern.test(throws(fixture(`r${passes + fails}`, extra, drop).load)))
refused('may_post but no buzz block', { may_post: mayPost }, /requires a buzz block/, ['buzz'])
refused('a may_post channel outside buzz.channels', { may_post: { ...mayPost, channels: [OTHER] } }, /subset of buzz\.channels/)
refused('no may_post channels', { may_post: { ...mayPost, channels: [] } }, /distinct channel UUIDs/)
refused('a duplicate may_post channel', { may_post: { ...mayPost, channels: [CH, CH] } }, /distinct channel UUIDs/)
refused('per_hour 0', { may_post: { ...mayPost, per_hour: 0 } }, /per_hour must be an integer from 1 to 30/)
refused('per_hour 31', { may_post: { ...mayPost, per_hour: 31 } }, /per_hour must be an integer from 1 to 30/)
refused('a fractional per_hour', { may_post: { ...mayPost, per_hour: 2.5 } }, /per_hour must be an integer/)
refused('a mention that is not a key', { may_post: { ...mayPost, mention: ['dennis'] } }, /pubkey or \{ name, pubkey \}/)
refused('a duplicate mention', { may_post: { ...mayPost, mention: [dennis, { name: 'd', pubkey: dennis }] } }, /pubkeys must be distinct/)
refused('a duplicate mention name', { may_post: { ...mayPost, mention: [{ name: 'Neil', pubkey: neil }, { name: 'neil', pubkey: dennis }] } }, /names must be distinct/)
refused('an unknown may_post field', { may_post: { ...mayPost, anyone: true } }, /takes only channels, per_hour and mention/)
refused('may_post on a headless worker manifest', { may_post: mayPost, delivery_mode: 'headless', worker_enabled: true,
  worker_image: `ghcr.io/x/w@sha256:${'a'.repeat(64)}`, worker_runner: 'codex', worker_credential_ref: '/etc/nvoy/w' }, /local-broker, worker-disabled notify_only/)
refused('max_hops 0', { agent_limits: { max_hops: 0 } }, /max_hops must be an integer from 1 to 10/)
refused('max_hops 11', { agent_limits: { max_hops: 11 } }, /max_hops must be an integer from 1 to 10/)
refused('per_sender_per_hour 121', { agent_limits: { per_sender_per_hour: 121 } }, /per_sender_per_hour must be an integer from 1 to 120/)
refused('an unknown agent_limits field', { agent_limits: { max_hops: 3, grantors_too: true } }, /takes only max_hops and per_sender_per_hour/)

// --- 2. the keyless tool's resolution ---
ok('the tool refuses without may_post: this identity may only reply', resolvePost(plain, { text: 'hi' }).message === 'this identity may only reply')
const r1 = resolvePost(poster, { text: '  morning all  ' })
ok('an omitted channel is the first may_post channel, with trimmed text and no mentions', r1.channel === CH && r1.content === 'morning all' && r1.mention.length === 0)
const r2 = resolvePost(poster, { text: 'hi', mention: ['NEIL', dennis, 'neil'] })
ok('a mention resolves by name or hex, once each', r2.mention.join() === [neil, dennis].join())
ok('a channel outside may_post is refused', resolvePost(poster, { text: 'hi', channel: CH2 }).code === 'NVOY_POST_CHANNEL_REFUSED')
const off = resolvePost(poster, { text: 'hi', mention: [stranger] })
ok('an off-allowlist mention is refused, naming only a key prefix', off.code === 'NVOY_POST_MENTION_REFUSED' && off.message.includes(stranger.slice(0, 8)) && !off.message.includes(stranger))
ok('an unknown name is refused', resolvePost(poster, { text: 'hi', mention: ['kerouac'] }).code === 'NVOY_POST_MENTION_REFUSED')
ok('empty text is refused', resolvePost(poster, { text: '   ' }).code === 'NVOY_BAD_POST')
ok('a reply without a mention needs no may_post', resolveReplyMention(plain, undefined).mention.length === 0 && resolveReplyMention(plain, []).mention.length === 0)
ok('a reply mention without may_post is refused', resolveReplyMention(plain, ['neil']).code === 'NVOY_REPLY_MENTION_NOT_PERMITTED')
ok('a reply mention resolves names and keys once each', resolveReplyMention(poster, ['Neil', dennis, 'neil']).mention.join() === [neil, dennis].join())
ok('an off-allowlist or unknown reply mention is refused', resolveReplyMention(poster, [stranger]).code === 'NVOY_REPLY_MENTION_REFUSED' &&
  resolveReplyMention(poster, ['kerouac']).code === 'NVOY_REPLY_MENTION_REFUSED' && resolveReplyMention(poster, 'neil').code === 'NVOY_BAD_REPLY')

// --- 3. nvoy_channel_post end to end: queue → broker → signed kind:9 on the relay ---
const credential = join(root, 'agent.key'); writeFileSync(credential, Buffer.from(agentSk).toString('hex'), { mode: 0o600 })
const post = (f, id, request) => run(['mcp/tools/instance-broker-post.mjs', '--instance', id, '--request', request],
  { NVOY_INSTANCE_ROOT: f.root, NVOY_BROKER_CREDENTIAL: credential })
const pf = fixture('posting', { may_post: { ...mayPost, per_hour: 2 } }), pm = pf.load()
ok('an unprovisioned post queue is refused rather than created', queuePost(pm, { text: 'hi' }).error?.code === 'NVOY_POST_QUEUE_FAILED' && !existsSync(join(pf.run, 'post-requests.jsonl')))
writeFileSync(join(pf.run, 'post-requests.jsonl'), '', { mode: 0o640 })
const q1 = queuePost(pm, { text: 'who is on the review rota?', mention: ['neil'] })
ok('the tool queues a bounded request with a resolved key and channel', q1.ok?.queued === true && q1.ok.channel === CH && q1.ok.mention.join() === neil)
let r = await post(pf, 'posting', q1.ok.request)
const first = stored.find(ev => ev.content === 'who is on the review rota?')
ok('the broker posts it', r.status === 0 && !!first)
ok('the post is a top-level kind:9 signed by the identity: h, the mention as p, nvoy-hop 1, no e',
  first?.kind === 9 && first.pubkey === agent && verifyEvent(first) &&
  JSON.stringify(first.tags) === JSON.stringify([['h', CH], ['p', neil], ['nvoy-hop', '1']]))
ok('the post log names the event prefix and the channel, never the content',
  r.stdout.includes(first?.id.slice(0, 12)) && r.stdout.includes(CH) && !r.stdout.includes('review rota'))
r = await post(pf, 'posting', q1.ok.request)
ok('a retry republishes nothing new', r.status === 0 && /"replay":true/.test(r.stdout) && stored.filter(ev => ev.content === 'who is on the review rota?').length === 1)
// Forged rows are dated outside the hour so only the genuine ones spend the tool's advisory budget.
const forge = (f, row) => { writeFileSync(join(f.run, 'post-requests.jsonl'), readFileSync(join(f.run, 'post-requests.jsonl'), 'utf8') +
  JSON.stringify({ version: 1, type: 'post-request', instance: 'posting', channel: CH, mention: [], content: 'forged', requested_at: Date.now() - 2 * HOUR_MS, ...row }) + '\n') }
forge(pf, { id: 'b'.repeat(32), channel: CH2 })
r = await post(pf, 'posting', 'b'.repeat(32))
ok('the broker refuses a queued channel outside may_post, whatever the keyless side wrote', r.status === 1 && /post refused: channel is not in may_post\.channels/.test(r.stderr))
forge(pf, { id: 'c'.repeat(32), mention: [stranger] })
r = await post(pf, 'posting', 'c'.repeat(32))
ok('the broker refuses an off-allowlist mention', r.status === 1 && /post refused: [0-9a-f]{8} is not on may_post\.mention/.test(r.stderr))
forge(pf, { id: 'd'.repeat(32), recipient: stranger })
r = await post(pf, 'posting', 'd'.repeat(32))
ok('the broker refuses a request carrying an extra field', r.status === 1 && /invalid or overbroad/.test(r.stderr))
const q2 = queuePost(pm, { text: 'second' })
r = await post(pf, 'posting', q2.ok.request)
ok('a second post inside the cap is published', r.status === 0 && stored.some(ev => ev.content === 'second'))
const advisory = queuePost(pm, { text: 'third' })
ok('the tool tells the agent at once when the hour is spent', advisory.error?.code === 'NVOY_POST_RATE_LIMITED')
forge(pf, { id: 'e'.repeat(32), content: 'third, forged past the advisory check' })
r = await post(pf, 'posting', 'e'.repeat(32))
ok('the broker\'s durable counter refuses a post over per_hour', r.status === 1 && /over the hourly cap \(2\/2/.test(r.stderr) && !stored.some(ev => ev.content.startsWith('third')))
ok('the counter lives in the broker state root', existsSync(join(pf.state, 'agent-limits', 'posts.json')))
const nf = fixture('noposting'); writeFileSync(join(nf.run, 'post-requests.jsonl'), JSON.stringify({ version: 1, type: 'post-request', id: 'f'.repeat(32),
  instance: 'noposting', channel: CH, mention: [], content: 'x', requested_at: Date.now() }) + '\n')
r = await post(nf, 'noposting', 'f'.repeat(32))
ok('an identity without may_post is refused by the broker: this identity may only reply', r.status === 1 && /post refused: this identity may only reply/.test(r.stderr))

// --- 4. the hop tag ---
const tpl = channelPost({ channel: CH, content: 'x', mentions: [dennis] })
ok('channelPost: hop 1, no e tags', hopOf(tpl) === 1 && !tpl.tags.some(t => t[0] === 'e'))
ok('channelPost refuses duplicate or non-hex mentions', !!throws(() => channelPost({ channel: CH, content: 'x', mentions: [dennis, dennis] })) &&
  !!throws(() => channelPost({ channel: CH, content: 'x', mentions: ['neil'] })))
const parent = { id: 'a'.repeat(64), pubkey: dennis, tags: [] }
ok('a reply to an untagged (human) message is hop 1', hopOf(channelReply({ channel: CH, parent, content: 'x', hop: nextHop(null) })) === 1)
ok('a reply to a hop-2 message is hop 3', hopOf(channelReply({ channel: CH, parent, content: 'x', hop: nextHop(2) })) === 3)
ok('a receipt from before hops were recorded continues at hop 1', nextHop(undefined) === 1)
ok('a reply still threads and p-tags its parent', channelReply({ channel: CH, parent, content: 'x', hop: 2 }).tags.some(t => t[0] === 'p' && t[1] === dennis))
ok('a reply\'s mentions follow its parent\'s p tag, without repeating the parent',
  JSON.stringify(channelReply({ channel: CH, parent, content: 'x', mentions: [dennis, neil] }).tags) ===
  JSON.stringify([['h', CH], ['e', parent.id, '', 'reply'], ['p', dennis], ['p', neil], ['nvoy-hop', '1']]))
ok('channelReply refuses duplicate or non-hex mentions', !!throws(() => channelReply({ channel: CH, parent, content: 'x', mentions: [neil, neil] })) &&
  !!throws(() => channelReply({ channel: CH, parent, content: 'x', mentions: ['neil'] })))
ok('an absent hop tag is null', hopOf({ tags: [['h', CH]] }) === null)
ok('a malformed or doubled hop tag is past every limit', hopOf({ tags: [['nvoy-hop', 'x']] }) === MALFORMED_HOP &&
  hopOf({ tags: [['nvoy-hop', '1'], ['nvoy-hop', '1']] }) === MALFORMED_HOP && hopOf({ tags: [['nvoy-hop', '01']] }) === MALFORMED_HOP)
ok('a malformed hop survives the JSON hop from attention', hopFromJson(JSON.parse(JSON.stringify({ h: MALFORMED_HOP })).h) === MALFORMED_HOP &&
  hopFromJson(undefined) === null && hopFromJson(-1) === MALFORMED_HOP && hopFromJson('2') === MALFORMED_HOP)
const authorSk = generateSecretKey(), author = getPublicKey(authorSk)
const carried = hop => {
  const source = JSON.parse(JSON.stringify(finalizeEvent({ kind: 9, created_at: 1785870000, content: 'go',
    tags: [['h', CH], ['p', agent], ...(hop == null ? [] : [['nvoy-hop', hop]])] }, authorSk)))
  return verifyChannelTaskCarry({ from: stranger, at: 1785870001, content: JSON.stringify({ v: 1, type: 'waggle-channel-task-carry', channel: CH, reason: 'mention', source }) },
    { channels: [CH], carrierGrant: { grantId: 'c'.repeat(64), grantor, cap: 'task-relay' }, taskGrantFor: () => ({ grantId: 'a'.repeat(64), grantor, cap: 'task' }) })
}
ok('a carried admission brings its source\'s hop, or null for a human', carried('2')?.admission.hop === 2 && carried(null)?.admission.hop === null)

// --- 5. the admission gate: hop limit and per-sender cap ---
const limits = { maxHops: 3, perSenderPerHour: 2 }
const counter = join(root, 'admissions.json')
const gate = (sender, eventId, hop = null, at = Date.now()) => admissionLimit({ limits, grantors: [grantor], sender, eventId, hop, path: counter, at })
ok('a hop at max_hops is not admitted, and says hop limit', /^hop limit: nvoy-hop 3 >= max_hops 3/.test(gate(dennis, '1'.repeat(64), 3) || ''))
ok('a hop below max_hops is admitted', gate(dennis, '2'.repeat(64), 2) === null)
ok('the hop limit binds a grantor\'s broker-signed message too', /hop limit/.test(gate(grantor, '3'.repeat(64), 5) || ''))
ok('a malformed hop is a hop limit', /malformed nvoy-hop/.test(gate(dennis, '4'.repeat(64), MALFORMED_HOP) || ''))
ok('an untagged message is not hop limited', gate(neil, '5'.repeat(64), null) === null)
ok('a second admission inside the hour is allowed', gate(dennis, '6'.repeat(64)) === null)
const over = gate(dennis, '7'.repeat(64))
ok('the third is refused as rate limit with an 8-hex sender prefix', /^rate limit: sender [0-9a-f]{8} already admitted 2\/2/.test(over || '') && over.includes(dennis.slice(0, 8)) && !over.includes(dennis))
ok('a retry of an already counted event is not refused by itself', gate(dennis, '6'.repeat(64)) === null)
ok('another sender has its own budget', gate(neil, '8'.repeat(64)) === null)
ok('grantors are exempt from the cap', [1, 2, 3, 4, 5].every(n => gate(grantor, String(n).repeat(64).replace(/^./, 'a')) === null))
ok('the counter is durable: a fresh read of the file still refuses', /rate limit/.test(admissionLimit({ limits, grantors: [], sender: dennis, eventId: '9'.repeat(64), hop: null, path: counter }) || ''))
ok('the window slides: an hour later the sender is admitted again', gate(dennis, 'a'.repeat(64), null, Date.now() + HOUR_MS + 1000) === null)
const w = slideWindow([{ key: 'k', id: 'old', at: 0 }, { key: 'k', id: 'new', at: HOUR_MS - 1 }], { key: 'k', id: 'x', at: HOUR_MS, limit: 1 })
ok('slideWindow drops entries older than the hour and reports when room returns', !w.allowed && w.count === 1 && w.entries.length === 1 && w.retryAt === 2 * HOUR_MS - 1)
writeFileSync(join(root, 'bad.json'), '{"version":2}')
ok('an unreadable counter fails closed', !!throws(() => admissionLimit({ limits, grantors: [], sender: dennis, eventId: 'b'.repeat(64), hop: null, path: join(root, 'bad.json') })))

// --- 6. NIP-40 grant expiry ---
ok('a grant without expiration never expires', grantExpired({ tags: [] }, 10) === false)
ok('a grant whose expiration has passed is expired', grantExpired({ tags: [['expiration', '10']] }, 10) === true)
ok('a future expiration is still live', grantExpired({ tags: [['expiration', '11']] }, 10) === false)
ok('a malformed expiration is treated as expired', grantExpired({ tags: [['expiration', 'soon']] }, 10) === true)
// attention --policy-only against a plain relay holding signed grants and one revocation
const scopeSalt = 'ab'.repeat(16)
const scope = createHash('sha256').update(Buffer.concat([Buffer.from('waggle/da-scope/v1'), Buffer.from([0]), Buffer.from(agent), Buffer.from(scopeSalt, 'hex')])).digest('hex')
const grantFor = (pk, at, extra = []) => finalizeEvent({ kind: 440, created_at: at, content: '',
  tags: [['p', pk], ['da-scope', scope, scopeSalt], ['da-cap', 'task'], ...extra] }, grantorSk)
const live = grantFor(dennis, now() - 100)
const expired = grantFor(neil, now() - 100, [['expiration', String(now() - 10)]])
const future = grantFor(author, now() - 100, [['expiration', String(now() + 3600)]])
const displaced = grantFor(stranger, now() - 200), newerExpired = grantFor(stranger, now() - 100, [['expiration', String(now() - 1)]])
const grants = [live, expired, future, displaced, newerExpired]
const gHttp = createServer((req, res) => { res.writeHead(404); res.end() })
await new Promise(res => gHttp.listen(0, '127.0.0.1', res))
const grantRelay = new WebSocketServer({ server: gHttp })
grantRelay.on('connection', ws => ws.on('message', raw => {
  const m = JSON.parse(raw.toString())
  if (m[0] !== 'REQ') return
  for (const ev of grants) if (m[2].kinds.includes(ev.kind) && m[2].authors.includes(ev.pubkey)) ws.send(JSON.stringify(['EVENT', m[1], ev]))
  ws.send(JSON.stringify(['EOSE', m[1]]))
}))
mkdirSync(join(root, 'home'))
r = await run(['mcp/tools/attention.mjs', '--policy-only'], { HOME: join(root, 'home'), NVOY_NSEC: Buffer.from(agentSk).toString('hex'),
  GRANTORS: grantor, NVOY_RELAYS: `ws://127.0.0.1:${gHttp.address().port}` })
let policy = {}; try { policy = JSON.parse(r.stdout) } catch { /* reported below */ }
const holders = (policy.grants || []).map(g => g.pubkey)
ok('attention answers for this identity with usable policy', r.status === 0 && policy.me === agent && policy.policyUsable === true)
ok('a grant with no expiration is live', holders.includes(dennis))
ok('a grant whose NIP-40 expiration has passed is ignored', !holders.includes(neil))
ok('a grant expiring later is live', holders.includes(author))
ok('an expired grant drops like a revocation, never reviving the grant it displaced', !holders.includes(stranger))

// --- 7. nvoy_channel_reply with a mention: same allowlist and hourly budget as a post ---
const rf = fixture('replying', { may_post: mayPost })
mkdirSync(join(rf.state, 'receipts'), { recursive: true, mode: 0o700 })
const asked = (n, row, receipt = {}) => {
  const source = String(n).repeat(64)
  writeFileSync(join(rf.state, 'receipts', `${source}.json`), JSON.stringify({ version: 3, mode: 'buzz-native', instance: 'replying', broker: agent,
    envelope: source, sender: dennis, grant_id: live.id, grantor, cap: 'task', source_event: source, reply_channel: CH, reply_root: source,
    admitted_at: Date.now(), expires_at: Date.now() + 300000, ...receipt }), { mode: 0o600 })
  const id = String(n).repeat(32)
  writeFileSync(join(rf.run, 'reply-requests.jsonl'), JSON.stringify({ version: 1, type: 'reply-request', id, instance: 'replying', receipt: source, content: `reply ${n}`, ...row }) + '\n', { flag: 'a' })
  return { id, source }
}
const reply = (id, mode) => run(['mcp/tools/instance-broker-reply.mjs', '--instance', 'replying', '--request', id, mode],
  { NVOY_INSTANCE_ROOT: rf.root, NVOY_BROKER_CREDENTIAL: credential })
let a = asked(1, { mention: [stranger] })
r = await reply(a.id, '--prepare')
ok('the broker refuses an off-allowlist reply mention before claiming the receipt', r.status === 1 && /reply refused: [0-9a-f]{8} is not on may_post\.mention/.test(r.stderr) &&
  isTerminalReplyFailure(r.stderr) && existsSync(join(rf.state, 'receipts', `${a.source}.json`)))
a = asked(2, { mention: [neil] }, { reply_channel: CH2 })
r = await reply(a.id, '--prepare')
ok('the broker refuses a reply mention in a channel outside may_post', r.status === 1 && /reply refused: channel is not in may_post\.channels/.test(r.stderr))
a = asked(3, { mention: [neil] }, { version: 1, mode: undefined })
r = await reply(a.id, '--prepare')
ok('the broker refuses a mention on a wrapped reply', r.status === 1 && /mentions are only for a native Buzz channel reply/.test(r.stderr))
a = asked(4, { mention: [] })
r = await reply(a.id, '--prepare')
ok('the broker refuses an empty or malformed mention field', r.status === 1 && /invalid or overbroad/.test(r.stderr))
// Past these checks the broker needs a live grant chain on a wss relay, so the rest is pinned in its source.
const replySource = readFileSync('mcp/tools/instance-broker-reply.mjs', 'utf8')
const capAt = replySource.indexOf("countInWindow(resolve(manifest.stateDir, 'agent-limits', 'posts.json'), { key: 'post', id: requestId, limit: manifest.mayPost.perHour })")
ok('a reply mention spends the same per-request post counter, after the live grant recheck and before the receipt is claimed',
  capAt > replySource.indexOf("die('admission receipt no longer has a live matching grant chain')") && capAt < replySource.indexOf('renameSync(receiptBase, receiptInflight)'))
ok('the frozen reply carries the validated mention', /channelReply\(\{[^}]*mentions: request\.mention \|\| \[\] \}\)/.test(replySource))

buzz.close(); http.close(); grantRelay.close(); gHttp.close()
console.log(`\n${passes}/${passes + fails} passed`)
process.exit(fails ? 1 : 0)
