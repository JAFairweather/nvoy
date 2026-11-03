// A mention right is a grant (waggle docs/DESIGN_MENTION_RIGHTS.md, step 1): a kind 440 with
// da-cap `mention` and a `name` tag, folded apart from who may task the agent, merged into
// may_post.mention without displacing an entry, enforced by the brokers on the live policy, and
// seen by the keyless channel MCPs through the snapshot the brokers record.
import { WebSocketServer } from 'ws'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { foldGrants, scopeHash } from '../mcp/tools/grant_fold.mjs'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'
import { capabilityHash, capabilitySummary, mentionView, mergeMentions, postToolSpec, readMentionGrants, recordMentionGrants, resolvePost,
  resolveReplyMention, validatePostRequest, validateReplyMention, withMentionGrants } from '../mcp/tools/agent_post.mjs'

let fails = 0, passes = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passes++ : fails++ }
const throws = fn => { try { fn(); return '' } catch (e) { return e.message } }
const sleep = ms => new Promise(r => setTimeout(r, ms))
const now = () => Math.floor(Date.now() / 1000)
const key = () => { const sk = generateSecretKey(); return { sk, pk: getPublicKey(sk) } }

const agentSk = generateSecretKey(), agent = getPublicKey(agentSk), other = getPublicKey(generateSecretKey())
const director = key(), voice = key(), stranger = key(), dennis = key().pk, neil = key().pk, kerouac = key().pk, mallory = key().pk
const grantors = [director.pk]
const salt = 'ef'.repeat(16)
const ev = (signer, kind, tags, at = now() - 100) => finalizeEvent({ kind, created_at: at, content: '', tags }, signer.sk)
const scoped = (signer, to, cap, { subject = agent, at, extra = [] } = {}) =>
  ev(signer, 440, [['p', to], ['da-scope', scopeHash(subject, salt), salt], ['da-cap', cap], ...extra], at)
const mention = (signer, to, name, opts = {}) => scoped(signer, to, 'mention', { ...opts, extra: [...(name == null ? [] : [['name', name]]), ...(opts.extra || [])] })
const revoke = (signer, id, at = now() - 50) => ev(signer, 441, [['e', id]], at)
const fold = events => foldGrants(events, { me: agent, grantors })
const held = (r, pk) => r.mentions.filter(g => g.pubkey === pk)
const has = (r, pk) => held(r, pk).length > 0

// --- 1. the fold ---
const right = mention(director, kerouac, 'kerouac')
let r = fold([right])
ok('a mention grant folds into mentions, with its name, id, grantor and time', JSON.stringify(r.mentions) ===
  JSON.stringify([{ pubkey: kerouac, name: 'kerouac', grantId: right.id, grantor: director.pk, created_at: right.created_at }]))
ok('a mention grant is never a grant to task the agent', !r.live.has(kerouac) && r.live.size === 0 && r.ended.size === 0)
r = fold([right, revoke(director, right.id)])
ok('a 441 ends it', !has(r, kerouac) && !r.live.has(kerouac))
ok('an expiry ends it', !has(fold([mention(director, kerouac, 'kerouac', { extra: [['expiration', String(now() - 1)]] })]), kerouac))
ok('a later expiry is live', has(fold([mention(director, kerouac, 'kerouac', { extra: [['expiration', String(now() + 3600)]] })]), kerouac))
ok('a non-grantor\'s mention grant counts for nothing', !fold([mention(stranger, kerouac, 'kerouac')]).mentions.length)
ok('a mention grant scoped to another agent is ignored', !fold([mention(director, kerouac, 'kerouac', { subject: other })]).mentions.length)
ok('a mention grant with no name, or one the manifest would refuse, is ignored',
  [null, '', '-kerouac', '.k', 'ker ouac', 'ker@ouac', 'k'.repeat(33)].every(name => !fold([mention(director, kerouac, name)]).mentions.length) &&
  ['k'.repeat(32), 'Kerouac', 'jack.k', 'jack_k', 'jack-k'].every(name => has(fold([mention(director, kerouac, name)]), kerouac)))
ok('a mention grant for a key that is not 64 hex is ignored', !fold([mention(director, 'kerouac', 'kerouac')]).mentions.length)
const forged = JSON.parse(JSON.stringify({ ...right, tags: [['p', mallory], ...right.tags.slice(1)] }))
r = fold([forged])
ok('a mention grant whose signature does not cover its tags is rejected', !r.mentions.length && r.rejected === 1)
const renamed = mention(director, kerouac, 'jack', { at: now() - 60 })
r = fold([renamed, right])
ok('every live mention grant is kept, oldest first', r.mentions.map(g => g.grantId).join() === [right.id, renamed.id].join())
r = fold([right, renamed, revoke(director, right.id, now() - 40)])
ok('a 441 ends only the grant it names', r.mentions.map(g => g.grantId).join() === renamed.id)
const twin = [mention(director, kerouac, 'a1', { at: now() - 70 }), mention(director, kerouac, 'a2', { at: now() - 70 })]
ok('grants of the same second are ordered by id', fold([...twin].reverse()).mentions.map(g => g.grantId).join() === twin.map(e => e.id).sort().join())
const own = scoped(director, director.pk, 'task+act'), sh = scoped(director, voice.pk, 'shadow', { subject: director.pk })
r = fold([own, sh, mention(director, director.pk, 'director')])
ok('a shadow voice inherits task grants but no mention grant', r.live.get(voice.pk)?.get('task+act')?.shadow === true &&
  has(r, director.pk) && !has(r, voice.pk) && ![...r.live.values()].some(caps => caps.has('mention')))
ok('a task grant is not a mention right', !fold([scoped(director, kerouac, 'task')]).mentions.length)

// --- 2. attention --policy-only reports them apart from grants ---
const relayEvents = [own, right, mention(director, mallory, 'mallory'), revoke(director, scoped(director, neil, 'mention').id)]
const revokedRight = mention(director, neil, 'neil-two'); relayEvents.push(revokedRight, revoke(director, revokedRight.id))
const http = createServer((req, res) => { res.writeHead(404); res.end() })
await new Promise(res => http.listen(0, '127.0.0.1', res))
const relay = new WebSocketServer({ server: http })
relay.on('connection', ws => ws.on('message', raw => {
  const m = JSON.parse(raw.toString())
  if (m[0] !== 'REQ') return
  for (const e of relayEvents) if (m[2].kinds.includes(e.kind) && m[2].authors.includes(e.pubkey)) ws.send(JSON.stringify(['EVENT', m[1], e]))
  ws.send(JSON.stringify(['EOSE', m[1]]))
}))
const root = mkdtempSync(join(tmpdir(), 'nvoy-mention-grants-')); mkdirSync(join(root, 'home'))
const out = await new Promise(done => {
  const child = spawn(process.execPath, ['mcp/tools/attention.mjs', '--policy-only'], { stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH, HOME: join(root, 'home'), NVOY_NSEC: Buffer.from(agentSk).toString('hex'),
      GRANTORS: grantors.join(','), NVOY_RELAYS: `ws://127.0.0.1:${http.address().port}` } })
  let stdout = ''; child.stdout.on('data', c => { stdout += c }); child.on('exit', status => done({ status, stdout }))
})
let policy = {}; try { policy = JSON.parse(out.stdout) } catch { /* reported below */ }
ok('attention lists live mention grants under mentions', out.status === 0 && policy.policyUsable === true &&
  JSON.stringify((policy.mentions || []).map(m => [m.pubkey, m.name, m.grant_id, m.grantor, m.created_at]).sort()) ===
  JSON.stringify([[kerouac, 'kerouac', right.id, director.pk, right.created_at], [mallory, 'mallory', relayEvents[2].id, director.pk, relayEvents[2].created_at]].sort()))
ok('and never under grants', (policy.grants || []).every(g => g.pubkey === director.pk && g.cap === 'task+act'))
relay.close(); http.close()

// --- 3. the effective mention list ---
const CH = '3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607'
const fixture = (id, extra = {}) => {
  const dir = join(root, id)
  for (const d of ['instances', 'state', 'run', 'spool']) mkdirSync(join(dir, d), { recursive: true })
  const m = { version: 1, id, pubkey: agent, broker_mode: 'local', key_ref: '/etc/nvoy/credentials/agent.nsec',
    worker_enabled: false, delivery_mode: 'notify_only', state_dir: join(dir, 'state'), runtime_dir: join(dir, 'run'), spool_dir: join(dir, 'spool'),
    broker_adapter_gid: process.getgid(), worker_handoff_gid: process.getgid() + 1, watcher_uid: process.getuid() + 11, broker_uid: process.getuid() + 12,
    adapter_uid: process.getuid() + 13, worker_uid: process.getuid(), grantors, relays: ['wss://127.0.0.1:1'],
    buzz: { relay: 'wss://buzz.example', channels: [CH] }, ...extra }
  writeFileSync(join(dir, 'instances', `${id}.json`), JSON.stringify(m))
  return { root: join(dir, 'instances'), run: join(dir, 'run'), load: () => readManifest(join(dir, 'instances'), id) }
}
const pf = fixture('poster', { may_post: { channels: [CH], per_hour: 5, mention: [dennis, { name: 'neil', pubkey: neil }] } })
const poster = pf.load(), plain = fixture('plain').load()
const hex = n => n.toString(16).padStart(64, '0')
const grant = (pubkey, name, n = 1, at = 1000 + n) => ({ pubkey, name, grant_id: hex(n), grantor: director.pk, created_at: at })
const logged = []
const { mention: list, refused } = mergeMentions(poster.mayPost.mention, [grant(stranger.pk, 'kerouac', 7, 1005), grant(kerouac, 'kerouac', 3, 1003),
  grant(neil, 'neil-again', 4), grant(dennis, 'dennis', 5), grant(mallory, 'N-e-i-l', 6), grant(kerouac, 'jack', 9),
  grant('zz', 'zz', 10), grant(other, '-bad', 11), { ...grant(other, 'other', 12), created_at: 'soon' }], line => logged.push(line))
const merged = withMentionGrants(poster, [grant(kerouac, 'kerouac', 3)])
ok('the manifest\'s entries come first, in manifest order, then grants by (created_at, id)', list.map(e => e.pubkey).join() === [dennis, neil, kerouac].join())
ok('a grant for a listed key attaches its id and keeps the name: no alias', list[0].name === null && list[0].grants.join() === hex(5) &&
  list[1].name === 'neil' && list[1].grants.join() === hex(4) && list[2].name === 'kerouac' && list[2].grants.join() === [hex(3), hex(9)].join())
ok('a name another key holds, under the resolver\'s fold, is refused and its key gains nothing',
  !list.some(e => [mallory, stranger.pk].includes(e.pubkey)) && JSON.stringify(refused.map(x => x.grant_id)) === JSON.stringify([hex(7), hex(6)]))
ok('each refusal says why, and is logged with the grant id prefix', refused[0].reason.includes(kerouac.slice(0, 8)) && refused[1].reason.includes(neil.slice(0, 8)) &&
  logged.length === 2 && logged[0].includes(hex(7).slice(0, 12)) && logged[1].includes(hex(6).slice(0, 12)))
ok('a refused grant\'s key is not mentionable even by hex', resolvePost(withMentionGrants(poster, [grant(mallory, 'neil', 6)], () => {}), { text: 'hi', mention: [mallory] }).code === 'NVOY_POST_MENTION_REFUSED')
ok('a malformed grant row adds nothing', !list.some(e => ['zz', other].includes(e.pubkey)))
ok('revoking the earlier holder of a name gives it to the next grant, recomputed from scratch',
  mergeMentions(poster.mayPost.mention, [grant(stranger.pk, 'kerouac', 7, 1005)], () => {}).mention.at(-1)?.pubkey === stranger.pk)
ok('the manifest itself is unchanged', poster.mayPost.mention.length === 2 && !('grants' in poster.mayPost.mention[0]) && Object.isFrozen(merged.mayPost.mention))
ok('no grants return the manifest as it was', withMentionGrants(poster, []) === poster)

ok('before the grant, a post mentioning the key is refused', resolvePost(poster, { text: 'hi', mention: ['kerouac'] }).code === 'NVOY_POST_MENTION_REFUSED' &&
  resolvePost(poster, { text: 'hi', mention: [kerouac] }).code === 'NVOY_POST_MENTION_REFUSED')
ok('after it, the post resolves the name, the key and an @name in the text', resolvePost(merged, { text: 'hi', mention: ['Kerouac'] }).mention?.join() === kerouac &&
  resolvePost(merged, { text: 'hi', mention: [kerouac] }).mention?.join() === kerouac && resolvePost(merged, { text: 'over to @kerouac' }).mention?.join() === kerouac)
ok('before the grant, a reply mention is refused; after it, accepted', resolveReplyMention(poster, ['kerouac']).code === 'NVOY_REPLY_MENTION_REFUSED' &&
  resolveReplyMention(merged, ['kerouac']).mention?.join() === kerouac)
const row = { version: 1, type: 'post-request', id: 'd'.repeat(32), instance: 'poster', channel: CH, mention: [kerouac], content: 'hi', requested_at: Date.now() }
ok('the post broker\'s check refuses the key on the manifest alone and accepts it on the merged list',
  /post refused: [0-9a-f]{8} is not on may_post\.mention/.test(throws(() => validatePostRequest(row, poster))) && throws(() => validatePostRequest(row, merged)) === '')
ok('the reply broker\'s check does the same', /reply refused: [0-9a-f]{8} is not on may_post\.mention/.test(throws(() => validateReplyMention([kerouac], poster, CH))) &&
  throws(() => validateReplyMention([kerouac], merged, CH)) === '')
ok('a mention grant never grants posting: without may_post nothing changes',
  withMentionGrants(plain, [grant(kerouac, 'kerouac')]) === plain && resolvePost(plain, { text: 'hi', mention: ['kerouac'] }).code === 'NVOY_POST_NOT_PERMITTED' &&
  resolveReplyMention(plain, ['kerouac']).code === 'NVOY_REPLY_MENTION_NOT_PERMITTED' && /may only reply/.test(throws(() => validatePostRequest({ ...row, instance: 'plain' }, plain))))
ok('the agent is told: the summary and the post tool name the granted key, and the capability hash moves',
  capabilitySummary(merged).includes('neil, kerouac') && postToolSpec(merged).description.includes('kerouac') &&
  capabilityHash(capabilitySummary(merged)) !== capabilityHash(capabilitySummary(poster)))

// --- 4. the snapshot the brokers record for the keyless MCPs ---
const snap = join(pf.run, 'mention-grants.json')
const usable = { me: agent, policyUsable: true, mentions: [grant(kerouac, 'kerouac', 3)] }
recordMentionGrants(poster, usable)
ok('an unprovisioned snapshot is not created', readMentionGrants(poster) === null && throws(() => readFileSync(snap)) !== '')
writeFileSync(snap, '', { mode: 0o640 })
const view = mentionView(poster)
ok('a provisioned but empty snapshot reads as no grants yet', view() === poster)
recordMentionGrants(poster, usable)
ok('a usable policy is recorded', JSON.stringify(readMentionGrants(poster)) === JSON.stringify(usable.mentions))
ok('and the view merges it', view().mayPost.mention.at(-1)?.pubkey === kerouac)
recordMentionGrants(poster, { ...usable, policyUsable: false, mentions: [] })
recordMentionGrants(poster, { ...usable, me: other, mentions: [] })
recordMentionGrants(plain, usable)
ok('an unusable policy, another identity\'s, or a reply-only manifest records nothing', readMentionGrants(poster)?.length === 1)
recordMentionGrants(poster, { ...usable, mentions: [] })
ok('a revocation empties it, and the view follows', readMentionGrants(poster)?.length === 0 && view() === poster)
recordMentionGrants(poster, usable); view()
writeFileSync(snap, '{"version":1,')
ok('a snapshot caught mid-rewrite keeps the last good reading', view().mayPost.mention.at(-1)?.pubkey === kerouac)
const elsewhere = join(root, 'elsewhere.json'); writeFileSync(elsewhere, 'untouched')
const lf = fixture('linked', { may_post: { channels: [CH], per_hour: 5 } }), linked = lf.load()
symlinkSync(elsewhere, join(lf.run, 'mention-grants.json'))
recordMentionGrants(linked, usable)
ok('the broker never writes through a symlink', readFileSync(elsewhere, 'utf8') === 'untouched')

// --- 5. the brokers enforce on the live policy (a wss grant relay is out of reach here, so pinned in source) ---
const replySource = readFileSync('mcp/tools/instance-broker-reply.mjs', 'utf8')
const merge = replySource.indexOf('validateReplyMention(request.mention, withMentionGrants(manifest, policy.mentions), receipt.reply_channel)')
ok('the reply broker checks mention keys on the live merged list, after the live recheck and before the post counter',
  merge > replySource.indexOf("die('admission receipt no longer has a live matching grant chain')") &&
  merge < replySource.indexOf("countInWindow(resolve(manifest.stateDir, 'agent-limits', 'posts.json')") &&
  !/validateReplyMention\(request\.mention, manifest,/.test(replySource))
const postSource = readFileSync('mcp/tools/instance-broker-post.mjs', 'utf8')
ok('the post broker validates against the merged list from a usable live policy',
  /allowed = withMentionGrants\(manifest, policy\.mentions\)/.test(postSource) && /validatePostRequest\(request, allowed\)/.test(postSource) &&
  postSource.indexOf("policy.policyUsable !== true) die('live mention grants are unavailable; held for retry')") < postSource.indexOf('allowed = withMentionGrants'))
const nativeSource = readFileSync('mcp/tools/instance-broker-native.mjs', 'utf8')
ok('the native broker records the live mention grants on every usable policy, before the grant verdict',
  nativeSource.indexOf('recordMentionGrants(manifest, policy)') > nativeSource.indexOf('if (!policy.policyUsable) requeue(') &&
  nativeSource.indexOf('recordMentionGrants(manifest, policy)') < nativeSource.indexOf('const grant = nativeGrant('))
ok('init provisions the snapshot broker-owned and worker-group readable, only for may_post',
  /if \(m\.mayPost\) provisionFile\(`\$\{m\.runtimeDir\}\/mention-grants\.json`, m\.brokerUid, m\.workerHandoffGid, 0o640/.test(readFileSync('mcp/tools/instance-runtime-init.mjs', 'utf8')))

// --- 6. the Claude channel sees a grant recorded while it runs, and tells the agent once ---
const cf = fixture('channel', { may_post: { channels: [CH], per_hour: 5, mention: [{ name: 'neil', pubkey: neil }] } }), channel = cf.load()
for (const f of ['admitted-tasks.jsonl', 'reply-requests.jsonl', 'post-requests.jsonl', 'mention-grants.json']) writeFileSync(join(cf.run, f), '', { mode: 0o640 })
mkdirSync(join(cf.run, 'claude-channel-state'))
const child = spawn(process.execPath, [resolve('mcp/tools/claude-channel.mjs'), '--instance', 'channel', '--poll-ms', '250', '--renotify-ms', '60000'],
  { env: { ...process.env, NVOY_INSTANCE_ROOT: cf.root }, stdio: ['pipe', 'pipe', 'pipe'] })
const notices = [], results = new Map()
let buf = ''
child.stdout.on('data', d => {
  buf += d
  const lines = buf.split('\n'); buf = lines.pop()
  for (const line of lines) {
    let m; try { m = JSON.parse(line) } catch { continue }
    if (m.method === 'notifications/claude/channel' && m.params?.meta?.capabilities) notices.push(m.params)
    if (m.id != null) results.set(m.id, m.result)
  }
})
const say = frame => child.stdin.write(JSON.stringify(frame) + '\n')
const call = async (id, name, args) => { say({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }); for (let i = 0; i < 40 && !results.has(id); i++) await sleep(50); return JSON.parse(results.get(id)?.content?.[0]?.text || '{}') }
try {
  say({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'mention-test', version: '0' } } })
  await sleep(300)
  say({ jsonrpc: '2.0', method: 'notifications/initialized' })
  await sleep(800)
  ok('a new session is told its capabilities, without the ungranted key', notices.length === 1 && notices[0].content.includes('neil') && !notices[0].content.includes('kerouac'))
  ok('before the grant, the channel refuses the post', (await call(2, 'nvoy_channel_post', { text: 'hi', mention: ['kerouac'] })).code === 'NVOY_POST_MENTION_REFUSED')
  recordMentionGrants(channel, usable)
  await sleep(800)
  ok('a grant recorded while it runs is told once, naming the key, under a new hash', notices.length === 2 &&
    notices[1].content.includes('neil, kerouac') && notices[1].meta.capabilities !== notices[0].meta.capabilities)
  const queued = await call(3, 'nvoy_channel_post', { text: 'hi @kerouac' })
  ok('after the grant, the same post is queued with the key', queued.queued === true && queued.mention?.join() === kerouac &&
    JSON.parse(readFileSync(join(cf.run, 'post-requests.jsonl'), 'utf8').trim()).mention.join() === kerouac)
  await sleep(500)
  ok('and the agent, having called a tool, is not told again', notices.length === 2 &&
    JSON.parse(readFileSync(join(cf.run, 'claude-channel-state', 'capabilities.json'), 'utf8')).hash === notices[1].meta.capabilities)
  recordMentionGrants(channel, { ...usable, mentions: [] })
  await sleep(800)
  ok('a revocation is told too, and the post is refused again', notices.length === 3 && !notices[2].content.includes('kerouac') &&
    (await call(4, 'nvoy_channel_post', { text: 'hi', mention: ['kerouac'] })).code === 'NVOY_POST_MENTION_REFUSED')
} finally { child.kill('SIGKILL') }

// --- 7. the Codex channel resolves against the same snapshot on every call ---
const xf = fixture('codex', { may_post: { channels: [CH], per_hour: 5, mention: [{ name: 'neil', pubkey: neil }] } }), codex = xf.load()
for (const f of ['admitted-tasks.jsonl', 'reply-requests.jsonl', 'post-requests.jsonl', 'mention-grants.json']) writeFileSync(join(xf.run, f), '', { mode: 0o640 })
mkdirSync(join(xf.run, 'codex-mcp-state'))
const client = new Client({ name: 'mention-test', version: '0.1.0' })
await client.connect(new StdioClientTransport({ command: process.execPath, args: [resolve('mcp/tools/codex-channel-mcp.mjs'), '--instance', 'codex'],
  env: { ...process.env, NVOY_INSTANCE_ROOT: xf.root }, stderr: 'pipe' }))
try {
  const before = await client.callTool({ name: 'nvoy_channel_post', arguments: { text: 'hi', mention: ['kerouac'] } })
  recordMentionGrants(codex, usable)
  const spec = (await client.listTools()).tools.find(t => t.name === 'nvoy_channel_post')
  const after = await client.callTool({ name: 'nvoy_channel_post', arguments: { text: 'hi', mention: ['kerouac'] } })
  ok('the Codex post is refused before the grant and queued after it, and its tool lists the key',
    before.isError === true && JSON.parse(before.content[0].text).code === 'NVOY_POST_MENTION_REFUSED' &&
    !after.isError && JSON.parse(after.content[0].text).mention?.join() === kerouac && spec.description.includes('kerouac'))
} finally { await client.close() }

console.log(fails ? `\n${fails} FAILED` : `\nmention-grants: all ${passes} passed`)
process.exit(fails ? 1 : 0)
