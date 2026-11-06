// Agents writing room-scoped Hive memory under their own key: the may_remember manifest block, the
// keyless memory_claim / memory_withdraw tools, and the broker actuator end to end against a
// Buzz-shaped relay that stores kind 30078 and answers an author + #d lookup.
import { WebSocketServer } from 'ws'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { nsecEncode } from 'nostr-tools/nip19'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'
import { capabilitySummary } from '../mcp/tools/agent_post.mjs'
import { memoryToolSpec, queueMemory } from '../mcp/tools/agent_memory.mjs'
import { HOUR_MS } from '../mcp/tools/agent_limits.mjs'
import { MAX_TTL_SEC, validateMemoryEvent } from '../mcp/tools/memory.mjs'
import { CODEX_CHANNEL_TOOLS } from '../mcp/tools/harness_session.mjs'

let fails = 0, passes = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passes++ : fails++ }
const throws = fn => { try { fn(); return '' } catch (e) { return e.message } }
const run = (args, env) => new Promise(resolve => {
  const child = spawn(process.execPath, args, { env: { PATH: process.env.PATH, ...env }, stdio: ['ignore', 'pipe', 'pipe'] })
  let stdout = '', stderr = ''
  child.stdout.on('data', c => { stdout += c }); child.stderr.on('data', c => { stderr += c })
  child.on('exit', status => resolve({ status, stdout, stderr }))
})

const ROOM = 'a8186b53-537d-46ad-a7e7-b6486c58970e', ROOM2 = '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d', OTHER = '00000000-0000-4000-8000-000000000000'
const agentSk = generateSecretKey(), agent = getPublicKey(agentSk)
const grantor = getPublicKey(generateSecretKey())
const tag = (ev, n) => ev?.tags.find(t => t[0] === n)?.[1]

// --- a Buzz-shaped relay: NIP-42 for the agent, events need an h tag, a kind 30078 lookup by author and #d ---
const stored = []
let failLookups = false
const lookups = []
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
      const ev = m[1]
      if (!(verifyEvent(ev) && tag(ev, 'challenge') === challenge && tag(ev, 'relay') === RELAY && ev.pubkey === agent)) return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted']))
      authed = ev.pubkey
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
    if (m[0] === 'EVENT') {
      const ev = m[1]
      if (!authed || ev.pubkey !== authed || ![5, 30078].includes(ev.kind) || !ev.tags.some(t => t[0] === 'h') || !verifyEvent(ev)) return ws.send(JSON.stringify(['OK', ev.id, false, 'restricted']))
      if (!stored.some(s => s.id === ev.id)) stored.push(ev)
      return ws.send(JSON.stringify(['OK', ev.id, true, '']))
    }
    if (m[0] === 'REQ') {
      const [, sub, f] = m
      lookups.push(f)
      if (failLookups) return ws.send(JSON.stringify(['CLOSED', sub, 'error: lookup unavailable']))
      const hits = stored.filter(ev => f.kinds.includes(ev.kind) && f.authors.includes(ev.pubkey) && f['#d'].includes(tag(ev, 'd')))
        .sort((a, b) => b.created_at - a.created_at).slice(0, f.limit)
      for (const ev of hits) ws.send(JSON.stringify(['EVENT', sub, ev]))
      return ws.send(JSON.stringify(['EOSE', sub]))
    }
  })
})

// --- manifests: one root per fixture, since the collision check reads every manifest beside it ---
const root = mkdtempSync(join(tmpdir(), 'nvoy-agent-memory-'))
const gid = process.getgid(), uid = process.getuid()
const base = id => ({ version: 1, id, pubkey: agent, broker_mode: 'local', key_ref: '/etc/nvoy/credentials/agent.nsec',
  worker_enabled: false, delivery_mode: 'notify_only',
  state_dir: join(root, id, 'state'), runtime_dir: join(root, id, 'run'), spool_dir: join(root, id, 'spool'),
  broker_adapter_gid: gid, worker_handoff_gid: gid + 1, watcher_uid: uid + 11, broker_uid: uid + 12, adapter_uid: uid + 13, worker_uid: uid + 14,
  grantors: [grantor], relays: ['wss://127.0.0.1:1'], buzz: { relay: RELAY, channels: [ROOM, ROOM2] } })
const fixture = (id, extra = {}, drop = []) => {
  const m = { ...base(id), ...extra }
  for (const key of drop) delete m[key]
  mkdirSync(join(root, id, 'instances'), { recursive: true })
  for (const d of ['state', 'run', 'spool']) mkdirSync(join(root, id, d), { recursive: true })
  writeFileSync(join(root, id, 'instances', `${id}.json`), JSON.stringify(m))
  return { root: join(root, id, 'instances'), load: () => readManifest(join(root, id, 'instances'), id), run: join(root, id, 'run'), state: join(root, id, 'state') }
}
const mayRemember = { rooms: [ROOM], per_hour: 3 }

// --- 1. manifest validation ---
const plain = fixture('plain').load()
ok('no may_remember means the identity may not write memory', plain.mayRemember === null)
const rememberer = fixture('rememberer', { may_remember: { rooms: [ROOM.toUpperCase()], per_hour: 6 } }).load()
ok('may_remember parses to lower-cased rooms and its hourly cap, frozen',
  rememberer.mayRemember.rooms.join() === ROOM && rememberer.mayRemember.perHour === 6 && Object.isFrozen(rememberer.mayRemember) && Object.isFrozen(rememberer.mayRemember.rooms))
const refused = (why, extra, pattern, drop) => ok(`the manifest is refused with ${why}`, pattern.test(throws(fixture(`r${passes + fails}`, extra, drop).load)))
refused('may_remember but no buzz block', { may_remember: mayRemember }, /may_remember requires a buzz block/, ['buzz'])
refused('a room outside buzz.channels', { may_remember: { ...mayRemember, rooms: [OTHER] } }, /may_remember\.rooms must be a subset of buzz\.channels/)
refused('no rooms', { may_remember: { ...mayRemember, rooms: [] } }, /distinct room UUIDs/)
refused('a duplicate room', { may_remember: { ...mayRemember, rooms: [ROOM, ROOM] } }, /distinct room UUIDs/)
refused('per_hour 0', { may_remember: { ...mayRemember, per_hour: 0 } }, /may_remember\.per_hour must be an integer from 1 to 30/)
refused('per_hour 31', { may_remember: { ...mayRemember, per_hour: 31 } }, /may_remember\.per_hour must be an integer from 1 to 30/)
refused('an unknown may_remember field', { may_remember: { ...mayRemember, scopes: ['hive:ops'] } }, /takes only rooms and per_hour/)
refused('may_remember on a headless worker manifest', { may_remember: mayRemember, delivery_mode: 'headless', worker_enabled: true,
  worker_image: `ghcr.io/x/w@sha256:${'a'.repeat(64)}`, worker_runner: 'codex', worker_credential_ref: '/etc/nvoy/w' }, /local-broker, worker-disabled notify_only/)

// --- 2. what the agent is told and offered ---
ok('an identity with may_remember is told its rooms and cap; one without is told the tools are refused',
  capabilitySummary(rememberer).includes(`memory_claim and memory_withdraw in room ${ROOM} (default ${ROOM}), at most 6 an hour`) &&
  capabilitySummary(plain).includes('not write memory: memory_claim and memory_withdraw are refused without may_remember'))
const claimSpec = memoryToolSpec(rememberer, 'claim'), withdrawSpec = memoryToolSpec(rememberer, 'withdraw')
ok('memory_claim reuses the memory.mjs schema, adds room, and needs no scope',
  claimSpec.name === 'memory_claim' && claimSpec.inputSchema.properties.room && claimSpec.inputSchema.properties.evidence.minItems === 1 &&
  claimSpec.inputSchema.required.join() === 'slug,claim,because,evidence' && claimSpec.inputSchema.additionalProperties === false &&
  /kind 30078/.test(claimSpec.description) && claimSpec.description.includes(ROOM))
ok('memory_withdraw takes a room, a slug and a reason', withdrawSpec.name === 'memory_withdraw' && withdrawSpec.inputSchema.required.join() === 'slug,because' &&
  /Refused: this identity may not write memory/.test(memoryToolSpec(plain, 'withdraw').description))
ok('the Codex harness pre-approves both memory tools', CODEX_CHANNEL_TOOLS.includes('memory_claim') && CODEX_CHANNEL_TOOLS.includes('memory_withdraw'))

// --- 3. the keyless tool's refusals ---
const claimArgs = { slug: 'review-rota', topic: 'rota', claim: 'Neil reviews infra PRs this week.', because: 'Agreed in the room on 11-05.',
  evidence: ['nvoy@f8b6a82:docs/BEESWARM.md'], as_of_git: 'nvoy@f8b6a82' }
ok('without may_remember the tool refuses', queueMemory(plain, 'claim', claimArgs).error?.code === 'NVOY_MEMORY_NOT_PERMITTED')
for (const scope of ['hive:ops', 'hive:canon', `self:${agent}`, 'room:not-a-uuid']) {
  const r = queueMemory(rememberer, 'claim', { ...claimArgs, scope })
  ok(`scope ${scope.slice(0, 12)} is refused: agents write room memory only`, r.error?.code === 'NVOY_MEMORY_SCOPE_REFUSED' && /only room:<uuid> scopes/.test(r.error.message))
}
ok('a room outside may_remember is refused', queueMemory(rememberer, 'claim', { ...claimArgs, room: ROOM2 }).error?.code === 'NVOY_MEMORY_ROOM_REFUSED')
ok('missing evidence is refused', /evidence is required/.test(queueMemory(rememberer, 'claim', { ...claimArgs, evidence: undefined }).error?.message || ''))
ok('a claim with no as_of anchor is refused by the memory builder', /as_of_git or as_of_evt/.test(queueMemory(rememberer, 'claim', { ...claimArgs, as_of_git: undefined }).error?.message || ''))
ok('a ttl past 30 days is refused', queueMemory(rememberer, 'claim', { ...claimArgs, ttl_sec: MAX_TTL_SEC + 1 }).error?.code === 'NVOY_BAD_MEMORY')
ok('a field the tool does not take is refused', /kind is not a memory_claim field/.test(queueMemory(rememberer, 'claim', { ...claimArgs, kind: 30079 }).error?.message || ''))

// --- 4. end to end: queue → broker → signed kind 30078 on the relay ---
const credential = join(root, 'agent.key'); writeFileSync(credential, Buffer.from(agentSk).toString('hex'), { mode: 0o600 })
const write = (f, id, request) => run(['mcp/tools/instance-broker-memory.mjs', '--instance', id, '--request', request],
  { NVOY_INSTANCE_ROOT: f.root, NVOY_BROKER_CREDENTIAL: credential })
const mf = fixture('memory', { may_remember: mayRemember }), mm = mf.load()
const queuePath = join(mf.run, 'memory-requests.jsonl')
ok('an unprovisioned memory queue is refused rather than created', queueMemory(mm, 'claim', claimArgs).error?.code === 'NVOY_MEMORY_QUEUE_FAILED' && !existsSync(queuePath))
writeFileSync(queuePath, '', { mode: 0o640 })
const leakedNsec = nsecEncode(generateSecretKey())
const leak = queueMemory(mm, 'claim', { ...claimArgs, because: `the key: ${leakedNsec}` })
ok('the tool withholds a claim carrying a credential, naming the pattern and not the value, and queues nothing',
  leak.error?.code === 'NVOY_WITHHELD_CREDENTIAL' && leak.error.message.includes('(a Nostr secret key)') && !JSON.stringify(leak).includes(leakedNsec) && readFileSync(queuePath, 'utf8') === '')
ok('the memory guard also withholds a relay URL in evidence', queueMemory(mm, 'claim', { ...claimArgs, evidence: ['wss://relay.example/x'] }).error?.code === 'NVOY_WITHHELD_CREDENTIAL')

const q1 = queueMemory(mm, 'claim', claimArgs)
ok('the tool queues a bounded request for the default room', q1.ok?.queued === true && q1.ok.scope === `room:${ROOM}` && q1.ok.d === `hive-memory:room:${ROOM}:review-rota`)
let r = await write(mf, 'memory', q1.ok.request)
const claim1 = stored.find(ev => ev.kind === 30078 && tag(ev, 'd') === q1.ok.d)
const body = claim1 ? JSON.parse(claim1.content) : {}
ok('the broker publishes it', r.status === 0 && !!claim1)
ok('the claim is a kind 30078 signed by the identity with d, h, s, topic, as_of_git and exp tags',
  claim1?.kind === 30078 && claim1.pubkey === agent && verifyEvent(claim1) && tag(claim1, 'h') === ROOM && tag(claim1, 's') === `room:${ROOM}` &&
  tag(claim1, 'topic') === 'rota' && tag(claim1, 'as_of_git') === 'nvoy@f8b6a82' && Number(tag(claim1, 'exp')) - claim1.created_at === 14 * 86400 &&
  Number(tag(claim1, 'exp')) <= claim1.created_at + MAX_TTL_SEC)
ok('its content is the claim, reason, evidence and active status, and it validates as Hive memory',
  body.claim === claimArgs.claim && body.because === claimArgs.because && body.evidence.join() === claimArgs.evidence.join() && body.status === 'active' &&
  validateMemoryEvent(claim1).ok)
ok('the broker looked up its own latest event at the fact key first', JSON.stringify(lookups[0]) === JSON.stringify({ kinds: [30078], authors: [agent], '#d': [q1.ok.d], limit: 1 }))
ok('the audit line names the event prefix and the room, never the words', r.stdout.includes(claim1?.id.slice(0, 12)) && r.stdout.includes(ROOM) && !r.stdout.includes('Neil'))
r = await write(mf, 'memory', q1.ok.request)
ok('a retry republishes nothing new', r.status === 0 && /"replay":true/.test(r.stdout) && stored.filter(ev => tag(ev, 'd') === q1.ok.d).length === 1)

// A claim later than the clock (another broker's, say) is still replaced by a strictly later one.
const future = queueMemory(mm, 'claim', { ...claimArgs, claim: 'Dennis reviews infra PRs this week.' })
const priorAt = claim1.created_at + 120
const ahead = finalizeEvent({ kind: 30078, created_at: priorAt, tags: claim1.tags, content: claim1.content }, agentSk)
stored.push(ahead)
r = await write(mf, 'memory', future.ok.request)
const claim2 = stored.find(ev => ev.kind === 30078 && JSON.parse(ev.content).claim?.startsWith('Dennis'))
ok('a replacement claim is created strictly after the prior event the relay returned', r.status === 0 && claim2?.created_at === priorAt + 1)
stored.splice(stored.indexOf(ahead), 1)

// --- 5. withdraw ---
failLookups = true
const w1 = queueMemory(mm, 'withdraw', { slug: 'review-rota', because: 'The rota changed.' })
const lookupsBefore = lookups.length
r = await write(mf, 'memory', w1.ok.request)
ok('a withdrawal that cannot look up its claim is held for retry, not guessed or refused for good',
  r.status === 1 && /cannot look up the claim to withdraw/.test(r.stderr) && /held for retry/.test(r.stderr) && !/memory refused/.test(r.stderr) &&
  lookups.length === lookupsBefore + 1 && !existsSync(join(mf.state, 'memory', `${w1.ok.request}.json`)))
failLookups = false
r = await write(mf, 'memory', w1.ok.request)
const withdrawal = stored.find(ev => ev.kind === 30078 && JSON.parse(ev.content).status === 'withdrawn')
const deletion = stored.find(ev => ev.kind === 5)
ok('the retry publishes a withdrawn replacement at the same fact key, strictly later than the claim',
  r.status === 0 && withdrawal && tag(withdrawal, 'd') === q1.ok.d && tag(withdrawal, 'h') === ROOM && withdrawal.created_at > claim2.created_at &&
  validateMemoryEvent(withdrawal).status === 'withdrawn')
ok('and the companion kind 5 deletes the claim it replaces, in the same room',
  deletion?.pubkey === agent && verifyEvent(deletion) && tag(deletion, 'e') === claim2.id && tag(deletion, 'a') === `30078:${agent}:${q1.ok.d}` &&
  tag(deletion, 'k') === '30078' && tag(deletion, 'h') === ROOM && /deletion accepted/.test(r.stdout))

// --- 6. the broker re-checks what the keyless side wrote ---
const forge = row => { writeFileSync(queuePath, readFileSync(queuePath, 'utf8') + JSON.stringify({ version: 1, type: 'memory-request', instance: 'memory', op: 'claim',
  scope: `room:${ROOM}`, fields: claimArgs, requested_at: Date.now() - 2 * HOUR_MS, ...row }) + '\n') }
const forged = async (name, n, row, pattern) => {
  forge({ id: n.repeat(32), ...row })
  const res = await write(mf, 'memory', n.repeat(32))
  ok(name, res.status === 1 && pattern.test(res.stderr) && !existsSync(join(mf.state, 'memory', `${n.repeat(32)}.json`)))
  return res
}
await forged('the broker refuses a hive:ops scope, whatever the keyless side wrote', 'a', { scope: 'hive:ops' }, /memory refused: only room:<uuid> scopes may be written by an agent; hive:ops is refused/)
await forged('the broker refuses a hive:canon scope', 'b', { scope: 'hive:canon' }, /memory refused: only room:<uuid> scopes/)
await forged('the broker refuses a self scope', 'c', { scope: `self:${agent}` }, /memory refused: only room:<uuid> scopes/)
await forged('the broker refuses a room outside may_remember', 'd', { scope: `room:${ROOM2}` }, /memory refused: room is not in may_remember\.rooms/)
const { evidence, ...noEvidence } = claimArgs
await forged('the broker refuses a claim without evidence', 'e', { fields: noEvidence }, /memory refused: evidence is required/)
await forged('the broker refuses a request carrying an extra field', '1', { event: { kind: 30079 } }, /invalid or overbroad shape/)
await forged('the broker refuses a raw tag smuggled into the fields', '2', { fields: { ...claimArgs, tags: [['h', OTHER]] } }, /memory refused: tags is not a memory_claim field/)
const secret = 'AK' + 'IA' + 'Q3ZT7RW2YX8V5N4M'
const s = await forged('the broker refuses a credential forged into the claim, without echoing it', '3', { fields: { ...claimArgs, claim: `use ${secret}` } },
  /memory refused: withheld: looks like a credential \(an AWS access key\)/)
ok('nothing carrying the forged credential reached the relay', !(s.stdout + s.stderr).includes(secret) && !stored.some(ev => ev.content.includes(secret)))
await forged('a withdrawal with no claim of this identity at the fact key is refused', '4', { op: 'withdraw', fields: { slug: 'never-claimed', because: 'x' } },
  /memory refused: no claim by this identity at hive-memory:room:[0-9a-f-]+:never-claimed to withdraw/)

// --- 7. the hourly cap: claim, replacement and withdrawal spent 3 of 3 ---
ok('the tool tells the agent at once when the hour is spent', queueMemory(mm, 'claim', { ...claimArgs, slug: 'fourth' }).error?.code === 'NVOY_MEMORY_RATE_LIMITED')
await forged('the broker\'s durable counter refuses a write over per_hour', '5', { fields: { ...claimArgs, slug: 'fourth' } }, /memory refused: over the hourly cap \(3\/3/)
ok('the counter lives in the broker state root', existsSync(join(mf.state, 'agent-limits', 'memory.json')))
ok('only kind 30078 and its kind 5 ever reached the relay', stored.every(ev => ev.kind === 30078 || ev.kind === 5) && stored.filter(ev => ev.kind === 30078).length === 3)

const nf = fixture('nomemory')
writeFileSync(join(nf.run, 'memory-requests.jsonl'), JSON.stringify({ version: 1, type: 'memory-request', id: '6'.repeat(32), instance: 'nomemory', op: 'claim',
  scope: `room:${ROOM}`, fields: claimArgs, requested_at: Date.now() }) + '\n')
r = await write(nf, 'nomemory', '6'.repeat(32))
ok('an identity without may_remember is refused by the broker', r.status === 1 && /memory refused: this identity may not write memory/.test(r.stderr))

buzz.close(); http.close()
console.log(`\n${passes} passed, ${fails} failed`)
process.exit(fails ? 1 : 0)
