// Agents writing room-scoped Hive memory under their own key: the may_remember manifest block, the
// keyless memory_claim / memory_withdraw tools and their per-request spool, and the broker actuator
// end to end against the private Hive memory store's writer socket. No relay is involved.
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { nsecEncode } from 'nostr-tools/nip19'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'
import { capabilitySummary } from '../mcp/tools/agent_post.mjs'
import { memoryTemplates, memoryToolSpec, queueMemory } from '../mcp/tools/agent_memory.mjs'
import { HOUR_MS } from '../mcp/tools/agent_limits.mjs'
import { replyRequestDigest } from '../mcp/tools/outbound_record.mjs'
import { MAX_TTL_SEC, validateMemoryEvent } from '../mcp/tools/memory.mjs'
import { initEmptyStore, recordVerifiedBackup, validateAndResolveConfig } from '../mcp/tools/hive_memory_store.mjs'
import { startMemoryDaemon } from '../mcp/tools/memory-daemon.mjs'
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
const owner = getPublicKey(generateSecretKey()), grantor = getPublicKey(generateSecretKey())
const tag = (ev, n) => ev?.tags.find(t => t[0] === n)?.[1]

// --- the private store: the agent may write ROOM only; ROOM2 is in its manifest but not in the store ACL ---
const root = mkdtempSync(join(tmpdir(), 'am-'))
const storeDir = join(root, 'store'), sockDir = join(root, 's')
mkdirSync(storeDir)
const store = { db: join(storeDir, 'memory.sqlite'), ledger: join(storeDir, 'ledger.jsonl'), receipt: join(storeDir, 'receipt.json') }
const storeConfig = {
  memoryGlobalChannelId: '11111111-2222-4333-8444-555555555555',
  ownerPubkey: owner,
  maxUnbackedSec: 3600,
  globalWriters: [],
  readers: { owner },
  writers: { agent: { pubkey: agent, perHour: 100 } },
  rooms: { [ROOM]: { members: [agent, owner], writers: [agent] }, [ROOM2]: { members: [agent, owner], writers: [] } },
}
validateAndResolveConfig(storeConfig)
initEmptyStore({ dbPath: store.db, ledgerPath: store.ledger })
recordVerifiedBackup({ receiptPath: store.receipt, writeSeq: 1, at: Math.floor(Date.now() / 1000) })
const daemon = await startMemoryDaemon({ dbPath: store.db, ledgerPath: store.ledger, receiptPath: store.receipt, config: storeConfig, socketDir: sockDir,
  readers: 'owner', writers: 'agent', log: () => {} })
const writerSocket = join(sockDir, 'writers', 'agent.sock')
const stored = d => daemon.store.db.prepare('SELECT raw_json FROM events WHERE d = ? ORDER BY created_at').all(d).map(r => JSON.parse(r.raw_json))
const allStored = () => daemon.store.db.prepare('SELECT raw_json FROM events').all().map(r => JSON.parse(r.raw_json))

// --- manifests: one root per fixture, since the collision check reads every manifest beside it ---
const gid = process.getgid(), uid = process.getuid()
const base = id => ({ version: 1, id, pubkey: agent, broker_mode: 'local', key_ref: '/etc/nvoy/credentials/agent.nsec',
  worker_enabled: false, delivery_mode: 'notify_only',
  state_dir: join(root, id, 'state'), runtime_dir: join(root, id, 'run'), spool_dir: join(root, id, 'spool'),
  broker_adapter_gid: gid, worker_handoff_gid: gid + 1, watcher_uid: uid + 11, broker_uid: uid + 12, adapter_uid: uid + 13, worker_uid: uid + 14,
  grantors: [grantor], relays: ['wss://127.0.0.1:1'], buzz: { relay: 'wss://127.0.0.1:1', channels: [ROOM, ROOM2] } })
const fixture = (id, extra = {}, drop = []) => {
  const m = { ...base(id), ...extra }
  for (const key of drop) delete m[key]
  mkdirSync(join(root, id, 'instances'), { recursive: true })
  for (const d of ['state', 'run', 'spool']) mkdirSync(join(root, id, d), { recursive: true })
  writeFileSync(join(root, id, 'instances', `${id}.json`), JSON.stringify(m))
  return { root: join(root, id, 'instances'), load: () => readManifest(join(root, id, 'instances'), id), run: join(root, id, 'run'), state: join(root, id, 'state') }
}
const provisionSpool = f => { mkdirSync(join(f.run, 'memory-requests'), { mode: 0o2770 }); writeFileSync(join(f.run, 'memory-rate.jsonl'), '', { mode: 0o600 }) }
const submit = { socket: writerSocket }
const mayRemember = { rooms: [ROOM], per_hour: 3, submit }

// --- 1. manifest validation ---
const plain = fixture('plain').load()
ok('no may_remember means the identity may not write memory', plain.mayRemember === null)
const rememberer = fixture('rememberer', { may_remember: { rooms: [ROOM.toUpperCase()], per_hour: 6, submit } }).load()
ok('may_remember parses to lower-cased rooms, its hourly cap and its writer transport, frozen',
  rememberer.mayRemember.rooms.join() === ROOM && rememberer.mayRemember.perHour === 6 && rememberer.mayRemember.submit.socket === writerSocket &&
  Object.isFrozen(rememberer.mayRemember) && Object.isFrozen(rememberer.mayRemember.rooms))
const refused = (why, extra, pattern, drop) => ok(`the manifest is refused with ${why}`, pattern.test(throws(fixture(`r${passes + fails}`, extra, drop).load)))
refused('may_remember but no buzz block', { may_remember: mayRemember }, /may_remember requires a buzz block/, ['buzz'])
refused('a room outside buzz.channels', { may_remember: { ...mayRemember, rooms: [OTHER] } }, /may_remember\.rooms must be a subset of buzz\.channels/)
refused('no rooms', { may_remember: { ...mayRemember, rooms: [] } }, /distinct room UUIDs/)
refused('a duplicate room', { may_remember: { ...mayRemember, rooms: [ROOM, ROOM] } }, /distinct room UUIDs/)
refused('per_hour 0', { may_remember: { ...mayRemember, per_hour: 0 } }, /may_remember\.per_hour must be an integer from 1 to 30/)
refused('per_hour 31', { may_remember: { ...mayRemember, per_hour: 31 } }, /may_remember\.per_hour must be an integer from 1 to 30/)
refused('an unknown may_remember field', { may_remember: { ...mayRemember, scopes: ['hive:ops'] } }, /takes only rooms, per_hour and submit/)
refused('no writer transport', { may_remember: { rooms: [ROOM], per_hour: 3 } }, /may_remember\.submit takes exactly one of socket/)
refused('a relative writer socket', { may_remember: { ...mayRemember, submit: { socket: 'writers/agent.sock' } } }, /may_remember\.submit takes exactly one of socket/)
refused('both a socket and a command', { may_remember: { ...mayRemember, submit: { socket: writerSocket, command: [process.execPath] } } }, /may_remember\.submit takes exactly one of socket/)
refused('a relative bridge command', { may_remember: { ...mayRemember, submit: { command: ['ssh', 'herd-cloud'] } } }, /may_remember\.submit takes exactly one of socket/)
refused('may_remember on a headless worker manifest', { may_remember: mayRemember, delivery_mode: 'headless', worker_enabled: true,
  worker_image: `ghcr.io/x/w@sha256:${'a'.repeat(64)}`, worker_runner: 'codex', worker_credential_ref: '/etc/nvoy/w' }, /local-broker, worker-disabled notify_only/)

// --- 2. what the agent is told and offered ---
ok('an identity with may_remember is told its rooms and cap; one without is told the tools are refused',
  capabilitySummary(rememberer).includes(`memory_claim and memory_withdraw in room ${ROOM} (default ${ROOM}), at most 6 an hour`) &&
  capabilitySummary(plain).includes('not write memory: memory_claim and memory_withdraw are refused without may_remember'))
const claimSpec = memoryToolSpec(rememberer, 'claim'), withdrawSpec = memoryToolSpec(rememberer, 'withdraw')
ok('memory_claim reuses the memory.mjs schema, adds room, needs no scope, and says it never goes to a relay',
  claimSpec.name === 'memory_claim' && claimSpec.inputSchema.properties.room && claimSpec.inputSchema.properties.evidence.minItems === 1 &&
  claimSpec.inputSchema.required.includes('slug') && !claimSpec.inputSchema.required.includes('scope') && claimSpec.inputSchema.additionalProperties === false &&
  /kind 30078/.test(claimSpec.description) && /never to a relay/.test(claimSpec.description) && claimSpec.description.includes(ROOM))
ok('memory_withdraw takes a room, a slug and a reason', withdrawSpec.name === 'memory_withdraw' && withdrawSpec.inputSchema.required.join() === 'slug,because' &&
  /Refused: this identity may not write memory/.test(memoryToolSpec(plain, 'withdraw').description))
ok('the claim tool and its ttl_sec field tell the agent the two retention classes: 0 for a durable decision, 1..2592000 for an expiring status',
  /0 for a Class B durable decision/.test(claimSpec.description) && /1\.\.2592000/.test(claimSpec.description) &&
  /0: Class B durable decision/.test(claimSpec.inputSchema.properties.ttl_sec.description) && claimSpec.inputSchema.properties.ttl_sec.minimum === 0 &&
  claimSpec.inputSchema.properties.ttl_sec.maximum === MAX_TTL_SEC && !!claimSpec.inputSchema.properties.topic.description)
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
const decision = queueMemory(rememberer, 'claim', { ...claimArgs, ttl_sec: 0 })
ok('ttl_sec 0 passes the tool\'s field check (it fails only later, on the unprovisioned spool)', decision.error?.code === 'NVOY_MEMORY_QUEUE_FAILED')

// --- 4. end to end: spool → broker → signed kind 30078 in the private store ---
const credential = join(root, 'agent.key'); writeFileSync(credential, Buffer.from(agentSk).toString('hex'), { mode: 0o600 })
const write = (f, id, request) => run(['mcp/tools/instance-broker-memory.mjs', '--instance', id, '--request', request],
  { NVOY_INSTANCE_ROOT: f.root, NVOY_BROKER_CREDENTIAL: credential })
const mf = fixture('memory', { may_remember: mayRemember }), mm = mf.load()
const spool = join(mf.run, 'memory-requests'), ratePath = join(mf.run, 'memory-rate.jsonl')
const spoolFile = id => join(spool, `${id}.json`), recordFile = id => join(mf.state, 'memory', `${id}.json`)
ok('an unprovisioned memory spool is refused rather than created', queueMemory(mm, 'claim', claimArgs).error?.code === 'NVOY_MEMORY_QUEUE_FAILED' && !existsSync(spool))
provisionSpool(mf)
const leakedNsec = nsecEncode(generateSecretKey())
const leak = queueMemory(mm, 'claim', { ...claimArgs, because: `the key: ${leakedNsec}` })
ok('the tool withholds a claim carrying a credential, naming the pattern and not the value, and spools nothing',
  leak.error?.code === 'NVOY_WITHHELD_CREDENTIAL' && leak.error.message.includes('(a Nostr secret key)') && !JSON.stringify(leak).includes(leakedNsec) &&
  readdirSync(spool).length === 0 && readFileSync(ratePath, 'utf8') === '')
ok('the memory guard also withholds a relay URL in evidence', queueMemory(mm, 'claim', { ...claimArgs, evidence: ['wss://relay.example/x'] }).error?.code === 'NVOY_WITHHELD_CREDENTIAL')

const q1 = queueMemory(mm, 'claim', claimArgs)
const spooled = existsSync(spoolFile(q1.ok?.request)) ? JSON.parse(readFileSync(spoolFile(q1.ok.request), 'utf8')) : null
ok('the tool spools one bounded request file for the default room', q1.ok?.queued === true && q1.ok.scope === `room:${ROOM}` &&
  q1.ok.d === `hive-memory:room:${ROOM}:review-rota` && spooled?.id === q1.ok.request && spooled.fields.claim === claimArgs.claim &&
  readdirSync(spool).join() === `${q1.ok.request}.json`)
ok('the rate log holds the id and time only, never the words',
  readFileSync(ratePath, 'utf8').trim() === JSON.stringify({ id: q1.ok.request, requested_at: spooled?.requested_at }))
let r = await write(mf, 'memory', q1.ok.request)
const claim1 = stored(q1.ok.d)[0]
const body = claim1 ? JSON.parse(claim1.content) : {}
ok('the broker submits it to the store', r.status === 0 && !!claim1)
ok('the claim is a kind 30078 signed by the identity with d, h, s, topic, as_of_git and exp tags',
  claim1?.kind === 30078 && claim1.pubkey === agent && verifyEvent(JSON.parse(JSON.stringify(claim1))) && tag(claim1, 'h') === ROOM && tag(claim1, 's') === `room:${ROOM}` &&
  tag(claim1, 'topic') === 'rota' && tag(claim1, 'as_of_git') === 'nvoy@f8b6a82' && Number(tag(claim1, 'exp')) - claim1.created_at === 14 * 86400)
ok('its content is the claim, reason, evidence and active status, and it validates as Hive memory',
  body.claim === claimArgs.claim && body.because === claimArgs.because && body.evidence.join() === claimArgs.evidence.join() && body.status === 'active' &&
  validateMemoryEvent(claim1).ok)
ok('the audit line names the event prefix and the room, never the words', r.stdout.includes(claim1?.id.slice(0, 12)) && r.stdout.includes(ROOM) && !r.stdout.includes('Neil'))
const rec1 = existsSync(recordFile(q1.ok.request)) ? readFileSync(recordFile(q1.ok.request), 'utf8') : ''
ok('once accepted the record is scrubbed to ids and times, and the spooled request is unlinked',
  Object.keys(JSON.parse(rec1 || '{}')).sort().join() === 'fingerprint,op,published,published_at,request_digest,request_id,version' &&
  !rec1.includes('Neil') && !rec1.includes('"sig"') && !existsSync(spoolFile(q1.ok.request)))
writeFileSync(spoolFile(q1.ok.request), JSON.stringify(spooled), { mode: 0o640 })
r = await write(mf, 'memory', q1.ok.request)
ok('a retry submits nothing new, reports replay, and unlinks a re-delivered request',
  r.status === 0 && /"replay":true/.test(r.stdout) && stored(q1.ok.d).length === 1 && !existsSync(spoolFile(q1.ok.request)))

// A claim later than the clock (another broker's, say) is still replaced by a strictly later one.
const future = queueMemory(mm, 'claim', { ...claimArgs, claim: 'Dennis reviews infra PRs this week.' })
const priorAt = claim1.created_at + 120
const ahead = finalizeEvent({ kind: 30078, created_at: priorAt, tags: claim1.tags, content: claim1.content }, agentSk)
ok('(fixture) a future-dated claim is accepted by the store', daemon.store.submit({ writer: 'agent', event: ahead, expectedPriorId: claim1.id }).accepted === true)
daemon.store.setConfig(null, new Error('fixture: config withdrawn'))
r = await write(mf, 'memory', future.ok.request)
ok('a claim that cannot look up its prior (store not ready) is held for retry, never signed without one',
  r.status === 1 && /cannot look up the latest claim/.test(r.stderr) && /HIVE_MEMORY_STORE_NOT_READY/.test(r.stderr) && /held for retry/.test(r.stderr) &&
  !existsSync(recordFile(future.ok.request)) && existsSync(spoolFile(future.ok.request)))
daemon.store.setConfig(validateAndResolveConfig(storeConfig))
r = await write(mf, 'memory', future.ok.request)
const claim2 = stored(q1.ok.d).find(ev => JSON.parse(ev.content).claim?.startsWith('Dennis'))
ok('a replacement claim is created strictly after the prior event the store returned', r.status === 0 && claim2?.created_at === priorAt + 1)

// --- 5. withdraw ---
daemon.store.setConfig(null, new Error('fixture: config withdrawn'))
const w1 = queueMemory(mm, 'withdraw', { slug: 'review-rota', because: 'The rota changed.' })
r = await write(mf, 'memory', w1.ok.request)
ok('a withdrawal that cannot look up its claim is held for retry, not guessed or refused for good',
  r.status === 1 && /cannot look up the latest claim/.test(r.stderr) && /held for retry/.test(r.stderr) && !/memory refused/.test(r.stderr) &&
  !existsSync(recordFile(w1.ok.request)))
daemon.store.setConfig(validateAndResolveConfig(storeConfig))
r = await write(mf, 'memory', w1.ok.request)
const withdrawal = stored(q1.ok.d).find(ev => JSON.parse(ev.content).status === 'withdrawn')
ok('the retry submits a withdrawn replacement at the same fact key, strictly later than the claim',
  r.status === 0 && withdrawal && tag(withdrawal, 'd') === q1.ok.d && tag(withdrawal, 'h') === ROOM && withdrawal.created_at > claim2.created_at &&
  validateMemoryEvent(withdrawal).status === 'withdrawn' &&
  daemon.store.lookupPrior({ writer: 'agent', d: q1.ok.d }).id === withdrawal.id)
ok('and nothing but kind 30078 is stored', allStored().every(ev => ev.kind === 30078))

// --- 6. the broker re-checks what the keyless side wrote ---
const forge = row => {
  const x = { version: 1, type: 'memory-request', instance: 'memory', op: 'claim', scope: `room:${ROOM}`, fields: claimArgs, requested_at: Date.now() - 2 * HOUR_MS, ...row }
  writeFileSync(spoolFile(x.id), JSON.stringify(x), { mode: 0o640 })
  return x
}
const forged = async (name, n, row, pattern) => {
  forge({ id: n.repeat(32), ...row })
  const res = await write(mf, 'memory', n.repeat(32))
  ok(name, res.status === 1 && pattern.test(res.stderr) && !existsSync(recordFile(n.repeat(32))))
  return res
}
await forged('the broker refuses a hive:ops scope, whatever the keyless side wrote', 'a', { scope: 'hive:ops' }, /memory refused: only room:<uuid> scopes may be written by an agent; hive:ops is refused/)
await forged('the broker refuses a hive:canon scope', 'b', { scope: 'hive:canon' }, /memory refused: only room:<uuid> scopes/)
await forged('the broker refuses a self scope', 'c', { scope: `self:${agent}` }, /memory refused: only room:<uuid> scopes/)
await forged('the broker refuses a room outside may_remember', 'd', { scope: `room:${OTHER}` }, /memory refused: room is not in may_remember\.rooms/)
const { evidence, ...noEvidence } = claimArgs
await forged('the broker refuses a claim without evidence', 'e', { fields: noEvidence }, /memory refused: evidence is required/)
await forged('the broker refuses a request carrying an extra field', '1', { event: { kind: 30079 } }, /invalid or overbroad shape/)
await forged('the broker refuses a raw tag smuggled into the fields', '2', { fields: { ...claimArgs, tags: [['h', OTHER]] } }, /memory refused: tags is not a memory_claim field/)
const secret = 'AK' + 'IA' + 'Q3ZT7RW2YX8V5N4M'
const s = await forged('the broker refuses a credential forged into the claim, without echoing it', '3', { fields: { ...claimArgs, claim: `use ${secret}` } },
  /memory refused: withheld: looks like a credential \(an AWS access key\)/)
ok('nothing carrying the forged credential reached the store', !(s.stdout + s.stderr).includes(secret) && !allStored().some(ev => ev.content.includes(secret)))
await forged('a withdrawal with no claim of this identity at the fact key is refused', '4', { op: 'withdraw', fields: { slug: 'never-claimed', because: 'x' } },
  /memory refused: no claim by this identity at hive-memory:room:[0-9a-f-]+:never-claimed to withdraw/)
await forged('a second withdrawal of an already-withdrawn claim is refused', '7', { op: 'withdraw', fields: { slug: 'review-rota', because: 'x' } },
  /memory refused: the claim at hive-memory:room:[0-9a-f-]+:review-rota is already withdrawn/)

// --- 7. the store's own ACL and CAS, independent of the manifest ---
const wide = fixture('wide', { may_remember: { rooms: [ROOM, ROOM2], per_hour: 30, submit } }), wm = wide.load()
provisionSpool(wide)
const qWide = queueMemory(wm, 'claim', { ...claimArgs, room: ROOM2, slug: 'outside-acl' })
r = await write(wide, 'wide', qWide.ok.request)
ok('a room the manifest allows but the store ACL does not is refused for good by the store, before anything is signed',
  r.status === 1 && /memory refused: HIVE_MEMORY_SCOPE_NOT_AUTHORIZED/.test(r.stderr) && !existsSync(join(wide.state, 'memory', `${qWide.ok.request}.json`)) &&
  stored(qWide.ok.d).length === 0)

const qCas = queueMemory(wm, 'claim', { ...claimArgs, slug: 'cas-race', claim: 'first writer wins' })
const casReq = JSON.parse(readFileSync(join(wide.run, 'memory-requests', `${qCas.ok.request}.json`), 'utf8'))
const staleBuilt = memoryTemplates(wm, casReq, null)
mkdirSync(join(wide.state, 'memory'), { recursive: true, mode: 0o700 })
const casRecord = join(wide.state, 'memory', `${qCas.ok.request}.json`)
// A record frozen against an empty fact key, and then another submission takes the key first.
writeFileSync(casRecord, JSON.stringify({ version: 1, request_id: qCas.ok.request, request_digest: replyRequestDigest(casReq), op: 'claim',
  fingerprint: getEventHash(staleBuilt.event), unsigned_event: staleBuilt.event, event: null, expected_prior_id: null, published: false }), { mode: 0o600 })
const racer = finalizeEvent({ ...staleBuilt.event, content: JSON.stringify({ ...JSON.parse(staleBuilt.event.content), claim: 'the other broker got here first' }) }, agentSk)
ok('(fixture) a racing claim takes the fact key', daemon.store.submit({ writer: 'agent', event: racer, expectedPriorId: null }).accepted === true)
r = await write(wide, 'wide', qCas.ok.request)
const casAfter = readFileSync(casRecord, 'utf8')
ok('a frozen write whose expected prior moved is refused for good (PRIOR_MISMATCH), scrubbed and unspooled',
  r.status === 1 && /memory refused: HIVE_MEMORY_PRIOR_MISMATCH/.test(r.stderr) && JSON.parse(casAfter).refused === 'HIVE_MEMORY_PRIOR_MISMATCH' &&
  !casAfter.includes('first writer wins') && !existsSync(join(wide.run, 'memory-requests', `${qCas.ok.request}.json`)) &&
  stored(qCas.ok.d).length === 1 && stored(qCas.ok.d)[0].id === racer.id)
r = await write(wide, 'wide', qCas.ok.request)
ok('and a retry of it stays refused without contacting the signer or store', r.status === 1 && /memory refused: HIVE_MEMORY_PRIOR_MISMATCH/.test(r.stderr))

// The forced-command transport: stdio bridged to the same writer socket.
const bridge = join(root, 'bridge.mjs')
writeFileSync(bridge, "import { connect } from 'node:net'\nconst c = connect(process.argv[2]); process.stdin.pipe(c); c.pipe(process.stdout); c.on('close', () => process.exit(0))\n")
const viaCmd = fixture('viacmd', { may_remember: { rooms: [ROOM], per_hour: 30, submit: { command: [process.execPath, bridge, writerSocket] } } }), vm = viaCmd.load()
provisionSpool(viaCmd)
const qCmd = queueMemory(vm, 'claim', { ...claimArgs, slug: 'via-command' })
r = await write(viaCmd, 'viacmd', qCmd.ok.request)
ok('the broker submits through a forced-command bridge as well as a socket', r.status === 0 && stored(qCmd.ok.d).length === 1)
const noStore = fixture('nostore', { may_remember: { rooms: [ROOM], per_hour: 30, submit: { socket: join(root, 'absent.sock') } } }), nm = noStore.load()
provisionSpool(noStore)
const qGone = queueMemory(nm, 'claim', { ...claimArgs, slug: 'store-gone' })
r = await write(noStore, 'nostore', qGone.ok.request)
ok('an unreachable store holds the request for retry and keeps it spooled',
  r.status === 1 && /memory store unreachable/.test(r.stderr) && /held for retry/.test(r.stderr) && !/memory refused/.test(r.stderr) &&
  existsSync(join(noStore.run, 'memory-requests', `${qGone.ok.request}.json`)))

// --- 8. the hourly cap: claim, replacement and withdrawal spent 3 of 3 ---
ok('the tool tells the agent at once when the hour is spent', queueMemory(mm, 'claim', { ...claimArgs, slug: 'fourth' }).error?.code === 'NVOY_MEMORY_RATE_LIMITED')
await forged('the broker\'s durable counter refuses a write over per_hour', '5', { fields: { ...claimArgs, slug: 'fourth' } }, /memory refused: over the hourly cap \(3\/3/)
ok('the counter lives in the broker state root', existsSync(join(mf.state, 'agent-limits', 'memory.json')))

const nf = fixture('nomemory')
provisionSpool(nf)
writeFileSync(join(nf.run, 'memory-requests', `${'6'.repeat(32)}.json`), JSON.stringify({ version: 1, type: 'memory-request', id: '6'.repeat(32), instance: 'nomemory', op: 'claim',
  scope: `room:${ROOM}`, fields: claimArgs, requested_at: Date.now() }))
r = await write(nf, 'nomemory', '6'.repeat(32))
ok('an identity without may_remember is refused by the broker', r.status === 1 && /memory refused: this identity may not write memory/.test(r.stderr))

// --- 9. (§5 test 1) worker spool writes racing broker unlinks: nothing lost, nothing lingering ---
const race = fixture('race', { may_remember: { rooms: [ROOM], per_hour: 30, submit } })
provisionSpool(race)
const raceSpool = join(race.run, 'memory-requests')
const agentMemory = resolve('mcp/tools/agent_memory.mjs'), runtimeManifest = resolve('mcp/tools/runtime_manifest.mjs')
const worker = n => run(['--input-type=module', '-e', `
  import { queueMemory } from ${JSON.stringify(agentMemory)}
  import { readManifest } from ${JSON.stringify(runtimeManifest)}
  const m = readManifest(process.env.R, 'race'), ids = []
  for (let i = 0; i < 4; i++) {
    const r = queueMemory(m, 'claim', { slug: 'race-${n}-' + i, topic: 'race', claim: 'secret-race-words ${n} ' + i, because: 'race fixture', evidence: ['nvoy@f8b6a82:x'], as_of_git: 'nvoy@f8b6a82' })
    if (!r.ok) { console.error(JSON.stringify(r.error)); process.exit(1) }
    ids.push(r.ok.request)
    await new Promise(res => setTimeout(res, 15))
  }
  console.log(JSON.stringify(ids))`], { R: race.root })
const raceDone = new Set(), raceFailed = []
let workersDone = false
const workers = Promise.all([1, 2, 3].map(worker)).then(rs => { workersDone = true; return rs })
const drainOnce = async () => {
  const names = readdirSync(raceSpool).filter(n => /^[0-9a-f]{32}\.json$/.test(n))
  await Promise.all(names.map(async name => {
    const res = await write(race, 'race', name.slice(0, 32))
    if (res.status === 0) raceDone.add(name.slice(0, 32)); else raceFailed.push(res.stderr)
  }))
  if (!names.length) await new Promise(res => setTimeout(res, 10))
}
while (!workersDone) await drainOnce()
const workerOut = await workers
await drainOnce()
const queuedIds = workerOut.flatMap(w => { try { return JSON.parse(w.stdout) } catch { return [] } })
const raceStored = allStored().filter(ev => tag(ev, 'topic') === 'race')
ok('three concurrent workers spooled twelve requests', workerOut.every(w => w.status === 0) && queuedIds.length === 12 && new Set(queuedIds).size === 12)
ok('every spooled request was enacted exactly once: none lost, none doubled',
  queuedIds.every(id => raceDone.has(id)) && raceStored.length === 12 && raceFailed.length === 0)
ok('no request file lingers after enactment and no stray .tmp is left', readdirSync(raceSpool).length === 0)
const raceRate = readFileSync(join(race.run, 'memory-rate.jsonl'), 'utf8')
ok('the race rate log holds twelve id/time rows and no claim text',
  raceRate.trim().split('\n').length === 12 && !raceRate.includes('secret-race-words') && !raceRate.includes('claim') &&
  raceRate.trim().split('\n').every(l => Object.keys(JSON.parse(l)).sort().join() === 'id,requested_at'))
ok('no enactment record keeps the words', queuedIds.every(id => !readFileSync(join(race.state, 'memory', `${id}.json`), 'utf8').includes('secret-race-words')))

await daemon.close()
console.log(`\n${passes} passed, ${fails} failed`)
process.exit(fails ? 1 : 0)
