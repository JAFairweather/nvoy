// onboard-two-key.mjs — the hosted route for a Pi or Codex agent: two keys in the bind, both reported, both re-read
// against the bind before the apply, and the apply told which harness it is seating. A Claude agent is unchanged.
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { SETUP_KIND, parseSetupRequest } from '../mcp/tools/onboard_request.mjs'
import { onboard } from '../mcp/tools/onboard_run.mjs'
import { readStagedKey, stagedKeyPath } from '../mcp/tools/onboard_stage.mjs'

const tmp = mkdtempSync(join(tmpdir(), 'nvoy-two-key-'))
const root = join(tmp, 'instances'), out = join(tmp, 'staged'), stateDir = join(tmp, 'state'), creds = join(tmp, 'creds'), backupRoot = join(tmp, 'root')
for (const dir of [root, out, creds, backupRoot]) mkdirSync(dir, { recursive: true })
const owner = generateSecretKey(), ownerHex = getPublicKey(owner), agent = getPublicKey(generateSecretKey())
const channel = '00000000-0000-4000-8000-000000000000'
let uid = 2000
const raw = (id, pubkey, extra = {}) => {
  const dir = join(tmp, 'var', id)
  for (const name of ['state', 'run', 'spool']) mkdirSync(join(dir, name), { recursive: true })
  uid += 10
  return { id, pubkey, grantors: [ownerHex], relays: ['wss://relay.example'], buzz: { relay: 'wss://buzz.example', channels: [channel] },
    broker_mode: 'local', bunker_uri_ref: join(creds, `${id}.bunker-uri`), bunker_client_ref: join(creds, `${id}.nip46-client`),
    delivery_mode: 'notify_only', worker_enabled: false, state_dir: join(dir, 'state'), runtime_dir: join(dir, 'run'), spool_dir: join(dir, 'spool'),
    broker_adapter_gid: uid, worker_handoff_gid: uid + 1, watcher_uid: uid + 2, broker_uid: uid + 3, adapter_uid: uid + 4, worker_uid: uid + 5, ...extra }
}
const pidog = raw('pi-dog', getPublicKey(generateSecretKey()), { may_set_profile: { kind: 0, pubkey: '', grant_id: 'ab'.repeat(32), picture_hosts: ['nave.pub'] } })
pidog.may_set_profile.pubkey = pidog.pubkey
writeFileSync(join(root, 'pi-dog.json'), JSON.stringify(pidog))

const body = n => 'AAAAC3NzaC1lZDI1NTE5AAAAI' + String(n).repeat(43)
const CHANNEL = `ssh-ed25519 ${body('a')}`, FEED = `ssh-ed25519 ${body('b')}`
const at = Math.floor(Date.now() / 1000)
const sign = tags => finalizeEvent({ kind: SETUP_KIND, created_at: at, content: '', tags }, owner)
const addTags = harness => [['d', 'nvoy-onboard/crusty/add_agent'], ['op', 'add_agent'], ['p', agent], ['harness', harness], ['like', 'pi-dog'], ['giver', ownerHex], ['room', channel]]
const bindTags = (harness, ...extra) => [['d', 'nvoy-onboard/crusty/bind_runtime'], ['op', 'bind_runtime'], ['p', agent], ['harness', harness], ['like', 'pi-dog'], ...extra]

// ── the request: feed_key rules ─────────────────────────────────────────────────────────────────
const manifests = new Map([['pi-dog', { id: 'pi-dog', pubkey: pidog.pubkey, grantors: [ownerHex] }]])
const parse = event => parseSetupRequest(event, { name: 'crusty', manifests, seen: new Set(), now: Date.now() })
const refuses = (code, event) => assert.throws(() => parse(event), error => error.code === code, code)
assert.equal(parse(sign(bindTags('pi', ['channel_key', CHANNEL], ['feed_key', FEED]))).feedKey.keyBody, body('b'), 'a Pi bind carries both keys')
refuses('ONBOARD_BAD_TAG', sign(bindTags('pi', ['channel_key', CHANNEL])))
refuses('ONBOARD_BAD_TAG', sign(bindTags('codex', ['channel_key', CHANNEL])))
refuses('ONBOARD_BAD_TAG', sign(bindTags('claude-code', ['channel_key', CHANNEL], ['feed_key', FEED])))
refuses('ONBOARD_BAD_TAG', sign([...addTags('pi'), ['feed_key', FEED]]))
refuses('ONBOARD_BAD_FEED_KEY', sign(bindTags('pi', ['channel_key', CHANNEL], ['feed_key', CHANNEL])))
refuses('ONBOARD_BAD_FEED_KEY', sign(bindTags('pi', ['channel_key', CHANNEL], ['feed_key', 'ssh-rsa AAAA x'])))
assert.equal(parse(sign(bindTags('claude-code', ['channel_key', CHANNEL]))).feedKey, null, 'a Claude bind has no feed key')

// ── the staged feed file ─────────────────────────────────────────────────────────────────────────
const request = 'c'.repeat(64)
writeFileSync(stagedKeyPath(tmp, request, 'feed'), `${FEED} nvoy-stage-feed:crusty:${request}\n`)
assert.equal(readStagedKey({ stateDir: tmp, request, instance: 'crusty', role: 'feed' }).state, 'done')
assert.match(stagedKeyPath(tmp, request, 'feed'), /\.staged-feed\.pub$/)
assert.equal(readStagedKey({ stateDir: tmp, request, instance: 'crusty', role: 'channel' }), null, 'the channel file is its own file')
assert.match(readStagedKey({ stateDir: tmp, request, instance: 'other', role: 'feed' }).detail, /not bound to this instance and request/)
writeFileSync(stagedKeyPath(tmp, request, 'feed'), `${FEED} nvoy-stage:crusty:${request}\n`)
assert.match(readStagedKey({ stateDir: tmp, request, instance: 'crusty', role: 'feed' }).detail, /not bound/, 'the channel binding comment does not pass for a feed file')

// ── the run ──────────────────────────────────────────────────────────────────────────────────────
const addEvent = sign(addTags('pi')), bindEvent = sign(bindTags('pi', ['channel_key', CHANNEL], ['feed_key', FEED]))
const applies = []
const runTool = (tool, args) => {
  const op = tool === 'instance-pair.mjs' ? 'pair' : args[0]
  const id = args[args.indexOf('--id') + 1]
  if (op === 'allocate') { writeFileSync(join(out, `${id}.json`), JSON.stringify(raw(id, agent))); return 0 }
  if (op === 'pair') return 1
  if (op === 'check') return 0
  if (op === 'apply') {
    applies.push({ args: [...args], feed: args.includes('--feed-public-key-file') ? readFileSync(args[args.indexOf('--feed-public-key-file') + 1], 'utf8') : null })
    writeFileSync(join(root, 'crusty.json'), readFileSync(join(out, 'crusty.json'))); return 0
  }
  throw new Error(`unexpected tool ${tool}`)
}
writeFileSync(join(creds, 'crusty.bunker-uri'), 'x'); writeFileSync(join(creds, 'crusty.nip46-client'), 'x')
const run = events => onboard({ command: 'run', name: 'crusty', root, out, stateDir, backupRoot, keysPath: join(tmp, 'authorized_keys'),
  fetchEvents: async () => events, runTool, joinWith: () => ({ signer: {}, open: async () => { throw new Error('AUTH refused: not a member') }, close() {} }), log: () => {} })
const states = result => Object.fromEntries(result.receipts.map(row => [row.step, row.state]))

mkdirSync(stateDir, { recursive: true })
const stageOf = role => stagedKeyPath(stateDir, addEvent.id, role)
const stageChannel = () => writeFileSync(stageOf('channel'), `${CHANNEL} nvoy-stage:crusty:${addEvent.id}\n`)
const stageFeed = key => writeFileSync(stageOf('feed'), `${key} nvoy-stage-feed:crusty:${addEvent.id}\n`)

// Both keys staged and bound: two rows, then the apply is told the harness and given the feed key.
stageChannel(); stageFeed(FEED)
let result = await run([addEvent, bindEvent])
assert.equal(states(result).channel_key, 'done'); assert.equal(states(result).feed_key, 'done')
assert.match(result.receipts.find(row => row.step === 'feed_key').detail, /staged for the owner to bind/)
assert.equal(applies.length, 1, 'the apply ran once')
const args = applies[0].args
assert.equal(args[args.indexOf('--harness') + 1], 'pi')
assert.match(applies[0].feed, /^ssh-ed25519 /); assert.ok(applies[0].feed.includes(body('b')) && !applies[0].feed.includes(body('a')), 'the feed file holds the feed key, not the channel key')
assert.ok(readFileSync(args[args.indexOf('--public-key-file') + 1], 'utf8').includes(body('a')), 'the channel file holds the channel key')

// Swapped: the staged feed file holds the channel key. Nothing is applied.
rmSync(join(root, 'crusty.json'), { force: true }); applies.length = 0
stageFeed(CHANNEL)
result = await run([addEvent, bindEvent])
assert.equal(states(result).feed_key, 'refused'); assert.equal(states(result).started, 'refused'); assert.equal(applies.length, 0, 'a swapped key reaches no apply')
assert.match(result.receipts.find(row => row.step === 'started').detail, /feed key/)

// A staged feed file bound to another request changes after it was reported: still refused at the apply.
stageFeed(FEED); writeFileSync(stageOf('feed'), `${FEED} nvoy-stage-feed:crusty:${'d'.repeat(64)}\n`)
result = await run([addEvent, bindEvent])
assert.equal(states(result).started, 'refused'); assert.equal(applies.length, 0)

// No staged files at all (an agent on its own box): the bind alone is enough, and no staged rows are made.
rmSync(stageOf('channel')); rmSync(stageOf('feed'))
result = await run([addEvent, bindEvent])
assert.equal(states(result).channel_key, undefined); assert.equal(states(result).feed_key, undefined); assert.equal(states(result).started, 'done'); assert.equal(applies.length, 1)

// A failure AFTER the manifest went in is repaired by the next run, once, and not on every tick after that.
rmSync(join(root, 'crusty.json'), { force: true }); applies.length = 0
{
  const verbs = []
  const flaky = (tool, args) => {
    if (args[0] === 'apply') { verbs.push('apply'); writeFileSync(join(root, 'crusty.json'), readFileSync(join(out, 'crusty.json'))); return 1 }   // installed, then the seat or verify failed
    if (args[0] === 'repair') { verbs.push('repair'); assert.ok(args.includes('--feed-public-key-file') && !args.includes('--out')); return repairCode }
    return runTool(tool, args)
  }
  let repairCode = 1
  const flakyRun = () => onboard({ command: 'run', name: 'crusty', root, out, stateDir, backupRoot, keysPath: join(tmp, 'authorized_keys'),
    fetchEvents: async () => [addEvent, bindEvent], runTool: flaky, joinWith: () => ({ signer: {}, open: async () => { throw new Error('AUTH refused: not a member') }, close() {} }), log: () => {} })
  let result = await flakyRun()
  assert.equal(states(result).started, 'refused'); assert.deepEqual(verbs, ['apply'], 'the first run applied and failed after installing')
  result = await flakyRun()
  assert.deepEqual(verbs, ['apply', 'repair'], 'the next run repairs the installed agent instead of calling it installed')
  assert.equal(states(result).started, 'refused'); assert.match(result.receipts.find(row => row.step === 'started').detail, /repair exited 1/)
  repairCode = 0
  result = await flakyRun()
  assert.deepEqual(verbs, ['apply', 'repair', 'repair']); assert.equal(states(result).started, 'done')
  assert.match(result.receipts.find(row => row.step === 'started').detail, /repaired/)
  result = await flakyRun()
  assert.deepEqual(verbs, ['apply', 'repair', 'repair'], 'once done, later ticks do not repair again'); assert.equal(states(result).started, 'done')
  // No recorded unfinished attempt: an installed agent whose request has no `started` row is left alone, marker or not.
  const receiptsFile = join(stateDir, `${addEvent.id}.jsonl`)
  writeFileSync(receiptsFile, readFileSync(receiptsFile, 'utf8').split('\n').filter(line => line && JSON.parse(line).step !== 'started').join('\n') + '\n')
  verbs.length = 0
  result = await flakyRun()
  assert.deepEqual(verbs, [], 'an installed agent with no unfinished started row is not repaired'); assert.equal(states(result).started, 'done')
  // An unfinished attempt, but the installed bytes are not the ones this request staged: refused, nothing seated.
  writeFileSync(receiptsFile, readFileSync(receiptsFile, 'utf8').split('\n').filter(line => line && JSON.parse(line).step !== 'started').join('\n') + '\n'
    + JSON.stringify({ step: 'started', state: 'refused', at: Date.now(), detail: 'apply exited 1' }) + '\n')
  const installedCopy = JSON.parse(readFileSync(join(root, 'crusty.json'), 'utf8'))
  writeFileSync(join(root, 'crusty.json'), JSON.stringify({ ...installedCopy, relays: ['wss://relay.other.example'] }))
  result = await flakyRun()
  assert.deepEqual(verbs, [], 'changed installed bytes are never repaired'); assert.equal(states(result).started, 'refused')
  assert.match(result.receipts.find(row => row.step === 'started').detail, /not the one this request staged/)
  rmSync(join(root, 'crusty.json')); rmSync(receiptsFile)
}

// The bind must match the add exactly: another harness (even in the same family) or another template is another intent.
rmSync(join(stateDir, `${addEvent.id}.jsonl`), { force: true })
for (const [label, tags] of [['harness in the same family', bindTags('codex', ['channel_key', CHANNEL], ['feed_key', FEED])],
  ['template', [...bindTags('pi', ['channel_key', CHANNEL], ['feed_key', FEED])].map(tag => tag[0] === 'like' ? ['like', 'pi-dog'] : tag)]]) {
  if (label === 'template') {
    // a second installed template, so `like` can differ and still parse
    const second = raw('crystalclaude', getPublicKey(generateSecretKey()))
    second.may_set_profile = { kind: 0, pubkey: second.pubkey, grant_id: 'cd'.repeat(32), per_day: 1, picture_hosts: ['nave.pub'] }
    writeFileSync(join(root, 'crystalclaude.json'), JSON.stringify(second))
    const other = sign(bindTags('pi', ['channel_key', CHANNEL], ['feed_key', FEED]).map(tag => tag[0] === 'like' ? ['like', 'crystalclaude'] : tag))
    await assert.rejects(run([addEvent, other]), error => error.code === 'ONBOARD_BIND_MISMATCH' && /starts like/.test(error.message), label)
  } else {
    await assert.rejects(run([addEvent, sign(tags)]), error => error.code === 'ONBOARD_BIND_MISMATCH' && /is for a codex agent but add_agent is pi/.test(error.message), label)
  }
}

// An add_agent for a Claude harness, a bind for a Pi one: refused, not guessed at.
rmSync(join(root, 'crusty.json'), { force: true }); applies.length = 0
const mismatched = sign([...addTags('claude-code')])
await assert.rejects(run([mismatched, bindEvent]), error => error.code === 'ONBOARD_BIND_MISMATCH')
assert.equal(applies.length, 0)

console.log('onboard-two-key: feed_key rules, staged feed file, both keys re-read against the bind, harness passed to apply, family mismatch refused pass')
