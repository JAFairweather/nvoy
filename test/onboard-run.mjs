import assert from 'node:assert/strict'
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { SETUP_KIND } from '../mcp/tools/onboard_request.mjs'
import { onboard, rewrite } from '../mcp/tools/onboard_run.mjs'

const tmp = mkdtempSync(join(tmpdir(), 'nvoy-onboard-'))
const root = join(tmp, 'instances'), out = join(tmp, 'staged'), stateDir = join(tmp, 'state'), creds = join(tmp, 'creds'), backupRoot = join(tmp, 'root')
for (const dir of [root, out, creds, backupRoot]) mkdirSync(dir, { recursive: true })
const owner = generateSecretKey(), ownerHex = getPublicKey(owner), agent = getPublicKey(generateSecretKey()), agent2 = getPublicKey(generateSecretKey())
const channel = '00000000-0000-4000-8000-000000000000', outsider = getPublicKey(generateSecretKey())
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
const pi = raw('pi-dog', getPublicKey(generateSecretKey()), { may_post: { channels: [channel], per_hour: 4, mention: [] } })
const crystal = raw('crystalclaude', getPublicKey(generateSecretKey()), { may_set_profile: { kind: 0, pubkey: '', grant_id: 'ab'.repeat(32), picture_hosts: ['nave.pub'] } })
crystal.may_set_profile.pubkey = crystal.pubkey
for (const manifest of [pi, crystal]) writeFileSync(join(root, `${manifest.id}.json`), JSON.stringify(manifest))

const KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0' + 'a'.repeat(40) + ' hr@box'
const at = Math.floor(Date.now() / 1000)
const sign = (tags, created_at = at) => finalizeEvent({ kind: SETUP_KIND, created_at, content: '', tags }, owner)
const add = sign([['d', 'nvoy-onboard/hr/add_agent'], ['op', 'add_agent'], ['p', agent], ['harness', 'claude-code'],
  ['like', 'crystalclaude'], ['giver', pi.pubkey], ['giver', ownerHex], ['giver', outsider], ['room', channel]])
const bind = sign([['d', 'nvoy-onboard/hr/bind_runtime'], ['op', 'bind_runtime'], ['p', agent], ['harness', 'claude-code'],
  ['like', 'crystalclaude'], ['channel_key', KEY]])

// Fake tools that make the state each real tool makes. The owner approves the pairing on the second try.
const calls = [], likes = []
let approved = false
const runTool = (tool, args) => {
  const op = tool === 'instance-pair.mjs' ? 'pair' : args[0]
  calls.push(op)
  const id = args[args.indexOf('--id') + 1]
  if (op === 'allocate') { likes.push(args[args.indexOf('--like') + 1]); writeFileSync(join(out, `${id}.json`), JSON.stringify(raw(id, id === 'hr' ? agent : agent2))); return 0 }
  if (op === 'pair') {
    if (id !== 'hr' || !approved) return 1
    writeFileSync(join(creds, 'hr.bunker-uri'), 'x'); writeFileSync(join(creds, 'hr.nip46-client'), 'x'); return 0
  }
  if (op === 'check') return 0
  if (op === 'apply') { assert.match(readFileSync(args[args.indexOf('--public-key-file') + 1], 'utf8'), /^ssh-ed25519 /); copyFileSync(join(out, 'hr.json'), join(root, 'hr.json')); return 0 }
  throw new Error(`unexpected tool ${tool}`)
}
let events = [add]
// Not a hive member yet, and this request carries no invite: the hive step waits for one. (onboard-join.mjs covers the claim.)
let joins = 0
const joinWith = manifest => { joins++; assert.equal(manifest.buzz.relay, 'wss://buzz.example'); return { signer: {}, open: async () => { throw new Error('AUTH refused: not a member') }, close() {} } }
const run = (extra = {}) => onboard({ command: 'run', name: 'hr', root, out, stateDir, backupRoot, keysPath: join(tmp, 'authorized_keys'),
  fetchEvents: async () => events, runTool, joinWith, log: () => {}, ...extra })
const states = result => Object.fromEntries(result.receipts.map(row => [row.step, row.state]))

// show writes nothing and runs nothing.
const shown = await onboard({ command: 'show', name: 'hr', root, out, stateDir, fetchEvents: async () => events, runTool, log: () => {} })
assert.equal(shown.request.pubkey, agent); assert.deepEqual(calls, []); assert.equal(existsSync(join(out, 'hr.json')), false)
assert.equal(existsSync(stateDir), false)

// First run: staged with its profile grant, then waits on the Bunker.
let result = await run()
assert.deepEqual(states(result), { staged: 'done', paired: 'pending' })
const staged = JSON.parse(readFileSync(join(out, 'hr.json'), 'utf8'))
assert.equal(staged.may_set_profile.pubkey, agent); assert.equal(staged.may_set_profile.per_day, 1)
assert.deepEqual(staged.may_set_profile.picture_hosts, ['nave.pub']); assert.match(staged.may_set_profile.grant_id, /^[0-9a-f]{64}$/)

// Approved: paired and checked, then waits for the box's bind_runtime.
approved = true
result = await run()
assert.deepEqual(states(result), { staged: 'done', paired: 'done', checked: 'done', started: 'pending' })

// The box binds: installed, then waits for the operator to agree to redeploy the givers.
events = [add, bind]
result = await run()
assert.equal(states(result).started, 'done'); assert.equal(states(result).givers, 'pending')
assert.match(result.receipts.find(row => row.step === 'givers').detail, /--givers-redeploy: it redeploys pi-dog/)
assert.equal(states(result)['relay writer'], 'pending'); assert.equal(states(result).hive, 'pending'); assert.equal(states(result).rooms, 'pending')
assert.match(result.receipts.find(row => row.step === 'hive').detail, /carries no invite/)
assert.equal(joins, 1, 'the agent connection opens only once it is installed')

// Agreed: pi-dog may now mention hr, with a backup taken first, and the manifest still reads. The
// giver outside the fleet stays pending, named, and nothing ran for it.
result = await run({ giversRedeploy: true })
assert.equal(states(result).givers, 'pending')
assert.match(result.receipts.find(row => row.step === 'givers').detail, new RegExp(`added hr to pi-dog; outside the fleet, nothing run: ${outsider.slice(0, 8)}`))
assert.deepEqual(JSON.parse(readFileSync(join(root, 'pi-dog.json'), 'utf8')).may_post.mention, [{ name: 'hr', pubkey: agent }])
const backups = readdirSync(backupRoot)
assert.equal(backups.length, 1); assert.match(backups[0], /^pi-dog-backups-\d{8}$/)
assert.equal(JSON.parse(readFileSync(join(backupRoot, backups[0], readdirSync(join(backupRoot, backups[0]))[0]), 'utf8')).may_post.mention.length, 0)

// Each tool that changes state ran once, except the pairing the owner had not yet approved; the
// read-only check runs again before the install. A further run runs nothing.
assert.deepEqual(calls, ['allocate', 'pair', 'pair', 'check', 'check', 'apply'])
result = await run({ giversRedeploy: true })
assert.deepEqual(calls, ['allocate', 'pair', 'pair', 'check', 'check', 'apply'])
assert.match(result.receipts.find(row => row.step === 'givers').detail, /every seat giver can mention hr/)
assert.equal(JSON.parse(readFileSync(join(root, 'pi-dog.json'), 'utf8')).may_post.mention.length, 1)

// A bind_runtime for another key is refused before anything runs.
events = [add, sign([...bind.tags.filter(tag => tag[0] !== 'p'), ['p', outsider]])]
await assert.rejects(run(), error => error.code === 'ONBOARD_BIND_MISMATCH')
assert.deepEqual(calls, ['allocate', 'pair', 'pair', 'check', 'check', 'apply'])

// Signed again after it started (the terms changed, or the invite expired): the new request continues
// to the hive with nothing reinstalled. A re-sign that changes its harness is refused.
events = [sign(add.tags, at + 1), bind]
result = await run({ giversRedeploy: true })
assert.deepEqual(states(result), { staged: 'done', paired: 'done', checked: 'done', started: 'done', givers: 'pending', 'relay writer': 'pending', hive: 'pending', rooms: 'pending' })
assert.match(result.receipts.find(row => row.step === 'started').detail, /^installed$/)
assert.deepEqual(calls, ['allocate', 'pair', 'pair', 'check', 'check', 'apply'])
events = [sign(add.tags.map(tag => tag[0] === 'harness' ? ['harness', 'codex'] : tag), at + 2), bind]
await assert.rejects(run(), error => error.code === 'ONBOARD_EXISTS')

// A newer signed request for the same name, before pairing, is staged afresh from its own template.
const hr2 = like => [['d', 'nvoy-onboard/hr2/add_agent'], ['op', 'add_agent'], ['p', agent2], ['harness', 'claude-code'], ['like', like]]
const first = sign(hr2('crystalclaude'), at - 60), second = sign(hr2('pi-dog'))
const run2 = list => onboard({ command: 'run', name: 'hr2', root, out, stateDir, backupRoot, fetchEvents: async () => list, runTool, log: () => {} })
likes.length = 0
assert.equal(states(await run2([first])).paired, 'pending')
result = await run2([first, second])
assert.equal(states(result).paired, 'pending'); assert.deepEqual(likes, ['crystalclaude', 'pi-dog'])
assert.equal(readFileSync(join(out, 'hr2.request'), 'utf8').trim(), second.id)
assert.ok(existsSync(join(out, `hr2.json.superseded-${first.id.slice(0, 12)}`)))
await run2([first, second]); assert.deepEqual(likes, ['crystalclaude', 'pi-dog'])

// Two backups of one giver in the same second both survive.
const fixed = () => Date.UTC(2026, 10, 2, 23, 50, 7)
for (let n = 0; n < 2; n++) rewrite(root, 'pi-dog', m => m, { backupRoot, now: fixed })
assert.deepEqual(readdirSync(join(backupRoot, 'pi-dog-backups-20261102')).filter(f => f.includes('235007')).sort(),
  ['pi-dog.json.pre-onboard-235007', 'pi-dog.json.pre-onboard-235007-1'])

rmSync(tmp, { recursive: true, force: true })
console.log('onboard-run: show writes nothing, resume, pairing wait, bind, givers backup and redeploy consent, re-signed after start, a newer request restages, backups never overwrite pass')
