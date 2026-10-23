import { strict as assert } from 'node:assert'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { WebSocketServer } from 'ws'
import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { readManifest } from '../mcp/tools/runtime_manifest.mjs'
import { queueProfile, profileStatus, profileToolSpec } from '../mcp/tools/agent_profile.mjs'
import { capabilitySummary } from '../mcp/tools/agent_post.mjs'
import { mergedProfile, ProfileRefusal, readbackProfile } from '../mcp/tools/profile_policy.mjs'

const secret = generateSecretKey(), pubkey = getPublicKey(secret), other = getPublicKey(generateSecretKey())
const root = mkdtempSync(join(tmpdir(), 'nvoy-profile-set-'))
const server = createServer((request, response) => { response.writeHead(404); response.end() })
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const relay = `ws://127.0.0.1:${server.address().port}`
const websocket = new WebSocketServer({ server })
const sent = []
let stored = [finalizeEvent({ kind: 0, created_at: 1, tags: [], content: JSON.stringify({ name: 'grok', about: 'old', custom: 'keep', bot: false }) }, secret)]
let dropNext = false, mismatchNext = false
websocket.on('connection', socket => {
  const challenge = Buffer.from(generateSecretKey()).toString('hex')
  let authorized = false
  socket.send(JSON.stringify(['AUTH', challenge]))
  socket.on('message', raw => {
    const frame = JSON.parse(raw.toString())
    if (frame[0] === 'AUTH') {
      const event = frame[1]
      authorized = verifyEvent(event) && event.kind === 22242 && event.pubkey === pubkey &&
        event.tags.some(tag => tag[0] === 'challenge' && tag[1] === challenge) &&
        event.tags.some(tag => tag[0] === 'relay' && tag[1] === relay)
      socket.send(JSON.stringify(['OK', event.id, authorized, authorized ? '' : 'unauthorized']))
    }
    if (frame[0] === 'REQ') {
      const event = mismatchNext ? stored[0] : stored.at(-1)
      if (authorized && event) socket.send(JSON.stringify(['EVENT', frame[1], event]))
      socket.send(JSON.stringify(['EOSE', frame[1]]))
    }
    if (frame[0] === 'EVENT') {
      const event = frame[1]
      assert(authorized && event.kind === 0 && event.pubkey === pubkey && verifyEvent(event))
      sent.push(event)
      if (dropNext) { dropNext = false; socket.close(); return }
      if (!mismatchNext && !stored.some(existing => existing.id === event.id)) stored.push(event)
      socket.send(JSON.stringify(['OK', event.id, true, '']))
    }
  })
})

function manifestFixture(id, extra = {}) {
  const directory = join(root, id)
  for (const name of ['instances', 'state', 'run', 'spool']) mkdirSync(join(directory, name), { recursive: true })
  const raw = { id, pubkey, grantors: [other], relays: ['wss://relay.example'], buzz: { relay, channels: ['00000000-0000-4000-8000-000000000000'] },
    broker_mode: 'local', key_ref: '/fake/key', delivery_mode: 'notify_only', worker_enabled: false,
    state_dir: join(directory, 'state'), runtime_dir: join(directory, 'run'), spool_dir: join(directory, 'spool'),
    broker_adapter_gid: 1001, worker_handoff_gid: 1002, watcher_uid: 1001, broker_uid: 1002,
    adapter_uid: 1003, worker_uid: 1004, ...extra }
  writeFileSync(join(directory, 'instances', `${id}.json`), JSON.stringify(raw))
  return { root: join(directory, 'instances'), directory, load: () => readManifest(join(directory, 'instances'), id) }
}
const grant = { kind: 0, pubkey, grant_id: 'ab'.repeat(32) }
const fixture = manifestFixture('seat', { may_set_profile: grant })
const manifest = fixture.load()
assert.equal(manifest.maySetProfile.perDay, 1)
assert.equal(manifest.maySetProfile.pubkey, pubkey)
assert.equal(manifest.maySetProfile.grantId, grant.grant_id)
assert.equal(manifest.maySetProfile.pictureHosts.join(), 'nave.pub')
const ungranted = manifestFixture('ungranted').load()
assert.equal(ungranted.maySetProfile, null)
assert.equal(queueProfile(ungranted, { fields: { about: 'no grant' } }).error.code, 'NVOY_PROFILE_NOT_PERMITTED')
assert(profileToolSpec(manifest).description.includes(grant.grant_id))
assert(profileToolSpec(manifest).description.includes('nave.pub'))
assert(capabilitySummary(manifest).includes('per rolling 24 hours'))
assert(!Object.hasOwn(profileToolSpec(manifest).inputSchema.properties, 'kind'))
assert(!Object.hasOwn(profileToolSpec(manifest).inputSchema.properties, 'pubkey'))
assert.throws(() => manifestFixture('bad-kind', { may_set_profile: { ...grant, kind: 9 } }).load(), /scope kind 0/)
assert.throws(() => manifestFixture('bad-key', { may_set_profile: { ...grant, pubkey: other } }).load(), /manifest pubkey/)
assert.throws(() => manifestFixture('bad-mode', { may_set_profile: grant, worker_enabled: true,
  worker_image: 'example@sha256:' + 'a'.repeat(64), worker_runner: 'codex', worker_credential_ref: '/fake/model' }).load(), /headless delivery|worker-disabled/)

const scope = { pubkey, pictureHosts: ['nave.pub'] }
const current = { name: 'grok', about: 'old', custom: 'keep', bot: false }
const merged = await mergedProfile(current, { about: 'new' }, scope)
assert.deepEqual(merged.profile, { name: 'grok', about: 'new', custom: 'keep', bot: true })
assert.deepEqual(merged.changed.about, { old: 'old', new: 'new' })
assert.deepEqual(merged.changed.bot, { old: false, new: true })
await assert.rejects(mergedProfile(current, { picture: 'https://other.example/avatar.png' }, scope), error => error.code === 'NVOY_PROFILE_BAD_PICTURE')
await assert.rejects(mergedProfile(current, { nip05: 'grok@nave.pub' }, {
  ...scope, fetchJson: async () => ({ names: { grok: other } }),
}), error => error.code === 'NVOY_PROFILE_NIP05_MISMATCH')
await assert.rejects(mergedProfile(current, { bad: 'field' }, scope), error => error.code === 'NVOY_PROFILE_BAD_FIELDS')
await assert.rejects(mergedProfile(current, { about: 'x'.repeat(1025) }, scope), error => error.code === 'NVOY_PROFILE_FIELD_TOO_LONG')
await assert.rejects(mergedProfile({ ...current, picture: 'https://other.example/avatar.png' }, { about: 'new' }, scope),
  error => error.code === 'NVOY_PROFILE_BAD_PICTURE')
await assert.rejects(mergedProfile({ ...current, about: `sk-${'A'.repeat(24)}` }, { name: 'grok' }, scope),
  error => error.code === 'NVOY_WITHHELD_CREDENTIAL')
const signed = finalizeEvent({ kind: 0, created_at: 2, tags: [], content: JSON.stringify(merged.profile) }, secret)
assert.equal(readbackProfile([signed], signed, merged.profile).about.match, true)
assert.throws(() => readbackProfile([], signed, merged.profile), error => error instanceof ProfileRefusal && error.code === 'NVOY_PROFILE_READBACK_MISMATCH')

writeFileSync(join(fixture.directory, 'run', 'profile-requests.jsonl'), '')
writeFileSync(join(fixture.directory, 'run', 'profile-results.jsonl'), '')
mkdirSync(join(fixture.directory, 'run', 'profile-request-ids'), { mode: 0o700 })
assert.equal(queueProfile(manifest, { fields: { about: `sk-${'A'.repeat(24)}` } }).error.code, 'NVOY_WITHHELD_CREDENTIAL')
const repeated = queueProfile(manifest, { request: 'cd'.repeat(16), fields: { about: 'same' } })
assert.equal(repeated.ok.request, 'cd'.repeat(16))
assert.equal(queueProfile(manifest, { request: 'cd'.repeat(16), fields: { about: 'same' } }).ok.repeat, true)
assert.equal(queueProfile(manifest, { request: 'cd'.repeat(16), fields: { about: 'different' } }).error.code, 'NVOY_PROFILE_REQUEST_CONFLICT')
const concurrentId = 'ef'.repeat(16)
const enqueueScript = `import { readManifest } from './mcp/tools/runtime_manifest.mjs';
import { queueProfile } from './mcp/tools/agent_profile.mjs';
console.log(JSON.stringify(queueProfile(readManifest(process.env.NVOY_TEST_ROOT, 'seat'),
  { request: process.env.NVOY_TEST_REQUEST, fields: { about: process.env.NVOY_TEST_ABOUT } })))`
const enqueue = about => new Promise(resolve => {
  const child = spawn(process.execPath, ['--input-type=module', '-e', enqueueScript],
    { cwd: new URL('..', import.meta.url).pathname, env: { ...process.env, NVOY_TEST_ROOT: fixture.root,
      NVOY_TEST_REQUEST: concurrentId, NVOY_TEST_ABOUT: about }, stdio: ['ignore', 'pipe', 'pipe'] })
  let output = '', error = ''
  child.stdout.on('data', chunk => { output += chunk })
  child.stderr.on('data', chunk => { error += chunk })
  child.on('exit', status => resolve({ status, result: output ? JSON.parse(output) : null, error }))
})
const concurrent = await Promise.all([enqueue('first'), enqueue('second')])
assert(concurrent.every(attempt => attempt.status === 0), JSON.stringify(concurrent))
assert.equal(concurrent.filter(attempt => attempt.result.ok).length, 1)
assert.equal(concurrent.filter(attempt => attempt.result.error?.code === 'NVOY_PROFILE_REQUEST_CONFLICT').length, 1)
assert.equal(readFileSync(join(fixture.directory, 'run', 'profile-requests.jsonl'), 'utf8').split('\n')
  .filter(line => line.includes(concurrentId)).length, 1)
writeFileSync(join(fixture.directory, 'run', 'profile-requests.jsonl'), '')
const credential = join(root, 'credential')
writeFileSync(credential, Buffer.from(secret).toString('hex'))
const runBroker = (extraEnv = {}) => new Promise(resolve => {
  const child = spawn(process.execPath, ['mcp/tools/instance-broker-profile.mjs', '--instance', 'seat', '--request', lastRequest],
    { cwd: new URL('..', import.meta.url).pathname, env: { ...process.env, NVOY_INSTANCE_ROOT: fixture.root, NVOY_BROKER_CREDENTIAL: credential, ...extraEnv },
      stdio: ['ignore', 'pipe', 'pipe'] })
  let stderr = ''
  child.stderr.on('data', chunk => { stderr += chunk })
  child.on('exit', status => resolve({ status, stderr }))
})
let lastRequest
const submit = args => {
  const queued = queueProfile(manifest, args)
  assert(queued.ok, JSON.stringify(queued.error))
  lastRequest = queued.ok.request
  return lastRequest
}
submit({ fields: { picture: 'https://other.example/avatar.png' }, dry_run: true })
assert.equal((await runBroker()).status, 0)
assert.equal(profileStatus(manifest, lastRequest).error.code, 'NVOY_PROFILE_BAD_PICTURE')
assert.equal(sent.length, 0)
submit({ fields: { about: 'dry' }, dry_run: true })
assert.equal((await runBroker()).status, 0)
assert.equal(profileStatus(manifest, lastRequest).ok.candidate.custom, 'keep')
assert.equal(profileStatus(manifest, lastRequest).ok.candidate.bot, true)
assert.equal(sent.length, 0)
submit({ fields: { about: 'published' } })
assert.equal((await runBroker()).status, 0)
const published = profileStatus(manifest, lastRequest).ok
assert.equal(published.event_id, sent.at(-1).id)
assert.equal(published.relay.accepted, true)
assert.equal(published.readback.custom.match, true)
assert.equal(JSON.parse(sent.at(-1).content).custom, 'keep')
submit({ fields: { about: 'too soon' } })
assert.equal((await runBroker()).status, 0)
assert.equal(profileStatus(manifest, lastRequest).error.code, 'NVOY_PROFILE_RATE_LIMITED')
const audit = readFileSync(join(fixture.directory, 'state', 'profile-audit.jsonl'), 'utf8').trim().split('\n').map(JSON.parse)
assert.equal(audit.length, 4)
assert.equal(audit[2].grant_id, grant.grant_id)
assert.equal(audit[2].changed.about.old, 'old')
assert.equal(audit[2].changed.about.new, 'published')

const manifestPath = join(fixture.root, 'seat.json')
const savedManifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
savedManifest.may_set_profile.per_day = 2
writeFileSync(manifestPath, JSON.stringify(savedManifest))
submit({ fields: { about: 'retry' } })
dropNext = true
assert.equal((await runBroker()).status, 1)
const firstAttempt = sent.at(-1).id
assert.equal(profileStatus(manifest, lastRequest).ok.pending, true)
assert.equal((await runBroker()).status, 0)
assert.equal(sent.at(-1).id, firstAttempt)
assert.equal(profileStatus(manifest, lastRequest).ok.event_id, firstAttempt)

savedManifest.may_set_profile.per_day = 3
writeFileSync(manifestPath, JSON.stringify(savedManifest))
submit({ fields: { about: 'tamper check' } })
dropNext = true
assert.equal((await runBroker()).status, 1)
const tamperRecordPath = join(fixture.directory, 'state', 'profiles', `${lastRequest}.json`)
const originalRecord = JSON.parse(readFileSync(tamperRecordPath, 'utf8'))
const sentBeforeTamper = sent.length
for (const change of [
  altered => { altered.unsigned_event.kind = 9 },
  altered => { altered.unsigned_event.pubkey = other },
  altered => { altered.unsigned_event.tags = [['x', 'out-of-scope']] },
  altered => { altered.unsigned_event.content = JSON.stringify({ about: 'not validated' }) },
  altered => { altered.profile.custom = 'forged'; altered.unsigned_event.content = JSON.stringify(altered.profile) },
  altered => { altered.profile.custom = `sk-${'B'.repeat(24)}`; altered.unsigned_event.content = JSON.stringify(altered.profile) },
  altered => { altered.current_event.content = JSON.stringify({ name: 'forged' }) },
]) {
  const altered = structuredClone(originalRecord)
  altered.event = null
  change(altered)
  altered.fingerprint = getEventHash(altered.unsigned_event)
  writeFileSync(tamperRecordPath, JSON.stringify(altered))
  assert.equal((await runBroker()).status, 0)
  assert.equal(profileStatus(manifest, lastRequest).error.code, 'NVOY_PROFILE_RECORD_INVALID')
  assert.equal(sent.length, sentBeforeTamper)
}
writeFileSync(tamperRecordPath, JSON.stringify(originalRecord))
assert.equal((await runBroker()).status, 0)
assert.equal(profileStatus(manifest, lastRequest).ok.event_id, originalRecord.event.id)

savedManifest.may_set_profile.per_day = 4
writeFileSync(manifestPath, JSON.stringify(savedManifest))
submit({ fields: { about: 'mismatch' } })
mismatchNext = true
assert.equal((await runBroker()).status, 0)
assert.equal(profileStatus(manifest, lastRequest).error.code, 'NVOY_PROFILE_READBACK_MISMATCH')
mismatchNext = false
const auditAfter = readFileSync(join(fixture.directory, 'state', 'profile-audit.jsonl'), 'utf8').trim().split('\n').map(JSON.parse)
assert.equal(auditAfter.at(-1).outcome, 'NVOY_PROFILE_READBACK_MISMATCH')
const savedEvents = stored
stored = []
submit({ fields: { about: 'missing current' }, dry_run: true })
assert.equal((await runBroker()).status, 0)
assert.equal(profileStatus(manifest, lastRequest).error.code, 'NVOY_PROFILE_INVALID_CURRENT')
stored = savedEvents
const fetchStub = join(root, 'nip05-mismatch.mjs')
writeFileSync(fetchStub, `globalThis.fetch = async () => ({ ok: true, json: async () => ({ names: { grok: '${other}' } }) })\n`)
submit({ fields: { nip05: 'grok@nave.pub' }, dry_run: true })
assert.equal((await runBroker({ NODE_OPTIONS: `--import=${fetchStub}` })).status, 0)
assert.equal(profileStatus(manifest, lastRequest).error.code, 'NVOY_PROFILE_NIP05_MISMATCH')

await new Promise(resolve => websocket.close(resolve))
await new Promise(resolve => server.close(resolve))
console.log('profile-set: manifest, validation, NIP-05, dry run, publish/readback, rate limit, retry and audit pass')
