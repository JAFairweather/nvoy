// A broker restart must not re-spawn a keyed child for every post and reply it has already published
// (q-108, 15 Nov 2026). The daemon's done sets were memory only and only refusals were logged, so after
// each restart drainPosts started one instance-broker-post.mjs per id ever queued (486 on one seat),
// each reaching its replay exit only after an attention policy child for an off-list mention. The
// daemon now reads each child's own durable record in process (broker_done.mjs) before any spawn.
//
// The daemon runs for real, under a preload that logs every child it starts.
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey } from 'nostr-tools/pure'
import { replyRequestDigest } from '../mcp/tools/outbound_record.mjs'
import { firstRows, postPublished, replyFinished } from '../mcp/tools/broker_done.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const sleep = ms => new Promise(r => setTimeout(r, ms))
const until = async (fn, ms = 20000) => { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(100) } return false }
const hex = n => randomBytes(n).toString('hex')

const CH = '3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607'
const agentSk = generateSecretKey(), agent = getPublicKey(agentSk)
const listed = getPublicKey(generateSecretKey()), offList = getPublicKey(generateSecretKey())
const root = mkdtempSync(join(tmpdir(), 'nvoy-replay-done-'))
const instances = join(root, 'instances'), state = join(root, 'state'), run = join(root, 'run'), spool = join(root, 'spool')
for (const d of [instances, state, run, spool, join(state, 'posts'), join(state, 'receipts')]) mkdirSync(d, { recursive: true, mode: 0o700 })
const gid = process.getgid(), uid = process.getuid()
writeFileSync(join(instances, 'replay.json'), JSON.stringify({ version: 1, id: 'replay', pubkey: agent, broker_mode: 'local',
  key_ref: '/etc/nvoy/credentials/replay.nsec', worker_enabled: false, delivery_mode: 'notify_only',
  state_dir: state, runtime_dir: run, spool_dir: spool,
  broker_adapter_gid: gid, worker_handoff_gid: gid + 1, watcher_uid: uid + 11, broker_uid: uid + 12, adapter_uid: uid + 13, worker_uid: uid + 14,
  grantors: ['4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'], relays: ['wss://127.0.0.1:1'],
  buzz: { relay: 'ws://127.0.0.1:1', channels: [CH] }, may_post: { channels: [CH], per_hour: 30, mention: [listed] } }))
const credential = join(root, 'agent.key'); writeFileSync(credential, Buffer.from(agentSk).toString('hex'), { mode: 0o600 })

// --- the queues, as a seat that has posted and replied for weeks leaves them ---
const postRow = mention => ({ version: 1, type: 'post-request', id: hex(16), instance: 'replay', channel: CH, mention, content: 'hello', requested_at: Date.now() })
const publish = (row, extra = {}) => {
  const unsigned = { pubkey: agent, kind: 9, created_at: Math.floor(Date.now() / 1000), content: row.content, tags: [['h', CH]] }
  writeFileSync(join(state, 'posts', `${row.id}.json`), JSON.stringify({ version: 1, request_id: row.id, request_digest: replyRequestDigest(row),
    fingerprint: getEventHash(unsigned), unsigned_event: unsigned, event: null, published: true, published_at: Date.now(), accepted: 1, ...extra }), { mode: 0o600 })
}
const N = 20
const normal = Array.from({ length: N }, () => postRow([listed]))
const offListed = Array.from({ length: N }, () => postRow([offList]))
for (const row of [...normal, ...offListed]) publish(row)
const pending = postRow([listed])                       // never published: its child must still run
const unbound = postRow([listed]); publish(unbound, { request_digest: 'ab'.repeat(32) })  // a record for some other row
const linked = postRow([listed]); publish(linked)
const linkedPath = join(state, 'posts', `${linked.id}.json`), aside = join(root, 'aside.json')
writeFileSync(aside, readFileSync(linkedPath)); writeFileSync(linkedPath, '');
await import('node:fs').then(fs => { fs.rmSync(linkedPath); symlinkSync(aside, linkedPath) })
// Bound and marked published, but not a record the child would replay (My Dude, PR 410 review): the
// daemon must not call any of these done; the child refuses each as not binding its request.
const signedPost = postRow([listed]); publish(signedPost)
{ const p = join(state, 'posts', `${signedPost.id}.json`), r = JSON.parse(readFileSync(p, 'utf8'))
  writeFileSync(p, JSON.stringify({ ...r, event: finalizeEvent({ ...r.unsigned_event }, agentSk) })) }
const malformed = {
  'no unsigned event': [postRow([listed]), r => ({ ...r, unsigned_event: null })],
  'a fingerprint that is not its hash': [postRow([listed]), r => ({ ...r, fingerprint: 'cd'.repeat(32) })],
  'a signed event with a bad signature': [postRow([listed]), r => ({ ...r, event: { ...finalizeEvent({ ...r.unsigned_event }, agentSk), sig: '00'.repeat(64) } })],
  'a signed event that is another event': [postRow([listed]), r => ({ ...r, event: finalizeEvent({ ...r.unsigned_event, content: 'other' }, agentSk) })],
}
for (const [row, change] of Object.values(malformed)) {
  publish(row)
  const p = join(state, 'posts', `${row.id}.json`)
  writeFileSync(p, JSON.stringify(change(JSON.parse(readFileSync(p, 'utf8')))))
}
const malformedRows = Object.values(malformed).map(([row]) => row)
const posts = [...normal, ...offListed, pending, unbound, linked, signedPost, ...malformedRows]
// A repeated id: the child takes the first line, and so does the daemon.
writeFileSync(join(run, 'post-requests.jsonl'), [...posts, { ...normal[0], content: 'a later line for the same id' }].map(r => JSON.stringify(r)).join('\n') + '\n{"id":')

const replyRow = () => ({ version: 1, type: 'reply-request', id: hex(16), instance: 'replay', receipt: hex(32), content: 'thanks' })
const replied = Array.from({ length: N }, replyRow)
for (const row of replied) writeFileSync(join(state, 'receipts', `${row.receipt}.${row.id}.used`), '{}', { mode: 0o600 })
const replyPending = replyRow()
writeFileSync(join(run, 'reply-requests.jsonl'), [...replied, replyPending].map(r => JSON.stringify(r)).join('\n') + '\n')

// --- the checks on their own ---
ok('a published, bound post record is done', normal.every(r => postPublished(state, r)) && offListed.every(r => postPublished(state, r)))
ok('an unpublished post is not done', !postPublished(state, pending))
ok('a record bound to another row is not done', !postPublished(state, unbound))
ok('a symlinked record is not done', !postPublished(state, linked))
ok('a record for a different id is not done', !postPublished(state, { ...normal[0], id: hex(16) }))
ok('a published record carrying its valid signed event is done', postPublished(state, signedPost))
for (const [what, [row]] of Object.entries(malformed)) ok(`a bound, published record with ${what} is not done`, !postPublished(state, row))
ok('a changed row no longer matches its record', !postPublished(state, { ...normal[0], content: 'edited' }))
ok('a malformed id reads nothing', !postPublished(state, { ...normal[0], id: '../x' }) && !replyFinished(state, { ...replied[0], id: '../x' }))
ok('a reply whose receipt was used is done', replied.every(r => replyFinished(state, r)))
ok('a reply still holding its receipt is not done', !replyFinished(state, replyPending))
ok('a reply with a malformed receipt is not done', !replyFinished(state, { ...replied[0], receipt: '../../x' }))
const firsts = firstRows(readFileSync(join(run, 'post-requests.jsonl'), 'utf8'))
ok('the first row of a repeated id is the one kept, and a partial line is skipped', firsts.size === posts.length && firsts.get(normal[0].id).content === 'hello')

// --- the daemon, restarted over that state ---
const hook = join(root, 'spawn-log.mjs'), spawnLog = join(root, 'spawns.jsonl')
writeFileSync(hook, `import cp from 'node:child_process'
import { syncBuiltinESMExports } from 'node:module'
import { appendFileSync } from 'node:fs'
for (const name of ['spawn', 'spawnSync']) {
  const real = cp[name]
  cp[name] = (cmd, args, ...rest) => { appendFileSync(${JSON.stringify(spawnLog)}, JSON.stringify((args || []).map(String)) + '\\n'); return real(cmd, args, ...rest) }
}
syncBuiltinESMExports()
`)
writeFileSync(spawnLog, '')
const spawned = () => readFileSync(spawnLog, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l))
const childrenFor = (script, id) => spawned().filter(a => a[0].endsWith(script) && a.includes(id)).length

async function restart(round) {
  let log = ''
  const daemon = spawn(process.execPath, ['--import', hook, 'mcp/tools/instance-broker-daemon.mjs', '--instance', 'replay'], { stdio: ['ignore', 'pipe', 'pipe'], detached: true,
    env: { PATH: process.env.PATH, NVOY_INSTANCE_ROOT: instances, NVOY_BROKER_CREDENTIAL: credential, NVOY_PRESENCE_DIR: join(root, 'no-presence') } })
  daemon.stdout.on('data', c => { log += c }); daemon.stderr.on('data', c => { log += c })
  // Round 1 must also reach the reply still pending; it ends terminal (no receipt), so round 2 does not.
  const started = await until(() => childrenFor('instance-broker-post.mjs', pending.id) >= 1 &&
    (round > 1 || malformedRows.every(r => childrenFor('instance-broker-post.mjs', r.id) >= 1)) &&
    (round > 1 || childrenFor('instance-broker-reply.mjs', replyPending.id) >= 1))
  await sleep(2500)                                      // two more drain ticks over the same queues
  try { process.kill(-daemon.pid, 'SIGKILL') } catch { /* gone */ }  // the daemon and its supervised children
  await sleep(300)
  return { started, log }
}
for (const round of [1, 2]) {
  writeFileSync(spawnLog, '')
  const { started, log } = await restart(round)
  ok(`restart ${round}: the daemon ran and started children for the work still pending`, started)
  if (!started) console.log(log.slice(-2000))
  ok(`restart ${round}: zero post children for ${N} published posts`, normal.every(r => childrenFor('instance-broker-post.mjs', r.id) === 0))
  ok(`restart ${round}: zero post children for ${N} published posts with an off-list mention`, offListed.every(r => childrenFor('instance-broker-post.mjs', r.id) === 0))
  ok(`restart ${round}: no attention policy child at all`, !spawned().some(a => a[0].endsWith('attention.mjs')))
  ok(`restart ${round}: zero reply children for ${N} published replies`, replied.every(r => childrenFor('instance-broker-reply.mjs', r.id) === 0))
  ok(`restart ${round}: zero post children for a published record with its signed event`, childrenFor('instance-broker-post.mjs', signedPost.id) === 0)
  if (round === 1) {
    ok('restart 1: an unbound or symlinked record still goes to the child, which decides',
      childrenFor('instance-broker-post.mjs', unbound.id) >= 1 && childrenFor('instance-broker-post.mjs', linked.id) >= 1)
    ok('restart 1: every bound, published record the child would not replay goes to the child',
      malformedRows.every(r => childrenFor('instance-broker-post.mjs', r.id) >= 1))
  }
  else {
    // The child refused the unbound record as terminal, durably; the symlink is only held for retry.
    ok('restart 2: the unbound record, refused as terminal, stays refused with no child', childrenFor('instance-broker-post.mjs', unbound.id) === 0)
    ok('restart 2: the symlinked record, held for retry, still goes to the child', childrenFor('instance-broker-post.mjs', linked.id) >= 1)
  }
}

// --- the post child alone: a published post with an off-list mention replays before any policy child ---
writeFileSync(spawnLog, '')
const child = await new Promise(resolve => {
  const c = spawn(process.execPath, ['--import', hook, 'mcp/tools/instance-broker-post.mjs', '--instance', 'replay', '--request', offListed[0].id],
    { stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: process.env.PATH, NVOY_INSTANCE_ROOT: instances, NVOY_BROKER_CREDENTIAL: credential } })
  let stdout = ''; c.stdout.on('data', d => { stdout += d }); c.on('exit', status => resolve({ status, stdout }))
})
ok('the post child replays a published off-list post with exit 0', child.status === 0 && /"replay":true/.test(child.stdout))
ok('and starts no attention policy child to get there', spawned().length === 0)
ok('the replay leaves the record as it was', existsSync(join(state, 'posts', `${offListed[0].id}.json`)) && postPublished(state, offListed[0]))

console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
