import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawn, spawnSync } from 'node:child_process'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { z } from 'zod'

let passed = 0, failed = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passed++ : failed++ }
const root = mkdtempSync(join(tmpdir(), 'nvoy-claude-channel-'))
const manifests = join(root, 'instances'), runtime = join(root, 'runtime')
mkdirSync(manifests); mkdirSync(runtime)
const uid = process.getuid(), gid = process.getgid()
const manifest = {
  version: 1, id: 'claude-test', pubkey: '1'.repeat(64), broker_mode: 'local',
  state_dir: join(root, 'state'), runtime_dir: runtime, spool_dir: join(root, 'spool'),
  bunker_uri_ref: '/etc/nvoy/test.bunker', bunker_client_ref: '/etc/nvoy/test.client',
  worker_enabled: false, delivery_mode: 'notify_only',
  broker_adapter_gid: gid, worker_handoff_gid: gid + 1,
  watcher_uid: uid + 11, broker_uid: uid + 12, adapter_uid: uid + 13, worker_uid: uid,
  grantors: ['2'.repeat(64)], relays: ['wss://nos.lol'],
}
writeFileSync(join(manifests, 'claude-test.json'), JSON.stringify(manifest))
const envelope = '3'.repeat(64)
const task = { type: 'admitted-task', instance: manifest.id, envelope,
  authority: { version: 1, type: 'scoped-instruction', sender: '4'.repeat(64), grant_id: '5'.repeat(64),
    grantor: manifest.grantors[0], cap: 'task', scope_subject: manifest.pubkey, policy_checked_at: Date.now() },
  messages: [{ from: '4'.repeat(64), at: 1785880000, content: 'inspect the queue' }] }
const notificationEnvelope = '7'.repeat(64)
const notification = { type: 'verified-notification', instance: manifest.id, envelope: notificationEnvelope,
  notification: { version: 1, type: 'verified-channel-activity', source_author: '6'.repeat(64),
    source_event: '5'.repeat(64), source_channel: 'a8186b53-537d-46ad-a7e7-b6486c58970e',
    carrier: '4'.repeat(64), carrier_grant_id: '3'.repeat(64), carrier_grantor: manifest.grantors[0],
    reason: 'mention', observed_at: Date.now() } }
manifest.task_carriers = [{ pubkey: notification.notification.carrier, channels: [notification.notification.source_channel] }]
writeFileSync(join(manifests, 'claude-test.json'), JSON.stringify(manifest))
writeFileSync(join(runtime, 'admitted-tasks.jsonl'), JSON.stringify(task) + '\n' + JSON.stringify(notification) + '\n', { mode: 0o600 })
mkdirSync(join(runtime, 'claude-channel-state'))
writeFileSync(join(runtime, 'reply-requests.jsonl'), '', { mode: 0o640 })

const transport = new StdioClientTransport({ command: process.execPath,
  args: [resolve('mcp/tools/claude-channel.mjs'), '--instance', manifest.id, '--poll-ms', '250'],
  env: { ...process.env, NVOY_INSTANCE_ROOT: manifests }, stderr: 'pipe' })
const client = new Client({ name: 'claude-channel-test', version: '0.1.0' })
const Channel = z.object({ method: z.literal('notifications/claude/channel'), params: z.object({
  content: z.string(), meta: z.record(z.string()),
}) })
const wakes = []
const arrived = new Promise(resolveWake => client.setNotificationHandler(Channel, notification => {
  wakes.push(notification.params); resolveWake()
}))

try {
  await client.connect(transport)
  await Promise.race([arrived, new Promise((_, reject) => setTimeout(() => reject(new Error('channel notification timed out')), 4000))])
  ok('the channel emits only an opaque marker, never sender or message content',
    wakes.length >= 1 && wakes.every(wake => wake?.meta?.instance === manifest.id &&
      [envelope, notificationEnvelope].includes(wake?.meta?.envelope) &&
      !JSON.stringify(wake).includes(task.messages[0].content) && !JSON.stringify(wake).includes(task.messages[0].from)))
  const tools = (await client.listTools()).tools.map(tool => tool.name)
  ok('Claude receives an explicit read tool, a receipt-bound reply tool, and a body-free discovery tool',
    tools.length === 3 && tools.includes('nvoy_channel_read') && tools.includes('nvoy_channel_reply') &&
    tools.includes('nvoy_channel_list'))
  const duplicateProcess = spawnSync(process.execPath, [resolve('mcp/tools/claude-channel.mjs'), '--instance', manifest.id, '--baseline'],
    { encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifests } })
  ok('a second Claude session cannot bind the same participant identity',
    duplicateProcess.status !== 0 && /already runs as pid/.test(duplicateProcess.stderr))
  const read = await client.callTool({ name: 'nvoy_channel_read', arguments: { envelope } })
  const body = JSON.parse(read.content[0].text)
  ok('the exact marker reads only its broker-validated task and authority',
    body.envelope === envelope && body.authority.sender === task.authority.sender && body.messages[0].content === task.messages[0].content)
  const noticeRead = await client.callTool({ name: 'nvoy_channel_read', arguments: { envelope: notificationEnvelope } })
  const noticeBody = JSON.parse(noticeRead.content[0].text)
  ok('a content-free verified notification remains readable without acquiring instruction authority',
    noticeBody.envelope === notificationEnvelope && noticeBody.authority === null &&
    noticeBody.notification.source_event === notification.notification.source_event && !('messages' in noticeBody))
  const noticeReply = await client.callTool({ name: 'nvoy_channel_reply', arguments: { envelope: notificationEnvelope, text: 'cannot reply' } })
  ok('a content-free activity notification cannot acquire reply authority', noticeReply.isError === true)
  const unknown = await client.callTool({ name: 'nvoy_channel_read', arguments: { envelope: '9'.repeat(64) } })
  ok('an envelope that was not delivered through this channel is unreadable', unknown.isError === true)
  const reply = await client.callTool({ name: 'nvoy_channel_reply', arguments: { envelope, text: 'queue inspected' } })
  const queued = JSON.parse(reply.content[0].text)
  const requests = readFileSync(join(runtime, 'reply-requests.jsonl'), 'utf8').trim().split('\n').map(JSON.parse)
  ok('reply tooling writes only envelope + bounded text; it cannot choose a recipient',
    queued.queued === true && requests.length === 1 && requests[0].receipt === envelope &&
    requests[0].content === 'queue inspected' && !('recipient' in requests[0]) && !('channel' in requests[0]))
  const duplicate = await client.callTool({ name: 'nvoy_channel_reply', arguments: { envelope, text: 'again' } })
  ok('one delivered envelope cannot queue a second reply', duplicate.isError === true && readFileSync(join(runtime, 'reply-requests.jsonl'), 'utf8').trim().split('\n').length === 1)
} finally { await client.close() }

const historicalEnvelope = '8'.repeat(64)
writeFileSync(join(runtime, 'admitted-tasks.jsonl'), JSON.stringify(task) + '\n' +
  JSON.stringify({ ...task, envelope: historicalEnvelope }) + '\n', { mode: 0o600 })
const baseline = spawnSync(process.execPath, [resolve('mcp/tools/claude-channel.mjs'), '--instance', manifest.id, '--baseline'],
  { encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: manifests } })
const readLog = readFileSync(join(runtime, 'claude-channel-state', 'read.jsonl'), 'utf8')
ok('one-time baseline records an old queue entry without launching a channel or reply',
  baseline.status === 0 && /baselined 1 existing/.test(baseline.stdout) && readLog.includes(historicalEnvelope) &&
  readFileSync(join(runtime, 'reply-requests.jsonl'), 'utf8').trim().split('\n').length === 1)

// #168 — a channel whose client is gone must release the lock by itself. The production case is an
// SSH forced command `docker exec -i`ing this process: when the SSH session drops, the shim holds
// the stdin pipe open, so no EOF ever arrives and the PID stays genuinely alive. The lock's
// liveness reclaim is therefore correct and useless, and the lane stays bricked until an operator
// intervenes. Both halves are asserted, because a fix that only evicts is a fix that evicts
// everyone.
const lockPath = join(runtime, 'claude-channel-state', 'channel.lock')
const abandoned = spawn(process.execPath, [resolve('mcp/tools/claude-channel.mjs'), '--instance', manifest.id,
  '--poll-ms', '250', '--handshake-ms', '1000', '--heartbeat-ms', '1000', '--heartbeat-misses', '2'],
  { env: { ...process.env, NVOY_INSTANCE_ROOT: manifests }, stdio: ['pipe', 'pipe', 'pipe'] })
let abandonedStderr = ''
abandoned.stderr.on('data', chunk => { abandonedStderr += chunk })
const abandonedExit = await Promise.race([
  new Promise(resolveExit => abandoned.on('exit', code => resolveExit(code))),
  new Promise(resolveExit => setTimeout(() => resolveExit('TIMEOUT'), 8000)),
])
if (abandonedExit === 'TIMEOUT') abandoned.kill('SIGKILL')
ok('a channel that no MCP client ever spoke to releases its lock instead of stranding the lane',
  abandonedExit === 0 && /no MCP client initialised/.test(abandonedStderr) && !existsSync(lockPath))

// Negative control. Without this, "releases the lock" is indistinguishable from "exits on a timer",
// which would replace a stuck lane with one that dies under a working session — a real session is
// legitimately silent for hours, so silence must never be the eviction signal. A live client is
// silent here for well past heartbeat-ms × heartbeat-misses and must survive on ping alone.
//
// Surviving is necessary but NOT sufficient, and asserting only survival is how this test read
// before review: the code resets `misses` on any non-timeout error, so a build whose ping
// round-trip was wholly broken — capability rejection, schema drift, a client with no ping at all —
// would take that same branch and pass under a name claiming the pong arrived. The pong is
// therefore observed directly, on stderr, as well as the survival.
//
// `--handshake-ms 1000` is deliberately shorter than the wait: a client that DID initialise must
// not be caught by the handshake arm, which is the whole point of splitting the two knobs.
const liveTransport = new StdioClientTransport({ command: process.execPath,
  args: [resolve('mcp/tools/claude-channel.mjs'), '--instance', manifest.id,
    '--poll-ms', '250', '--handshake-ms', '1000', '--heartbeat-ms', '1000', '--heartbeat-misses', '2'],
  env: { ...process.env, NVOY_INSTANCE_ROOT: manifests }, stderr: 'pipe' })
const liveClient = new Client({ name: 'claude-channel-heartbeat', version: '0.1.0' })
// An evicted session makes listTools() throw rather than return, so the failure has to be caught
// and reported. Letting it propagate would abort the run with no verdict printed for this case —
// a suite that says nothing about the property it exists to defend.
let liveStderr = ''
try {
  await liveClient.connect(liveTransport)
  liveTransport.stderr?.on('data', chunk => { liveStderr += chunk })
  await new Promise(done => setTimeout(done, 3500))
  const stillThere = (await liveClient.listTools()).tools.map(tool => tool.name)
  ok('a client that is merely idle answers the ping and is never evicted',
    stillThere.includes('nvoy_channel_read') && existsSync(lockPath))
  ok('the pong is OBSERVED, not merely survived — a broken round-trip cannot pass as a live one',
    /answered the first heartbeat ping/.test(liveStderr))
  ok('an initialised client is not caught by the handshake arm', !/no MCP client initialised/.test(liveStderr))
} catch (error) {
  ok(`a client that is merely idle answers the ping and is never evicted (evicted: ${error.message})`, false)
  ok('the pong is OBSERVED, not merely survived — a broken round-trip cannot pass as a live one', false)
  ok('an initialised client is not caught by the handshake arm', false)
} finally { try { await liveClient.close() } catch { /* already gone */ } }

// `nvoy_channel_list` exists for harnesses that never receive `notifications/claude/channel` — the
// only source of an envelope marker until now, which left a non-Claude-Code client blind by
// construction. These cases run on their own instance so the lock, the queue and the in-memory
// disclosure state are all independent of the assertions above.
const listId = 'claude-list-test'
const listRuntime = join(root, 'list-runtime')
mkdirSync(listRuntime); mkdirSync(join(listRuntime, 'claude-channel-state'))
const listPubkey = 'd'.repeat(64)
const listManifest = { ...manifest, id: listId, pubkey: listPubkey, runtime_dir: listRuntime,
  state_dir: join(root, 'list-state'), spool_dir: join(root, 'list-spool') }
// Each instance is a distinct identity and the tool refuses a shared pubkey, so the task authority
// is re-scoped to the new subject rather than copied wholesale.
const listTask = { ...task, instance: listId, authority: { ...task.authority, scope_subject: listPubkey } }
writeFileSync(join(manifests, `${listId}.json`), JSON.stringify(listManifest))
const seeded = 'b'.repeat(64), unlisted = 'c'.repeat(64)
writeFileSync(join(listRuntime, 'admitted-tasks.jsonl'),
  JSON.stringify({ ...listTask, envelope: seeded }) + '\n', { mode: 0o600 })
writeFileSync(join(listRuntime, 'reply-requests.jsonl'), '', { mode: 0o640 })

// A 60s poll means the initial `oninitialized` poll is the ONLY announcement in this window, so an
// envelope appended after connect cannot reach `notifiedThisRun`. That is what isolates the
// disclosure arm: without it the read below would pass on the notification path and prove nothing.
const discoverTransport = new StdioClientTransport({ command: process.execPath,
  args: [resolve('mcp/tools/claude-channel.mjs'), '--instance', listId, '--poll-ms', '60000'],
  env: { ...process.env, NVOY_INSTANCE_ROOT: manifests }, stderr: 'pipe' })
const discoverClient = new Client({ name: 'claude-channel-list', version: '0.1.0' })
// `connect()` resolves on the initialize RESPONSE, but the server's first poll is driven by the
// client's `initialized` NOTIFICATION, which lands a moment later. Appending before that poll has
// run lets it announce the new envelope, and the disclosure arm is then never exercised — the case
// passes on the notification path while claiming to prove discovery. Wait for the seeded
// announcement, which is the observable proof the initial poll is done; the next one is 60s away.
const seededSeen = new Promise(resolve => discoverClient.setNotificationHandler(Channel,
  note => { if (note.params?.meta?.envelope === seeded) resolve() }))
let discoverStderr = ''
discoverTransport.stderr?.on('data', chunk => { discoverStderr += chunk })
try {
  await discoverClient.connect(discoverTransport)
  await Promise.race([seededSeen,
    new Promise((_, reject) => setTimeout(() => reject(new Error('initial poll never announced the seeded envelope')), 4000))])
  appendFileSync(join(listRuntime, 'admitted-tasks.jsonl'),
    JSON.stringify({ ...listTask, envelope: unlisted }) + '\n', { mode: 0o600 })
  const blocked = await discoverClient.callTool({ name: 'nvoy_channel_read', arguments: { envelope: unlisted } })
  ok('an envelope that was never announced is unreadable before it is listed',
    blocked.isError === true && /NVOY_NOT_DELIVERED/.test(blocked.content[0].text))
  const listed = await discoverClient.callTool({ name: 'nvoy_channel_list', arguments: {} })
  const markers = JSON.parse(listed.content[0].text)
  ok('a no-argument list dispatches above the envelope validation instead of being refused',
    listed.isError !== true && Array.isArray(markers.envelopes))
  ok('list returns opaque markers only — never a body, a sender, or an authority',
    markers.envelopes.includes(unlisted) &&
    !JSON.stringify(markers).includes(task.messages[0].content) &&
    !JSON.stringify(markers).includes(task.messages[0].from) && !JSON.stringify(markers).includes('authority'))
  const afterList = await discoverClient.callTool({ name: 'nvoy_channel_read', arguments: { envelope: unlisted } })
  ok('a listed marker becomes readable without ever having been announced',
    afterList.isError !== true && JSON.parse(afterList.content[0].text).envelope === unlisted)
  const relisted = await discoverClient.callTool({ name: 'nvoy_channel_list', arguments: {} })
  ok('list omits an envelope once it has been read', !JSON.parse(relisted.content[0].text).envelopes.includes(unlisted))
  ok('list still offers the envelope that has not been read', JSON.parse(relisted.content[0].text).envelopes.includes(seeded))
} catch (error) {
  ok(`nvoy_channel_list discovery path (threw: ${error.message}) STDERR=${discoverStderr}`, false)
} finally { try { await discoverClient.close() } catch { /* already gone */ } }

// The regression this guards is the tempting one-line version of the fix: registering listed ids in
// `notifiedThisRun`. That map ALSO drives the re-announce throttle, so a list call arriving before
// the first poll would suppress the first notification for `renotifyMs` — silently, on every seat
// that depends on the notification to wake at all. `--renotify-ms 600000` makes that suppression
// permanent for the length of this test, so the mutation cannot pass by being merely slow.
const throttleRuntime = join(root, 'throttle-runtime')
const throttleId = 'claude-throttle-test'
const throttlePubkey = 'e'.repeat(64)
mkdirSync(throttleRuntime); mkdirSync(join(throttleRuntime, 'claude-channel-state'))
writeFileSync(join(manifests, `${throttleId}.json`), JSON.stringify({ ...manifest, id: throttleId, pubkey: throttlePubkey, runtime_dir: throttleRuntime,
  state_dir: join(root, 'throttle-state'), spool_dir: join(root, 'throttle-spool') }))
const throttleTask = { ...task, instance: throttleId, authority: { ...task.authority, scope_subject: throttlePubkey } }
writeFileSync(join(throttleRuntime, 'admitted-tasks.jsonl'), '', { mode: 0o600 })
writeFileSync(join(throttleRuntime, 'reply-requests.jsonl'), '', { mode: 0o640 })
const throttleTransport = new StdioClientTransport({ command: process.execPath,
  args: [resolve('mcp/tools/claude-channel.mjs'), '--instance', throttleId, '--poll-ms', '250', '--renotify-ms', '600000'],
  env: { ...process.env, NVOY_INSTANCE_ROOT: manifests }, stderr: 'pipe' })
const throttleClient = new Client({ name: 'claude-channel-throttle', version: '0.1.0' })
const announced = new Set()
throttleClient.setNotificationHandler(Channel, note => { announced.add(note.params?.meta?.envelope) })
try {
  await throttleClient.connect(throttleTransport)
  // The list call must land before the poll sees the new envelope, or the case cannot discriminate.
  // A 250ms tick makes that overwhelmingly likely but not certain, so the precondition is asserted
  // rather than assumed, and a lost race is retried on a fresh marker instead of scoring a pass.
  let raced = true, subject = null
  for (let attempt = 0; attempt < 5 && raced; attempt++) {
    subject = `${attempt}`.repeat(64)
    appendFileSync(join(throttleRuntime, 'admitted-tasks.jsonl'),
      JSON.stringify({ ...throttleTask, envelope: subject }) + '\n', { mode: 0o600 })
    await throttleClient.callTool({ name: 'nvoy_channel_list', arguments: {} })
    raced = announced.has(subject)
  }
  ok('the throttle case reached its precondition — listed before the poll announced', !raced)
  const deadline = Date.now() + 4000
  while (!announced.has(subject) && Date.now() < deadline) await new Promise(done => setTimeout(done, 100))
  ok('listing an envelope does not suppress its first notification to a client that wakes on them',
    announced.has(subject))
} catch (error) {
  ok(`the throttle case reached its precondition — listed before the poll announced (threw: ${error.message})`, false)
  ok('listing an envelope does not suppress its first notification to a client that wakes on them', false)
} finally { try { await throttleClient.close() } catch { /* already gone */ } }

console.log(`\n${passed}/${passed + failed} passed`)
process.exit(failed ? 1 : 0)
