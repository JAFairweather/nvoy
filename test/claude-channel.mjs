import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
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
  ok('Claude receives one explicit read tool and one receipt-bound reply tool',
    tools.length === 2 && tools.includes('nvoy_channel_read') && tools.includes('nvoy_channel_reply'))
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
  '--poll-ms', '250', '--heartbeat-ms', '1000', '--heartbeat-misses', '2'],
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
const liveTransport = new StdioClientTransport({ command: process.execPath,
  args: [resolve('mcp/tools/claude-channel.mjs'), '--instance', manifest.id,
    '--poll-ms', '250', '--heartbeat-ms', '1000', '--heartbeat-misses', '2'],
  env: { ...process.env, NVOY_INSTANCE_ROOT: manifests }, stderr: 'pipe' })
const liveClient = new Client({ name: 'claude-channel-heartbeat', version: '0.1.0' })
// An evicted session makes listTools() throw rather than return, so the failure has to be caught
// and reported. Letting it propagate would abort the run with no verdict printed for this case —
// a suite that says nothing about the property it exists to defend.
try {
  await liveClient.connect(liveTransport)
  await new Promise(done => setTimeout(done, 3500))
  const stillThere = (await liveClient.listTools()).tools.map(tool => tool.name)
  ok('a client that is merely idle answers the ping and is never evicted',
    stillThere.includes('nvoy_channel_read') && existsSync(lockPath))
} catch (error) {
  ok(`a client that is merely idle answers the ping and is never evicted (evicted: ${error.message})`, false)
} finally { try { await liveClient.close() } catch { /* already gone */ } }

console.log(`\n${passed}/${passed + failed} passed`)
process.exit(failed ? 1 : 0)
