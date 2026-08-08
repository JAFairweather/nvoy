// The channel announced each envelope exactly once, as early as it could, and called that
// delivered. Both halves were wrong, and together they lost wakes silently.
//
// Observed on the wire against a real Claude Code 2.1.224 session: the server emitted its
// notification 4ms after the client's own `notifications/initialized`, the client logged
// "Channel notifications registered", and nothing was ever injected. The session was not yet
// accepting messages. There is no acknowledgement in this protocol, so a dropped announcement
// looked identical to a quiet queue — the exact failure the channel exists to prevent.
//
// This drives the server over raw stdio rather than through the MCP SDK client, because the SDK
// sends `initialized` for you the moment you connect, and the whole point is to control that
// moment. Both directions are asserted throughout: silence must be caused by the gate and by a
// read envelope, never by the server simply not working.
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawn } from 'node:child_process'

let passed = 0, failed = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passed++ : failed++ }
const sleep = ms => new Promise(r => setTimeout(r, ms))

const root = mkdtempSync(join(tmpdir(), 'nvoy-channel-delivery-'))
const manifests = join(root, 'instances'), runtime = join(root, 'runtime')
mkdirSync(manifests); mkdirSync(runtime); mkdirSync(join(runtime, 'claude-channel-state'))
const uid = process.getuid(), gid = process.getgid()
const manifest = {
  version: 1, id: 'claude-delivery', pubkey: '1'.repeat(64), broker_mode: 'local',
  state_dir: join(root, 'state'), runtime_dir: runtime, spool_dir: join(root, 'spool'),
  bunker_uri_ref: '/etc/nvoy/test.bunker', bunker_client_ref: '/etc/nvoy/test.client',
  worker_enabled: false, delivery_mode: 'notify_only',
  broker_adapter_gid: gid, worker_handoff_gid: gid + 1,
  watcher_uid: uid + 11, broker_uid: uid + 12, adapter_uid: uid + 13, worker_uid: uid,
  grantors: ['2'.repeat(64)], relays: ['wss://nos.lol'],
}
writeFileSync(join(manifests, `${manifest.id}.json`), JSON.stringify(manifest))
const envelope = '3'.repeat(64)
writeFileSync(join(runtime, 'admitted-tasks.jsonl'), JSON.stringify({
  type: 'admitted-task', instance: manifest.id, envelope,
  authority: { version: 1, type: 'scoped-instruction', sender: '4'.repeat(64), grant_id: '5'.repeat(64),
    grantor: manifest.grantors[0], cap: 'task', scope_subject: manifest.pubkey, policy_checked_at: Date.now() },
  messages: [{ from: '4'.repeat(64), at: 1785880000, content: 'inspect the queue' }],
}) + '\n', { mode: 0o600 })
writeFileSync(join(runtime, 'reply-requests.jsonl'), '', { mode: 0o640 })
const readPath = join(runtime, 'claude-channel-state', 'read.jsonl')

const RENOTIFY = 3000
const child = spawn(process.execPath,
  [resolve('mcp/tools/claude-channel.mjs'), '--instance', manifest.id, '--poll-ms', '250', '--renotify-ms', String(RENOTIFY)],
  { env: { ...process.env, NVOY_INSTANCE_ROOT: manifests }, stdio: ['pipe', 'pipe', 'pipe'] })

let buf = ''
const wakes = []
let initializeResult = null
child.stdout.on('data', d => {
  buf += d
  const lines = buf.split('\n'); buf = lines.pop()
  for (const line of lines) {
    if (!line.trim()) continue
    let m; try { m = JSON.parse(line) } catch { continue }
    if (m.id === 1) initializeResult = m.result
    else if (m.method === 'notifications/claude/channel') wakes.push({ at: Date.now(), params: m.params })
  }
})
const send = frame => child.stdin.write(JSON.stringify(frame) + '\n')

try {
  send({ jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'delivery-test', version: '0' } } })
  await sleep(1500)

  ok('the server declares the channel capability to the client',
    !!initializeResult?.capabilities?.experimental?.['claude/channel'])

  // The gate. A notification sent here reaches a client that has not registered its handler.
  ok('nothing is announced before the client reports the session initialized', wakes.length === 0)

  send({ jsonrpc: '2.0', method: 'notifications/initialized' })
  await sleep(1200)

  // The mirror of the gate: a server that announces nothing at all would also pass the check
  // above, so prove the silence was the gate and not a broken poll.
  ok('an unread envelope is announced once the session is initialized', wakes.length === 1)
  ok('the announcement names the envelope and carries no message body',
    wakes[0]?.params?.meta?.envelope === envelope &&
    !JSON.stringify(wakes[0]).includes('inspect the queue'))

  // Persistence. One announcement into a session that was not listening is a lost wake, and
  // nothing in this protocol reports that back.
  await sleep(RENOTIFY + 1200)
  ok('an envelope nobody has read is announced again after the interval', wakes.length >= 2)

  const gap = wakes.length >= 2 ? wakes[1].at - wakes[0].at : 0
  ok('it is repeated on the interval rather than on every poll', gap >= RENOTIFY)

  // ...and the repeat must stop. A wake that repeats forever after it has been handled is its
  // own failure: it would re-steer a session that already acted on the envelope.
  appendFileSync(readPath, JSON.stringify({ version: 1, instance: manifest.id, envelope, read_at: Date.now() }) + '\n')
  const before = wakes.length
  await sleep(RENOTIFY + 1200)
  ok('announcements stop once the envelope has been read', wakes.length === before)
} finally {
  child.kill('SIGKILL')
}

console.log(failed ? `\n${failed} FAILED` : `\nall ${passed} passed`)
process.exit(failed ? 1 : 0)
