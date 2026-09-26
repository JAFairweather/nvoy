// Portable Codex harness: the ChatGPT-login Codex config, the fleet-side wake feed and its consumer
// lock, the feed's forced-command line, and the watchable supervisor end to end. No real Codex, SSH
// or ChatGPT login runs: a fake `codex app-server --listen unix://…` speaks WebSocket over a Unix
// socket, and a fake ssh execs the local feed script. The first live session is the operator's check.
import { appendFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawn, spawnSync } from 'node:child_process'
import { sshChannelEntry } from '../mcp/tools/channel_client.mjs'
import { CODEX_CHANNEL_TOOLS, codexConfigToml, codexTurnText } from '../mcp/tools/harness_session.mjs'
import { attachCommand, sshFeedArgs } from '../mcp/tools/codex_portable_harness.mjs'
import { claimPidLock } from '../mcp/tools/pid_lock.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const root = realpathSync(mkdtempSync(join(tmpdir(), 'cph-')))
const wait = ms => new Promise(done => setTimeout(done, ms))
async function waitFor(test, ms = 10000) { const end = Date.now() + ms; while (Date.now() < end) { if (test()) return true; await wait(25) } return false }
const readText = path => { try { return readFileSync(path, 'utf8') } catch { return '' } }
const secretFile = (path, value, mode = 0o600) => { writeFileSync(path, value, { mode }); chmodSync(path, mode); return path }
const envelope = n => String(n).repeat(64)
const brokerAdapterGid = process.getgid()
const workerHandoffGid = process.getgroups().find(g => g !== brokerAdapterGid)
if (!Number.isInteger(workerHandoffGid)) throw new Error('test runner needs a second supplementary group')
const channel = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const manifestFor = (id, extra = {}) => ({ version: 1, id, pubkey: 'c'.repeat(64),
  state_dir: join(root, `st-${id}`), runtime_dir: join(root, `rt-${id}`), spool_dir: join(root, `sp-${id}`),
  bunker_uri_ref: `/etc/nvoy/credentials/${id}.bunker`, bunker_client_ref: `/etc/nvoy/credentials/${id}.client`,
  broker_adapter_gid: brokerAdapterGid, worker_handoff_gid: workerHandoffGid, watcher_uid: 41021, broker_uid: 41022, adapter_uid: 41023, worker_uid: process.getuid(),
  grantors: ['4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d'],
  relays: ['wss://nos.lol'], worker_enabled: false, delivery_mode: 'notify_only',
  buzz: { relay: 'wss://nave.communities.buzz.xyz', channels: [channel] }, ...extra })
const fleet = mkdtempSync(join(root, 'i-'))
const manifest = manifestFor('cx-test')
writeFileSync(join(fleet, 'cx-test.json'), JSON.stringify(manifest))
mkdirSync(join(manifest.runtime_dir, 'codex-mcp-state'), { recursive: true, mode: 0o700 })
const queue = join(manifest.runtime_dir, 'admitted-tasks.jsonl')
const lockPath = join(manifest.runtime_dir, 'codex-mcp-state', 'feed.lock')
// Queue lines carry everything a real record does; none of it but the envelope, type and time may leave.
const record = (n, type = 'admitted-task') => JSON.stringify({ version: 1, type, instance: 'cx-test', envelope: envelope(n), received_at: 1000 + n,
  messages: [{ sender: 'd'.repeat(64), content: `SECRET-BODY-${n}` }], authority: { grant: 'SECRET-GRANT' }, notification: { content: 'SECRET-NOTE' } }) + '\n'

// ChatGPT-login Codex config
const remote = { identity: '/keys/cx-channel', knownHosts: '/keys/known_hosts', target: 'nvoy-codex@broker.example' }
const toml = codexConfigToml({ manifest: { id: 'cx-test' }, root: '', auth: 'chatgpt', remote })
const tomlLines = toml.split('\n').filter(Boolean)
ok('the ChatGPT config is well-formed TOML of tables and single-line keys', tomlLines.every(line => /^\[[a-z0-9_.-]+\]$/i.test(line) || /^[a-z_]+ = (?:"[^"]*"|\[.*\])$/.test(line)))
const args = JSON.parse(tomlLines.find(line => line.startsWith('args = ')).slice(7))
ok('the ChatGPT config forces the ChatGPT login from a file store, with no provider and no key', /^forced_login_method = "chatgpt"$/m.test(toml) &&
  /^cli_auth_credentials_store = "file"$/m.test(toml) && !/model_provider|env_key|OPENAI_API_KEY|requires_openai_auth|sk-|base_url/.test(toml))
ok('the ChatGPT config asks for no approval and keeps shell commands read-only', /^approval_policy = "never"$/m.test(toml) && /^sandbox_mode = "read-only"$/m.test(toml) && !/danger|full-access/.test(toml))
ok('its one MCP server is the hardened ssh entry to the channel forced command', (toml.match(/^\[mcp_servers\.[^.\]]+\]$/gm) || []).length === 1 &&
  toml.includes('[mcp_servers.nvoy-cx-test]\ncommand = "/usr/bin/ssh"\n') && JSON.stringify(args) === JSON.stringify(sshChannelEntry(remote).args) && !/NVOY_INSTANCE_ROOT/.test(toml))
ok('each keyless channel tool, and only those, is pre-approved', CODEX_CHANNEL_TOOLS.every(tool => toml.includes(`[mcp_servers.nvoy-cx-test.tools.${tool}]\napproval_mode = "approve"\n`)) &&
  (toml.match(/^approval_mode = /gm) || []).length === 3)
ok('a model is set only when chosen', !/^model = /m.test(toml) && /^model = "gpt-5\.5"$/m.test(codexConfigToml({ manifest: { id: 'cx-test' }, root: '', model: 'gpt-5.5', auth: 'chatgpt', remote })))
ok('a ChatGPT config without the SSH channel, or an unknown auth mode, is refused', (() => { try { codexConfigToml({ manifest: { id: 'x' }, root: '', auth: 'chatgpt' }); return false } catch { return true } })() &&
  (() => { try { codexConfigToml({ manifest: { id: 'x' }, root: '', auth: 'env' }); return false } catch { return true } })())
ok('the fleet API-key config is unchanged by default', codexConfigToml({ manifest: { id: 'dj' }, root: '/r' }) === codexConfigToml({ manifest: { id: 'dj' }, root: '/r', auth: 'api-key' }) &&
  /^model_provider = "nvoy-openai-api"$/m.test(codexConfigToml({ manifest: { id: 'dj' }, root: '/r' })))

// Forced-command lines
const pub = join(root, 'feed.pub')
writeFileSync(pub, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly feed\n')
const keyLine = (...extra) => spawnSync(process.execPath, ['mcp/tools/instance-codex-channel-authorized-key.mjs', '--instance', 'cx-test', '--public-key-file', pub, '--container', 'nvoy-cx-adapter', ...extra],
  { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: fleet } })
const feedLine = keyLine('--mode', 'feed'), channelLine = keyLine(), defaultLine = keyLine('--mode', 'channel')
ok('--mode feed renders one restricted line fixing the worker, container, feed program and instance, under its own tag', feedLine.status === 0 &&
  feedLine.stdout === `restrict,command="/usr/bin/docker exec -i --user ${process.getuid()}:${workerHandoffGid} nvoy-cx-adapter /usr/local/bin/node /srv/nvoy/mcp/tools/codex-channel-feed.mjs --instance cx-test" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly nvoy-codex-feed-cx-test\n`)
ok('the channel line is unchanged, by default and as --mode channel', channelLine.stdout === defaultLine.stdout &&
  channelLine.stdout.includes('/codex-channel-mcp.mjs --instance cx-test" ssh-ed25519') && channelLine.stdout.trim().endsWith(' nvoy-codex-channel-cx-test'))
ok('an unknown mode is refused', /--mode must be channel or feed/.test(keyLine('--mode', 'shell').stderr) && keyLine('--mode', 'shell').status !== 0)

// Wake feed
writeFileSync(queue, record(1))
function feed(extra = [], root2 = fleet) {
  const child = spawn(process.execPath, ['mcp/tools/codex-channel-feed.mjs', '--instance', 'cx-test', '--heartbeat-ms', '150', '--poll-ms', '40', ...extra],
    { cwd: resolve('.'), env: { ...process.env, NVOY_INSTANCE_ROOT: root2 } })
  const run = { child, out: '', err: '', events: () => run.out.split('\n').slice(0, -1).map(JSON.parse) }
  child.stdout.on('data', d => { run.out += d }); child.stderr.on('data', d => { run.err += d }); child.stdin.on('error', () => {})
  run.exited = new Promise(done => child.on('exit', code => done(code)))
  run.hello = since => child.stdin.write(JSON.stringify({ since }) + '\n')
  run.ping = setInterval(() => { try { child.stdin.write('{"ping":1}\n') } catch {} }, 100)
  run.close = async () => { clearInterval(run.ping); child.stdin.end(); return run.exited }
  return run
}
const a = feed()
a.hello(null)
await waitFor(() => a.events().some(e => e.event === 'hello'))
const helloA = a.events()[0] || {}
ok('a feed with no cursor starts from now and names where now is', helloA.event === 'hello' && helloA.instance === 'cx-test' && helloA.since_found === null && helloA.cursor === envelope(1) &&
  !a.events().some(e => e.event === 'admitted'))
appendFileSync(queue, record(2) + 'not json\n' + JSON.stringify({ envelope: 'XYZ' }) + '\n' + record(3, 'verified-notification'))
await waitFor(() => a.events().filter(e => e.event === 'admitted').length >= 2 && a.events().some(e => e.event === 'heartbeat'))
const admittedA = a.events().filter(e => e.event === 'admitted')
ok('each new envelope is announced once, in order, with its type and time', JSON.stringify(admittedA) === JSON.stringify([
  { event: 'admitted', envelope: envelope(2), type: 'admitted-task', at: 1002 }, { event: 'admitted', envelope: envelope(3), type: 'verified-notification', at: 1003 }]))
ok('the feed is metadata only: no body, sender, authority or notification field leaks', !/SECRET|"(?:sender|messages|authority|notification|content|pad)"/.test(a.out) &&
  a.events().every(e => Object.keys(e).every(k => ['event', 'instance', 'since_found', 'cursor', 'envelope', 'type', 'at'].includes(k))))
ok('the feed sends heartbeats carrying its cursor', a.events().some(e => e.event === 'heartbeat' && e.cursor === envelope(3) && Number.isFinite(e.at)))
ok('every feed line is bounded', a.out.split('\n').every(line => line.length < 512))
ok('the feed holds the identity\'s Codex lock, owner-only', (() => { try { const lock = JSON.parse(readText(lockPath)); return lock.pid === a.child.pid && lock.instance === 'cx-test' && (statSync(lockPath).mode & 0o777) === 0o600 } catch { return false } })())
const b = feed()
b.hello(null)
const bCode = await Promise.race([b.exited, wait(5000).then(() => 'hung')])
ok('a second consumer for the identity is refused while the first lives', bCode === 1 && new RegExp(`Codex harness feed already runs as pid ${a.child.pid}`).test(b.err) && !b.out)
clearInterval(b.ping)
ok('closing the client\'s stdin ends the feed and frees the lock', await Promise.race([a.close(), wait(5000).then(() => 'hung')]) === 0 && !existsSync(lockPath))
const c = feed()
c.hello(envelope(1))
await waitFor(() => c.events().filter(e => e.event === 'admitted').length >= 2)
appendFileSync(queue, record(4))
await waitFor(() => c.events().filter(e => e.event === 'admitted').length >= 3)
ok('a cursor resumes after that envelope: the backlog first, then live arrivals', c.events()[0].since_found === true &&
  c.events().filter(e => e.event === 'admitted').map(e => e.envelope).join() === [envelope(2), envelope(3), envelope(4)].join())
await c.close()
const d = feed()
d.hello('start')
await waitFor(() => d.events().filter(e => e.event === 'admitted').length >= 4)
ok('"start" replays the whole queue, for a client that baselined on an empty one', d.events()[0].since_found === true &&
  d.events().filter(e => e.event === 'admitted').map(e => e.envelope).join() === [1, 2, 3, 4].map(envelope).join())
await d.close()
const e = feed()
e.hello(envelope(9))
await waitFor(() => e.events().length >= 1)
await wait(200)
ok('a cursor the queue no longer holds is reported, and the feed starts from now instead of replaying', e.events()[0].since_found === false && e.events()[0].cursor === envelope(4) &&
  !e.events().some(ev => ev.event === 'admitted'))
await e.close()
const dead = spawnSync(process.execPath, ['-e', '0']).pid
writeFileSync(lockPath, JSON.stringify({ version: 1, instance: 'cx-test', pid: dead, started_at: 1 }))
const f = feed()
f.hello(null)
ok('a lock whose holder is gone is reclaimed', await waitFor(() => f.events().some(ev => ev.event === 'hello')) && JSON.parse(readText(lockPath)).pid === f.child.pid)
await f.close()
writeFileSync(lockPath, JSON.stringify({ version: 1, instance: 'other-test', pid: dead, started_at: 1 }))
const g = feed()
g.hello(null)
ok('a lock that binds another instance fails closed', await Promise.race([g.exited, wait(5000)]) === 1 && /does not bind this instance/.test(g.err))
clearInterval(g.ping); rmSync(lockPath)
// The holder must look like this feed for this instance: on Linux the feed reads /proc and would
// rightly reclaim a lock whose live PID runs anything else.
const holder = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)', 'codex-channel-feed.mjs', '--instance', 'cx-test'], { stdio: 'ignore' })
writeFileSync(lockPath, JSON.stringify({ version: 1, instance: 'cx-test', pid: holder.pid, started_at: 1 }))
const h = feed()
h.hello(null)
ok('a lock naming a live process is not reclaimed', await Promise.race([h.exited, wait(5000)]) === 1 && new RegExp(`already runs as pid ${holder.pid}`).test(h.err))
clearInterval(h.ping); holder.kill(); rmSync(lockPath)
// The feed lock outlives the adapter container, and in the next one its PID can name a live,
// unrelated process. Where /proc shows the PID running anything but this feed for this instance,
// the lock is stale; where /proc cannot say, a live PID still refuses.
const stranger = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' })
const proc = join(root, 'proc'), strangerLock = join(root, 'stranger.lock')
const cmdline = (...argv) => { mkdirSync(join(proc, String(stranger.pid)), { recursive: true }); writeFileSync(join(proc, String(stranger.pid), 'cmdline'), argv.join('\0') + '\0') }
const claimOver = (options) => {
  writeFileSync(strangerLock, JSON.stringify({ version: 1, instance: 'cx-test', pid: stranger.pid, started_at: 1 }))
  try { claimPidLock(strangerLock, 'cx-test', 'Codex harness feed', options)(); return 'claimed' } catch (error) { return error.message }
}
const feedOptions = { program: 'codex-channel-feed.mjs', procRoot: proc }
const noProc = claimOver(feedOptions)
cmdline('/usr/bin/python3', '-m', 'http.server')
const strangerProgram = claimOver(feedOptions)
cmdline('node', '/srv/nvoy/mcp/tools/codex-channel-feed.mjs', '--instance', 'other-test')
const otherInstance = claimOver(feedOptions)
cmdline('node', '/srv/nvoy/mcp/tools/codex-channel-feed.mjs', '--instance', 'cx-test', '--heartbeat-ms', '150')
const liveFeed = claimOver(feedOptions)
cmdline('/usr/bin/python3', '-m', 'http.server')
const noProgram = claimOver({ procRoot: proc })
stranger.kill()
ok('a feed lock whose live PID /proc shows running another program, or the feed for another instance, is reclaimed',
  strangerProgram === 'claimed' && otherInstance === 'claimed')
ok('a live PID running this instance\'s feed, or one /proc cannot describe, still holds the lock', /already runs as pid/.test(liveFeed) && /already runs as pid/.test(noProc) &&
  /already runs as pid/.test(noProgram))
rmSync(strangerLock, { force: true })
const quiet = spawn(process.execPath, ['mcp/tools/codex-channel-feed.mjs', '--instance', 'cx-test', '--client-timeout-ms', '600'], { cwd: resolve('.'), env: { ...process.env, NVOY_INSTANCE_ROOT: fleet } })
let quietErr = ''
quiet.stdin.on('error', () => {})
quiet.stderr.on('data', d => { quietErr += d })
quiet.stdin.write('{"since":null}\n')
ok('a client that stops sending keepalives is gone: the feed exits and frees the lock (#168)',
  await Promise.race([new Promise(done => quiet.on('exit', done)), wait(5000).then(() => 'hung')]) === 0 && /no client keepalive/.test(quietErr) && !existsSync(lockPath))
const mute = spawn(process.execPath, ['mcp/tools/codex-channel-feed.mjs', '--instance', 'cx-test', '--handshake-ms', '500'], { cwd: resolve('.'), env: { ...process.env, NVOY_INSTANCE_ROOT: fleet } })
let muteErr = ''
mute.stdin.on('error', () => {})
mute.stderr.on('data', d => { muteErr += d })
ok('a connection that never sends its cursor frees the lock', await Promise.race([new Promise(done => mute.on('exit', done)), wait(5000).then(() => 'hung')]) === 0 &&
  /no client cursor/.test(muteErr) && !existsSync(lockPath))
mute.stdin.end()
const big = feed()
big.hello(null)
await waitFor(() => big.events().length >= 1)
appendFileSync(queue, JSON.stringify({ envelope: envelope(5), type: 'admitted-task', pad: 'x'.repeat(1100 * 1024) }) + '\n' + record(6))
await waitFor(() => big.events().some(ev => ev.envelope === envelope(6)))
ok('a record over its bound is dropped whole, and the next is still announced', big.events().filter(ev => ev.event === 'admitted').map(ev => ev.envelope).join() === envelope(6))
await big.close()
const otherRoot = mkdtempSync(join(root, 'i-'))
writeFileSync(join(otherRoot, 'cx-test.json'), JSON.stringify({ ...manifest, worker_uid: 41024 }))
const wrongUser = spawnSync(process.execPath, ['mcp/tools/codex-channel-feed.mjs', '--instance', 'cx-test'], { cwd: resolve('.'), encoding: 'utf8', env: { ...process.env, NVOY_INSTANCE_ROOT: otherRoot }, input: '' })
ok('the feed runs only as the manifest-bound worker user', wrongUser.status === 1 && /worker user/.test(wrongUser.stderr))

// Supervisor, against a fake WebSocket-over-unix app-server and a fake ssh that runs the feed locally
const fakeBin = join(root, 'bin')
mkdirSync(fakeBin, { mode: 0o700 })
writeFileSync(join(fakeBin, 'codex'), `#!/usr/bin/env node
const net = require('node:net'), crypto = require('node:crypto'), fs = require('node:fs')
const home = process.env.CODEX_HOME
const log = row => fs.appendFileSync(home + '/fake.jsonl', JSON.stringify(row) + '\\n')
if (process.argv[2] !== 'app-server' || process.argv[3] !== '--listen' || !String(process.argv[4]).startsWith('unix://')) process.exit(2)
const path = process.argv[4].slice(7)
log({ start: true, env: Object.keys(process.env).sort(), listen: path })
fs.rmSync(home + '/mcp-dead', { force: true })
const THREAD = fs.existsSync(home + '/unsaved') ? '0199a213-81c0-7800-8aa1-cccccccccccc' : '0199a213-81c0-7800-8aa1-bbab2a035a53'
const conns = new Set()
let turns = 0, queued = [], active = null, activeAt = 0
const broadcast = m => { for (const send of conns) send(m) }
const begin = (via) => { active = 'turn-' + ++turns; activeAt = Date.now(); broadcast({ method: 'turn/started', params: { threadId: THREAD, turn: { id: active, status: 'inProgress' } } }); log({ began: active, via }); return active }
setInterval(() => {
  if (!active || fs.existsSync(home + '/hold') || Date.now() - activeAt < 30) return
  broadcast({ method: 'turn/completed', params: { threadId: THREAD, turn: { id: active, status: 'completed', items: [] } } }); active = null
  if (queued.length) begin(queued.shift())
}, 20)
net.createServer(sock => {
  let buf = Buffer.alloc(0), up = false, experimental = false
  const send = m => { const b = Buffer.from(JSON.stringify(m)); const h = b.length < 126 ? Buffer.from([0x81, b.length]) : Buffer.from([0x81, 126, b.length >> 8, b.length & 255]); sock.write(Buffer.concat([h, b])) }
  sock.on('close', () => conns.delete(send)); sock.on('error', () => {})
  sock.on('data', data => {
    buf = Buffer.concat([buf, data])
    if (!up) {
      const i = buf.indexOf('\\r\\n\\r\\n'); if (i < 0) return
      const key = /Sec-WebSocket-Key: (\\S+)/i.exec(String(buf.subarray(0, i)))[1]
      sock.write('HTTP/1.1 101 Switching Protocols\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Accept: ' + crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64') + '\\r\\n\\r\\n')
      buf = buf.subarray(i + 4); up = true; conns.add(send)
    }
    while (buf.length >= 2) {
      const op = buf[0] & 15, masked = !!(buf[1] & 128)
      let n = buf[1] & 127, o = 2
      if (n === 126) { n = buf.readUInt16BE(2); o = 4 }
      if (buf.length < o + (masked ? 4 : 0) + n) return
      const mask = masked ? buf.subarray(o, o + 4) : null; o += masked ? 4 : 0
      const body = Buffer.from(buf.subarray(o, o + n)); buf = buf.subarray(o + n)
      if (mask) for (let i = 0; i < body.length; i++) body[i] ^= mask[i % 4]
      if (op === 8) { sock.end(); return }
      if (op !== 1) continue
      const m = JSON.parse(String(body)); log({ ...m, masked })
      if (m.method === 'initialize') { experimental = m.params?.capabilities?.experimentalApi === true; send({ id: m.id, result: { userAgent: 'fake' } }) }
      if (m.method === 'thread/start') send({ id: m.id, result: { thread: { id: THREAD, status: { type: 'idle' } } } })
      if (m.method === 'thread/resume') send(THREAD.endsWith('cccc') ? { id: m.id, error: { code: -32600, message: 'no rollout found for thread id ' + m.params.threadId } } : { id: m.id, result: { thread: { id: m.params.threadId, status: { type: active ? 'active' : 'idle' } } } })
      if (m.method === 'turn/start') {
        if (active) { send({ id: m.id, error: { code: -32600, message: 'a turn is already running' } }); continue }
        send({ id: m.id, result: { turn: { id: begin(m.params.clientUserMessageId) } } })
        send({ id: 'srv-' + turns, method: 'item/tool/requestUserInput', params: { threadId: THREAD } })
      }
      // Shapes observed from codex-cli 0.149.1 (2026-09-25): a live server resolves with its result;
      // a server that has exited, cleanly or by signal, rejects with -32603 "Transport closed".
      if (m.method === 'mcpServer/tool/call') send(fs.existsSync(home + '/no-probe-spec') ? { id: m.id, error: { code: -32601, message: 'Method not found' } }
        : fs.existsSync(home + '/no-probe') ? { id: m.id, error: { code: -32600, message: 'Invalid request: unknown variant \`' + m.method + '\`, expected one of \`initialize\`' } }
        : fs.existsSync(home + '/mcp-dead') ? { id: m.id, error: { code: -32603, message: 'tool call failed for \`' + m.params.server + '/' + m.params.tool + '\`: Transport closed' } }
        : { id: m.id, result: { content: [{ type: 'text', text: '[]' }] } })
      if (m.method === 'thread/queue/add') {
        if (!experimental) { send({ id: m.id, error: { code: -32600, message: 'thread/queue/add requires experimentalApi' } }); continue }
        queued.push(m.params.clientUserMessageId); send({ id: m.id, result: { queuedSubmission: { id: 'q-' + queued.length, input: m.params.input, clientUserMessageId: m.params.clientUserMessageId } } })
      }
    }
  })
}).listen(path)
process.on('SIGTERM', () => { try { fs.rmSync(path) } catch {} process.exit(0) })
`)
chmodSync(join(fakeBin, 'codex'), 0o755)
const fakeSsh = secretFile(join(fakeBin, 'ssh'), `#!/bin/sh
echo "$@" >> ${join(root, 'ssh-args.log')}
NVOY_INSTANCE_ROOT=${fleet} exec ${process.execPath} ${resolve('mcp/tools/codex-channel-feed.mjs')} --instance cx-test --heartbeat-ms 150 --poll-ms 40
`, 0o700)
const ownHome = join(root, 'own')
mkdirSync(ownHome, { mode: 0o700 })
const codexHome = join(root, 'ch')
const makeCodexHome = (path, auth = { auth_mode: 'chatgpt', OPENAI_API_KEY: null, tokens: { access_token: 'CHATGPT-TOKEN-MUST-NEVER-PRINT' } }, mode = 0o700) => {
  mkdirSync(path, { recursive: true, mode }); chmodSync(path, mode)
  if (auth) secretFile(join(path, 'auth.json'), JSON.stringify(auth))
  return path
}
makeCodexHome(codexHome)
const chanKey = secretFile(join(root, 'chan-key'), 'PRIVATE-KEY-MUST-NEVER-PRINT\n'), feedKey = secretFile(join(root, 'feed-key'), 'PRIVATE-KEY-MUST-NEVER-PRINT\n')
const knownHosts = secretFile(join(root, 'known_hosts'), 'broker.example ssh-ed25519 AAAAC3NzaTest\n', 0o644)
const client = { instance: 'cx-test', ssh_target: 'nvoy-codex@broker.example', identity_file: chanKey, feed_identity_file: feedKey, known_hosts_file: knownHosts, codex_home: codexHome }
const clientConfig = (value, mode = 0o600) => secretFile(join(mkdtempSync(join(root, 'c-')), 'client.json'), JSON.stringify(value), mode)
const baseEnv = (() => { const env = { ...process.env }; delete env.OPENAI_API_KEY; delete env.CODEX_API_KEY; return env })()
const supervisorEnv = { ...baseEnv, HOME: ownHome, PATH: `${fakeBin}:${process.env.PATH}`, NVOY_HARNESS_SSH: fakeSsh, HARNESS_FEED_KEEPALIVE_MS: '100', HARNESS_FEED_SILENCE_MS: '3000' }
const refused = (value, pattern, env = {}, mode) => {
  const r = spawnSync(process.execPath, ['mcp/tools/codex-harness-portable.mjs', '--instance', 'cx-test', '--config', clientConfig(value, mode)], { cwd: resolve('.'), encoding: 'utf8', env: { ...supervisorEnv, ...env }, timeout: 10000 })
  return r.status === 1 && pattern.test(r.stderr) && !/PRIVATE-KEY|CHATGPT-TOKEN|sk-proj-live/.test(r.stdout + r.stderr)
}
ok('an OpenAI API key in the environment refuses the harness, without printing it', refused(client, /OPENAI_API_KEY is set in this environment/, { OPENAI_API_KEY: 'sk-proj-live-value' }) &&
  refused(client, /CODEX_API_KEY is set/, { CODEX_API_KEY: 'sk-proj-live-value' }))
ok('a config naming an OpenAI API key, by field or by value, is refused', refused({ ...client, OPENAI_API_KEY: '/x' }, /must not name an OpenAI API key/) &&
  refused({ ...client, api_key_file: '/x' }, /must not name an OpenAI API key/) && refused({ ...client, model: 'sk-proj-live-value' }, /must not name an OpenAI API key/))
ok('a config naming a Nostr key or Bunker credential is refused', refused({ ...client, nsec_file: '/x' }, /Nostr key or Bunker/) &&
  refused({ ...client, model: 'bunker://' + 'b'.repeat(64) }, /Nostr key or Bunker/))
ok('an unknown field, another instance, or a writable config is refused', refused({ ...client, home: '/x' }, /unknown field home/) &&
  refused({ ...client, instance: 'other-test' }, /different instance/) && refused(client, /must not be group\/world writable/, {}, 0o666))
ok('CODEX_HOME must be the harness\'s own, owner-only, and never ~/.codex', refused({ ...client, codex_home: makeCodexHome(join(ownHome, '.codex')) }, /never your home or ~\/\.codex/) &&
  refused({ ...client, codex_home: 'ch' }, /codex_home path must be absolute/) && refused({ ...client, codex_home: makeCodexHome(join(root, 'loose'), undefined, 0o750) }, /mode 0700/) &&
  refused({ ...client, codex_home: join(root, 'absent') }, /codex_home is missing/))
ok('a CODEX_HOME without a ChatGPT login is refused, reading only its auth mode', refused({ ...client, codex_home: makeCodexHome(join(root, 'nologin'), null) }, /auth\.json\) is missing/) &&
  refused({ ...client, codex_home: makeCodexHome(join(root, 'apikey'), { auth_mode: 'apikey' }) }, /not a ChatGPT login/) &&
  refused({ ...client, codex_home: makeCodexHome(join(root, 'keyed'), { auth_mode: 'chatgpt', OPENAI_API_KEY: 'sk-proj-live-value' }) }, /holds an API key/))
ok('the channel and feed keys must be two owner-only keys', refused({ ...client, feed_identity_file: chanKey }, /must be two keys/) &&
  refused({ ...client, feed_identity_file: secretFile(join(root, 'loose-key'), 'x\n', 0o640) }, /feed identity file must not be accessible/))
ok('a CODEX_HOME too deep for its control socket is refused', refused({ ...client, codex_home: makeCodexHome(join(root, 'd'.repeat(90))) }, /too deep for its control socket/))

writeFileSync(queue, record(1))
const fakeLog = home => readText(join(home, 'fake.jsonl')).split('\n').filter(Boolean).map(JSON.parse)
function startSupervisor(config = client, env = {}) {
  const child = spawn(process.execPath, ['mcp/tools/codex-harness-portable.mjs', '--instance', 'cx-test', '--config', clientConfig(config)], { cwd: resolve('.'), env: { ...supervisorEnv, ...env } })
  const run = { child, out: '' }
  child.stdout.on('data', d => { run.out += d }); child.stderr.on('data', d => { run.out += d })
  run.exited = new Promise(done => child.on('exit', done))
  run.stop = async () => { child.kill('SIGTERM'); await run.exited }
  return run
}
const clientCalls = (method, home = codexHome) => fakeLog(home).filter(m => m.method === method && m.masked)
const THREAD = '0199a213-81c0-7800-8aa1-bbab2a035a53'
const socket = join(codexHome, 'ctl', 'as.sock')
const s1 = startSupervisor(client, { HARNESS_EXTRA_VAR: 'kept-out' })
ok('the supervisor starts its thread, baselines the fleet queue, and connects the feed', await waitFor(() => /session ready/.test(s1.out) && /wake feed connected/.test(s1.out)) &&
  /first start: baselined the cx-test queue/.test(s1.out) && clientCalls('thread/start').length === 1 && clientCalls('thread/start')[0].params.cwd === join(codexHome, 'workspace'))
const attachLine = `attach: CODEX_HOME=${codexHome} codex resume ${THREAD} --remote unix://${socket}`
// "session ready" and the attach line are two writes, and they can reach this process as two chunks.
await waitFor(() => /attach: /.test(s1.out))
ok('a new thread has no rollout to resume yet, so ready says when the attach command comes instead of printing it (#218)',
  /attach: available after the thread's first turn/.test(s1.out) && !s1.out.includes(attachLine) && attachCommand({ codexHome: '/a b', socket: '/s', threadId: 't' }) === "CODEX_HOME='/a b' codex resume t --remote unix:///s")
ok('the thread\'s channel is asked before ready, by the channel\'s own tool', clientCalls('mcpServer/tool/call')[0]?.params.server === 'nvoy-cx-test' &&
  clientCalls('mcpServer/tool/call')[0]?.params.tool === 'nvoy_channel_list' && clientCalls('mcpServer/tool/call')[0]?.params.threadId === THREAD)
ok('the app-server listens on the owner-only socket under CODEX_HOME, and the client frames are masked', fakeLog(codexHome)[0].listen === socket &&
  (statSync(socket).mode & 0o777) === 0o600 && clientCalls('initialize').length === 1)
ok('it opts into the experimental API that thread/queue/add needs', clientCalls('initialize')[0].params.capabilities.experimentalApi === true)
writeFileSync(join(codexHome, 'hold'), '')
appendFileSync(queue, record(2))
await waitFor(() => /injected 222222222222 as a turn/.test(s1.out))
appendFileSync(queue, record(3, 'verified-notification'))
await waitFor(() => /queued 333333333333 behind the running turn/.test(s1.out))
rmSync(join(codexHome, 'hold'))
await waitFor(() => fakeLog(codexHome).filter(m => m.began).length >= 2)
ok('the attach command is printed once the thread\'s first turn has ended', await waitFor(() => s1.out.includes(attachLine)) &&
  s1.out.indexOf(attachLine) > s1.out.indexOf('turn for 222222222222 ended'))
const starts1 = clientCalls('turn/start'), queues1 = clientCalls('thread/queue/add')
ok('an envelope arriving while the thread is idle is injected once as turn/start', starts1.length === 1 && starts1[0].params.threadId === THREAD &&
  starts1[0].params.clientUserMessageId === `nvoy:${envelope(2)}` && starts1[0].params.input[0].text === codexTurnText({ envelope: envelope(2), type: 'admitted-task' }))
ok('an envelope arriving mid-turn is queued once behind it with thread/queue/add, on the same thread', queues1.length === 1 && queues1[0].params.threadId === THREAD &&
  queues1[0].params.clientUserMessageId === `nvoy:${envelope(3)}` && queues1[0].params.input[0].text === codexTurnText({ envelope: envelope(3), type: 'verified-notification' }) &&
  fakeLog(codexHome).filter(m => m.began).map(m => m.via).join() === `nvoy:${envelope(2)},nvoy:${envelope(3)}`)
ok('the baselined envelope is never injected', !JSON.stringify(fakeLog(codexHome)).includes(envelope(1)))
ok('a request Codex makes of the client is left for an attached person, not declined', /Codex asked the client for item\/tool\/requestUserInput; left for an attached person/.test(s1.out) &&
  !fakeLog(codexHome).some(m => m.id === 'srv-1'))
const appEnv = fakeLog(codexHome)[0].env.filter(k => !/^(__CF|LC_|_$|SHLVL|PWD)/.test(k))
ok('the app-server gets a built environment: no API key, nothing inherited', appEnv.join() === 'CODEX_HOME,HOME,PATH')
const written = readText(join(codexHome, 'config.toml'))
ok('CODEX_HOME/config.toml is the ChatGPT config on the channel key, owner-only', (statSync(join(codexHome, 'config.toml')).mode & 0o777) === 0o600 &&
  /^forced_login_method = "chatgpt"$/m.test(written) && written.includes(`"-i", "${chanKey}"`) && !written.includes(feedKey) && written.includes('command = "/usr/bin/ssh"'))
const sshArgs = readText(join(root, 'ssh-args.log')).trim().split('\n')[0]
ok('the feed runs on its own key through the hardened entry, with ssh keepalives', sshArgs === sshFeedArgs({ feedIdentity: feedKey, knownHosts, target: client.ssh_target }).join(' ') &&
  sshArgs.includes(`-i ${feedKey}`) && /ServerAliveInterval=15 -o ServerAliveCountMax=3 nvoy-codex@broker\.example$/.test(sshArgs) && sshArgs.includes('BatchMode=yes'))
ok('no key, login token or message body reaches a log', !/PRIVATE-KEY|CHATGPT-TOKEN|SECRET/.test(s1.out + readText(join(codexHome, 'nvoy', 'delivered.jsonl')) + readText(join(codexHome, 'nvoy', 'feed-cursor.json'))))
ok('the delivered record and cursor are owner-only and name the last envelope', (statSync(join(codexHome, 'nvoy', 'delivered.jsonl')).mode & 0o777) === 0o600 &&
  JSON.parse(readText(join(codexHome, 'nvoy', 'feed-cursor.json'))).cursor === envelope(3))
const s2dup = startSupervisor()
ok('a second supervisor on the same CODEX_HOME is refused', await Promise.race([s2dup.exited, wait(5000).then(() => 'hung')]) === 1 && /portable Codex harness already runs as pid/.test(s2dup.out))
const otherHome = makeCodexHome(join(root, 'ch2'))
const s3 = startSupervisor({ ...client, codex_home: otherHome })
ok('a second harness elsewhere for the same identity is refused by the fleet lock and injects nothing',
  await waitFor(() => /wake feed exited \(1\): .*Codex harness feed already runs as pid/.test(s3.out)) && !clientCalls('turn/start', otherHome).length && !/wake feed connected/.test(s3.out))
await s3.stop()
await s1.stop()
ok('stopping the supervisor ends its feed and frees the fleet lock', await waitFor(() => !existsSync(lockPath), 5000))
appendFileSync(queue, record(4))
const s2 = startSupervisor(client, { HARNESS_RETRY_MS: '100' })
await waitFor(() => /injected 444444444444 as a turn/.test(s2.out))
ok('a restart resumes the same thread and injects only what arrived while it was down, once', /resumed the cx-test thread/.test(s2.out) &&
  clientCalls('thread/resume').some(m => m.params.threadId === THREAD) && clientCalls('thread/start').length === 1 &&
  clientCalls('turn/start').length === 2 && clientCalls('turn/start')[1].params.clientUserMessageId === `nvoy:${envelope(4)}` && clientCalls('thread/queue/add').length === 1)
ok('a resumed thread prints its attach command at ready', s2.out.indexOf(attachLine) >= 0 && s2.out.indexOf(attachLine) < s2.out.indexOf('injected 444444444444'))
// The fleet recreates the adapter: the thread's channel MCP and the wake feed die together.
await waitFor(() => /turn for 444444444444 ended/.test(s2.out))
writeFileSync(join(codexHome, 'hold'), '')
appendFileSync(queue, record(5))
await waitFor(() => /injected 555555555555 as a turn/.test(s2.out))
const appServers = () => fakeLog(codexHome).filter(m => m.start).length, serversBefore = appServers()
writeFileSync(join(codexHome, 'mcp-dead'), '')
process.kill(JSON.parse(readText(lockPath)).pid, 'SIGKILL')
ok('a wake feed reconnect asks the channel, and a closed transport marks it down', await waitFor(() => /the channel to the fleet is down \(tool call failed for `nvoy-cx-test\/nvoy_channel_list`: Transport closed\)/.test(s2.out)))
await wait(400)
ok('a running turn is never cut short to reconnect the channel', !/restarting codex app-server/.test(s2.out) && appServers() === serversBefore)
rmSync(join(codexHome, 'hold'))
ok('once the turn ends, codex app-server restarts and resumes the same thread', await waitFor(() => appServers() === serversBefore + 1 && /session ready/.test(s2.out.slice(s2.out.lastIndexOf('restarting codex app-server')))) &&
  /restarting codex app-server to reconnect the channel/.test(s2.out) && clientCalls('thread/resume').filter(m => m.params.threadId === THREAD).length === 2 && clientCalls('thread/start').length === 1)
appendFileSync(queue, record(6))
ok('after the restart, new envelopes reach the thread again', await waitFor(() => /injected 666666666666 as a turn/.test(s2.out)) &&
  clientCalls('turn/start').at(-1).params.clientUserMessageId === `nvoy:${envelope(6)}`)
await s2.stop()
// A Codex without the tool-call method: the feed reconnect alone is the signal.
for (const [file, answer] of [['no-probe', '-32600 unknown variant, as 0.149.1 answers'], ['no-probe-spec', '-32601, as JSON-RPC specifies']]) {
  writeFileSync(join(codexHome, file), '')
  const s5 = startSupervisor(client, { HARNESS_RETRY_MS: '100' })
  await waitFor(() => /session ready/.test(s5.out) && /wake feed connected/.test(s5.out))
  const s5Servers = appServers()
  process.kill(JSON.parse(readText(lockPath)).pid, 'SIGKILL')
  ok(`where Codex cannot be asked about its channel (${answer}), a wake feed reconnect restarts codex app-server`, /cannot be asked about its channel/.test(s5.out) &&
    await waitFor(() => /channel to the fleet is down \(the wake feed reconnected\)/.test(s5.out) && appServers() === s5Servers + 1 && (s5.out.match(/session ready/g) || []).length === 2))
  await s5.stop()
  rmSync(join(codexHome, file))
}
writeFileSync(join(codexHome, 'unsaved'), '')
const s4 = startSupervisor()
ok('a stored thread Codex never saved is replaced by a new one (#218)', await waitFor(() => /never saved the stored cx-test thread; starting a new one/.test(s4.out) && /session ready/.test(s4.out)) &&
  JSON.parse(readText(join(codexHome, 'nvoy', 'codex-thread.json'))).thread_id === '0199a213-81c0-7800-8aa1-cccccccccccc')
await s4.stop()

rmSync(root, { recursive: true, force: true })
console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
