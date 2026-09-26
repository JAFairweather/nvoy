// Portable Pi harness: the client config, the launcher's pi command line and environment, and the
// extension end to end. No real pi, SSH or ChatGPT login runs: a fake pi API object stands in for
// pi, a fake ssh execs the fleet's own feed and channel MCP locally, and a fake tmux runs a sleeper
// for the launcher. The first live session is the operator's check.
import { appendFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawn, spawnSync } from 'node:child_process'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { codexTurnText } from '../mcp/tools/harness_session.mjs'
import nvoyPiHarness, { PI_CHANNEL_TOOLS } from '../mcp/tools/pi_harness_extension.mjs'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const root = realpathSync(mkdtempSync(join(tmpdir(), 'pih-')))
const wait = ms => new Promise(done => setTimeout(done, ms))
async function waitFor(test, ms = 10000) { const end = Date.now() + ms; while (Date.now() < end) { if (test()) return true; await wait(25) } return false }
const readText = path => { try { return readFileSync(path, 'utf8') } catch { return '' } }
const secretFile = (path, value, mode = 0o600) => { writeFileSync(path, value, { mode }); chmodSync(path, mode); return path }
const envelope = n => String(n).repeat(64)
const throws = (fn, pattern) => { try { fn(); return false } catch (error) { return pattern.test(error.message) } }

// A fleet identity whose queue the real feed and channel MCP both accept.
const uid = process.getuid(), gid = process.getgid(), channelId = 'a8186b53-537d-46ad-a7e7-b6486c58970e'
const fleet = join(root, 'instances'), runtime = join(root, 'runtime')
mkdirSync(fleet); mkdirSync(join(runtime, 'codex-mcp-state'), { recursive: true })
const manifest = { version: 1, id: 'pd-test', pubkey: '1'.repeat(64), broker_mode: 'local', state_dir: join(root, 'fstate'), runtime_dir: runtime,
  spool_dir: join(root, 'spool'), bunker_uri_ref: '/etc/nvoy/test.bunker', bunker_client_ref: '/etc/nvoy/test.client', worker_enabled: false,
  delivery_mode: 'notify_only', broker_adapter_gid: gid, worker_handoff_gid: gid + 1, watcher_uid: uid + 11, broker_uid: uid + 12,
  adapter_uid: uid + 13, worker_uid: uid, grantors: ['2'.repeat(64)], task_carriers: [{ pubkey: '3'.repeat(64), channels: [channelId] }], relays: ['wss://nos.lol'] }
writeFileSync(join(fleet, 'pd-test.json'), JSON.stringify(manifest))
const authority = { version: 2, type: 'scoped-instruction', sender: '6'.repeat(64), grant_id: '7'.repeat(64), grantor: manifest.grantors[0],
  cap: 'task', scope_subject: manifest.pubkey, policy_checked_at: Date.now(), carrier: manifest.task_carriers[0].pubkey,
  carrier_grant_id: '8'.repeat(64), carrier_grantor: manifest.grantors[0], source_event: '9'.repeat(64), reply_channel: channelId }
const queue = join(runtime, 'admitted-tasks.jsonl'), replies = join(runtime, 'reply-requests.jsonl'), lockPath = join(runtime, 'codex-mcp-state', 'feed.lock')
const record = (n, trusted = true) => JSON.stringify({ type: 'admitted-task', instance: 'pd-test', envelope: envelope(n), received_at: Date.now(), authority: trusted ? authority : null,
  messages: [{ from: trusted ? authority.sender : 'a'.repeat(64), at: 1785880000 + n, content: `SECRET-BODY-${n}`, event_id: trusted ? authority.source_event : 'b'.repeat(64), kind: 9 }] }) + '\n'
writeFileSync(queue, record(1)); writeFileSync(replies, '')

// Client side: keys, known_hosts, the harness's own pi home with a fake ChatGPT login, and a config.
const own = join(root, 'own'), piHome = join(root, 'pihome'), stateDir = join(root, 'st')
mkdirSync(own, { mode: 0o700 })
const makePiHome = (path, auth = { 'openai-codex': { type: 'oauth', access: 'CHATGPT-TOKEN-MUST-NEVER-PRINT', refresh: 'r', expires: 1 } }, mode = 0o700) => {
  mkdirSync(path, { recursive: true, mode }); chmodSync(path, mode)
  if (auth) secretFile(join(path, 'auth.json'), JSON.stringify(auth))
  return path
}
makePiHome(piHome)
const chanKey = secretFile(join(root, 'chan-key'), 'PRIVATE-KEY-MUST-NEVER-PRINT\n'), feedKey = secretFile(join(root, 'feed-key'), 'PRIVATE-KEY-MUST-NEVER-PRINT\n')
const knownHosts = secretFile(join(root, 'known_hosts'), 'broker.example ssh-ed25519 AAAAC3NzaTest\n', 0o644)
const client = { instance: 'pd-test', ssh_target: 'nvoy-pi@broker.example', identity_file: chanKey, feed_identity_file: feedKey, known_hosts_file: knownHosts,
  state_dir: stateDir, pi_home: piHome }
const clientConfig = (value, mode = 0o600) => secretFile(join(mkdtempSync(join(root, 'c-')), 'client.json'), JSON.stringify(value), mode)

// Launcher: refusals
const fakeBin = join(root, 'bin')
mkdirSync(fakeBin, { mode: 0o700 })
const launcherEnv = { ...process.env, HOME: own, PATH: `${fakeBin}:${process.env.PATH}`, HARNESS_WATCH_MS: '50', HARNESS_RETRY_MS: '100', OPENAI_API_KEY: 'sk-proj-live-value' }
const refused = (value, pattern, mode) => {
  const r = spawnSync(process.execPath, ['mcp/tools/pi-harness.mjs', '--instance', 'pd-test', '--config', clientConfig(value, mode)], { cwd: resolve('.'), encoding: 'utf8', env: launcherEnv, timeout: 10000 })
  return r.status === 1 && pattern.test(r.stderr) && !/PRIVATE-KEY|CHATGPT-TOKEN|sk-proj-live/.test(r.stdout + r.stderr)
}
ok('a config naming a Nostr key, Bunker credential or API key, by field or by value, is refused', refused({ ...client, nsec_file: '/x' }, /Nostr key or Bunker/) &&
  refused({ ...client, model: 'bunker://' + 'b'.repeat(64) }, /Nostr key or Bunker/) && refused({ ...client, api_key_file: '/x' }, /must not name an API key/) &&
  refused({ ...client, model: 'sk-proj-live-value' }, /must not name an API key/))
ok('an unknown field, another instance, a writable config or a loose ssh_target is refused', refused({ ...client, home: '/x' }, /unknown field home/) &&
  refused({ ...client, instance: 'other-test' }, /different instance/) && refused(client, /must not be group\/world writable/, 0o666) &&
  refused({ ...client, ssh_target: '-oProxyCommand=x@h' }, /fixed user@host/))
ok('state_dir must be absolute, the harness\'s own, and short enough for its tmux socket', refused({ ...client, state_dir: 'st' }, /state_dir path must be absolute/) &&
  refused({ ...client, state_dir: own }, /never your home/) && refused({ ...client, state_dir: join(root, 'd'.repeat(90)) }, /too deep for its tmux socket/))
ok('the channel and feed keys must be two owner-only keys', refused({ ...client, feed_identity_file: chanKey }, /must be two keys/) &&
  refused({ ...client, feed_identity_file: secretFile(join(root, 'loose-key'), 'x\n', 0o640) }, /feed identity file must not be accessible/))
ok('pi_home must be the harness\'s own owner-only directory, never ~/.pi/agent', refused({ ...client, pi_home: makePiHome(join(own, '.pi', 'agent')) }, /never your home or ~\/\.pi\/agent/) &&
  refused({ ...client, pi_home: 'pihome' }, /pi_home path must be absolute/) && refused({ ...client, pi_home: makePiHome(join(root, 'loose'), undefined, 0o750) }, /mode 0700/) &&
  refused({ ...client, pi_home: join(root, 'absent') }, /pi_home is missing/))
ok('pi_home must hold a ChatGPT login and no API key, reading only each credential\'s type', refused({ ...client, pi_home: makePiHome(join(root, 'nologin'), null) }, /auth\.json\) is missing/) &&
  refused({ ...client, pi_home: makePiHome(join(root, 'keyed'), { 'openai-codex': { type: 'oauth' }, openai: { type: 'api_key', key: 'sk-proj-live-value' } }) }, /holds an API key/) &&
  refused({ ...client, pi_home: makePiHome(join(root, 'other'), { anthropic: { type: 'oauth' } }) }, /not a ChatGPT login/))

// Launcher: a fake tmux whose session is a sleeper, logging what it was asked to run and with what.
writeFileSync(join(fakeBin, 'tmux'), `#!/usr/bin/env node
const { appendFileSync, readFileSync, writeFileSync } = require('node:fs')
const socket = process.argv[3]
let rest = process.argv.slice(4)
if (rest[0] === '-f') rest = rest.slice(2)
const e = process.env
const pid = (() => { try { return Number(readFileSync(socket + '.pid', 'utf8')) } catch { return 0 } })()
const alive = () => { try { process.kill(pid, 0); return true } catch { return false } }
if (rest[0] === 'new-session') {
  appendFileSync(socket + '.log', JSON.stringify({ socket, args: rest, env: Object.keys(e).filter(k => !/^(__CF|LC_|_$|SHLVL|PWD)/.test(k)).sort(), home: e.HOME,
    agentDir: e.PI_CODING_AGENT_DIR, config: e.NVOY_PI_HARNESS_CONFIG, instance: e.NVOY_PI_HARNESS_INSTANCE, skip: e.PI_SKIP_VERSION_CHECK }) + '\\n')
  const session = require('node:child_process').spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { detached: true, stdio: 'ignore' })
  writeFileSync(socket + '.pid', String(session.pid)); session.unref()
}
if (rest[0] === 'kill-server' && pid) try { process.kill(pid, 'SIGKILL') } catch {}
if (rest[0] === 'display-message') { if (!pid) process.exit(1); console.log(alive() ? '0 ' : '1 0') }
if (rest[0] === 'capture-pane') console.log('No API key found for openai-codex')
`)
chmodSync(join(fakeBin, 'tmux'), 0o755)
const configPath = clientConfig(client)
const launcher = spawn(process.execPath, ['mcp/tools/pi-harness.mjs', '--instance', 'pd-test', '--config', configPath], { cwd: resolve('.'), env: launcherEnv })
let launched = ''
launcher.stdout.on('data', d => { launched += d }); launcher.stderr.on('data', d => { launched += d })
const launcherExited = new Promise(done => launcher.on('exit', done))
const socket = join(stateDir, 'tmux.sock')
const sessions = () => readText(`${socket}.log`).split('\n').filter(Boolean).map(JSON.parse)
ok('the launcher starts pi in tmux on the harness\'s own socket and prints how to attach', await waitFor(() => /attach: tmux -S /.test(launched)) &&
  launched.includes(`attach: tmux -S ${socket} attach -t harness`) && sessions().length === 1 && sessions()[0].socket === socket)
const args = sessions()[0]?.args || []
const argAfter = name => args[args.indexOf(name) + 1]
ok('pi runs on the ChatGPT login, gpt-5.5 by default, resuming its one session from the state dir', args.includes('pi') && argAfter('--provider') === 'openai-codex' &&
  argAfter('--model') === 'gpt-5.5' && argAfter('--session-dir') === join(stateDir, 'sessions') && args.at(-1) === '--continue' && argAfter('-c') === join(stateDir, 'workspace'))
ok('discovered extensions are off and only this extension loads, by absolute path', args.includes('--no-extensions') && argAfter('-e') === resolve('mcp/tools/pi_harness_extension.mjs') &&
  args.filter(arg => arg === '-e').length === 1 && args.includes('--no-approve'))
ok('the channel tools are pi\'s only tools', argAfter('--tools') === 'nvoy_channel_list,nvoy_channel_read,nvoy_channel_reply')
ok('pi gets a built environment: its own agent dir and home, the config, and no API key', sessions()[0].env.join() ===
  'HOME,LANG,NVOY_PI_HARNESS_CONFIG,NVOY_PI_HARNESS_INSTANCE,PATH,PI_CODING_AGENT_DIR,PI_SKIP_VERSION_CHECK,TERM' && sessions()[0].agentDir === piHome &&
  sessions()[0].home === join(stateDir, 'home') && sessions()[0].config === configPath && sessions()[0].instance === 'pd-test' && sessions()[0].skip === '1')
ok('the workspace gets the participant instructions, owner-only, in an owner-only state dir', /You are the participant `pd-test`/.test(readText(join(stateDir, 'workspace', 'AGENTS.md'))) &&
  (statSync(join(stateDir, 'workspace', 'AGENTS.md')).mode & 0o777) === 0o600 && (statSync(stateDir).mode & 0o777) === 0o700)
const dup = spawnSync(process.execPath, ['mcp/tools/pi-harness.mjs', '--instance', 'pd-test', '--config', configPath], { cwd: resolve('.'), encoding: 'utf8', env: launcherEnv, timeout: 10000 })
ok('a second launcher on the same state dir is refused', dup.status === 1 && /portable Pi harness already runs as pid/.test(dup.stderr))
process.kill(Number(readText(`${socket}.pid`)), 'SIGKILL')
ok('pi exiting during startup is logged with its screen, and pi is restarted', await waitFor(() => sessions().length === 2) &&
  /pi exited \(status 0\) during startup; restarting:\nNo API key found for openai-codex/.test(launched) && /next start in/.test(launched))
ok('no key, login token or message body reaches the launcher\'s output', !/PRIVATE-KEY|CHATGPT-TOKEN|SECRET|sk-proj-live/.test(launched))
launcher.kill('SIGTERM'); await launcherExited
ok('stopping the launcher ends the session and frees its lock', await waitFor(() => { try { process.kill(Number(readText(`${socket}.pid`)), 0); return false } catch { return true } }) &&
  !existsSync(join(stateDir, 'nvoy', 'supervisor.lock')))

// Extension, in-process, against a fake pi. The fake ssh runs the fleet's own feed on the feed key
// and its own channel MCP on the channel key, each for this fleet root.
const ctl = join(root, 'ctl')
mkdirSync(ctl)
const fakeSsh = secretFile(join(fakeBin, 'ssh'), `#!/bin/sh
echo "$@" >> ${join(root, 'ssh-args.log')}
case "$*" in *"-i ${feedKey} "*) NVOY_INSTANCE_ROOT=${fleet} exec ${process.execPath} ${resolve('mcp/tools/codex-channel-feed.mjs')} --instance pd-test --heartbeat-ms 150 --poll-ms 40 ;; esac
[ -e ${ctl}/refuse ] && { echo "Connection closed by broker.example port 22" >&2; exit 255; }
echo $$ > ${join(root, 'channel.pid')}
[ -e ${ctl}/hang ] && exec sleep 30
NVOY_INSTANCE_ROOT=${fleet} exec ${process.execPath} ${resolve('mcp/tools/codex-channel-mcp.mjs')} --instance pd-test
`, 0o700)
Object.assign(process.env, { HARNESS_FEED_KEEPALIVE_MS: '100', HARNESS_FEED_SILENCE_MS: '3000', HARNESS_CHANNEL_CALL_MS: '3000' })
function fakePi() {
  const pi = { tools: new Map(), handlers: new Map(), sent: [], statuses: [] }
  pi.registerTool = tool => pi.tools.set(tool.name, tool)
  pi.on = (event, handler) => { pi.handlers.set(event, handler); return () => {} }
  pi.sendUserMessage = (text, options) => pi.sent.push({ text, options })
  pi.ctx = { hasUI: true, ui: { setStatus: (key, text) => pi.statuses.push(`${key}=${text}`) } }
  pi.start = () => pi.handlers.get('session_start')({ type: 'session_start', reason: 'startup' }, pi.ctx)
  pi.stop = () => pi.handlers.get('session_shutdown')({ type: 'session_shutdown', reason: 'quit' }, pi.ctx)
  return pi
}
ok('outside the launcher, the extension refuses to load rather than run unconfigured', throws(() => nvoyPiHarness(fakePi()), /NVOY_PI_HARNESS_CONFIG and NVOY_PI_HARNESS_INSTANCE must be set/))
Object.assign(process.env, { NVOY_PI_HARNESS_CONFIG: configPath, NVOY_PI_HARNESS_INSTANCE: 'pd-test', NVOY_HARNESS_SSH: fakeSsh })
const pi1 = fakePi()
const harness1 = nvoyPiHarness(pi1)
ok('loading registers the three channel tools and starts nothing', [...pi1.tools.keys()].join() === 'nvoy_channel_list,nvoy_channel_read,nvoy_channel_reply' &&
  !existsSync(join(root, 'ssh-args.log')) && !existsSync(lockPath))
const mcp = new Client({ name: 'pi-harness-test', version: '1' })
await mcp.connect(new StdioClientTransport({ command: process.execPath, args: [resolve('mcp/tools/codex-channel-mcp.mjs'), '--instance', 'pd-test'], env: { ...process.env, NVOY_INSTANCE_ROOT: fleet } }))
const fleetTools = (await mcp.listTools()).tools
await mcp.close()
ok('each tool\'s name, description and schema are the fleet channel\'s own', fleetTools.length === 3 && fleetTools.every(tool => {
  const mine = PI_CHANNEL_TOOLS.find(t => t.name === tool.name), registered = pi1.tools.get(tool.name)
  return mine && registered && mine.description === tool.description && JSON.stringify(mine.parameters) === JSON.stringify(tool.inputSchema) && typeof registered.execute === 'function' && registered.label
}))

const privateDir = join(stateDir, 'nvoy'), harnessLog = join(privateDir, 'harness.log')
pi1.start(); pi1.start()
ok('session_start connects the wake feed once and baselines the fleet queue', await waitFor(() => /wake feed connected/.test(readText(harnessLog))) &&
  /first start: baselined the pd-test queue/.test(readText(harnessLog)) && readText(join(root, 'ssh-args.log')).trim().split('\n').length === 1 &&
  pi1.statuses.at(-1) === 'nvoy=nvoy pd-test: listening')
const feedArgs = readText(join(root, 'ssh-args.log')).trim()
ok('the feed runs on its own key through the hardened entry, with ssh keepalives', feedArgs.includes(`-i ${feedKey} `) && !feedArgs.includes(chanKey) &&
  /ServerAliveInterval=15 -o ServerAliveCountMax=3 nvoy-pi@broker\.example$/.test(feedArgs) && feedArgs.includes('BatchMode=yes') && feedArgs.includes(`UserKnownHostsFile=${knownHosts}`))
appendFileSync(queue, record(2))
await waitFor(() => pi1.sent.length >= 1)
ok('an admitted envelope is injected as a readable follow-up user message carrying its id', pi1.sent.length === 1 &&
  pi1.sent[0].text === codexTurnText({ envelope: envelope(2), type: 'admitted-task' }) && pi1.sent[0].text.includes(`NVOY_ENVELOPE_ID=${envelope(2)}`) &&
  /nvoy_channel_read/.test(pi1.sent[0].text) && JSON.stringify(pi1.sent[0].options) === '{"deliverAs":"followUp"}')
ok('the baselined envelope is never injected, and no body reaches the message', !JSON.stringify(pi1.sent).includes(envelope(1)) && !/SECRET/.test(JSON.stringify(pi1.sent)))

const call = (name, params = {}, signal) => pi1.tools.get(name).execute('call-1', params, signal, undefined, pi1.ctx)
const listed = JSON.parse((await call('nvoy_channel_list')).content[0].text)
ok('nvoy_channel_list round-trips to the fleet channel over the channel key', listed.instance === 'pd-test' && listed.records.map(r => r.envelope).join() === [1, 2].map(envelope).join() &&
  readText(join(root, 'ssh-args.log')).includes(`-i ${chanKey} `))
const read = await call('nvoy_channel_read', { envelope: envelope(2) })
ok('nvoy_channel_read returns the admitted message to pi, and only through the tool', JSON.parse(read.content[0].text).messages[0].content === 'SECRET-BODY-2' && read.details === undefined)
const reply = JSON.parse((await call('nvoy_channel_reply', { envelope: envelope(2), text: 'done' })).content[0].text)
ok('nvoy_channel_reply queues a receipt-bound reply on the fleet', reply.queued === true && JSON.parse(readText(replies)).receipt === envelope(2) && JSON.parse(readText(replies)).content === 'done')
const again = await call('nvoy_channel_reply', { envelope: envelope(2), text: 'twice' }).then(() => '', error => error.message)
ok('a tool error from the fleet fails the tool call with its code', /NVOY_ALREADY_REPLIED/.test(again))
ok('one channel child serves every call', harness1.channel.spawned() === 1)
const firstChild = readText(join(root, 'channel.pid')).trim()
process.kill(Number(firstChild), 'SIGKILL')
await wait(100)
ok('a channel child that closes is replaced at the next call', JSON.parse((await call('nvoy_channel_list')).content[0].text).instance === 'pd-test' &&
  harness1.channel.spawned() === 2 && readText(join(root, 'channel.pid')).trim() !== firstChild)
writeFileSync(join(ctl, 'hang'), '')
harness1.channel.reset('test')
const hung = await call('nvoy_channel_list').then(() => '', error => error.message)
rmSync(join(ctl, 'hang'))
ok('a channel that never answers fails the call within its bound instead of hanging the turn', /did not answer within 3s/.test(hung) &&
  JSON.parse((await call('nvoy_channel_list')).content[0].text).instance === 'pd-test')
writeFileSync(join(ctl, 'refuse'), '')
harness1.channel.reset('test')
const refusedCall = await call('nvoy_channel_list').then(() => '', error => error.message)
rmSync(join(ctl, 'refuse'))
ok('a refused channel fails the call with ssh\'s own last line, and the next call reconnects', /the channel to the fleet closed \(255\): Connection closed by broker\.example/.test(refusedCall) &&
  JSON.parse((await call('nvoy_channel_list')).content[0].text).instance === 'pd-test')
const spawnedBefore = harness1.channel.spawned()
process.kill(JSON.parse(readText(lockPath)).pid, 'SIGKILL')
ok('the fleet recreating the adapter (the feed dying) reconnects the feed and drops the channel child', await waitFor(() => (readText(harnessLog).match(/wake feed connected/g) || []).length === 2) &&
  /wake feed exited .*; reconnecting in 1s/.test(readText(harnessLog)) && /dropping the channel child \(the wake feed reconnected\)/.test(readText(harnessLog)))
appendFileSync(queue, record(3, false))
ok('after the reconnect, new envelopes are injected again, and the channel is a fresh child', await waitFor(() => pi1.sent.length === 2) &&
  pi1.sent[1].text === codexTurnText({ envelope: envelope(3), type: 'admitted-task' }) && JSON.parse((await call('nvoy_channel_list')).content[0].text).records.length === 3 &&
  harness1.channel.spawned() === spawnedBefore + 1)
pi1.stop()
ok('session_shutdown ends the feed and frees the fleet lock', await waitFor(() => !existsSync(lockPath), 5000))

// A replay the fleet sends again (here, a cursor set back) is never injected twice.
writeFileSync(join(privateDir, 'feed-cursor.json'), JSON.stringify({ version: 1, instance: 'pd-test', cursor: envelope(1) }))
appendFileSync(queue, record(4))
const pi2 = fakePi()
nvoyPiHarness(pi2)
pi2.start()
await waitFor(() => pi2.sent.length >= 1)
await wait(300)
ok('envelopes already injected are skipped on replay; only the new one is injected, once', pi2.sent.length === 1 && pi2.sent[0].text.includes(`NVOY_ENVELOPE_ID=${envelope(4)}`) &&
  readText(join(privateDir, 'delivered.jsonl')).trim().split('\n').map(line => JSON.parse(line).envelope).join() === [2, 3, 4].map(envelope).join())
ok('the cursor, delivered record and log are owner-only and name the last envelope', ['feed-cursor.json', 'delivered.jsonl', 'harness.log'].every(f => (statSync(join(privateDir, f)).mode & 0o777) === 0o600) &&
  JSON.parse(readText(join(privateDir, 'feed-cursor.json'))).cursor === envelope(4))
ok('no key, login token or message body reaches the harness\'s files', !/PRIVATE-KEY|CHATGPT-TOKEN|SECRET/.test(readText(harnessLog) + readText(join(privateDir, 'delivered.jsonl')) + readText(join(privateDir, 'feed-cursor.json'))))
pi2.stop()
await waitFor(() => !existsSync(lockPath), 5000)

rmSync(root, { recursive: true, force: true })
console.log(fails ? `\n${fails} FAILED` : '\nall passed')
process.exit(fails ? 1 : 0)
