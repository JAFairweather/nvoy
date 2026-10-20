// The HTTPS door relays one fixed channel argv and nothing else, and only for the minted token.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, statSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { request } from 'node:http'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { LoggingMessageNotificationSchema } from '@modelcontextprotocol/sdk/types.js'
import { createDoor, tokenDigest } from '../mcp/tools/channel-https-door.mjs'
import { channelArgv, forcedArgv, forcedCommand } from '../mcp/tools/participant_unit.mjs'

let passed = 0, failed = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passed++ : failed++ }
const sleep = ms => new Promise(r => setTimeout(r, ms))
const root = mkdtempSync(join(tmpdir(), 'nvoy-door-'))
const fake = resolve(new URL('.', import.meta.url).pathname, 'fixtures/door-fake-channel.mjs')
const token = 'a'.repeat(64)
const argv = [process.execPath, fake, '--instance', 'door-test']
const logs = []
const door = createDoor({ id: 'door-test', tokenHash: tokenDigest(token).toString('hex'), argv, env: { PATH: process.env.PATH },
  maxSessions: 2, failLimit: 5, log: m => logs.push(m) })
await new Promise(r => door.listen({ host: '127.0.0.1', port: 0 }, r))
const base = `http://127.0.0.1:${door.address().port}`
const url = `${base}/door/door-test/mcp`
const init = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } }
const post = (path, auth, body = init, extra = {}) => fetch(`${base}${path}`, { method: 'POST',
  headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...(auth ? { authorization: auth } : {}), ...extra },
  body: typeof body === 'string' ? body : JSON.stringify(body) })
const connect = async () => {
  const client = new Client({ name: 'door-test-client', version: '0' })
  const transport = new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { authorization: `Bearer ${token}` } } })
  await client.connect(transport)
  return { client, transport }
}
const text = r => r.content?.[0]?.text

// --- the single argv definition -------------------------------------------------------------
const m = { id: 'x', workerUid: 1001, workerHandoffGid: 1002, adapterContainer: 'nvoy-x-adapter-1' }
ok('the SSH forced command is the door argv joined — one definition for both transports', forcedCommand(m) === forcedArgv(m).join(' '))
ok('the SSH forced command is docker exec as the worker into the manifest adapter', forcedArgv(m).slice(1, 6).join(' ') === 'exec -i --user 1001:1002 nvoy-x-adapter-1')
ok('…of exactly the argv the door spawns', JSON.stringify(forcedArgv(m).slice(6)) === JSON.stringify(channelArgv(m))
  && channelArgv(m).join(' ') === '/usr/local/bin/node /srv/nvoy/mcp/tools/claude-channel.mjs --instance x')

// --- who may dial ---------------------------------------------------------------------------
ok('a path other than /door/<id>/mcp is 404', (await post('/door/other/mcp', `Bearer ${token}`)).status === 404)
ok('no token is 401', (await post('/door/door-test/mcp')).status === 401)
ok('a wrong token is 401', (await post('/door/door-test/mcp', `Bearer ${'b'.repeat(64)}`)).status === 401)
ok('a non-Bearer scheme is 401', (await post('/door/door-test/mcp', `Basic ${token}`)).status === 401)
ok('an authorized non-initialize first request opens nothing', (await post('/door/door-test/mcp', `Bearer ${token}`, { jsonrpc: '2.0', id: 2, method: 'tools/list' })).status === 400)
// Only the headers are sent: a door that answers proves it refused the body without reading it.
const declaredTooBig = await new Promise((done, fail) => {
  const r = request(url, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json',
    'content-length': String(1024 * 1024 + 1) } }, res => { res.resume(); done(res.statusCode) })
  r.on('error', fail); r.flushHeaders()
})
ok('a declared oversized body is 413 before it is read', declaredTooBig === 413)
ok('a body that is not JSON is 400', (await post('/door/door-test/mcp', `Bearer ${token}`, '{nope')).status === 400)
const bareGet = await fetch(url, { headers: { authorization: `Bearer ${token}`, accept: 'text/event-stream' } })
ok('an authorized GET without a session is 405 with Allow: POST, as Streamable HTTP requires',
  bareGet.status === 405 && bareGet.headers.get('allow') === 'POST' && logs.some(l => /GET without a session refused 405/.test(l)))
const staleGet = await fetch(url, { headers: { authorization: `Bearer ${token}`, accept: 'text/event-stream', 'mcp-session-id': 'gone-session-id' } })
ok('…but a GET for an unknown session is 404, so the client re-initializes', staleGet.status === 404
  && logs.some(l => /GET for unknown session gone-ses refused 404/.test(l)))
ok('an unauthorized GET is still 401 before anything else', (await fetch(url)).status === 401)

// --- the relay ------------------------------------------------------------------------------
const a = await connect()
const tools = await a.client.listTools()
ok('tools/list is relayed from the channel', tools.tools.map(t => t.name).join(',') === 'argv,echo,notify')
ok('a tool call round-trips unchanged', text(await a.client.callTool({ name: 'echo', arguments: { text: 'héllo door' } })) === 'héllo door')
const seen = JSON.parse(text(await a.client.callTool({ name: 'argv', arguments: { instance: 'someone-else', argv: ['/bin/sh'] } })))
ok('the channel ran the fixed argv — nothing a request carried', JSON.stringify(seen.argv) === JSON.stringify(['--instance', 'door-test']))
const announced = new Promise(r => a.client.setNotificationHandler(LoggingMessageNotificationSchema, n => r(n.params.data)))
await sleep(200) // let the client open its standalone SSE stream
await a.client.callTool({ name: 'notify', arguments: {} })
ok('a channel notification reaches the client', await Promise.race([announced, sleep(3000).then(() => null)]) === 'door-announce')

// --- session lifecycle ----------------------------------------------------------------------
const pidAlive = pid => { try { process.kill(pid, 0); return true } catch { return false } }
ok('the channel process is alive while its session is open', pidAlive(seen.pid))
await a.transport.terminateSession()
await sleep(500)
ok('DELETE ends the session and its channel process', !pidAlive(seen.pid) && logs.some(l => /closed \(client deleted it\)/.test(l)))

const b = await connect(), c = await connect()
const bPid = JSON.parse(text(await b.client.callTool({ name: 'argv', arguments: {} }))).pid
const d = await connect()
await sleep(500)
ok('a session beyond maxSessions evicts the oldest, and its channel exits', !pidAlive(bPid) && logs.some(l => /evicted by a newer session/.test(l)))
ok('the newer sessions still work', text(await d.client.callTool({ name: 'echo', arguments: { text: 'd' } })) === 'd'
  && text(await c.client.callTool({ name: 'echo', arguments: { text: 'c' } })) === 'c')
ok('no token or body ever reaches the log', !logs.some(l => l.includes(token) || l.includes('héllo')))
await c.transport.terminateSession(); await d.transport.terminateSession()

// The real channel is single-instance per identity, so the default door keeps one session, and a
// client that reconnects without a DELETE takes the channel over rather than waiting out the idle.
const lockDoor = createDoor({ id: 'door-test', tokenHash: tokenDigest(token).toString('hex'),
  argv: [...argv, '--lock', join(root, 'channel.lock')], env: { PATH: process.env.PATH }, log: m => logs.push(m) })
await new Promise(r => lockDoor.listen({ host: '127.0.0.1', port: 0 }, r))
const lockUrl = new URL(`http://127.0.0.1:${lockDoor.address().port}/door/door-test/mcp`)
const lockConnect = async () => {
  const client = new Client({ name: 'door-lock-client', version: '0' })
  const transport = new StreamableHTTPClientTransport(lockUrl, { requestInit: { headers: { authorization: `Bearer ${token}` } } })
  await client.connect(transport)
  return { client, transport }
}
const e = await lockConnect()
const ePid = JSON.parse(text(await e.client.callTool({ name: 'argv', arguments: {} }))).pid
const f = await lockConnect() // e is abandoned, never DELETEd
const fPid = JSON.parse(text(await f.client.callTool({ name: 'argv', arguments: {} }))).pid
ok('by default a reconnect evicts the abandoned session and gets a working channel despite its lock',
  !pidAlive(ePid) && pidAlive(fPid) && fPid !== ePid)
await f.transport.terminateSession()
lockDoor.close()

// --- the failure bucket ---------------------------------------------------------------------
for (let i = 0; i < 6; i++) await post('/door/door-test/mcp', 'Bearer nope')
ok('after failLimit failures in a minute, a wrong token gets 429', (await post('/door/door-test/mcp', 'Bearer nope')).status === 429)
const stillOpen = await post('/door/door-test/mcp', `Bearer ${token}`)
ok('…but strangers cannot lock out the right token', stillOpen.status === 200 && Boolean(stillOpen.headers.get('mcp-session-id')))
if (stillOpen.headers.get('mcp-session-id')) await fetch(url, { method: 'DELETE', headers: { authorization: `Bearer ${token}`, 'mcp-session-id': stillOpen.headers.get('mcp-session-id') } })
door.close()

// --- the CLI: mint, and what serve refuses --------------------------------------------------
const instances = join(root, 'instances'); mkdirSync(instances)
const uid = process.getuid(), gid = process.getgid()
const manifest = (id, extra = {}) => ({ version: 1, id, pubkey: '1'.repeat(64), broker_mode: 'local',
  state_dir: join(root, id, 'state'), runtime_dir: join(root, id, 'runtime'), spool_dir: join(root, id, 'spool'),
  bunker_uri_ref: '/etc/nvoy/test.bunker', bunker_client_ref: '/etc/nvoy/test.client',
  worker_enabled: false, delivery_mode: 'notify_only', broker_adapter_gid: gid, worker_handoff_gid: gid + 1,
  watcher_uid: uid + 11, broker_uid: uid + 12, adapter_uid: uid + 13, worker_uid: uid,
  grantors: ['2'.repeat(64)], relays: ['wss://nos.lol'],
  channel_door: { token_hash_ref: `/etc/nvoy/credentials/${id}.door-token.sha256`, network: 'nave' }, ...extra })
for (const id of ['door-ok', 'door-worker', 'door-none']) for (const d of ['state', 'runtime', 'spool']) mkdirSync(join(root, id, d), { recursive: true })
writeFileSync(join(instances, 'door-ok.json'), JSON.stringify(manifest('door-ok')))
// A separate root: assertNoCollisions reads every manifest beside the one being loaded.
const workerInstances = join(root, 'worker-instances'); mkdirSync(workerInstances)
writeFileSync(join(workerInstances, 'door-worker.json'), JSON.stringify(manifest('door-worker', { delivery_mode: 'codex_app_server', codex_thread_id: '00000000-0000-4000-8000-000000000000' })))
const tool = resolve(new URL('.', import.meta.url).pathname, '../mcp/tools/channel-https-door.mjs')
const run = (...args) => spawnSync(process.execPath, [tool, ...args], { env: { ...process.env, NVOY_INSTANCE_ROOT: instances }, encoding: 'utf8' })
const runIn = (dir, ...args) => spawnSync(process.execPath, [tool, ...args], { env: { ...process.env, NVOY_INSTANCE_ROOT: dir }, encoding: 'utf8' })
const noDoorInstances = join(root, 'no-door-instances'); mkdirSync(noDoorInstances)
writeFileSync(join(noDoorInstances, 'door-none.json'), JSON.stringify(manifest('door-none', { channel_door: undefined })))
const tokenOut = join(root, 'door-ok.token'), hashOut = join(root, 'door-ok.sha256')
const minted = run('mint', '--instance', 'door-ok', '--token-out', tokenOut, '--token-hash-file', hashOut)
ok('mint succeeds for a notify-only channel instance', minted.status === 0)
const minted_token = existsSync(tokenOut) ? readFileSync(tokenOut, 'utf8').trim() : ''
ok('the token file is 0600 and holds 64 hex', (statSync(tokenOut).mode & 0o777) === 0o600 && /^[0-9a-f]{64}$/.test(minted_token))
ok('the host keeps only the hash of the token', readFileSync(hashOut, 'utf8').trim() === tokenDigest(minted_token).toString('hex'))
ok('mint prints paths, never the token', !minted.stdout.includes(minted_token) && minted.stdout.includes(tokenOut))
ok('mint refuses to overwrite an existing token file', run('mint', '--instance', 'door-ok', '--token-out', tokenOut, '--token-hash-file', hashOut).status !== 0)
ok('the door refuses any instance but notify_only, as the SSH principal does',
  /requires a local-broker, worker-disabled notify_only/.test(runIn(workerInstances, 'serve', '--instance', 'door-worker', '--listen', '127.0.0.1:0').stderr))
ok('the door refuses an instance whose manifest does not ask for one',
  /has no channel_door in its manifest/.test(runIn(noDoorInstances, 'serve', '--instance', 'door-none', '--listen', '127.0.0.1:0').stderr))
// door-ok's worker gid is this process's gid + 1, so this process is not its worker.
ok('serve refuses to run as anyone but the manifest worker, whose uid:gid the channel inherits',
  /must run as the manifest worker/.test(run('serve', '--instance', 'door-ok', '--listen', '127.0.0.1:0', '--token-hash-file', hashOut).stderr))
let bad = 0
const badRoot = (channel_door, extra = {}) => {
  const dir = join(root, `bad-${++bad}`); mkdirSync(dir)
  for (const x of ['state', 'runtime', 'spool']) mkdirSync(join(root, 'door-bad', x), { recursive: true })
  writeFileSync(join(dir, 'door-bad.json'), JSON.stringify(manifest('door-bad', { channel_door, ...extra })))
  return runIn(dir, 'mint', '--instance', 'door-bad', '--token-out', join(dir, 'never'))
}
ok('a channel_door hash outside /etc/nvoy/credentials is refused', /channel_door requires token_hash_ref/.test(badRoot({ token_hash_ref: '/tmp/x', network: 'nave' }).stderr))
ok('a channel_door without a network is refused', /channel_door requires network/.test(badRoot({ token_hash_ref: '/etc/nvoy/credentials/x' }).stderr))
ok('a channel_door hash naming a Nostr credential is refused', /must not name another credential/.test(
  badRoot({ token_hash_ref: '/etc/nvoy/credentials/door-bad.bunker', network: 'nave' }, { bunker_uri_ref: '/etc/nvoy/credentials/door-bad.bunker' }).stderr))

// --- rendering ------------------------------------------------------------------------------
const renderer = resolve(new URL('.', import.meta.url).pathname, '../mcp/tools/render-instance-compose.mjs')
const image = `ghcr.io/example/nvoy@sha256:${'c'.repeat(64)}`
const render = (dir, id) => spawnSync(process.execPath, [renderer, '--instance', id, '--image', image], { env: { ...process.env, NVOY_INSTANCE_ROOT: dir }, encoding: 'utf8' })
const withDoor = render(instances, 'door-ok'), withoutDoor = render(noDoorInstances, 'door-none')
ok('a door manifest renders a door service', withDoor.status === 0 && /^  door:$/m.test(withDoor.stdout) && withDoor.stdout.includes('container_name: nvoy-door-ok-door'))
const doorService = (withDoor.stdout.split(/^  door:$/m)[1] || '').split(/^  # @|^secrets:/m)[0]
ok('…as the manifest worker, on only the proxy network, with no host port',
  doorService.includes(`user: "${uid}:${gid + 1}"`) && doorService.includes('networks: [door_edge]') && !/ports:/.test(doorService)
  && /door_edge:\n\s+external: true\n\s+name: "nave"/.test(withDoor.stdout))
ok('…reading the hash through init, never the token', withDoor.stdout.includes('file: "/etc/nvoy/credentials/door-ok.door-token.sha256"') && doorService.includes('channel_door_credentials'))
const initService = (withDoor.stdout.split(/^  init:$/m)[1] || '').split(/^  watcher:$/m)[0]
ok('only the root initializer receives the hash file', initService.includes('source: nvoy_channel_door_token_hash')
  && initService.includes('NVOY_CHANNEL_DOOR_TOKEN_HASH_SOURCE: /run/secrets/channel-door-token-hash') && !doorService.includes('secrets:'))
const initSource = readFileSync(resolve(new URL('.', import.meta.url).pathname, '../mcp/tools/instance-runtime-init.mjs'), 'utf8')
ok('the initializer copies the hash worker-owned, and refuses a stray hash source',
  /provisionSecret\(sources\.channelDoorTokenHash, `\$\{doorCredDir\}\/token\.sha256`, m\.workerUid, m\.workerUid/.test(initSource)
  && /a runtime without a channel door refuses a token hash source/.test(initSource))
const runnerSource = readFileSync(resolve(new URL('.', import.meta.url).pathname, '../deploy/runtime-deploy-runner.py'), 'utf8')
ok('the fleet runner fails a deploy whose door is not running', /"door": raw\.get\("channel_door"\) is not None/.test(runnerSource)
  && /\(\["door"\] if instance\.get\("door"\) else \[\]\)/.test(runnerSource))
ok('a manifest without channel_door renders no door, network or hash', withoutDoor.status === 0 && !/channel-https-door|door_edge|channel_door|CHANNEL_DOOR/.test(withoutDoor.stdout))

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
