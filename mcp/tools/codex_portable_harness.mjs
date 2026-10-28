// A Codex harness that runs on any box, a Mac included, on its owner's ChatGPT login, and that a
// person can watch and join. codex_harness.mjs is the fleet form (stdio, API key, local queue);
// this one differs in three places, each forced by where it runs:
//
// - Transport. `codex app-server --listen unix://<CODEX_HOME>/ctl/as.sock` instead of stdio, so
//   `codex resume <thread> --remote unix://…` can attach a TUI to the very thread being driven.
//   Requests Codex makes of the client fan out to every attached connection, so this supervisor
//   answers none of them: a person may.
// - Wake source. The admitted queue is on the fleet. A second forced-command key streams its
//   metadata (codex-channel-feed.mjs) over a long-lived, non-blocking ssh; the supervisor keeps an
//   envelope cursor and reconnects from it with backoff. The feed also holds the fleet-side lock
//   that makes this the identity's only Codex consumer.
// - Injection. A person may be mid-turn, so envelopes become `turn/start` only when the thread is
//   idle. Those that arrive mid-turn are held and go in together, as one turn, when it ends: one
//   turn each was most of an agent's day (waggle#633). A turn that outlasts HARNESS_HOLD_MAX_MS
//   gets them as one `thread/queue/add` (experimental API) instead, which runs after it. Either
//   way the input carries `clientUserMessageId: nvoy:<first envelope>`, and each is recorded once.
//
// The channel MCP is an ssh into the fleet's adapter container, which each release or manifest
// change recreates. Codex never restarts a dead MCP server: every later tool call fails with
// "Transport closed" (codex-cli 0.149.1, 2026-09-25). So the supervisor asks the channel itself,
// with `mcpServer/tool/call`, before it declares the thread ready, before each injection, and
// whenever the feed reconnects (the feed's ssh dies with the same container). A dead channel
// restarts `codex app-server` once no turn is running, and the thread is resumed.
//
// Like the fleet form it never reads a message body or a reply: Codex does, through the keyless
// channel tools, and the broker rechecks the grant before it signs.

import { appendFileSync, chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { spawn, spawnSync } from 'node:child_process'
import { homedir } from 'node:os'
import { isAbsolute, resolve } from 'node:path'
import { fixedPath, knownHostsFile, privateFile, sshChannelEntry, SSH, SSH_TARGET } from './channel_client.mjs'
import { instanceId } from './runtime_manifest.mjs'
import { codexBatchText, codexConfigToml, defaultInstructions, serverName } from './harness_session.mjs'
import { openThread } from './codex_harness.mjs'
import { connectWsPeer } from './codex_ws_peer.mjs'
import { claimPidLock } from './pid_lock.mjs'

const HEX64 = /^[0-9a-f]{64}$/
const sleep = ms => new Promise(done => setTimeout(done, ms))
const PS = existsSync('/bin/ps') ? '/bin/ps' : '/usr/bin/ps'
const gone = pid => { try { process.kill(pid, 0); return false } catch (error) { return error.code === 'ESRCH' } }

// The client config names paths, never values. Beyond the portable Claude config's refusals, a
// field or value that could carry an OpenAI API key refuses the file: this harness bills the
// owner's subscription, and a key anywhere near it is how it would quietly bill an account instead.
const CODEX_FIELDS = new Set(['instance', 'ssh_target', 'identity_file', 'feed_identity_file', 'known_hosts_file', 'codex_home', 'model', 'pubkey', 'channels'])
export function readCodexClientConfig(path, id, own = homedir()) {
  const file = fixedPath(path, 'client config', 64 * 1024)
  if ((file.stat.mode & 0o022) !== 0) throw new Error('client config must not be group/world writable')
  let raw
  try { raw = JSON.parse(readFileSync(file.path, 'utf8')) } catch { throw new Error('client config is not valid JSON') }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('client config must be a JSON object')
  const text = JSON.stringify(raw)
  if (Object.keys(raw).some(key => /nsec|bunker|secret|signer|private/i.test(key)) || /nsec1[02-9ac-hj-np-z]{20,}|bunker:\/\//i.test(text)) {
    throw new Error('client config must not name a Nostr key or Bunker credential: nothing on this box signs')
  }
  if (Object.keys(raw).some(key => /api[_-]?key|openai|token|credential|password/i.test(key)) || /(^|[^a-z0-9])sk-[a-z0-9_-]{8,}/i.test(text)) {
    throw new Error('client config must not name an OpenAI API key: the portable Codex harness runs on the ChatGPT login only')
  }
  const unknown = Object.keys(raw).filter(key => !CODEX_FIELDS.has(key))
  if (unknown.length) throw new Error(`client config has unknown field ${unknown.join(', ')}`)
  if (raw.instance !== id) throw new Error('client config names a different instance')
  const target = String(raw.ssh_target || '')
  if (!SSH_TARGET.test(target)) throw new Error('client config ssh_target must be a fixed user@host')
  const model = String(raw.model || '')
  if (model && !/^[a-z0-9][a-z0-9.\-\[\]]{0,63}$/i.test(model)) throw new Error('client config model must be a model name or alias')
  const pubkey = String(raw.pubkey || '')
  if (pubkey && !/^[0-9a-f]{64}$/.test(pubkey)) throw new Error('client config pubkey must be 64 lowercase hex characters')
  const channels = raw.channels === undefined ? [] : raw.channels
  if (!Array.isArray(channels) || !channels.every(c => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(c))) throw new Error('client config channels must be Buzz channel ids')
  const codexHome = codexHomeDir(String(raw.codex_home || ''), own)
  const identity = privateFile(String(raw.identity_file || ''), 'SSH channel identity file')
  const feedIdentity = privateFile(String(raw.feed_identity_file || ''), 'SSH feed identity file')
  if (identity === feedIdentity) throw new Error('the channel and feed keys must be two keys: each forced command admits exactly one')
  const socket = resolve(codexHome, 'ctl', 'as.sock')
  if (Buffer.byteLength(socket) >= 104) throw new Error('codex_home is too deep for its control socket; choose a shorter path')
  return Object.freeze({ id: instanceId(id), target, model, pubkey, channels, codexHome, socket, identity, feedIdentity,
    knownHosts: knownHostsFile(String(raw.known_hosts_file || '')) })
}

// The harness's own CODEX_HOME, which its owner has logged in with `codex login --device-auth`.
// Only the auth mode is read from the login, and nothing from it is ever printed.
function codexHomeDir(path, own) {
  if (!isAbsolute(path)) throw new Error('client config codex_home path must be absolute')
  const home = resolve(path)
  if (home === resolve(own) || home === resolve(own, '.codex')) throw new Error('codex_home must be the harness\'s own directory, never your home or ~/.codex')
  let st
  try { st = lstatSync(home) } catch { throw new Error('codex_home is missing: create it and log in there first') }
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error('codex_home must be a real directory')
  if (st.uid !== process.getuid?.()) throw new Error('codex_home must be owned by the current user')
  if ((st.mode & 0o077) !== 0) throw new Error('codex_home must not be accessible by group or other (use mode 0700)')
  const authFile = privateFile(resolve(home, 'auth.json'), 'Codex login (codex_home/auth.json)')
  let auth
  try { auth = JSON.parse(readFileSync(authFile, 'utf8')) } catch { throw new Error('Codex login (codex_home/auth.json) is not valid JSON') }
  if (auth?.OPENAI_API_KEY) throw new Error('Codex login in codex_home holds an API key: log in with `codex login --device-auth` only')
  if (auth?.auth_mode !== 'chatgpt') throw new Error('Codex login in codex_home is not a ChatGPT login: run `codex login --device-auth` there')
  return home
}

export function refuseApiKeyEnvironment(env) {
  for (const name of ['OPENAI_API_KEY', 'CODEX_API_KEY']) if (env[name]) throw new Error(`${name} is set in this environment: the portable Codex harness runs on the ChatGPT login only; unset it`)
}

const shellWord = value => /^[\w/.:@%+=-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`
export const attachCommand = ({ codexHome, socket, threadId }) => `CODEX_HOME=${shellWord(codexHome)} codex resume ${threadId} --remote ${shellWord(`unix://${socket}`)}`

// The feed's ssh: the hardened channel entry, keepalives included, on the feed key.
export function sshFeedArgs(config) {
  return sshChannelEntry({ identity: config.feedIdentity, knownHosts: config.knownHosts, target: config.target }).args
}

export async function runCodexPortableHarness({ config, log, stopping, ssh = SSH }) {
  const { codexHome, socket } = config
  const workdir = resolve(codexHome, 'workspace'), privateDir = resolve(codexHome, 'nvoy'), ctlDir = resolve(codexHome, 'ctl')
  const threadPath = resolve(privateDir, 'codex-thread.json'), deliveredPath = resolve(privateDir, 'delivered.jsonl'), cursorPath = resolve(privateDir, 'feed-cursor.json')
  const STARTUP_MS = Number(process.env.HARNESS_STARTUP_MS || 30000)
  const RETRY_MAX_MS = Number(process.env.HARNESS_RETRY_MAX_MS || 300000)
  const KEEPALIVE_MS = Number(process.env.HARNESS_FEED_KEEPALIVE_MS || 20000)
  const SILENCE_MS = Number(process.env.HARNESS_FEED_SILENCE_MS || 90000)
  const FEED_RETRY_MAX_MS = Number(process.env.HARNESS_FEED_RETRY_MAX_MS || 60000)
  const RETRY_MS = Number(process.env.HARNESS_RETRY_MS || 5000)
  const PROBE_MS = Number(process.env.HARNESS_CHANNEL_PROBE_MS || 30000)
  const STOP_MS = Number(process.env.HARNESS_STOP_MS || 5000)
  const HOLD_MAX_MS = Number(process.env.HARNESS_HOLD_MAX_MS || 900000)
  const BATCH_MAX = Math.max(1, Number(process.env.HARNESS_BATCH_MAX || 20))
  const writePrivate = (path, value) => { writeFileSync(path, value, { mode: 0o600 }); chmodSync(path, 0o600) }
  for (const dir of [workdir, privateDir, ctlDir]) { mkdirSync(dir, { recursive: true, mode: 0o700 }); chmodSync(dir, 0o700) }
  const release = claimPidLock(resolve(privateDir, 'supervisor.lock'), config.id, 'portable Codex harness')
  const children = new Set()
  process.on('exit', () => { for (const child of children) try { child.kill('SIGTERM') } catch {} release() })

  const manifest = { id: config.id, pubkey: config.pubkey, buzz: { channels: config.channels }, harness: { runner: 'codex', model: config.model } }
  writePrivate(resolve(codexHome, 'config.toml'), codexConfigToml({ manifest, root: '', model: config.model, auth: 'chatgpt',
    remote: { identity: config.identity, knownHosts: config.knownHosts, target: config.target } }))
  if (!existsSync(resolve(workdir, 'AGENTS.md'))) writePrivate(resolve(workdir, 'AGENTS.md'), defaultInstructions(manifest))

  const delivered = new Set(existsSync(deliveredPath)
    ? readFileSync(deliveredPath, 'utf8').split('\n').filter(Boolean).map(line => { try { return JSON.parse(line).envelope } catch { return '' } }) : [])
  const markDelivered = (envelope, row) => {
    appendFileSync(deliveredPath, JSON.stringify({ envelope, ...row, at: Date.now() }) + '\n', { mode: 0o600 }); chmodSync(deliveredPath, 0o600)
    delivered.add(envelope)
  }
  // undefined: never baselined. null: baselined on an empty queue, so everything it holds is new.
  let cursor
  try { const saved = JSON.parse(readFileSync(cursorPath, 'utf8')); if (saved.instance === config.id && (saved.cursor === null || HEX64.test(saved.cursor))) cursor = saved.cursor } catch {}
  const saveCursor = value => { cursor = value; writePrivate(cursorPath, JSON.stringify({ version: 1, instance: config.id, cursor: value }) + '\n') }

  // Envelopes the feed has announced and the thread has not yet taken, oldest first.
  const pending = [], announced = new Set()
  let wake = () => {}, feeds = 0, recheck = false
  const offer = row => { if (announced.has(row.envelope)) return; announced.add(row.envelope); pending.push(row); wake() }

  async function feedOnce() {
    const since = cursor === undefined ? null : cursor === null ? 'start' : cursor
    const child = spawn(ssh, sshFeedArgs(config), { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH || '/usr/bin:/bin', HOME: codexHome } })
    children.add(child)
    let stderr = '', out = '', healthy = false, lastLine = Date.now(), reason = ''
    const stop = why => { if (!reason) reason = why; try { child.kill('SIGTERM') } catch {} }
    const exited = new Promise(done => child.on('close', code => done(code)))
    child.on('error', error => stop(error.code || error.message))
    child.stdin.on('error', () => {})
    child.stderr.on('data', data => { stderr = (stderr + String(data)).slice(-600) })
    child.stdin.write(JSON.stringify({ since }) + '\n')
    const keepalive = setInterval(() => child.stdin.write('{"ping":1}\n'), KEEPALIVE_MS)
    const watchdog = setInterval(() => { if (Date.now() - lastLine > SILENCE_MS) stop(`silent for ${SILENCE_MS}ms`) }, Math.min(SILENCE_MS, 1000))
    child.stdout.on('data', data => {
      out += data
      if (out.length > 4096 && out.indexOf('\n') < 0) return stop('feed line exceeds its bound')
      let at
      while ((at = out.indexOf('\n')) >= 0) {
        const line = out.slice(0, at); out = out.slice(at + 1); lastLine = Date.now()
        let event
        try { event = JSON.parse(line) } catch { return stop('feed sent malformed JSON') }
        if (event.event === 'hello') {
          if (event.instance !== config.id) return stop('feed answered for another instance')
          healthy = true
          if (++feeds > 1) { recheck = true; wake() }
          const placed = event.cursor === null || HEX64.test(String(event.cursor)) ? event.cursor : null
          if (cursor === undefined) { saveCursor(placed); log(`first start: baselined the ${config.id} queue; later arrivals are live`) }
          else if (event.since_found === false) { saveCursor(placed); log(`the fleet queue no longer holds the saved cursor; resuming from now`) }
          log('wake feed connected')
        } else if (event.event === 'admitted' && healthy && HEX64.test(String(event.envelope))) {
          offer({ envelope: event.envelope, type: event.type === 'verified-notification' ? 'verified-notification' : 'admitted-task' })
        }
      }
    })
    const code = await exited
    clearInterval(keepalive); clearInterval(watchdog); children.delete(child)
    return { healthy, reason: reason || `exited (${code})${stderr.trim() ? `: ${stderr.trim().split('\n').at(-1).slice(0, 300)}` : ''}` }
  }
  ;(async () => {
    let delay = 1000
    while (!stopping()) {
      const { healthy, reason } = await feedOnce()
      if (stopping()) break
      if (healthy) delay = 1000
      log(`wake feed ${reason}; reconnecting in ${Math.round(delay / 1000)}s`)
      await sleep(delay)
      delay = Math.min(delay * 2, FEED_RETRY_MAX_MS)
    }
  })()

  const env = { PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin', HOME: codexHome, CODEX_HOME: codexHome }
  // codex-cli 0.163 drains on SIGTERM while a client stays attached, and holds its daemon lock,
  // outside CODEX_HOME, until it exits: a server only asked to stop outlived the restart, and
  // every later start failed "control socket is already in use" (dj-codex, 2026-10-27). So ask, then make it.
  const stopPid = async (pid, exited) => {
    if (exited()) return
    try { process.kill(pid, 'SIGTERM') } catch { return }
    for (const until = Date.now() + STOP_MS; Date.now() < until && !exited(); ) await sleep(50)
    if (exited()) return
    log(`codex app-server ${pid} did not stop when asked; killing it`)
    try { process.kill(pid, 'SIGKILL') } catch {}
    for (const until = Date.now() + STOP_MS; Date.now() < until && !exited(); ) await sleep(50)
  }
  // One an earlier supervisor left (one killed outright cannot stop its child) holds the same lock.
  const leftovers = () => (spawnSync(PS, ['-axww', '-o', 'pid=,command='], { encoding: 'utf8' }).stdout || '').split('\n')
    .map(line => /^\s*(\d+)\s+(.*)$/.exec(line)).filter(m => m && m[2].endsWith(` app-server --listen unix://${socket}`)).map(m => Number(m[1]))
    .filter(pid => pid !== process.pid && ![...children].some(child => child.pid === pid))
  let delay = RETRY_MS
  while (!stopping()) {
    const startedAt = Date.now()
    let server = null, child = null
    try {
      for (const pid of leftovers()) { log(`stopping codex app-server ${pid}, left on the control socket by an earlier run`); await stopPid(pid, () => gone(pid)) }
      if (existsSync(socket)) { const st = lstatSync(socket); if (!st.isSocket() && !st.isSymbolicLink()) throw new Error('the control socket path holds something that is not a socket'); rmSync(socket) }
      child = spawn('codex', ['app-server', '--listen', `unix://${socket}`], { stdio: ['ignore', 'ignore', 'pipe'], env })
      children.add(child)
      let stderr = ''
      child.stderr.on('data', data => { stderr = (stderr + String(data)).slice(-4000) })
      const childExited = new Promise(done => child.on('exit', code => done(`codex app-server exited (${code})${stderr ? `: ${stderr.trim().slice(-300)}` : ''}`)))
      child.on('error', () => {})
      const deadline = Date.now() + STARTUP_MS
      while (!server) {
        if (existsSync(socket)) try { server = await connectWsPeer({ socketPath: socket, onServerRequest: message => log(`Codex asked the client for ${message.method}; left for an attached person to answer`) }) } catch {}
        if (server) break
        const early = await Promise.race([childExited, sleep(100).then(() => '')])
        if (early) throw new Error(early)
        if (Date.now() > deadline) throw new Error(`codex app-server did not listen within ${Math.round(STARTUP_MS / 1000)}s`)
      }
      chmodSync(socket, 0o600)
      await server.request('initialize', { clientInfo: { name: 'nvoy-harness', title: 'Nvoy harness', version: '1' }, capabilities: { experimentalApi: true } })
      server.notify('initialized')
      const { threadId, thread, saved } = await openThread({ server, manifest, workdir, threadPath, log, writePrivate })
      // '' when the channel answered, null when this Codex cannot be asked, else why it is down.
      // Any answer, a tool error included, is a live channel; only a failed call is a dead one. On
      // 0.149.1 a server that has exited rejects with -32603 "Transport closed", an unknown method
      // is -32600 "unknown variant" (-32601 by the JSON-RPC spec), and the call adds nothing to the
      // thread's rollout, so probing never reaches the conversation the model sees.
      const channelDown = async () => {
        try { await server.request('mcpServer/tool/call', { threadId, server: serverName(manifest), tool: 'nvoy_channel_list', arguments: {} }, PROBE_MS); return '' }
        catch (error) { if (server.closed) throw error; return error.code === -32601 || /unknown variant `mcpServer\/tool\/call`/.test(error.message) ? null : error.message }
      }
      const down0 = await channelDown()
      if (down0) throw new Error(`the channel to the fleet did not answer: ${down0}`)
      if (down0 === null) log('this Codex cannot be asked about its channel; a wake feed reconnect restarts it instead')
      let busy = thread?.status?.type === 'active', attachable = saved, down = ''
      const ended = new Set(), turnEnvelope = new Map()
      server.on(message => {
        const p = message.params || {}
        if (p.threadId !== threadId) return
        if (message.method === 'turn/started') busy = true
        if (message.method === 'thread/status/changed') busy = p.status?.type === 'active'
        if (message.method === 'turn/completed') {
          busy = false; ended.add(p.turn?.id)
          const envelope = turnEnvelope.get(p.turn?.id)
          log(`turn ${envelope ? `for ${envelope.slice(0, 12)} ` : ''}ended: ${p.turn?.status || 'unknown'}`)
          // Codex writes a thread's rollout at its first turn; until then `codex resume` finds nothing (#218).
          if (!attachable) { attachable = true; log(`attach: ${attachCommand({ codexHome, socket, threadId })}`) }
        }
        if (!busy) wake()
      })
      log(`${config.id} session ready; admitted messages will be injected into the thread`)
      log(attachable ? `attach: ${attachCommand({ codexHome, socket, threadId })}` : 'attach: available after the thread\'s first turn, when Codex saves it; the command is printed then')
      // Held: arrivals not yet delivered while a turn runs, until the ceiling since the first of them.
      let heldSince = 0, heldNoted = 0
      const fresh = rows => rows.filter(row => !delivered.has(row.envelope))
      const holding = () => busy && fresh(pending).length > 0 && (heldSince ||= Date.now()) + HOLD_MAX_MS > Date.now()
      while (!stopping() && !server.closed) {
        if (down && !busy) { log(`restarting codex app-server to reconnect the channel (${down})`); break }
        const next = pending[0]
        if (down || (!next && !recheck)) { await Promise.race([new Promise(done => { wake = done }), server.exited]); continue }
        const reconnected = recheck
        if (!reconnected && holding()) {
          const held = fresh(pending).length
          if (held > heldNoted) { heldNoted = held; log(`holding ${held} until the running turn ends`) }
          await Promise.race([new Promise(done => { wake = done }), server.exited, sleep(heldSince + HOLD_MAX_MS - Date.now())])
          continue
        }
        recheck = false
        const batch = pending.slice(0, BATCH_MAX), rows = fresh(batch)
        const why = reconnected || rows.length ? await channelDown() : ''
        if (why || (why === null && reconnected)) {
          down = why || 'the wake feed reconnected'
          log(`the channel to the fleet is down (${down}); codex app-server restarts once no turn is running`)
          continue
        }
        if (!next || holding()) continue
        if (rows.length) {
          const input = [{ type: 'text', text: codexBatchText(rows) }], clientUserMessageId = `nvoy:${rows[0].envelope}`
          const what = `${rows[0].envelope.slice(0, 12)}${rows.length > 1 ? ` and ${rows.length - 1} more` : ''}`
          let turn = ''
          if (!busy) {
            try {
              turn = String((await server.request('turn/start', { threadId, input, clientUserMessageId }))?.turn?.id || '')
              if (!turn) throw new Error('Codex returned no turn id')
              busy = !ended.has(turn); turnEnvelope.set(turn, rows[0].envelope)
            } catch (error) { if (server.closed) throw error; log(`turn/start refused (${error.message}); holding ${what} until the running turn ends`); busy = true; continue }
          }
          if (turn) {
            for (const row of rows) markDelivered(row.envelope, { turn })
            log(`injected ${what} as a turn`)
          } else {
            const queued = String((await server.request('thread/queue/add', { threadId, input, clientUserMessageId }))?.queuedSubmission?.id || '')
            if (!queued) throw new Error('Codex returned no queued submission id')
            for (const row of rows) markDelivered(row.envelope, { queued })
            log(`queued ${what} behind a turn still running after ${Math.round(HOLD_MAX_MS / 1000)}s`)
          }
        }
        for (const row of batch) { pending.shift(); announced.delete(row.envelope) }
        saveCursor(batch.at(-1).envelope)
        // What a batch could not take keeps its first arrival's deadline, so it is not held twice.
        heldNoted = 0
        if (!fresh(pending).length) heldSince = 0
      }
    } catch (error) {
      log(`codex harness: ${error.message}`)
    } finally {
      server?.stop()
      if (child) { await stopPid(child.pid, () => child.exitCode !== null || child.signalCode !== null); children.delete(child) }
    }
    if (stopping()) break
    if (Date.now() - startedAt > RETRY_MAX_MS) delay = RETRY_MS
    log(`next start in ${Math.round(delay / 1000)}s`)
    await sleep(delay)
    delay = Math.min(delay * 2, RETRY_MAX_MS)
  }
}
