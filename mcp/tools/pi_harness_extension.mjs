// A pi extension that makes one long-lived pi session an Nvoy participant, the pi form of the
// portable Codex harness (codex_portable_harness.mjs). pi-harness.mjs starts pi with it and nothing
// else: `--no-extensions -e <this file>`, and the three channel tools as the only tools.
//
// - Wake source. The same fleet-side feed as Codex (codex-channel-feed.mjs) over the feed key,
//   followed from an envelope cursor in <state_dir>/nvoy, reconnecting with backoff when the fleet
//   recreates the adapter. The feed also holds the identity's one-consumer lock on the fleet.
// - Injection. Each admitted envelope becomes a user message in the session, with
//   `sendUserMessage(text, { deliverAs: 'followUp' })`: a turn at once when pi is idle, else queued
//   behind the running one, so a person typing into the session is never cut off. Each envelope is
//   recorded once in delivered.jsonl and never injected twice.
// - Channel. nvoy_channel_list / read / reply are proxies to the fleet's channel MCP
//   (codex-channel-mcp.mjs) over the channel key. One ssh child is kept and a closed one is replaced
//   at the next call; a feed reconnect means the adapter was recreated, so the child is dropped then.
//
// It never reads a message body or a reply: pi does, through the tools, and the broker rechecks the
// grant before it signs. Its log names envelope ids only. pi may load extensions without starting a
// session, so nothing starts before session_start.

import { appendFileSync, chmodSync, existsSync, lstatSync, mkdirSync, readFileSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { homedir } from 'node:os'
import { isAbsolute, resolve } from 'node:path'
import { fixedPath, knownHostsFile, privateFile, sshChannelEntry, SSH, SSH_TARGET } from './channel_client.mjs'
import { instanceId } from './runtime_manifest.mjs'
import { codexTurnText } from './harness_session.mjs'
import { feedCursor, followWakeFeed } from './wake_feed_client.mjs'

// Mirrors codex-channel-mcp.mjs's tools/list, which is what the fleet enforces. pi validates tool
// arguments against plain JSON Schema as well as TypeBox, so no TypeBox import is needed here.
export const PI_CHANNEL_TOOLS = [
  { name: 'nvoy_channel_list', label: 'Nvoy channel: list', description: 'List bounded metadata for this fixed participant queue; returns no message content.',
    parameters: { type: 'object', properties: {}, additionalProperties: false } },
  { name: 'nvoy_channel_read', label: 'Nvoy channel: read', description: 'Read one exact broker-admitted envelope and its broker-attested authority.',
    parameters: { type: 'object', properties: { envelope: { type: 'string', pattern: '^[0-9a-f]{64}$' } }, required: ['envelope'], additionalProperties: false } },
  { name: 'nvoy_channel_reply', label: 'Nvoy channel: reply', description: 'Request one receipt-bound reply to an instruction-authorized envelope. This process cannot sign or select a recipient.',
    parameters: { type: 'object', properties: { envelope: { type: 'string', pattern: '^[0-9a-f]{64}$' }, text: { type: 'string', minLength: 1, maxLength: 4000 } }, required: ['envelope', 'text'], additionalProperties: false } },
]

// The client config names paths, never values, and is refused on the portable Codex config's
// grounds: nothing here signs, and nothing may bill an API key instead of the owner's subscription.
const PI_FIELDS = new Set(['instance', 'ssh_target', 'identity_file', 'feed_identity_file', 'known_hosts_file', 'state_dir', 'pi_home', 'model', 'pubkey', 'channels'])
export function readPiClientConfig(path, id, own = homedir()) {
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
    throw new Error('client config must not name an API key: the portable Pi harness runs on the ChatGPT login only')
  }
  const unknown = Object.keys(raw).filter(key => !PI_FIELDS.has(key))
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
  const stateDir = String(raw.state_dir || '')
  if (!isAbsolute(stateDir)) throw new Error('client config state_dir path must be absolute')
  if (resolve(stateDir) === resolve(own)) throw new Error('state_dir must be the harness\'s own directory, never your home')
  const identity = privateFile(String(raw.identity_file || ''), 'SSH channel identity file')
  const feedIdentity = privateFile(String(raw.feed_identity_file || ''), 'SSH feed identity file')
  if (identity === feedIdentity) throw new Error('the channel and feed keys must be two keys: each forced command admits exactly one')
  const socket = resolve(stateDir, 'tmux.sock')
  if (Buffer.byteLength(socket) >= 104) throw new Error('state_dir is too deep for its tmux socket; choose a shorter path')
  return Object.freeze({ id: instanceId(id), target, model, pubkey, channels, stateDir: resolve(stateDir), socket, identity, feedIdentity,
    piHome: piHomeDir(String(raw.pi_home || ''), own), knownHosts: knownHostsFile(String(raw.known_hosts_file || '')) })
}

// The harness's own PI_CODING_AGENT_DIR, which its owner has logged in with `/login` (ChatGPT, the
// openai-codex provider). Never ~/.pi/agent: that one loads the owner's own extensions, and a
// shared auth.json would lose its refresh token to whichever copy refreshed last. Only each
// credential's `type` is read, and nothing from the file is ever printed.
function piHomeDir(path, own) {
  if (!isAbsolute(path)) throw new Error('client config pi_home path must be absolute')
  const home = resolve(path)
  if ([own, resolve(own, '.pi'), resolve(own, '.pi', 'agent')].some(dir => home === resolve(dir))) throw new Error('pi_home must be the harness\'s own directory, never your home or ~/.pi/agent')
  let st
  try { st = lstatSync(home) } catch { throw new Error('pi_home is missing: create it and log in there first') }
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error('pi_home must be a real directory')
  if (st.uid !== process.getuid?.()) throw new Error('pi_home must be owned by the current user')
  if ((st.mode & 0o077) !== 0) throw new Error('pi_home must not be accessible by group or other (use mode 0700)')
  const authFile = privateFile(resolve(home, 'auth.json'), 'pi login (pi_home/auth.json)')
  let auth
  try { auth = JSON.parse(readFileSync(authFile, 'utf8')) } catch { throw new Error('pi login (pi_home/auth.json) is not valid JSON') }
  if (!auth || typeof auth !== 'object' || Array.isArray(auth)) throw new Error('pi login (pi_home/auth.json) must be a JSON object')
  if (Object.values(auth).some(credential => credential?.type !== 'oauth')) throw new Error('pi login in pi_home holds an API key: log in with /login only')
  if (auth['openai-codex']?.type !== 'oauth') throw new Error('pi login in pi_home is not a ChatGPT login: run pi there and /login to ChatGPT')
  return home
}

// One ssh child speaking newline-delimited JSON-RPC to the fleet's channel MCP. A call that gets no
// answer within HARNESS_CHANNEL_CALL_MS ends the child, so a dead carrier cannot hang a turn.
export function channelProxy({ config, ssh = SSH, env, log = () => {} }) {
  const CALL_MS = Number(process.env.HARNESS_CHANNEL_CALL_MS || 30000)
  const entry = sshChannelEntry({ identity: config.identity, knownHosts: config.knownHosts, target: config.target })
  let current = null, spawned = 0

  function connect() {
    const child = spawn(ssh, entry.args, { stdio: ['pipe', 'pipe', 'pipe'], env })
    const pending = new Map()
    let out = '', stderr = '', nextId = 1, closed = false
    const conn = { child, closed: () => closed }
    spawned++
    // A child that closed, failed to start or went silent is never reused, even before it exits.
    const drop = () => { closed = true; if (current === conn) current = null }
    const fail = error => { for (const { reject, timer } of pending.values()) { clearTimeout(timer); reject(error) } pending.clear() }
    child.on('error', error => { drop(); fail(new Error(`the channel to the fleet did not start: ${error.code || error.message}`)) })
    child.on('close', code => {
      drop()
      fail(new Error(`the channel to the fleet closed (${code})${stderr.trim() ? `: ${stderr.trim().split('\n').at(-1).slice(0, 300)}` : ''}`))
    })
    child.stdin.on('error', () => {})
    child.stderr.on('data', data => { stderr = (stderr + String(data)).slice(-600) })
    child.stdout.on('data', data => {
      out += data
      let at
      while ((at = out.indexOf('\n')) >= 0) {
        const line = out.slice(0, at); out = out.slice(at + 1)
        let message
        try { message = JSON.parse(line) } catch { continue }
        const waiting = pending.get(message?.id)
        if (!waiting) continue
        pending.delete(message.id); clearTimeout(waiting.timer)
        if (message.error) waiting.reject(new Error(`the channel refused the call: ${String(message.error.message || message.error.code).slice(0, 300)}`))
        else waiting.resolve(message.result)
      }
    })
    conn.request = (method, params, signal) => new Promise((done, reject) => {
      if (closed) return reject(new Error('the channel to the fleet is closed'))
      const id = nextId++
      const timer = setTimeout(() => { pending.delete(id); drop(); reject(new Error(`the channel to the fleet did not answer within ${Math.round(CALL_MS / 1000)}s`)); child.kill('SIGTERM') }, CALL_MS)
      pending.set(id, { resolve: done, reject, timer })
      signal?.addEventListener?.('abort', () => { if (pending.delete(id)) { clearTimeout(timer); reject(new Error('the tool call was aborted')) } }, { once: true })
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n')
    })
    conn.ready = conn.request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'nvoy-pi-harness', version: '1' } })
      .then(() => child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n'))
    conn.ready.catch(() => {})
    return conn
  }

  return {
    spawned: () => spawned,
    async call(name, args, signal) {
      if (!current || current.closed()) current = connect()
      const conn = current
      await conn.ready
      const result = await conn.request('tools/call', { name, arguments: args || {} }, signal)
      const text = (result?.content || []).filter(part => part?.type === 'text').map(part => String(part.text)).join('\n')
      if (result?.isError) throw new Error(text || `${name} failed`)
      return { content: [{ type: 'text', text }], details: undefined }
    },
    // The adapter was recreated: the child's ssh is into a container that no longer exists.
    reset(why) { if (current) { log(`dropping the channel child (${why}); the next call starts a new one`); try { current.child.kill('SIGTERM') } catch {} current = null } },
    close() { if (current) try { current.child.kill('SIGTERM') } catch {} current = null },
  }
}

export function createPiHarness({ pi, config, ssh = SSH, log: logLine }) {
  const privateDir = resolve(config.stateDir, 'nvoy')
  mkdirSync(privateDir, { recursive: true, mode: 0o700 }); chmodSync(privateDir, 0o700)
  const deliveredPath = resolve(privateDir, 'delivered.jsonl'), logPath = resolve(privateDir, 'harness.log')
  const log = logLine || (message => { appendFileSync(logPath, `${new Date().toISOString()} ${message}\n`, { mode: 0o600 }); chmodSync(logPath, 0o600) })
  const env = { PATH: process.env.PATH || '/usr/bin:/bin', HOME: config.stateDir }
  const channel = channelProxy({ config, ssh, env, log })
  for (const tool of PI_CHANNEL_TOOLS) pi.registerTool({ ...tool, execute: (_id, params, signal) => channel.call(tool.name, params, signal) })

  let run = null
  const children = new Set()
  function inject(row, delivered, cursor) {
    if (!delivered.has(row.envelope)) {
      pi.sendUserMessage(codexTurnText(row), { deliverAs: 'followUp' })
      appendFileSync(deliveredPath, JSON.stringify({ envelope: row.envelope, type: row.type, at: Date.now() }) + '\n', { mode: 0o600 }); chmodSync(deliveredPath, 0o600)
      delivered.add(row.envelope)
      log(`injected ${row.envelope.slice(0, 12)}`)
    }
    cursor.save(row.envelope)
  }
  return {
    channel,
    // Idempotent: a reload or session switch shuts the old run down before the next one starts.
    start(ctx) {
      if (run) return
      const current = run = { stopping: false }
      const status = text => { if (ctx?.hasUI) ctx.ui.setStatus('nvoy', `nvoy ${config.id}: ${text}`) }
      const delivered = new Set(existsSync(deliveredPath)
        ? readFileSync(deliveredPath, 'utf8').split('\n').filter(Boolean).map(line => { try { return JSON.parse(line).envelope } catch { return '' } }) : [])
      const cursor = feedCursor(resolve(privateDir, 'feed-cursor.json'), config.id)
      status('connecting')
      followWakeFeed({ config, cursor, ssh, env, children, stopping: () => current.stopping,
        log: message => { log(message); if (message === 'wake feed connected') status('listening'); else if (/reconnecting/.test(message)) status('reconnecting') },
        onAdmitted: row => inject(row, delivered, cursor),
        onConnected: n => { if (n > 1) channel.reset('the wake feed reconnected') } })
      log(`${config.id} session ready; admitted messages will be injected into it`)
    },
    stop() {
      if (run) run.stopping = true
      run = null
      for (const child of children) try { child.kill('SIGTERM') } catch {}
      channel.close()
    },
  }
}

// pi's entry point. The launcher names the config and instance in pi's environment; a replacement
// ssh (a test's) must still be a fixed, owner-held file, as for the Codex harness.
export default function nvoyPiHarness(pi) {
  const configPath = process.env.NVOY_PI_HARNESS_CONFIG || '', id = process.env.NVOY_PI_HARNESS_INSTANCE || ''
  if (!configPath || !id) throw new Error('nvoy pi harness: NVOY_PI_HARNESS_CONFIG and NVOY_PI_HARNESS_INSTANCE must be set; start it with mcp/tools/pi-harness.mjs')
  const config = readPiClientConfig(configPath, id)
  const ssh = process.env.NVOY_HARNESS_SSH ? fixedPath(process.env.NVOY_HARNESS_SSH, 'ssh executable', null).path : SSH
  const harness = createPiHarness({ pi, config, ssh })
  pi.on('session_start', (_event, ctx) => harness.start(ctx))
  pi.on('session_shutdown', () => harness.stop())
  return harness
}
