#!/usr/bin/env node
// Keep one agent's own Claude Code session open, with the Nvoy channel loaded into it. A Codex
// harness is the same idea behind `codex app-server`; see codex_harness.mjs.
//
// The session runs in tmux so it has a terminal and nobody has to hold one. It is the SAME session
// across restarts: its home is a persistent volume, and it resumes with --continue. The supervisor
// answers only the fixed startup screens (the development-channel warning, and folder trust or
// theme if they appear), then leaves the session alone and restarts it if it exits. It never reads
// or logs the conversation, except the screen of a session that dies before it is ready.
//
// With --remote <client-config.json> the same supervisor runs on any box, a Mac included. The
// config stands in for the manifest; the channel, its lock and its queue stay on the fleet, reached
// through the identity's SSH forced-command key; and the session's home is the harness's own
// directory, never the owner's, so their own Claude Code login and settings are not touched.
//
// Where the owner runs herdr (HARNESS_TERMINAL=herdr, or auto when herdr answers), the session runs
// in a herdr pane instead of tmux: one workspace per identity, labelled with its name, where herdr
// shows the agent and its state like any other. See harness_herdr.mjs.

import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { readClientConfig } from './channel_client.mjs'
import { runCodexHarness } from './codex_harness.mjs'
import { herdrAgentName, herdrClient, herdrSession } from './harness_herdr.mjs'
import { channelState, classifyPane, claudeArgs, ensureInstructions, hasPriorSession, LOCAL_DREAM_VERIFY, mcpConfig, seedClaudeJson, seedSettings, serverName } from './harness_session.mjs'

const die = message => { console.error(`instance-harness: ${message}`); process.exit(1) }
const log = message => console.log(`instance-harness: ${message}`)
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
if (!id) die('usage: --instance <id> [--remote <client-config.json>]')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest, remote = null
if (process.argv.includes('--remote')) {
  try { remote = readClientConfig(flag('--remote'), id) } catch (error) { die(error.message) }
  manifest = { id: remote.id, pubkey: remote.pubkey, buzz: { channels: remote.channels }, harness: { runner: 'claude', model: remote.model },
    ...(remote.remember ? { mayRemember: { remote: true } } : {}), ...(remote.recall ? { recall: remote.recall } : {}) }
} else {
  try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (error) { die(error.message) }
  if (!manifest.harness) die('manifest has no harness block')
  if (process.getuid?.() !== manifest.workerUid) die('the harness must run as the manifest-bound worker user')
}

const home = remote ? remote.home : process.env.HOME || ''
if (!home.startsWith('/')) die('HOME must be the absolute, persistent harness home')
let token
const credentialName = manifest.harness.runner === 'codex' ? 'OpenAI API key' : 'Claude login credential'
const credentialFile = remote ? remote.credentialFile : process.env.NVOY_HARNESS_CREDENTIAL_FILE || '/run/nvoy-harness-credentials/credential'
try { token = readFileSync(credentialFile, 'utf8').trim() } catch (error) { die(`${credentialName} unreadable: ${error.code || error.message}`) }
if (!token || /\s/.test(token)) die(`${credentialName} is empty or malformed`)

// Codex has no terminal session to hold: `codex app-server` keeps the thread, and the supervisor
// injects each admitted envelope into it as a turn.
if (manifest.harness.runner === 'codex') {
  let stopping = false
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { stopping = true; process.exit(0) })
  await runCodexHarness({ manifest, root, home, credential: token, log, stopping: () => stopping })
  process.exit(0)
}

const server = serverName(manifest)
const workdir = resolve(home, 'workspace')
const privateDir = resolve(home, '.nvoy-harness')
const mcpConfigPath = resolve(privateDir, 'mcp.json')
const socket = process.env.HARNESS_TMUX_SOCKET || (remote ? resolve(privateDir, 'tmux.sock') : '/tmp/harness.sock')
const tmuxConf = `${socket}.conf`
const STARTUP_MS = Number(process.env.HARNESS_STARTUP_MS || 120000)
const POLL_MS = Number(process.env.HARNESS_POLL_MS || 1000)
const WATCH_MS = Number(process.env.HARNESS_WATCH_MS || 5000)
const RETRY_MS = Number(process.env.HARNESS_RETRY_MS || 5000)
const RETRY_MAX_MS = Number(process.env.HARNESS_RETRY_MAX_MS || 300000)
const SETTLE_MS = Number(process.env.HARNESS_CHANNEL_SETTLE_MS || 10000)
// A ready session whose proxy cannot hold a link for this long (a refused key, a lock the fleet still holds, an
// adapter that stays down) is restarted as before, so a dead channel never looks up. A release's drop is a few
// seconds and stays on the reconnect path.
const DOWN_MS = Number(process.env.HARNESS_CHANNEL_DOWN_MS || 600000)
const LAUNCH_MS = Number(process.env.HARNESS_LAUNCH_MS || 10000)

function readJson(path) { try { return JSON.parse(readFileSync(path, 'utf8')) } catch { return {} } }
function writePrivate(path, value) { writeFileSync(path, value, { mode: 0o600 }); chmodSync(path, 0o600) }

mkdirSync(workdir, { recursive: true, mode: 0o700 })
mkdirSync(privateDir, { recursive: true, mode: 0o700 })
mkdirSync(resolve(home, '.claude'), { recursive: true, mode: 0o700 })
writePrivate(resolve(home, '.claude.json'), JSON.stringify(seedClaudeJson(readJson(resolve(home, '.claude.json')), workdir), null, 2))
const settingsPath = resolve(home, '.claude', 'settings.json')
const dreamVerify = manifest.id === 'curator' && existsSync(LOCAL_DREAM_VERIFY)
const settings = seedSettings(readJson(settingsPath), server, { recall: Boolean(manifest.recall), dreamVerify })
writePrivate(settingsPath, JSON.stringify(settings, null, 2))
const sessionMcp = mcpConfig({ manifest, root, remote, dreamVerify })
writePrivate(mcpConfigPath, JSON.stringify(sessionMcp, null, 2))
ensureInstructions(resolve(workdir, 'CLAUDE.md'), manifest)
// The channel lock lives on the runtime volume, so it outlives the container whose channel wrote it.
// PIDs restart with the container, so its PID can name a live process here and the new channel
// refuses to start, leaving a "ready" session with no ears (MC Claude, 2026-09-25 01:44 UTC).
// Nothing can hold the lock before this harness starts its first session. Off the fleet the lock
// is the fleet's, behind the forced command, and there is none here to clear.
if (!remote) rmSync(resolve(manifest.runtimeDir, 'claude-channel-state', 'channel.lock'), { force: true })
// The login token travels only in the tmux server's environment, or in herdr from its file through
// the launcher, never in an argv. The environment is built, not inherited, so an owner's own
// CLAUDE_CONFIG_DIR cannot pull the session back home.
const sessionEnv = {
  PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin', HOME: home, TERM: 'xterm-256color', LANG: 'C.UTF-8',
  ...(remote ? {} : { NVOY_INSTANCE_ROOT: root }), CLAUDE_CODE_OAUTH_TOKEN: token, DISABLE_AUTOUPDATER: '1',
}
const sleep = ms => new Promise(done => setTimeout(done, ms))
const args = resume => ['claude', ...claudeArgs({ server, mcpConfigPath, resume, model: manifest.harness.model, permissionMode: settings.permissions.defaultMode })]

// The terminal the session runs in: start it, read its screen, send it keys, tell whether it has
// exited, name the process at its root, and stop it.
function tmuxTerminal() {
  const tmux = (a, env = process.env) => spawnSync('tmux', ['-S', socket, ...a], { encoding: 'utf8', env })
  // A dead pane stays readable, so a session that fails to start can say why.
  writeFileSync(tmuxConf, 'set -g remain-on-exit on\nset -g history-limit 5000\n')
  return {
    start(resume) {
      tmux(['kill-server'])
      const r = tmux(['-f', tmuxConf, 'new-session', '-d', '-s', 'harness', '-x', '200', '-y', '50', '-c', workdir, ...args(resume)], sessionEnv)
      if (r.status !== 0) throw new Error(`tmux would not start: ${(r.stderr || '').trim().slice(0, 200)}`)
    },
    screen: () => tmux(['capture-pane', '-p', '-t', 'harness']).stdout || '',
    keys: key => tmux(['send-keys', '-t', 'harness', key]),
    dead() {
      const r = tmux(['display-message', '-p', '-t', 'harness', '#{pane_dead} #{pane_dead_status}'])
      if (r.status !== 0) return { dead: true, status: 'gone' }
      const [dead, status] = r.stdout.trim().split(' ')
      return { dead: dead === '1', status: status || '' }
    },
    pid: () => tmux(['display-message', '-p', '-t', 'harness', '#{pane_pid}']).stdout?.trim(),
    named() {},
    stop: () => tmux(['kill-server']),
  }
}

function herdrTerminal(herdr) {
  const session = herdrSession({ herdr, name: herdrAgentName(manifest.id), dir: privateDir, cwd: workdir, launchMs: LAUNCH_MS, log })
  const { CLAUDE_CODE_OAUTH_TOKEN, ...env } = sessionEnv
  return { ...session, start: resume => session.start({ command: args(resume), env, credential: { env: 'CLAUDE_CODE_OAUTH_TOKEN', file: credentialFile } }) }
}

const mode = process.env.HARNESS_TERMINAL || 'auto'
if (!['auto', 'herdr', 'tmux'].includes(mode)) die('HARNESS_TERMINAL must be auto, herdr or tmux')
const herdr = herdrClient()
const useHerdr = !!remote && (mode === 'herdr' || (mode === 'auto' && herdr.available()))
if (mode === 'herdr' && !remote) die('a herdr terminal is for the portable harness (--remote)')
const term = useHerdr ? herdrTerminal(herdr) : tmuxTerminal()
log(`the session runs in ${useHerdr ? 'herdr' : 'tmux'}`)

// Off the fleet the channel is the reconnecting proxy (harness_session.mjs reconnectingEntry) with ssh under
// it. A release or manifest change recreates the adapter and ends the ssh; the proxy dials again and the
// session carries on. At startup the supervisor waits for the proxy's live link (so a refused key never looks
// ready); after that it restarts the session if the proxy itself is gone, or if no link has held for DOWN_MS.
// The proxy swallows the replayed initialize response, so the session keeps the tool list it started with:
// a release that adds or removes adapter tools needs a session restart to show them. The fleet form is left as it was.
let watchChannel = !!remote
function channelNow() {
  const pid = term.pid()
  if (!/^\d+$/.test(pid || '')) return { proxy: false, link: '' }
  const ps = spawnSync('ps', ['-A', '-ww', '-o', 'pid=,ppid=,command='], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  if (ps.status !== 0) { watchChannel = false; log('cannot list processes; the channel is not watched'); return null }
  return channelState(ps.stdout, pid)
}
// Startup: the channel is up once the proxy holds a live link to the fleet; it returns that link's pid, so a
// redial (a new pid) during startup counts as the channel closing, however briefly it was down.
function channelUp() { const now = channelNow(); return now === null ? null : now.proxy && now.link ? now.link : false }

let stopping = false
for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.on(signal, async () => { stopping = true; await term.stop(); process.exit(0) })

async function start() {
  const resume = hasPriorSession(home, workdir)
  if (useHerdr && !herdr.available()) throw new Error('herdr is not answering; the session starts once it is')
  await term.start(resume)
  log(`${resume ? 'resuming' : 'starting'} the ${manifest.id} session with channel ${server}`)
  const answered = new Map()
  const deadline = Date.now() + STARTUP_MS
  let readyAt = 0, channelSince = 0, channelLink = ''
  while (!stopping && Date.now() < deadline) {
    await sleep(POLL_MS)
    const { dead, status } = term.dead()
    if (dead) {
      const tail = term.screen().split('\n').filter(line => line.trim()).slice(-12).join('\n')
      throw new Error(`session exited during startup (status ${status})${tail ? `:\n${tail}` : ''}`)
    }
    // Ready means the channel is up too: a fleet that still holds the channel lock, or refuses the
    // key, ends the ssh within a second while the prompt looks ready (mc-claude, 2026-09-25).
    if (watchChannel) {
      const up = channelUp()
      if (up && channelSince && up !== channelLink) throw new Error('the channel to the fleet closed during startup and was redialled; the fleet may still hold the channel lock from an earlier session')
      if (up) { channelSince ||= Date.now(); channelLink = up }
      else if (up === false && channelSince) throw new Error('the channel to the fleet closed during startup; the fleet may still hold the channel lock from an earlier session')
    }
    if (readyAt) {
      if (!watchChannel) { log(`${manifest.id} session ready`); return }
      if (channelSince && Date.now() - channelSince >= SETTLE_MS) { log(`${manifest.id} session ready; its channel to the fleet is up`); return }
      if (!channelSince && Date.now() - readyAt >= SETTLE_MS) throw new Error('the session is ready but its channel to the fleet never started')
      continue
    }
    term.named()
    const screen = classifyPane(term.screen())
    if (screen.state === 'login') throw new Error('Claude Code is not logged in: the harness credential was refused or has expired')
    if (screen.state === 'ready') { if (!watchChannel) { log(`${manifest.id} session ready; the channel will inject admitted messages`); return } readyAt = Date.now(); continue }
    if (screen.key) {
      const count = answered.get(screen.state) || 0
      if (count >= 3) throw new Error(`startup screen "${screen.state}" would not accept its answer`)
      answered.set(screen.state, count + 1)
      term.keys(screen.key)
      if (screen.key !== 'Enter') { await sleep(300); if (classifyPane(term.screen()).state === screen.state) term.keys('Enter') }
      log(`answered the ${screen.state} screen`)
    }
  }
  if (!stopping) log(`session not confirmed ready after ${Math.round(STARTUP_MS / 1000)}s; leaving it running — attach to inspect`)
}

let delay = RETRY_MS
while (!stopping) {
  const startedAt = Date.now()
  try {
    await start()
    let link = channelNow()?.link || '', linkSince = Date.now(), heldAt = Date.now()
    while (!stopping) {
      await sleep(WATCH_MS)
      term.named()
      const { dead, status } = term.dead()
      if (dead) { log(`session exited (status ${status}); restarting`); break }
      if (watchChannel) {
        const now = channelNow()
        if (now && !now.proxy) { log('the channel proxy exited; restarting the session'); break }
        if (now && now.link !== link) {
          log(!now.link ? 'the channel to the fleet dropped; the proxy is reconnecting it' : link ? 'the channel to the fleet was redialled' : 'the channel to the fleet is back')
          link = now.link; linkSince = Date.now()
        }
        // Held: the same link has stayed up for the settle time, as startup requires.
        if (now && now.link && Date.now() - linkSince >= SETTLE_MS) heldAt = Date.now()
        if (Date.now() - heldAt > DOWN_MS) { log(`the channel to the fleet has not held a link for ${Math.round(DOWN_MS / 1000)}s; restarting the session`); break }
      }
    }
    if (Date.now() - startedAt > RETRY_MAX_MS) delay = RETRY_MS
  } catch (error) {
    console.error(`instance-harness: ${error.message}`)
  }
  if (stopping) break
  log(`next start in ${Math.round(delay / 1000)}s`)
  await sleep(delay)
  delay = Math.min(delay * 2, RETRY_MAX_MS)
}
