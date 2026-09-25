#!/usr/bin/env node
// Keep one agent's own Claude Code session open, with the Nvoy channel loaded into it.
//
// The session runs in tmux so it has a terminal and nobody has to hold one. It is the SAME session
// across restarts: its home is a persistent volume, and it resumes with --continue. The supervisor
// answers only the fixed startup screens (the development-channel warning, and folder trust or
// theme if they appear), then leaves the session alone and restarts it if it exits. It never reads
// or logs the conversation, except the screen of a session that dies before it is ready.

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'
import { classifyPane, claudeArgs, defaultInstructions, hasPriorSession, mcpConfig, seedClaudeJson, seedSettings, serverName } from './harness_session.mjs'

const die = message => { console.error(`instance-harness: ${message}`); process.exit(1) }
const log = message => console.log(`instance-harness: ${message}`)
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
if (!id) die('usage: --instance <id>')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (error) { die(error.message) }
if (!manifest.harness) die('manifest has no harness block')
if (process.getuid?.() !== manifest.workerUid) die('the harness must run as the manifest-bound worker user')

const home = process.env.HOME || ''
if (!home.startsWith('/')) die('HOME must be the absolute, persistent harness home')
let token
try { token = readFileSync(process.env.NVOY_HARNESS_CREDENTIAL_FILE || '/run/nvoy-harness-credentials/claude-oauth-token', 'utf8').trim() } catch (error) { die(`Claude login credential unreadable: ${error.code || error.message}`) }
if (!token || /\s/.test(token)) die('Claude login credential is empty or malformed')

const server = serverName(manifest)
const workdir = resolve(home, 'workspace')
const privateDir = resolve(home, '.nvoy-harness')
const mcpConfigPath = resolve(privateDir, 'mcp.json')
const socket = process.env.HARNESS_TMUX_SOCKET || '/tmp/harness.sock'
const tmuxConf = `${socket}.conf`
const STARTUP_MS = Number(process.env.HARNESS_STARTUP_MS || 120000)
const POLL_MS = Number(process.env.HARNESS_POLL_MS || 1000)
const WATCH_MS = Number(process.env.HARNESS_WATCH_MS || 5000)
const RETRY_MAX_MS = Number(process.env.HARNESS_RETRY_MAX_MS || 300000)

function readJson(path) { try { return JSON.parse(readFileSync(path, 'utf8')) } catch { return {} } }
function writePrivate(path, value) { writeFileSync(path, value, { mode: 0o600 }); chmodSync(path, 0o600) }

mkdirSync(workdir, { recursive: true, mode: 0o700 })
mkdirSync(privateDir, { recursive: true, mode: 0o700 })
mkdirSync(resolve(home, '.claude'), { recursive: true, mode: 0o700 })
writePrivate(resolve(home, '.claude.json'), JSON.stringify(seedClaudeJson(readJson(resolve(home, '.claude.json')), workdir), null, 2))
const settingsPath = resolve(home, '.claude', 'settings.json')
writePrivate(settingsPath, JSON.stringify(seedSettings(readJson(settingsPath), server), null, 2))
writePrivate(mcpConfigPath, JSON.stringify(mcpConfig({ manifest, root }), null, 2))
if (!existsSync(resolve(workdir, 'CLAUDE.md'))) writePrivate(resolve(workdir, 'CLAUDE.md'), defaultInstructions(manifest))
// A dead pane stays readable, so a session that fails to start can say why.
writeFileSync(tmuxConf, 'set -g remain-on-exit on\nset -g history-limit 5000\n')

// The login token travels only in the tmux server's environment, never in an argv.
const sessionEnv = {
  PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin', HOME: home, TERM: 'xterm-256color', LANG: 'C.UTF-8',
  NVOY_INSTANCE_ROOT: root, CLAUDE_CODE_OAUTH_TOKEN: token, DISABLE_AUTOUPDATER: '1',
}
const tmux = (args, env = process.env) => spawnSync('tmux', ['-S', socket, ...args], { encoding: 'utf8', env })
const sleep = ms => new Promise(done => setTimeout(done, ms))
const pane = () => tmux(['capture-pane', '-p', '-t', 'harness']).stdout || ''
const paneDead = () => {
  const r = tmux(['display-message', '-p', '-t', 'harness', '#{pane_dead} #{pane_dead_status}'])
  if (r.status !== 0) return { dead: true, status: 'gone' }
  const [dead, status] = r.stdout.trim().split(' ')
  return { dead: dead === '1', status: status || '' }
}

let stopping = false
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { stopping = true; tmux(['kill-server']); process.exit(0) })

async function start() {
  const resume = hasPriorSession(home, workdir)
  tmux(['kill-server'])
  const r = tmux(['-f', tmuxConf, 'new-session', '-d', '-s', 'harness', '-x', '200', '-y', '50', '-c', workdir,
    'claude', ...claudeArgs({ server, mcpConfigPath, resume, model: manifest.harness.model })], sessionEnv)
  if (r.status !== 0) throw new Error(`tmux would not start: ${(r.stderr || '').trim().slice(0, 200)}`)
  log(`${resume ? 'resuming' : 'starting'} the ${manifest.id} session with channel ${server}`)
  const answered = new Map()
  const deadline = Date.now() + STARTUP_MS
  while (!stopping && Date.now() < deadline) {
    await sleep(POLL_MS)
    const { dead, status } = paneDead()
    if (dead) {
      const tail = pane().split('\n').filter(line => line.trim()).slice(-12).join('\n')
      throw new Error(`session exited during startup (status ${status})${tail ? `:\n${tail}` : ''}`)
    }
    const screen = classifyPane(pane())
    if (screen.state === 'login') throw new Error('Claude Code is not logged in: the harness credential was refused or has expired')
    if (screen.state === 'ready') { log(`${manifest.id} session ready; the channel will inject admitted messages`); return }
    if (screen.key) {
      const count = answered.get(screen.state) || 0
      if (count >= 3) throw new Error(`startup screen "${screen.state}" would not accept its answer`)
      answered.set(screen.state, count + 1)
      tmux(['send-keys', '-t', 'harness', screen.key])
      if (screen.key !== 'Enter') { await sleep(300); if (classifyPane(pane()).state === screen.state) tmux(['send-keys', '-t', 'harness', 'Enter']) }
      log(`answered the ${screen.state} screen`)
    }
  }
  if (!stopping) log(`session not confirmed ready after ${Math.round(STARTUP_MS / 1000)}s; leaving it running — attach to inspect`)
}

let delay = 5000
while (!stopping) {
  const startedAt = Date.now()
  try {
    await start()
    while (!stopping) {
      await sleep(WATCH_MS)
      const { dead, status } = paneDead()
      if (dead) { log(`session exited (status ${status}); restarting`); break }
    }
    if (Date.now() - startedAt > RETRY_MAX_MS) delay = 5000
  } catch (error) {
    console.error(`instance-harness: ${error.message}`)
  }
  if (stopping) break
  log(`next start in ${Math.round(delay / 1000)}s`)
  await sleep(delay)
  delay = Math.min(delay * 2, RETRY_MAX_MS)
}
