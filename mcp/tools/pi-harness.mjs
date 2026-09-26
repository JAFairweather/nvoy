#!/usr/bin/env node
// Run one identity's pi session on this box, on its owner's ChatGPT login, as an Nvoy participant.
// The session is interactive pi in tmux, so a person can attach, watch and type into it; the
// extension (pi_harness_extension.mjs) injects each admitted envelope into it and gives it the
// channel tools. This supervisor only validates, starts pi, and restarts it when it exits.
//
//   node mcp/tools/pi-harness.mjs --instance <id> --config <client-config.json>
//
// pi runs with its own PI_CODING_AGENT_DIR (pi_home), never ~/.pi/agent, with discovered
// extensions off and the three channel tools as its only tools. Its environment is built, not
// inherited, so no API key or owner setting reaches it.

import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defaultInstructions } from './harness_session.mjs'
import { claimPidLock } from './pid_lock.mjs'
import { PI_CHANNEL_TOOLS, readPiClientConfig } from './pi_harness_extension.mjs'

const die = message => { console.error(`pi-harness: ${message}`); process.exit(1) }
const log = message => console.log(`pi-harness: ${message}`)
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), configPath = flag('--config')
if (!id || !configPath) die('usage: --instance <id> --config <client-config.json>')
let config
try { config = readPiClientConfig(configPath, id) } catch (error) { die(error.message) }

const extension = resolve(dirname(fileURLToPath(import.meta.url)), 'pi_harness_extension.mjs')
const piArgs = ({ model, stateDir }) => ['--provider', 'openai-codex', '--model', model || 'gpt-5.5',
  '--no-extensions', '-e', extension, '--tools', PI_CHANNEL_TOOLS.map(tool => tool.name).join(','),
  '--no-approve', '--session-dir', resolve(stateDir, 'sessions'), '--continue']

const { stateDir, socket } = config
const workdir = resolve(stateDir, 'workspace'), privateDir = resolve(stateDir, 'nvoy'), home = resolve(stateDir, 'home')
const tmuxConf = `${socket}.conf`
const STARTUP_MS = Number(process.env.HARNESS_STARTUP_MS || 30000)
const WATCH_MS = Number(process.env.HARNESS_WATCH_MS || 5000)
const RETRY_MS = Number(process.env.HARNESS_RETRY_MS || 5000)
const RETRY_MAX_MS = Number(process.env.HARNESS_RETRY_MAX_MS || 300000)
const writePrivate = (path, value) => { writeFileSync(path, value, { mode: 0o600 }); chmodSync(path, 0o600) }

for (const dir of [stateDir, workdir, privateDir, home, resolve(stateDir, 'sessions')]) { mkdirSync(dir, { recursive: true, mode: 0o700 }); chmodSync(dir, 0o700) }
let release
try { release = claimPidLock(resolve(privateDir, 'supervisor.lock'), config.id, 'portable Pi harness') } catch (error) { die(error.message) }
const manifest = { id: config.id, pubkey: config.pubkey, buzz: { channels: config.channels } }
if (!existsSync(resolve(workdir, 'AGENTS.md'))) writePrivate(resolve(workdir, 'AGENTS.md'), defaultInstructions(manifest))
// A dead pane stays readable, so a session that fails to start can say why.
writePrivate(tmuxConf, 'set -g remain-on-exit on\nset -g history-limit 5000\n')

// HOME is the harness's own, so pi never reads the owner's dotfiles; the login is in pi_home.
const sessionEnv = {
  PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin', HOME: home, TERM: 'xterm-256color', LANG: 'C.UTF-8',
  PI_CODING_AGENT_DIR: config.piHome, PI_SKIP_VERSION_CHECK: '1', NVOY_PI_HARNESS_CONFIG: resolve(configPath), NVOY_PI_HARNESS_INSTANCE: config.id,
}
const tmux = (args, env = process.env) => spawnSync('tmux', ['-S', socket, ...args], { encoding: 'utf8', env })
const sleep = ms => new Promise(done => setTimeout(done, ms))
const paneDead = () => {
  const r = tmux(['display-message', '-p', '-t', 'harness', '#{pane_dead} #{pane_dead_status}'])
  if (r.status !== 0) return { dead: true, status: 'gone' }
  const [dead, status] = r.stdout.trim().split(' ')
  return { dead: dead === '1', status: status || '' }
}

let stopping = false
process.on('exit', () => release())
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { stopping = true; tmux(['kill-server']); process.exit(0) })

let delay = RETRY_MS
while (!stopping) {
  const startedAt = Date.now()
  tmux(['kill-server'])
  const r = tmux(['-f', tmuxConf, 'new-session', '-d', '-s', 'harness', '-x', '200', '-y', '50', '-c', workdir, 'pi', ...piArgs(config)], sessionEnv)
  if (r.status !== 0) log(`tmux would not start: ${(r.stderr || '').trim().slice(0, 200)}`)
  else {
    log(`started the ${config.id} pi session; the extension injects admitted messages into it`)
    log(`attach: tmux -S ${socket} attach -t harness`)
    for (;;) {
      await sleep(WATCH_MS)
      if (stopping) break
      const { dead, status } = paneDead()
      if (!dead) continue
      // Only a session that dies while starting shows its screen: usually a missing or expired login.
      const early = Date.now() - startedAt < STARTUP_MS
      const tail = early ? (tmux(['capture-pane', '-p', '-t', 'harness']).stdout || '').split('\n').filter(line => line.trim()).slice(-12).join('\n') : ''
      log(`pi exited (status ${status})${early ? ' during startup' : ''}; restarting${tail ? `:\n${tail}` : ''}`)
      break
    }
  }
  if (stopping) break
  if (Date.now() - startedAt > RETRY_MAX_MS) delay = RETRY_MS
  log(`next start in ${Math.round(delay / 1000)}s`)
  await sleep(delay)
  delay = Math.min(delay * 2, RETRY_MAX_MS)
}
