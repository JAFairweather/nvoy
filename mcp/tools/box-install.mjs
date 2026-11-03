#!/usr/bin/env node
// box-install.mjs — the install line of waggle's Add an agent, step 4 (DESIGN_ADD_AN_AGENT.md,
// "The install line"). It runs on the agent's own box, never on the fleet, and sets up the portable
// Claude harness (instance-harness.mjs --remote) for one identity:
//
//   1. makes the channel key here (ed25519, 0600), or keeps the one an earlier run made;
//   2. pins the fleet's host key from the line itself, never from a first connection;
//   3. writes the client config that channel_client.mjs reads;
//   4. with --start, starts the harness, which retries until the fleet accepts the key.
//
// Stdout is one line: the public half of the channel key, which the owner pastes into the page for
// the signed bind_runtime. Everything else goes to stderr. The private key is never read here, and
// nothing on this box signs: the Claude login is the owner's own, saved by them to a 0600 file.
//
//   box-install.mjs --instance <id> --ssh-target <user@host> --host-key '<type> <base64>'
//                   [--dir <absolute path>] [--claude <path>] [--start]
//
// Exit 0: set up. 3: set up, but the Claude login file is not there yet. 2: a tool is missing, and
// nothing was written. 1: the line itself is wrong.

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { SSH, SSH_TARGET, readClientConfig } from './channel_client.mjs'

const ID = /^[a-z0-9][a-z0-9._-]{1,63}$/i
const HOST_KEY_TYPES = new Set(['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'])
export const LOGIN_FILE = 'claude-oauth-token'

// A host key is accepted only when its base64 body names the same key type as its label, so a
// pasted fragment, a comment or a second key cannot slip into known_hosts.
export function parseHostKey(value) {
  const parts = String(value || '').trim().split(' ')
  if (parts.length !== 2 || !HOST_KEY_TYPES.has(parts[0]) || !/^[A-Za-z0-9+/]+={0,2}$/.test(parts[1])) {
    throw new Error('--host-key must be one key: its type (ssh-ed25519 or ecdsa-sha2-*) and its base64 body')
  }
  const body = Buffer.from(parts[1], 'base64')
  const length = body.length >= 4 ? body.readUInt32BE(0) : 0
  if (length !== parts[0].length || body.subarray(4, 4 + length).toString('latin1') !== parts[0]) {
    throw new Error(`--host-key body is not a ${parts[0]} key`)
  }
  return `${parts[0]} ${parts[1]}`
}

export function knownHostsLine(target, hostKey) { return `${target.split('@')[1]} ${hostKey}\n` }

// Only the key type and body, so the page's shape check sees exactly one key and no comment.
export function publicHalf(text) {
  const [type, body] = String(text || '').trim().split(/\s+/)
  if (type !== 'ssh-ed25519' || !/^AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$/.test(body || '')) throw new Error('the channel public key is not one ed25519 key')
  return `${type} ${body}`
}

export function clientConfig({ id, target, dir }) {
  return { instance: id, ssh_target: target, identity_file: join(dir, 'channel'), known_hosts_file: join(dir, 'known_hosts'),
    credential_file: join(dir, LOGIN_FILE), home: join(dir, 'home') }
}

const which = name => {
  const run = spawnSync('sh', ['-c', `command -v ${name}`], { encoding: 'utf8' })
  return run.status === 0 ? run.stdout.trim() : ''
}

// Every missing tool is named at once, before anything is written.
export function missingTools({ claude, ssh = SSH, nodeVersion = process.versions.node } = {}) {
  const missing = []
  if (Number(nodeVersion.split('.')[0]) < 20) missing.push(`node 20 or later (this is ${nodeVersion})`)
  if (!existsSync(ssh)) missing.push(`ssh at ${ssh}`)
  if (!which('ssh-keygen')) missing.push('ssh-keygen')
  if (!which('tmux')) missing.push('tmux')
  const bin = claude || which('claude')
  if (!bin) missing.push('Claude Code (claude)')
  else {
    const run = spawnSync(bin, ['--version'], { encoding: 'utf8', timeout: 10_000 })
    const v = `${run.stdout || ''} ${run.stderr || ''}`.match(/(?:^|\s)(\d+)\.(\d+)\.(\d+)(?:\s|$)/)
    const at = v ? v.slice(1).map(Number) : null
    if (!at || at[0] < 2 || (at[0] === 2 && (at[1] < 1 || (at[1] === 1 && at[2] < 80)))) missing.push(`Claude Code 2.1.80 or later (found ${at ? at.join('.') : 'no version'})`)
  }
  return missing
}

function writeAtomic(path, text, mode) {
  const tmp = `${path}.${process.pid}.tmp`
  writeFileSync(tmp, text, { mode })
  chmodSync(tmp, mode)
  renameSync(tmp, path)
}

export function install({ id, target, hostKey, dir }) {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)
  const key = join(dir, 'channel')
  let kept = existsSync(key)
  if (!kept) {
    const made = spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', `nvoy-channel-${id}`, '-f', key], { encoding: 'utf8' })
    if (made.status !== 0) throw new Error(`ssh-keygen failed: ${(made.stderr || '').trim().slice(0, 200)}`)
  } else {
    // The printed half always comes from the kept private key, so a stale or swapped .pub is rewritten.
    const derived = spawnSync('ssh-keygen', ['-y', '-f', key], { encoding: 'utf8' })
    if (derived.status !== 0) throw new Error('the existing channel key could not be read by ssh-keygen; move it aside to make a new one')
    const half = publicHalf(derived.stdout)
    let onDisk = ''
    try { onDisk = publicHalf(readFileSync(`${key}.pub`, 'utf8')) } catch { onDisk = '' }
    if (onDisk !== half) writeAtomic(`${key}.pub`, `${half} nvoy-channel-${id}\n`, 0o644)
  }
  chmodSync(key, 0o600)
  writeAtomic(join(dir, 'known_hosts'), knownHostsLine(target, hostKey), 0o644)
  const config = join(dir, 'client.json')
  writeAtomic(config, `${JSON.stringify(clientConfig({ id, target, dir }), null, 2)}\n`, 0o600)
  mkdirSync(join(dir, 'home'), { recursive: true, mode: 0o700 })
  return { kept, config, pub: publicHalf(readFileSync(`${key}.pub`, 'utf8')), login: join(dir, LOGIN_FILE) }
}

function main(argv) {
  const flag = name => { const i = argv.indexOf(name); return i < 0 ? '' : argv[i + 1] || '' }
  const say = message => console.error(`box-install: ${message}`)
  const id = flag('--instance'), target = flag('--ssh-target')
  let hostKey
  try {
    if (!ID.test(id)) throw new Error('--instance must be the agent\'s instance id')
    if (!SSH_TARGET.test(target)) throw new Error('--ssh-target must be user@host')
    hostKey = parseHostKey(flag('--host-key'))
  } catch (error) { say(error.message); return 1 }
  const dir = resolve(flag('--dir') || join(homedir(), '.nvoy-box', id))
  if (flag('--dir') && !isAbsolute(flag('--dir'))) { say('--dir must be absolute'); return 1 }

  const missing = missingTools({ claude: flag('--claude') })
  if (missing.length) { say(`missing, so nothing was changed: ${missing.join('; ')}`); return 2 }

  let done
  try { done = install({ id, target, hostKey, dir }) } catch (error) { say(error.message); return 1 }
  console.log(done.pub)
  say(`${done.kept ? 'kept the channel key from an earlier run' : 'made a new channel key'}; paste the line above into step 4 on the page`)
  if (!existsSync(done.login)) {
    say(`next, save this box's Claude login: run \`claude setup-token\`, then \`(umask 077; cat > ${done.login})\`, paste the token, and press Ctrl-D`)
    say('then run this line again with --start')
    return 3
  }
  try { readClientConfig(done.config, id) } catch (error) { say(error.message); return 1 }
  const start = [process.execPath, fileURLToPath(new URL('./instance-harness.mjs', import.meta.url)), '--instance', id, '--remote', done.config]
  if (!argv.includes('--start')) { say(`to start the agent: ${start.join(' ')}`); return 0 }
  say('starting the agent; it retries until the fleet accepts the key (after the page\'s bind_runtime)')
  return spawnSync(start[0], start.slice(1), { stdio: 'inherit' }).status ?? 1
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) process.exit(main(process.argv.slice(2)))
