#!/usr/bin/env node
// Owner-facing preflight for one native Claude Code Channel identity. This command never reads
// or prints private-key contents. It validates either the local Claude/SSH client edge or the
// fixed broker-side manifest and renders the exact commands an owner must install deliberately.

import { createHash } from 'node:crypto'
import { lstatSync, readFileSync, realpathSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { dirname, isAbsolute, parse } from 'node:path'
import { readManifest, assertNoCollisions, instanceId } from './runtime_manifest.mjs'

const die = message => { console.error(`claude-channel-doctor: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const mode = flag('--mode')

function regular(path, label, max = 256 * 1024) {
  let st
  try { st = lstatSync(path) } catch { die(`${label} is missing`) }
  if (!st.isFile() || st.isSymbolicLink() || st.size > max) die(`${label} must be a bounded regular non-symlink file`)
  return st
}

function fixedPath(path, label, max = 256 * 1024) {
  if (!isAbsolute(path)) die(`${label} path must be absolute`)
  let supplied
  try { supplied = lstatSync(path) } catch { die(`${label} is missing`) }
  if (supplied.isSymbolicLink()) die(`${label} must be a bounded regular non-symlink file`)
  let canonical
  try { canonical = realpathSync(path) } catch { die(`${label} is missing`) }
  const st = regular(canonical, label, max)
  const allowedOwners = new Set([0, typeof process.getuid === 'function' ? process.getuid() : 0])
  if (!allowedOwners.has(st.uid)) die(`${label} must be owned by root or the current user`)

  let dir = dirname(canonical)
  const root = parse(dir).root
  for (;;) {
    const parent = lstatSync(dir)
    const stickyRootDirectory = parent.uid === 0 && (parent.mode & 0o1000) !== 0
    if (!parent.isDirectory() || parent.isSymbolicLink() || !allowedOwners.has(parent.uid) ||
        ((parent.mode & 0o022) !== 0 && !stickyRootDirectory)) {
      die(`${label} must be beneath a non-replaceable root/current-user-owned directory chain`)
    }
    if (dir === root) break
    dir = dirname(dir)
  }
  return { path: canonical, stat: st }
}

function privateFile(path, label) {
  const { path: canonical, stat: st } = fixedPath(path, label)
  if ((st.mode & 0o077) !== 0) die(`${label} must not be accessible by group or other (use mode 0600)`)
  return canonical
}

function safeName(value, label) {
  if (!/^[a-z0-9][a-z0-9._-]{1,63}$/i.test(value)) die(`${label} must be a short stable identifier`)
  return value
}

function client() {
  const claudeInput = flag('--claude') || '/usr/local/bin/claude'
  const identityInput = flag('--identity-file')
  const knownHostsInput = flag('--known-hosts-file')
  const target = flag('--ssh-target')
  const server = safeName(flag('--server'), 'server name')
  if (!identityInput || !knownHostsInput || !/^[a-z_][a-z0-9_-]{0,31}@[a-z0-9.-]+$/i.test(target)) {
    die('client usage: --mode client --server <name> --claude <path> --identity-file <path> --known-hosts-file <path> --ssh-target <user@host>')
  }
  const claudeChecked = fixedPath(claudeInput, 'Claude executable', 64 * 1024 * 1024)
  if ((claudeChecked.stat.mode & 0o022) !== 0 || (claudeChecked.stat.mode & 0o111) === 0) {
    die('Claude executable must be executable and not group/world writable')
  }
  const claude = claudeChecked.path
  const identity = privateFile(identityInput, 'SSH identity file')
  const { path: knownHosts, stat: knownStat } = fixedPath(knownHostsInput, 'known_hosts file')
  if ((knownStat.mode & 0o022) !== 0) die('known_hosts file must not be group/world writable')
  const versionRun = spawnSync(claude, ['--version'], { encoding: 'utf8', timeout: 10_000 })
  if (versionRun.status !== 0) die('Claude version check failed')
  const match = `${versionRun.stdout || ''} ${versionRun.stderr || ''}`.match(/(?:^|\s)(\d+)\.(\d+)\.(\d+)(?:\s|$)/)
  if (!match) die('Claude version output did not contain a semantic version')
  const version = match.slice(1).map(Number)
  if (version[0] < 2 || (version[0] === 2 && (version[1] < 1 || (version[1] === 1 && version[2] < 80)))) {
    die(`Claude Code ${version.join('.')} is too old; native Channels require 2.1.80 or newer`)
  }
  const args = ['-F', '/dev/null', '-T', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${knownHosts}`, '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ClearAllForwardings=yes', '-i', identity, target]
  const config = { mcpServers: { [server]: { command: '/usr/bin/ssh', args } } }
  console.log(JSON.stringify({
    ok: true,
    mode: 'client',
    claudeVersion: version.join('.'),
    knownHostsSha256: createHash('sha256').update(readFileSync(knownHosts)).digest('hex'),
    mcpConfig: config,
    launch: [claude, '--dangerously-load-development-channels', `server:${server}`],
    manualChecks: ['For Team or Enterprise, an administrator has enabled Claude Code Channels.', 'Keep the intended Claude Code session open while this channel is active.']
  }, null, 2))
}

function broker() {
  const id = flag('--instance'), publicKeyInput = flag('--public-key-file'), container = flag('--container')
  if (!id || !publicKeyInput || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(container)) {
    die('broker usage: --mode broker --instance <id> --public-key-file <key.pub> --container <fixed-adapter-container>')
  }
  const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
  let manifest
  try { manifest = readManifest(root, instanceId(id)); assertNoCollisions(root, manifest) } catch (error) { die(error.message) }
  if (manifest.brokerMode !== 'local' || manifest.deliveryMode !== 'notify_only' || manifest.workerEnabled) {
    die('Claude channel requires a local-broker, worker-disabled notify_only instance')
  }
  const { path: publicKey, stat: st } = fixedPath(publicKeyInput, 'public key file', 16 * 1024)
  if ((st.mode & 0o022) !== 0) die('public key file must not be group/world writable')
  const fields = readFileSync(publicKey, 'utf8').trim().split(/\s+/)
  if (!/^(ssh-ed25519|ecdsa-sha2-nistp256)$/.test(fields[0] || '') || !/^[A-Za-z0-9+/]+={0,2}$/.test(fields[1] || '')) die('unsupported or malformed OpenSSH public key')
  const tool = '/srv/nvoy/mcp/tools/claude-channel.mjs'
  console.log(JSON.stringify({
    ok: true,
    mode: 'broker',
    instance: manifest.id,
    recipient: manifest.pubkey,
    baseline: ['/usr/bin/docker', 'exec', '--user', `${manifest.workerUid}:${manifest.workerHandoffGid}`, container, '/usr/local/bin/node', tool, '--instance', manifest.id, '--baseline'],
    authorizedKeyRenderer: ['/usr/local/bin/node', '/srv/nvoy/mcp/tools/instance-claude-channel-authorized-key.mjs', '--instance', manifest.id, '--public-key-file', publicKey, '--container', container],
    invariants: ['Run baseline before installing or enabling the client key.', 'Install the renderer output unmodified for the dedicated SSH principal.', 'No shell, PTY, forwarding, signer, or model-worker credential is granted.']
  }, null, 2))
}

if (mode === 'client') client()
else if (mode === 'broker') broker()
else die('usage: --mode client|broker (run the selected mode for its required flags)')
