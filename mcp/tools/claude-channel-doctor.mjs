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

// `max = null` means the file is never READ by this tool, only stat-ed and exec'd, so there is
// nothing to bound. See the Claude executable in client() (#186).
//
// The three conditions are refused separately. Collapsed into one string they cost an operator an
// hour: the Claude binary is a regular non-symlink file that merely exceeded the cap, and the
// message said "must be a bounded regular non-symlink file" — with `claude` on PATH genuinely
// being an nvm symlink, so the most legible word in the refusal confirmed the wrong hypothesis.
// The size case prints both numbers, because "too big" without them sends you to the wrong file.
function regular(path, label, max = 256 * 1024) {
  let st
  try { st = lstatSync(path) } catch { die(`${label} is missing`) }
  if (st.isSymbolicLink()) die(`${label} must not be a symlink`)
  if (!st.isFile()) die(`${label} must be a regular file`)
  if (max !== null && st.size > max) die(`${label} is ${st.size} bytes, above the ${max}-byte limit for a file this tool reads`)
  return st
}

function fixedPath(path, label, max = 256 * 1024) {
  if (!isAbsolute(path)) die(`${label} path must be absolute`)
  let supplied
  try { supplied = lstatSync(path) } catch { die(`${label} is missing`) }
  if (supplied.isSymbolicLink()) die(`${label} must not be a symlink`)
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
  // Unbounded, deliberately (#186). Every other `max` here guards a readFileSync; this one guarded
  // nothing — the doctor stats this file, checks its mode bits, and spawns it with `--version`. It
  // never reads it. The 64 MB cap therefore bought no safety and refused every shipped Claude Code
  // binary: 2.1.229 is 281 MB, and the cap has been below the real size since well before the
  // 2.1.80 floor this tool enforces, so client mode could not succeed for anyone.
  const claudeChecked = fixedPath(claudeInput, 'Claude executable', null)
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
  // The container is the manifest's to declare, not the caller's to supply (#154). The doctor was
  // echoing `--container` straight into both emitted commands without checking it, and the renderer
  // asserts it against the manifest — so a caller who named anything other than the manifest's
  // adapter got a well-formed command that died on the step they were told to run unmodified, and
  // a `baseline` pointed at a container that may not be theirs. Refuse here, where the operator can
  // still fix it, rather than emitting a command that fails later.
  if (container !== manifest.adapterContainer) {
    die(`--container ${container} is not this instance's adapter: the manifest declares ${manifest.adapterContainer}`)
  }
  const { path: publicKey, stat: st } = fixedPath(publicKeyInput, 'public key file', 16 * 1024)
  if ((st.mode & 0o022) !== 0) die('public key file must not be group/world writable')
  const fields = readFileSync(publicKey, 'utf8').trim().split(/\s+/)
  if (!/^(ssh-ed25519|ecdsa-sha2-nistp256)$/.test(fields[0] || '') || !/^[A-Za-z0-9+/]+={0,2}$/.test(fields[1] || '')) die('unsupported or malformed OpenSSH public key')
  // Both paths are inside the adapter image, never on the host — see authorizedKeyRenderer below.
  const tool = '/srv/nvoy/mcp/tools/claude-channel.mjs'
  const renderer = '/srv/nvoy/mcp/tools/instance-claude-channel-authorized-key.mjs'
  console.log(JSON.stringify({
    ok: true,
    mode: 'broker',
    instance: manifest.id,
    recipient: manifest.pubkey,
    baseline: ['/usr/bin/docker', 'exec', '--user', `${manifest.workerUid}:${manifest.workerHandoffGid}`, container, '/usr/local/bin/node', tool, '--instance', manifest.id, '--baseline'],
    // Wrapped in `docker exec` for the same reason `baseline` is: `/usr/local/bin/node` and
    // `/srv/nvoy` exist inside the adapter image and NOT on the container host, so the unwrapped
    // form fails with `node: command not found` on the very host it names. Invariant 3 below asks
    // the owner to install this output UNMODIFIED — a command they must guess how to wrap is one
    // they will wrap differently each time, on the step where "unmodified" is the safety property.
    //
    // Same worker identity as `baseline`, for a weaker reason than baseline's. This tool only
    // reads the manifest and a public key and prints a line, so it does not NEED the worker's
    // privileges — it runs as the worker so that it cannot need more than baseline does, and the
    // container's default root would be more. Measured on the live adapter: 41024:42022 reads the
    // manifest (mode 0644) and executes node.
    //
    // The key goes BY VALUE, not as a path (#188). Everything after the container name runs inside
    // the image, and `publicKey` is a canonicalised HOST path the container cannot see: the two
    // share only /etc/nvoy/instances, the rootfs is read-only so `docker cp` is refused, and nobody
    // keeps a public key under the instance directory. Emitting the path produced a command that
    // died with "public key file is missing" on the live adapter — on the very step invariant 2
    // tells the owner to run unmodified. The fields are parsed and validated ten lines above, a
    // public key is not a secret, and by value no path crosses the boundary.
    authorizedKeyRenderer: ['/usr/bin/docker', 'exec', '--user', `${manifest.workerUid}:${manifest.workerHandoffGid}`, container, '/usr/local/bin/node', renderer, '--instance', manifest.id, '--public-key-type', fields[0], '--public-key-body', fields[1], '--container', container],
    invariants: ['Run baseline before installing or enabling the client key.', 'Install the renderer output unmodified for the dedicated SSH principal.', 'No shell, PTY, forwarding, signer, or model-worker credential is granted.']
  }, null, 2))
}

if (mode === 'client') client()
else if (mode === 'broker') broker()
else die('usage: --mode client|broker (run the selected mode for its required flags)')
