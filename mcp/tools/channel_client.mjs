// The client edge of one Claude Code Channel identity, off the fleet: the file checks an owner's
// SSH identity and pinned known_hosts must pass, and the one hardened ssh command that reaches the
// fleet-side channel through its forced-command key. claude-channel-doctor.mjs --mode client and
// the portable harness (instance-harness.mjs --remote) share both, so they cannot drift apart.
// Every check throws; the caller owns how it dies. No function here reads a private key.

import { lstatSync, readFileSync, realpathSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, parse, resolve } from 'node:path'
import { instanceId } from './runtime_manifest.mjs'

export const SSH = '/usr/bin/ssh'
export const SSH_TARGET = /^[a-z_][a-z0-9_-]{0,31}@[a-z0-9.-]+$/i

// `max = null` means the file is never READ by the caller, only stat-ed and exec'd, so there is
// nothing to bound. See the Claude executable in the doctor's client() (#186).
//
// The three conditions are refused separately. Collapsed into one string they cost an operator an
// hour: the Claude binary is a regular non-symlink file that merely exceeded the cap, and the
// message said "must be a bounded regular non-symlink file" — with `claude` on PATH genuinely
// being an nvm symlink, so the most legible word in the refusal confirmed the wrong hypothesis.
// The size case prints both numbers, because "too big" without them sends you to the wrong file.
export function regular(path, label, max = 256 * 1024) {
  let st
  try { st = lstatSync(path) } catch { throw new Error(`${label} is missing`) }
  if (st.isSymbolicLink()) throw new Error(`${label} must not be a symlink`)
  if (!st.isFile()) throw new Error(`${label} must be a regular file`)
  if (max !== null && st.size > max) throw new Error(`${label} is ${st.size} bytes, above the ${max}-byte limit for a file this tool reads`)
  return st
}

export function fixedPath(path, label, max = 256 * 1024) {
  if (!isAbsolute(path)) throw new Error(`${label} path must be absolute`)
  let supplied
  try { supplied = lstatSync(path) } catch { throw new Error(`${label} is missing`) }
  if (supplied.isSymbolicLink()) throw new Error(`${label} must not be a symlink`)
  let canonical
  try { canonical = realpathSync(path) } catch { throw new Error(`${label} is missing`) }
  const st = regular(canonical, label, max)
  const allowedOwners = new Set([0, typeof process.getuid === 'function' ? process.getuid() : 0])
  if (!allowedOwners.has(st.uid)) throw new Error(`${label} must be owned by root or the current user`)

  let dir = dirname(canonical)
  const root = parse(dir).root
  for (;;) {
    const parent = lstatSync(dir)
    const stickyRootDirectory = parent.uid === 0 && (parent.mode & 0o1000) !== 0
    if (!parent.isDirectory() || parent.isSymbolicLink() || !allowedOwners.has(parent.uid) ||
        ((parent.mode & 0o022) !== 0 && !stickyRootDirectory)) {
      throw new Error(`${label} must be beneath a non-replaceable root/current-user-owned directory chain`)
    }
    if (dir === root) break
    dir = dirname(dir)
  }
  return { path: canonical, stat: st }
}

export function privateFile(path, label) {
  const { path: canonical, stat: st } = fixedPath(path, label)
  if ((st.mode & 0o077) !== 0) throw new Error(`${label} must not be accessible by group or other (use mode 0600)`)
  return canonical
}

export function knownHostsFile(path) {
  const { path: canonical, stat: st } = fixedPath(path, 'known_hosts file')
  if ((st.mode & 0o022) !== 0) throw new Error('known_hosts file must not be group/world writable')
  return canonical
}

// The only process the session may start for its channel: no config file, no agent or forwarding,
// one identity, and a host key pinned in one file. The fleet's forced command decides the rest.
export function sshChannelEntry({ identity, knownHosts, target }) {
  return { command: SSH, args: ['-F', '/dev/null', '-T', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${knownHosts}`, '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ClearAllForwardings=yes', '-i', identity, target] }
}

// A portable harness's whole configuration. It names paths, never values, and it can hold nothing
// that signs: like a remote-broker manifest, a field that could carry a Nostr key or Bunker
// credential refuses the file rather than being ignored.
const CLIENT_FIELDS = new Set(['instance', 'ssh_target', 'identity_file', 'known_hosts_file', 'credential_file', 'home', 'model', 'pubkey', 'channels'])
export function readClientConfig(path, id) {
  const file = fixedPath(path, 'client config', 64 * 1024)
  if ((file.stat.mode & 0o022) !== 0) throw new Error('client config must not be group/world writable')
  let raw
  try { raw = JSON.parse(readFileSync(file.path, 'utf8')) } catch { throw new Error('client config is not valid JSON') }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('client config must be a JSON object')
  const text = JSON.stringify(raw)
  if (Object.keys(raw).some(key => /nsec|bunker|secret|signer|private/i.test(key)) || /nsec1[02-9ac-hj-np-z]{20,}|bunker:\/\//i.test(text)) {
    throw new Error('client config must not name a Nostr key or Bunker credential: nothing on this box signs')
  }
  const unknown = Object.keys(raw).filter(key => !CLIENT_FIELDS.has(key))
  if (unknown.length) throw new Error(`client config has unknown field ${unknown.join(', ')}`)
  if (raw.instance !== id) throw new Error('client config names a different instance')
  const target = String(raw.ssh_target || '')
  if (!SSH_TARGET.test(target)) throw new Error('client config ssh_target must be a fixed user@host')
  const own = resolve(homedir())
  const home = raw.home === undefined ? resolve(own, '.nvoy-harness', id) : String(raw.home)
  if (!isAbsolute(home)) throw new Error('client config home path must be absolute')
  if (resolve(home) === own) throw new Error('client config home must be the harness\'s own directory, never your home')
  const model = String(raw.model || '')
  if (model && !/^[a-z0-9][a-z0-9.\-\[\]]{0,63}$/i.test(model)) throw new Error('client config model must be a model name or alias')
  const pubkey = String(raw.pubkey || '')
  if (pubkey && !/^[0-9a-f]{64}$/.test(pubkey)) throw new Error('client config pubkey must be 64 lowercase hex characters')
  const channels = raw.channels === undefined ? [] : raw.channels
  if (!Array.isArray(channels) || !channels.every(c => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(c))) throw new Error('client config channels must be Buzz channel ids')
  return Object.freeze({
    id: instanceId(id), target, home: resolve(home), model, pubkey, channels,
    identity: privateFile(String(raw.identity_file || ''), 'SSH identity file'),
    knownHosts: knownHostsFile(String(raw.known_hosts_file || '')),
    credentialFile: privateFile(String(raw.credential_file || ''), 'Claude login credential file'),
  })
}
