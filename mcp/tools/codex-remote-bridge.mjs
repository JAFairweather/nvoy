#!/usr/bin/env node
// Pull adapter-admitted tasks through a forced-command SSH key and deliver them to one fixed
// Codex Desktop thread. The SSH credential can read only this instance's admitted queue; it is
// not a login key and it is never a Nostr signer.

import { existsSync, lstatSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { readManifest, instanceId } from './runtime_manifest.mjs'

const die = message => { console.error(`codex-remote-bridge: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance')
const once = process.argv.includes('--once'), baseline = process.argv.includes('--baseline')
const intervalMs = Number(flag('--interval-ms') || 2000)
if (!id) die('usage: --instance <id> [--baseline] [--once] [--interval-ms 1000..60000]')
if (!Number.isInteger(intervalMs) || intervalMs < 1000 || intervalMs > 60000) die('--interval-ms must be 1000..60000')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
let manifest
try { manifest = readManifest(root, instanceId(id)) } catch (error) { die(error.message) }
if (manifest.brokerMode !== 'remote' || manifest.deliveryMode !== 'codex_app_server' || manifest.codexTransport !== 'local_control_socket') die('manifest is not a keyless remote-broker Codex binding')
const target = manifest.sshTarget, identity = resolve(manifest.sshIdentityFile), knownHosts = resolve(manifest.sshKnownHostsFile)
for (const [path, label] of [[identity, 'SSH identity'], [knownHosts, 'known-hosts file']]) {
  let stat; try { stat = lstatSync(path) } catch { die(`${label} is missing`) }
  if (!stat.isFile() || stat.isSymbolicLink()) die(`${label} must be a regular non-symlink file`)
  if (stat.mode & 0o077) die(`${label} must be owner-only`)
}
const knownDigest = createHash('sha256').update(readFileSync(knownHosts)).digest('hex')
if (knownDigest !== manifest.sshKnownHostsSha256) die('known-hosts file does not match the manifest-pinned digest')

const sshArgs = ['-i', identity, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
  '-o', `UserKnownHostsFile=${knownHosts}`, '-o', 'ClearAllForwardings=yes', '-T', target]
// The Desktop half is keyless. Do not let an unrelated shell's signer, cloud, or proxy
// credentials leak into either parser or the Codex delivery adapter merely because the bridge
// was launched from an interactive terminal.
const childEnv = { HOME: process.env.HOME || '', PATH: process.env.PATH || '', NVOY_INSTANCE_ROOT: root }
function cycle() {
  // No remote command is supplied. authorized_keys must force the single worker-UID sync command;
  // a server that offers an interactive shell is a deployment error, not a supported mode.
  const replyQueue = resolve(manifest.runtimeDir, 'reply-requests.jsonl')
  let replies = ''
  if (!baseline && existsSync(replyQueue)) {
    const stat = lstatSync(replyQueue)
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16 * 1024 * 1024) throw new Error('local reply queue is not a bounded regular file')
    replies = readFileSync(replyQueue, 'utf8')
  }
  const pulled = spawnSync('ssh', sshArgs, { encoding: 'utf8', input: replies, maxBuffer: 64 * 1024 * 1024 })
  if (pulled.status !== 0) throw new Error(`restricted queue export failed (${pulled.status}): ${String(pulled.stderr || '').trim()}`)
  const imported = spawnSync(process.execPath, [resolve(repoRoot, 'mcp/tools/instance-admitted-import.mjs'), '--instance', manifest.id, ...(baseline ? ['--baseline'] : [])],
    { cwd: repoRoot, encoding: 'utf8', input: pulled.stdout, env: childEnv, maxBuffer: 64 * 1024 * 1024 })
  if (imported.status !== 0) throw new Error(String(imported.stderr || 'admitted import failed').trim())
  if (!baseline) {
    const delivered = spawnSync(process.execPath, [resolve(repoRoot, 'mcp/tools/codex-app-server-adapter.mjs'), '--instance', manifest.id, '--once'],
      { cwd: repoRoot, encoding: 'utf8', env: childEnv, maxBuffer: 1024 * 1024 })
    if (delivered.status !== 0) throw new Error(String(delivered.stderr || 'Codex delivery failed').trim())
    if (delivered.stdout) process.stdout.write(delivered.stdout)
  }
  if (imported.stdout) process.stdout.write(imported.stdout)
}

try { cycle() } catch (error) { die(error.message) }
if (once || baseline) process.exit(0)
setInterval(() => { try { cycle() } catch (error) { console.error(`codex-remote-bridge: ${error.message}`) } }, intervalMs)
