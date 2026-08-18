#!/usr/bin/env node
// Verify the Codex Desktop shared-daemon topology for one manifest-bound task.
// Exit codes: 0 = owner match; 1 = definite split-owner/failure; 3 = inconclusive/unreadable.

import { existsSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { readManifest, instanceId } from './runtime_manifest.mjs'
import { appServerCall } from './codex_app_server.mjs'

const labelDefault = 'pub.nave.codex.app-server-daemon'
const die = (message, code = 1) => { console.error(`codex-shared-daemon-canary: ${message}`); process.exit(code) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const has = name => process.argv.includes(name)
const id = flag('--instance')
const label = flag('--label') || labelDefault
const timeoutMs = Number(flag('--timeout-ms') || 120000)
const explicitRoot = flag('--root')
const noDrive = has('--no-drive')
if (!id || has('--help') || has('-h')) {
  console.error('usage: codex-shared-daemon-canary --instance <id> [--root <instance-root>] [--label <launchd-label>] [--timeout-ms <ms>] [--no-drive]')
  process.exit(id ? 0 : 1)
}
if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) die('--timeout-ms must be a positive number', 3)

const uid = process.getuid?.()
if (!Number.isInteger(uid)) die('cannot determine uid', 3)
function defaultRoot(instance) {
  if (explicitRoot) return explicitRoot
  if (process.env.NVOY_INSTANCE_ROOT) return process.env.NVOY_INSTANCE_ROOT
  const home = process.env.HOME || ''
  if (process.platform === 'darwin' && home) {
    for (const candidate of [
      join(home, '.nvoy', 'codex-desktop', instance, 'instances'),
      join(home, '.nvoy', 'desktop', instance, 'instances'),
    ]) if (existsSync(candidate)) return candidate
  }
  return '/etc/nvoy/instances'
}
const root = defaultRoot(id)
let manifest
try { manifest = readManifest(root, instanceId(id)) }
catch (error) {
  if (/ENOENT|no such file or directory|is missing/.test(error.message || '')) {
    die(`instance root not found at ${root} — set NVOY_INSTANCE_ROOT or pass --root`, 3)
  }
  die(error.message, 3)
}
if (manifest.deliveryMode !== 'codex_app_server' || manifest.codexTransport !== 'local_control_socket') {
  die('manifest is not a local-control codex_app_server binding', 3)
}

function daemonPid() {
  let out = ''
  try { out = execFileSync('/bin/launchctl', ['print', `gui/${uid}/${label}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }) }
  catch { die('daemon not running or launchd label unreadable — INCONCLUSIVE, not green', 3) }
  const match = out.match(/\bpid = (\d+)/)
  if (!match) die('daemon not running or PID unreadable — INCONCLUSIVE, not green', 3)
  return match[1]
}
function lockHolders(lockPath) {
  if (!existsSync(lockPath)) die('lock file absent — INCONCLUSIVE (the turn never opened the thread)', 3)
  let out = ''
  try { out = execFileSync('/usr/sbin/lsof', ['-t', lockPath], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }) }
  catch (error) {
    if (error.status === 1) out = String(error.stdout || '')
    else die(`lsof failed while checking lock holders — INCONCLUSIVE: ${error.message || error}`, 3)
  }
  const holders = out.split('\n').map(s => s.trim()).filter(Boolean)
  if (!holders.length) die('lock exists with no holder — the turn did not run — INCONCLUSIVE', 3)
  if (!holders.every(pid => /^\d+$/.test(pid))) die(`lock holder PID unreadable: ${holders.join(' ')}`, 3)
  if (holders.length !== 1) die(`multiple holders: ${holders.join(' ')}`, 1)
  return holders[0]
}

const dpid = daemonPid()
if (!noDrive) {
  const token = `NVOY_SHARED_DAEMON_CANARY=${Date.now()}`
  const input = `Shared-daemon ownership canary. Reply exactly: SHARED-DAEMON-OWNER-OK\n${token}`
  try {
    await appServerCall({ socketPath: manifest.codexSocketPath, threadId: manifest.codexThreadId,
      input, clientUserMessageId: `shared-daemon-canary:${token}`, dedupeToken: token,
      steerActive: true, timeoutMs })
  } catch (error) {
    die(`canary turn failed before ownership check — INCONCLUSIVE: ${error.message || error}`, 3)
  }
}
const holder = lockHolders(`${process.env.HOME || ''}/.codex/thread-writer-locks/${manifest.codexThreadId}.lock`)
if (holder !== dpid) die(`split-owner: lock held by ${holder}, daemon is ${dpid}`, 1)
console.log(JSON.stringify({ ok: true, instance: manifest.id, daemon_pid: dpid, lock_holder: holder, thread_id: manifest.codexThreadId }, null, 2))
