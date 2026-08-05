#!/usr/bin/env node
// Keyless V1 binder: one broker-admitted identity queue -> one visible Codex Desktop chat.

import { appendFileSync, closeSync, existsSync, fsyncSync, lstatSync, openSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { randomBytes } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { readManifest, instanceId } from './runtime_manifest.mjs'
import { baselineDesktopQueue, deliverPending } from './macos_desktop_adapter.mjs'
import { observeDesktopTurn } from './codex_app_server.mjs'

const die = message => { console.error(`codex-macos-desktop-adapter: ${message}`); process.exit(1) }
const flag = name => { const i = process.argv.indexOf(name); return i < 0 ? '' : process.argv[i + 1] || '' }
const id = flag('--instance'), once = process.argv.includes('--once'), baseline = process.argv.includes('--baseline')
if (!id) die('usage: --instance <id> [--baseline|--once]')
const root = process.env.NVOY_INSTANCE_ROOT || '/etc/nvoy/instances'
let manifest
try { manifest = readManifest(root, instanceId(id)) } catch (error) { die(error.message) }
if (manifest.deliveryMode !== 'macos_desktop' || manifest.brokerMode !== 'remote') die('manifest is not a keyless remote macos_desktop binding')

const queuePath = resolve(manifest.runtimeDir, 'admitted-tasks.jsonl')
const baselinePath = resolve(manifest.runtimeDir, 'macos-desktop-baseline.jsonl')
const visiblePath = resolve(manifest.runtimeDir, 'macos-desktop-visible.jsonl')
const completedPath = resolve(manifest.runtimeDir, 'macos-desktop-completed.jsonl')
const replyPath = resolve(manifest.runtimeDir, 'reply-requests.jsonl')
const lockPath = resolve(manifest.runtimeDir, 'macos-desktop-adapter.lock')
const binding = { appBundleId: manifest.codexAppBundleId, projectLabel: manifest.codexProjectLabel, chatLabel: manifest.codexChatLabel }
const policy = { instance: manifest.id, scopeSubject: manifest.pubkey, grantors: manifest.grantors, carriers: manifest.carriers }

function records(path) {
  if (!existsSync(path)) return []
  const stat = lstatSync(path)
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 32 * 1024 * 1024) throw new Error('reply queue must be a bounded regular non-symlink file')
  return readFileSync(path, 'utf8').split('\n').flatMap(line => { if (!line.trim()) return []; try { return [JSON.parse(line)] } catch { throw new Error('reply queue contains invalid JSON') } })
}
function durableAppend(path, row) {
  const fd = openSync(path, 'a', 0o600)
  try { appendFileSync(fd, JSON.stringify(row) + '\n'); fsyncSync(fd) } finally { closeSync(fd) }
}
async function invoke(request) {
  const stat = lstatSync(manifest.codexUiDriver)
  if (!stat.isFile() || stat.isSymbolicLink() || !(stat.mode & 0o100)) throw new Error('Codex UI driver must be an executable regular non-symlink file')
  const result = spawnSync(manifest.codexUiDriver, [], { input: JSON.stringify(request), encoding: 'utf8',
    env: {}, maxBuffer: 1024 * 1024, timeout: 30000 })
  if (result.status !== 0) throw new Error(String(result.stderr || 'Codex UI driver failed').trim())
  let evidence; try { evidence = JSON.parse(result.stdout) } catch { throw new Error('Codex UI driver returned invalid evidence') }
  return evidence
}
async function observe(request) {
  const result = await observeDesktopTurn({ socketPath: manifest.codexSocketPath, threadId: manifest.codexThreadId,
    receipt: request.receipt, timeoutMs: 10 * 60 * 1000 })
  return result.finalText
}
async function queueReply({ envelope, content }) {
  if (records(replyPath).some(row => row?.receipt === envelope)) return
  durableAppend(replyPath, { version: 1, type: 'reply-request', id: randomBytes(16).toString('hex'),
    instance: manifest.id, receipt: envelope, content })
}
async function drain() { return deliverPending({ queuePath, baselinePath, visiblePath, completedPath, binding, policy, invoke, observe, queueReply }) }
function acquire() {
  try { writeFileSync(lockPath, JSON.stringify({ pid: process.pid }), { flag: 'wx', mode: 0o600 }) }
  catch (error) {
    if (error.code !== 'EEXIST') throw error
    let old; try { old = JSON.parse(readFileSync(lockPath, 'utf8')) } catch { throw new Error('adapter lock is invalid') }
    try { process.kill(old.pid, 0); throw new Error(`another adapter is running (pid ${old.pid})`) }
    catch (probe) { if (probe?.code !== 'ESRCH') throw probe }
    unlinkSync(lockPath); writeFileSync(lockPath, JSON.stringify({ pid: process.pid }), { flag: 'wx', mode: 0o600 })
  }
}
try {
  acquire()
  const result = baseline ? { baselined: baselineDesktopQueue({ queuePath, baselinePath, policy }) } : await drain()
  if (once || baseline) console.log(JSON.stringify(result))
}
catch (error) { try { unlinkSync(lockPath) } catch {}; die(error.message || String(error)) }
const release = () => { try { unlinkSync(lockPath) } catch {} }
process.once('exit', release)
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { release(); process.exit(0) })
if (once || baseline) { release(); process.exit(0) }
let busy = false
setInterval(async () => { if (busy) return; busy = true; try { await drain() } catch (error) { console.error(`codex-macos-desktop-adapter: ${error.message}`) } finally { busy = false } }, 1000)
