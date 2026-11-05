#!/usr/bin/env node
// Keep one stdio MCP server alive under a client that does not reconnect. Usage:
//   mcp-reconnect.mjs [--max-backoff-ms N] [--wake-herdr <agent>] -- <command> [args...]
// An interactive Claude Code session holds its channel over `ssh`, and every fleet deploy recreates
// the broker's container, which ends that ssh. Claude Code then marks the server failed until someone
// runs /mcp by hand (waggle-dev, after nvoy #264 and #265, 2026-10-27). A supervised harness restarts
// its whole session instead; an interactive one has nobody to do that.
//
// This sits between the client and the command. It records the client's `initialize` request and
// `initialized` notification, and when the command exits it starts it again and replays both, so the
// new server is set up exactly as the old one was. The replayed response is swallowed: the client
// already has one. Requests in flight when the command died, and any sent while it is down, are
// answered with an error rather than left hanging. It reads no message body beyond the JSON-RPC
// envelope, and it holds no key: authentication stays with the command.
//
// --wake-herdr names the herdr agent this client runs as. For a client that does not act on a
// channel's wake markers itself (agy), each marker is also typed into that agent's pane once it is
// idle (herdr_wake.mjs). That is the one exception to reading only the envelope: a marker's
// envelope id is read, checked, and nothing else.

import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { herdrClient } from './harness_herdr.mjs'
import { herdrWaker } from './herdr_wake.mjs'

const argv = process.argv.slice(2)
const split = argv.indexOf('--')
const die = message => { console.error(`mcp-reconnect: ${message}`); process.exit(2) }
if (split < 0 || split === argv.length - 1) die('usage: mcp-reconnect.mjs [--max-backoff-ms N] [--wake-herdr <agent>] -- <command> [args...]')
const options = argv.slice(0, split), [command, ...args] = argv.slice(split + 1)
const flag = name => { const i = options.indexOf(name); return i < 0 ? '' : options[i + 1] || '' }
const maxBackoffMs = Number(flag('--max-backoff-ms') || 30000)
const stableMs = Number(flag('--stable-ms') || 60000)
if (!Number.isInteger(maxBackoffMs) || maxBackoffMs < 100) die('--max-backoff-ms must be an integer >= 100')

const log = message => console.error(`mcp-reconnect: ${message}`)
const wakeAgent = flag('--wake-herdr')
if (options.includes('--wake-herdr') && !/^[a-z][a-z0-9_-]{0,31}$/.test(wakeAgent)) die('--wake-herdr must be a herdr agent name')
const wakeEveryMs = Number(flag('--wake-every-ms') || 2000)
if (!Number.isInteger(wakeEveryMs) || wakeEveryMs < 100 || wakeEveryMs > 60000) die('--wake-every-ms must be 100..60000')
const waker = wakeAgent ? herdrWaker({ agent: wakeAgent, herdr: herdrClient(), log, everyMs: wakeEveryMs }) : null
const toClient = message => process.stdout.write(JSON.stringify(message) + '\n')
const isRequest = m => m && m.method && m.id !== undefined && m.id !== null
const isResponse = m => m && !m.method && m.id !== undefined && m.id !== null
const unavailable = id => toClient({ jsonrpc: '2.0', id, error: { code: -32000, message: 'MCP server is reconnecting; retry shortly' } })

const firstBackoffMs = Math.min(1000, maxBackoffMs)
let child = null, ready = false, stopping = false, backoffMs = firstBackoffMs, generation = 0
let initialize = null, initialized = null
const inFlight = new Set()
const replayId = () => `mcp-reconnect-${generation}`

function start() {
  generation += 1
  const started = Date.now(), gen = generation
  const proc = spawn(command, args, { stdio: ['pipe', 'pipe', 'inherit'] })
  child = proc
  // A first start waits for the client's own initialize. A restart replays it, and is ready only
  // once the new server has answered.
  ready = !initialize
  proc.on('error', error => log(`start failed: ${error.message}`))
  createInterface({ input: proc.stdout }).on('line', line => {
    let message
    try { message = JSON.parse(line) } catch { return process.stdout.write(line + '\n') }
    if (isResponse(message) && message.id === replayId()) {
      if (message.error) { log(`replayed initialize refused: ${message.error.message || 'error'}`); return proc.kill('SIGTERM') }
      if (initialized) proc.stdin.write(JSON.stringify(initialized) + '\n')
      ready = true
      return log('reconnected')
    }
    if (isResponse(message)) inFlight.delete(message.id)
    waker?.notice(message)
    toClient(message)
  })
  proc.stdin.on('error', () => {})
  // Once per process, on exit or on close: a command that cannot start emits error and close but no
  // exit, and its restart and the answers to requests sent to it must still come.
  let ended = false
  const end = code => {
    if (ended) return
    ended = true
    if (child !== proc) return
    child = null; ready = false
    for (const id of inFlight) unavailable(id)
    inFlight.clear()
    if (stopping) return process.exit(code ?? 0)
    if (Date.now() - started > stableMs) backoffMs = firstBackoffMs
    log(`server exited (${code ?? 'signal'}); restarting in ${backoffMs}ms`)
    setTimeout(() => { if (!stopping && gen === generation) start() }, backoffMs)
    backoffMs = Math.min(backoffMs * 2, maxBackoffMs)
  }
  proc.on('exit', end)
  proc.on('close', end)
  if (initialize) proc.stdin.write(JSON.stringify({ ...initialize, id: replayId() }) + '\n')
}

createInterface({ input: process.stdin }).on('line', line => {
  let message
  try { message = JSON.parse(line) } catch { message = null }
  if (message?.method === 'initialize' && isRequest(message)) initialize = message
  if (message?.method === 'notifications/initialized') initialized = message
  if (!child || !ready) {
    if (isRequest(message)) unavailable(message.id)
    return
  }
  if (isRequest(message)) inFlight.add(message.id)
  child.stdin.write(line + '\n')
}).on('close', () => {
  stopping = true
  if (child?.pid) child.kill('SIGTERM')
  else process.exit(0)
})
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { stopping = true; if (child?.pid) child.kill(signal); else process.exit(0) })

start()
