// Keep one agent's own Codex thread open behind `codex app-server`, and inject each admitted
// envelope into it as a turn. The thread persists in the harness home, so a restart resumes the
// same conversation. Codex reads the message and replies itself, through the keyless channel
// tools; the supervisor never reads a message body or a reply.

import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { resolve } from 'node:path'
import { codexConfigToml, codexTurnText, defaultInstructions, pendingEnvelopes } from './harness_session.mjs'
import { codexThreadId } from './codex_app_server.mjs'

const sleep = ms => new Promise(done => setTimeout(done, ms))

// One JSON-RPC peer over the app-server's stdio. Requests the server makes of us (approvals,
// elicitations) are declined: nobody is there to answer, and the policy asks for none.
function appServer({ env, log }) {
  const child = spawn('codex', ['app-server'], { stdio: ['pipe', 'pipe', 'pipe'], env })
  const pending = new Map(), listeners = new Set()
  let nextId = 1, closed = false, stderr = ''
  const send = message => { if (!closed) child.stdin.write(JSON.stringify(message) + '\n') }
  const exited = new Promise(done => child.on('exit', code => {
    closed = true
    for (const { reject } of pending.values()) reject(new Error(`codex app-server exited (${code})${stderr ? `: ${stderr.trim().slice(-300)}` : ''}`))
    pending.clear()
    done(code)
  }))
  child.on('error', error => { stderr += error.message })
  child.stderr.on('data', data => { stderr = (stderr + String(data)).slice(-4000) })
  createInterface({ input: child.stdout }).on('line', line => {
    let message
    try { message = JSON.parse(line) } catch { return }
    if (message.id != null && message.method) {
      log(`declined a ${message.method} request from Codex`)
      return send({ id: message.id, error: { code: -32601, message: 'the nvoy harness answers no requests' } })
    }
    if (message.id != null && pending.has(message.id)) {
      const { resolve: done, reject } = pending.get(message.id)
      pending.delete(message.id)
      return message.error ? reject(new Error(message.error.message || 'unknown error')) : done(message.result)
    }
    if (message.method) for (const listener of listeners) listener(message)
  })
  return {
    request(method, params, timeoutMs = 60000) {
      const id = nextId++
      return new Promise((done, reject) => {
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out`)) }, timeoutMs)
        pending.set(id, { resolve: value => { clearTimeout(timer); done(value) }, reject: error => { clearTimeout(timer); reject(error) } })
        send({ method, id, params })
      })
    },
    notify: (method, params = {}) => send({ method, params }),
    on: listener => { listeners.add(listener); return () => listeners.delete(listener) },
    exited,
    get closed() { return closed },
    stop: () => { try { child.kill('SIGTERM') } catch {} },
  }
}

// Resume the stored thread, or start one and store it. Shared by the fleet and portable supervisors.
export async function openThread({ server, manifest, workdir, threadPath, log, writePrivate }) {
  let threadId = '', thread = null
  try { threadId = codexThreadId(JSON.parse(readFileSync(threadPath, 'utf8')).thread_id) } catch {}
  if (threadId) {
    try {
      const resumed = await server.request('thread/resume', { threadId })
      if (resumed?.thread?.id !== threadId) throw new Error('Codex resumed an unexpected thread')
      thread = resumed.thread
      log(`resumed the ${manifest.id} thread`)
    } catch (error) {
      // Codex saves a thread at its first turn, so a thread that never had one cannot be
      // resumed after a restart. Retrying it can never succeed (DJ Codex, 2026-09-25).
      if (!/no rollout found/i.test(error.message)) throw error
      log(`Codex never saved the stored ${manifest.id} thread; starting a new one`)
      threadId = ''
    }
  }
  if (!threadId) {
    const started = await server.request('thread/start', { cwd: workdir, serviceName: 'nvoy_harness', ...(manifest.harness.model ? { model: manifest.harness.model } : {}) })
    threadId = codexThreadId(started?.thread?.id)
    thread = started.thread
    writePrivate(threadPath, JSON.stringify({ version: 1, instance: manifest.id, thread_id: threadId }) + '\n')
    log(`started the ${manifest.id} thread`)
  }
  return { threadId, thread }
}

export async function runCodexHarness({ manifest, root, home, credential, log, stopping }) {
  const codexHome = resolve(home, '.codex'), workdir = resolve(home, 'workspace'), privateDir = resolve(home, '.nvoy-harness')
  const threadPath = resolve(privateDir, 'codex-thread.json'), deliveredPath = resolve(privateDir, 'delivered.jsonl')
  const queuePath = resolve(manifest.runtimeDir, 'admitted-tasks.jsonl')
  const POLL_MS = Number(process.env.HARNESS_POLL_MS || 1000)
  const TURN_MS = Number(process.env.HARNESS_TURN_MS || 10 * 60 * 1000)
  const RETRY_MAX_MS = Number(process.env.HARNESS_RETRY_MAX_MS || 300000)
  const writePrivate = (path, value) => { writeFileSync(path, value, { mode: 0o600 }); chmodSync(path, 0o600) }
  for (const dir of [codexHome, workdir, privateDir]) mkdirSync(dir, { recursive: true, mode: 0o700 })
  writePrivate(resolve(codexHome, 'config.toml'), codexConfigToml({ manifest, root, model: manifest.harness.model }))
  if (!existsSync(resolve(workdir, 'AGENTS.md'))) writePrivate(resolve(workdir, 'AGENTS.md'), defaultInstructions(manifest))

  const queueText = () => { try { return readFileSync(queuePath, 'utf8') } catch { return '' } }
  const delivered = () => existsSync(deliveredPath)
    ? readFileSync(deliveredPath, 'utf8').split('\n').filter(Boolean).map(line => { try { return JSON.parse(line).envelope } catch { return '' } })
    : null
  const markDelivered = (envelope, turn) => { appendFileSync(deliveredPath, JSON.stringify({ envelope, turn, at: Date.now() }) + '\n', { mode: 0o600 }); chmodSync(deliveredPath, 0o600) }
  // A first start owns no conversation yet: whatever the queue already holds is history, not a
  // burst of work. Later arrivals are live.
  if (delivered() === null) {
    const backlog = pendingEnvelopes(queueText(), [])
    writePrivate(deliveredPath, backlog.map(row => JSON.stringify({ envelope: row.envelope, turn: null, at: Date.now() }) + '\n').join(''))
    log(`first start: baselined ${backlog.length} admitted envelope(s)`)
  }

  const env = { PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin', HOME: home, CODEX_HOME: codexHome, OPENAI_API_KEY: credential }
  let delay = 5000
  while (!stopping()) {
    const startedAt = Date.now()
    const server = appServer({ env, log })
    try {
      await server.request('initialize', { clientInfo: { name: 'nvoy-harness', title: 'Nvoy harness', version: '1' }, capabilities: {} })
      server.notify('initialized')
      const { threadId } = await openThread({ server, manifest, workdir, threadPath, log, writePrivate })
      log(`${manifest.id} session ready; admitted messages will be injected as turns`)
      while (!stopping()) {
        const next = pendingEnvelopes(queueText(), delivered() || [])[0]
        if (!next) { await Promise.race([sleep(POLL_MS), server.exited]); if (server.closed) break; continue }
        const completed = new Promise(done => {
          const timer = setTimeout(() => { off(); done('timed out') }, TURN_MS)
          const off = server.on(message => {
            if (message.method === 'turn/completed' && message.params?.threadId === threadId && message.params?.turn?.id === turnId) {
              clearTimeout(timer); off(); done(message.params.turn.status || 'unknown')
            }
          })
        })
        let turnId = ''
        const started = await server.request('turn/start', { threadId, input: [{ type: 'text', text: codexTurnText(next) }], clientUserMessageId: `nvoy:${next.envelope}` })
        turnId = String(started?.turn?.id || '')
        if (!turnId) throw new Error('Codex returned no turn id')
        markDelivered(next.envelope, turnId)
        log(`injected ${next.envelope.slice(0, 12)} as a turn`)
        log(`turn for ${next.envelope.slice(0, 12)} ended: ${await Promise.race([completed, server.exited.then(() => 'server exited')])}`)
      }
    } catch (error) {
      log(`codex harness: ${error.message}`)
    } finally {
      server.stop()
    }
    if (stopping()) break
    if (Date.now() - startedAt > RETRY_MAX_MS) delay = 5000
    log(`next start in ${Math.round(delay / 1000)}s`)
    await sleep(delay)
    delay = Math.min(delay * 2, RETRY_MAX_MS)
  }
}
