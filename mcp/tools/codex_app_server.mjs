// Local Codex app-server client. The Unix socket is a host-local control plane; this module
// never accepts a network address, never knows Nostr credentials, and receives its thread id
// only from the supervisor-owned runtime manifest.
import net from 'node:net'
import { createHash, randomBytes } from 'node:crypto'
import { resolve } from 'node:path'

// `thread/read` returns the complete durable thread when the adapter checks its envelope token
// after an uncertain prior delivery.  A healthy, long-lived Desktop thread can exceed 10 MiB;
// rejecting that response wedges every later wake even though the admitted task is small. Keep
// a finite local-only transport bound, but size it for real project threads. Inbound Nostr data
// remains independently bounded by the broker/adapter before this control-plane call.
const MAX_FRAME = 64 * 1024 * 1024
const defaultSocket = () => resolve(process.env.HOME || '', '.codex', 'app-server-control', 'app-server-control.sock')

function validThread(id) {
  return /^thr_[A-Za-z0-9_-]{6,}$/.test(id) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)
}

export function codexThreadId(value) {
  const id = String(value || '')
  if (!validThread(id)) throw new Error('Codex thread id must be a persistent app-server UUID or thr_ id')
  return id
}

export function localControlSocket(value = '') {
  const path = String(value || defaultSocket())
  if (!path.startsWith('/')) throw new Error('Codex app-server socket must be an absolute local path')
  return path
}

// Once Codex supplies phase metadata for any assistant item, only an explicit final_answer is
// replyable. The legacy last-message fallback is reserved for turns with no phases at all.
export function finalAgentText(items = []) {
  const agents = items.filter(item => item?.type === 'agentMessage' && typeof item.text === 'string')
  const phased = agents.filter(item => typeof item.phase === 'string' && item.phase.length > 0)
  const candidates = phased.length ? phased.filter(item => item.phase === 'final_answer') : agents
  return [...candidates].reverse().find(item => item.text.trim())?.text || ''
}

// Minimal RFC 6455 client for the documented Unix app-server transport. `ws` does not reliably
// route Unix sockets on every supported Node build; keeping the transport here also means a
// desktop adapter has no HTTP listener and no path supplied by an incoming notification.
export function appServerCall({ socketPath, threadId, input, clientUserMessageId = null, listOnly = false, readOnly = false, bootstrap = null, dedupeToken = '', waitForCompletion = false, observeOnly = false, steerActive = false, expectedUserText = '', expectedUserSha256 = '', timeoutMs = 30000 }) {
  const socket = localControlSocket(socketPath)
  const id = listOnly || bootstrap ? null : codexThreadId(threadId)
  if ([listOnly, readOnly, Boolean(bootstrap)].filter(Boolean).length > 1) throw new Error('Codex app-server call cannot combine list, read, and bootstrap modes')
  if (observeOnly && (!dedupeToken || !waitForCompletion || listOnly || !expectedUserText ||
      createHash('sha256').update(expectedUserText).digest('hex') !== expectedUserSha256)) {
    throw new Error('observeOnly requires one exact receipt-and-message-bound completed turn')
  }
  return new Promise((resolveCall, rejectCall) => {
    const stream = net.createConnection({ path: socket })
    let buffer = Buffer.alloc(0), upgraded = false, finished = false, startedTurn = '', finalText = '', sawPhasedAgent = false, requestThree = '', bootstrappedThread = ''
    const finish = (error, value) => {
      if (finished) return
      finished = true; clearTimeout(timer)
      try { stream.destroy() } catch {}
      if (error) rejectCall(error); else resolveCall(value)
    }
    const timer = setTimeout(() => finish(new Error('Codex app-server did not acknowledge delivery within the timeout')), timeoutMs)
    const sendFrame = (opcode, payload) => {
      const body = Buffer.from(payload)
      if (body.length > MAX_FRAME) throw new Error('Codex app-server request is too large')
      const key = randomBytes(4); let head
      if (body.length < 126) head = Buffer.from([0x80 | opcode, 0x80 | body.length])
      else if (body.length < 65536) head = Buffer.from([0x80 | opcode, 0xfe, body.length >> 8, body.length & 0xff])
      else { head = Buffer.alloc(10); head[0] = 0x80 | opcode; head[1] = 0xff; head.writeBigUInt64BE(BigInt(body.length), 2) }
      const masked = Buffer.alloc(body.length)
      for (let i = 0; i < body.length; i++) masked[i] = body[i] ^ key[i % 4]
      stream.write(Buffer.concat([head, key, masked]))
    }
    const send = message => sendFrame(1, JSON.stringify(message))
    const request = (method, requestId, params) => send({ method, id: requestId, params })
    const readFrames = () => {
      while (buffer.length >= 2) {
        const opcode = buffer[0] & 0x0f; const initial = buffer[1] & 0x7f
        let offset = 2, length = initial
        if (initial === 126) { if (buffer.length < 4) return; length = buffer.readUInt16BE(2); offset = 4 }
        if (initial === 127) { if (buffer.length < 10) return; length = Number(buffer.readBigUInt64BE(2)); offset = 10 }
        if (!Number.isSafeInteger(length) || length > MAX_FRAME) return finish(new Error('Codex app-server response is too large'))
        if (buffer.length < offset + length) return
        const body = buffer.subarray(offset, offset + length); buffer = buffer.subarray(offset + length)
        if (opcode === 9) { sendFrame(10, body); continue }
        if (opcode !== 1) continue
        let message; try { message = JSON.parse(String(body)) } catch { continue }
        if (waitForCompletion && message.method === 'item/completed') {
          const p = message.params || {}
          if (p.threadId === id && p.turnId === startedTurn && p.item?.type === 'agentMessage' && typeof p.item.text === 'string') {
            // A remotely controlled Desktop turn can publish its durable final-answer item
            // without replaying turn/completed to this secondary socket subscriber. Waiting
            // only for the latter strands the broker receipt after the user has already seen
            // the answer. Commentary is never a reply; only Codex's explicit final phase may
            // close the call early. Older app-server builds without item phases retain the
            // turn/completed path below.
            if (typeof p.item.phase === 'string' && p.item.phase.length > 0) sawPhasedAgent = true
            if (p.item.phase === 'final_answer' && p.item.text.trim())
              return finish(null, { threadId: id, turnId: startedTurn, recovered: false, finalText: p.item.text })
            if (!sawPhasedAgent) finalText = p.item.text
          }
          continue
        }
        if (waitForCompletion && message.method === 'turn/completed') {
          const p = message.params || {}
          if (p.threadId !== id || p.turn?.id !== startedTurn) continue
          if (p.turn.status !== 'completed') return finish(new Error(`Codex turn ended with status ${p.turn.status || 'unknown'}`))
          const items = p.turn.items || []
          const turnHasPhases = items.some(item => item?.type === 'agentMessage' && typeof item.phase === 'string' && item.phase.length > 0)
          if (sawPhasedAgent || turnHasPhases || !finalText) finalText = finalAgentText(items)
          if (!finalText.trim()) return finish(new Error('Codex completed without a final assistant message'))
          return finish(null, { threadId: id, turnId: startedTurn, recovered: false, finalText })
        }
        if (message.id === 1) {
          if (message.error) return finish(new Error(`Codex initialize failed: ${message.error.message || 'unknown error'}`))
          send({ method: 'initialized', params: {} })
          if (listOnly) request('thread/list', 2, { limit: 50, sortKey: 'recency_at', sortDirection: 'desc' })
          else if (bootstrap) request('thread/list', 2, { limit: 50, searchTerm: bootstrap.name, cwd: bootstrap.cwd, sourceKinds: ['appServer'] })
          else if (readOnly) request('thread/read', 2, { threadId: id, includeTurns: true })
          else if (dedupeToken) request('thread/read', 2, { threadId: id, includeTurns: true })
          else request('thread/resume', 2, { threadId: id })
        } else if (message.id === 2) {
          if (message.error) return finish(new Error(`Codex ${listOnly || bootstrap ? 'thread/list' : readOnly || dedupeToken ? 'thread/read' : 'thread/resume'} failed: ${message.error.message || 'unknown error'}`))
          if (listOnly) return finish(null, message.result?.data || [])
          if (bootstrap) {
            const exact = (message.result?.data || []).filter(thread => thread?.name === bootstrap.name && thread?.cwd === bootstrap.cwd && typeof thread.id === 'string')
            if (exact.length > 1) return finish(new Error('multiple exact Codex participant tasks exist; refusing ambiguous selection'))
            if (exact.length === 1) return finish(null, { version: 1, created: false, thread_id: exact[0].id, name: bootstrap.name, cwd: bootstrap.cwd })
            const params = { cwd: bootstrap.cwd, serviceName: 'nvoy_nostr_participant' }
            if (bootstrap.model) params.model = bootstrap.model
            return request('thread/start', 3, params)
          }
          if (readOnly) return finish(null, message.result?.thread)
          if (message.result?.thread?.id !== id) return finish(new Error('Codex app-server returned an unexpected thread'))
          if (dedupeToken) {
            const userText = item => (item?.content || []).map(part => typeof part === 'string' ? part :
              (typeof part?.text === 'string' ? part.text : '')).join('')
            const prior = (message.result.thread.turns || []).find(turn => (turn.items || []).some(item => {
              if (item?.type !== 'userMessage' || !JSON.stringify(item).includes(dedupeToken)) return false
              if (!observeOnly) return true
              const exact = userText(item)
              return exact === expectedUserText && createHash('sha256').update(exact).digest('hex') === expectedUserSha256
            }))
            if (prior?.id) {
              const recoveredText = finalAgentText(prior.items || [])
              if (waitForCompletion && prior.status === 'completed' && recoveredText.trim()) return finish(null, { threadId: id, turnId: prior.id, recovered: true, finalText: recoveredText })
              if (observeOnly) return setTimeout(() => request('thread/read', 2, { threadId: id, includeTurns: true }), 250)
              if (waitForCompletion) return finish(new Error('recovered Codex turn is not complete with a final assistant message'))
              return finish(null, { threadId: id, turnId: prior.id, recovered: true })
            }
            if (observeOnly) return setTimeout(() => request('thread/read', 2, { threadId: id, includeTurns: true }), 250)
            const active = steerActive && message.result.thread.status?.type === 'active'
              ? [...(message.result.thread.turns || [])].reverse().find(turn => turn?.status === 'inProgress' && typeof turn.id === 'string')
              : null
            if (active) {
              requestThree = 'steer'
              request('turn/steer', 3, { threadId: id, input: [{ type: 'text', text: String(input || '') }], expectedTurnId: active.id })
            } else {
              requestThree = 'resume'
              request('thread/resume', 3, { threadId: id })
            }
          } else request('turn/start', 3, { threadId: id, input: [{ type: 'text', text: String(input || '') }], clientUserMessageId })
        } else if (message.id === 3) {
          if (bootstrap) {
            if (message.error) return finish(new Error(`Codex thread/start failed: ${message.error.message || 'unknown error'}`))
            bootstrappedThread = message.result?.thread?.id || ''
            try { codexThreadId(bootstrappedThread) } catch { return finish(new Error('Codex thread/start returned an invalid task id')) }
            request('thread/name/set', 4, { threadId: bootstrappedThread, name: bootstrap.name })
            continue
          }
          if (dedupeToken) {
            if (requestThree === 'steer') {
              if (message.error) return finish(new Error(`Codex turn/steer failed: ${message.error.message || 'unknown error'}`))
              if (!message.result?.turnId) return finish(new Error('Codex turn/steer returned an invalid acknowledgement'))
              startedTurn = message.result.turnId
              if (!waitForCompletion) return finish(null, { threadId: id, turnId: startedTurn, recovered: false, steered: true })
              continue
            }
            if (message.error) return finish(new Error(`Codex thread/resume failed: ${message.error.message || 'unknown error'}`))
            if (message.result?.thread?.id !== id) return finish(new Error('Codex app-server resumed an unexpected thread'))
            request('turn/start', 4, { threadId: id, input: [{ type: 'text', text: String(input || '') }], clientUserMessageId })
          } else {
            if (message.error) return finish(new Error(`Codex turn/start failed: ${message.error.message || 'unknown error'}`))
            if (!message.result?.turn?.id) return finish(new Error('Codex app-server returned an invalid turn acknowledgement'))
            startedTurn = message.result.turn.id
            if (!waitForCompletion) return finish(null, { threadId: id, turnId: startedTurn })
          }
        } else if (message.id === 4 && bootstrap) {
          if (message.error) return finish(new Error(`Codex thread/name/set failed: ${message.error.message || 'unknown error'}`))
          request('thread/read', 5, { threadId: bootstrappedThread, includeTurns: false })
        } else if (message.id === 4 && dedupeToken) {
          if (message.error) return finish(new Error(`Codex turn/start failed: ${message.error.message || 'unknown error'}`))
          if (!message.result?.turn?.id) return finish(new Error('Codex app-server returned an invalid turn acknowledgement'))
          startedTurn = message.result.turn.id
          if (!waitForCompletion) return finish(null, { threadId: id, turnId: startedTurn, recovered: false })
        } else if (message.id === 5 && bootstrap) {
          if (message.error) return finish(new Error(`Codex bootstrap verification failed: ${message.error.message || 'unknown error'}`))
          const thread = message.result?.thread
          if (thread?.id !== bootstrappedThread || thread?.name !== bootstrap.name || thread?.cwd !== bootstrap.cwd)
            return finish(new Error('Codex bootstrap could not verify the exact named task'))
          return finish(null, { version: 1, created: true, thread_id: bootstrappedThread, name: bootstrap.name, cwd: bootstrap.cwd })
        }
      }
    }
    stream.on('connect', () => stream.write(`GET /rpc HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${randomBytes(16).toString('base64')}\r\nSec-WebSocket-Version: 13\r\n\r\n`))
    stream.on('data', data => {
      buffer = Buffer.concat([buffer, data])
      if (!upgraded) {
        const end = buffer.indexOf('\r\n\r\n'); if (end < 0) return
        if (!String(buffer.subarray(0, end)).startsWith('HTTP/1.1 101')) return finish(new Error('Codex app-server rejected local WebSocket upgrade'))
        buffer = buffer.subarray(end + 4); upgraded = true
        request('initialize', 1, { clientInfo: { name: 'nvoy-notification-adapter', title: 'Nvoy notification adapter', version: '1' }, capabilities: {} })
      }
      readFrames()
    })
    stream.on('error', error => finish(error))
    stream.on('close', () => { if (!finished) finish(new Error('Codex app-server closed before acknowledging delivery')) })
  })
}

// Observe a turn created by the visible Codex Desktop UI. This path can only poll thread/read;
// it cannot resume a thread or call turn/start, so a secondary client never manufactures a
// background response that is absent from the user's Desktop transcript.
export async function observeDesktopTurn({ socketPath, threadId, receipt, expectedUserText, expectedUserSha256, timeoutMs = 10 * 60 * 1000 }) {
  const token = String(receipt || '')
  if (!/^\[nvoy:[0-9a-f]{16}\]$/.test(token)) throw new Error('Desktop observer requires an exact visible receipt')
  const result = await appServerCall({ socketPath, threadId, input: '', dedupeToken: token,
    waitForCompletion: true, observeOnly: true, expectedUserText, expectedUserSha256, timeoutMs })
  return result
}
