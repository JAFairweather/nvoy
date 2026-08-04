// Local Codex app-server client. The Unix socket is a host-local control plane; this module
// never accepts a network address, never knows Nostr credentials, and receives its thread id
// only from the supervisor-owned runtime manifest.
import net from 'node:net'
import { randomBytes } from 'node:crypto'
import { resolve } from 'node:path'

const MAX_FRAME = 10 * 1024 * 1024
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

// Minimal RFC 6455 client for the documented Unix app-server transport. `ws` does not reliably
// route Unix sockets on every supported Node build; keeping the transport here also means a
// desktop adapter has no HTTP listener and no path supplied by an incoming notification.
export function appServerCall({ socketPath, threadId, input, listOnly = false, timeoutMs = 30000 }) {
  const socket = localControlSocket(socketPath)
  const id = listOnly ? null : codexThreadId(threadId)
  return new Promise((resolveCall, rejectCall) => {
    const stream = net.createConnection({ path: socket })
    let buffer = Buffer.alloc(0), upgraded = false, finished = false
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
        if (message.id === 1) {
          if (message.error) return finish(new Error(`Codex initialize failed: ${message.error.message || 'unknown error'}`))
          send({ method: 'initialized', params: {} })
          if (listOnly) request('thread/list', 2, { limit: 50, sortKey: 'recency_at', sortDirection: 'desc' })
          else request('thread/resume', 2, { threadId: id })
        } else if (message.id === 2) {
          if (message.error) return finish(new Error(`Codex ${listOnly ? 'thread/list' : 'thread/resume'} failed: ${message.error.message || 'unknown error'}`))
          if (listOnly) return finish(null, message.result?.data || [])
          if (message.result?.thread?.id !== id) return finish(new Error('Codex app-server resumed an unexpected thread'))
          request('turn/start', 3, { threadId: id, input: [{ type: 'text', text: String(input || '') }] })
        } else if (message.id === 3) {
          if (message.error) return finish(new Error(`Codex turn/start failed: ${message.error.message || 'unknown error'}`))
          if (!message.result?.turn?.id) return finish(new Error('Codex app-server returned an invalid turn acknowledgement'))
          return finish(null, { threadId: id, turnId: message.result.turn.id })
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
