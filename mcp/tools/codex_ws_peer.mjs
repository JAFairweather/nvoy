// One long-lived JSON-RPC peer on `codex app-server --listen unix://…`: WebSocket over a Unix
// socket, the transport that lets a person attach to the same thread with `codex resume --remote`.
// The framing is codex_app_server.mjs's minimal RFC 6455 client, kept open instead of per call.
// The peer's interface matches codex_harness.mjs's stdio peer, except that requests Codex makes of
// the client are handed to `onServerRequest` rather than declined: in a watched session a person
// may be the one to answer them.

import net from 'node:net'
import { createHash, randomBytes } from 'node:crypto'

const MAX_FRAME = 16 * 1024 * 1024

export function connectWsPeer({ socketPath, onServerRequest = () => {}, timeoutMs = 10000 }) {
  return new Promise((resolveConnect, rejectConnect) => {
    const stream = net.createConnection({ path: socketPath })
    const pending = new Map(), listeners = new Set(), key = randomBytes(16).toString('base64')
    let buffer = Buffer.alloc(0), upgraded = false, closed = false, nextId = 1, markExited
    const exited = new Promise(done => { markExited = done })
    const close = reason => {
      if (closed) return
      closed = true; clearTimeout(timer)
      for (const { reject } of pending.values()) reject(new Error(`codex app-server connection closed${reason ? `: ${reason}` : ''}`))
      pending.clear()
      try { stream.destroy() } catch {}
      if (!upgraded) rejectConnect(new Error(`codex app-server socket refused the connection${reason ? `: ${reason}` : ''}`))
      markExited(reason || 'closed')
    }
    const timer = setTimeout(() => close('no WebSocket upgrade within the timeout'), timeoutMs)
    const frame = (opcode, payload) => {
      if (closed) return
      const body = Buffer.from(payload)
      if (body.length > MAX_FRAME) throw new Error('Codex app-server request is too large')
      const mask = randomBytes(4); let head
      if (body.length < 126) head = Buffer.from([0x80 | opcode, 0x80 | body.length])
      else if (body.length < 65536) head = Buffer.from([0x80 | opcode, 0xfe, body.length >> 8, body.length & 0xff])
      else { head = Buffer.alloc(10); head[0] = 0x80 | opcode; head[1] = 0xff; head.writeBigUInt64BE(BigInt(body.length), 2) }
      const masked = Buffer.alloc(body.length)
      for (let i = 0; i < body.length; i++) masked[i] = body[i] ^ mask[i % 4]
      stream.write(Buffer.concat([head, mask, masked]))
    }
    const send = message => frame(1, JSON.stringify(message))
    const dispatch = message => {
      if (message.id != null && message.method) return onServerRequest(message)
      if (message.id != null && pending.has(message.id)) {
        const { resolve: done, reject } = pending.get(message.id)
        pending.delete(message.id)
        return message.error ? reject(Object.assign(new Error(message.error.message || 'unknown error'), { code: message.error.code })) : done(message.result)
      }
      if (message.method) for (const listener of listeners) listener(message)
    }
    const readFrames = () => {
      while (buffer.length >= 2) {
        const opcode = buffer[0] & 0x0f, initial = buffer[1] & 0x7f
        let offset = 2, length = initial
        if (initial === 126) { if (buffer.length < 4) return; length = buffer.readUInt16BE(2); offset = 4 }
        if (initial === 127) { if (buffer.length < 10) return; length = Number(buffer.readBigUInt64BE(2)); offset = 10 }
        if (!Number.isSafeInteger(length) || length > MAX_FRAME) return close('frame exceeds its bound')
        if (buffer.length < offset + length) return
        const body = buffer.subarray(offset, offset + length); buffer = buffer.subarray(offset + length)
        if (opcode === 8) return close('closed by Codex')
        if (opcode === 9) { frame(10, body); continue }
        if (opcode !== 1) continue
        let message; try { message = JSON.parse(String(body)) } catch { continue }
        dispatch(message)
      }
    }
    stream.on('connect', () => stream.write(`GET /rpc HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`))
    stream.on('data', data => {
      buffer = Buffer.concat([buffer, data])
      if (!upgraded) {
        const end = buffer.indexOf('\r\n\r\n')
        if (end < 0) { if (buffer.length > 16384) close('oversized upgrade response'); return }
        const head = String(buffer.subarray(0, end))
        const accept = createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
        if (!head.startsWith('HTTP/1.1 101') || !new RegExp(`^sec-websocket-accept:\\s*${accept.replace(/[+/=]/g, '\\$&')}\\s*$`, 'im').test(head)) return close('WebSocket upgrade refused')
        buffer = buffer.subarray(end + 4); upgraded = true; clearTimeout(timer)
        resolveConnect(peer)
      }
      readFrames()
    })
    stream.on('error', error => close(error.code || error.message))
    stream.on('close', () => close(''))
    const peer = {
      request(method, params, requestTimeoutMs = 60000) {
        const id = nextId++
        return new Promise((done, reject) => {
          if (closed) return reject(new Error('codex app-server connection closed'))
          const t = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out`)) }, requestTimeoutMs)
          pending.set(id, { resolve: value => { clearTimeout(t); done(value) }, reject: error => { clearTimeout(t); reject(error) } })
          send({ method, id, params })
        })
      },
      notify: (method, params = {}) => send({ method, params }),
      respond: (id, body) => send({ id, ...body }),
      on: listener => { listeners.add(listener); return () => listeners.delete(listener) },
      exited,
      get closed() { return closed },
      stop: () => { try { frame(8, Buffer.alloc(0)) } catch {} close('stopped') },
    }
  })
}
