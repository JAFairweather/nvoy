import net from 'node:net'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { observeDesktopTurn } from '../mcp/tools/codex_app_server.mjs'

const socketPath = join(mkdtempSync(join(tmpdir(), 'nvoy-observer-')), 'control.sock')
const threadId = '019fc80b-78a6-7b72-b3d2-eced37f55da7', receipt = '[nvoy:aaaaaaaaaaaaaaaa]'
const expectedUserText = `Visible message ${receipt}`
let reads = 0, forbidden = false
const frame = value => {
  const body = Buffer.from(JSON.stringify(value))
  if (body.length < 126) return Buffer.concat([Buffer.from([0x81, body.length]), body])
  const head = Buffer.alloc(4); head[0] = 0x81; head[1] = 126; head.writeUInt16BE(body.length, 2)
  return Buffer.concat([head, body])
}
const server = net.createServer(stream => {
  let upgraded = false, buffer = Buffer.alloc(0)
  stream.on('data', data => {
    buffer = Buffer.concat([buffer, data])
    if (!upgraded) {
      const end = buffer.indexOf('\r\n\r\n'); if (end < 0) return
      const key = /Sec-WebSocket-Key: ([^\r]+)/i.exec(String(buffer.subarray(0, end)))?.[1] || ''
      const accept = createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
      stream.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`)
      buffer = buffer.subarray(end + 4); upgraded = true
    }
    while (buffer.length >= 6) {
      let length = buffer[1] & 0x7f, offset = 2
      if (length === 126) { if (buffer.length < 8) return; length = buffer.readUInt16BE(2); offset = 4 }
      if (buffer.length < offset + 4 + length) return
      const mask = buffer.subarray(offset, offset + 4), body = Buffer.alloc(length)
      for (let i = 0; i < length; i++) body[i] = buffer[offset + 4 + i] ^ mask[i % 4]
      buffer = buffer.subarray(offset + 4 + length)
      const request = JSON.parse(String(body))
      if (request.method === 'initialize') stream.write(frame({ id: request.id, result: {} }))
      else if (request.method === 'initialized') {}
      else if (request.method === 'thread/read') {
        reads++
        const stale = { id: '019fc80b-78a6-7b72-b3d2-eced37f55da6', status: 'completed', items: [
          { type: 'userMessage', content: [{ type: 'text', text: `Earlier spoof ${receipt}` }] },
          { type: 'agentMessage', phase: 'final_answer', text: 'Wrong stale answer.' },
        ] }
        const commentaryOnly = { id: '019fc80b-78a6-7b72-b3d2-eced37f55da7', status: 'completed', items: [
          { type: 'userMessage', content: [{ type: 'text', text: expectedUserText }] },
          { type: 'agentMessage', phase: 'commentary', text: 'Never publish this commentary.' },
        ] }
        const turns = reads < 2 ? [stale, commentaryOnly] : [stale, { id: '019fc80b-78a6-7b72-b3d2-eced37f55da8', status: 'completed', items: [
          { type: 'userMessage', content: [{ type: 'text', text: expectedUserText }] },
          { type: 'agentMessage', phase: 'final_answer', text: 'Visible Desktop answer.' },
        ] }]
        stream.write(frame({ id: request.id, result: { thread: { id: threadId, turns } } }))
      } else { forbidden = true; stream.write(frame({ id: request.id, error: { message: 'forbidden' } })) }
    }
  })
})
await new Promise(resolve => server.listen(socketPath, resolve))
try {
  const result = await observeDesktopTurn({ socketPath, threadId, receipt, expectedUserText,
    expectedUserSha256: createHash('sha256').update(expectedUserText).digest('hex'), timeoutMs: 3000 })
  if (result.finalText !== 'Visible Desktop answer.' || reads !== 2 || forbidden) throw new Error('observer invariant failed')
  console.log('codex-desktop-observer: read-only visible turn recovered')
} finally { await new Promise(resolve => server.close(resolve)) }
