import net from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { appServerCall } from '../mcp/tools/codex_app_server.mjs'

const root = mkdtempSync(join(tmpdir(), 'nvoy-codex-completion-'))
const socket = join(root, 'control.sock'), thread = '019fce57-063d-7f50-b837-967d33ee384a', turn = '019fd200-0000-7000-8000-000000000001'
const frame = value => {
  const body = Buffer.from(JSON.stringify(value)); let head
  if (body.length < 126) head = Buffer.from([0x81, body.length])
  else { head = Buffer.alloc(4); head[0] = 0x81; head[1] = 126; head.writeUInt16BE(body.length, 2) }
  return Buffer.concat([head, body])
}
function requests(buffer) {
  const out = []
  while (buffer.length >= 2) {
    const initial = buffer[1] & 0x7f; let length = initial, offset = 2
    if (initial === 126) { if (buffer.length < 4) break; length = buffer.readUInt16BE(2); offset = 4 }
    if (initial === 127) { if (buffer.length < 10) break; length = Number(buffer.readBigUInt64BE(2)); offset = 10 }
    const maskBytes = buffer[1] & 0x80 ? 4 : 0
    if (buffer.length < offset + maskBytes + length) break
    const mask = buffer.subarray(offset, offset + maskBytes), body = Buffer.from(buffer.subarray(offset + maskBytes, offset + maskBytes + length))
    if (maskBytes) for (let i = 0; i < body.length; i++) body[i] ^= mask[i % 4]
    out.push(JSON.parse(String(body))); buffer = buffer.subarray(offset + maskBytes + length)
  }
  return { out, rest: buffer }
}
const server = net.createServer(stream => {
  let upgraded = false, buffer = Buffer.alloc(0)
  stream.on('data', chunk => {
    buffer = Buffer.concat([buffer, chunk])
    if (!upgraded) {
      const end = buffer.indexOf('\r\n\r\n'); if (end < 0) return
      buffer = buffer.subarray(end + 4); upgraded = true
      stream.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    }
    const parsed = requests(buffer); buffer = parsed.rest
    for (const request of parsed.out) {
      if (request.method === 'initialize') stream.write(frame({ id: request.id, result: {} }))
      if (request.method === 'thread/read') stream.write(frame({ id: request.id, result: { thread: { id: thread, turns: [] } } }))
      if (request.method === 'thread/resume') stream.write(frame({ id: request.id, result: { thread: { id: thread } } }))
      if (request.method === 'turn/start') {
        stream.write(frame({ id: request.id, result: { turn: { id: turn } } }))
        stream.write(frame({ method: 'item/completed', params: { threadId: thread, turnId: turn, completedAtMs: Date.now(), item: { id: 'comment', type: 'agentMessage', phase: 'commentary', text: 'Still working.' } } }))
        stream.write(frame({ method: 'item/completed', params: { threadId: thread, turnId: turn, completedAtMs: Date.now(), item: { id: 'msg', type: 'agentMessage', phase: 'final_answer', text: 'WAKE proof acknowledged once.' } } }))
        // Deliberately omit turn/completed: the live secondary control-socket subscriber can
        // miss it even though the explicitly phased final item is durable in the thread.
      }
    }
  })
})

try {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socket, resolve) })
  const result = await appServerCall({ socketPath: socket, threadId: thread, input: 'wake', clientUserMessageId: 'nvoy:test',
    dedupeToken: 'NVOY_ENVELOPE_ID=' + 'a'.repeat(64), waitForCompletion: true, timeoutMs: 10_000 })
  if (result.turnId !== turn || result.finalText !== 'WAKE proof acknowledged once.') throw new Error('completed response was not bound and captured')
  console.log('codex-app-server-completion: commentary ignored and exact final item captured without turn/completed')
} finally {
  await new Promise(resolve => server.close(resolve))
  rmSync(root, { recursive: true, force: true })
}
