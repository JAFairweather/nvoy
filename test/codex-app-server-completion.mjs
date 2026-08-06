import net from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { appServerCall } from '../mcp/tools/codex_app_server.mjs'

const root = mkdtempSync(join(tmpdir(), 'nvoy-codex-completion-'))
const socket = join(root, 'control.sock'), thread = '019fce57-063d-7f50-b837-967d33ee384a', turn = '019fd200-0000-7000-8000-000000000001'
let started = 0, reads = 0, steered = 0
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
      if (request.method === 'thread/read') {
        reads++
        const turns = reads === 1 ? [{ id: turn, status: 'inProgress', items: [] }] : reads < 3 ? [] : [{ id: turn, status: 'completed', items: [
          { type: 'userMessage', content: [{ type: 'text', text: 'NVOY_ENVELOPE_ID=' + 'c'.repeat(64) }] },
          { type: 'agentMessage', phase: 'commentary', text: 'Never publish recovered commentary.' },
        ] }]
        stream.write(frame({ id: request.id, result: { thread: { id: thread, status: { type: reads === 1 ? 'active' : 'idle' }, turns } } }))
      }
      if (request.method === 'thread/resume') stream.write(frame({ id: request.id, result: { thread: { id: thread } } }))
      if (request.method === 'turn/start') {
        started++
        stream.write(frame({ id: request.id, result: { turn: { id: turn } } }))
        stream.write(frame({ method: 'item/completed', params: { threadId: thread, turnId: turn, completedAtMs: Date.now(), item: { id: 'comment', type: 'agentMessage', phase: 'commentary', text: 'Still working.' } } }))
        stream.write(frame({ method: 'turn/completed', params: { threadId: thread, turn: { id: turn, status: 'completed', items: [
          { id: 'comment', type: 'agentMessage', phase: 'commentary', text: 'Never publish live commentary.' },
        ] } } }))
      }
      if (request.method === 'turn/steer') {
        steered++
        if (request.params.expectedTurnId !== turn || request.params.threadId !== thread) throw new Error('steer was not bound to the exact active turn')
        stream.write(frame({ id: request.id, result: { turnId: turn } }))
        stream.write(frame({ method: 'item/completed', params: { threadId: thread, turnId: turn, item: { id: 'steered-final', type: 'agentMessage', phase: 'final_answer', text: 'Steered wake acknowledged.' } } }))
      }
    }
  })
})

try {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socket, resolve) })
  const snapshot = await appServerCall({ socketPath: socket, threadId: thread, readOnly: true, timeoutMs: 10_000 })
  if (snapshot?.id !== thread || snapshot.status?.type !== 'active' || started !== 0 || steered !== 0) throw new Error('read-only probe mutated the active thread')
  reads = 0
  const result = await appServerCall({ socketPath: socket, threadId: thread, input: 'wake', clientUserMessageId: 'nvoy:test',
    dedupeToken: 'NVOY_ENVELOPE_ID=' + 'a'.repeat(64), waitForCompletion: true, steerActive: true, timeoutMs: 10_000 })
  if (result.turnId !== turn || result.finalText !== 'Steered wake acknowledged.' || steered !== 1 || started !== 0) throw new Error('active response was not steered into the exact turn')
  let liveRefused = false, recoveryRefused = false
  try {
    await appServerCall({ socketPath: socket, threadId: thread, input: 'wake again', clientUserMessageId: 'nvoy:test-2',
      dedupeToken: 'NVOY_ENVELOPE_ID=' + 'b'.repeat(64), waitForCompletion: true, timeoutMs: 10_000 })
  } catch (error) { liveRefused = /without a final assistant message/.test(error.message) }
  try {
    await appServerCall({ socketPath: socket, threadId: thread, input: 'recover', clientUserMessageId: 'nvoy:test-3',
      dedupeToken: 'NVOY_ENVELOPE_ID=' + 'c'.repeat(64), waitForCompletion: true, timeoutMs: 10_000 })
  } catch (error) { recoveryRefused = /not complete with a final assistant message/.test(error.message) }
  if (!liveRefused || !recoveryRefused) throw new Error('phased commentary became a live or recovered reply')
  console.log('codex-app-server-completion: active turn steered; commentary ignored and exact final item captured')
} finally {
  await new Promise(resolve => server.close(resolve))
  rmSync(root, { recursive: true, force: true })
}
