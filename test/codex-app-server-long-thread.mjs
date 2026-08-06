import net from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { appServerCall } from '../mcp/tools/codex_app_server.mjs'

const root = mkdtempSync(join(tmpdir(), 'nvoy-codex-long-thread-'))
const socket = join(root, 'control.sock')
const largeHistory = 'x'.repeat(12 * 1024 * 1024)
let serverError = null

function frame(value) {
  const body = Buffer.from(JSON.stringify(value))
  const head = Buffer.alloc(10)
  head[0] = 0x81
  head[1] = 127
  head.writeBigUInt64BE(BigInt(body.length), 2)
  return Buffer.concat([head, body])
}

function requests(buffer) {
  const out = []
  while (buffer.length >= 2) {
    const initial = buffer[1] & 0x7f
    let offset = 2, length = initial
    if (initial === 126) { if (buffer.length < 4) break; length = buffer.readUInt16BE(2); offset = 4 }
    if (initial === 127) { if (buffer.length < 10) break; length = Number(buffer.readBigUInt64BE(2)); offset = 10 }
    const masked = Boolean(buffer[1] & 0x80), maskBytes = masked ? 4 : 0
    if (buffer.length < offset + maskBytes + length) break
    const mask = buffer.subarray(offset, offset + maskBytes)
    const body = Buffer.from(buffer.subarray(offset + maskBytes, offset + maskBytes + length))
    if (masked) for (let i = 0; i < body.length; i++) body[i] ^= mask[i % 4]
    out.push(JSON.parse(String(body)))
    buffer = buffer.subarray(offset + maskBytes + length)
  }
  return { out, rest: buffer }
}

const server = net.createServer(stream => {
  let upgraded = false, buffer = Buffer.alloc(0)
  // appServerCall intentionally destroys its local socket after the complete frame is parsed.
  // A queued tail write may then report EPIPE to this fake peer even though the client received
  // and verified the whole 12 MiB response. Preserve every other transport error.
  stream.on('error', error => { if (error.code !== 'EPIPE') serverError = error })
  stream.on('data', chunk => {
    buffer = Buffer.concat([buffer, chunk])
    if (!upgraded) {
      const end = buffer.indexOf('\r\n\r\n')
      if (end < 0) return
      buffer = buffer.subarray(end + 4)
      upgraded = true
      stream.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    }
    const parsed = requests(buffer); buffer = parsed.rest
    for (const request of parsed.out) {
      if (request.method === 'initialize') stream.write(frame({ id: request.id, result: {} }))
      if (request.method === 'thread/list') stream.write(frame({ id: request.id, result: { data: [{ id: 'thread', history: largeHistory }] } }))
    }
  })
})

try {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socket, resolve) })
  const rows = await appServerCall({ socketPath: socket, listOnly: true, timeoutMs: 10_000 })
  if (rows?.[0]?.history?.length !== largeHistory.length) throw new Error('large app-server response was not preserved')
  if (serverError) throw serverError
  console.log('codex-app-server-long-thread: 12 MiB response accepted')
} finally {
  await new Promise(resolve => server.close(resolve))
  rmSync(root, { recursive: true, force: true })
}
