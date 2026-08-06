import net from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { appServerCall } from '../mcp/tools/codex_app_server.mjs'

const root = mkdtempSync(join(tmpdir(), 'nvoy-codex-bootstrap-'))
const socket = join(root, 'control.sock'), thread = '019fd900-0000-7000-8000-000000000001'
const seen = []
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
    const masked = Boolean(buffer[1] & 0x80), maskBytes = masked ? 4 : 0
    if (buffer.length < offset + maskBytes + length) break
    const mask = buffer.subarray(offset, offset + maskBytes), body = Buffer.from(buffer.subarray(offset + maskBytes, offset + maskBytes + length))
    if (masked) for (let i = 0; i < body.length; i++) body[i] ^= mask[i % 4]
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
      seen.push(request)
      if (request.id === 1) stream.write(frame({ id: 1, result: {} }))
      if (request.id === 2) stream.write(frame({ id: 2, result: { data: [] } }))
      if (request.id === 3) stream.write(frame({ id: 3, result: { thread: { id: thread } } }))
      if (request.id === 4) stream.write(frame({ id: 4, result: {} }))
      if (request.id === 5) stream.write(frame({ id: 5, result: { thread: { id: thread, name: 'Codex - Nostr participant', cwd: resolve('.') } } }))
    }
  })
})

try {
  await new Promise((resolveListen, reject) => { server.once('error', reject); server.listen(socket, resolveListen) })
  const output = await appServerCall({ socketPath: socket, bootstrap: { name: 'Codex - Nostr participant', cwd: resolve('.'), model: 'test-model' }, timeoutMs: 10_000 })
  if (!output.created || output.thread_id !== thread) throw new Error('new participant task was not returned')
  if (!seen.some(x => x.method === 'thread/list' && x.params.searchTerm === 'Codex - Nostr participant' && x.params.cwd === resolve('.') && x.params.sourceKinds?.[0] === 'appServer')) throw new Error('existing selection was not operator-name/cwd constrained')
  if (!seen.some(x => x.method === 'thread/start' && x.params.cwd === resolve('.') && x.params.model === 'test-model' && x.params.serviceName === 'nvoy_nostr_participant')) throw new Error('participant task was not created with fixed local inputs')
  if (!seen.some(x => x.method === 'thread/name/set' && x.params.threadId === thread && x.params.name === 'Codex - Nostr participant')) throw new Error('participant task was not named exactly')
  const bad = spawnSync(process.execPath, ['mcp/tools/codex-session-bootstrap.mjs', '--name', 'bad\nname', '--cwd', resolve('.'), '--socket', socket], { cwd: resolve('.'), encoding: 'utf8' })
  if (bad.status === 0 || !/printable/.test(bad.stderr)) throw new Error('control characters in task names were accepted')
  console.log('codex-session-bootstrap: operator-only exact task creation passed')
} finally {
  await new Promise(resolveClose => server.close(resolveClose))
  rmSync(root, { recursive: true, force: true })
}
