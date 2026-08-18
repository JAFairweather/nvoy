import net from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { appServerCall } from '../mcp/tools/codex_app_server.mjs'

// WHY THIS FIXTURE EXISTS.
//
// When the shared app-server daemon already owns an idle loaded thread, `thread/resume` answers
// with an error rather than a result, and the adapter falls through to `turn/start` instead of
// failing the delivery (codex_app_server.mjs:236). That fallthrough is matched on the app-server's
// own error TEXT, so it is coupled to a string this repo does not own: reword it upstream and the
// wedge returns silently with every suite still green. This drives the exact response.
//
// It pins the coupling in BOTH directions on purpose. Widening the matcher to swallow every resume
// error would turn a fatal control-plane failure into a silent second turn, so the unrelated-error
// case below is as load-bearing as the active-writer case.

const root = mkdtempSync(join(tmpdir(), 'nvoy-codex-active-writer-'))
const socket = join(root, 'control.sock')
const thread = '019fce57-063d-7f50-b837-967d33ee384a', turn = '019fd300-0000-7000-8000-000000000001'
const TEST_TIMEOUT_MS = 60_000

// The live active-writer text, verbatim from the daemon-owned idle thread this fixture models.
const ACTIVE_WRITER = `thread \`${thread}\` already has an active writer`
let resumeError = ACTIVE_WRITER
let resumes = 0, started = 0

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
    const mask = buffer.subarray(offset, offset + maskBytes)
    const body = Buffer.from(buffer.subarray(offset + maskBytes, offset + maskBytes + length))
    if (maskBytes) for (let i = 0; i < body.length; i++) body[i] ^= mask[i % 4]
    out.push(JSON.parse(String(body))); buffer = buffer.subarray(offset + maskBytes + length)
  }
  return { out, rest: buffer }
}

const server = net.createServer(stream => {
  let upgraded = false, buffer = Buffer.alloc(0)
  stream.on('error', () => {})
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
      // Idle: the thread is loaded and owned by the daemon, with no turn of its own running. This
      // is the state that sends the adapter down the resume path rather than the steer path.
      if (request.method === 'thread/read')
        stream.write(frame({ id: request.id, result: { thread: { id: thread, status: { type: 'idle' }, turns: [] } } }))
      if (request.method === 'thread/resume') {
        resumes++
        stream.write(frame({ id: request.id, error: { message: resumeError } }))
      }
      if (request.method === 'turn/start') {
        started++
        stream.write(frame({ id: request.id, result: { turn: { id: turn } } }))
        stream.write(frame({ method: 'item/completed', params: { threadId: thread, turnId: turn,
          item: { id: 'final', type: 'agentMessage', phase: 'final_answer', text: 'Daemon-owned answer.' } } }))
      }
    }
  })
})

try {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socket, resolve) })

  // 1. The active-writer refusal must fall through to turn/start and deliver a real answer.
  const result = await appServerCall({ socketPath: socket, threadId: thread, input: 'wake',
    clientUserMessageId: 'nvoy:active-writer', dedupeToken: 'NVOY_ENVELOPE_ID=' + 'a'.repeat(64),
    waitForCompletion: true, timeoutMs: TEST_TIMEOUT_MS })
  if (resumes !== 1)
    throw new Error(`the daemon-owned thread was not resumed exactly once (${resumes})`)
  if (started !== 1)
    throw new Error('the active-writer refusal did not fall through to turn/start')
  if (result.finalText !== 'Daemon-owned answer.' || result.turnId !== turn)
    throw new Error('the fallthrough turn did not return its exact final answer')

  // 2. An unrelated resume error must stay fatal. Without this, widening the matcher to swallow
  //    every resume failure would read as a pass while silently starting a second turn.
  resumes = 0; started = 0
  resumeError = 'thread is not loaded'
  let refused = ''
  try {
    await appServerCall({ socketPath: socket, threadId: thread, input: 'wake again',
      clientUserMessageId: 'nvoy:unrelated', dedupeToken: 'NVOY_ENVELOPE_ID=' + 'b'.repeat(64),
      waitForCompletion: true, timeoutMs: TEST_TIMEOUT_MS })
  } catch (error) { refused = error.message }
  if (!/Codex thread\/resume failed: thread is not loaded/.test(refused))
    throw new Error(`an unrelated resume error was not fatal (${refused || 'call succeeded'})`)
  if (started !== 0)
    throw new Error('an unrelated resume error still started a turn')

  console.log('codex-app-server-active-writer: daemon-owned resume falls through to turn/start, unrelated resume errors stay fatal')
} finally {
  await new Promise(resolve => server.close(resolve))
  rmSync(root, { recursive: true, force: true })
}
