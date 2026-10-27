// The reconnecting stdio proxy: a fake MCP server that exits on demand stands in for an ssh channel
// whose broker container a deploy recreated.
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'

let fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); if (!value) fails++ }
const dir = mkdtempSync(join(tmpdir(), 'nvoy-mcprc-'))
const starts = join(dir, 'starts.jsonl')
const server = join(dir, 'server.mjs')
writeFileSync(server, `
import { appendFileSync } from 'node:fs'
import { createInterface } from 'node:readline'
const pid = process.pid
createInterface({ input: process.stdin }).on('line', line => {
  const m = JSON.parse(line)
  appendFileSync(${JSON.stringify(starts)}, JSON.stringify({ pid, method: m.method, id: m.id ?? null, caps: m.params?.capabilities ?? null }) + '\\n')
  const reply = result => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result }) + '\\n')
  if (m.method === 'initialize') reply({ protocolVersion: m.params.protocolVersion, serverInfo: { name: 'fake', version: String(pid) }, capabilities: {} })
  else if (m.method === 'tools/list') reply({ tools: [{ name: 'echo', server: pid }] })
  else if (m.method === 'test/die') process.exit(3)
  else if (m.method === 'test/hang') {}
})
`)

const proxy = spawn(process.execPath, [resolve('mcp/tools/mcp-reconnect.mjs'), '--max-backoff-ms', '200', '--', process.execPath, server], { stdio: ['pipe', 'pipe', 'pipe'] })
let stderr = ''
proxy.stderr.on('data', d => { stderr += d })
const inbox = []
let waiter = null
createInterface({ input: proxy.stdout }).on('line', line => { inbox.push(JSON.parse(line)); if (waiter) waiter() })
const send = m => proxy.stdin.write(JSON.stringify({ jsonrpc: '2.0', ...m }) + '\n')
const next = id => new Promise((done, fail) => {
  const timer = setTimeout(() => fail(new Error(`no reply to ${id}`)), 5000)
  const look = () => { const i = inbox.findIndex(m => m.id === id); if (i >= 0) { clearTimeout(timer); waiter = null; done(inbox.splice(i, 1)[0]) } }
  waiter = look; look()
})
const pause = ms => new Promise(done => setTimeout(done, ms))
const log = () => readFileSync(starts, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l))

send({ id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: { experimental: { 'claude/channel': {} } }, clientInfo: { name: 't', version: '1' } } })
const init = await next(1)
send({ method: 'notifications/initialized' })
const first = (await (send({ id: 2, method: 'tools/list' }), next(2))).result.tools[0].server
ok('the first server answers initialize and tools/list', init.result?.serverInfo?.name === 'fake' && first > 0)

send({ id: 3, method: 'test/hang' })
await pause(100)
send({ id: 4, method: 'test/die' })
const lost = await next(3)
ok('a request in flight when the server dies gets an error, not silence', lost.error?.code === -32000)
await pause(600)
const second = (await (send({ id: 5, method: 'tools/list' }), next(5))).result?.tools?.[0]?.server
ok('after the server exits, a new one answers on the same client connection', second > 0 && second !== first)

const rows = log().filter(r => r.pid === second)
ok('the new server was given the original initialize, then initialized, before any other call',
  rows[0]?.method === 'initialize' && rows[1]?.method === 'notifications/initialized' && rows[2]?.method === 'tools/list')
ok('the replayed initialize carries the client\'s capabilities', !!rows[0]?.caps?.experimental?.['claude/channel'])
ok('the replayed initialize response never reaches the client', !inbox.some(m => String(m.id).startsWith('mcp-reconnect')) && inbox.every(m => m.id !== 1))
ok('the restart is logged on stderr', /restarting in/.test(stderr) && /reconnected/.test(stderr))

proxy.stdin.end()
const code = await new Promise(done => proxy.on('exit', done))
ok('closing the client stops the proxy and its server', code !== null)

process.exit(fails ? 1 : 0)
