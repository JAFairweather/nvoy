// A stand-in channel MCP for test/channel-https-door.mjs: reports its own argv, echoes, and emits a
// notification on request, so the test can see exactly what the door spawned and relayed. With
// `--lock <path>` it refuses to start while another live process holds the lock, as the real
// channel does.
import { readFileSync, writeFileSync } from 'node:fs'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'

const lockAt = process.argv.indexOf('--lock')
if (lockAt > 0) {
  const lock = process.argv[lockAt + 1]
  let prior = 0
  try { prior = Number(readFileSync(lock, 'utf8')) } catch {}
  if (prior) try { process.kill(prior, 0); console.error(`channel already runs as pid ${prior}`); process.exit(1) } catch {}
  writeFileSync(lock, String(process.pid))
}

const server = new Server({ name: 'door-fake-channel', version: '0.0.0' }, { capabilities: { tools: {}, logging: {} } })
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [
  { name: 'argv', description: 'argv', inputSchema: { type: 'object', properties: {} } },
  { name: 'echo', description: 'echo', inputSchema: { type: 'object', properties: { text: { type: 'string' } } } },
  { name: 'notify', description: 'notify', inputSchema: { type: 'object', properties: {} } },
] }))
server.setRequestHandler(CallToolRequestSchema, async ({ params }) => {
  if (params.name === 'argv') return { content: [{ type: 'text', text: JSON.stringify({ argv: process.argv.slice(2), pid: process.pid }) }] }
  if (params.name === 'echo') return { content: [{ type: 'text', text: String(params.arguments?.text ?? '') }] }
  if (params.name === 'notify') {
    setTimeout(() => server.notification({ method: 'notifications/message', params: { level: 'info', data: 'door-announce' } }).catch(() => {}), 50)
    return { content: [{ type: 'text', text: 'queued' }] }
  }
  throw new Error(`unknown tool ${params.name}`)
})
await server.connect(new StdioServerTransport())
