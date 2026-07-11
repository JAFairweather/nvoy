// agenttool.mjs — drive ONE tool on the built Nvoy MCP server as a given
// agent, exactly as an MCP client would. The generic sibling of
// agentread.mjs, used by the browser E2E to play the agent side of
// request_access / outbox_write / grant_relinquish flows.
//
//   node test/agenttool.mjs <agent-nsec|hex> <tool> '<json-args>' [relay,relay…]
//
// e.g. node test/agenttool.mjs nsec1… nvoy_request_access \
//        '{"delegator_npub":"npub1…","purpose":"Plan travel"}' ws://127.0.0.1:4460
//
// Prints the tool result JSON (or the well-shaped error body). Exit 0 either
// way; exit 1 on transport/usage failure.

import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'

const [nsec, tool, argsJson, relays] = process.argv.slice(2)
if (!nsec || !tool) {
  console.error("usage: node test/agenttool.mjs <agent-nsec|hex> <tool> '<json-args>' [relay,relay…]")
  process.exit(1)
}
let args = {}
try { args = argsJson ? JSON.parse(argsJson) : {} }
catch (err) { console.error(`bad json-args: ${err.message}`); process.exit(1) }

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(root, 'mcp', 'dist', 'server.js')],
  env: {
    ...process.env,
    NVOY_NSEC: nsec,
    ...(relays ? { NVOY_RELAYS: relays } : {}),
  },
  stderr: 'pipe',
})
const client = new Client({ name: 'nvoy-agenttool', version: '0.1.0' })

try {
  await client.connect(transport)
  const result = await client.callTool({ name: tool, arguments: args })
  const text = result.content?.find(c => c.type === 'text')?.text
  console.log(text ?? JSON.stringify(result))
} catch (err) {
  console.error(`transport failure: ${err.message}`)
  process.exit(1)
} finally {
  await client.close().catch(() => {})
}
process.exit(0)
