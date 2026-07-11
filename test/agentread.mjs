// agentread.mjs — drive the BUILT Nvoy MCP server as a given agent and read
// one scope, exactly as an MCP client would. The console E2E's verification
// half: delegate in the browser, then prove the agent's server actually
// serves (or correctly refuses) the scope.
//
//   node test/agentread.mjs <agent-nsec|hex> <author-npub|hex> <scope-d> [relay,relay…]
//
// Prints JSON: { grants: [...], read: {...} } — `read` is the scope_read
// result (data on success, or the well-shaped error body e.g.
// NVOY_GRANT_REVOKED). Exit 0 either way; exit 1 on transport failure.

import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'

const [nsec, author, d, relays] = process.argv.slice(2)
if (!nsec || !author || !d) {
  console.error('usage: node test/agentread.mjs <agent-nsec|hex> <author-npub|hex> <scope-d> [relay,relay…]')
  process.exit(1)
}

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
const client = new Client({ name: 'nvoy-agentread', version: '0.1.0' })
const textJson = (r) => JSON.parse(r.content.find(c => c.type === 'text').text)

try {
  await client.connect(transport)
  const grants = textJson(await client.callTool({ name: 'nvoy_grants_list' }))
  const read = textJson(await client.callTool({
    name: 'nvoy_scope_read', arguments: { d, author_npub: author, max_age: 0 },
  }))
  console.log(JSON.stringify({ grants: grants.grants, read }, null, 2))
} catch (err) {
  console.error(`transport failure: ${err.message}`)
  process.exit(1)
} finally {
  await client.close().catch(() => {})
}
process.exit(0)
