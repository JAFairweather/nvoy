// nopersist.mjs — no_persist conformance (spec §5, §8): spawn the REAL
// server binary with test/fsintercept.mjs preloaded (patches every fs write
// API before app modules link), run a full serve cycle with a canary string
// in the scope plaintext, and prove:
//
//   1. zero fs writes carried the plaintext (interceptor silent),
//   2. the log channel (stderr) never carried it,
//   3. cache + keys were zeroized on shutdown (SIGTERM path).
//
// Channel honesty: stdout is the MCP protocol channel — the plaintext
// legitimately crosses it inside tool results (serving the model context is
// the point of the grant). The no_persist contract is about DISK and LOGS;
// the server's design invariant "stdout carries only MCP frames" is enforced
// by the SDK client parsing every frame during this very cycle.

import { fileURLToPath, pathToFileURL } from 'node:url'
import { dirname, join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { newScopeKey, publishScope } from '../lib/nipxx.mjs'
import { LocalRelay } from '../lib/liverelay.mjs'
import { grantWithTerms, opaqueScopeId } from './nvoygrant.mjs'
import { startWsRelay } from './wsrelay.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

let n = 0, failed = 0
const check = (name, cond) => {
  n++
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${String(n).padStart(2)}. ${name}`)
  if (!cond) failed = 1
}
const textJson = (result) => JSON.parse(result.content.find(c => c.type === 'text').text)

// ------------------------------------------------ seed a delegation offline

const MARKER = 'NVOY-NO-PERSIST-CANARY-93f1c2'
const ws = await startWsRelay()
const seedRelay = new LocalRelay(ws.store)

const delegatorSk = generateSecretKey()
const delegatorNpub = nip19.npubEncode(getPublicKey(delegatorSk))
const agentSk = generateSecretKey()

const scopeId = opaqueScopeId()
const scopeKey = newScopeKey()
const payload = { name: 'no-persist probe', fields: { secret_note: MARKER } }
await publishScope(seedRelay, delegatorSk, { scopeId, generation: 1, scopeKey, payload })
await grantWithTerms(seedRelay, delegatorSk, getPublicKey(agentSk), {
  scopeId, generation: 1, scopeKey, scopeName: 'no-persist-probe', relayHint: ws.url,
  terms: { purpose: 'conformance probe', no_persist: true },
})

// ------------------------- spawn the real binary with the write interceptor

const preload = pathToFileURL(join(root, 'test', 'fsintercept.mjs')).href
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(root, 'mcp', 'dist', 'server.js')],
  env: {
    ...process.env,
    NVOY_NSEC: nip19.nsecEncode(agentSk),
    NVOY_RELAYS: ws.url,
    NODE_OPTIONS: `--import ${preload}`,
    NVOY_TEST_MARKER: MARKER,
    NVOY_TEST_SELFCHECK: '1',
  },
  stderr: 'pipe',
})
const client = new Client({ name: 'nvoy-nopersist', version: '0.1.0' })

let stderr = ''
try {
  await client.connect(transport)
  transport.stderr?.on('data', (chunk) => { stderr += chunk })

  // ------------------------------------------------------ full serve cycle
  const list = textJson(await client.callTool({ name: 'nvoy_grants_list' }))
  check('grant held with no_persist term', list.grants?.[0]?.terms?.no_persist === true)

  const read = textJson(await client.callTool({
    name: 'nvoy_scope_read', arguments: { d: scopeId, author_npub: delegatorNpub },
  }))
  check('plaintext (with canary) served to the MCP client', read.data?.fields?.secret_note === MARKER)
  check('result attests nvoy_no_persist: true', read.nvoy_no_persist === true)

  // cached read + forced-fresh read + resource read — every plaintext path
  await client.callTool({ name: 'nvoy_scope_read', arguments: { d: scopeId, author_npub: delegatorNpub } })
  await client.callTool({ name: 'nvoy_scope_read', arguments: { d: scopeId, author_npub: delegatorNpub, max_age: 0 } })
  const rc = await client.readResource({ uri: `nvoy://${delegatorNpub}/${scopeId}` })
  check('resource path served the plaintext too', rc.contents[0].text.includes(MARKER))
} finally {
  await client.close().catch(() => {}) // SIGTERM → teardown → zeroize
}
await new Promise(r => setTimeout(r, 600)) // let the dying child's stderr drain
await ws.close()

// ------------------------------------------------------------- the verdict

check('fs interceptor was armed before app modules linked', stderr.includes('[fsintercept] armed'))
check('interception demonstrably live (selfcheck caught its own canary write)', stderr.includes('[fsintercept] selfcheck ok'))
check('ZERO fs writes contained scope plaintext', !stderr.includes('[fsintercept] VIOLATION'))
check('stderr log channel never contained the plaintext', !stderr.includes(MARKER))
check('cache + keys zeroized on shutdown (SIGTERM handler ran)', stderr.includes('cache zeroized (shutdown)'))

console.log(failed ? '\nNO-PERSIST CONFORMANCE: FAIL' : `\nNO-PERSIST CONFORMANCE: ALL ${n} PASS`)
process.exit(failed)
