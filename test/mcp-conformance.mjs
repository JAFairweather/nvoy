// mcp-conformance.mjs — spawn the BUILT Nvoy server over stdio and drive it
// with the official MCP SDK client, exactly as Claude Desktop would:
//
//   local ws relay ← seeded delegation ← this test
//   node mcp/dist/server.js (NVOY_NSEC, NVOY_RELAYS=ws://127.0.0.1:…)
//   SDK Client → listTools / 3 tool calls / listResources / readResource
//
// Asserts tool output shapes per spec §6.2. Fully offline.

import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { newScopeKey, publishScope, rotateScope } from '../lib/nipxx.mjs'
import { LocalRelay } from '../lib/liverelay.mjs'
import { grantWithTerms, sendRevocationNotice, opaqueScopeId, TRAVEL_PREFERENCES } from './nvoygrant.mjs'
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

const ws = await startWsRelay()
const seedRelay = new LocalRelay(ws.store) // write straight into the store

const delegatorSk = generateSecretKey()
const delegatorNpub = nip19.npubEncode(getPublicKey(delegatorSk))
const agentSk = generateSecretKey()
const agentNpub = nip19.npubEncode(getPublicKey(agentSk))

const scopeId = opaqueScopeId()
const scopeKey = newScopeKey()
const purpose = 'Plan travel within stated preferences'
await publishScope(seedRelay, delegatorSk, { scopeId, generation: 1, scopeKey, payload: TRAVEL_PREFERENCES })
await grantWithTerms(seedRelay, delegatorSk, getPublicKey(agentSk), {
  scopeId, generation: 1, scopeKey, scopeName: 'travel-preferences', relayHint: ws.url,
  terms: { purpose, expires_at: Math.floor(Date.now() / 1000) + 3600, no_persist: true, redelegate: false, contact: delegatorNpub },
})

// a second, already-expired grant (soft expiry per §4 — the runtime honors it)
const expiredScopeId = opaqueScopeId()
const expiredKey = newScopeKey()
await publishScope(seedRelay, delegatorSk, { scopeId: expiredScopeId, generation: 1, scopeKey: expiredKey, payload: { name: 'lapsed', fields: {} } })
await grantWithTerms(seedRelay, delegatorSk, getPublicKey(agentSk), {
  scopeId: expiredScopeId, generation: 1, scopeKey: expiredKey, scopeName: 'lapsed-demo', relayHint: ws.url,
  terms: { purpose: 'already lapsed', expires_at: Math.floor(Date.now() / 1000) - 3600 },
})

// --------------------------------------------- spawn the real server binary

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(root, 'mcp', 'dist', 'server.js')],
  env: { ...process.env, NVOY_NSEC: nip19.nsecEncode(agentSk), NVOY_RELAYS: ws.url },
  stderr: 'pipe',
})
const client = new Client({ name: 'nvoy-conformance', version: '0.1.0' })

try {
  await client.connect(transport)

  // ------------------------------------------------------------- tool list
  const tools = (await client.listTools()).tools.map(t => t.name)
  check('server exposes exactly the read-path tools',
    ['nvoy_whoami', 'nvoy_grants_list', 'nvoy_scope_read'].every(t => tools.includes(t)) && tools.length === 3)

  // ---------------------------------------------------------------- whoami
  const who = textJson(await client.callTool({ name: 'nvoy_whoami' }))
  check('nvoy_whoami: npub matches the injected identity', who.npub === agentNpub)
  check('nvoy_whoami: relay set reported', Array.isArray(who.relays) && who.relays[0] === ws.url)
  check('nvoy_whoami: pubkey is hex, metadata null when unpublished',
    /^[0-9a-f]{64}$/.test(who.pubkey) && who.metadata === null)

  // ----------------------------------------------------------- grants_list
  const list = textJson(await client.callTool({ name: 'nvoy_grants_list' }))
  check('nvoy_grants_list: both held grants', list.grants?.length === 2)
  const lg = list.grants?.find(g => g.d === scopeId) ?? {}
  check('grants_list shape: { d, author_npub, purpose, expires_at, terms, v, status }',
    lg.d === scopeId && lg.author_npub === delegatorNpub && lg.purpose === purpose
    && typeof lg.expires_at === 'number' && lg.terms?.no_persist === true && lg.v === 1)
  check('grants_list status: active', lg.status === 'active')
  check('grants_list status: expired grant flagged (soft expiry honored)',
    list.grants?.find(g => g.d === expiredScopeId)?.status === 'expired')

  // ------------------------------------------------------------ scope_read
  const read = textJson(await client.callTool({
    name: 'nvoy_scope_read',
    arguments: { d: scopeId, author_npub: delegatorNpub },
  }))
  check('nvoy_scope_read: decrypted payload served', read.data?.fields?.seat === 'aisle')
  check('nvoy_scope_read: metadata { v, fetched_at, terms }',
    read.v === 1 && typeof read.fetched_at === 'number' && read.terms?.purpose === purpose)
  check('nvoy_scope_read: no_persist attested in output metadata (nvoy_no_persist: true)',
    read.nvoy_no_persist === true)

  // expired grant → clean soft-expiry error
  const exp = await client.callTool({ name: 'nvoy_scope_read', arguments: { d: expiredScopeId, author_npub: delegatorNpub } })
  const expBody = textJson(exp)
  check('nvoy_scope_read: expired grant is a clean NVOY_GRANT_EXPIRED error',
    exp.isError === true && expBody.code === 'NVOY_GRANT_EXPIRED' && typeof expBody.expires_at === 'number')

  // hex author accepted too
  const readHex = textJson(await client.callTool({
    name: 'nvoy_scope_read',
    arguments: { d: scopeId, author_npub: getPublicKey(delegatorSk), max_age: 0 },
  }))
  check('nvoy_scope_read: hex author + max_age:0 accepted', readHex.data?.fields?.home_airport === 'YYZ')

  // unknown scope → well-shaped error
  const bad = await client.callTool({ name: 'nvoy_scope_read', arguments: { d: 'nope', author_npub: delegatorNpub } })
  check('nvoy_scope_read: unknown scope is a clean NVOY_NO_GRANT error',
    bad.isError === true && textJson(bad).code === 'NVOY_NO_GRANT')

  // -------------------------------------------------------------- resources
  const res = await client.listResources()
  const r = res.resources?.find(x => x.uri === `nvoy://${delegatorNpub}/${scopeId}`)
  check('resources list: nvoy://{author_npub}/{d} for the active grant', !!r && r.mimeType === 'application/json')
  check('resource name/description from scope_name/purpose', r?.name === 'travel-preferences' && r?.description === purpose)
  check('resources list: expired grant excluded (active only)', res.resources?.length === 1)

  const rc = await client.readResource({ uri: `nvoy://${delegatorNpub}/${scopeId}` })
  const body = JSON.parse(rc.contents[0].text)
  check('resource read: live-dereferenced scope JSON', body.data?.fields?.seat === 'aisle' && body.v === 1)
  check('resource read: no_persist attested', body.nvoy_no_persist === true)

  // ------------------------------------------- revocation, mid-conversation
  // The delegator rotates the key past the agent (survivors = []) and sends
  // the optional kind-441 notice — exactly the 90-second demo's beat (§9).
  const reason = 'delegation ended: itinerary confirmed'
  await rotateScope(seedRelay, delegatorSk, {
    scopeId, generation: 1, payload: TRAVEL_PREFERENCES, scopeName: 'travel-preferences', survivors: [],
  })
  await sendRevocationNotice(seedRelay, delegatorSk, getPublicKey(agentSk), { scopeId, reason })

  const revoked = await client.callTool({
    name: 'nvoy_scope_read',
    arguments: { d: scopeId, author_npub: delegatorNpub, max_age: 0 },
  })
  const rBody = textJson(revoked)
  check('scope_read after rotation: well-shaped NVOY_GRANT_REVOKED error',
    revoked.isError === true && rBody.code === 'NVOY_GRANT_REVOKED' && rBody.d === scopeId && rBody.author_npub === delegatorNpub)
  check('441 notice surfaced in the error', rBody.notice?.reason === reason)

  const list2 = textJson(await client.callTool({ name: 'nvoy_grants_list' }))
  const lg2 = list2.grants?.find(g => g.d === scopeId)
  check('grants_list after detection: status revoked-detected + notice',
    lg2?.status === 'revoked-detected' && lg2?.revocation?.notice?.reason === reason)

  const repeat = textJson(await client.callTool({
    name: 'nvoy_scope_read', arguments: { d: scopeId, author_npub: delegatorNpub },
  }))
  check('repeat read short-circuits on the recorded revocation', repeat.code === 'NVOY_GRANT_REVOKED')

  const res2 = await client.listResources()
  check('resources list after revocation: nothing active remains', (res2.resources?.length ?? 0) === 0)

  // -------------------------------------- adversarial observer, real relay
  const view = ws.store.observerView()
  const kinds = new Set(view.map(e => e.kind))
  check('observer: relay saw only 30440 + 1059 (no grant kind, no naked 441)',
    !kinds.has(440) && !kinds.has(441) && [...kinds].every(k => [30440, 1059].includes(k)))
  check('observer: no delegation metadata or revocation reason in stored content',
    !JSON.stringify(view).includes('aisle') && !JSON.stringify(view).includes(purpose)
    && !JSON.stringify(ws.store.events).includes(reason))
} finally {
  await client.close().catch(() => {})
  await ws.close()
}

console.log(failed ? '\nMCP CONFORMANCE: FAIL' : `\nMCP CONFORMANCE: ALL ${n} PASS`)
process.exit(failed)
