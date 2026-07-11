// demo.mjs — the 90-second demo (spec §9), scripted.
//
// A delegator grants a travel-preferences scope to an agent. The agent —
// the REAL Nvoy MCP server binary, driven by the official MCP SDK client
// exactly as Claude Desktop would drive it — plans a trip from the delegated
// data. Mid-conversation the delegator revokes: one key rotation. The
// agent's very next tool call returns NVOY_GRANT_REVOKED, cleanly, with the
// delegator's notice attached. No token to expire, no admin panel, no ACL —
// the data itself stopped being readable.
//
//   node examples/demo-trip-planner/demo.mjs          # offline, in-memory relay
//   node examples/demo-trip-planner/demo.mjs --live   # real public relays
//
// Throwaway keys, demo data only. Nobody in the OAuth world can show this.

import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { newScopeKey, publishScope, rotateScope } from '../../lib/nipxx.mjs'
import { LiveRelay, LocalRelay } from '../../lib/liverelay.mjs'
import { grantWithTerms, sendRevocationNotice, opaqueScopeId, TRAVEL_PREFERENCES } from '../../test/nvoygrant.mjs'
import { startWsRelay } from '../../test/wsrelay.mjs'

const LIVE = process.argv.includes('--live')
const PUBLIC_RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net']
const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..')

const say = (s = '') => console.log(s)
const act = (s) => console.log(`\n━━ ${s} ${'━'.repeat(Math.max(2, 68 - s.length))}`)
const settle = () => (LIVE ? new Promise(r => setTimeout(r, 1500)) : Promise.resolve())
const textJson = (r) => JSON.parse(r.content.find(c => c.type === 'text').text)

// ---------------------------------------------------------------- the stage

const ws = LIVE ? null : await startWsRelay()
const relayUrls = LIVE ? (process.env.NVOY_RELAYS?.split(',').map(s => s.trim()).filter(Boolean) ?? PUBLIC_RELAYS) : [ws.url]
const relay = LIVE ? new LiveRelay(relayUrls) : new LocalRelay(ws.store)

const delegatorSk = generateSecretKey()
const delegatorNpub = nip19.npubEncode(getPublicKey(delegatorSk))
const agentSk = generateSecretKey()
const agentNpub = nip19.npubEncode(getPublicKey(agentSk))

say('NVOY — scoped, revocable data delegation to agents, over nostr')
say(LIVE ? `relays: ${relayUrls.join(', ')}` : 'relay: in-memory (run with --live for real public relays)')
say(`delegator ${delegatorNpub.slice(0, 20)}…   agent ${agentNpub.slice(0, 20)}…`)

// ------------------------------------------------------------------- act 1

act('ACT 1 — The delegator curates and grants')
const scopeId = opaqueScopeId()
const scopeKey = newScopeKey()
const terms = {
  purpose: 'Plan the Lisbon trip within stated preferences',
  expires_at: Math.floor(Date.now() / 1000) + 24 * 3600,
  no_persist: true,
  redelegate: false,
  contact: delegatorNpub,
}
await publishScope(relay, delegatorSk, { scopeId, generation: 1, scopeKey, payload: TRAVEL_PREFERENCES })
await grantWithTerms(relay, delegatorSk, getPublicKey(agentSk), {
  scopeId, generation: 1, scopeKey, scopeName: 'travel-preferences', relayHint: relayUrls[0], terms,
})
await settle()
say(`published encrypted scope 30440 d=${scopeId} (opaque id — relays learn nothing)`)
say(`granted to the agent inside a gift wrap, with terms:`)
say(`  purpose: "${terms.purpose}"`)
say(`  no_persist: true, redelegate: false, expires in 24h`)

// ------------------------------------------------------------------- act 2

act('ACT 2 — The agent plans the trip (real MCP server, real SDK client)')
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(root, 'mcp', 'dist', 'server.js')],
  env: { ...process.env, NVOY_NSEC: nip19.nsecEncode(agentSk), NVOY_RELAYS: relayUrls.join(',') },
  stderr: LIVE ? 'inherit' : 'ignore',
})
const client = new Client({ name: 'trip-planner', version: '0.1.0' })
let exitCode = 0

try {
  await client.connect(transport)

  const grants = textJson(await client.callTool({ name: 'nvoy_grants_list' })).grants
  say(`nvoy_grants_list → ${grants.length} grant: "${grants[0].scope_name}" — ${grants[0].purpose} [${grants[0].status}]`)

  const read = textJson(await client.callTool({
    name: 'nvoy_scope_read', arguments: { d: scopeId, author_npub: delegatorNpub },
  }))
  const f = read.data.fields
  say(`nvoy_scope_read  → v${read.v}, no_persist attested: ${read.nvoy_no_persist === true}`)
  say('')
  say('  Agent: "Booking within your preferences —')
  say(`     ${f.seat} seat on ${f.airlines[0]}, out of ${f.home_airport},`)
  say(`     ${f.hotel_brands[0]} under $${f.budget_per_night_usd}/night, ${f.dietary} meals.`)
  say(`     ${f.note}"`)

  // ----------------------------------------------------------------- act 3

  act('ACT 3 — The delegator taps Revoke, mid-conversation')
  await rotateScope(relay, delegatorSk, {
    scopeId, generation: 1, payload: TRAVEL_PREFERENCES, scopeName: 'travel-preferences', survivors: [],
  })
  await sendRevocationNotice(relay, delegatorSk, getPublicKey(agentSk), {
    scopeId, reason: 'trip planned — delegation complete, thanks',
  })
  await settle()
  say('scope key rotated (v1 → v2), data republished under the new key,')
  say('re-granted to nobody. Plus a courtesy kind-441 notice, gift-wrapped.')
  say('That is the entire revocation. No server was asked for permission.')

  // ----------------------------------------------------------------- act 4

  act("ACT 4 — The agent's next tool call")
  const revoked = await client.callTool({
    name: 'nvoy_scope_read', arguments: { d: scopeId, author_npub: delegatorNpub, max_age: 0 },
  })
  const err = textJson(revoked)
  say(`nvoy_scope_read → isError: ${revoked.isError === true}`)
  say(`  code:   ${err.code}`)
  say(`  notice: "${err.notice?.reason ?? '(silent revocation)'}"`)
  say('')
  say('  Agent: "My access to your travel preferences was revoked by the')
  say(`     delegator ('${err.notice?.reason}'). I have destroyed my cached`)
  say('     copy and can no longer read updates."')

  const after = textJson(await client.callTool({ name: 'nvoy_grants_list' })).grants
  say(`\nnvoy_grants_list → status: ${after.find(g => g.d === scopeId)?.status}`)

  act('CURTAIN')
  say('Revocation enforced by cryptography, not policy: the next dereference')
  say('simply failed to decrypt. Scope key + cached plaintext zeroized in the')
  say('agent runtime. Try that with a bearer token.')

  if (![err.code === 'NVOY_GRANT_REVOKED', err.notice?.reason, after.find(g => g.d === scopeId)?.status === 'revoked-detected'].every(Boolean)) {
    exitCode = 1
    say('\nDEMO: FAIL (unexpected shapes above)')
  }
} finally {
  await client.close().catch(() => {})
  relay.close?.()
  await ws?.close()
}
process.exit(exitCode)
