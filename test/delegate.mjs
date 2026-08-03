// delegate.mjs — the M1 delegator script (console arrives in M3).
//
// Generates a delegator key (or uses DELEGATOR_NSEC), publishes a sample
// travel-preferences scope, grants it to the given agent npub WITH an nvoy
// terms object, saves the Grant Index, and prints everything needed to run
// the Nvoy MCP server against it.
//
// Usage:
//   node test/delegate.mjs <agent-npub> [expires-in-seconds]
//   DELEGATOR_NSEC=nsec1... node test/delegate.mjs <agent-npub>
//   NVOY_RELAYS=wss://... node test/delegate.mjs <agent-npub>

import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { newScopeKey, publishScope, loadGrantIndex, saveGrantIndex, toIssuedEntry } from '../lib/nipxx.mjs'
import { LiveRelay } from '../lib/liverelay.mjs'
import { grantWithTerms, opaqueScopeId, TRAVEL_PREFERENCES } from './nvoygrant.mjs'

const DEFAULT_RELAYS = ['wss://nos.lol', 'wss://relay.primal.net']

const agentArg = process.argv[2]
if (!agentArg) {
  console.error('usage: node test/delegate.mjs <agent-npub> [expires-in-seconds]')
  console.error('       (get the npub from the server boot line: node mcp/dist/server.js --ephemeral)')
  process.exit(1)
}
const agentPub = agentArg.startsWith('npub1') ? nip19.decode(agentArg).data : agentArg
const expiresIn = Number(process.argv[3] ?? 7 * 24 * 3600) // default 7 days

const relays = (process.env.NVOY_RELAYS?.split(',').map(s => s.trim()).filter(Boolean)) ?? DEFAULT_RELAYS
const relay = new LiveRelay(relays)

const generated = !process.env.DELEGATOR_NSEC
const delegatorSk = generated
  ? generateSecretKey()
  : nip19.decode(process.env.DELEGATOR_NSEC.trim()).data
const delegatorPub = getPublicKey(delegatorSk)
const delegatorNpub = nip19.npubEncode(delegatorPub)

const scopeId = opaqueScopeId()
const scopeKey = newScopeKey()
const scopeName = 'travel-preferences'
const terms = {
  purpose: 'Plan travel within stated preferences',
  expires_at: Math.floor(Date.now() / 1000) + expiresIn,
  no_persist: true,
  redelegate: false,
  reply_scope_requested: false,
  contact: delegatorNpub,
  auto_relinquish: false, // standing delegation; task-scoped grants should set true (§6.6)
}

console.error(`delegator ${delegatorNpub}${generated ? ' (generated)' : ''}`)
console.error(`relays    ${relays.join(', ')}`)
console.error(`agent     ${nip19.npubEncode(agentPub)}`)
console.error(`scope     d=${scopeId} (opaque), name=${scopeName}`)

console.error('\npublishing scope (kind 30440)…')
const pub = await publishScope(relay, delegatorSk, { scopeId, generation: 1, scopeKey, payload: TRAVEL_PREFERENCES })
console.error(`  acks ${pub.acks}/${pub.of}`)

console.error('issuing grant with nvoy terms (kind 440 in a 1059 gift wrap)…')
const g = await grantWithTerms(relay, delegatorSk, agentPub, {
  scopeId, generation: 1, scopeKey, scopeName, relayHint: relays[0], terms,
})
console.error(`  acks ${g.acks}/${g.of}`)

console.error('saving Grant Index (kind 10440, NIP-44 to self)…')
const index = await loadGrantIndex(relay, delegatorSk)
index.issued = index.issued.filter(e => e.scope !== scopeId)
index.issued.push(toIssuedEntry({ scopeId, scopeName, generation: 1, scopeKey }, [agentPub]))
const idx = await saveGrantIndex(relay, delegatorSk, index)
console.error(`  acks ${idx.acks}/${idx.of}`)

console.error(`
────────────────────────────────────────────────────────────────────────
Delegation complete. The agent now holds a grant for scope '${scopeId}'.

Run the Nvoy MCP server as that agent:

  NVOY_NSEC=<the agent's nsec> \\
  NVOY_RELAYS=${relays.join(',')} \\
  node mcp/dist/server.js

Then, from any MCP client:
  nvoy_grants_list                          → shows the grant, purpose, terms
  nvoy_scope_read { "d": "${scopeId}",
    "author_npub": "${delegatorNpub}" }     → the travel preferences JSON
${generated ? `
Delegator key (generated — keep only if you want to update/revoke later):
  DELEGATOR_NSEC=${nip19.nsecEncode(delegatorSk)}
` : ''}────────────────────────────────────────────────────────────────────────`)

relay.close()
process.exit(0)
