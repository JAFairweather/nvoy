// m4accept.mjs — the spec §7 M4 acceptance, scripted end to end:
//
//   "Agent completes a task, relinquishes, ledger shows
//    granted → relinquished → rotated with the agent's subsequent
//    scope_read returning NVOY_GRANT_REVOKED."
//
// The delegator side runs the console's own modules (delegate → ledger →
// relinquish policy, exactly what the browser executes); the agent side is
// the REAL built MCP server driven by the official SDK client. Fully offline
// against the ws relay.
//
//   node test/m4accept.mjs

import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { localSigner, newScopeKey, publishScope, saveGrantIndex, loadGrantIndex, toIssuedEntry } from '../lib/nipxx.mjs'
import { LocalRelay } from '../lib/liverelay.mjs'
import { grantWithTerms, opaqueScopeId, receiveNotices, TEMPLATES } from '../console/nvoygrant.mjs'
import { appendLedger, grantedEvent, deriveDelegations, eventsFor } from '../console/ledgerlog.mjs'
import { relinquishPlan, runRelinquishRotation } from '../console/ttl.mjs'
import { startWsRelay } from './wsrelay.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

let n = 0, failed = 0
const check = (name, cond) => {
  n++
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${String(n).padStart(2)}. ${name}`)
  if (!cond) failed = 1
}
const textJson = (r) => JSON.parse(r.content.find(c => c.type === 'text').text)

const ws = await startWsRelay()
const relay = new LocalRelay(ws.store)

// ------------------------------------------- 1. the delegator delegates
// (console modules — same code path as the Delegations tab)

const delegatorSk = generateSecretKey()
const delegatorPub = getPublicKey(delegatorSk)
const signer = localSigner(delegatorSk)
const agentSk = generateSecretKey()
const agentPub = getPublicKey(agentSk)

const scopeId = opaqueScopeId()
const scopeKey = newScopeKey()
const terms = {
  purpose: 'Plan one trip, then hand the data back',
  no_persist: true, redelegate: false, reply_scope_requested: false,
  auto_relinquish: true, contact: nip19.npubEncode(delegatorPub),
}
await publishScope(relay, signer, { scopeId, generation: 1, scopeKey, payload: TEMPLATES['travel-prefs'].payload })
await grantWithTerms(relay, signer, agentPub, { scopeId, generation: 1, scopeKey, scopeName: 'travel-preferences', relayHint: ws.url, terms })
let index = { issued: [toIssuedEntry({ scopeId, scopeName: 'travel-preferences', generation: 1, scopeKey }, [agentPub])], received: [] }
index.nvoy_agents = [{ pub: agentPub, added_at: Math.floor(Date.now() / 1000) }]
index.nvoy_ledger = appendLedger(index, grantedEvent({ scope: scopeId, agent: agentPub, v: 1, terms: { nvoy: 1, ...terms }, name: 'travel-preferences' }))
await saveGrantIndex(relay, signer, index)

// --------------------------------- 2. the agent works, then relinquishes

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(root, 'mcp', 'dist', 'server.js')],
  env: { ...process.env, NVOY_NSEC: nip19.nsecEncode(agentSk), NVOY_RELAYS: ws.url },
  stderr: 'pipe',
})
const client = new Client({ name: 'nvoy-m4accept', version: '0.1.0' })

try {
  await client.connect(transport)

  const read = textJson(await client.callTool({
    name: 'nvoy_scope_read', arguments: { d: scopeId, author_npub: nip19.npubEncode(delegatorPub) },
  }))
  check('agent reads the delegated scope (task runs)', read.data?.fields?.seat === 'aisle' && read.nvoy_no_persist === true)

  const rel = textJson(await client.callTool({
    name: 'nvoy_grant_relinquish',
    arguments: { d: scopeId, author_npub: nip19.npubEncode(delegatorPub), reason: 'task complete' },
  }))
  check('agent relinquishes on completion: key + cache destroyed, notice sent',
    rel.relinquished === true && rel.notice_sent === true)

  // ------------------- 3. the delegator's console finalizes (decision 6)
  // Sole grantee → the console AUTO-rotates on its next load. Same modules.

  index = await loadGrantIndex(relay, signer)
  const notices = await receiveNotices(relay, signer)
  const plan = relinquishPlan(index, notices.relinquishes)
  check('console sees the relinquish notice; sole grantee → auto-rotate queue',
    plan.auto.length === 1 && plan.auto[0].scope === scopeId && plan.auto[0].agent === agentPub && plan.confirm.length === 0)
  await runRelinquishRotation(relay, signer, index, plan.auto[0], { relayHint: ws.url })

  // -------------------------------------------- 4. the ledger shows the arc

  const arc = eventsFor(index, scopeId, agentPub).map(e => e.t)
  check('ledger arc: granted → relinquished → rotated', arc.join(',') === 'granted,relinquished,rotated')
  const row = deriveDelegations(index).find(d => d.scope === scopeId && d.agent === agentPub)
  check('delegation row reads "relinquished" with the agent\'s reason in history',
    row?.status === 'relinquished'
    && eventsFor(index, scopeId, agentPub).some(e => e.t === 'relinquished' && e.reason === 'task complete'))
  check('index is rotation-clean: no grantees left at v2',
    index.issued.find(e => e.scope === scopeId)?.v === 2
    && index.issued.find(e => e.scope === scopeId)?.grantees.length === 0)

  // ------------------- 5. the agent's next read: severance is cryptographic

  const after = await client.callTool({
    name: 'nvoy_scope_read', arguments: { d: scopeId, author_npub: nip19.npubEncode(delegatorPub), max_age: 0 },
  })
  check('agent\'s subsequent scope_read returns NVOY_GRANT_REVOKED',
    after.isError === true && textJson(after).code === 'NVOY_GRANT_REVOKED')

  // ------------------------------------------------- 6. observer stays blind

  const view = ws.store.observerView()
  const kinds = new Set(view.map(e => e.kind))
  check('observer: only 30440/1059/10440 ever hit the relay',
    [...kinds].every(k => [30440, 1059, 10440].includes(k)))
  check('observer: no purpose, reason, or relinquish type visible',
    !JSON.stringify(ws.store.events).includes('task complete')
    && !JSON.stringify(ws.store.events).includes('relinquish')
    && !JSON.stringify(ws.store.events).includes('Plan one trip'))
} finally {
  await client.close().catch(() => {})
  await ws.close()
}

console.log(failed ? '\nM4 ACCEPTANCE: FAIL' : `\nM4 ACCEPTANCE: ALL ${n} PASS`)
process.exit(failed)
