// ledger.mjs — PASS/FAIL assertions over the M3 console layer: the DOM-free
// modules the console imports (console/nvoygrant.mjs, console/ledgerlog.mjs,
// console/config.mjs), cross-checked against the compiled MCP server modules
// — a grant issued by the console MUST parse identically on the agent side.
// Fully offline, in-memory relay.
//
//   node test/ledger.mjs

import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { localSigner, newScopeKey, publishScope, fetchScope, saveGrantIndex, loadGrantIndex, toIssuedEntry, fromIssuedEntry } from '../lib/nipxx.mjs'
import { Relay } from '../lib/relay.mjs'
import { LocalRelay } from '../lib/liverelay.mjs'
import { grantWithTerms, sendRevocationNotice, rotateWithTerms, opaqueScopeId, TEMPLATES } from '../console/nvoygrant.mjs'
import {
  appendLedger, grantedEvent, rotatedEvent, revokedEvent,
  deriveDelegations, eventsFor, computeTotals, fmtCountdown, LEDGER_CAP,
} from '../console/ledgerlog.mjs'
import { sanitizeConfig, DEFAULT_RELAYS } from '../console/config.mjs'
import { receiveGrants, latestGrants, findRevocationNotice, grantStatus } from '../mcp/dist/grants.js'

let n = 0, failed = 0
const check = (name, cond) => {
  n++
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${String(n).padStart(2)}. ${name}`)
  if (!cond) failed = 1
}

const inMem = new Relay()
const relay = new LocalRelay(inMem)
const delegatorSk = generateSecretKey()
const delegatorPub = getPublicKey(delegatorSk)
const signer = localSigner(delegatorSk)          // the console never holds sk after login
const agentA = generateSecretKey(), agentAPub = getPublicKey(agentA)
const agentB = generateSecretKey(), agentBPub = getPublicKey(agentB)
const now = Math.floor(Date.now() / 1000)

// ------------------------------------------- 1. console grant ↔ MCP interop

const scopeId = opaqueScopeId()
const scopeKey = newScopeKey()
const terms = {
  purpose: 'Plan travel within stated preferences',
  expires_at: now + 7 * 24 * 3600,
  no_persist: true, redelegate: false, reply_scope_requested: false,
  contact: 'npub1demo', auto_relinquish: false,
}
await publishScope(relay, signer, { scopeId, generation: 1, scopeKey, payload: TEMPLATES['travel-prefs'].payload })
await grantWithTerms(relay, signer, agentAPub, { scopeId, generation: 1, scopeKey, scopeName: 'travel-preferences', terms })
await grantWithTerms(relay, signer, agentBPub, { scopeId, generation: 1, scopeKey, scopeName: 'travel-preferences', terms: { ...terms, purpose: 'B purpose' } })

const held = latestGrants(await receiveGrants(relay, agentA))
const g = held.find(x => x.publisher === delegatorPub && x.scopeId === scopeId)
check('signer-issued grant unwraps on the MCP side (seal-verified)', !!g && g.generation === 1)
check('nested nvoy terms carrier parses identically (mcp terms.ts)',
  g?.terms?.purpose === terms.purpose && g?.terms?.no_persist === true && g?.terms?.auto_relinquish === false)
check('agent dereferences the console-published scope',
  (await fetchScope(relay, g)).data?.fields?.seat === 'aisle')
check('grant status active per console-authored expires_at', grantStatus(g) === 'active')

// ------------------------------------------------ 2. ledger event log shape

let index = { issued: [], received: [] }
index.issued.push(toIssuedEntry({ scopeId, scopeName: 'travel-preferences', generation: 1, scopeKey }, [agentAPub, agentBPub]))
index.nvoy_ledger = appendLedger(index, grantedEvent({ scope: scopeId, agent: agentAPub, v: 1, terms: { nvoy: 1, ...terms }, name: 'travel-preferences', at: now - 100 }))
index.nvoy_ledger = appendLedger(index, grantedEvent({ scope: scopeId, agent: agentBPub, v: 1, terms: { nvoy: 1, ...terms, purpose: 'B purpose' }, name: 'travel-preferences', at: now - 90 }))
index.nvoy_agents = [{ pub: agentAPub, added_at: now - 200 }, { pub: agentBPub, added_at: now - 200 }]
await saveGrantIndex(relay, signer, index)

let dels = deriveDelegations(index, now)
check('deriveDelegations: one row per (scope, agent) pair', dels.length === 2)
check('active status + terms + purpose on each row',
  dels.every(d => d.status === 'active') && dels.find(d => d.agent === agentBPub)?.purpose === 'B purpose')
check('totals: 2 active to 2 agents, 0 revoked this month', (() => {
  const t = computeTotals(dels, index.nvoy_ledger, now)
  return t.active === 2 && t.agents === 2 && t.revokedThisMonth === 0
})())

// -------------------------------- 3. revoke-now: rotate, preserve B's terms

const res = await fetchScope(relay, { publisher: delegatorPub, scopeId, generation: 1, scopeKey })
const rot = await rotateWithTerms(relay, signer, {
  scopeId, generation: 1, payload: res.data, scopeName: 'travel-preferences',
  survivors: [{ pub: agentBPub, terms: { ...terms, purpose: 'B purpose' } }],
})
await sendRevocationNotice(relay, signer, agentAPub, { scopeId, reason: 'trip planned; delegation over' })
index.issued = index.issued.map(e => e.scope !== scopeId ? e :
  toIssuedEntry({ scopeId, scopeName: 'travel-preferences', generation: rot.generation, scopeKey: rot.scopeKey }, [agentBPub]))
index.nvoy_ledger = appendLedger(index, revokedEvent({ scope: scopeId, agent: agentAPub, v: 1, reason: 'trip planned; delegation over', notice: true, at: now - 10 }))
index.nvoy_ledger = appendLedger(index, rotatedEvent({ scope: scopeId, from_v: 1, to_v: 2, survivors: 1, at: now - 10 }))
await saveGrantIndex(relay, signer, index)

check('revoked agent: fresh dereference is stale (v superseded)',
  (await fetchScope(relay, g)).status === 'stale')
const heldB = latestGrants(await receiveGrants(relay, agentB)).find(x => x.scopeId === scopeId)
check('survivor re-granted at v2 with ORIGINAL terms preserved',
  heldB?.generation === 2 && heldB?.terms?.purpose === 'B purpose' && heldB?.terms?.no_persist === true)
check('survivor still dereferences after rotation',
  (await fetchScope(relay, heldB)).data?.fields?.seat === 'aisle')
const notice = await findRevocationNotice(relay, agentA, delegatorPub, scopeId)
check('console 441 notice authenticated by MCP findRevocationNotice',
  notice?.content?.reason === 'trip planned; delegation over')

dels = deriveDelegations(index, now)
const dA = dels.find(d => d.agent === agentAPub)
const dB = dels.find(d => d.agent === agentBPub)
check('ledger rows: A revoked, B active at v2', dA?.status === 'revoked' && dB?.status === 'active' && dB?.v === 2)
check('revoked rows sort after active rows', dels[0].agent === agentBPub)
const hist = eventsFor(index, scopeId, agentAPub)
check('event history for A: granted → revoked → rotated, oldest first',
  hist.map(e => e.t).join(',') === 'granted,revoked,rotated')
check('rotation event is scope-wide (also in B’s history)',
  eventsFor(index, scopeId, agentBPub).some(e => e.t === 'rotated' && e.to_v === 2))
check('totals after revoke: 1 active to 1 agent, 1 revoked this month', (() => {
  const t = computeTotals(dels, index.nvoy_ledger, now)
  return t.active === 1 && t.agents === 1 && t.revokedThisMonth === 1
})())

// ------------------------------------------------- 4. expiry + countdown

index.nvoy_ledger = appendLedger(index, grantedEvent({
  scope: 'expired1', agent: agentAPub, v: 1,
  terms: { nvoy: 1, purpose: 'lapsed', expires_at: now - 3600 }, name: 'lapsed', at: now - 7200,
}))
index.issued.push(toIssuedEntry({ scopeId: 'expired1', scopeName: 'lapsed', generation: 1, scopeKey: newScopeKey() }, [agentAPub]))
await saveGrantIndex(relay, signer, index)
check('expired status: agent still holds the key but terms lapsed',
  deriveDelegations(index, now).find(d => d.scope === 'expired1')?.status === 'expired')
check('fmtCountdown: future / past / none',
  fmtCountdown(now + 3 * 24 * 3600 + 3600, now) === 'expires in 3d 1h'
  && fmtCountdown(now - 90, now) === 'expired 1m ago'
  && fmtCountdown(null, now) === 'no expiry')

// ------------------------------------------- 5. reconstitution from nsec

const recovered = await loadGrantIndex(relay, localSigner(delegatorSk))
const rDels = deriveDelegations(recovered, now)
check('Grant Index round-trips: agents + ledger + issued survive re-login',
  recovered.nvoy_agents?.length === 2 && (recovered.nvoy_ledger?.length ?? 0) >= 5
  && rDels.find(d => d.agent === agentAPub && d.scope === scopeId)?.status === 'revoked'
  && rDels.find(d => d.agent === agentBPub)?.status === 'active')
check('recovered issued entry is rotation-ready (v2 key present)', (() => {
  const e = recovered.issued.map(fromIssuedEntry).find(x => x.scopeId === scopeId)
  return e?.generation === 2 && e?.scopeKey?.length === 32 && e?.grantees?.length === 1
})())

// ------------------------------------------------ 6. log cap + config

let big = { nvoy_ledger: [] }
for (let i = 0; i < LEDGER_CAP + 25; i++)
  big.nvoy_ledger = appendLedger(big, grantedEvent({ scope: 's', agent: 'a', v: i, terms: null, name: 'x', at: i }))
check(`ledger log capped at ${LEDGER_CAP}, oldest trimmed`,
  big.nvoy_ledger.length === LEDGER_CAP && big.nvoy_ledger[0].v === 25)

check('config: ws:// kept for local relay, junk falls back to defaults',
  sanitizeConfig({ relays: ['ws://127.0.0.1:4460/'] }).relays[0] === 'ws://127.0.0.1:4460'
  && sanitizeConfig({ relays: ['http://nope', 42] }).relays.join() === DEFAULT_RELAYS.join()
  && sanitizeConfig(null).relays.length === 3)

// ------------------------------------------------ 7. adversarial observer

const view = inMem.observerView()
const kinds = new Set(view.map(e => e.kind))
check('observer: only 30440/1059/10440 on the relay (no 440, no naked 441)',
  !kinds.has(440) && !kinds.has(441) && [...kinds].every(k => [30440, 1059, 10440].includes(k)))
const blob = JSON.stringify(inMem.events)
check('observer: no terms, purposes, reasons, or agent registry in stored content',
  !blob.includes('no_persist') && !blob.includes('Plan travel') && !blob.includes('B purpose')
  && !blob.includes('trip planned') && !blob.includes('nvoy_agents') && !blob.includes('nvoy_ledger'))
check('observer: wrap senders are ephemeral (delegator never linked to agents)',
  inMem.query({ kinds: [1059] }).every(w => ![delegatorPub, agentAPub, agentBPub].includes(w.pubkey)))

console.log(failed ? '\nLEDGER: FAIL' : `\nLEDGER: ALL ${n} PASS`)
process.exit(failed)
