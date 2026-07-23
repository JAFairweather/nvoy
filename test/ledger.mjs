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
import {
  grantWithTerms, sendRevocationNotice, rotateWithTerms, opaqueScopeId, TEMPLATES,
  receiveGrantsWithTerms, receiveNotices,
} from '../console/nvoygrant.mjs'
import {
  appendLedger, grantedEvent, rotatedEvent, revokedEvent,
  deriveDelegations, eventsFor, computeTotals, fmtCountdown, LEDGER_CAP,
} from '../console/ledgerlog.mjs'
import { expiryRotationPlan, nextExpiry, runExpiryRotation, relinquishPlan, runRelinquishRotation } from '../console/ttl.mjs'
import { sanitizeConfig, DEFAULT_RELAYS } from '../console/config.mjs'
import { receiveGrants, latestGrants, findRevocationNotice, grantStatus } from '../mcp/dist/grants.js'
import { sendAccessRequest, sendRelinquishNotice } from '../mcp/dist/notices.js'

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
check('totals split grantees: agents (in registry) vs other identities', (() => {
  // agentA is a registered agent; agentB is treated as an outside identity here.
  const t = computeTotals(dels, index.nvoy_ledger, now, new Set([agentAPub]))
  return t.agents === 1 && t.identities === 1
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

// ------------------- 7. §6.5 outputs: agent grants its outbox back (console
// receives terms-aware — the read side of the Ledger "outputs" surface)

const outScope = opaqueScopeId()
const outKey = newScopeKey()
await publishScope(relay, agentB, { scopeId: outScope, generation: 1, scopeKey: outKey,
  payload: { name: 'agent output', fields: { status: 'itinerary drafted', updated: 'now' } } })
await grantWithTerms(relay, agentB, delegatorPub, {
  scopeId: outScope, generation: 1, scopeKey: outKey, scopeName: 'agent output',
  terms: { purpose: 'agent output' },
})
const rxGrants = await receiveGrantsWithTerms(relay, signer)
const outRec = rxGrants.find(g => g.publisher === agentBPub && g.scopeId === outScope)
check('console receives the agent outbox grant WITH terms (signer-based unwrap)',
  outRec?.terms?.purpose === 'agent output' && outRec?.scopeName === 'agent output' && outRec?.generation === 1)
check('console dereferences the agent output live',
  (await fetchScope(relay, outRec)).data?.fields?.status === 'itinerary drafted')

// --------------- 8. nvoy notices cross-impl: MCP runtime sends, console reads

await sendAccessRequest(relay, agentA, delegatorPub, 'Draft weekly status emails from the project brief')
await sendRelinquishNotice(relay, agentB, delegatorPub,
  { publisher: delegatorPub, scopeId, reason: 'trip planned — handing the data back', destroyed_at: now })
const notices = await receiveNotices(relay, signer)
check('access request unwraps: agent pubkey + purpose intact',
  notices.accessRequests.some(r => r.from === agentAPub && r.purpose === 'Draft weekly status emails from the project brief'))
check('relinquish notice unwraps: { from, scope, reason, destroyed_at }', (() => {
  const rel = notices.relinquishes.find(x => x.scope === scopeId)
  return rel?.from === agentBPub && rel?.reason === 'trip planned — handing the data back' && rel?.destroyed_at === now
})())

// ------------- 9. relinquish policy (§6.6 + decision 6): sole grantee → auto

let plan = relinquishPlan(index, notices.relinquishes)
check('relinquish plan: sole grantee (B on the travel scope) queued for AUTO-rotation',
  plan.auto.length === 1 && plan.auto[0].scope === scopeId && plan.auto[0].agent === agentBPub
  && plan.auto[0].others === 0 && plan.confirm.length === 0)
const heldB2 = latestGrants(await receiveGrants(relay, agentB)).find(x => x.scopeId === scopeId)
await runRelinquishRotation(relay, signer, index, plan.auto[0])
check('relinquish finalized: agent dropped from grantees, next dereference stale',
  !index.issued.find(e => e.scope === scopeId).grantees.includes(agentBPub)
  && (await fetchScope(relay, heldB2)).status === 'stale')
check('ledger arc for B: granted → rotated → relinquished → rotated', (() => {
  const ts = eventsFor(index, scopeId, agentBPub).map(e => e.t)
  return ts.join(',') === 'granted,rotated,relinquished,rotated'
})())
check('delegation status: relinquished (agent-initiated, distinct from revoked)',
  deriveDelegations(index, now + 1).find(d => d.scope === scopeId && d.agent === agentBPub)?.status === 'relinquished')
plan = relinquishPlan(index, (await receiveNotices(relay, signer)).relinquishes)
check('plan self-heals: already-rotated relinquishment no longer queued',
  !plan.auto.some(x => x.scope === scopeId) && !plan.confirm.some(x => x.scope === scopeId))

// multi-grantee case: notice queues a one-tap confirm instead of auto-rotating
const scope2 = opaqueScopeId()
const key2 = newScopeKey()
await publishScope(relay, signer, { scopeId: scope2, generation: 1, scopeKey: key2, payload: { name: 'shared brief', fields: { x: 1 } } })
await grantWithTerms(relay, signer, agentAPub, { scopeId: scope2, generation: 1, scopeKey: key2, scopeName: 'shared brief', terms: { purpose: 'A work' } })
await grantWithTerms(relay, signer, agentBPub, { scopeId: scope2, generation: 1, scopeKey: key2, scopeName: 'shared brief', terms: { purpose: 'B work' } })
index.issued.push(toIssuedEntry({ scopeId: scope2, scopeName: 'shared brief', generation: 1, scopeKey: key2 }, [agentAPub, agentBPub]))
index.nvoy_ledger = appendLedger(index, grantedEvent({ scope: scope2, agent: agentAPub, v: 1, terms: { nvoy: 1, purpose: 'A work' }, name: 'shared brief' }))
index.nvoy_ledger = appendLedger(index, grantedEvent({ scope: scope2, agent: agentBPub, v: 1, terms: { nvoy: 1, purpose: 'B work' }, name: 'shared brief' }))
await saveGrantIndex(relay, signer, index)
await sendRelinquishNotice(relay, agentA, delegatorPub, { publisher: delegatorPub, scopeId: scope2, destroyed_at: now + 1 })
plan = relinquishPlan(index, (await receiveNotices(relay, signer)).relinquishes)
check('relinquish plan: other grantees exist → one-tap CONFIRM queue, not auto',
  plan.confirm.some(x => x.scope === scope2 && x.agent === agentAPub && x.others === 1)
  && !plan.auto.some(x => x.scope === scope2))
await runRelinquishRotation(relay, signer, index, plan.confirm.find(x => x.scope === scope2))
const heldB3 = latestGrants(await receiveGrants(relay, agentB)).find(x => x.scopeId === scope2)
check('confirmed relinquish: survivor re-granted at v2 under ORIGINAL terms',
  heldB3?.generation === 2 && heldB3?.terms?.purpose === 'B work'
  && (await fetchScope(relay, heldB3)).data?.fields?.x === 1)

// --------------------------- 10. TTL hard expiry (§6.4.3): plan + rotation

const ttlScope = opaqueScopeId()
const ttlKey = newScopeKey()
await publishScope(relay, signer, { scopeId: ttlScope, generation: 1, scopeKey: ttlKey, payload: { name: 'short-lived', fields: { secret: 'until friday' } } })
await grantWithTerms(relay, signer, agentAPub, { scopeId: ttlScope, generation: 1, scopeKey: ttlKey, scopeName: 'short-lived', terms: { purpose: 'lapses', expires_at: now - 60 } })
await grantWithTerms(relay, signer, agentBPub, { scopeId: ttlScope, generation: 1, scopeKey: ttlKey, scopeName: 'short-lived', terms: { purpose: 'stands', expires_at: now + 7200 } })
index.issued.push(toIssuedEntry({ scopeId: ttlScope, scopeName: 'short-lived', generation: 1, scopeKey: ttlKey }, [agentAPub, agentBPub]))
index.nvoy_ledger = appendLedger(index, grantedEvent({ scope: ttlScope, agent: agentAPub, v: 1, terms: { nvoy: 1, purpose: 'lapses', expires_at: now - 60 }, name: 'short-lived' }))
index.nvoy_ledger = appendLedger(index, grantedEvent({ scope: ttlScope, agent: agentBPub, v: 1, terms: { nvoy: 1, purpose: 'stands', expires_at: now + 7200 }, name: 'short-lived' }))
await saveGrantIndex(relay, signer, index)

const ttlPlan = expiryRotationPlan(index, now)
check('expiry plan: one item per scope, listing only the lapsed grantees',
  ttlPlan.length >= 1 && (() => {
    const item = ttlPlan.find(x => x.scope === ttlScope)
    return item?.expired.join() === agentAPub && item.scopeName === 'short-lived'
  })())
check('nextExpiry: soonest FUTURE deadline among active delegations',
  nextExpiry(index, now) === now + 7200)

const heldAttl = latestGrants(await receiveGrants(relay, agentA)).find(x => x.scopeId === ttlScope)
const rot2 = await runExpiryRotation(relay, signer, index, ttlPlan.find(x => x.scope === ttlScope))
check('TTL rotation: expired grantee dropped, key rotated (v2), survivor kept',
  rot2.to_v === 2 && rot2.survivors.join() === agentBPub
  && index.issued.find(e => e.scope === ttlScope).grantees.join() === agentBPub)
check('expired agent: fresh dereference is stale — hard expiry needed no cooperation',
  (await fetchScope(relay, heldAttl)).status === 'stale')
const heldBttl = latestGrants(await receiveGrants(relay, agentB)).find(x => x.scopeId === ttlScope)
check('unexpired survivor re-granted at v2 under original terms',
  heldBttl?.generation === 2 && heldBttl?.terms?.expires_at === now + 7200
  && (await fetchScope(relay, heldBttl)).data?.fields?.secret === 'until friday')
check('ledger: expired-rotated event { from_v, to_v, expired, survivors }', (() => {
  const ev = (index.nvoy_ledger ?? []).find(e => e.t === 'expired-rotated' && e.scope === ttlScope)
  return ev?.from_v === 1 && ev?.to_v === 2 && ev?.expired === 1 && ev?.survivors === 1
})())
check('dropped-by-expiry status reads "expired", and it is in the survivor\'s history too',
  deriveDelegations(index, now + 10).find(d => d.scope === ttlScope && d.agent === agentAPub)?.status === 'expired'
  && eventsFor(index, ttlScope, agentBPub).some(e => e.t === 'expired-rotated'))
check('plan clears after rotation (idempotent sweep)',
  !expiryRotationPlan(index, now).some(x => x.scope === ttlScope))

// ------------------------------------------------ 11. adversarial observer

const view = inMem.observerView()
const kinds = new Set(view.map(e => e.kind))
check('observer: only 30440/1059/10440 on the relay (no 440, no naked 441)',
  !kinds.has(440) && !kinds.has(441) && [...kinds].every(k => [30440, 1059, 10440].includes(k)))
const blob = JSON.stringify(inMem.events)
check('observer: no terms, purposes, reasons, or agent registry in stored content',
  !blob.includes('no_persist') && !blob.includes('Plan travel') && !blob.includes('B purpose')
  && !blob.includes('trip planned') && !blob.includes('nvoy_agents') && !blob.includes('nvoy_ledger'))
check('observer: no access requests, relinquishes, or agent output in stored content',
  !blob.includes('access_request') && !blob.includes('relinquish')
  && !blob.includes('agent output') && !blob.includes('itinerary drafted')
  && !blob.includes('until friday') && !blob.includes('expired-rotated'))
check('observer: wrap senders are ephemeral (delegator never linked to agents)',
  inMem.query({ kinds: [1059] }).every(w => ![delegatorPub, agentAPub, agentBPub].includes(w.pubkey)))

console.log(failed ? '\nLEDGER: FAIL' : `\nLEDGER: ALL ${n} PASS`)
process.exit(failed)
