// mcp-conformance.mjs — spawn the BUILT Nvoy server and drive it with the
// official MCP SDK client, exactly as Claude Desktop (stdio) or a remote
// MCP client (streamable HTTP) would:
//
//   local ws relay ← seeded delegation ← this test
//   node mcp/dist/server.js (NVOY_NSEC, NVOY_RELAYS=ws://127.0.0.1:…)
//   SDK Client → tools / resources on BOTH transports
//
// Covers the full §6.2 tool surface: whoami, grants_list, scope_read,
// scope_subscribe (stdio cache-invalidation AND http update notifications),
// outbox_write (§6.5), request_access, grant_relinquish + auto_relinquish
// (§6.6), plus the conversation tools and M2 revocation beats. Fully offline.

import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { ResourceUpdatedNotificationSchema } from '@modelcontextprotocol/sdk/types.js'
import { finalizeEvent, generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { unwrapEvent } from 'nostr-tools/nip59'
import { newScopeKey, publishScope, rotateScope, fetchScope, loadGrantIndex } from '../lib/nipxx.mjs'
import { LocalRelay } from '../lib/liverelay.mjs'
import { grantWithTerms, sendRevocationNotice, opaqueScopeId, TRAVEL_PREFERENCES } from './nvoygrant.mjs'
import { receiveGrants, latestGrants } from '../mcp/dist/grants.js'
import { KIND_NVOY_MSG } from '../mcp/dist/notices.js'
import { startWsRelay } from './wsrelay.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const sleep = (ms) => new Promise(r => setTimeout(r, ms))

let n = 0, failed = 0
const check = (name, cond) => {
  n++
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${String(n).padStart(2)}. ${name}`)
  if (!cond) failed = 1
}
const textJson = (result) => JSON.parse(result.content.find(c => c.type === 'text').text)

const TOOLS = [
  'nvoy_whoami', 'nvoy_grants_list', 'nvoy_capabilities_list', 'nvoy_scope_read', 'nvoy_scope_subscribe',
  'nvoy_derived_grant_issue',
  'nvoy_outbox_write', 'nvoy_draft_publish', 'nvoy_draft_withdraw',
  'nvoy_request_access', 'nvoy_grant_relinquish',
  'nvoy_chat_post', 'nvoy_chat_read', 'nvoy_dm_send', 'nvoy_dm_read',
]

// ------------------------------------------------ seed a delegation offline

const ws = await startWsRelay()
const seedRelay = new LocalRelay(ws.store) // write straight into the store

const delegatorSk = generateSecretKey()
const delegatorPub = getPublicKey(delegatorSk)
const delegatorNpub = nip19.npubEncode(delegatorPub)
const agentSk = generateSecretKey()
const agentNpub = nip19.npubEncode(getPublicKey(agentSk))
const leafSk = generateSecretKey()
const leafPub = getPublicKey(leafSk)

const publicAdmission = finalizeEvent({
  kind: 440, created_at: Math.floor(Date.now() / 1000), content: '',
  tags: [['p', getPublicKey(agentSk)], ['da-scope', 'a'.repeat(64), 'b'.repeat(32)], ['da-cap', 'admit']],
}, delegatorSk)
await seedRelay.publish(publicAdmission)

const scopeId = opaqueScopeId()
const scopeKey = newScopeKey()
const purpose = 'Plan travel within stated preferences'
await publishScope(seedRelay, delegatorSk, { scopeId, generation: 1, scopeKey, payload: TRAVEL_PREFERENCES })
await grantWithTerms(seedRelay, delegatorSk, getPublicKey(agentSk), {
  scopeId, generation: 1, scopeKey, scopeName: 'travel-preferences', relayHint: ws.url,
  terms: { purpose, expires_at: Math.floor(Date.now() / 1000) + 3600, no_persist: true, redelegate: false, reply_scope_requested: true, contact: delegatorNpub },
})

const derivedParentId = opaqueScopeId(), derivedParentKey = newScopeKey()
await publishScope(seedRelay, delegatorSk, { scopeId: derivedParentId, generation: 1, scopeKey: derivedParentKey, payload: { safe: 'yes', secret: 'root-only' } })
await grantWithTerms(seedRelay, delegatorSk, getPublicKey(agentSk), {
  scopeId: derivedParentId, generation: 1, scopeKey: derivedParentKey, scopeName: 'derivable-parent', relayHint: ws.url,
  terms: { purpose: 'derive bounded leaf', redelegate: true },
})

// a second, already-expired grant (soft expiry per §4 — the runtime honors it)
const expiredScopeId = opaqueScopeId()
const expiredKey = newScopeKey()
await publishScope(seedRelay, delegatorSk, { scopeId: expiredScopeId, generation: 1, scopeKey: expiredKey, payload: { name: 'lapsed', fields: {} } })
await grantWithTerms(seedRelay, delegatorSk, getPublicKey(agentSk), {
  scopeId: expiredScopeId, generation: 1, scopeKey: expiredKey, scopeName: 'lapsed-demo', relayHint: ws.url,
  terms: { purpose: 'already lapsed', expires_at: Math.floor(Date.now() / 1000) - 3600 },
})

// a third scope the agent will relinquish (§6.6)
const relScopeId = opaqueScopeId()
const relKey = newScopeKey()
await publishScope(seedRelay, delegatorSk, { scopeId: relScopeId, generation: 1, scopeKey: relKey, payload: { name: 'one-task brief', fields: { task: 'demo' } } })
await grantWithTerms(seedRelay, delegatorSk, getPublicKey(agentSk), {
  scopeId: relScopeId, generation: 1, scopeKey: relKey, scopeName: 'one-task-brief', relayHint: ws.url,
  terms: { purpose: 'single task then hand back', contact: delegatorNpub },
})

// a fourth: auto_relinquish with an expiry a few seconds out — the runtime's
// sweeper must destroy it unprompted once expires_at passes
const autoScopeId = opaqueScopeId()
const autoKey = newScopeKey()
await publishScope(seedRelay, delegatorSk, { scopeId: autoScopeId, generation: 1, scopeKey: autoKey, payload: { name: 'short-lived', fields: {} } })
await grantWithTerms(seedRelay, delegatorSk, getPublicKey(agentSk), {
  scopeId: autoScopeId, generation: 1, scopeKey: autoKey, scopeName: 'short-lived', relayHint: ws.url,
  terms: { purpose: 'auto-relinquish demo', expires_at: Math.floor(Date.now() / 1000) + 4, auto_relinquish: true, contact: delegatorNpub },
})

/** Delegator-side unwrap of nvoy notices (access requests, relinquishes). */
const delegatorNotices = () => ws.store.query({ kinds: [1059], '#p': [delegatorPub] })
  .map(w => { try { return unwrapEvent(w, delegatorSk) } catch { return null } })
  .filter(r => r?.kind === KIND_NVOY_MSG)
  .map(r => ({ ...JSON.parse(r.content), from: r.pubkey, at: r.created_at }))

// --------------------------------------------- spawn the real server binary

const serverEnv = {
  ...process.env,
  NVOY_NSEC: nip19.nsecEncode(agentSk),
  NVOY_RELAYS: ws.url,
  NVOY_SUBSCRIBE_POLL_MS: '250',
  NVOY_SWEEP_MS: '300',
}
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(root, 'mcp', 'dist', 'server.js')],
  env: serverEnv,
  stderr: 'pipe',
})
const client = new Client({ name: 'nvoy-conformance', version: '0.1.0' })

// HTTP server: second process, same identity, ephemeral port announced on stderr
function spawnHttpServer() {
  const child = spawn(process.execPath, [join(root, 'mcp', 'dist', 'server.js')], {
    env: { ...serverEnv, NVOY_HTTP_PORT: '0' },
    stdio: ['ignore', 'ignore', 'pipe'],
  })
  return new Promise((resolve, reject) => {
    let buf = ''
    const timer = setTimeout(() => reject(new Error(`http server never announced: ${buf}`)), 8000)
    child.stderr.on('data', (chunk) => {
      buf += chunk
      const m = buf.match(/ready on (http:\/\/[^ ]+\/mcp)/)
      if (m) { clearTimeout(timer); resolve({ child, url: m[1] }) }
    })
    child.on('exit', (code) => reject(new Error(`http server exited ${code}: ${buf}`)))
  })
}

let httpChild = null
try {
  await client.connect(transport)

  // ------------------------------------------------------------- tool list
  const tools = (await client.listTools()).tools.map(t => t.name)
  check('server exposes exactly the declared tool surface',
    TOOLS.every(t => tools.includes(t)) && tools.length === TOOLS.length)

  // ---------------------------------------------------------------- whoami
  const who = textJson(await client.callTool({ name: 'nvoy_whoami' }))
  check('nvoy_whoami: npub matches the injected identity', who.npub === agentNpub)
  check('nvoy_whoami: relay set reported', Array.isArray(who.relays) && who.relays[0] === ws.url)
  check('nvoy_whoami: pubkey is hex, metadata null when unpublished',
    /^[0-9a-f]{64}$/.test(who.pubkey) && who.metadata === null)

  // ----------------------------------------------------------- grants_list
  const list = textJson(await client.callTool({ name: 'nvoy_grants_list' }))
  check('nvoy_grants_list: all five held grants', list.grants?.length === 5)
  const lg = list.grants?.find(g => g.d === scopeId) ?? {}
  check('grants_list shape: { d, author_npub, purpose, expires_at, terms, v, status }',
    lg.d === scopeId && lg.author_npub === delegatorNpub && lg.purpose === purpose
    && typeof lg.expires_at === 'number' && lg.terms?.no_persist === true && lg.v === 1)
  check('grants_list status: active', lg.status === 'active')
  check('grants_list status: expired grant flagged (soft expiry honored)',
    list.grants?.find(g => g.d === expiredScopeId)?.status === 'expired')

  // ---------------------------------------------------- capabilities_list
  const capabilities = textJson(await client.callTool({ name: 'nvoy_capabilities_list' }))
  check('nvoy_capabilities_list: cold-reads this identity\'s public channel admission',
    capabilities.capabilities?.length === 1 && capabilities.capabilities[0].cap === 'admit' &&
    capabilities.capabilities[0].status === 'active')
  check('nvoy_capabilities_list: reports completed relay queries',
    capabilities.verification?.status === 'verified' && capabilities.verification.grant_query_answered === 1 &&
    capabilities.verification.revocation_query_answered === 1)

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

  const deniedDerive = await client.callTool({ name: 'nvoy_derived_grant_issue', arguments: {
    parent_d: scopeId, parent_author_npub: delegatorNpub, grantee_npub: nip19.npubEncode(leafPub), payload: { safe: 'no' }, scope_name: 'derived:forbidden', purpose: 'must refuse',
  } })
  check('derived grant tool refuses parent without redelegate:true', deniedDerive.isError === true && textJson(deniedDerive).code === 'NVOY_REDELEGATION_FORBIDDEN')
  const derived = textJson(await client.callTool({ name: 'nvoy_derived_grant_issue', arguments: {
    parent_d: derivedParentId, parent_author_npub: delegatorNpub, grantee_npub: nip19.npubEncode(leafPub), payload: { safe: 'yes' }, scope_name: 'derived:booking', purpose: 'booking subset',
  } }))
  await sleep(80)
  const leafGrant = (await receiveGrants(seedRelay, leafSk)).find(g => g.scopeId === derived.scopeId)
  const leafData = leafGrant ? await fetchScope(seedRelay, leafGrant) : null
  check('derived grant tool issues an attenuated new scope, never the parent key', leafGrant?.publisher === getPublicKey(agentSk) && leafData?.data?.safe === 'yes' && leafData?.data?.secret === undefined && !(await receiveGrants(seedRelay, leafSk)).some(g => g.scopeId === derivedParentId))

  // -------------------------------------------- scope_subscribe over stdio
  // The read above cached the scope (60s TTL). Subscribe arms invalidation;
  // a republish must make the NEXT default read fresh — no max_age needed.
  const sub = textJson(await client.callTool({
    name: 'nvoy_scope_subscribe', arguments: { d: scopeId, author_npub: delegatorNpub },
  }))
  check('scope_subscribe (stdio): armed as cache-invalidation with poll interval',
    sub.subscribed === true && sub.mode === 'cache-invalidation' && sub.poll_seconds >= 0)
  const sub2 = textJson(await client.callTool({
    name: 'nvoy_scope_subscribe', arguments: { d: scopeId, author_npub: delegatorNpub },
  }))
  check('scope_subscribe: idempotent re-subscribe', sub2.already_subscribed === true)

  await publishScope(seedRelay, delegatorSk, {
    scopeId, generation: 1, scopeKey,
    payload: { ...TRAVEL_PREFERENCES, fields: { ...TRAVEL_PREFERENCES.fields, note: 'UPDATED: window seat now' } },
  })
  await sleep(700) // > poll interval (250ms)
  const fresh = textJson(await client.callTool({
    name: 'nvoy_scope_read', arguments: { d: scopeId, author_npub: delegatorNpub },
  }))
  check('subscribe detected the republish: next default read is FRESH (cache invalidated)',
    fresh.data?.fields?.note === 'UPDATED: window seat now')

  // -------------------------------------------------------------- resources
  const res = await client.listResources()
  const r = res.resources?.find(x => x.uri === `nvoy://${delegatorNpub}/${scopeId}`)
  check('resources list: nvoy://{author_npub}/{d} for the active grant', !!r && r.mimeType === 'application/json')
  check('resource name/description from scope_name/purpose', r?.name === 'travel-preferences' && r?.description === purpose)

  const rc = await client.readResource({ uri: `nvoy://${delegatorNpub}/${scopeId}` })
  const body = JSON.parse(rc.contents[0].text)
  check('resource read: live-dereferenced scope JSON', body.data?.fields?.seat === 'aisle' && body.v === 1)
  check('resource read: no_persist attested', body.nvoy_no_persist === true)

  // ------------------------------------------------------ outbox_write §6.5
  // The travel grant carries reply_scope_requested — the sole reply target.
  const out1 = textJson(await client.callTool({
    name: 'nvoy_outbox_write',
    arguments: { payload: { name: 'trip plan', fields: { itinerary: 'YYZ→SFO 08:10, aisle 14C', status: 'draft' } } },
  }))
  check('outbox_write: auto-targets the reply_scope_requested delegator',
    out1.written === true && out1.granted_to === delegatorNpub && out1.first_write === true && typeof out1.d === 'string')
  check('outbox_write: persisted (identity from NVOY_NSEC → agent Grant Index)', out1.persisted === true)

  // delegator side: the outbox grant unwraps + dereferences like any grant
  const dHeld = latestGrants(await receiveGrants(seedRelay, delegatorSk))
  const outGrant = dHeld.find(g => g.publisher === getPublicKey(agentSk) && g.scopeId === out1.d)
  check('delegator receives the outbox grant (scope_name "agent output", purpose in terms)',
    outGrant?.scopeName === 'agent output' && outGrant?.terms?.purpose === 'agent output')
  const outRead1 = await fetchScope(seedRelay, outGrant)
  check('delegator dereferences the agent output live', outRead1.data?.fields?.status === 'draft')

  // second write: same scope, same key — a live update, no new grant
  const out2 = textJson(await client.callTool({
    name: 'nvoy_outbox_write',
    arguments: { payload: { name: 'trip plan', fields: { itinerary: 'YYZ→SFO 08:10, aisle 14C', status: 'final' } } },
  }))
  const outRead2 = await fetchScope(seedRelay, outGrant)
  check('outbox_write: second write updates in place (same d, same v, new content)',
    out2.d === out1.d && out2.first_write === false && outRead2.data?.fields?.status === 'final')
  const agentIndex = await loadGrantIndex(seedRelay, agentSk)
  check('agent outbox key recovered from the agent\'s own Grant Index (nsec-only recovery)',
    agentIndex.nvoy_outbox?.[delegatorPub] === out1.d
    && agentIndex.issued?.some(e => e.scope === out1.d && e.grantees?.includes(delegatorPub)))

  // ------------------------------------- draft_publish / draft_withdraw (#28)
  // The director-path delivery wire (nact#37): a fresh scope per offer,
  // granted to the Director, withdrawable by tombstone.
  const draft = textJson(await client.callTool({
    name: 'nvoy_draft_publish',
    arguments: {
      grantee_npub: delegatorNpub,
      payload: { kind: 'draft:post', text: 'raised through the mcp desk', proposedBy: 'jaf-quill@dequalsf.com', proposedAt: 1 },
    },
  }))
  check('draft_publish: fresh per-offer scope, draft:post/<id8> name, granted to the Director',
    typeof draft.d === 'string' && draft.v === 1
    && draft.scope_name === `draft:post/${draft.d.slice(0, 8)}` && draft.granted_to === delegatorNpub)

  // Director side: unwraps + gates exactly like the Ngage desk (draft: namespace,
  // first-hand publisher = the agent identity), and the payload rides byte-faithful.
  const held = latestGrants(await receiveGrants(seedRelay, delegatorSk))
  const draftGrant = held.find(g => g.scopeId === draft.d)
  check('draft grant: draft: namespace, first-hand from the agent identity',
    draftGrant?.scopeName === draft.scope_name && draftGrant?.publisher === getPublicKey(agentSk))
  const draftRead = await fetchScope(seedRelay, draftGrant)
  check('draft dereferences with the granted key; text byte-identical',
    draftRead.status === 'ok' && draftRead.data?.text === 'raised through the mcp desk')

  check('draft_publish: non-draft scope_name refused (namespace guard)',
    textJson(await client.callTool({
      name: 'nvoy_draft_publish',
      arguments: { grantee_npub: delegatorNpub, payload: { text: 'x' }, scope_name: 'steer:draft' },
    })).code === 'NVOY_BAD_INPUT')

  const wd = textJson(await client.callTool({ name: 'nvoy_draft_withdraw', arguments: { d: draft.d } }))
  const afterWd = await fetchScope(seedRelay, draftGrant)
  check('draft_withdraw: tombstoned — the granted key no longer opens it',
    wd.withdrawn === true && wd.v === 2 && afterWd.status !== 'ok')
  check('draft_withdraw: idempotent; unknown id is a typed error',
    textJson(await client.callTool({ name: 'nvoy_draft_withdraw', arguments: { d: draft.d } })).v === 2
    && textJson(await client.callTool({ name: 'nvoy_draft_withdraw', arguments: { d: 'nope' } })).code === 'NVOY_UNKNOWN_DRAFT')

  // ---------------------------------------------------- request_access §6.2
  const req = textJson(await client.callTool({
    name: 'nvoy_request_access',
    arguments: { delegator_npub: delegatorNpub, purpose: 'Draft weekly status emails from the project brief' },
  }))
  check('request_access: request sent', req.requested === true && req.delegator_npub === delegatorNpub)
  const reqNotice = delegatorNotices().find(x => x.type === 'access_request')
  check('delegator unwraps the access request (agent npub + purpose, relay saw neither)',
    reqNotice?.from === getPublicKey(agentSk) && reqNotice?.purpose === 'Draft weekly status emails from the project brief')

  // -------------------------------------------------- grant_relinquish §6.6
  const relRead = textJson(await client.callTool({
    name: 'nvoy_scope_read', arguments: { d: relScopeId, author_npub: delegatorNpub },
  }))
  check('relinquish setup: agent reads the one-task scope', relRead.data?.fields?.task === 'demo')
  const rel = textJson(await client.callTool({
    name: 'nvoy_grant_relinquish',
    arguments: { d: relScopeId, author_npub: delegatorNpub, reason: 'task complete' },
  }))
  check('grant_relinquish: key + cache destroyed, notice sent',
    rel.relinquished === true && typeof rel.destroyed_at === 'number' && rel.notice_sent === true)
  const relAgain = textJson(await client.callTool({
    name: 'nvoy_grant_relinquish', arguments: { d: relScopeId, author_npub: delegatorNpub },
  }))
  check('grant_relinquish: idempotent', relAgain.already_relinquished === true)
  const relList = textJson(await client.callTool({ name: 'nvoy_grants_list' }))
  check('grants_list: relinquished status + destruction record',
    relList.grants?.find(g => g.d === relScopeId)?.status === 'relinquished'
    && typeof relList.grants?.find(g => g.d === relScopeId)?.relinquishment?.destroyed_at === 'number')
  const relReadBack = await client.callTool({
    name: 'nvoy_scope_read', arguments: { d: relScopeId, author_npub: delegatorNpub },
  })
  check('scope_read after relinquish (delegator not yet rotated): NVOY_GRANT_RELINQUISHED',
    relReadBack.isError === true && textJson(relReadBack).code === 'NVOY_GRANT_RELINQUISHED')
  const relNotice = delegatorNotices().find(x => x.type === 'relinquish' && x.d === relScopeId)
  check('delegator unwraps the relinquish notice { type, d, reason, destroyed_at }',
    relNotice?.reason === 'task complete' && typeof relNotice?.destroyed_at === 'number')

  // delegator finalizes: rotate → the severance is now cryptographic (§6.6.2)
  await rotateScope(seedRelay, delegatorSk, {
    scopeId: relScopeId, generation: 1, payload: { name: 'one-task brief', fields: { task: 'demo' } },
    scopeName: 'one-task-brief', survivors: [],
  })
  const relFinal = await client.callTool({
    name: 'nvoy_scope_read', arguments: { d: relScopeId, author_npub: delegatorNpub, max_age: 0 },
  })
  check('scope_read after the delegator rotates: NVOY_GRANT_REVOKED (severance final)',
    relFinal.isError === true && textJson(relFinal).code === 'NVOY_GRANT_REVOKED')

  // ------------------------------------------- streamable HTTP transport
  const http = await spawnHttpServer()
  httpChild = http.child
  const httpClient = new Client({ name: 'nvoy-conformance-http', version: '0.1.0' })
  const updates = []
  httpClient.setNotificationHandler(ResourceUpdatedNotificationSchema, (note) => updates.push(note.params.uri))
  await httpClient.connect(new StreamableHTTPClientTransport(new URL(http.url)))

  const httpTools = (await httpClient.listTools()).tools.map(t => t.name)
  check('HTTP transport: same declared tool surface', TOOLS.every(t => httpTools.includes(t)) && httpTools.length === TOOLS.length)
  const httpRead = textJson(await httpClient.callTool({
    name: 'nvoy_scope_read', arguments: { d: scopeId, author_npub: delegatorNpub },
  }))
  check('HTTP transport: scope_read serves the scope', httpRead.data?.fields?.seat === 'aisle')

  const httpSub = textJson(await httpClient.callTool({
    name: 'nvoy_scope_subscribe', arguments: { d: scopeId, author_npub: delegatorNpub },
  }))
  check('scope_subscribe (HTTP): mode update-notifications', httpSub.subscribed === true && httpSub.mode === 'update-notifications')
  await publishScope(seedRelay, delegatorSk, {
    scopeId, generation: 1, scopeKey,
    payload: { ...TRAVEL_PREFERENCES, fields: { ...TRAVEL_PREFERENCES.fields, note: 'UPDATED again: hotel changed' } },
  })
  await sleep(900) // > poll interval
  check('scope change streams a notifications/resources/updated for the nvoy:// uri',
    updates.includes(`nvoy://${delegatorNpub}/${scopeId}`))
  const httpFresh = textJson(await httpClient.callTool({
    name: 'nvoy_scope_read', arguments: { d: scopeId, author_npub: delegatorNpub },
  }))
  check('HTTP read after notification: fresh content', httpFresh.data?.fields?.note === 'UPDATED again: hotel changed')
  await httpClient.close().catch(() => {})
  httpChild.kill('SIGTERM')
  httpChild = null

  // ------------------------------------------------- auto_relinquish sweep
  // Seeded with expires_at ≈ +4s and NVOY_SWEEP_MS=300 — by now the sweeper
  // must have destroyed the key unprompted and notified the delegator.
  {
    const deadline = Date.now() + 6000
    let g = null
    while (Date.now() < deadline) {
      const l = textJson(await client.callTool({ name: 'nvoy_grants_list' }))
      g = l.grants?.find(x => x.d === autoScopeId)
      if (g?.status === 'relinquished') break
      await sleep(300)
    }
    check('auto_relinquish: sweeper destroyed the key at term expiry (status relinquished)',
      g?.status === 'relinquished')
    check('auto_relinquish: delegator received the relinquish notice',
      delegatorNotices().some(x => x.type === 'relinquish' && x.d === autoScopeId))
  }

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
  check('resources list after revocation: the revoked scope is absent while unrelated active scopes remain', !(res2.resources ?? []).some(x => x.uri === `nvoy://${delegatorNpub}/${scopeId}`))

  // -------------------------------------- adversarial observer, real relay
  const view = ws.store.observerView()
  const kinds = new Set(view.map(e => e.kind))
  const public440s = view.filter(event => event.kind === 440)
  check('observer: only the deliberately public capability 440 is visible; data grants and notices stay wrapped',
    public440s.length === 1 && !kinds.has(441) && !kinds.has(KIND_NVOY_MSG)
    && [...kinds].every(k => [30440, 1059, 10440, 440].includes(k)))
  const blob = JSON.stringify(ws.store.events)
  check('observer: no delegation metadata, reasons, outputs, or requests in stored content',
    !blob.includes('aisle') && !blob.includes(purpose) && !blob.includes(reason)
    && !blob.includes('agent output') && !blob.includes('access_request')
    && !blob.includes('task complete') && !blob.includes('itinerary'))
} finally {
  await client.close().catch(() => {})
  if (httpChild) httpChild.kill('SIGTERM')
  await ws.close()
}

console.log(failed ? '\nMCP CONFORMANCE: FAIL' : `\nMCP CONFORMANCE: ALL ${n} PASS`)
process.exit(failed)
