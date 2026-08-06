// app.ts — the Nvoy MCP server factory: tools + resources wired onto shared
// stores. server.ts builds ONE shared context (identity, relay, grant store,
// scope cache) and calls createNvoyServer once per transport session — one
// instance for stdio, one per Streamable HTTP session — so notifications go
// to the right client while grants/cache/revocations stay process-wide.
//
// Tools (spec §6.2): nvoy_whoami, nvoy_grants_list, nvoy_capabilities_list, nvoy_scope_read,
// nvoy_scope_subscribe, nvoy_outbox_write, nvoy_request_access,
// nvoy_grant_relinquish.
// Resources: nvoy://{author_npub}/{d} — one per active held grant.
//
// no_persist audit (spec §5): scope plaintext exists ONLY in ScopeCache's
// in-memory Map and in MCP tool/resource results (the model context — the
// whole point). Nothing here writes scope data to disk, and ctx.log() must
// never be handed scope payloads.

import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'
import { nip19 } from 'nostr-tools'
import { KIND_DATA_SET, type RelayLike } from '../lib/nipxx.mjs'
import { requireLocalKey, type Identity } from './identity.js'
import { GrantStore, findRevocationNotice, grantStatus, toHexPubkey, type HeldGrant } from './grants.js'
import { ScopeCache } from './scopes.js'
import { Outbox } from './outbox.js'
import { DraftDesk } from './drafts.js'
import { sendAccessRequest, sendRelinquishNotice } from './notices.js'
import { registerChatTools } from './chat.js'
import { cascadeDerivedRevocation, issueDerivedGrant, RedelegationForbidden } from './subgrants.js'
import { readHeldCapabilities } from './capabilities.js'

export interface NvoyContext {
  identity: Identity
  relays: string[]
  relay: RelayLike
  grantStore: GrantStore
  scopeCache: ScopeCache
  outbox: Outbox
  drafts: DraftDesk
  /** which transport this server instance speaks (shapes subscribe behavior) */
  transport: 'stdio' | 'http'
  /** subscription poll interval (ms); NVOY_SUBSCRIBE_POLL_MS, default 15s */
  pollMs: number
  log: (...args: unknown[]) => void
}

const nowSec = () => Math.floor(Date.now() / 1000)

const json = (obj: unknown) => ({
  content: [{ type: 'text' as const, text: JSON.stringify(obj, null, 2) }],
})
const jsonError = (obj: unknown) => ({ ...json(obj), isError: true })

function grantSummary(g: HeldGrant) {
  return {
    d: g.scopeId,
    author_npub: nip19.npubEncode(g.publisher),
    scope_name: g.scopeName ?? null,
    purpose: g.terms?.purpose ?? null,
    expires_at: g.terms?.expires_at ?? g.expiration ?? null,
    terms: g.terms,
    v: g.generation,
    status: grantStatus(g),
    ...(g.revoked ? { revocation: { detected_at: g.revoked.detected_at, notice: g.revoked.notice } } : {}),
    ...(g.relinquished ? { relinquishment: { destroyed_at: g.relinquished.destroyed_at, reason: g.relinquished.reason ?? null } } : {}),
  }
}

/** The §6.3 error: verified rotation past this grant. Nothing leaks about why
 *  beyond what the publisher chose to say in the (optional) 441 notice. */
function revokedError(g: HeldGrant, notice: unknown) {
  return jsonError({
    code: 'NVOY_GRANT_REVOKED',
    d: g.scopeId,
    author_npub: nip19.npubEncode(g.publisher),
    notice: notice ?? null,
    message:
      'the delegator rotated this scope key past your grant — access is revoked; cached data and key material have been destroyed',
  })
}

/** Query the raw 30440 event (no decrypt — ciphertext metadata only). */
async function scopeEvent(ctx: NvoyContext, publisher: string, scopeId: string) {
  const [event] = await ctx.relay.query({ kinds: [KIND_DATA_SET], authors: [publisher], '#d': [scopeId] })
  return event as { id: string; tags: string[][] } | undefined
}

const eventGeneration = (ev: { tags: string[][] } | undefined) =>
  Number(ev?.tags.find((t) => t[0] === 'v')?.[1] ?? 0)

/**
 * Detect-and-seal a revocation (§6.3): look for a gift-wrapped kind-441
 * notice, mark the grant revoked-detected, and zeroize the scope key and any
 * cached plaintext.
 */
export async function detectRevocation(ctx: NvoyContext, g: HeldGrant) {
  const found = await findRevocationNotice(ctx.relay, ctx.identity.signer, g.publisher, g.scopeId).catch(() => null)
  const record = ctx.grantStore.markRevoked(g.publisher, g.scopeId, g.generation, found?.content ?? null)
  ctx.scopeCache.zeroize(g.publisher, g.scopeId)
  // This identity may have issued attenuated descendants of the dead grant.  Cascading is
  // ordinary auditable code under the issuer's Bunker signer; a child never keeps its old key
  // merely because the issuing runtime restarted.
  try {
    const cascade = await cascadeDerivedRevocation(ctx.relay, ctx.identity, g)
    if (cascade.cascaded) ctx.log(`derived cascade: ${cascade.cascaded} child scope(s) severed from ${g.scopeId}`)
  } catch (e) { ctx.log(`derived cascade for ${g.scopeId} failed; parent remains revoked: ${String((e as Error).message)}`) }
  ctx.log(`grant revoked-detected: scope ${g.scopeId} (v${g.generation} superseded) — key + cache zeroized`)
  return record
}

/**
 * Relinquish a held grant (§6.6 phase 1): zeroize the scope key and cached
 * plaintext, mark the grant relinquished, and send the gift-wrapped notice
 * to the delegator's contact (falling back to the scope publisher). Shared
 * by the nvoy_grant_relinquish tool and the auto_relinquish sweeper.
 */
export async function relinquishGrant(
  ctx: NvoyContext,
  g: HeldGrant,
  reason?: string,
): Promise<{ destroyed_at: number; notice_sent: boolean }> {
  const destroyed_at = nowSec()
  ctx.scopeCache.zeroize(g.publisher, g.scopeId)
  ctx.grantStore.markRelinquished(g.publisher, g.scopeId, g.generation, destroyed_at, reason)
  let notice_sent = false
  try {
    let recipient = g.publisher
    if (g.terms?.contact) {
      try { recipient = toHexPubkey(g.terms.contact) } catch { /* malformed contact → publisher */ }
    }
    await sendRelinquishNotice(ctx.relay, requireLocalKey(ctx.identity, 'grant relinquish notice'), recipient, {
      publisher: g.publisher, scopeId: g.scopeId, reason, destroyed_at,
    })
    notice_sent = true
  } catch (e) {
    // Key destruction is unilateral and already done; the notice is the
    // finalization request and can fail on a flaky relay without undoing it.
    ctx.log(`relinquish notice for scope ${g.scopeId} failed to send: ${String((e as Error).message)}`)
  }
  ctx.log(`grant relinquished: scope ${g.scopeId} (v${g.generation}) — key + cache zeroized${notice_sent ? ', notice sent' : ''}`)
  return { destroyed_at, notice_sent }
}

/**
 * auto_relinquish sweep (§6.6): relinquish any held grant whose terms carry
 * auto_relinquish and whose expires_at has passed. Called at boot and on an
 * interval while the runtime is up — the runtime-side half of expiry; the
 * delegator's TTL rotation is the cryptographic half.
 */
export async function sweepAutoRelinquish(ctx: NvoyContext): Promise<number> {
  let done = 0
  const grants = await ctx.grantStore.list().catch(() => [] as HeldGrant[])
  for (const g of grants) {
    if (g.revoked || g.relinquished) continue
    if (!g.terms?.auto_relinquish) continue
    if (grantStatus(g) !== 'expired') continue
    await relinquishGrant(ctx, g, 'auto_relinquish: term expiry reached')
    done++
  }
  return done
}

export interface NvoyServerHandle {
  server: McpServer
  /** stop this instance's subscription pollers (session close / shutdown) */
  cleanup: () => void
}

export function createNvoyServer(ctx: NvoyContext): NvoyServerHandle {
  const server = new McpServer({ name: 'nvoy', version: '0.1.0' })

  // Per-instance subscription pollers: notifications must reach the session
  // that asked for them. key = `${publisher}:${scopeId}`.
  const pollers = new Map<string, NodeJS.Timeout>()
  const cleanup = () => {
    for (const t of pollers.values()) clearInterval(t)
    pollers.clear()
  }

  // ------------------------------------------------------------------ tools

  server.registerTool(
    'nvoy_whoami',
    {
      title: 'Who am I',
      description:
        'The agent\'s nostr identity: npub (its address — what a delegator grants to), relay set, and kind-0 metadata if published.',
    },
    async () => {
      let metadata: unknown = null
      try {
        const [ev] = await ctx.relay.query({ kinds: [0], authors: [ctx.identity.pubkey] })
        if (ev) metadata = JSON.parse(ev.content)
      } catch {
        /* metadata is optional */
      }
      return json({ npub: ctx.identity.npub, pubkey: ctx.identity.pubkey, relays: ctx.relays, metadata })
    },
  )

  server.registerTool(
    'nvoy_grants_list',
    {
      title: 'List held data grants',
      description:
        'DATA grants only. Every NIP-DA data grant this agent holds: scope id (d), author, purpose, terms, key generation (v), and status (active | expired per expires_at | revoked-detected after a verified key rotation | relinquished after this agent destroyed its own key). ' +
        'It does NOT report capability grants: a channel admission or a tasking authority is a PUBLIC kind-440 carrying a da-cap tag, which this tool cannot see. ' +
        'So an empty result means "no data grants", never "no authority" — an agent can hold live admissions and still read [] here. To answer "am I still admitted?", read the public 440s naming your key off the relays; that check needs no key at all.',
    },
    async () => {
      const grants = await ctx.grantStore.list()
      return json({ grants: grants.map(grantSummary) })
    },
  )

  server.registerTool(
    'nvoy_capabilities_list',
    {
      title: 'List held capability grants',
      description:
        'Keyless cold read of public NIP-DA capability grants naming this identity, including channel admission and task authority. ' +
        'Verifies grant signatures, resolves same-author public 441 revocations, reports relay EOSE coverage, and returns an explicit unverifiable state rather than an empty list when no relay answers.',
    },
    async () => json(await readHeldCapabilities(ctx.relays, ctx.identity.pubkey)),
  )

  server.registerTool(
    'nvoy_scope_read',
    {
      title: 'Read a delegated scope',
      description:
        'Dereference a granted scope at call time: fetch the current encrypted data set from relays and decrypt it. Returns the scope JSON plus { v, fetched_at, terms }. Reads pass through a short memory-only cache; max_age: 0 forces a fresh fetch.',
      inputSchema: {
        d: z.string().describe('scope id (the d tag from nvoy_grants_list)'),
        author_npub: z.string().describe('the delegator, as npub or hex pubkey'),
        max_age: z
          .number()
          .min(0)
          .optional()
          .describe('max acceptable cache age in seconds; 0 forces a fresh relay fetch'),
      },
    },
    async ({ d, author_npub, max_age }) => {
      let author: string
      try {
        author = toHexPubkey(author_npub)
      } catch (e) {
        return jsonError({ code: 'NVOY_BAD_INPUT', message: String((e as Error).message) })
      }
      const grant = await ctx.grantStore.find(author, d)
      if (!grant) {
        return jsonError({
          code: 'NVOY_NO_GRANT',
          message: `this agent holds no grant for scope ${d} from ${author_npub}`,
          d,
          author_npub,
        })
      }
      const status = grantStatus(grant)
      if (status === 'revoked-detected') return revokedError(grant, grant.revoked?.notice ?? null)
      if (status === 'relinquished') {
        // The key was destroyed locally (§6.6 phase 1). If the delegator has
        // since rotated (phase 2), report the severance as the revocation it
        // now is; otherwise stay honest about who destroyed what.
        const ev = await scopeEvent(ctx, grant.publisher, d).catch(() => undefined)
        if (ev && eventGeneration(ev) > grant.generation) {
          const record = await detectRevocation(ctx, grant)
          return revokedError(grant, record.notice)
        }
        return jsonError({
          code: 'NVOY_GRANT_RELINQUISHED',
          d,
          author_npub,
          destroyed_at: grant.relinquished?.destroyed_at ?? null,
          message: 'this agent relinquished the grant — its key material was destroyed locally; ask the delegator to re-delegate if access is needed again',
        })
      }
      if (status === 'expired') {
        // Soft expiry (§4): the runtime honors expires_at mechanically; hard
        // expiry is the delegator's TTL rotation, never agent cooperation.
        return jsonError({
          code: 'NVOY_GRANT_EXPIRED',
          d,
          author_npub,
          expires_at: grant.terms?.expires_at ?? grant.expiration ?? null,
          message: 'this grant has expired per its terms; ask the delegator to renew',
        })
      }
      const result = await ctx.scopeCache.read(grant, { maxAgeSec: max_age })
      if (result.status === 'stale') {
        // v-supersession or MAC failure on a previously-readable scope,
        // observed on a fresh 30440 fetch → the key was rotated past us (§6.3).
        const record = await detectRevocation(ctx, grant)
        return revokedError(grant, record.notice)
      }
      if (result.status !== 'ok') {
        // 'missing' is ambiguous: scope deleted (NIP-09 after tombstone) or
        // relay flake. A 441 notice disambiguates to revocation; otherwise
        // stay honest with UNAVAILABLE.
        const found = await findRevocationNotice(ctx.relay, ctx.identity.signer, grant.publisher, d).catch(() => null)
        if (found) {
          const record = await detectRevocation(ctx, grant)
          return revokedError(grant, record.notice)
        }
        return jsonError({
          code: 'NVOY_SCOPE_UNAVAILABLE',
          status: result.status,
          d,
          author_npub,
          message: 'no scoped data set found on the configured relays',
        })
      }
      return json({
        data: result.data,
        v: result.generation,
        fetched_at: result.fetched_at,
        terms: grant.terms,
        // handling hint for downstream frameworks (§5); attests honored terms
        ...(grant.terms?.no_persist ? { nvoy_no_persist: true } : {}),
      })
    },
  )

  server.registerTool(
    'nvoy_scope_subscribe',
    {
      title: 'Subscribe to a delegated scope',
      description:
        'Watch a granted scope for live updates: polls the encrypted data set on the relays and reacts when the publisher republishes or rotates it. On the HTTP transport this streams notifications/resources/updated for the matching nvoy:// resource; on stdio it arms cache invalidation so the next nvoy_scope_read after a change is guaranteed fresh.',
      inputSchema: {
        d: z.string().describe('scope id (the d tag from nvoy_grants_list)'),
        author_npub: z.string().describe('the delegator, as npub or hex pubkey'),
      },
    },
    async ({ d, author_npub }) => {
      let author: string
      try {
        author = toHexPubkey(author_npub)
      } catch (e) {
        return jsonError({ code: 'NVOY_BAD_INPUT', message: String((e as Error).message) })
      }
      const grant = await ctx.grantStore.find(author, d)
      if (!grant) {
        return jsonError({ code: 'NVOY_NO_GRANT', d, author_npub, message: `this agent holds no grant for scope ${d} from ${author_npub}` })
      }
      const status = grantStatus(grant)
      if (status === 'revoked-detected') return revokedError(grant, grant.revoked?.notice ?? null)

      const uri = `nvoy://${nip19.npubEncode(author)}/${d}`
      const info = {
        d,
        author_npub: nip19.npubEncode(author),
        uri,
        poll_seconds: Math.round(ctx.pollMs / 1000),
        mode: ctx.transport === 'http' ? 'update-notifications' : 'cache-invalidation',
        note: ctx.transport === 'http'
          ? 'you will receive notifications/resources/updated for this uri when the scope changes'
          : 'stdio transport: no push channel is assumed — a detected change invalidates the read cache, so the next nvoy_scope_read returns fresh data',
      }
      const key = `${author}:${d}`
      if (pollers.has(key)) return json({ subscribed: true, already_subscribed: true, ...info })

      // Baseline on the raw event id: any republish (same-key update) or
      // rotation produces a new id — no decryption needed to detect change.
      let lastId: string | null = (await scopeEvent(ctx, author, d).catch(() => undefined))?.id ?? null
      const timer = setInterval(async () => {
        try {
          const ev = await scopeEvent(ctx, author, d)
          if (!ev || ev.id === lastId) return
          lastId = ev.id
          ctx.scopeCache.invalidate(author, d)
          ctx.log(`scope ${d} changed on relay (v${eventGeneration(ev)}) — cache invalidated`)
          if (ctx.transport === 'http') await server.server.sendResourceUpdated({ uri })
        } catch {
          /* transient relay failure — next tick retries */
        }
      }, ctx.pollMs)
      timer.unref?.()
      pollers.set(key, timer)
      return json({ subscribed: true, ...info })
    },
  )

  server.registerTool(
    'nvoy_derived_grant_issue',
    {
      title: 'Issue an attenuated derived grant',
      description:
        'Create a new encrypted derived scope from a parent grant and give it to one leaf identity. This is the only supported re-delegation mechanism: it requires a live parent with redelegate:true, never re-wraps the parent key, refuses no_persist parents, and bounds the child expiry to the parent. Payload is the intentionally narrowed child document, not an automatic copy of the parent.',
      inputSchema: {
        parent_d: z.string().describe('parent scope id (d) already held by this agent'),
        parent_author_npub: z.string().describe('parent delegator, as npub or hex public key'),
        grantee_npub: z.string().describe('leaf identity receiving the NEW derived scope, as npub or hex public key'),
        payload: z.record(z.unknown()).describe('attenuated JSON object for the leaf; do not copy a parent wholesale'),
        scope_name: z.string().startsWith('derived:').describe("derived scope name; must begin 'derived:'"),
        purpose: z.string().min(1).describe('specific purpose for this leaf grant'),
        expires_at: z.number().int().optional().describe('optional child expiry; required when parent has an expiry and may not exceed it'),
        allow_redelegate: z.boolean().optional().describe('default false; permit one further derived hop only when explicitly intended'),
      },
    },
    async ({ parent_d, parent_author_npub, grantee_npub, payload, scope_name, purpose, expires_at, allow_redelegate }) => {
      let publisher: string, recipient: string
      try { publisher = toHexPubkey(parent_author_npub); recipient = toHexPubkey(grantee_npub) }
      catch (e) { return jsonError({ code: 'NVOY_BAD_INPUT', message: String((e as Error).message) }) }
      const parent = await ctx.grantStore.find(publisher, parent_d)
      if (!parent) return jsonError({ code: 'NVOY_NO_GRANT', d: parent_d, author_npub: parent_author_npub, message: 'no held parent grant exists to derive from' })
      if (grantStatus(parent) !== 'active') return jsonError({ code: 'NVOY_PARENT_NOT_ACTIVE', d: parent_d, message: 'the parent grant is not active; no derived grant was issued' })
      // Force a fresh parent fetch before minting anything. A stale/missing
      // source is a hard stop, never an opportunity to sub-issue an old view.
      const fresh = await ctx.scopeCache.read(parent, { maxAgeSec: 0 })
      if (fresh.status !== 'ok') return jsonError({ code: 'NVOY_PARENT_UNAVAILABLE', d: parent_d, status: fresh.status, message: 'parent data was not freshly readable; no derived grant was issued' })
      try {
        const issued = await issueDerivedGrant(ctx.relay, ctx.identity, parent, recipient, payload, scope_name, {
          purpose, expires_at, redelegate: allow_redelegate === true,
        })
        return json({ ...issued, grantee_npub: nip19.npubEncode(recipient), parent_author_npub: nip19.npubEncode(publisher), redelegate: allow_redelegate === true })
      } catch (e) {
        const code = e instanceof RedelegationForbidden ? 'NVOY_REDELEGATION_FORBIDDEN' : 'NVOY_DERIVED_GRANT_FAILED'
        return jsonError({ code, message: String((e as Error).message) })
      }
    },
  )

  server.registerTool(
    'nvoy_outbox_write',
    {
      title: 'Write the agent outbox',
      description:
        'Publish (or update) this agent\'s own encrypted output scope and grant it back to the delegator — results come home over the same primitive pointing the other way (spec §6.5). The target is the delegator whose grant carries reply_scope_requested; pass delegator_npub explicitly when more than one qualifies. Payload must be a JSON object.',
      inputSchema: {
        payload: z.record(z.unknown()).describe('the output document (JSON object) — replaces the previous outbox content for this delegator'),
        delegator_npub: z.string().optional().describe('target delegator (npub or hex); optional when exactly one held grant requests a reply scope'),
      },
    },
    async ({ payload, delegator_npub }) => {
      let target: string | null = null
      if (delegator_npub) {
        try {
          target = toHexPubkey(delegator_npub)
        } catch (e) {
          return jsonError({ code: 'NVOY_BAD_INPUT', message: String((e as Error).message) })
        }
      } else {
        const grants = await ctx.grantStore.list()
        const requesting = [...new Set(grants
          .filter(g => grantStatus(g) === 'active' && g.terms?.reply_scope_requested)
          .map(g => g.publisher))]
        if (requesting.length === 0) {
          return jsonError({
            code: 'NVOY_NO_REPLY_TARGET',
            message: 'no active held grant carries reply_scope_requested — pass delegator_npub explicitly to write output for a specific delegator',
          })
        }
        if (requesting.length > 1) {
          return jsonError({
            code: 'NVOY_AMBIGUOUS_REPLY_TARGET',
            candidates: requesting.map(p => nip19.npubEncode(p)),
            message: 'more than one delegator requested a reply scope — pass delegator_npub',
          })
        }
        target = requesting[0]
      }
      try {
        const res = await ctx.outbox.write(target, payload)
        return json({
          written: true,
          d: res.scopeId,
          v: res.generation,
          granted_to: nip19.npubEncode(target),
          first_write: res.firstWrite,
          persisted: res.persisted,
        })
      } catch (e) {
        return jsonError({ code: 'NVOY_OUTBOX_FAILED', message: String((e as Error).message) })
      }
    },
  )

  server.registerTool(
    'nvoy_draft_publish',
    {
      title: 'Publish a draft offer',
      description:
        'Mint ONE draft offer for a sovereign desk (nvoy#28; the director-path delivery wire of nact#37): a fresh scope under a fresh key, published by this agent identity and gift-wrapped as a grant to the grantee. Per-offer scopes — unlike the outbox, which is one mutable scope per delegator. scope_name must stay in the draft: namespace; this tool mints draft offers, never arbitrary grants. Payload must be a JSON object (the Ngage desk schema: text, image, hashtags, rationale, proposedBy, proposedAt).',
      inputSchema: {
        grantee_npub: z.string().describe('who the offer is sealed to (npub or hex) — the Director'),
        payload: z.record(z.unknown()).describe('the draft document (JSON object)'),
        scope_name: z.string().optional().describe("grant scope name; defaults draft:post/<id8>; MUST start 'draft:'"),
      },
    },
    async ({ grantee_npub, payload, scope_name }) => {
      let grantee: string
      try {
        grantee = toHexPubkey(grantee_npub)
      } catch (e) {
        return jsonError({ code: 'NVOY_BAD_INPUT', message: String((e as Error).message) })
      }
      if (scope_name !== undefined && !scope_name.startsWith('draft:')) {
        return jsonError({ code: 'NVOY_BAD_INPUT', message: `scope_name '${scope_name}' is outside the draft: namespace — this tool mints draft offers only` })
      }
      try {
        const res = await ctx.drafts.publish(grantee, payload, scope_name)
        return json({ d: res.scopeId, v: res.generation, scope_name: res.scopeName, granted_to: nip19.npubEncode(grantee) })
      } catch (e) {
        return jsonError({ code: 'NVOY_DRAFT_FAILED', message: String((e as Error).message) })
      }
    },
  )

  server.registerTool(
    'nvoy_draft_withdraw',
    {
      title: 'Withdraw a draft offer',
      description:
        'Take a draft offer back: tombstone its scope (empty payload, a fresh key granted to no one, bumped generation + NIP-09), so the desk shows it withdrawn and nothing remains signable. Only offers minted THIS session are known; idempotent.',
      inputSchema: {
        d: z.string().describe('the scope id returned by nvoy_draft_publish'),
      },
    },
    async ({ d }) => {
      try {
        const res = await ctx.drafts.withdraw(d)
        if (!res) return jsonError({ code: 'NVOY_UNKNOWN_DRAFT', message: `no draft '${d}' was published this session` })
        return json({ withdrawn: true, d: res.scopeId, v: res.generation })
      } catch (e) {
        return jsonError({ code: 'NVOY_DRAFT_FAILED', message: String((e as Error).message) })
      }
    },
  )

  server.registerTool(
    'nvoy_request_access',
    {
      title: 'Request access from a delegator',
      description:
        'Send a gift-wrapped access request to a delegator: "this agent (npub) would like a data delegation for this purpose". It surfaces as a pending approval in the delegator\'s Nvoy console; the relay never sees who asked whom for what.',
      inputSchema: {
        delegator_npub: z.string().describe('the delegator to ask, as npub or hex pubkey'),
        purpose: z.string().describe('what the data is for — the contract line the delegator will see and grant under'),
      },
    },
    async ({ delegator_npub, purpose }) => {
      let target: string
      try {
        target = toHexPubkey(delegator_npub)
      } catch (e) {
        return jsonError({ code: 'NVOY_BAD_INPUT', message: String((e as Error).message) })
      }
      if (!purpose.trim()) return jsonError({ code: 'NVOY_BAD_INPUT', message: 'purpose is required — it is the contract line the delegator grants under' })
      try {
        await sendAccessRequest(ctx.relay, requireLocalKey(ctx.identity, 'access request'), target, purpose.trim())
      } catch (e) {
        return jsonError({ code: 'NVOY_REQUEST_FAILED', message: String((e as Error).message) })
      }
      return json({
        requested: true,
        delegator_npub: nip19.npubEncode(target),
        purpose: purpose.trim(),
        note: 'the request is delivered gift-wrapped; approval arrives as a normal grant — watch nvoy_grants_list',
      })
    },
  )

  server.registerTool(
    'nvoy_grant_relinquish',
    {
      title: 'Relinquish a held grant',
      description:
        'Agent self-revocation (spec §6.6): destroy this agent\'s copy of the scope key and all cached plaintext, mark the grant relinquished, and send a gift-wrapped relinquish notice to the delegator so they can rotate and make the severance cryptographically final. Call this on task completion — hygiene by default.',
      inputSchema: {
        d: z.string().describe('scope id (the d tag from nvoy_grants_list)'),
        author_npub: z.string().describe('the delegator, as npub or hex pubkey'),
        reason: z.string().optional().describe('optional line for the delegator\'s ledger, e.g. "task complete"'),
      },
    },
    async ({ d, author_npub, reason }) => {
      let author: string
      try {
        author = toHexPubkey(author_npub)
      } catch (e) {
        return jsonError({ code: 'NVOY_BAD_INPUT', message: String((e as Error).message) })
      }
      const grant = await ctx.grantStore.find(author, d)
      if (!grant) {
        return jsonError({ code: 'NVOY_NO_GRANT', d, author_npub, message: `this agent holds no grant for scope ${d} from ${author_npub}` })
      }
      if (grant.revoked) return revokedError(grant, grant.revoked.notice)
      if (grant.relinquished) {
        // idempotent: destruction already happened
        return json({ relinquished: true, already_relinquished: true, d, author_npub: nip19.npubEncode(author), destroyed_at: grant.relinquished.destroyed_at })
      }
      const { destroyed_at, notice_sent } = await relinquishGrant(ctx, grant, reason)
      return json({
        relinquished: true,
        d,
        author_npub: nip19.npubEncode(author),
        destroyed_at,
        notice_sent,
        message: 'scope key and cached plaintext destroyed; the delegator was asked to rotate, which makes the severance cryptographically final',
      })
    },
  )

  // -------------------------------------------------------------- resources

  server.registerResource(
    'nvoy-scope',
    new ResourceTemplate('nvoy://{author_npub}/{d}', {
      list: async () => {
        const grants = await ctx.grantStore.list()
        return {
          resources: grants
            .filter(g => grantStatus(g) === 'active')
            .map(g => ({
              uri: `nvoy://${nip19.npubEncode(g.publisher)}/${g.scopeId}`,
              name: g.scopeName ?? g.scopeId,
              description: g.terms?.purpose ?? `delegated scope ${g.scopeId}`,
              mimeType: 'application/json',
            })),
        }
      },
    }),
    {
      title: 'Delegated scopes',
      description: 'Active NIP-DA scoped data sets this agent holds grants for, dereferenced live.',
      mimeType: 'application/json',
    },
    async (uri, variables) => {
      const author = toHexPubkey(String(variables.author_npub))
      const d = String(variables.d)
      const grant = await ctx.grantStore.find(author, d)
      if (!grant) throw new Error(`NVOY_NO_GRANT: no grant held for ${uri.href}`)
      const status = grantStatus(grant)
      if (status === 'revoked-detected') throw new Error(`NVOY_GRANT_REVOKED: ${uri.href}`)
      if (status === 'relinquished') throw new Error(`NVOY_GRANT_RELINQUISHED: ${uri.href}`)
      if (status === 'expired') throw new Error(`NVOY_GRANT_EXPIRED: ${uri.href}`)
      const result = await ctx.scopeCache.read(grant)
      if (result.status === 'stale') {
        await detectRevocation(ctx, grant)
        throw new Error(`NVOY_GRANT_REVOKED: ${uri.href}`)
      }
      if (result.status !== 'ok') throw new Error(`NVOY_SCOPE_UNAVAILABLE (${result.status}): ${uri.href}`)
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: 'application/json',
            text: JSON.stringify({
              data: result.data,
              v: result.generation,
              fetched_at: result.fetched_at,
              terms: grant.terms,
              ...(grant.terms?.no_persist ? { nvoy_no_persist: true } : {}),
            }),
          },
        ],
      }
    },
  )

  // Conversation surface (chat.ts): public kind:1 + sealed NIP-17 DMs.
  registerChatTools(server, ctx)

  return { server, cleanup }
}
