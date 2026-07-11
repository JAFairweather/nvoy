#!/usr/bin/env node
// server.ts — the Nvoy MCP server (stdio transport, M1 read path + M2
// revocation/terms enforcement).
//
// Tools:   nvoy_whoami, nvoy_grants_list, nvoy_scope_read
// Resources: nvoy://{author_npub}/{d} — one per active held grant
//
// stdout is the MCP protocol channel; ALL diagnostics go to stderr.
// no_persist audit (spec §5): scope plaintext exists ONLY in ScopeCache's
// in-memory Map and in MCP tool/resource results on stdout (the model
// context — the whole point). Nothing here writes scope data to disk, and
// log() must never be handed scope payloads. Cache is scrubbed on TTL
// expiry (sweeper), on revocation, and on shutdown (below).

import { writeSync } from 'node:fs'
import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { nip19 } from 'nostr-tools'
import { LiveRelay } from '../../lib/liverelay.mjs'
import { loadIdentity, loadRelays } from './identity.js'
import { GrantStore, findRevocationNotice, grantStatus, toHexPubkey, type HeldGrant } from './grants.js'
import { ScopeCache } from './scopes.js'

const log = (...args: unknown[]) => console.error('[nvoy]', ...args)

const identity = loadIdentity()
const relays = loadRelays()
const relay = new LiveRelay(relays)
const grantStore = new GrantStore(relay, identity.secretKey)
const scopeCache = new ScopeCache(relay)

log(`agent ${identity.npub} (key source: ${identity.source})`)
log(`relays: ${relays.join(', ')}`)

// ------------------------------------------------------------------ helpers

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

/**
 * Detect-and-seal a revocation (§6.3): look for a gift-wrapped kind-441
 * notice, mark the grant revoked-detected, and zeroize the scope key and any
 * cached plaintext. The failed read that got us here was itself a fresh
 * 30440 fetch (failed reads are never cached), so the supersession is
 * already verified against the live event.
 */
async function detectRevocation(g: HeldGrant) {
  const found = await findRevocationNotice(relay, identity.secretKey, g.publisher, g.scopeId).catch(() => null)
  const record = grantStore.markRevoked(g.publisher, g.scopeId, g.generation, found?.content ?? null)
  scopeCache.zeroize(g.publisher, g.scopeId)
  log(`grant revoked-detected: scope ${g.scopeId} (v${g.generation} superseded) — key + cache zeroized`)
  return record
}

// -------------------------------------------------------------------- tools

const server = new McpServer({ name: 'nvoy', version: '0.1.0' })

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
      const [ev] = await relay.query({ kinds: [0], authors: [identity.pubkey] })
      if (ev) metadata = JSON.parse(ev.content)
    } catch {
      /* metadata is optional */
    }
    return json({ npub: identity.npub, pubkey: identity.pubkey, relays, metadata })
  },
)

server.registerTool(
  'nvoy_grants_list',
  {
    title: 'List held grants',
    description:
      'All data grants this agent holds: scope id (d), author, purpose, terms, key generation (v), and status (active | expired per expires_at | revoked-detected after a verified key rotation).',
  },
  async () => {
    const grants = await grantStore.list()
    return json({ grants: grants.map(grantSummary) })
  },
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
    const grant = await grantStore.find(author, d)
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
    const result = await scopeCache.read(grant, { maxAgeSec: max_age })
    if (result.status === 'stale') {
      // v-supersession or MAC failure on a previously-readable scope,
      // observed on a fresh 30440 fetch → the key was rotated past us (§6.3).
      const record = await detectRevocation(grant)
      return revokedError(grant, record.notice)
    }
    if (result.status !== 'ok') {
      // 'missing' is ambiguous: scope deleted (NIP-09 after tombstone) or
      // relay flake. A 441 notice disambiguates to revocation; otherwise
      // stay honest with UNAVAILABLE.
      const found = await findRevocationNotice(relay, identity.secretKey, grant.publisher, d).catch(() => null)
      if (found) {
        const record = await detectRevocation(grant)
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

// ---------------------------------------------------------------- resources

server.registerResource(
  'nvoy-scope',
  new ResourceTemplate('nvoy://{author_npub}/{d}', {
    list: async () => {
      const grants = await grantStore.list()
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
    const grant = await grantStore.find(author, d)
    if (!grant) throw new Error(`NVOY_NO_GRANT: no grant held for ${uri.href}`)
    const status = grantStatus(grant)
    if (status === 'revoked-detected') throw new Error(`NVOY_GRANT_REVOKED: ${uri.href}`)
    if (status === 'expired') throw new Error(`NVOY_GRANT_EXPIRED: ${uri.href}`)
    const result = await scopeCache.read(grant)
    if (result.status === 'stale') {
      await detectRevocation(grant)
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

// --------------------------------------------------------------------- main

// no_persist (§5): zeroize cached plaintext + all held scope keys on ANY
// exit path — signals and normal termination alike. The 'exit' handler is
// the sync backstop (double-run guarded); signal handlers log the fact so
// the conformance test can observe it.
let downed = false
function teardown(): void {
  if (downed) return
  downed = true
  scopeCache.destroy()
  grantStore.zeroizeAll()
  // fs.writeSync, not console.error: pipe writes are async on POSIX and a
  // process.exit right after would drop the line the no_persist conformance
  // test watches for.
  try {
    writeSync(2, '[nvoy] cache zeroized (shutdown)\n')
  } catch {
    /* stderr already gone */
  }
}
process.on('exit', teardown)
for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    teardown()
    process.exit(0)
  })
}

const transport = new StdioServerTransport()
await server.connect(transport)
log('MCP server ready on stdio')
