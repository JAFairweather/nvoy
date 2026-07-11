#!/usr/bin/env node
// server.ts — the Nvoy MCP server (stdio transport, M1 read path).
//
// Tools:   nvoy_whoami, nvoy_grants_list, nvoy_scope_read
// Resources: nvoy://{author_npub}/{d} — one per active held grant
//
// stdout is the MCP protocol channel; ALL diagnostics go to stderr.

import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { nip19 } from 'nostr-tools'
import { LiveRelay } from '../../lib/liverelay.mjs'
import { loadIdentity, loadRelays } from './identity.js'
import { GrantStore, grantStatus, toHexPubkey, type HeldGrant } from './grants.js'
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
  }
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
      'All data grants this agent holds: scope id (d), author, purpose, terms, key generation (v), and status (active | expired per expires_at).',
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
    const result = await scopeCache.read(grant, { maxAgeSec: max_age })
    if (result.status !== 'ok') {
      // M2 turns the stale case into the full NVOY_GRANT_REVOKED flow
      // (fresh-fetch verification, kind-441 lookup, cache zeroization).
      return jsonError({
        code: 'NVOY_SCOPE_UNAVAILABLE',
        status: result.status,
        d,
        author_npub,
        message:
          result.status === 'stale'
            ? 'scope key superseded (v rotated past this grant) — access to updates may have been revoked'
            : 'no scoped data set found on the configured relays',
      })
    }
    return json({
      data: result.data,
      v: result.generation,
      fetched_at: result.fetched_at,
      terms: grant.terms,
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
    if (!grant) throw new Error(`no grant held for ${uri.href}`)
    const result = await scopeCache.read(grant)
    if (result.status !== 'ok') throw new Error(`scope unavailable (${result.status}) for ${uri.href}`)
    return {
      contents: [
        {
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify({ data: result.data, v: result.generation, fetched_at: result.fetched_at, terms: grant.terms }),
        },
      ],
    }
  },
)

// --------------------------------------------------------------------- main

const transport = new StdioServerTransport()
await server.connect(transport)
log('MCP server ready on stdio')
