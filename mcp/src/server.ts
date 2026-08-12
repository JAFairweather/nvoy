#!/usr/bin/env node
// server.ts — Nvoy MCP server entry: one shared context (identity, relay,
// grant store, scope cache, outbox), served over stdio (default) or the
// Streamable HTTP transport (NVOY_HTTP_PORT set). Tool/resource wiring lives
// in app.ts (createNvoyServer — one instance per transport session).
//
// Transport selection (decision recorded in CLAUDE.md): stdio unless
// NVOY_HTTP_PORT is set; 0 picks an ephemeral port. HTTP binds 127.0.0.1 by
// default (NVOY_HTTP_HOST to override — the server carries delegated data
// and an agent key; exposing it is the operator's explicit act). Endpoint:
// POST/GET/DELETE /mcp, stateful sessions per the MCP spec so server →
// client update notifications (nvoy_scope_subscribe) have a stream to ride.
//
// stdout is the MCP protocol channel in stdio mode; ALL diagnostics go to
// stderr. no_persist audit (spec §5): scope plaintext exists ONLY in
// ScopeCache's in-memory Map and in MCP tool/resource results. Cache is
// scrubbed on TTL expiry (sweeper), on revocation/relinquishment, and on
// shutdown (below).

import { writeSync } from 'node:fs'
import { createServer as createHttpServer } from 'node:http'
import { randomUUID } from 'node:crypto'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { LiveRelay } from '../lib/liverelay.mjs'
import { bindIdentity, loadIdentity, loadRelays } from './identity.js'
import { GrantStore } from './grants.js'
import { ScopeCache } from './scopes.js'
import { Outbox } from './outbox.js'
import { DraftDesk } from './drafts.js'
import { createNvoyServer, sweepAutoRelinquish, type NvoyContext, type NvoyServerHandle } from './app.js'

const log = (...args: unknown[]) => console.error('[nvoy]', ...args)

// Confirm which identity this process actually holds BEFORE anything can sign or answer whoami
// (#338). Top-level await: ES2022 + NodeNext. A failure here is a refusal to start, deliberately —
// a server that cannot confirm its own identity must not act as any identity.
const identity = await bindIdentity(loadIdentity())
const relays = loadRelays()
const relay = new LiveRelay(relays)
const httpPort = process.env.NVOY_HTTP_PORT

const ctx: NvoyContext = {
  identity,
  relays,
  relay,
  grantStore: new GrantStore(relay, identity.signer),
  scopeCache: new ScopeCache(relay),
  outbox: new Outbox(relay, identity),
  drafts: new DraftDesk(relay, identity),
  transport: httpPort !== undefined ? 'http' : 'stdio',
  pollMs: Math.max(250, Number(process.env.NVOY_SUBSCRIBE_POLL_MS) || 15_000),
  log,
}

log(`agent ${identity.npub} (key source: ${identity.source}, identity confirmed with the signer)`)
log(`relays: ${relays.join(', ')}`)

// ---------------------------------------------------------------- lifecycle

const handles = new Set<NvoyServerHandle>()

// auto_relinquish (§6.6): runtime-side expiry watcher — boot sweep plus an
// interval while the process lives. Granularity is the sweep period (default
// 30s, NVOY_SWEEP_MS for tests); hard expiry remains the delegator's TTL
// rotation, never agent cooperation.
const sweepMs = Math.max(100, Number(process.env.NVOY_SWEEP_MS) || 30_000)
const sweeper = setInterval(() => void sweepAutoRelinquish(ctx).catch(() => {}), sweepMs)
sweeper.unref?.()

// no_persist (§5): zeroize cached plaintext + all held scope keys on ANY
// exit path — signals and normal termination alike. The 'exit' handler is
// the sync backstop (double-run guarded); signal handlers log the fact so
// the conformance test can observe it.
let downed = false
function teardown(): void {
  if (downed) return
  downed = true
  clearInterval(sweeper)
  for (const h of handles) h.cleanup()
  ctx.scopeCache.destroy()
  ctx.grantStore.zeroizeAll()
  ctx.outbox.zeroizeAll()
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

// --------------------------------------------------------------- transports

if (httpPort === undefined) {
  // stdio: single session for the lifetime of the process.
  const handle = createNvoyServer(ctx)
  handles.add(handle)
  await handle.server.connect(new StdioServerTransport())
  log('MCP server ready on stdio')
  void sweepAutoRelinquish(ctx).catch(() => {})
} else {
  // Streamable HTTP: stateful sessions — each initialize creates a transport
  // + server instance pair, so subscribe notifications reach the session
  // that armed them. Shared stores keep grants/cache/revocations process-wide.
  const host = process.env.NVOY_HTTP_HOST || '127.0.0.1'
  const sessions = new Map<string, { transport: StreamableHTTPServerTransport; handle: NvoyServerHandle }>()

  const dropSession = (sid: string) => {
    const s = sessions.get(sid)
    if (!s) return
    sessions.delete(sid)
    s.handle.cleanup()
    handles.delete(s.handle)
    log(`http session closed: ${sid}`)
  }

  const httpServer = createHttpServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
      if (url.pathname !== '/mcp' && url.pathname !== '/') {
        res.writeHead(404, { 'content-type': 'text/plain' }).end('not found — MCP endpoint is /mcp')
        return
      }
      const sid = req.headers['mcp-session-id'] as string | undefined
      const existing = sid ? sessions.get(sid) : undefined
      if (existing) {
        if (req.method === 'DELETE') {
          await existing.transport.handleRequest(req, res)
          dropSession(sid!)
          return
        }
        await existing.transport.handleRequest(req, res)
        return
      }
      if (req.method !== 'POST') {
        res.writeHead(400, { 'content-type': 'text/plain' }).end('missing or unknown mcp-session-id')
        return
      }
      // New session: must be an initialize request.
      const handle = createNvoyServer(ctx)
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          sessions.set(id, { transport, handle })
          handles.add(handle)
          log(`http session opened: ${id}`)
        },
        onsessionclosed: (id) => dropSession(id),
      })
      transport.onclose = () => {
        if (transport.sessionId) dropSession(transport.sessionId)
      }
      await handle.server.connect(transport)
      await transport.handleRequest(req, res)
    } catch (e) {
      log(`http request failed: ${String((e as Error).message)}`)
      if (!res.headersSent) res.writeHead(500).end()
    }
  })

  await new Promise<void>((resolve) => httpServer.listen(Number(httpPort), host, resolve))
  const addr = httpServer.address()
  const port = typeof addr === 'object' && addr ? addr.port : httpPort
  log(`MCP server ready on http://${host}:${port}/mcp (streamable HTTP)`)
  void sweepAutoRelinquish(ctx).catch(() => {})
}
