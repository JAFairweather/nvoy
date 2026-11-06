#!/usr/bin/env node
// memory-viewer.mjs — Read-only, phone-first web viewer for Hive Shared Memory.
//
// Security & design invariants:
//   1. Connects to ONE reader Unix domain socket (--socket /run/hive-memory/viewer.sock) over MCP
//      JSON-RPC as the keyless 'viewer' reader. Opens no other sockets and has no write paths.
//   2. Polls only `memory_wake` and `memory_query` every few seconds (--poll-ms, default 3000) and
//      streams read-only snapshots to connected browsers over Server-Sent Events (`GET /events`).
//   3. Treats every memory record strictly as untrusted data (`authority: null`, `trustedInstruction: false`):
//      escapes all HTML and JSON payloads, renders no markdown, follows or creates no links (`<a>`),
//      and sets a strict Content-Security-Policy (`default-src 'none'`).
//   4. Listen address and port come from CLI flags (`--host <addr> --port <port>` or `--listen <addr>:<port>`).
//   5. The viewer's memory_wake also carries the daemon's metadata-only activity ring and agent roster, which
//      drive the cortex canvas. Its simulation controls animate locally and never call the server.

import { createServer as createHttpServer } from 'node:http'
import { createConnection } from 'node:net'
import { isAbsolute, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'

const DEFAULT_POLL_MS = 3000
const MAX_EVENT_LOG = 60
const ACTIVITY_KINDS = new Set(['wake', 'query', 'lookup', 'submit', 'refused'])

export function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

export function safeJsonForScript(value) {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029')
}

export function parseListenTarget({ listen = '', host = '', port = '' } = {}) {
  let resolvedHost = String(host || '').trim()
  let resolvedPortStr = String(port ?? '').trim()

  if (listen) {
    const raw = String(listen).trim()
    if (raw.startsWith('[')) {
      const closeIdx = raw.indexOf(']')
      if (closeIdx < 0 || raw[closeIdx + 1] !== ':') {
        throw new Error('--listen with bracketed IPv6 must be [addr]:port')
      }
      resolvedHost = raw.slice(1, closeIdx)
      resolvedPortStr = raw.slice(closeIdx + 2)
    } else {
      const lastColon = raw.lastIndexOf(':')
      if (lastColon <= 0) throw new Error('--listen must be host:port or [ipv6]:port')
      resolvedHost = raw.slice(0, lastColon)
      resolvedPortStr = raw.slice(lastColon + 1)
    }
  }

  if (!resolvedHost || /\s/.test(resolvedHost)) {
    throw new Error('a listen address is required (--host <addr> --port <port> or --listen <addr>:<port>)')
  }
  const resolvedPort = Number(resolvedPortStr)
  if (! resolvedPortStr || !Number.isInteger(resolvedPort) || resolvedPort < 0 || resolvedPort > 65535) {
    throw new Error('--port must be an integer between 0 and 65535')
  }
  return { host: resolvedHost, port: resolvedPort }
}

export function parseViewerFlags(argv) {
  const args = Array.isArray(argv) ? argv : []
  const countFlag = name => args.filter(a => a === name).length
  if (countFlag('--socket') > 1) throw new Error('only one --socket may be specified')
  const getFlag = name => {
    const idx = args.indexOf(name)
    return idx < 0 ? '' : String(args[idx + 1] ?? '')
  }

  const socketRaw = getFlag('--socket')
  if (!socketRaw || !isAbsolute(socketRaw)) {
    throw new Error('--socket <absolute-path> is required')
  }
  const { host, port } = parseListenTarget({
    listen: getFlag('--listen'),
    host: getFlag('--host'),
    port: getFlag('--port'),
  })
  const pollRaw = getFlag('--poll-ms')
  const pollMs = pollRaw ? Number(pollRaw) : DEFAULT_POLL_MS
  if (!Number.isInteger(pollMs) || pollMs < 100 || pollMs > 300_000) {
    throw new Error('--poll-ms must be an integer between 100 and 300000')
  }
  return {
    socketPath: resolve(socketRaw),
    host,
    port,
    pollMs,
  }
}

export function sanitizeMemoryRecord(rec) {
  if (!rec || typeof rec !== 'object') return null
  return {
    record_type: 'memory-claim',
    authority: null,
    trustedInstruction: false,
    verification: String(rec.verification || 'unverified'),
    verification_reason: rec.verification_reason ? String(rec.verification_reason) : null,
    checked_at: Number.isFinite(rec.checked_at) ? Number(rec.checked_at) : null,
    computed_rank: Number.isFinite(rec.computed_rank) ? Number(rec.computed_rank) : null,
    event_id: String(rec.event_id || ''),
    author_pubkey: String(rec.author_pubkey || ''),
    scope: String(rec.scope || ''),
    d: String(rec.d || ''),
    topic: String(rec.topic || ''),
    claim: String(rec.claim || ''),
    because: String(rec.because || ''),
    evidence: Array.isArray(rec.evidence) ? rec.evidence.map(e => String(e)) : [],
    as_of_git: rec.as_of_git ? String(rec.as_of_git) : null,
    as_of_evt: rec.as_of_evt ? String(rec.as_of_evt) : null,
    created_at: Number.isFinite(rec.created_at) ? Number(rec.created_at) : null,
    expires_at: Number.isFinite(rec.expires_at) ? Number(rec.expires_at) : null,
    stale_warning: rec.stale_warning ? String(rec.stale_warning) : null,
    conflict: Boolean(rec.conflict),
  }
}

const shortStr = v => (typeof v === 'string' ? v.slice(0, 200) : null)

export function sanitizeActivity(entry) {
  if (!entry || typeof entry !== 'object' || !Number.isSafeInteger(entry.seq)) return null
  return {
    seq: entry.seq,
    at: Number.isFinite(entry.at) ? Number(entry.at) : null,
    kind: ACTIVITY_KINDS.has(entry.kind) ? entry.kind : 'other',
    actor: shortStr(entry.actor) || '',
    count: Number.isSafeInteger(entry.count) ? entry.count : null,
    event_ids: Array.isArray(entry.event_ids) ? entry.event_ids.filter(id => typeof id === 'string').map(id => id.slice(0, 64)).slice(0, 20) : [],
    d: shortStr(entry.d),
    topic: shortStr(entry.topic),
    scope: shortStr(entry.scope),
    accepted: typeof entry.accepted === 'boolean' ? entry.accepted : null,
    code: shortStr(entry.code),
  }
}

export function sanitizeRosterEntry(agent) {
  if (!agent || typeof agent !== 'object' || typeof agent.id !== 'string' || !agent.id) return null
  return {
    id: agent.id.slice(0, 64),
    pubkey: shortStr(agent.pubkey),
    is_reader: agent.is_reader === true,
    is_writer: agent.is_writer === true,
    is_owner: agent.is_owner === true,
    per_hour: Number.isSafeInteger(agent.per_hour) ? agent.per_hour : 0,
    used_last_hour: Number.isSafeInteger(agent.used_last_hour) ? agent.used_last_hour : null,
  }
}

function describeActivity(a) {
  const hidden = '(key outside the viewer ACL)'
  if (a.kind === 'wake') return `${a.actor} memory_wake: ${a.count ?? 0} records`
  if (a.kind === 'query') {
    return `${a.actor} memory_query${a.topic ? ` topic=${a.topic}` : ''}${a.scope ? ` scope=${a.scope}` : ''}: ${a.count ?? 0} records`
  }
  if (a.kind === 'lookup') return `${a.actor} lookup_prior ${a.d || hidden}`
  if (a.kind === 'submit') return `${a.actor} memory_submit accepted ${a.d || hidden}`
  if (a.kind === 'refused') return `${a.actor} refused ${a.code || 'unknown'}${a.d ? ` at ${a.d}` : ''}`
  return `${a.actor} ${a.kind}`
}

export function computeScopeCounts(wakeCounts = {}, records = []) {
  let canon = 0
  let ops = 0
  let rooms = 0
  let self = 0
  for (const r of records) {
    const scope = String(r?.scope || '')
    if (scope === 'hive:canon') canon += 1
    else if (scope === 'hive:ops') ops += 1
    else if (scope.startsWith('room:')) rooms += 1
    else if (scope.startsWith('self:')) self += 1
  }
  const canonTotal = Math.max(canon, (Number(wakeCounts.canon_shown) || 0) + (Number(wakeCounts.canon_omitted) || 0))
  const opsAndRoomsWake = (Number(wakeCounts.ops_shown) || 0) + (Number(wakeCounts.ops_omitted) || 0)
  const selfTotal = Math.max(self, (Number(wakeCounts.self_shown) || 0) + (Number(wakeCounts.self_omitted) || 0))
  return {
    canon: canonTotal,
    ops: Math.max(ops, rooms === 0 ? opsAndRoomsWake : ops),
    rooms,
    self: selfTotal,
    canon_unverified: Number(wakeCounts.canon_unverified) || 0,
    unverified_total: Number(wakeCounts.unverified_total) || 0,
  }
}

export function diffViewerSnapshots(prev, next, nowSec = Math.floor(Date.now() / 1000)) {
  const events = []
  const push = (kind, summary) => events.push({ at: nowSec, kind, summary: String(summary) })

  if (!prev) {
    push(
      'init',
      `Initial poll: store_state=${next.store_state?.state || 'UNKNOWN'}, write_seq=${next.store_state?.write_seq ?? '-'}, records=${next.records.length}`
    )
    return events
  }

  if (prev.connected !== next.connected) {
    push('socket', next.connected ? 'Reader socket connected' : `Reader socket disconnected: ${next.error || 'closed'}`)
  }

  const prevState = prev.store_state?.state || null
  const nextState = next.store_state?.state || null
  if (prevState !== nextState && nextState) {
    push('store', `store_state: ${prevState || 'NONE'} -> ${nextState}`)
  }
  if (prev.store_state?.write_seq !== next.store_state?.write_seq && Number.isSafeInteger(next.store_state?.write_seq)) {
    push('write', `write_seq: ${prev.store_state?.write_seq ?? '-'} -> ${next.store_state.write_seq}`)
  }
  if (prev.store_state?.unbacked_writes !== next.store_state?.unbacked_writes && Number.isSafeInteger(next.store_state?.unbacked_writes)) {
    push('backup', `unbacked writes: ${prev.store_state?.unbacked_writes ?? '-'} -> ${next.store_state.unbacked_writes}`)
  }

  if ((prev.scope_counts?.unverified_total || 0) !== (next.scope_counts?.unverified_total || 0)) {
    push(
      'unverified',
      `unverified claims: ${prev.scope_counts?.unverified_total || 0} -> ${next.scope_counts?.unverified_total || 0}`
    )
  }

  const prevMap = new Map()
  for (const r of prev.records || []) {
    prevMap.set(`${r.author_pubkey}:${r.d}`, r)
  }
  const nextMap = new Map()
  for (const r of next.records || []) {
    nextMap.set(`${r.author_pubkey}:${r.d}`, r)
  }

  for (const [key, r] of nextMap.entries()) {
    const old = prevMap.get(key)
    if (!old) {
      push('claim-added', `+ [${r.scope}] ${r.d} by ${r.author_pubkey.slice(0, 12)}… (${r.event_id.slice(0, 10)}…)`)
    } else if (old.event_id !== r.event_id) {
      push(
        'claim-updated',
        `~ [${r.scope}] ${r.d} updated (${old.event_id.slice(0, 8)}… -> ${r.event_id.slice(0, 8)}…)`
      )
    } else if (old.verification !== r.verification || old.conflict !== r.conflict) {
      push(
        'claim-status',
        `! [${r.scope}] ${r.d} verification=${r.verification} conflict=${r.conflict}`
      )
    }
  }

  for (const [key, old] of prevMap.entries()) {
    if (!nextMap.has(key)) {
      push('claim-removed', `- [${old.scope}] ${old.d} (${old.event_id.slice(0, 10)}…) removed/withdrawn/expired`)
    }
  }

  const maxSeq = list => list.reduce((m, a) => Math.max(m, a.seq), 0)
  const prevActivity = Array.isArray(prev.recent_activity) ? prev.recent_activity : []
  const nextActivity = Array.isArray(next.recent_activity) ? next.recent_activity : []
  const seenSeq = maxSeq(nextActivity) < maxSeq(prevActivity) ? 0 : maxSeq(prevActivity)
  for (const a of nextActivity) {
    if (a.seq > seenSeq) push(`activity-${a.kind}`, describeActivity(a))
  }

  return events
}

// Single-socket MCP client over the viewer's Unix domain socket.
export function createSingleSocketMcpClient(socketPath) {
  let socket = null
  let connected = false
  let initialized = false
  let serverName = null
  let nextId = 1
  const pending = new Map()
  let connectPromise = null

  function failAll(err) {
    for (const [, entry] of pending.entries()) {
      clearTimeout(entry.timer)
      entry.reject(err)
    }
    pending.clear()
  }

  function disconnect() {
    connected = false
    initialized = false
    if (socket) {
      try {
        socket.destroy()
      } catch {
        /* ignore */
      }
      socket = null
    }
  }

  function sendRaw(obj, timeoutMs = 5000) {
    return new Promise((resolveReq, rejectReq) => {
      if (!socket || !connected) {
        rejectReq(new Error('viewer socket is not connected'))
        return
      }
      const id = nextId++
      const timer = setTimeout(() => {
        pending.delete(id)
        rejectReq(new Error(`MCP request ${obj.method} timed out`))
      }, timeoutMs)
      pending.set(id, { resolve: resolveReq, reject: rejectReq, timer })
      socket.write(JSON.stringify({ jsonrpc: '2.0', id, ...obj }) + '\n')
    })
  }

  async function ensureConnected() {
    if (connected && initialized && socket) return
    if (connectPromise) return connectPromise
    connectPromise = (async () => {
      disconnect()
      await new Promise((resolveConn, rejectConn) => {
        const sock = createConnection(socketPath)
        let settled = false
        sock.once('connect', () => {
          settled = true
          socket = sock
          connected = true
          resolveConn()
        })
        sock.once('error', err => {
          if (!settled) {
            settled = true
            rejectConn(err)
          } else {
            failAll(err)
            disconnect()
          }
        })
        sock.once('close', () => {
          failAll(new Error('viewer socket closed'))
          disconnect()
        })
        const rl = createInterface({ input: sock, crlfDelay: Infinity })
        rl.on('line', line => {
          if (!line.trim()) return
          let msg
          try {
            msg = JSON.parse(line)
          } catch {
            return
          }
          if (msg && msg.id !== undefined && pending.has(msg.id)) {
            const entry = pending.get(msg.id)
            pending.delete(msg.id)
            clearTimeout(entry.timer)
            if (msg.error) entry.reject(new Error(msg.error.message || 'MCP error'))
            else entry.resolve(msg.result)
          }
        })
      })

      const initRes = await sendRaw({
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'hive-memory-viewer', version: '0.1.0' },
        },
      })
      serverName = initRes?.serverInfo?.name ? String(initRes.serverInfo.name) : 'hive-memory-viewer'
      if (socket && connected) {
        socket.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} }) + '\n')
      }
      initialized = true
    })().finally(() => {
      connectPromise = null
    })
    return connectPromise
  }

  async function callReadTool(name, args = {}) {
    if (name !== 'memory_wake' && name !== 'memory_query') {
      throw new Error(`refusing non-read tool in memory-viewer: ${name}`)
    }
    await ensureConnected()
    const res = await sendRaw({
      method: 'tools/call',
      params: { name, arguments: args },
    })
    if (res?.isError) {
      throw new Error(res?.content?.[0]?.text || `tool ${name} returned error`)
    }
    const text = res?.content?.[0]?.text || '{}'
    return JSON.parse(text)
  }

  return {
    callReadTool,
    getServerName: () => serverName,
    close: disconnect,
  }
}

export function renderViewerHtml(initialState) {
  const escapedInitial = safeJsonForScript(initialState)
  const syncState = escapeHtml(initialState.store_state?.state || 'CONNECTING')
  const readerName = escapeHtml(initialState.reader || 'viewer')
  const serverName = escapeHtml(initialState.server_name || 'hive-memory-viewer')

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>Hive Memory Viewer (Read-Only)</title>
  <style>
    :root {
      --bg: #040711;
      --panel: rgba(11, 17, 32, 0.84);
      --panel-solid: #131b29;
      --panel-alt: #182234;
      --border: rgba(99, 130, 190, 0.26);
      --border-bright: rgba(125, 211, 252, 0.48);
      --text: #e6edf7;
      --muted: #93a4bf;
      --ok: #22c55e;
      --ok-bg: rgba(34, 197, 94, 0.14);
      --warn: #f59e0b;
      --warn-bg: rgba(245, 158, 11, 0.15);
      --err: #ef4444;
      --err-bg: rgba(239, 68, 68, 0.15);
      --info: #38bdf8;
      --info-bg: rgba(56, 189, 248, 0.14);
      --canon: #fbbf24;
      --decision: #a78bfa;
      --fresh: #38bdf8;
      --aging: #f59e0b;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: radial-gradient(circle at 50% 48%, #0a1329 0%, #050914 60%, #02040a 100%) fixed;
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-size: 14px;
      line-height: 1.45;
      -webkit-text-size-adjust: 100%;
    }
    body[data-view="graph"] { height: 100vh; overflow: hidden; }
    body[data-view="graph"] .cards-only { display: none; }
    body[data-view="cards"] .graph-only { display: none; }
    body[data-view="cards"] { padding: 12px; }
    #stage-wrap { position: fixed; inset: 0; }
    canvas#cortex { width: 100%; height: 100%; display: block; cursor: grab; touch-action: none; }
    .panel {
      background: var(--panel);
      -webkit-backdrop-filter: blur(14px);
      backdrop-filter: blur(14px);
      border: 1px solid var(--border);
      border-radius: 12px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.45);
    }
    .hud-top {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 10px;
      flex-wrap: wrap;
      z-index: 20;
    }
    body[data-view="graph"] .hud-top { position: fixed; top: 12px; left: 12px; right: 12px; pointer-events: none; }
    body[data-view="cards"] .hud-top { max-width: 760px; margin: 0 auto 12px; flex-direction: column; align-items: stretch; }
    .hud-top > * { pointer-events: auto; }
    .brand-card { padding: 10px 14px; display: flex; gap: 12px; align-items: flex-start; max-width: 100%; }
    .brain-orb {
      width: 30px;
      height: 30px;
      margin-top: 2px;
      border-radius: 50%;
      flex-shrink: 0;
      background: radial-gradient(circle at 35% 35%, #7dd3fc, #6366f1 55%, #1e1b4b 100%);
      box-shadow: 0 0 18px rgba(56, 189, 248, 0.55);
    }
    .brand-text { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
    h1 { margin: 0; font-size: 16px; font-weight: 700; letter-spacing: -0.01em; }
    .badges { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
    .quarantine-banner {
      font-family: var(--mono);
      font-size: 11px;
      padding: 5px 8px;
      border-radius: 6px;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid var(--border);
      color: var(--muted);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 600;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: var(--panel-alt);
      color: var(--text);
      white-space: nowrap;
    }
    .badge.ok { color: #86efac; background: var(--ok-bg); border-color: rgba(34, 197, 94, 0.4); }
    .badge.warn { color: #fcd34d; background: var(--warn-bg); border-color: rgba(245, 158, 11, 0.4); }
    .badge.err { color: #fca5a5; background: var(--err-bg); border-color: rgba(239, 68, 68, 0.4); }
    .badge.info { color: #7dd3fc; background: var(--info-bg); border-color: rgba(56, 189, 248, 0.4); }
    .badge.sim { color: #fde68a; background: rgba(245, 158, 11, 0.12); border: 1px dashed rgba(251, 191, 36, 0.6); }
    .telemetry-strip { display: flex; gap: 16px; padding: 8px 14px; flex-wrap: wrap; }
    .metric { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
    .metric-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
    .metric-val { font-family: var(--mono); font-size: 14px; font-weight: 700; word-break: break-word; }
    .metric-sub { font-family: var(--mono); font-size: 10.5px; color: var(--muted); word-break: break-word; }
    .hud-left, .hud-right {
      position: fixed;
      top: var(--hud-top, 150px);
      bottom: var(--hud-bottom, 96px);
      display: flex;
      flex-direction: column;
      gap: 10px;
      z-index: 15;
      pointer-events: none;
    }
    .hud-left { left: 12px; width: 268px; }
    .hud-right { right: 12px; width: 330px; }
    .hud-left > *, .hud-right > * { pointer-events: auto; }
    .glass-box { padding: 10px 12px; min-height: 0; }
    .box-title {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: var(--muted);
      margin-bottom: 8px;
      display: flex;
      justify-content: space-between;
      gap: 8px;
    }
    .mini { font-family: var(--mono); font-size: 10px; color: #7dd3fc; text-transform: none; letter-spacing: 0; }
    .agent-list { display: flex; flex-direction: column; gap: 4px; max-height: 22vh; overflow-y: auto; }
    .agent-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding: 5px 8px;
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.025);
      border: 1px solid transparent;
      cursor: pointer;
    }
    .agent-row:hover, .agent-row.active { background: rgba(56, 189, 248, 0.1); border-color: var(--border-bright); }
    .agent-ident { display: flex; align-items: center; gap: 8px; min-width: 0; }
    .agent-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
    .agent-name { font-size: 12.5px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .agent-model { font-family: var(--mono); font-size: 9.5px; color: var(--muted); }
    .agent-stats { font-family: var(--mono); font-size: 10.5px; white-space: nowrap; }
    .legend-grid { display: flex; flex-direction: column; gap: 5px; font-size: 11.5px; color: var(--muted); }
    .legend-item { display: flex; align-items: center; gap: 8px; }
    .shape { width: 11px; height: 11px; flex-shrink: 0; }
    .shape.canon { background: var(--canon); transform: rotate(45deg); border-radius: 2px; box-shadow: 0 0 8px var(--canon); }
    .shape.decision { background: var(--decision); transform: rotate(45deg); box-shadow: 0 0 8px var(--decision); }
    .shape.fresh { background: var(--fresh); border-radius: 50%; box-shadow: 0 0 8px var(--fresh); }
    .shape.aging { background: var(--aging); border-radius: 50%; box-shadow: 0 0 8px var(--aging); }
    .feed-box { flex: 1; display: flex; flex-direction: column; }
    .stream-list { font-family: var(--mono); font-size: 10.5px; display: flex; flex-direction: column; gap: 4px; overflow-y: auto; min-height: 0; }
    .stream-item {
      padding: 4px 7px;
      border-radius: 6px;
      background: rgba(0, 0, 0, 0.28);
      border-left: 2.5px solid #38bdf8;
      color: #cbd5e1;
      word-break: break-word;
    }
    .stream-item.write { border-left-color: #34d399; }
    .stream-item.lookup { border-left-color: #a78bfa; }
    .stream-item.refuse { border-left-color: #f87171; }
    .stream-item.sim { border-left-style: dashed; border-left-color: #fbbf24; color: #fde68a; }
    .inspector { flex: 0 1 auto; min-height: 0; overflow-y: auto; display: flex; flex-direction: column; gap: 9px; }
    .inspect-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; border-bottom: 1px solid var(--border); padding-bottom: 7px; }
    .inspect-kicker { font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
    .inspect-title { font-family: var(--mono); font-size: 13px; font-weight: 700; color: #93c5fd; word-break: break-word; }
    .kv-list { display: flex; flex-direction: column; font-family: var(--mono); font-size: 11px; }
    .kv-row { display: flex; justify-content: space-between; gap: 8px; padding: 4px 0; border-bottom: 1px dashed rgba(255, 255, 255, 0.06); }
    .kv-key { color: var(--muted); flex-shrink: 0; }
    .kv-val { text-align: right; word-break: break-all; }
    .ttl-bar-wrap { background: rgba(255, 255, 255, 0.07); height: 7px; border-radius: 999px; overflow: hidden; margin-top: 4px; }
    .ttl-bar-fill { height: 100%; border-radius: 999px; }
    .hud-bottom {
      position: fixed;
      bottom: 12px;
      left: 12px;
      right: 12px;
      display: flex;
      justify-content: space-between;
      gap: 10px;
      flex-wrap: wrap;
      z-index: 20;
      pointer-events: none;
    }
    .hud-bottom > * { pointer-events: auto; }
    .control-bar { padding: 8px 12px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-family: var(--mono); font-size: 11.5px; }
    .sim-bar { border-style: dashed; border-color: rgba(251, 191, 36, 0.55); }
    .sim-label { font-size: 10.5px; font-weight: 700; color: #fde68a; text-transform: uppercase; letter-spacing: 0.05em; }
    button.btn {
      font-family: var(--sans);
      font-size: 12px;
      font-weight: 600;
      color: var(--text);
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 6px 10px;
      cursor: pointer;
    }
    button.btn:hover { background: rgba(56, 189, 248, 0.16); border-color: var(--border-bright); }
    button.btn.sim { border-style: dashed; border-color: rgba(251, 191, 36, 0.55); color: #fde68a; }
    input[type="range"] { accent-color: #38bdf8; width: 140px; }
    #time-label { min-width: 96px; color: #7dd3fc; font-weight: 700; }
    .wrap { max-width: 760px; margin: 0 auto; display: flex; flex-direction: column; gap: 12px; }
    .grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    @media (min-width: 560px) {
      .grid-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    }
    .card { background: var(--panel-solid); border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; }
    .card-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); margin-bottom: 4px; }
    .card-val { font-family: var(--mono); font-size: 16px; font-weight: 700; word-break: break-word; }
    .card-sub { font-family: var(--mono); font-size: 11px; color: var(--muted); margin-top: 3px; word-break: break-word; }
    section { background: var(--panel-solid); border: 1px solid var(--border); border-radius: 12px; padding: 12px 14px; }
    h2 { margin: 0 0 10px 0; font-size: 14px; font-weight: 600; display: flex; align-items: center; justify-content: space-between; }
    .record-list { display: flex; flex-direction: column; gap: 10px; }
    .record {
      background: var(--panel-alt);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 12px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .record-head { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
    .record-key { font-family: var(--mono); font-size: 12px; font-weight: 700; color: #93c5fd; word-break: break-all; }
    .record-claim {
      font-family: var(--mono);
      font-size: 13px;
      color: var(--text);
      white-space: pre-wrap;
      word-break: break-word;
      background: rgba(0, 0, 0, 0.25);
      padding: 8px;
      border-radius: 6px;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }
    .record-meta { font-family: var(--mono); font-size: 11px; color: var(--muted); display: flex; flex-direction: column; gap: 3px; word-break: break-all; }
    .empty {
      font-family: var(--mono);
      font-size: 12px;
      color: var(--muted);
      padding: 12px;
      text-align: center;
      border: 1px dashed var(--border);
      border-radius: 8px;
    }
    .log-list { font-family: var(--mono); font-size: 11px; display: flex; flex-direction: column; gap: 5px; max-height: 240px; overflow-y: auto; }
    .log-row { padding: 5px 8px; border-radius: 6px; background: var(--panel-alt); border: 1px solid var(--border); word-break: break-word; }
    .log-time { color: var(--muted); margin-right: 6px; }
    @media (max-width: 1024px) {
      .hud-left { display: none; }
      .hud-right { width: 290px; }
    }
    @media (max-width: 680px) {
      body[data-view="graph"] .telemetry-strip { display: none; }
      .quarantine-banner { font-size: 10px; }
      .hud-right { top: auto; left: 12px; right: 12px; width: auto; max-height: 32vh; }
      .inspector.idle { display: none; }
      .control-bar { padding: 6px 8px; gap: 6px; }
      button.btn { padding: 5px 8px; font-size: 11px; }
      input[type="range"] { width: 100px; }
    }
  </style>
</head>
<body data-view="graph">
  <div id="stage-wrap" class="graph-only"><canvas id="cortex" aria-label="Hive memory cortex graph"></canvas></div>

  <header class="hud-top">
    <div class="brand-card panel">
      <div class="brain-orb"></div>
      <div class="brand-text">
        <h1>Hive Shared Memory · Cortex Observatory</h1>
        <div class="badges">
          <span id="sse-badge" class="badge info">SSE: connecting</span>
          <span id="sync-badge" class="badge">${syncState}</span>
          <button id="view-toggle" class="btn" type="button">Raw cards</button>
        </div>
        <div class="quarantine-banner">
          reader: <span id="reader-name">${readerName}</span> (<span id="server-name">${serverName}</span>) |
          DATA ONLY: authority=null, trustedInstruction=false | read-only socket
        </div>
      </div>
    </div>
    <div class="telemetry-strip panel">
      <div class="metric">
        <span class="metric-label">Store State</span>
        <span id="sync-state" class="metric-val">${syncState}</span>
        <span id="sync-sub" class="metric-sub">waiting for poll…</span>
      </div>
      <div class="metric">
        <span class="metric-label">Write Seq</span>
        <span id="seq-val" class="metric-val">-</span>
        <span id="seq-sub" class="metric-sub">current claims: -</span>
      </div>
      <div class="metric">
        <span class="metric-label">Last Verified Backup</span>
        <span id="backup-val" class="metric-val">-</span>
        <span id="backup-sub" class="metric-sub">unbacked writes: -</span>
      </div>
      <div class="metric">
        <span class="metric-label">Last Poll</span>
        <span id="poll-val" class="metric-val">-</span>
        <span id="poll-sub" class="metric-sub">-</span>
      </div>
      <div class="metric">
        <span class="metric-label">Memory Tiers</span>
        <span id="hud-tiers" class="metric-val">-</span>
        <span id="hud-forecast" class="metric-sub">at now</span>
      </div>
    </div>
  </header>

  <aside class="hud-left graph-only">
    <div class="glass-box panel">
      <div class="box-title"><span>Agent Ganglia</span><span id="roster-count" class="mini">0 agents</span></div>
      <div id="agent-list" class="agent-list"></div>
    </div>
    <div class="glass-box panel">
      <div class="box-title">Engram Morphology &amp; Decay</div>
      <div class="legend-grid">
        <div class="legend-item"><span class="shape canon"></span><span>Rank 2 canon (owner)</span></div>
        <div class="legend-item"><span class="shape decision"></span><span>Class B decision (no expiry)</span></div>
        <div class="legend-item"><span class="shape fresh"></span><span>Class A status, fresh</span></div>
        <div class="legend-item"><span class="shape aging"></span><span>Class A status, near expiry</span></div>
      </div>
    </div>
    <div class="glass-box panel feed-box">
      <div class="box-title"><span>Synaptic Activity</span><span id="pulse-counter" class="mini">0 pulses</span></div>
      <div id="stream-list" class="stream-list"></div>
    </div>
  </aside>

  <aside class="hud-right graph-only">
    <div id="inspector-box" class="glass-box panel inspector"></div>
  </aside>

  <div class="hud-bottom graph-only">
    <div class="control-bar sim-bar panel">
      <span class="sim-label">Simulation · local animation only, nothing is sent</span>
      <button class="btn sim" id="btn-sim-write" type="button">Sim write</button>
      <button class="btn sim" id="btn-sim-recall" type="button">Sim recall</button>
      <button class="btn sim" id="btn-sim-consolidate" type="button">Sim consolidator preview</button>
      <button class="btn sim" id="btn-sim-refuse" type="button">Sim refusal</button>
    </div>
    <div class="control-bar panel">
      <label for="time-slider">Time-decay forecast</label>
      <input type="range" id="time-slider" min="0" max="30" step="0.5" value="0">
      <span id="time-label">NOW (+0.0d)</span>
      <button class="btn" id="btn-reset-view" type="button">Reset camera</button>
    </div>
  </div>

  <main class="wrap cards-only">
    <div class="grid grid-4">
      <div class="card">
        <div class="card-label">Rank 2: Canon</div>
        <div id="count-canon" class="card-val">0</div>
        <div id="sub-canon" class="card-sub">owner-only</div>
      </div>
      <div class="card">
        <div class="card-label">Rank 3: Ops</div>
        <div id="count-ops" class="card-val">0</div>
        <div id="sub-ops" class="card-sub">grant-backed</div>
      </div>
      <div class="card">
        <div class="card-label">Rank 3: Rooms</div>
        <div id="count-rooms" class="card-val">0</div>
        <div class="card-sub">39002-gated</div>
      </div>
      <div class="card">
        <div class="card-label">Rank 4: Self</div>
        <div id="count-self" class="card-val">0</div>
        <div id="sub-unverified" class="card-sub">unverified: 0</div>
      </div>
    </div>

    <section>
      <h2>
        <span>Latest Memory Claims</span>
        <span id="records-count" class="badge">0 records</span>
      </h2>
      <div id="records-list" class="record-list"></div>
    </section>

    <section>
      <h2>
        <span>Poll Change Log</span>
        <span id="log-count" class="badge">0 events</span>
      </h2>
      <div id="log-list" class="log-list"></div>
    </section>
  </main>

  <script id="initial-state" type="application/json">${escapedInitial}</script>
  <script>
    (function () {
      'use strict';
      var el = function (id) { return document.getElementById(id); };
      var DAY_SEC = 86400;
      var KNOWN_AGENTS = {
        james: { name: 'James', model: 'Sovereign Key', color: '#fbbf24' },
        biggy: { name: 'Biggy', model: 'Gemini / Antigravity', color: '#818cf8' },
        rabidrabbit: { name: 'RabidRabbit', model: 'Claude Opus 4.6', color: '#f59e0b' },
        mydude: { name: 'My Dude', model: 'OpenAI Codex', color: '#10b981' },
        neil: { name: 'Neil', model: 'OpenAI Codex', color: '#38bdf8' },
        'waggle-dev': { name: 'Waggle-Dev', model: 'Claude Sonnet 4.6', color: '#fb923c' },
        crystalclaude: { name: 'CrystalClaude', model: 'Claude Opus 4.6', color: '#f472b6' },
        'dj-codex': { name: 'DJ-Codex', model: 'OpenAI Codex', color: '#34d399' },
        grokdoggydog: { name: 'GrokDoggyDog', model: 'xAI Grok 4', color: '#f87171' },
        'pi-dog': { name: 'Pi-Dog', model: 'Pi Harness Agent', color: '#2dd4bf' },
        lukedog: { name: 'LukeDog', model: '', color: '#a3e635' },
        'mc-claude': { name: 'MC-Claude', model: '', color: '#e879f9' }
      };
      var SPARE_COLORS = ['#60a5fa', '#c084fc', '#fda4af', '#5eead4', '#fde047', '#93c5fd', '#86efac', '#fdba74'];
      var TOPIC_ANCHORS = [
        { id: 'hive-memory', angle: -Math.PI / 2, color: '#818cf8' },
        { id: 'nvoy', angle: -Math.PI / 10, color: '#38bdf8' },
        { id: 'herd-infra', angle: Math.PI * 0.35, color: '#34d399' },
        { id: 'buzz', angle: Math.PI * 0.72, color: '#f59e0b' },
        { id: 'r1', angle: Math.PI * 1.12, color: '#f472b6' }
      ];
      var NO_TOPIC = '(no topic)';

      var canvas = el('cortex');
      var ctx = canvas.getContext('2d');
      var width = window.innerWidth;
      var height = window.innerHeight;
      var dpr = 1;
      var cam = { x: 0, y: 0, zoom: 1, targetZoom: 1 };
      var hudTop = 150;
      var hudBottom = 96;
      var view = 'graph';
      var agents = [];
      var topics = [];
      var nodes = [];
      var pulses = [];
      var shockwaves = [];
      var consolidator = null;
      var hovered = null;
      var selected = null;
      var futureDays = 0;
      var lastActivitySeq = null;
      var pulseTotal = 0;
      var tick = 0;

      function fmtTime(sec) {
        if (!sec || typeof sec !== 'number') return 'never';
        var d = new Date(sec * 1000);
        return d.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
      }

      function fmtAge(sec, nowSec) {
        if (!sec || typeof sec !== 'number') return 'none';
        var diff = Math.max(0, (nowSec || Math.floor(Date.now() / 1000)) - sec);
        if (diff < 60) return diff + 's ago';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ' + (diff % 60) + 's ago';
        return Math.floor(diff / 3600) + 'h ' + Math.floor((diff % 3600) / 60) + 'm ago';
      }

      function syncBadgeClass(state) {
        if (state === 'READY') return 'badge ok';
        return 'badge err';
      }

      function makeBadge(text, cls) {
        var span = document.createElement('span');
        span.className = 'badge' + (cls ? ' ' + cls : '');
        span.textContent = String(text);
        return span;
      }

      function makeDiv(cls, text) {
        var d = document.createElement('div');
        if (cls) d.className = cls;
        if (text !== undefined && text !== null) d.textContent = String(text);
        return d;
      }

      function renderRecords(records, nowSec) {
        var container = el('records-list');
        container.textContent = '';
        el('records-count').textContent = records.length + (records.length === 1 ? ' record' : ' records');
        if (!records.length) {
          var empty = document.createElement('div');
          empty.className = 'empty';
          empty.textContent = 'No active memory records in store.';
          container.appendChild(empty);
          return;
        }
        for (var i = 0; i < records.length; i++) {
          var r = records[i];
          var card = document.createElement('div');
          card.className = 'record';

          var head = document.createElement('div');
          head.className = 'record-head';
          head.appendChild(makeBadge('rank: ' + (r.computed_rank !== null ? r.computed_rank : 'unranked'), 'info'));
          head.appendChild(makeBadge(r.scope || 'unknown', ''));
          head.appendChild(makeBadge('verification: ' + (r.verification || 'unverified'), r.verification === 'accepted' ? 'ok' : 'warn'));
          head.appendChild(makeBadge('authority: ' + JSON.stringify(r.authority), ''));
          head.appendChild(makeBadge('trustedInstruction: ' + String(Boolean(r.trustedInstruction)), ''));
          if (r.conflict) head.appendChild(makeBadge('CONFLICT', 'warn'));
          if (r.stale_warning) head.appendChild(makeBadge(r.stale_warning, 'warn'));
          card.appendChild(head);

          var keyLine = document.createElement('div');
          keyLine.className = 'record-key';
          keyLine.textContent = (r.d || '') + (r.topic ? ' (topic: ' + r.topic + ')' : '');
          card.appendChild(keyLine);

          var claimBox = document.createElement('div');
          claimBox.className = 'record-claim';
          claimBox.textContent = 'claim: ' + String(r.claim || '') + (r.because ? '\\nbecause: ' + String(r.because) : '');
          card.appendChild(claimBox);

          var meta = document.createElement('div');
          meta.className = 'record-meta';
          var evLine = document.createElement('div');
          evLine.textContent = 'evidence: ' + (Array.isArray(r.evidence) && r.evidence.length ? r.evidence.join(', ') : '(none)');
          meta.appendChild(evLine);

          var anchorLine = document.createElement('div');
          anchorLine.textContent = 'anchor: ' + (r.as_of_git ? 'git=' + r.as_of_git + ' ' : '') + (r.as_of_evt ? 'evt=' + r.as_of_evt : (!r.as_of_git ? '(none)' : ''));
          meta.appendChild(anchorLine);

          var idLine = document.createElement('div');
          idLine.textContent = 'author: ' + (r.author_pubkey || '') + ' | event: ' + (r.event_id || '');
          meta.appendChild(idLine);

          var timeLine = document.createElement('div');
          timeLine.textContent = 'created: ' + fmtTime(r.created_at) + ' (' + fmtAge(r.created_at, nowSec) + ') | expires: ' + fmtTime(r.expires_at);
          meta.appendChild(timeLine);

          card.appendChild(meta);
          container.appendChild(card);
        }
      }

      function renderLog(events) {
        var container = el('log-list');
        container.textContent = '';
        var list = Array.isArray(events) ? events : [];
        el('log-count').textContent = list.length + (list.length === 1 ? ' event' : ' events');
        if (!list.length) {
          var empty = document.createElement('div');
          empty.className = 'empty';
          empty.textContent = 'No poll events yet.';
          container.appendChild(empty);
          return;
        }
        for (var i = list.length - 1; i >= 0; i--) {
          var item = list[i];
          var row = document.createElement('div');
          row.className = 'log-row';
          var t = document.createElement('span');
          t.className = 'log-time';
          t.textContent = '[' + fmtTime(item.at) + '] (' + (item.kind || 'event') + ')';
          var msg = document.createElement('span');
          msg.textContent = ' ' + String(item.summary || '');
          row.appendChild(t);
          row.appendChild(msg);
          container.appendChild(row);
        }
      }

      // --- Cortex model: agents on the rim, topic nebulae inside, canon at the core ---

      function hashIndex(str, mod) {
        var h = 0;
        for (var i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
        return h % mod;
      }

      function nowSec() { return Date.now() / 1000; }
      function simNow() { return nowSec() + futureDays * DAY_SEC; }
      function isCanon(rec) { return rec.scope === 'hive:canon'; }
      function topicOf(rec) { return rec.topic || NO_TOPIC; }
      function slugOf(rec) { var parts = String(rec.d || '').split(':'); return parts[parts.length - 1] || rec.d || ''; }
      function agentById(id) { for (var i = 0; i < agents.length; i++) if (agents[i].id === id) return agents[i]; return null; }
      function agentByPubkey(pk) { for (var i = 0; i < agents.length; i++) if (pk && agents[i].pubkey === pk) return agents[i]; return null; }
      function topicById(id) { for (var i = 0; i < topics.length; i++) if (topics[i].id === id) return topics[i]; return topics[0]; }
      function nodeByEventId(id) { for (var i = 0; i < nodes.length; i++) if (nodes[i].rec.event_id === id) return nodes[i]; return null; }

      function makeAgent(id, extra) {
        var known = KNOWN_AGENTS[id] || {};
        var a = {
          id: id,
          name: known.name || id,
          model: known.model || '',
          color: known.color || SPARE_COLORS[hashIndex(id, SPARE_COLORS.length)],
          pubkey: null,
          is_reader: false,
          is_writer: false,
          is_owner: false,
          per_hour: 0,
          used_last_hour: null,
          listed: true,
          energy: 0,
          x: 0,
          y: 0,
          angle: 0,
          radius: 17
        };
        for (var k in extra) if (Object.prototype.hasOwnProperty.call(extra, k)) a[k] = extra[k];
        return a;
      }

      function ensureAgent(id) {
        var a = agentById(id);
        if (a) return a;
        a = makeAgent(id, { listed: false });
        agents.push(a);
        layout();
        return a;
      }

      function evalRecord(rec, at) {
        if (isCanon(rec)) return { state: 'canon', freshness: 1, ttlDays: Infinity, color: '#fbbf24', radius: 13 };
        if (rec.expires_at === null || rec.expires_at === undefined) return { state: 'decision', freshness: 1, ttlDays: Infinity, color: '#a78bfa', radius: 11 };
        var total = Math.max(1, rec.expires_at - (rec.created_at || rec.expires_at - 14 * DAY_SEC));
        var rem = rec.expires_at - at;
        var frac = Math.max(0, Math.min(1, rem / total));
        if (rem <= 0) return { state: 'expired', freshness: 0, ttlDays: rem / DAY_SEC, color: '#475569', radius: 6 };
        var color = frac < 0.35 ? '#f59e0b' : (frac < 0.7 ? '#60a5fa' : '#38bdf8');
        return { state: frac < 0.35 ? 'aging' : 'fresh', freshness: frac, ttlDays: rem / DAY_SEC, color: color, radius: 7.5 + frac * 3.5 };
      }

      function layout() {
        var minDim = stageDim();
        var rim = rimR();
        agents.forEach(function (a, i) {
          a.angle = -Math.PI / 2 + (i / Math.max(1, agents.length)) * Math.PI * 2;
          a.x = Math.cos(a.angle) * rim;
          a.y = Math.sin(a.angle) * rim;
          a.radius = a.is_owner ? 21 : 17;
        });
        var even = topics.length > TOPIC_ANCHORS.length;
        topics.forEach(function (t, i) {
          var angle = even ? -Math.PI / 2 + (i / topics.length) * Math.PI * 2 : t.anchorAngle;
          t.x = Math.cos(angle) * minDim * 0.26;
          t.y = Math.sin(angle) * minDim * 0.26;
          t.radius = minDim * 0.12;
        });
      }

      function placeNode(n, idx) {
        if (isCanon(n.rec)) {
          n.x = Math.cos(idx * 2.1) * 26;
          n.y = Math.sin(idx * 2.1) * 26;
        } else {
          var t = topicById(topicOf(n.rec));
          var spread = evalRecord(n.rec, nowSec()).state === 'decision' ? 28 : 54;
          n.x = t.x + Math.cos(idx * 1.37) * spread;
          n.y = t.y + Math.sin(idx * 1.37) * spread;
        }
      }

      function syncAgents(s) {
        var roster = Array.isArray(s.agent_roster) ? s.agent_roster : [];
        var next = [];
        roster.forEach(function (r) {
          var prev = agentById(r.id);
          next.push(makeAgent(r.id, {
            pubkey: r.pubkey || null,
            is_reader: Boolean(r.is_reader),
            is_writer: Boolean(r.is_writer),
            is_owner: Boolean(r.is_owner),
            per_hour: r.per_hour || 0,
            used_last_hour: typeof r.used_last_hour === 'number' ? r.used_last_hour : null,
            energy: prev ? prev.energy : 0
          }));
        });
        var known = {};
        next.forEach(function (a) { if (a.pubkey) known[a.pubkey] = true; });
        (Array.isArray(s.records) ? s.records : []).forEach(function (rec) {
          var pk = rec.author_pubkey;
          if (!pk || known[pk]) return;
          known[pk] = true;
          var id = 'author:' + pk.slice(0, 8);
          var prev = agentById(id);
          next.push(makeAgent(id, { name: pk.slice(0, 8) + '…', pubkey: pk, listed: false, energy: prev ? prev.energy : 0 }));
        });
        agents.forEach(function (a) {
          if (!a.listed && a.id.indexOf('author:') !== 0 && !next.some(function (b) { return b.id === a.id; })) next.push(a);
        });
        agents = next;
      }

      function syncTopics(records) {
        var ids = TOPIC_ANCHORS.map(function (t) { return t.id; });
        records.forEach(function (rec) {
          if (!isCanon(rec) && ids.indexOf(topicOf(rec)) < 0) ids.push(topicOf(rec));
        });
        topics = ids.map(function (id, i) {
          var anchor = i < TOPIC_ANCHORS.length ? TOPIC_ANCHORS[i] : null;
          return { id: id, anchorAngle: anchor ? anchor.angle : 0, color: anchor ? anchor.color : SPARE_COLORS[hashIndex(id, SPARE_COLORS.length)], x: 0, y: 0, radius: 0 };
        });
      }

      function syncGraph(s, animate) {
        var records = Array.isArray(s.records) ? s.records : [];
        syncAgents(s);
        syncTopics(records);
        layout();

        var byKey = {};
        nodes.forEach(function (n) { byKey[n.key] = n; });
        var fresh = [];
        var nextNodes = records.map(function (rec, i) {
          var key = rec.author_pubkey + ':' + rec.d;
          var n = byKey[key];
          if (!n) {
            n = { key: key, rec: rec, x: 0, y: 0, vx: 0, vy: 0, birthGlow: animate ? 1 : 0 };
            placeNode(n, i);
            fresh.push(n);
          } else {
            if (n.rec.event_id !== rec.event_id) {
              n.birthGlow = 1;
              fresh.push(n);
            }
            n.rec = rec;
          }
          return n;
        });
        nodes = nextNodes;
        if (selected && selected.type === 'memory' && nodes.indexOf(selected.data) < 0) selected = null;
        if (hovered && hovered.type === 'memory' && nodes.indexOf(hovered.data) < 0) hovered = null;
        if (selected && selected.type === 'agent') selected = agentById(selected.data.id) ? { type: 'agent', data: agentById(selected.data.id) } : null;

        var activity = Array.isArray(s.recent_activity) ? s.recent_activity : [];
        var maxSeq = activity.reduce(function (m, a) { return Math.max(m, a.seq); }, 0);
        var covered = {};
        if (lastActivitySeq === null || maxSeq < lastActivitySeq) {
          activity.slice(-12).forEach(function (a) { logStream(feedClass(a.kind), activityText(a), a.at); });
        } else {
          activity.forEach(function (a) { if (a.seq > lastActivitySeq) fireActivity(a, covered); });
        }
        lastActivitySeq = maxSeq;

        if (animate) {
          fresh.forEach(function (n) {
            if (covered[n.rec.event_id]) return;
            var author = agentByPubkey(n.rec.author_pubkey);
            if (author) writeComet(author, n);
          });
        }
        renderAgentRoster();
        updateTiers();
        renderInspector();
      }

      // --- Pulses: real activity from the ring, or local simulations ---

      function writeComet(agent, node) {
        agent.energy = 1;
        pulses.push({ kind: 'write', fromX: agent.x, fromY: agent.y, toNode: node, toX: 0, toY: 0, color: agent.color, t: 0, speed: 0.022 });
      }

      function recallWave(agent, node) {
        pulses.push({ kind: 'recall', fromNode: node, fromX: 0, fromY: 0, toX: agent.x, toY: agent.y, agent: agent, color: '#38bdf8', t: 0, speed: 0.025 });
      }

      function refusalProbe(agent) {
        agent.energy = 1;
        pulses.push({ kind: 'refuse', fromX: agent.x, fromY: agent.y, toX: agent.x * 0.78, toY: agent.y * 0.78, agent: agent, color: '#f87171', t: 0, speed: 0.035 });
      }

      function lookupProbe(agent) {
        agent.energy = 0.6;
        pulses.push({ kind: 'lookup', fromX: agent.x, fromY: agent.y, toX: agent.x * 0.6, toY: agent.y * 0.6, color: '#a78bfa', t: 0, speed: 0.03 });
      }

      function feedClass(kind) {
        if (kind === 'submit') return 'write';
        if (kind === 'refused') return 'refuse';
        if (kind === 'lookup') return 'lookup';
        return 'recall';
      }

      function activityText(a) {
        var hidden = '(key outside the viewer ACL)';
        if (a.kind === 'wake') return a.actor + ' <- memory_wake: ' + (a.count || 0) + ' records';
        if (a.kind === 'query') return a.actor + ' <- memory_query' + (a.topic ? ' topic=' + a.topic : '') + (a.scope ? ' scope=' + a.scope : '') + ': ' + (a.count || 0) + ' records';
        if (a.kind === 'lookup') return a.actor + ' -> lookup_prior ' + (a.d || hidden);
        if (a.kind === 'submit') return a.actor + ' -> memory_submit accepted ' + (a.d || hidden);
        if (a.kind === 'refused') return a.actor + ' REFUSED ' + (a.code || '') + (a.d ? ' at ' + a.d : '');
        return a.actor + ' ' + a.kind;
      }

      function fireActivity(a, covered) {
        var agent = ensureAgent(a.actor);
        var ids = Array.isArray(a.event_ids) ? a.event_ids : [];
        if (a.kind === 'wake' || a.kind === 'query') {
          var hit = 0;
          ids.slice(0, 8).forEach(function (id) {
            var n = nodeByEventId(id);
            if (n) { recallWave(agent, n); hit += 1; }
          });
          if (!hit) recallWave(agent, null);
        } else if (a.kind === 'submit') {
          var target = ids.length ? nodeByEventId(ids[0]) : null;
          if (target) covered[target.rec.event_id] = true;
          writeComet(agent, target);
        } else if (a.kind === 'lookup') {
          lookupProbe(agent);
        } else if (a.kind === 'refused') {
          refusalProbe(agent);
        }
        logStream(feedClass(a.kind), activityText(a), a.at);
      }

      function logStream(cls, text, at) {
        var list = el('stream-list');
        var row = makeDiv('stream-item ' + cls, '[' + new Date((at || nowSec()) * 1000).toISOString().slice(11, 19) + 'Z] ' + text);
        list.insertBefore(row, list.firstChild);
        while (list.children.length > 40) list.removeChild(list.lastChild);
        pulseTotal += 1;
        el('pulse-counter').textContent = pulseTotal + (pulseTotal === 1 ? ' pulse' : ' pulses');
      }

      function pickAgent(filter) {
        if (selected && selected.type === 'agent' && (!filter || filter(selected.data))) return selected.data;
        var pool = agents.filter(function (a) { return !filter || filter(a); });
        if (!pool.length) pool = agents;
        return pool.length ? pool[Math.floor(Math.random() * pool.length)] : null;
      }

      function simWrite() {
        var agent = pickAgent(function (a) { return a.is_writer; });
        if (!agent) return logStream('sim', 'SIM write: no agents to animate');
        var pool = nodes.filter(function (n) { return !isCanon(n.rec); });
        var target = pool.length ? pool[Math.floor(Math.random() * pool.length)] : null;
        writeComet(agent, target);
        logStream('sim', 'SIM write comet: ' + agent.name + ' -> ' + (target ? slugOf(target.rec) : 'core') + ' (nothing written)');
      }

      function simRecall() {
        var agent = pickAgent(null);
        if (!agent) return logStream('sim', 'SIM recall: no agents to animate');
        var focus = topics.length ? topics[Math.floor(Math.random() * topics.length)].id : null;
        var recalled = nodes.filter(function (n) { return isCanon(n.rec) || topicOf(n.rec) === focus; }).slice(0, 6);
        if (!recalled.length) recallWave(agent, null);
        recalled.forEach(function (n) { recallWave(agent, n); });
        logStream('sim', 'SIM recall wave: ' + agent.name + ' <- ' + recalled.length + ' engrams (nothing queried)');
      }

      function simConsolidate() {
        if (consolidator) return;
        var best = null;
        var bestNodes = [];
        topics.forEach(function (t) {
          var cands = nodes.filter(function (n) {
            var st = evalRecord(n.rec, simNow()).state;
            return !isCanon(n.rec) && topicOf(n.rec) === t.id && (st === 'fresh' || st === 'aging');
          });
          if (cands.length > bestNodes.length) { best = t; bestNodes = cands; }
        });
        if (bestNodes.length < 2) return logStream('sim', 'SIM consolidator preview: no topic holds 2+ Class A claims');
        consolidator = { topic: best, targets: bestNodes.slice(0, 4), x: best.x, y: best.y, progress: 0 };
        logStream('sim', 'SIM consolidator preview in #' + best.id + ': folding ' + consolidator.targets.length + ' Class A claims (nothing written)');
      }

      function simRefuse() {
        var agent = pickAgent(function (a) { return !a.is_writer; });
        if (!agent) return logStream('sim', 'SIM refusal: no agents to animate');
        refusalProbe(agent);
        logStream('sim', 'SIM refusal shield at ' + agent.name + ' gate (nothing sent)');
      }

      // --- HUD: roster, tiers and inspector (record text only ever via textContent) ---

      function renderAgentRoster() {
        var list = el('agent-list');
        list.textContent = '';
        el('roster-count').textContent = agents.length + (agents.length === 1 ? ' agent' : ' agents');
        agents.forEach(function (a) {
          var count = nodes.filter(function (n) { return a.pubkey && n.rec.author_pubkey === a.pubkey; }).length;
          var row = makeDiv('agent-row' + (selected && selected.type === 'agent' && selected.data.id === a.id ? ' active' : ''));
          var ident = makeDiv('agent-ident');
          var dot = document.createElement('span');
          dot.className = 'agent-dot';
          dot.style.background = a.color;
          dot.style.boxShadow = '0 0 8px ' + a.color;
          ident.appendChild(dot);
          var names = makeDiv('');
          names.appendChild(makeDiv('agent-name', a.name));
          names.appendChild(makeDiv('agent-model', a.model || (a.listed ? a.id : 'not in roster')));
          ident.appendChild(names);
          row.appendChild(ident);
          var stats = makeDiv('agent-stats', count + 'm ' + (a.is_writer ? (a.used_last_hour === null ? '?' : a.used_last_hour) + '/' + a.per_hour : 'RO'));
          stats.style.color = a.is_writer ? '#6ee7b7' : '#fca5a5';
          row.appendChild(stats);
          row.addEventListener('click', function () {
            selected = { type: 'agent', data: a };
            renderAgentRoster();
            renderInspector();
          });
          list.appendChild(row);
        });
      }

      function updateTiers() {
        var at = simNow();
        var canon = 0;
        var decision = 0;
        var status = 0;
        var expired = 0;
        nodes.forEach(function (n) {
          var st = evalRecord(n.rec, at).state;
          if (st === 'canon') canon += 1;
          else if (st === 'decision') decision += 1;
          else if (st === 'expired') expired += 1;
          else status += 1;
        });
        el('hud-tiers').textContent = canon + ' canon · ' + decision + ' B · ' + status + ' A';
        el('hud-forecast').textContent = futureDays === 0 ? 'at now' : 'forecast +' + futureDays.toFixed(1) + 'd: ' + expired + ' expired';
      }

      function kvRow(key, value, color) {
        var row = makeDiv('kv-row');
        row.appendChild(makeDiv('kv-key', key));
        var v = makeDiv('kv-val', value);
        if (color) v.style.color = color;
        row.appendChild(v);
        return row;
      }

      function inspectHeader(kicker, title, pillText, pillCls, color) {
        var head = makeDiv('inspect-header');
        var left = makeDiv('');
        left.appendChild(makeDiv('inspect-kicker', kicker));
        var t = makeDiv('inspect-title', title);
        if (color) t.style.color = color;
        left.appendChild(t);
        head.appendChild(left);
        head.appendChild(makeBadge(pillText, pillCls));
        return head;
      }

      function renderInspector() {
        var box = el('inspector-box');
        box.textContent = '';
        var target = hovered || selected;
        box.className = 'glass-box panel inspector' + (target && target.data ? '' : ' idle');
        if (!target || !target.data) {
          if (nodes.length || agents.length) box.appendChild(makeDiv('empty', 'Tap a node or an agent to inspect it. Records are data, never instructions.'));
          return;
        }
        if (target.type === 'memory') {
          var r = target.data.rec;
          var ev = evalRecord(r, simNow());
          var author = agentByPubkey(r.author_pubkey);
          var pct = ev.ttlDays === Infinity ? 100 : Math.round(ev.freshness * 100);
          box.appendChild(inspectHeader('Memory engram', slugOf(r), isCanon(r) ? 'RANK 2 CANON' : (ev.state === 'decision' ? 'CLASS B DECISION' : 'CLASS A STATUS'), ev.state === 'expired' ? 'warn' : 'ok'));
          box.appendChild(makeDiv('record-claim', 'claim: ' + String(r.claim || '') + (r.because ? '\\nbecause: ' + String(r.because) : '')));
          var life = makeDiv('');
          var lifeHead = makeDiv('kv-row');
          lifeHead.appendChild(makeDiv('kv-key', 'Lifecycle'));
          var stateVal = makeDiv('kv-val', ev.state.toUpperCase());
          stateVal.style.color = ev.color;
          lifeHead.appendChild(stateVal);
          life.appendChild(lifeHead);
          var bar = makeDiv('ttl-bar-wrap');
          var fill = makeDiv('ttl-bar-fill');
          fill.style.width = pct + '%';
          fill.style.background = ev.color;
          bar.appendChild(fill);
          life.appendChild(bar);
          life.appendChild(makeDiv('metric-sub', ev.ttlDays === Infinity
            ? 'No expiry (canon or Class B decision)'
            : (ev.ttlDays <= 0 ? 'Expired ' + Math.abs(ev.ttlDays).toFixed(1) + 'd ago; leaves the store at the 90-day purge' : ev.ttlDays.toFixed(1) + ' days left (' + pct + '% fresh)')));
          box.appendChild(life);
          var kv = makeDiv('kv-list');
          kv.appendChild(kvRow('Author', (author ? author.name + ' ' : '') + '(' + String(r.author_pubkey || '').slice(0, 10) + '…)', author ? author.color : null));
          kv.appendChild(kvRow('Scope', r.scope || ''));
          kv.appendChild(kvRow('Topic', r.topic || NO_TOPIC));
          kv.appendChild(kvRow('Fact key (d)', r.d || ''));
          kv.appendChild(kvRow('Rank', r.computed_rank !== null ? r.computed_rank : 'unranked'));
          kv.appendChild(kvRow('Verification', r.verification || 'unverified'));
          kv.appendChild(kvRow('Anchor', r.as_of_git || r.as_of_evt || '(none)'));
          kv.appendChild(kvRow('Evidence', Array.isArray(r.evidence) && r.evidence.length ? r.evidence.join(', ') : '(none)'));
          kv.appendChild(kvRow('Event id', String(r.event_id || '').slice(0, 20) + '…'));
          kv.appendChild(kvRow('Created', fmtTime(r.created_at)));
          kv.appendChild(kvRow('Expires', fmtTime(r.expires_at)));
          if (r.conflict) kv.appendChild(kvRow('Conflict', 'yes', '#fcd34d'));
          if (r.stale_warning) kv.appendChild(kvRow('Stale', r.stale_warning, '#fcd34d'));
          kv.appendChild(kvRow('Quarantine', 'authority: ' + JSON.stringify(r.authority) + ' · trustedInstruction: ' + String(Boolean(r.trustedInstruction)), '#6ee7b7'));
          box.appendChild(kv);
        } else if (target.type === 'agent') {
          var a = target.data;
          var authored = nodes.filter(function (n) { return a.pubkey && n.rec.author_pubkey === a.pubkey; });
          box.appendChild(inspectHeader('Agent ganglion', a.name, !a.listed ? 'NOT IN ROSTER' : (a.is_writer ? 'WRITER SOCKET' : 'READ-ONLY SOCKET'), a.is_writer ? 'ok' : 'warn', a.color));
          if (a.model) box.appendChild(makeDiv('metric-sub', 'harness: ' + a.model));
          var akv = makeDiv('kv-list');
          akv.appendChild(kvRow('Binding', a.id));
          akv.appendChild(kvRow('Pubkey', a.pubkey ? a.pubkey.slice(0, 22) + '…' : '(keyless)'));
          akv.appendChild(kvRow('Owner', a.is_owner ? 'yes' : 'no'));
          akv.appendChild(kvRow('Reader socket', a.is_reader ? 'yes' : 'no'));
          akv.appendChild(kvRow('Writes this hour', a.is_writer ? (a.used_last_hour === null ? '?' : a.used_last_hour) + ' / ' + a.per_hour : 'read-only'));
          akv.appendChild(kvRow('Visible claims', authored.length + ' (' + authored.filter(function (n) { return evalRecord(n.rec, simNow()).state === 'decision'; }).length + ' Class B)'));
          box.appendChild(akv);
        }
      }

      // --- Canvas: camera, physics and drawing ---

      function measureHud() {
        if (view !== 'graph') return;
        hudTop = Math.ceil(document.querySelector('.hud-top').getBoundingClientRect().bottom) + 10;
        hudBottom = Math.ceil(height - document.querySelector('.hud-bottom').getBoundingClientRect().top) + 10;
        document.documentElement.style.setProperty('--hud-top', hudTop + 'px');
        document.documentElement.style.setProperty('--hud-bottom', hudBottom + 'px');
      }

      function centerY() { return height / 2 + (hudTop - hudBottom) / 2; }
      function stageDim() { return Math.max(260, Math.min(width, height - hudTop - hudBottom + 20)); }
      function rimR() { return stageDim() * (width < 680 ? 0.36 : 0.41); }

      function resize() {
        width = window.innerWidth;
        height = window.innerHeight;
        measureHud();
        dpr = Math.min(window.devicePixelRatio || 1, 2);
        canvas.width = Math.floor(width * dpr);
        canvas.height = Math.floor(height * dpr);
        layout();
      }

      function screenToWorld(sx, sy) {
        return { x: (sx - width / 2 - cam.x) / cam.zoom, y: (sy - centerY() - cam.y) / cam.zoom };
      }

      function hitTest(sx, sy) {
        var pt = screenToWorld(sx, sy);
        for (var i = 0; i < nodes.length; i++) {
          if (Math.hypot(pt.x - nodes[i].x, pt.y - nodes[i].y) < 16) return { type: 'memory', data: nodes[i] };
        }
        for (var j = 0; j < agents.length; j++) {
          if (Math.hypot(pt.x - agents[j].x, pt.y - agents[j].y) < agents[j].radius + 8) return { type: 'agent', data: agents[j] };
        }
        return null;
      }

      var drag = null;
      canvas.addEventListener('pointerdown', function (e) {
        drag = { x: e.clientX, y: e.clientY, camX: cam.x, camY: cam.y, moved: false };
        if (canvas.setPointerCapture) canvas.setPointerCapture(e.pointerId);
      });
      canvas.addEventListener('pointermove', function (e) {
        if (drag) {
          if (Math.abs(e.clientX - drag.x) + Math.abs(e.clientY - drag.y) > 5) drag.moved = true;
          if (drag.moved) {
            cam.x = drag.camX + e.clientX - drag.x;
            cam.y = drag.camY + e.clientY - drag.y;
          }
          return;
        }
        if (e.pointerType !== 'mouse') return;
        var found = hitTest(e.clientX, e.clientY);
        if ((found && found.data) !== (hovered && hovered.data)) {
          hovered = found;
          canvas.style.cursor = found ? 'pointer' : 'grab';
          renderInspector();
        }
      });
      canvas.addEventListener('pointerup', function (e) {
        if (drag && !drag.moved) {
          selected = hitTest(e.clientX, e.clientY);
          renderAgentRoster();
          renderInspector();
        }
        drag = null;
      });
      canvas.addEventListener('pointercancel', function () { drag = null; });
      canvas.addEventListener('pointerleave', function () {
        if (hovered) { hovered = null; renderInspector(); }
      });
      canvas.addEventListener('wheel', function (e) {
        e.preventDefault();
        cam.targetZoom = Math.max(0.55, Math.min(2.4, cam.targetZoom * (e.deltaY < 0 ? 1.1 : 0.9)));
      }, { passive: false });
      window.addEventListener('resize', resize);

      function stepPhysics() {
        tick += 1;
        cam.zoom += (cam.targetZoom - cam.zoom) * 0.14;
        var at = simNow();
        var horizonR = stageDim() * 0.34;
        for (var i = 0; i < nodes.length; i++) {
          var n = nodes[i];
          var ev = evalRecord(n.rec, at);
          var topic = topicById(topicOf(n.rec));
          var tx = topic.x;
          var ty = topic.y;
          if (isCanon(n.rec)) {
            tx = 0;
            ty = 0;
          } else if (ev.state === 'expired') {
            var out = Math.atan2(n.y, n.x);
            tx = Math.cos(out) * horizonR;
            ty = Math.sin(out) * horizonR;
          }
          var k = isCanon(n.rec) ? 0.04 : (ev.state === 'decision' ? 0.032 : 0.02);
          n.vx += (tx - n.x) * k;
          n.vy += (ty - n.y) * k;
          if (!isCanon(n.rec)) {
            n.vx += -(n.y - topic.y) * 0.0009;
            n.vy += (n.x - topic.x) * 0.0009;
          }
          for (var j = i + 1; j < nodes.length; j++) {
            var o = nodes[j];
            var dx = n.x - o.x;
            var dy = n.y - o.y;
            var d2 = dx * dx + dy * dy + 0.1;
            if (d2 < 34 * 34) {
              var d = Math.sqrt(d2);
              var push = (34 - d) * 0.05;
              n.vx += dx / d * push;
              n.vy += dy / d * push;
              o.vx -= dx / d * push;
              o.vy -= dy / d * push;
            }
          }
          if (consolidator && consolidator.targets.indexOf(n) >= 0) {
            n.vx += (consolidator.x - n.x) * 0.06;
            n.vy += (consolidator.y - n.y) * 0.06;
          }
          n.vx *= 0.86;
          n.vy *= 0.86;
          n.x += n.vx;
          n.y += n.vy;
          if (n.birthGlow > 0) n.birthGlow = Math.max(0, n.birthGlow - 0.015);
        }
        if (consolidator) {
          consolidator.progress += 0.012;
          if (consolidator.progress >= 1) {
            shockwaves.push({ x: consolidator.x, y: consolidator.y, r: 8, maxR: 130, color: '#fbbf24', alpha: 1 });
            logStream('sim', 'SIM consolidator preview done: a real pass would supersede ' + consolidator.targets.length + ' claims with one Class B decision');
            consolidator = null;
          }
        }
        for (var p = pulses.length - 1; p >= 0; p--) {
          var pl = pulses[p];
          pl.t += pl.speed;
          if (pl.t >= 1) {
            if (pl.kind === 'write') {
              var end = pl.toNode || { x: pl.toX, y: pl.toY };
              shockwaves.push({ x: end.x, y: end.y, r: 6, maxR: 58, color: pl.color, alpha: 0.95 });
            } else if (pl.kind === 'refuse') {
              shockwaves.push({ x: pl.toX, y: pl.toY, r: 4, maxR: 44, color: '#f87171', alpha: 1, hex: true });
            } else if (pl.kind === 'recall' && pl.agent) {
              pl.agent.energy = 1;
            }
            pulses.splice(p, 1);
          }
        }
        for (var s = shockwaves.length - 1; s >= 0; s--) {
          shockwaves[s].r += (shockwaves[s].maxR - shockwaves[s].r) * 0.12;
          shockwaves[s].alpha -= 0.028;
          if (shockwaves[s].alpha <= 0) shockwaves.splice(s, 1);
        }
        agents.forEach(function (a) { if (a.energy > 0) a.energy = Math.max(0, a.energy - 0.02); });
      }

      function polygon(cx, cy, sides, r, rotation) {
        ctx.beginPath();
        for (var i = 0; i < sides; i++) {
          var ang = rotation + (i / sides) * Math.PI * 2;
          if (i === 0) ctx.moveTo(cx + Math.cos(ang) * r, cy + Math.sin(ang) * r);
          else ctx.lineTo(cx + Math.cos(ang) * r, cy + Math.sin(ang) * r);
        }
        ctx.closePath();
      }

      function glow(x, y, r0, r1, color) {
        var g = ctx.createRadialGradient(x, y, r0, x, y, r1);
        g.addColorStop(0, color);
        g.addColorStop(1, 'transparent');
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(x, y, r1, 0, Math.PI * 2);
        ctx.fill();
      }

      function draw() {
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, width, height);
        ctx.translate(width / 2 + cam.x, centerY() + cam.y);
        ctx.scale(cam.zoom, cam.zoom);
        var minDim = stageDim();
        var at = simNow();
        var focus = hovered || selected;

        ctx.lineWidth = 1.5;
        ctx.strokeStyle = 'rgba(52, 211, 153, 0.16)';
        ctx.beginPath();
        ctx.arc(0, 0, rimR() + 30, 0, Math.PI * 2);
        ctx.stroke();
        ctx.save();
        ctx.setLineDash([5, 7]);
        ctx.strokeStyle = 'rgba(245, 158, 11, 0.2)';
        ctx.beginPath();
        ctx.arc(0, 0, minDim * 0.34, 0, Math.PI * 2);
        ctx.stroke();
        ctx.restore();
        ctx.strokeStyle = 'rgba(251, 191, 36, 0.22)';
        ctx.beginPath();
        ctx.arc(0, 0, 52, 0, Math.PI * 2);
        ctx.stroke();

        ctx.textAlign = 'center';
        ctx.textBaseline = 'alphabetic';
        topics.forEach(function (t) {
          var g = ctx.createRadialGradient(t.x, t.y, 6, t.x, t.y, t.radius);
          g.addColorStop(0, t.color + '2e');
          g.addColorStop(0.6, t.color + '10');
          g.addColorStop(1, 'transparent');
          ctx.fillStyle = g;
          ctx.beginPath();
          ctx.arc(t.x, t.y, t.radius, 0, Math.PI * 2);
          ctx.fill();
          ctx.font = '600 11px ui-monospace, SFMono-Regular, Menlo, monospace';
          ctx.fillStyle = 'rgba(226, 232, 240, 0.55)';
          ctx.fillText('#' + t.id, t.x, t.y - t.radius * 0.62);
        });

        nodes.forEach(function (n) {
          var author = agentByPubkey(n.rec.author_pubkey);
          if (!author) return;
          var lit = focus && ((focus.type === 'memory' && focus.data === n) || (focus.type === 'agent' && focus.data === author));
          ctx.beginPath();
          ctx.moveTo(author.x, author.y);
          ctx.quadraticCurveTo((author.x + n.x) * 0.35, (author.y + n.y) * 0.35, n.x, n.y);
          ctx.strokeStyle = lit ? author.color + '99' : 'rgba(148, 163, 184, 0.08)';
          ctx.lineWidth = lit ? 1.6 : 0.8;
          ctx.stroke();
        });

        if (consolidator) {
          var c = consolidator;
          var pr = 24 + Math.sin(tick * 0.25) * 6;
          var cg = ctx.createRadialGradient(c.x, c.y, 2, c.x, c.y, pr * 2.4);
          cg.addColorStop(0, 'rgba(251, 191, 36, 0.65)');
          cg.addColorStop(0.5, 'rgba(168, 85, 247, 0.32)');
          cg.addColorStop(1, 'transparent');
          ctx.fillStyle = cg;
          ctx.beginPath();
          ctx.arc(c.x, c.y, pr * 2.4, 0, Math.PI * 2);
          ctx.fill();
          c.targets.forEach(function (tn) {
            ctx.beginPath();
            ctx.moveTo(c.x, c.y);
            ctx.lineTo(tn.x, tn.y);
            ctx.strokeStyle = 'rgba(251, 191, 36, 0.88)';
            ctx.lineWidth = 2.2;
            ctx.stroke();
          });
          polygon(c.x, c.y, 6, 15, tick * 0.06);
          ctx.fillStyle = '#fbbf24';
          ctx.fill();
          ctx.font = '700 10px ui-monospace, monospace';
          ctx.fillStyle = '#fde68a';
          ctx.fillText('SIM CONSOLIDATOR ' + Math.round(c.progress * 100) + '%', c.x, c.y - 22);
        }

        nodes.forEach(function (n) {
          var ev = evalRecord(n.rec, at);
          var isSel = (hovered && hovered.data === n) || (selected && selected.data === n);
          var r = ev.radius + (isSel ? 3 : 0);
          if (ev.state !== 'expired') glow(n.x, n.y, r * 0.2, r * (2.3 + (n.birthGlow || 0) * 2), ev.color + '66');
          if (ev.state === 'canon') {
            polygon(n.x, n.y, 8, r, tick * 0.008);
            ctx.fillStyle = ev.color;
            ctx.fill();
            ctx.strokeStyle = '#fef3c7';
            ctx.lineWidth = 1.6;
            ctx.stroke();
          } else if (ev.state === 'decision') {
            polygon(n.x, n.y, 4, r, 0);
            ctx.fillStyle = ev.color;
            ctx.fill();
            ctx.strokeStyle = '#f3e8ff';
            ctx.lineWidth = isSel ? 2.2 : 1.2;
            ctx.stroke();
          } else {
            ctx.beginPath();
            ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
            ctx.fillStyle = ev.state === 'expired' ? 'rgba(71, 85, 105, 0.38)' : ev.color;
            ctx.fill();
            if (ev.freshness > 0) {
              ctx.beginPath();
              ctx.arc(n.x, n.y, r + 3.2, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * ev.freshness);
              ctx.strokeStyle = ev.color;
              ctx.lineWidth = 1.5;
              ctx.stroke();
            }
          }
          if (n.rec.conflict) {
            ctx.beginPath();
            ctx.arc(n.x, n.y, r + 5, 0, Math.PI * 2);
            ctx.strokeStyle = '#fcd34d';
            ctx.lineWidth = 1;
            ctx.stroke();
          }
          if (isSel) {
            ctx.beginPath();
            ctx.arc(n.x, n.y, r + 6.5, 0, Math.PI * 2);
            ctx.strokeStyle = '#ffffff';
            ctx.lineWidth = 1.5;
            ctx.stroke();
            ctx.font = '600 10.5px ui-monospace, monospace';
            ctx.fillStyle = '#f8fafc';
            ctx.fillText(slugOf(n.rec), n.x, n.y + r + 15);
          }
        });

        pulses.forEach(function (pl) {
          var sx = pl.fromNode ? pl.fromNode.x : pl.fromX;
          var sy = pl.fromNode ? pl.fromNode.y : pl.fromY;
          var ex = pl.toNode ? pl.toNode.x : pl.toX;
          var ey = pl.toNode ? pl.toNode.y : pl.toY;
          var cx = (sx + ex) * 0.35;
          var cy = (sy + ey) * 0.35;
          var t = pl.t;
          var inv = 1 - t;
          var px = inv * inv * sx + 2 * inv * t * cx + t * t * ex;
          var py = inv * inv * sy + 2 * inv * t * cy + t * t * ey;
          var g = ctx.createRadialGradient(px, py, 1, px, py, 14);
          g.addColorStop(0, '#ffffff');
          g.addColorStop(0.35, pl.color);
          g.addColorStop(1, 'transparent');
          ctx.fillStyle = g;
          ctx.beginPath();
          ctx.arc(px, py, 14, 0, Math.PI * 2);
          ctx.fill();
        });

        shockwaves.forEach(function (sw) {
          ctx.save();
          ctx.globalAlpha = Math.max(0, sw.alpha);
          if (sw.hex) polygon(sw.x, sw.y, 6, sw.r, 0);
          else {
            ctx.beginPath();
            ctx.arc(sw.x, sw.y, sw.r, 0, Math.PI * 2);
          }
          ctx.strokeStyle = sw.color;
          ctx.lineWidth = sw.hex ? 2.5 : 2;
          ctx.stroke();
          ctx.restore();
        });

        agents.forEach(function (a) {
          var isSel = (hovered && hovered.data === a) || (selected && selected.data === a);
          if (a.energy > 0 || isSel) glow(a.x, a.y, a.radius * 0.4, a.radius * (2.1 + a.energy * 1.1), a.color + '77');
          ctx.beginPath();
          ctx.arc(a.x, a.y, a.radius, 0, Math.PI * 2);
          ctx.fillStyle = '#0b1325';
          ctx.fill();
          ctx.save();
          if (!a.listed) ctx.setLineDash([3, 3]);
          ctx.strokeStyle = a.color;
          ctx.lineWidth = isSel ? 3 : 2;
          ctx.stroke();
          ctx.restore();
          if (a.is_writer && a.per_hour > 0 && a.used_last_hour) {
            ctx.beginPath();
            ctx.arc(a.x, a.y, a.radius + 4.5, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * Math.min(1, a.used_last_hour / a.per_hour));
            ctx.strokeStyle = a.color;
            ctx.lineWidth = 2.2;
            ctx.stroke();
          }
          ctx.textBaseline = 'middle';
          ctx.font = '700 10.5px -apple-system, BlinkMacSystemFont, sans-serif';
          ctx.fillStyle = '#f8fafc';
          ctx.fillText(a.is_owner ? '\\u2605' : a.name.slice(0, 2).toUpperCase(), a.x, a.y);
          ctx.font = '600 11.5px -apple-system, BlinkMacSystemFont, sans-serif';
          ctx.fillStyle = isSel ? '#ffffff' : '#cbd5e1';
          ctx.fillText(a.name, a.x + Math.cos(a.angle) * (a.radius + 17), a.y + Math.sin(a.angle) * (a.radius + 17));
          ctx.textBaseline = 'alphabetic';
        });
      }

      function frame() {
        if (view === 'graph' && !document.hidden) {
          stepPhysics();
          draw();
        }
        requestAnimationFrame(frame);
      }

      // --- Controls ---

      el('view-toggle').addEventListener('click', function () {
        view = view === 'graph' ? 'cards' : 'graph';
        document.body.setAttribute('data-view', view);
        el('view-toggle').textContent = view === 'graph' ? 'Raw cards' : 'Cortex graph';
        if (view === 'graph') resize();
      });
      el('btn-sim-write').addEventListener('click', simWrite);
      el('btn-sim-recall').addEventListener('click', simRecall);
      el('btn-sim-consolidate').addEventListener('click', simConsolidate);
      el('btn-sim-refuse').addEventListener('click', simRefuse);
      el('time-slider').addEventListener('input', function () {
        futureDays = Number(el('time-slider').value);
        el('time-label').textContent = futureDays === 0 ? 'NOW (+0.0d)' : 'FUTURE (+' + futureDays.toFixed(1) + 'd)';
        el('time-label').style.color = futureDays > 10 ? '#fcd34d' : '#7dd3fc';
        updateTiers();
        renderInspector();
      });
      el('btn-reset-view').addEventListener('click', function () {
        cam.x = 0;
        cam.y = 0;
        cam.targetZoom = 1;
      });

      var graphReady = false;
      function renderState(s) {
        if (!s || typeof s !== 'object') return;
        var nowSec = s.polled_at || Math.floor(Date.now() / 1000);
        var st = s.store_state || {};
        var syncState = s.connected === false ? 'SOCKET_ERROR' : (st.state || 'UNKNOWN');

        el('reader-name').textContent = s.reader || 'viewer';
        el('server-name').textContent = s.server_name || 'hive-memory-viewer';

        var syncBadge = el('sync-badge');
        syncBadge.textContent = syncState;
        syncBadge.className = syncBadgeClass(syncState);

        el('sync-state').textContent = syncState;
        el('sync-sub').textContent = s.connected === false
          ? ('error: ' + (s.error || 'disconnected'))
          : (st.state === 'READY' ? 'private store ready; never synced to a relay' : 'store not ready; claims withheld until verified restore');

        el('seq-val').textContent = st.write_seq == null ? '-' : String(st.write_seq);
        el('seq-sub').textContent = 'current claims: ' + (st.current_claims == null ? '-' : String(st.current_claims));

        el('backup-val').textContent = st.last_backup_age_sec == null ? 'none' : (String(st.last_backup_age_sec) + 's ago');
        el('backup-sub').textContent = 'unbacked writes: ' + (st.unbacked_writes == null ? '-' : String(st.unbacked_writes));

        el('poll-val').textContent = fmtTime(s.polled_at);
        el('poll-sub').textContent = 'query answer: ' + (s.query_answer || '-') + ' (poll #' + (s.poll_seq || 0) + ')';

        var sc = s.scope_counts || {};
        el('count-canon').textContent = String(sc.canon ?? 0);
        el('sub-canon').textContent = 'unverified canon: ' + String(sc.canon_unverified ?? 0);
        el('count-ops').textContent = String(sc.ops ?? 0);
        el('count-rooms').textContent = String(sc.rooms ?? 0);
        el('count-self').textContent = String(sc.self ?? 0);
        el('sub-unverified').textContent = 'unverified total: ' + String(sc.unverified_total ?? 0);

        renderRecords(Array.isArray(s.records) ? s.records : [], nowSec);
        renderLog(s.event_log);
        measureHud();
        syncGraph(s, graphReady);
        graphReady = true;
      }

      resize();
      try {
        var initJson = el('initial-state').textContent;
        if (initJson) renderState(JSON.parse(initJson));
      } catch (_) {}
      requestAnimationFrame(frame);

      if (typeof EventSource !== 'undefined') {
        var es = new EventSource('/events');
        var sseBadge = el('sse-badge');
        es.onopen = function () {
          sseBadge.textContent = 'SSE: live';
          sseBadge.className = 'badge ok';
        };
        es.onmessage = function (ev) {
          try {
            renderState(JSON.parse(ev.data));
          } catch (_) {}
        };
        es.onerror = function () {
          sseBadge.textContent = 'SSE: reconnecting';
          sseBadge.className = 'badge warn';
        };
      }
    })();
  </script>
</body>
</html>`
}

export async function startMemoryViewer({
  socketPath,
  host,
  port,
  pollMs = DEFAULT_POLL_MS,
} = {}) {
  if (!socketPath || !isAbsolute(socketPath)) {
    throw new Error('--socket <absolute-path> is required')
  }
  const target = parseListenTarget({ host, port })
  const client = createSingleSocketMcpClient(socketPath)
  const sseClients = new Set()
  const eventLog = []
  let pollSeq = 0
  let stopped = false

  let currentState = {
    connected: false,
    error: 'initial poll pending',
    server_name: 'hive-memory-viewer',
    reader: 'viewer',
    reader_pubkey: null,
    authority: null,
    trustedInstruction: false,
    polled_at: null,
    poll_seq: 0,
    store_state: { state: 'CONNECTING', write_seq: null, current_claims: null, last_backup_age_sec: null, unbacked_writes: null },
    scope_counts: { canon: 0, ops: 0, rooms: 0, self: 0, canon_unverified: 0, unverified_total: 0 },
    query_answer: null,
    records: [],
    agent_roster: [],
    recent_activity: [],
    event_log: [],
  }

  function broadcastState() {
    const payload = `data: ${JSON.stringify(currentState)}\n\n`
    for (const res of sseClients) {
      try {
        res.write(payload)
      } catch {
        sseClients.delete(res)
      }
    }
  }

  async function pollOnce() {
    if (stopped) return currentState
    const nowSec = Math.floor(Date.now() / 1000)
    pollSeq += 1
    let nextSnapshot
    try {
      const wake = await client.callReadTool('memory_wake', {})
      const query = await client.callReadTool('memory_query', { limit: 100, format: 'full' })

      const byKey = new Map()
      for (const r of Array.isArray(query?.records) ? query.records : []) {
        const clean = sanitizeMemoryRecord(r)
        if (clean) byKey.set(`${clean.author_pubkey}:${clean.d}`, clean)
      }
      // Since Phase 2 wake records are bare references (no claim); only full records are shown.
      for (const r of Array.isArray(wake?.records) ? wake.records.filter(x => typeof x?.claim === 'string') : []) {
        const clean = sanitizeMemoryRecord(r)
        if (clean && !byKey.has(`${clean.author_pubkey}:${clean.d}`)) {
          byKey.set(`${clean.author_pubkey}:${clean.d}`, clean)
        }
      }
      const records = [...byKey.values()].sort(
        (a, b) => (a.computed_rank || 99) - (b.computed_rank || 99) || (b.created_at || 0) - (a.created_at || 0)
      )
      const scopeCounts = computeScopeCounts(wake?.counts, records)

      nextSnapshot = {
        connected: true,
        error: null,
        server_name: client.getServerName() || 'hive-memory-viewer',
        reader: String(wake?.reader || query?.reader || 'viewer'),
        reader_pubkey: wake?.reader_pubkey || query?.reader_pubkey || null,
        authority: null,
        trustedInstruction: false,
        polled_at: nowSec,
        poll_seq: pollSeq,
        store_state: wake?.store_state || query?.store_state || { state: 'UNKNOWN', write_seq: null, current_claims: null, last_backup_age_sec: null, unbacked_writes: null },
        scope_counts: scopeCounts,
        query_answer: String(query?.answer || 'unknown'),
        records,
        agent_roster: (Array.isArray(wake?.agent_roster) ? wake.agent_roster : []).map(sanitizeRosterEntry).filter(Boolean),
        recent_activity: (Array.isArray(wake?.recent_activity) ? wake.recent_activity : []).map(sanitizeActivity).filter(Boolean),
      }
    } catch (err) {
      nextSnapshot = {
        ...currentState,
        connected: false,
        error: String(err.message || err),
        polled_at: nowSec,
        poll_seq: pollSeq,
        authority: null,
        trustedInstruction: false,
      }
    }

    const prevForDiff = currentState.polled_at === null ? null : currentState
    const diffs = diffViewerSnapshots(prevForDiff, nextSnapshot, nowSec)
    for (const d of diffs) {
      eventLog.push(d)
      if (eventLog.length > MAX_EVENT_LOG) eventLog.shift()
    }
    currentState = {
      ...nextSnapshot,
      event_log: [...eventLog],
    }
    broadcastState()
    return currentState
  }

  await pollOnce()
  const pollTimer = setInterval(() => {
    void pollOnce()
  }, pollMs)
  pollTimer.unref?.()

  const securityHeaders = {
    'Content-Security-Policy':
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
  }

  const httpServer = createHttpServer((req, res) => {
    const method = req.method || 'GET'
    if (method !== 'GET' && method !== 'HEAD') {
      res.writeHead(405, { ...securityHeaders, Allow: 'GET, HEAD', 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('Method Not Allowed\n')
      return
    }

    const urlPath = String(req.url || '/').split('?')[0]
    if (urlPath === '/events') {
      res.writeHead(200, {
        ...securityHeaders,
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
      })
      if (method === 'HEAD') {
        res.end()
        return
      }
      res.write(`data: ${JSON.stringify(currentState)}\n\n`)
      sseClients.add(res)
      req.on('close', () => {
        sseClients.delete(res)
      })
      return
    }

    if (urlPath === '/api/state' || urlPath === '/state.json') {
      const body = JSON.stringify(currentState, null, 2) + '\n'
      res.writeHead(200, {
        ...securityHeaders,
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(body),
      })
      res.end(method === 'HEAD' ? undefined : body)
      return
    }

    if (urlPath === '/' || urlPath === '/index.html') {
      const html = renderViewerHtml(currentState)
      res.writeHead(200, {
        ...securityHeaders,
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Length': Buffer.byteLength(html),
      })
      res.end(method === 'HEAD' ? undefined : html)
      return
    }

    res.writeHead(404, { ...securityHeaders, 'Content-Type': 'text/plain; charset=utf-8' })
    res.end('Not Found\n')
  })

  await new Promise((resolveListen, rejectListen) => {
    httpServer.once('error', rejectListen)
    httpServer.listen(target.port, target.host, () => {
      httpServer.removeListener('error', rejectListen)
      resolveListen()
    })
  })

  const addr = httpServer.address()
  const boundPort = typeof addr === 'object' && addr ? addr.port : target.port

  return {
    host: target.host,
    port: boundPort,
    pollOnce,
    getState: () => currentState,
    async stop() {
      stopped = true
      clearInterval(pollTimer)
      for (const res of sseClients) {
        try {
          res.end()
        } catch {
          /* ignore */
        }
      }
      sseClients.clear()
      client.close()
      await new Promise(resolveClose => httpServer.close(() => resolveClose()))
    },
  }
}

async function main() {
  let flags
  try {
    flags = parseViewerFlags(process.argv.slice(2))
  } catch (err) {
    console.error(`memory-viewer: ${err.message}`)
    process.exit(1)
  }

  try {
    const viewer = await startMemoryViewer(flags)
    const fmtHost = viewer.host.includes(':') ? `[${viewer.host}]` : viewer.host
    console.log(`memory-viewer: listening on http://${fmtHost}:${viewer.port} (socket ${flags.socketPath})`)
    const shutdown = async () => {
      await viewer.stop()
      process.exit(0)
    }
    process.on('SIGINT', shutdown)
    process.on('SIGTERM', shutdown)
  } catch (err) {
    console.error(`memory-viewer: startup failed: ${err.message}`)
    process.exit(1)
  }
}

if (process.argv[1] && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1])) {
  main()
}
