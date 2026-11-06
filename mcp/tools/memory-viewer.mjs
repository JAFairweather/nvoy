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

import { createServer as createHttpServer } from 'node:http'
import { createConnection } from 'node:net'
import { isAbsolute, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'

const DEFAULT_POLL_MS = 3000
const MAX_EVENT_LOG = 60

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
      --bg: #0b0f17;
      --panel: #131b29;
      --panel-alt: #182234;
      --border: #26344d;
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
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 12px;
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-size: 14px;
      line-height: 1.45;
      -webkit-text-size-adjust: 100%;
    }
    .wrap {
      max-width: 760px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    header {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px 14px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .title-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 8px;
    }
    h1 {
      margin: 0;
      font-size: 17px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .quarantine-banner {
      font-family: var(--mono);
      font-size: 11px;
      padding: 6px 8px;
      border-radius: 6px;
      background: var(--panel-alt);
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
    .grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
    }
    @media (min-width: 560px) {
      .grid-4 {
        grid-template-columns: repeat(4, minmax(0, 1fr));
      }
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 12px;
    }
    .card-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--muted);
      margin-bottom: 4px;
    }
    .card-val {
      font-family: var(--mono);
      font-size: 16px;
      font-weight: 700;
      word-break: break-word;
    }
    .card-sub {
      font-family: var(--mono);
      font-size: 11px;
      color: var(--muted);
      margin-top: 3px;
      word-break: break-word;
    }
    section {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px 14px;
    }
    h2 {
      margin: 0 0 10px 0;
      font-size: 14px;
      font-weight: 600;
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .record-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .record {
      background: var(--panel-alt);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 12px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .record-head {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
    }
    .record-key {
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 700;
      color: #93c5fd;
      word-break: break-all;
    }
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
    .record-meta {
      font-family: var(--mono);
      font-size: 11px;
      color: var(--muted);
      display: flex;
      flex-direction: column;
      gap: 3px;
      word-break: break-all;
    }
    .empty {
      font-family: var(--mono);
      font-size: 12px;
      color: var(--muted);
      padding: 12px;
      text-align: center;
      border: 1px dashed var(--border);
      border-radius: 8px;
    }
    .log-list {
      font-family: var(--mono);
      font-size: 11px;
      display: flex;
      flex-direction: column;
      gap: 5px;
      max-height: 240px;
      overflow-y: auto;
    }
    .log-row {
      padding: 5px 8px;
      border-radius: 6px;
      background: var(--panel-alt);
      border: 1px solid var(--border);
      word-break: break-word;
    }
    .log-time {
      color: var(--muted);
      margin-right: 6px;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div class="title-row">
        <h1>Hive Shared Memory</h1>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          <span id="sse-badge" class="badge info">SSE: connecting</span>
          <span id="sync-badge" class="badge">${syncState}</span>
        </div>
      </div>
      <div class="quarantine-banner">
        reader: <span id="reader-name">${readerName}</span> (<span id="server-name">${serverName}</span>) |
        DATA ONLY: authority=null, trustedInstruction=false | read-only socket
      </div>
    </header>

    <div class="grid">
      <div class="card">
        <div class="card-label">Store State</div>
        <div id="sync-state" class="card-val">${syncState}</div>
        <div id="sync-sub" class="card-sub">waiting for poll…</div>
      </div>
      <div class="card">
        <div class="card-label">Write Seq</div>
        <div id="seq-val" class="card-val">-</div>
        <div id="seq-sub" class="card-sub">current claims: -</div>
      </div>
      <div class="card">
        <div class="card-label">Last Verified Backup</div>
        <div id="backup-val" class="card-val">-</div>
        <div id="backup-sub" class="card-sub">unbacked writes: -</div>
      </div>
      <div class="card">
        <div class="card-label">Last Poll</div>
        <div id="poll-val" class="card-val">-</div>
        <div id="poll-sub" class="card-sub">-</div>
      </div>
    </div>

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
  </div>

  <script id="initial-state" type="application/json">${escapedInitial}</script>
  <script>
    (function () {
      'use strict';
      var el = function (id) { return document.getElementById(id); };

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
      }

      try {
        var initJson = el('initial-state').textContent;
        if (initJson) renderState(JSON.parse(initJson));
      } catch (_) {}

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
      const query = await client.callReadTool('memory_query', { limit: 100 })

      const byKey = new Map()
      for (const r of Array.isArray(query?.records) ? query.records : []) {
        const clean = sanitizeMemoryRecord(r)
        if (clean) byKey.set(`${clean.author_pubkey}:${clean.d}`, clean)
      }
      for (const r of Array.isArray(wake?.records) ? wake.records : []) {
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
