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
//      drive the cortex canvas and live Merkle Dreaming & 3-Trigger Curation telemetry.

import { readFileSync } from 'node:fs'
import { createServer as createHttpServer } from 'node:http'
import { createConnection } from 'node:net'
import { isAbsolute, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import {
  DEFAULT_DREAM_INTERVAL_SEC,
  DEFAULT_TOPIC_PRESSURE_THRESHOLD,
  DEFAULT_WRITE_DELTA_THRESHOLD,
  computeTopicEigenvectors,
  defaultCuratorStatePath,
  evaluateDreamTriggers,
  planMerkleDream,
  readCuratorStateFile,
  resolveCuratorStatePath,
} from './memory-curate.mjs'
import {
  buildConstellationLinks,
  compileTopicPagesFromRecords,
  renderTopicPageMarkdown,
} from './hive_memory_store.mjs'

const DEFAULT_POLL_MS = 3000
const MAX_EVENT_LOG = 60
// One version for the page and the live snapshot: the page reloads whenever they differ.
const VIEWER_VERSION = '2026-11-09-v14'
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
  if (countFlag('--state-file') > 1) throw new Error('only one --state-file may be specified')
  const getFlag = name => {
    const idx = args.indexOf(name)
    return idx < 0 ? '' : String(args[idx + 1] ?? '')
  }

  const socketRaw = getFlag('--socket')
  if (!socketRaw || !isAbsolute(socketRaw)) {
    throw new Error('--socket <absolute-path> is required')
  }
  const stateFileRaw = getFlag('--state-file')
  if (stateFileRaw && !isAbsolute(stateFileRaw)) {
    throw new Error('--state-file <absolute-path> must be an absolute path')
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
    ...(stateFileRaw ? { stateFile: resolve(stateFileRaw) } : {}),
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
    status: rec.status ? String(rec.status) : 'active',
    is_current: rec.is_current === undefined ? true : Boolean(rec.is_current),
    claim: String(rec.claim || ''),
    because: String(rec.because || ''),
    evidence: Array.isArray(rec.evidence) ? rec.evidence.map(e => String(e)) : [],
    as_of_git: rec.as_of_git ? String(rec.as_of_git) : null,
    as_of_evt: rec.as_of_evt ? String(rec.as_of_evt) : null,
    created_at: Number.isFinite(rec.created_at) ? Number(rec.created_at) : null,
    expires_at: Number.isFinite(rec.expires_at) ? Number(rec.expires_at) : null,
    stale_warning: rec.stale_warning ? String(rec.stale_warning) : null,
    consolidated_by: rec.consolidated_by ? String(rec.consolidated_by) : null,
    merkle_sources: rec.merkle_sources ? String(rec.merkle_sources) : null,
    supersedes: Array.isArray(rec.supersedes) ? rec.supersedes.map(s => String(s)) : [],
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

const CANON_PRIORITY_TOPICS = new Set([
  'r1',
  'primer',
  'illustrated-primer',
  'hive-memory',
  'nvoy',
  'herd-infra',
  'hive',
  'buzz',
  'waggle',
])
const KEBAB_TOPIC_RE = /^[a-z0-9][a-z0-9-]{0,31}$/
const ARTIFACT_REF_RE = /\b(?:PR\s*#?\d+|#\d{2,4}|(?:nvoy|rabidrabbit|herd-infra|waggle)@[0-9a-f]{7})/gi

function evaluateCoherenceSlice(slice, rosterByPk, expectedRosterSize, writeSeqEst) {
  if (!Array.isArray(slice) || slice.length === 0) {
    return {
      at: null,
      claims: 0,
      authors: 0,
      shared_refs: 0,
      score: 0,
      axes: { alignment: 0, grounding: 0, convergence: 0, coupling: 0, consolidation: 0 },
    }
  }
  const nonCanon = slice.filter(r => r.scope !== 'hive:canon')
  const canonCount = slice.length - nonCanon.length
  const canonFactor = Math.min(1, canonCount / 5)
  const alignedCount = nonCanon.filter(r => CANON_PRIORITY_TOPICS.has(String(r.topic || ''))).length
  const alignedRatio = nonCanon.length > 0 ? alignedCount / nonCanon.length : 1
  const kebabCount = slice.filter(r => KEBAB_TOPIC_RE.test(String(r.topic || ''))).length
  const kebabRatio = kebabCount / slice.length
  const alignment = Math.round((0.35 * canonFactor + 0.35 * alignedRatio + 0.3 * kebabRatio) * 1000) / 10

  const anchoredCount = nonCanon.filter(r => Boolean(r.as_of_git || r.as_of_evt)).length
  const anchoredRatio = nonCanon.length > 0 ? anchoredCount / nonCanon.length : 1
  const cleanCount = slice.filter(r => !r.conflict && !r.stale_warning).length
  const cleanRatio = cleanCount / slice.length
  const grounding = Math.round((0.5 * anchoredRatio + 0.5 * cleanRatio) * 1000) / 10

  const artifactAuthors = new Map()
  const authors = new Set()
  for (const r of slice) {
    const pk = String(r.author_pubkey || '')
    const actor = rosterByPk.get(pk) || pk.slice(0, 8) || 'unknown'
    authors.add(actor)
    const blob = [r.as_of_git || '', r.claim || '', ...(Array.isArray(r.evidence) ? r.evidence : [])].join(' ')
    const matches = blob.match(ARTIFACT_REF_RE) || []
    for (const raw of matches) {
      const norm = raw.replace(/\s+/g, '').toUpperCase()
      let set = artifactAuthors.get(norm)
      if (!set) {
        set = new Set()
        artifactAuthors.set(norm, set)
      }
      set.add(actor)
    }
  }
  let sharedRefs = 0
  for (const set of artifactAuthors.values()) {
    if (set.size >= 2) sharedRefs += 1
  }
  for (const r of slice) {
    if (r.merkle_sources && Array.isArray(r.supersedes) && r.supersedes.length >= 2) {
      sharedRefs += 1
    }
  }
  // Coherence 2.0 Convergence: blends cumulative cross-author artifact density (which scales with store size
  // rather than saturating permanently at 12 refs) with recent-window cross-agent topic corroboration.
  const targetSharedRefs = slice.length <= 15 ? Math.max(1, slice.length * 0.4) : Math.max(6, nonCanon.length * 0.14)
  const refDensityScore = Math.min(100, (sharedRefs / targetSharedRefs) * 100)

  const peerNonCanon = nonCanon.filter(r => !r.merkle_sources && rosterByPk.get(String(r.author_pubkey || '')) !== 'curator')
  const recentNonCanon = (peerNonCanon.length > 0 ? peerNonCanon : nonCanon).slice(-18)
  const recentTopics = new Map()
  const recentAuthors = new Set()
  for (const r of recentNonCanon) {
    const pk = String(r.author_pubkey || '')
    const actor = rosterByPk.get(pk) || pk.slice(0, 8) || 'unknown'
    recentAuthors.add(actor)
    const top = String(r.topic || 'general')
    let set = recentTopics.get(top)
    if (!set) {
      set = { count: 0, authors: new Set() }
      recentTopics.set(top, set)
    }
    set.count += 1
    set.authors.add(actor)
  }
  let multiClaimTopics = 0
  let corroboratedTopics = 0
  let siloedTopics = 0
  for (const info of recentTopics.values()) {
    if (info.count >= 2) {
      multiClaimTopics += 1
      if (info.authors.size >= 2) corroboratedTopics += 1
      else if (info.count >= 3) siloedTopics += 1
    }
  }
  const topicCorroboration =
    multiClaimTopics > 0
      ? Math.max(0, (corroboratedTopics / multiClaimTopics) * 100 - siloedTopics * 12)
      : recentNonCanon.length <= 2
        ? refDensityScore
        : 65
  const convergence = Math.round((0.6 * refDensityScore + 0.4 * topicCorroboration) * 10) / 10

  // Coherence 2.0 Coupling: blends cumulative roster breadth (55%) with active-window author participation (45%)
  // so coupling dips when only 1-2 agents write a burst of claims while the rest of the Hive is silent.
  const denomAuthors = Math.max(1, Math.min(14, expectedRosterSize || 14))
  const cumulativeCoupling = Math.min(100, (authors.size / denomAuthors) * 100)
  const windowTargetAuthors = Math.max(1, Math.min(denomAuthors, Math.min(6, recentNonCanon.length || 1)))
  const windowCoupling = Math.min(100, (recentAuthors.size / windowTargetAuthors) * 100)
  const coupling = Math.round((0.55 * cumulativeCoupling + 0.45 * windowCoupling) * 10) / 10

  const durableCount = slice.filter(r => r.scope === 'hive:canon' || r.expires_at === null || r.expires_at === undefined).length
  const durableRatio = durableCount / slice.length
  const curatedOrSuperseded = slice.filter(
    r => Boolean(r.merkle_sources) || (Array.isArray(r.supersedes) && r.supersedes.length > 0)
  ).length
  const uncuratedClassACount = nonCanon.filter(
    r => r.expires_at !== null && r.expires_at !== undefined && !r.merkle_sources
  ).length
  let reuseBonus = 1
  if (Number.isSafeInteger(writeSeqEst) && writeSeqEst > slice.length) {
    reuseBonus = Math.min(1, 0.7 + 0.3 * ((writeSeqEst - slice.length) / Math.max(1, writeSeqEst)))
  }
  let rawConsolidation = (0.6 * Math.min(1, durableRatio / 0.35) + 0.4 * reuseBonus) * 100
  if (slice.length > 15 && uncuratedClassACount > durableCount) {
    const backlogRatio = uncuratedClassACount / slice.length
    const merkleCoverage = Math.min(1, curatedOrSuperseded / Math.max(1, nonCanon.length * 0.16))
    const backlogPenalty = Math.max(0, (backlogRatio - 0.35) * 95 * (1 - 0.7 * merkleCoverage))
    rawConsolidation = Math.max(18, rawConsolidation - backlogPenalty)
  }
  const consolidation = Math.round(Math.min(100, rawConsolidation) * 10) / 10

  const score = Math.round((0.25 * alignment + 0.2 * grounding + 0.25 * convergence + 0.15 * coupling + 0.15 * consolidation) * 10) / 10
  return {
    at: slice[slice.length - 1]?.created_at || null,
    claims: slice.length,
    authors: authors.size,
    shared_refs: sharedRefs,
    score,
    axes: { alignment, grounding, convergence, coupling, consolidation },
  }
}

const WORKFLOW_SLUG_RE = /-(?:review|status|owner|wip|handoff)$/

function filterActiveAtEpoch(heads, epochAt, isCurrentFinal = false) {
  const unexpired = heads.filter(r => {
    if (!r || r.status === 'withdrawn' || r.verification === 'withdrawn') return false
    if (isCurrentFinal && (r.verification === 'expired' || r.verification === 'consolidated' || r.verification === 'superseded')) {
      return false
    }
    return r.expires_at === null || r.expires_at === undefined || r.expires_at > epochAt
  })
  const byEventId = new Map()
  for (const r of unexpired) {
    if (r.event_id) byEventId.set(r.event_id, r)
  }
  const supersededByPeer = new Set()
  for (const c of unexpired) {
    if (Array.isArray(c.supersedes)) {
      for (const tid of c.supersedes) {
        const s = byEventId.get(String(tid))
        if (
          s &&
          c.event_id !== s.event_id &&
          c.scope === s.scope &&
          (c.created_at || 0) >= (s.created_at || 0) &&
          s.scope !== 'hive:canon' &&
          WORKFLOW_SLUG_RE.test(String(s.d || '').split(':').pop() || '')
        ) {
          supersededByPeer.add(s.event_id)
        }
      }
    }
  }
  return unexpired.filter(r => {
    if (r.scope === 'hive:canon') return true
    if (isCurrentFinal && r.consolidated_by && byEventId.has(r.consolidated_by)) return false
    if (r.event_id && supersededByPeer.has(r.event_id)) return false
    return true
  })
}

export function computeCoherence({
  records = [],
  history_records = null,
  agent_roster = [],
  recent_activity = [],
  store_state = {},
  now_sec = null,
  history_complete = true,
} = {}) {
  const hasHistory = Array.isArray(history_records) && history_records.length > 0
  const sourceEvents = hasHistory ? history_records : (Array.isArray(records) ? records : [])
  const chronological = [...sourceEvents]
    .filter(Boolean)
    .sort((a, b) => (a.created_at || 0) - (b.created_at || 0) || (String(a.event_id || '') < String(b.event_id || '') ? -1 : 1))
  const rosterByPk = new Map()
  let writerCount = 0
  for (const a of Array.isArray(agent_roster) ? agent_roster : []) {
    if (a?.pubkey) rosterByPk.set(a.pubkey, a.id)
    if (a?.is_writer) writerCount += 1
  }
  const expectedRosterSize = writerCount > 0 ? Math.min(14, writerCount) : 14

  if (chronological.length === 0) {
    return {
      score: 0,
      inception_at: null,
      inception_score: 0,
      delta_since_inception: 0,
      total_events: 0,
      shared_artifacts: 0,
      history_complete: Boolean(history_complete),
      history_window: history_complete ? '90d-retained' : 'truncated-5000',
      axes: { alignment: 0, grounding: 0, convergence: 0, coupling: 0, consolidation: 0 },
      epistemic_drift: {
        score: 0,
        status: 'empty',
        zero_hit_queries: 0,
        missed_topics: [],
        silent_active_writers: [],
        siloed_recent_topics: [],
      },
      history: [],
    }
  }

  const total = chronological.length
  const extraSteps = []
  if (total > 150) {
    for (let s = 170; s < total; s += 15) extraSteps.push(s)
    if (total > 12) extraSteps.push(total - 8, total - 4)
  }
  const rawSteps = [1, 5, 10, 20, 30, 40, 50, 65, 80, 100, 125, 150, ...extraSteps, total]
  const uniqueSteps = [...new Set(rawSteps.filter(k => k >= 1 && k <= total))].sort((a, b) => a - b)
  while (uniqueSteps.length > 14) {
    uniqueSteps.splice(1, 1)
  }
  if (uniqueSteps[uniqueSteps.length - 1] !== total) uniqueSteps.push(total)

  // Replay retained historical events (including supersessions, cross-author checkpoints, and withdrawals).
  const stepSet = new Set(uniqueSteps)
  const activeHeads = new Map()
  const history = []
  for (let i = 0; i < total; i++) {
    const ev = chronological[i]
    const headKey = `${ev.author_pubkey || ''}:${ev.d || ''}`
    if (ev.status === 'withdrawn' || ev.verification === 'withdrawn') {
      activeHeads.delete(headKey)
    } else {
      activeHeads.set(headKey, ev)
    }
    const stepNum = i + 1
    if (stepSet.has(stepNum)) {
      const isFinalStep = stepNum === total
      const epochAt = isFinalStep && Number.isSafeInteger(now_sec)
        ? Math.max(ev.created_at || 0, now_sec)
        : (ev.created_at || 0)
      let activeAtEpoch = filterActiveAtEpoch([...activeHeads.values()], epochAt, isFinalStep)
      if (isFinalStep && hasHistory && Array.isArray(records)) {
        const reconciled = filterActiveAtEpoch(records, epochAt, true)
        if (reconciled.length > 0 || records.length === 0) {
          activeAtEpoch = reconciled
        }
      }
      const writeSeqAtEpoch = isFinalStep && Number.isSafeInteger(store_state?.write_seq)
        ? Math.max(stepNum, store_state.write_seq)
        : stepNum
      const snap = evaluateCoherenceSlice(activeAtEpoch, rosterByPk, expectedRosterSize, writeSeqAtEpoch)
      snap.at = epochAt || snap.at
      snap.events = stepNum
      history.push(snap)
    }
  }

  const current = history[history.length - 1]
  const inception = history[0]
  const activityList = Array.isArray(recent_activity) ? recent_activity : []

  // Epistemic Drift & Blind-Spot Detection:
  // Catches when agents query shared memory and get 0 matches (blind spots), when active writers wake/query
  // repeatedly without sharing room claims (silent work drift), or when recent topics are siloed to a single author.
  const allNonCanon = chronological.filter(r => r && r.scope !== 'hive:canon' && r.status !== 'withdrawn')
  const peerChrono = allNonCanon.filter(r => !r.merkle_sources && rosterByPk.get(String(r.author_pubkey || '')) !== 'curator')
  const recentNonCanon = (peerChrono.length > 0 ? peerChrono : allNonCanon).slice(-18)
  const recentTopicAuthors = new Map()
  const recentWriterIds = new Set()
  for (const r of recentNonCanon) {
    const actor = rosterByPk.get(String(r.author_pubkey || '')) || String(r.author_pubkey || '').slice(0, 8)
    if (actor) recentWriterIds.add(actor)
    const top = String(r.topic || '').trim()
    if (!top) continue
    let entry = recentTopicAuthors.get(top)
    if (!entry) {
      entry = { count: 0, authors: new Set() }
      recentTopicAuthors.set(top, entry)
    }
    entry.count += 1
    if (actor) entry.authors.add(actor)
  }
  const nonCuratorRecentWriters = [...recentWriterIds].filter(w => w !== 'curator')
  const siloedRecentTopics = []
  if (nonCuratorRecentWriters.length >= 2) {
    for (const [top, info] of recentTopicAuthors.entries()) {
      if (info.count >= 3 && info.authors.size === 1) {
        siloedRecentTopics.push(top)
      }
    }
  }

  let zeroHitQueries = 0
  const missedTopicsSet = new Set()
  const readsByActor = new Map()
  const recallByActor = new Map()
  const writesByActor = new Map()
  for (let idx = 0; idx < activityList.length; idx++) {
    const a = activityList[idx]
    if (!a || typeof a !== 'object') continue
    const actor = String(a.actor || '')
    if (a.kind === 'query' || a.kind === 'wake' || a.kind === 'lookup') {
      if (actor) readsByActor.set(actor, (readsByActor.get(actor) || 0) + 1)
      if ((a.kind === 'query' || a.kind === 'wake') && actor) {
        recallByActor.set(actor, (recallByActor.get(actor) || 0) + 1)
      }
      if (a.kind === 'query' && a.count === 0 && actor !== 'curator' && actor !== 'viewer' && a.topic) {
        missedTopicsSet.add(String(a.topic))
        const resolvedSoon = activityList.slice(idx + 1, idx + 12).some(
          next =>
            next &&
            next.actor === actor &&
            ((next.kind === 'query' && Number(next.count) > 0) ||
              (next.kind === 'submit' && next.accepted !== false))
        )
        if (!resolvedSoon) {
          zeroHitQueries += 1
        }
      }
    } else if (a.kind === 'submit' && a.accepted !== false) {
      if (actor) writesByActor.set(actor, (writesByActor.get(actor) || 0) + 1)
    }
  }

  const rosterArr = Array.isArray(agent_roster) ? agent_roster : []
  const writerIdSet = new Set(
    rosterArr.filter(a => a?.is_writer && a?.id).map(a => a.id)
  )
  const silentActiveWriters = []
  for (const [actor, readCount] of readsByActor.entries()) {
    if (writerIdSet.has(actor) && readCount >= 4 && !writesByActor.has(actor) && !recentWriterIds.has(actor)) {
      silentActiveWriters.push(actor)
    }
  }

  // Bilateral Fleet Recall & Participation Audit:
  // If agents on the roster are not reading (0 wake/query) or are writing blind (lookup-only without wake/query),
  // the Hive cannot be fully coherent even if the few active writers produce well-formatted records.
  const peerReaders = rosterArr.filter(a => a && a.is_reader === true && a.id && a.id !== 'curator' && a.id !== 'viewer')
  const blindRosterAgents = []
  const lookupOnlyWriters = []
  const verifiedRecallAgents = []
  const toolFailureAlerts = []
  const behavioralAlerts = []
  const recentRefusalByActor = new Map()
  for (const a of activityList) {
    if (a && a.kind === 'refused' && a.actor) {
      const prev = recentRefusalByActor.get(a.actor)
      if (!prev || (a.at || 0) >= (prev.at || 0)) {
        recentRefusalByActor.set(a.actor, { code: a.code || 'STORE_REFUSED', at: a.at || now_sec, d: a.d || null })
      }
    }
  }
  const reportedFailureRegex = /timed out during banner exchange|memory store did not answer in time|permission denied \(publickey\)|ssh-timeout-diagnosis|cli-ssh-handshake/i
  const seenFailureSlugs = new Set()
  for (const r of allNonCanon) {
    if (!r || typeof r !== 'object') continue
    const age = Math.max(0, now_sec - (r.created_at || 0))
    if (age > 3600) continue
    const slug = String(r.d || '').split(':').pop() || r.d || 'incident'
    if (seenFailureSlugs.has(slug)) continue
    const text = `${slug} ${r.claim || ''}`
    if (reportedFailureRegex.test(text) && !/\b(?:fixed|resolved|verified)\b/i.test(slug)) {
      seenFailureSlugs.add(slug)
      const actor = rosterByPk.get(String(r.author_pubkey || '')) || String(r.author_pubkey || '').slice(0, 8)
      toolFailureAlerts.push({
        agent: actor,
        category: 'tool_failure',
        kind: 'reported_tool_or_transport_failure',
        severity: 'error',
        code: 'TRANSPORT_OR_CLI_FAILURE',
        detail: `${slug}: ${String(r.claim || '').slice(0, 120)}`,
        at: r.created_at || now_sec,
      })
    }
  }
  for (const [actor, ref] of recentRefusalByActor.entries()) {
    toolFailureAlerts.push({
      agent: actor,
      category: 'tool_failure',
      kind: 'store_refusal',
      severity: 'error',
      code: ref.code,
      detail: `Store refused write/read (${ref.code})${ref.d ? ` on ${String(ref.d).split(':').pop()}` : ''}`,
      at: ref.at,
    })
  }
  for (const a of peerReaders) {
    const id = a.id
    if (a.last_refused_at && Math.max(0, now_sec - a.last_refused_at) <= 3600 && !recentRefusalByActor.has(id)) {
      toolFailureAlerts.push({
        agent: id,
        category: 'tool_failure',
        kind: 'store_refusal',
        severity: 'error',
        code: a.last_refused_code || 'STORE_REFUSED',
        detail: `Store refused operation (${a.last_refused_code || 'STORE_REFUSED'})`,
        at: a.last_refused_at,
      })
    }
    const isLiveClock = Number.isSafeInteger(now_sec) && now_sec > 100000
    const recallAtForSeat = a.last_recall_at || ((a.last_read_kind === 'wake' || a.last_read_kind === 'query') ? a.last_read_at : null)
    const seatRecallAge = recallAtForSeat ? Math.max(0, now_sec - recallAtForSeat) : null
    const hasRecall = isLiveClock
      ? (recallByActor.has(id) || (seatRecallAge !== null && seatRecallAge <= 3600 && a.last_read_kind !== 'lookup'))
      : (
          recallByActor.has(id) ||
          a.last_recall_kind === 'wake' ||
          a.last_recall_kind === 'query' ||
          a.last_read_kind === 'wake' ||
          a.last_read_kind === 'query'
        )
    const hasAnyRead = readsByActor.has(id) || Boolean(a.last_read_at)
    if (hasRecall) {
      verifiedRecallAgents.push(id)
    } else if (hasAnyRead || writesByActor.has(id) || recentWriterIds.has(id)) {
      if (a.last_read_kind === 'lookup' || !recallAtForSeat) {
        lookupOnlyWriters.push(id)
        behavioralAlerts.push({
          agent: id,
          category: 'behavioral_noncompliance',
          kind: 'write_without_recall',
          severity: 'warning',
          code: 'WRITE_WITHOUT_RECALL',
          detail: 'Wrote claims (lookup/submit) without calling memory_wake or memory_query',
          at: a.last_write_at || a.last_read_at || now_sec,
        })
      }
    } else {
      blindRosterAgents.push(id)
      behavioralAlerts.push({
        agent: id,
        category: 'behavioral_noncompliance',
        kind: 'blind_roster_seat',
        severity: 'warning',
        code: 'BLIND_ROSTER_SEAT',
        detail: 'Provisioned reader seat has 0 observed memory_wake / memory_query calls',
        at: now_sec,
      })
    }
  }
  for (const actor of silentActiveWriters) {
    behavioralAlerts.push({
      agent: actor,
      category: 'behavioral_noncompliance',
      kind: 'read_without_write',
      severity: 'warning',
      code: 'READ_WITHOUT_WRITE',
      detail: 'Executed >=4 memory reads without recording any claim in window',
      at: now_sec,
    })
  }
  const hasExplicitReaderFleet = peerReaders.length >= 4
  const recallCoveragePct = peerReaders.length > 0
    ? Math.round((verifiedRecallAgents.length / peerReaders.length) * 1000) / 10
    : (recallByActor.size > 0 ? 100 : 0)
  const alerts = [...toolFailureAlerts, ...(hasExplicitReaderFleet ? behavioralAlerts : [])].map(a => ({
    ...a,
    actor: a.actor || a.agent,
    summary: a.summary || a.detail,
  }))

  const missedTopics = [...missedTopicsSet]
  // Per-agent periphery coherence score (0-100): measures how synchronized each individual agent on the periphery
  // is with the Hive's memory state (Recall Sync 50% + Write/Tool Hygiene 30% + Shared Resonance 20%), with recency decay.
  const isLiveClockForPeriphery = Number.isSafeInteger(now_sec) && now_sec > 100000
  const peripheryAgents = peerReaders.map(a => {
    const id = a.id
    const hasEverRecalled =
      recallByActor.has(id) ||
      a.last_recall_kind === 'wake' ||
      a.last_recall_kind === 'query' ||
      a.last_read_kind === 'wake' ||
      a.last_read_kind === 'query'
    const hasAnyRead = readsByActor.has(id) || Boolean(a.last_read_at)
    const hasWrite = writesByActor.has(id) || recentWriterIds.has(id) || Boolean(a.last_write_at)
    const hasRefusal = recentRefusalByActor.has(id) || (a.last_refused_at && Math.max(0, now_sec - a.last_refused_at) <= 900)
    const recallAt = a.last_recall_at || (hasEverRecalled ? (a.last_read_at || now_sec) : null)
    const recallAge = recallAt ? Math.max(0, now_sec - recallAt) : null
    const writeAge = a.last_write_at ? Math.max(0, now_sec - a.last_write_at) : (writesByActor.has(id) ? 0 : null)
    let recallSync = 0
    let writeHygiene = 0
    let sharedResonance = 0
    if (isLiveClockForPeriphery) {
      recallSync = hasEverRecalled && recallAge !== null
        ? (recallAge <= 900 ? 50 : (recallAge <= 3600 ? 34 : (recallAge <= 7200 ? 18 : (recallAge <= 21600 ? 10 : 0))))
        : 0
      const recalledRecently = hasEverRecalled && recallAge !== null && recallAge <= 3600 && a.last_read_kind !== 'lookup'
      if (writeAge !== null && writeAge <= 3600) {
        writeHygiene = recalledRecently ? 30 : 12
      } else if (writeAge !== null && writeAge <= 21600) {
        writeHygiene = (hasEverRecalled && recallAge !== null && recallAge <= 7200) ? 20 : 10
      } else if (writeAge !== null) {
        writeHygiene = 6
      } else if (recalledRecently) {
        writeHygiene = 20
      } else if (hasEverRecalled && recallAge !== null && recallAge <= 21600) {
        writeHygiene = 8
      }
      if (hasRefusal) writeHygiene = Math.max(0, writeHygiene - 15)
      if (recalledRecently && writeAge !== null && writeAge <= 21600) {
        sharedResonance = 20
      } else if (recalledRecently || (writeAge !== null && writeAge <= 3600)) {
        sharedResonance = 10
      } else if ((recallAge !== null && recallAge <= 21600) || (writeAge !== null && writeAge <= 21600)) {
        sharedResonance = 4
      }
    } else {
      recallSync = hasEverRecalled
        ? (recallAge !== null && recallAge <= 900 ? 50 : (recallAge !== null && recallAge <= 3600 ? 44 : 36))
        : 0
      if (hasWrite) {
        writeHygiene = hasEverRecalled ? 30 : 18
      } else if (hasEverRecalled) {
        writeHygiene = 24
      } else if (hasAnyRead) {
        writeHygiene = 10
      }
      if (hasRefusal) writeHygiene = Math.max(0, writeHygiene - 15)
      sharedResonance = (hasEverRecalled && hasWrite) ? 20 : ((hasEverRecalled || hasWrite) ? 14 : (hasAnyRead ? 6 : 0))
    }
    const computedScore = Math.max(0, Math.min(100, Math.round(recallSync + writeHygiene + sharedResonance)))
    const agentScore = typeof a.coherence_score === 'number' && !isLiveClockForPeriphery
      ? a.coherence_score
      : computedScore
    const isSynced = isLiveClockForPeriphery
      ? (hasEverRecalled && recallAge !== null && recallAge <= 3600 && a.last_read_kind !== 'lookup')
      : hasEverRecalled
    return {
      id,
      coherence_score: agentScore,
      status: hasRefusal ? 'tool_failure' : (isSynced ? 'synced' : (hasWrite || hasAnyRead ? 'write_without_recall' : 'blind_seat')),
    }
  })
  const peripheryCoherenceScore = peripheryAgents.length > 0
    ? Math.round((peripheryAgents.reduce((acc, x) => acc + x.coherence_score, 0) / peripheryAgents.length) * 10) / 10
    : current.score

  const fleetRecallPenalty = hasExplicitReaderFleet
    ? blindRosterAgents.length * 4 + lookupOnlyWriters.length * 3
    : 0
  const epistemicPenalty = Math.min(
    75,
    zeroHitQueries * 16 + silentActiveWriters.length * 12 + siloedRecentTopics.length * 8 + fleetRecallPenalty
  )
  const epistemicScore = Math.max(0, Math.round((100 - epistemicPenalty) * 10) / 10)
  const epistemicStatus =
    zeroHitQueries >= 2 || epistemicPenalty >= 28 || (hasExplicitReaderFleet && recallCoveragePct < 50)
      ? 'blind_spot'
      : epistemicPenalty > 0
        ? 'drifting'
        : 'aligned'

  const baseCurrentScore = current.score
  if (activityList.length > 0 || siloedRecentTopics.length > 0 || hasExplicitReaderFleet) {
    if (activityList.length > 0 || hasExplicitReaderFleet) {
      const refusals = activityList.filter(a => a?.kind === 'refused').length
      const gateHygiene = activityList.length > 0 ? Math.max(0, 1 - refusals / activityList.length) : 1
      const silencePenalty = silentActiveWriters.length * 12 + zeroHitQueries * 6
      const hygieneScore = Math.max(0, gateHygiene * 100 - silencePenalty)
      const liveCoupling = hasExplicitReaderFleet
        ? Math.round((0.45 * hygieneScore + 0.55 * recallCoveragePct) * 10) / 10
        : hygieneScore
      current.axes.coupling = Math.round(((hasExplicitReaderFleet ? 0.35 : 0.7) * current.axes.coupling + (hasExplicitReaderFleet ? 0.65 : 0.3) * liveCoupling) * 10) / 10
    }
    if (zeroHitQueries > 0 || siloedRecentTopics.length > 0) {
      const convPenalty = Math.min(45, zeroHitQueries * 14 + siloedRecentTopics.length * 8)
      current.axes.convergence = Math.max(0, Math.round((current.axes.convergence - convPenalty) * 10) / 10)
    }
    if (missedTopics.length > 0) {
      const alignPenalty = Math.min(30, missedTopics.length * 10)
      current.axes.alignment = Math.max(0, Math.round((current.axes.alignment - alignPenalty) * 10) / 10)
    }
    const fleetBlindnessPenalty =
      hasExplicitReaderFleet && recallCoveragePct < 75
        ? Math.min(26, Math.round((75 - recallCoveragePct) * 0.42 * 10) / 10)
        : 0
    current.score = Math.max(0, Math.round((
      0.25 * current.axes.alignment +
      0.2 * current.axes.grounding +
      0.25 * current.axes.convergence +
      0.15 * current.axes.coupling +
      0.15 * current.axes.consolidation -
      fleetBlindnessPenalty
    ) * 10) / 10)
  }

  return {
    score: current.score,
    core_memory_score: baseCurrentScore,
    periphery_coherence_score: peripheryCoherenceScore,
    periphery_agents: peripheryAgents,
    inception_at: chronological[0]?.created_at || null,
    inception_score: inception.score,
    delta_since_inception: Math.round((current.score - inception.score) * 10) / 10,
    total_events: total,
    shared_artifacts: current.shared_refs,
    history_complete: Boolean(history_complete),
    history_window: history_complete ? '90d-retained' : 'truncated-5000',
    axes: current.axes,
    epistemic_drift: {
      score: epistemicScore,
      status: epistemicStatus,
      zero_hit_queries: zeroHitQueries,
      missed_topics: missedTopics,
      silent_active_writers: silentActiveWriters,
      siloed_recent_topics: siloedRecentTopics,
      recall_coverage_pct: recallCoveragePct,
      blind_roster_agents: blindRosterAgents,
      lookup_only_writers: lookupOnlyWriters,
      tool_failures: toolFailureAlerts.length,
      behavioral_gaps: hasExplicitReaderFleet ? behavioralAlerts.length : 0,
      alerts,
    },
    history,
  }
}

const REPO_PR_EXTRACT_RE = /\b(nvoy|nave\.pub|nave-pub|herd-infra|rabidrabbit|illustrated-primer|waggle|buzz)[-\s]*(?:pr[-\s]*)?#?(\d{2,4})\b/gi
const SLUG_STEP_SUFFIX_RE = /-(?:owner|review|reviewed|approved|approval|deployed|deploy|merged|merge|status|hold|live|fix|fixes|fixed|verified|verify|wip|handoff|ready|done|receipt)(?:-[a-z0-9]+)*$/i

export function computeSynapticEfficacy({
  records = [],
  history_records = null,
  agent_roster = [],
  recent_activity = [],
  coherence = null,
  curator_state = null,
  now_sec = null,
} = {}) {
  const activeRecords = Array.isArray(records) ? records.filter(Boolean) : []
  const sourceEvents = Array.isArray(history_records) && history_records.length > 0 ? history_records : activeRecords
  const chronological = [...sourceEvents]
    .filter(Boolean)
    .sort((a, b) => (a.created_at || 0) - (b.created_at || 0) || (String(a.event_id || '') < String(b.event_id || '') ? -1 : 1))

  const rosterArr = Array.isArray(agent_roster) ? agent_roster : []
  const rosterByPk = new Map()
  for (const a of rosterArr) {
    if (a?.pubkey && a?.id) rosterByPk.set(a.pubkey, a.id)
  }
  rosterByPk.set('4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d', 'james')

  if (activeRecords.length === 0 && chronological.length === 0) {
    return {
      score: 0,
      axes: { breadth: 0, precision: 0, velocity: 0, reuse: 0 },
      distribution: {
        recall_coverage_pct: 0,
        read_before_write_pct: 0,
        active_bus_agents: 0,
        total_peer_seats: 0,
        compliant_writers: [],
        receipt_only_writers: [],
        blind_seats: [],
        writer_funnel: [],
      },
      retrieval: {
        query_hit_rate_pct: 0,
        query_hits: 0,
        query_total: 0,
        zero_hit_queries: 0,
        wake_surface_pct: 0,
        state_compression_pct: 0,
        durable_claims: 0,
        raw_class_a_claims: 0,
      },
      velocity: {
        median_handoff_min: null,
        p25_handoff_min: null,
        handoff_count: 0,
        multi_agent_chains: 0,
        recent_handoffs: [],
      },
      reuse: {
        corroborated_topic_pct: 0,
        corroborated_topics: 0,
        total_multi_claim_topics: 0,
        reused_or_durable_pct: 0,
        sprawl_slug_count: 0,
      },
      projected: {
        after_curator_score: 0,
        after_curator_precision: 0,
        after_curator_reuse: 0,
        after_wake_hook_score: 0,
        after_wake_hook_breadth: 0,
      },
      history: [],
    }
  }

  // --- 1. Distribution Breadth & Read-Before-Write Funnel ---
  const activityList = Array.isArray(recent_activity) ? recent_activity : []
  const actorStats = new Map()
  const ensureActor = id => {
    if (!actorStats.has(id)) {
      actorStats.set(id, { actor: id, wakes: 0, queries: 0, query_hits: 0, lookups: 0, submits: 0 })
    }
    return actorStats.get(id)
  }
  let queryTotal = 0
  let queryHits = 0
  let zeroHitQueries = 0
  for (const a of activityList) {
    if (!a || typeof a !== 'object' || !a.actor) continue
    const id = String(a.actor)
    if (id === 'viewer' || id === 'curator') continue
    const st = ensureActor(id)
    if (a.kind === 'wake') st.wakes += 1
    else if (a.kind === 'query') {
      st.queries += 1
      queryTotal += 1
      if ((a.count || 0) > 0) {
        st.query_hits += 1
        queryHits += 1
      } else {
        zeroHitQueries += 1
      }
    } else if (a.kind === 'lookup') st.lookups += 1
    else if (a.kind === 'submit' && a.accepted !== false) st.submits += 1
  }

  const peerReaders = rosterArr.filter(a => a && a.is_reader === true && a.id && a.id !== 'curator' && a.id !== 'viewer')
  const compliantWriters = []
  const receiptOnlyWriters = []
  const blindSeats = []
  const writerFunnel = []

  for (const st of actorStats.values()) {
    const recalled = st.wakes + st.queries > 0
    const wrote = st.submits > 0 || st.lookups > 0
    let mode = 'reader'
    if (wrote && recalled) {
      mode = 'read_before_write'
      compliantWriters.push(st.actor)
    } else if (wrote && !recalled) {
      mode = 'receipt_only'
      receiptOnlyWriters.push(st.actor)
    } else if (recalled) {
      mode = 'recall_only'
    }
    writerFunnel.push({ ...st, mode })
  }
  writerFunnel.sort((a, b) => (b.submits + b.queries + b.wakes) - (a.submits + a.queries + a.wakes))

  let recalledSeatCount = 0
  for (const seat of peerReaders) {
    const st = actorStats.get(seat.id)
    const hasRecall =
      (st && st.wakes + st.queries > 0) ||
      seat.last_recall_kind === 'wake' ||
      seat.last_recall_kind === 'query' ||
      seat.last_read_kind === 'wake' ||
      seat.last_read_kind === 'query'
    const hasWrite = (st && (st.submits > 0 || st.lookups > 0)) || Boolean(seat.last_write_at) || seat.last_read_kind === 'lookup'
    if (hasRecall) {
      recalledSeatCount += 1
    } else if (!hasWrite) {
      blindSeats.push(seat.id)
    } else if (!receiptOnlyWriters.includes(seat.id)) {
      receiptOnlyWriters.push(seat.id)
    }
  }

  const recallCoveragePct = peerReaders.length > 0
    ? Math.round((recalledSeatCount / peerReaders.length) * 1000) / 10
    : (typeof coherence?.epistemic_drift?.recall_coverage_pct === 'number'
        ? coherence.epistemic_drift.recall_coverage_pct
        : (compliantWriters.length > 0 ? 100 : 0))
  const totalActiveWriters = compliantWriters.length + receiptOnlyWriters.length
  const readBeforeWritePct = totalActiveWriters > 0
    ? Math.round((compliantWriters.length / totalActiveWriters) * 1000) / 10
    : recallCoveragePct
  const breadth = Math.round((0.55 * readBeforeWritePct + 0.45 * recallCoveragePct) * 10) / 10

  // --- 2. Retrieval Precision & Signal-to-Noise ---
  const queryHitRatePct = queryTotal > 0 ? Math.round((queryHits / queryTotal) * 1000) / 10 : 85
  const nonCanon = activeRecords.filter(r => r.scope !== 'hive:canon')
  const durableClaims = activeRecords.filter(
    r => r.scope === 'hive:canon' || r.expires_at === null || r.expires_at === undefined || Boolean(r.merkle_sources)
  ).length
  const rawClassAClaims = Math.max(0, activeRecords.length - durableClaims)
  const stateCompressionPct = activeRecords.length > 0
    ? Math.round((durableClaims / activeRecords.length) * 1000) / 10
    : 100
  const wakeSurfacePct = activeRecords.length > 0
    ? Math.min(100, Math.round((Math.min(10, activeRecords.length) / activeRecords.length) * 1000) / 10)
    : 100
  const compressionScore = Math.min(100, (stateCompressionPct / 50) * 100)
  const precision = Math.round((0.60 * queryHitRatePct + 0.40 * compressionScore) * 10) / 10

  // --- 3. Cross-Agent Handoff Velocity (Builder -> Reviewer -> Deployer) ---
  function computeSliceVelocityAndReuse(slice) {
    const sliceNonCanon = slice.filter(r => r && r.scope !== 'hive:canon')
    const chains = new Map()
    const eventChainMembership = new Set()
    const addStep = (key, rec, actor, slug) => {
      let arr = chains.get(key)
      if (!arr) {
        arr = []
        chains.set(key, arr)
      }
      if (!arr.some(x => x.event_id === rec.event_id)) {
        arr.push({
          event_id: rec.event_id || `${actor}:${slug}:${rec.created_at}`,
          actor,
          slug,
          at: rec.created_at || 0,
          git: rec.as_of_git || null,
          key,
        })
      }
    }
    for (const r of sliceNonCanon) {
      const actor = rosterByPk.get(String(r.author_pubkey || '')) || String(r.author_pubkey || '').slice(0, 8) || 'unknown'
      const slug = String(r.d || '').split(':').pop() || ''
      const stem = slug.replace(SLUG_STEP_SUFFIX_RE, '')
      if (stem && stem.length >= 3) addStep(`stem:${stem}`, r, actor, slug)
      const blob = `${slug.replace(/-pr(\d+)/gi, ' #$1')} ${r.claim || ''}`
      REPO_PR_EXTRACT_RE.lastIndex = 0
      let m
      while ((m = REPO_PR_EXTRACT_RE.exec(blob)) !== null) {
        const repo = m[1].toLowerCase().replace('nave.pub', 'nave-pub').replace('rabidrabbit', 'illustrated-primer')
        addStep(`pr:${repo}#${m[2]}`, r, actor, slug)
      }
    }

    const handoffByPair = new Map()
    const multiAgentChainKeys = new Set()
    for (const [k, arr] of chains.entries()) {
      if (arr.length >= 2) {
        for (const item of arr) eventChainMembership.add(item.event_id)
      }
      arr.sort((a, b) => a.at - b.at)
      const authors = new Set(arr.map(x => x.actor))
      if (authors.size >= 2) {
        const cleanKey = k.replace(/^(?:stem|pr):/, '')
        multiAgentChainKeys.add(cleanKey)
        for (let i = 1; i < arr.length; i++) {
          if (arr[i].actor !== arr[i - 1].actor && arr[i].at >= arr[i - 1].at) {
            const pairId = `${arr[i - 1].event_id}->${arr[i].event_id}`
            const dtMin = Math.max(0.1, Math.round(((arr[i].at - arr[i - 1].at) / 60) * 10) / 10)
            const prev = handoffByPair.get(pairId)
            // Prefer explicit repo#PR label over generic stem label
            if (!prev || k.startsWith('pr:')) {
              handoffByPair.set(pairId, {
                chain: cleanKey,
                from: arr[i - 1].actor,
                to: arr[i].actor,
                from_slug: arr[i - 1].slug,
                to_slug: arr[i].slug,
                latency_min: dtMin,
                at: arr[i].at,
                git_ref: arr[i].git || arr[i - 1].git || null,
              })
            }
          }
        }
      }
    }
    const handoffs = [...handoffByPair.values()].sort((a, b) => b.at - a.at)
    const dts = handoffs.map(h => h.latency_min).sort((a, b) => a - b)
    const medianMin = dts.length > 0 ? dts[Math.floor(dts.length / 2)] : null
    const p25Min = dts.length > 0 ? dts[Math.floor(dts.length * 0.25)] : null

    let latencyScore = 75
    if (medianMin !== null) {
      if (medianMin <= 5) latencyScore = 98
      else if (medianMin <= 15) latencyScore = Math.round(98 - ((medianMin - 5) / 10) * 10)
      else if (medianMin <= 60) latencyScore = Math.round(88 - ((medianMin - 15) / 45) * 16)
      else latencyScore = Math.max(40, Math.round(72 - Math.min(32, (medianMin - 60) * 0.08)))
    }
    const targetHandoffs = Math.max(2, Math.min(12, Math.ceil(sliceNonCanon.length * 0.04)))
    const volumeFactor = Math.min(1, handoffs.length / targetHandoffs)
    const velocityScore = Math.round((0.75 * latencyScore + 0.25 * (volumeFactor * 100)) * 10) / 10

    // --- 4. State Reuse vs. Slug Sprawl ---
    const topicMap = new Map()
    for (const r of sliceNonCanon) {
      const actor = rosterByPk.get(String(r.author_pubkey || '')) || String(r.author_pubkey || '').slice(0, 8)
      const top = String(r.topic || 'general')
      let entry = topicMap.get(top)
      if (!entry) {
        entry = { count: 0, authors: new Set() }
        topicMap.set(top, entry)
      }
      entry.count += 1
      entry.authors.add(actor)
    }
    let multiClaimTopics = 0
    let corroboratedTopics = 0
    for (const info of topicMap.values()) {
      if (info.count >= 2) {
        multiClaimTopics += 1
        if (info.authors.size >= 2) corroboratedTopics += 1
      }
    }
    const corroboratedTopicPct = multiClaimTopics > 0
      ? Math.round((corroboratedTopics / multiClaimTopics) * 1000) / 10
      : 100

    let sprawlSlugCount = 0
    let reusedOrDurableCount = 0
    for (const r of slice) {
      const isDurable = r.scope === 'hive:canon' || r.expires_at === null || r.expires_at === undefined || Boolean(r.merkle_sources)
      const inChain = eventChainMembership.has(r.event_id) || (Array.isArray(r.supersedes) && r.supersedes.length > 0)
      if (isDurable || inChain) {
        reusedOrDurableCount += 1
      } else {
        sprawlSlugCount += 1
      }
    }
    const reusedOrDurablePct = slice.length > 0
      ? Math.round((reusedOrDurableCount / slice.length) * 1000) / 10
      : 100
    const reuseScore = Math.round((0.45 * corroboratedTopicPct + 0.55 * Math.min(100, (reusedOrDurablePct / 65) * 100)) * 10) / 10

    return {
      velocityScore,
      medianMin,
      p25Min,
      handoffCount: handoffs.length,
      multiAgentChains: multiAgentChainKeys.size,
      recentHandoffs: handoffs.slice(0, 8),
      reuseScore,
      corroboratedTopicPct,
      corroboratedTopics,
      multiClaimTopics,
      reusedOrDurablePct,
      sprawlSlugCount,
    }
  }

  const currentVR = computeSliceVelocityAndReuse(activeRecords)
  const velocity = currentVR.velocityScore
  const reuse = currentVR.reuseScore
  const score = Math.round((0.30 * breadth + 0.25 * precision + 0.25 * velocity + 0.20 * reuse) * 10) / 10

  // --- 5. Projected Efficacy After @curator & Turn-Start Wake Hook ---
  const stagedPromotions = Number(curator_state?.planned_summary?.promotions || 0)
  const stagedDistillations = Number(curator_state?.planned_summary?.distillations || 0)
  const stagedClusters = stagedPromotions + stagedDistillations || Number(coherence?.projected_after_dream?.staged_actions || 44)
  const foldedRaw = Number(coherence?.projected_after_dream?.superseded_raw_claims || Math.min(rawClassAClaims, stagedClusters * 2))
  const postCuratorTotal = Math.max(1, activeRecords.length - foldedRaw + stagedClusters)
  const postCuratorDurable = Math.min(postCuratorTotal, durableClaims + stagedClusters)
  const postCuratorCompressionPct = Math.round((postCuratorDurable / postCuratorTotal) * 1000) / 10
  const afterCuratorPrecision = Math.round((0.60 * queryHitRatePct + 0.40 * Math.min(100, (postCuratorCompressionPct / 50) * 100)) * 10) / 10
  const postCuratorReusedPct = Math.min(100, Math.round(((activeRecords.length - currentVR.sprawlSlugCount + Math.round(foldedRaw * 0.65)) / Math.max(1, activeRecords.length)) * 1000) / 10)
  const afterCuratorReuse = Math.round((0.45 * currentVR.corroboratedTopicPct + 0.55 * Math.min(100, (postCuratorReusedPct / 65) * 100)) * 10) / 10
  const afterCuratorScore = Math.round((0.30 * breadth + 0.25 * afterCuratorPrecision + 0.25 * velocity + 0.20 * afterCuratorReuse) * 10) / 10

  const afterWakeHookBreadth = Math.round((0.55 * 100 + 0.45 * Math.max(recallCoveragePct, 80)) * 10) / 10
  const afterWakeHookScore = Math.round((0.30 * afterWakeHookBreadth + 0.25 * afterCuratorPrecision + 0.25 * velocity + 0.20 * afterCuratorReuse) * 10) / 10

  // --- 6. Historical Efficacy Trajectory ---
  const cohHistory = Array.isArray(coherence?.history) ? coherence.history : []
  const history = cohHistory.map((pt, idx) => {
    const isLast = idx === cohHistory.length - 1
    if (isLast) {
      return {
        at: pt.at,
        claims: pt.claims,
        score,
        axes: { breadth, precision, velocity, reuse },
      }
    }
    const sliceLen = Math.max(1, Math.min(chronological.length, pt.events || pt.claims || 1))
    const slice = chronological.slice(0, sliceLen)
    const vr = computeSliceVelocityAndReuse(slice)
    const slDurable = slice.filter(r => r.scope === 'hive:canon' || r.expires_at === null || r.expires_at === undefined || Boolean(r.merkle_sources)).length
    const slComp = (slDurable / slice.length) * 100
    const slPrec = Math.round((0.60 * queryHitRatePct + 0.40 * Math.min(100, (slComp / 50) * 100)) * 10) / 10
    const slBreadth = Math.round((0.5 * breadth + 0.5 * Math.min(100, (pt.axes?.coupling || breadth))) * 10) / 10
    const slScore = Math.round((0.30 * slBreadth + 0.25 * slPrec + 0.25 * vr.velocityScore + 0.20 * vr.reuseScore) * 10) / 10
    return {
      at: pt.at,
      claims: pt.claims,
      score: slScore,
      axes: { breadth: slBreadth, precision: slPrec, velocity: vr.velocityScore, reuse: vr.reuseScore },
    }
  })

  return {
    score,
    axes: { breadth, precision, velocity, reuse },
    distribution: {
      recall_coverage_pct: recallCoveragePct,
      read_before_write_pct: readBeforeWritePct,
      active_bus_agents: actorStats.size,
      total_peer_seats: peerReaders.length,
      compliant_writers: compliantWriters,
      receipt_only_writers: receiptOnlyWriters,
      blind_seats: blindSeats,
      writer_funnel: writerFunnel,
    },
    retrieval: {
      query_hit_rate_pct: queryHitRatePct,
      query_hits: queryHits,
      query_total: queryTotal,
      zero_hit_queries: zeroHitQueries,
      wake_surface_pct: wakeSurfacePct,
      state_compression_pct: stateCompressionPct,
      durable_claims: durableClaims,
      raw_class_a_claims: rawClassAClaims,
    },
    velocity: {
      median_handoff_min: currentVR.medianMin,
      p25_handoff_min: currentVR.p25Min,
      handoff_count: currentVR.handoffCount,
      multi_agent_chains: currentVR.multiAgentChains,
      recent_handoffs: currentVR.recentHandoffs,
    },
    reuse: {
      corroborated_topic_pct: currentVR.corroboratedTopicPct,
      corroborated_topics: currentVR.corroboratedTopics,
      total_multi_claim_topics: currentVR.multiClaimTopics,
      reused_or_durable_pct: currentVR.reusedOrDurablePct,
      sprawl_slug_count: currentVR.sprawlSlugCount,
    },
    projected: {
      after_curator_score: afterCuratorScore,
      after_curator_precision: afterCuratorPrecision,
      after_curator_reuse: afterCuratorReuse,
      after_wake_hook_score: afterWakeHookScore,
      after_wake_hook_breadth: afterWakeHookBreadth,
    },
    history,
  }
}

export const ACTIVE_WINDOW_SEC = 300
// herd-infra's hive-memory-watch writes this every 5 minutes. Its writers map is the only place saving shows: the daemon's
// store_state stays READY while every writer is fenced (2026-11-07, 04:15-12:20 UTC, no alert).
const WATCH_STATUS_PATH = process.env.HIVE_MEMORY_WATCH_STATUS || '/run/hive-memory-watch/status.json'
export const WATCH_STALE_SEC = 900

export function readWatchStatus(path = WATCH_STATUS_PATH, nowSec = Math.floor(Date.now() / 1000)) {
  let raw
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'))
  } catch (err) {
    return { at: null, stale: true, saving: 'unknown', writers: {}, fenced: [], problems: [`no health check status (${err.code || 'unreadable'})`] }
  }
  const writers = {}
  for (const [name, state] of Object.entries(raw?.writers && typeof raw.writers === 'object' ? raw.writers : {})) {
    if (/^[a-z0-9][a-z0-9-]{0,39}$/.test(name)) writers[name] = state === 'open' ? 'open' : 'FENCED'
  }
  const names = Object.keys(writers)
  const fenced = names.filter((n) => writers[n] !== 'open')
  const saving = names.length === 0 ? 'unknown' : fenced.length === 0 ? 'open' : fenced.length === names.length ? 'OFF' : 'partial'
  const problems = (Array.isArray(raw?.problems) ? raw.problems : []).filter((x) => typeof x === 'string').slice(0, 10).map((x) => x.slice(0, 300))
  const at = Number.isSafeInteger(raw?.at) ? raw.at : null
  return { at, stale: at === null || nowSec - at > WATCH_STALE_SEC, saving, writers, fenced, problems }
}

export function watchView(nowSec, path = undefined) {
  const watch = readWatchStatus(path, nowSec)
  return { ...watch, alert: watchAlert(watch, nowSec), hard: !watch.stale && (watch.saving === 'OFF' || watch.saving === 'partial') }
}

export function watchAlert(watch, nowSec = Math.floor(Date.now() / 1000)) {
  if (!watch) return null
  // A stale report says nothing about now: name its age and what it last said, never claim it as the current state.
  if (watch.stale) {
    if (watch.at === null) return 'The health check has not reported: saving cannot be confirmed'
    const last = watch.saving === 'OFF' ? ' (it then said saving was OFF)'
      : watch.saving === 'partial' ? ` (it then said saving was off for ${watch.fenced.join(', ')})` : ''
    return `The health check last reported ${Math.round((nowSec - watch.at) / 60)} min ago${last}: saving cannot be confirmed`
  }
  if (watch.saving === 'OFF') return `SAVING IS OFF: all ${watch.fenced.length} writers are fenced, so every save is refused`
  if (watch.saving === 'partial') return `Saving is off for ${watch.fenced.join(', ')}: their saves are refused`
  if (watch.saving === 'unknown') return 'The health check does not report writers: saving cannot be confirmed'
  if (watch.problems.length) return `Health check: ${watch.problems[0]}`
  return null
}
export const WARM_WINDOW_SEC = 1200

export function computeAgentHealth({
  agent_roster = [],
  recent_activity = [],
  records = [],
  history_records = [],
  prior_telemetry = null,
  now_sec = Math.floor(Date.now() / 1000),
} = {}) {
  const telemetry = prior_telemetry instanceof Map ? prior_telemetry : new Map()
  const rosterByPk = new Map()
  for (const a of Array.isArray(agent_roster) ? agent_roster : []) {
    if (a?.pubkey && a?.id) rosterByPk.set(a.pubkey, a.id)
  }

  const getEntry = id => {
    let e = telemetry.get(id)
    if (!e) {
      e = {
        last_read_at: null,
        last_read_kind: null,
        last_recall_at: null,
        last_recall_kind: null,
        last_write_at: null,
        last_write_d: null,
        last_refused_at: null,
        last_refused_code: null,
      }
      telemetry.set(id, e)
    }
    return e
  }

  const allRecords = [
    ...(Array.isArray(records) ? records : []),
    ...(Array.isArray(history_records) ? history_records : []),
  ]
  for (const r of allRecords) {
    if (!r || typeof r !== 'object') continue
    const actor = rosterByPk.get(String(r.author_pubkey || ''))
    const at = Number.isSafeInteger(r.created_at) ? r.created_at : null
    if (!actor || !at) continue
    const e = getEntry(actor)
    if (e.last_write_at === null || at >= e.last_write_at) {
      e.last_write_at = at
      if (r.d) e.last_write_d = String(r.d)
    }
  }

  const reads5mByActor = new Map()
  const writes5mByActor = new Map()
  for (const a of Array.isArray(recent_activity) ? recent_activity : []) {
    if (!a || typeof a !== 'object' || !a.actor) continue
    const actor = String(a.actor)
    const at = Number.isSafeInteger(a.at) ? a.at : null
    if (!at) continue
    const e = getEntry(actor)
    const in5m = Math.max(0, now_sec - at) <= ACTIVE_WINDOW_SEC
    if (a.kind === 'wake' || a.kind === 'query' || a.kind === 'lookup') {
      if (e.last_read_at === null || at >= e.last_read_at) {
        e.last_read_at = at
        e.last_read_kind = a.kind
      }
      if ((a.kind === 'wake' || a.kind === 'query') && (e.last_recall_at === null || at >= e.last_recall_at)) {
        e.last_recall_at = at
        e.last_recall_kind = a.kind
      }
      if (in5m) reads5mByActor.set(actor, (reads5mByActor.get(actor) || 0) + 1)
    } else if (a.kind === 'submit') {
      if (e.last_write_at === null || at >= e.last_write_at) {
        e.last_write_at = at
        if (a.d) e.last_write_d = String(a.d)
      }
      if (in5m) writes5mByActor.set(actor, (writes5mByActor.get(actor) || 0) + 1)
    } else if (a.kind === 'refused') {
      if (e.last_refused_at === null || at >= e.last_refused_at) {
        e.last_refused_at = at
        e.last_refused_code = a.code || 'REFUSED'
      }
    }
  }

  const summary = {
    active_5m: 0,
    warm_20m: 0,
    stale: 0,
    error: 0,
    compliant_recall: 0,
    write_without_recall: 0,
    blind_seats: 0,
    total: 0,
    window_sec: ACTIVE_WINDOW_SEC,
  }

  const enrichedRoster = (Array.isArray(agent_roster) ? agent_roster : []).map(agent => {
    const e = telemetry.get(agent.id) || {
      last_read_at: null,
      last_read_kind: null,
      last_recall_at: null,
      last_recall_kind: null,
      last_write_at: null,
      last_write_d: null,
      last_refused_at: null,
      last_refused_code: null,
    }
    const lastSeen = Math.max(e.last_read_at || 0, e.last_write_at || 0) || null
    const ageSec = lastSeen !== null ? Math.max(0, now_sec - lastSeen) : null
    const active5m = ageSec !== null && ageSec <= ACTIVE_WINDOW_SEC
    let health = 'stale'
    if (
      e.last_refused_at !== null &&
      (lastSeen === null || e.last_refused_at > lastSeen) &&
      Math.max(0, now_sec - e.last_refused_at) <= 900
    ) {
      health = 'error'
      summary.error += 1
    } else if (active5m) {
      health = 'active'
      summary.active_5m += 1
    } else if (ageSec !== null && ageSec <= WARM_WINDOW_SEC) {
      health = 'warm'
      summary.warm_20m += 1
    } else {
      health = 'stale'
      summary.stale += 1
    }
    const isLiveClock = Number.isSafeInteger(now_sec) && now_sec > 100000
    const recallAge = e.last_recall_at !== null ? Math.max(0, now_sec - e.last_recall_at) : null
    const writeAge = e.last_write_at !== null ? Math.max(0, now_sec - e.last_write_at) : null
    let complianceStatus = 'compliant'
    if (health === 'error') {
      complianceStatus = 'tool_failure'
    } else if (agent.is_reader && agent.id !== 'curator' && agent.id !== 'viewer') {
      const wroteWithoutFreshRecall = isLiveClock
        && writeAge !== null
        && writeAge <= 3600
        && (e.last_read_kind === 'lookup' || recallAge === null || recallAge > 3600)
      if (wroteWithoutFreshRecall) {
        complianceStatus = 'write_without_recall'
        summary.write_without_recall += 1
      } else if (e.last_recall_at !== null) {
        complianceStatus = 'compliant'
        summary.compliant_recall += 1
      } else if (e.last_write_at !== null || e.last_read_at !== null) {
        complianceStatus = 'write_without_recall'
        summary.write_without_recall += 1
      } else {
        complianceStatus = 'blind_seat'
        summary.blind_seats += 1
      }
    }
    let recallSync = 0
    let writeHygiene = 0
    let sharedResonance = 0
    if (isLiveClock && !agent.is_owner) {
      recallSync = e.last_recall_at !== null && recallAge !== null
        ? (recallAge <= 900 ? 50 : (recallAge <= 3600 ? 34 : (recallAge <= 7200 ? 18 : (recallAge <= 21600 ? 10 : 0))))
        : 0
      const recalledRecently = e.last_recall_at !== null && recallAge !== null && recallAge <= 3600 && e.last_read_kind !== 'lookup'
      if (writeAge !== null && writeAge <= 3600) {
        writeHygiene = recalledRecently ? 30 : 12
      } else if (writeAge !== null && writeAge <= 21600) {
        writeHygiene = (e.last_recall_at !== null && recallAge !== null && recallAge <= 7200) ? 20 : 10
      } else if (writeAge !== null) {
        writeHygiene = 6
      } else if (recalledRecently) {
        writeHygiene = 20
      } else if (e.last_recall_at !== null && recallAge !== null && recallAge <= 21600) {
        writeHygiene = 8
      }
      if (health === 'error') writeHygiene = Math.max(0, writeHygiene - 15)
      if (recalledRecently && writeAge !== null && writeAge <= 21600) {
        sharedResonance = 20
      } else if (recalledRecently || (writeAge !== null && writeAge <= 3600)) {
        sharedResonance = 10
      } else if ((recallAge !== null && recallAge <= 21600) || (writeAge !== null && writeAge <= 21600)) {
        sharedResonance = 4
      }
    } else {
      recallSync = e.last_recall_at !== null
        ? (recallAge <= 900 ? 50 : (recallAge <= 3600 ? 44 : 36))
        : (agent.is_owner ? 50 : 0)
      if (e.last_write_at !== null) {
        writeHygiene = e.last_recall_at !== null || agent.is_owner ? 30 : 18
      } else if (e.last_recall_at !== null || agent.is_owner) {
        writeHygiene = 24
      } else if (e.last_read_at !== null) {
        writeHygiene = 10
      }
      if (health === 'error') writeHygiene = Math.max(0, writeHygiene - 15)
      sharedResonance = (e.last_recall_at !== null && e.last_write_at !== null) || agent.is_owner
        ? 20
        : ((e.last_recall_at !== null || e.last_write_at !== null) ? 14 : (e.last_read_at !== null ? 6 : 0))
    }
    const coherenceScore = Math.max(0, Math.min(100, Math.round(recallSync + writeHygiene + sharedResonance)))
    summary.total += 1
    return {
      ...agent,
      last_read_at: e.last_read_at,
      last_read_kind: e.last_read_kind,
      last_recall_at: e.last_recall_at,
      last_recall_kind: e.last_recall_kind,
      last_write_at: e.last_write_at,
      last_write_d: e.last_write_d,
      last_refused_at: e.last_refused_at,
      last_refused_code: e.last_refused_code,
      last_seen_at: lastSeen,
      age_sec: ageSec,
      active_5m: active5m,
      reads_5m: reads5mByActor.get(agent.id) || 0,
      writes_5m: writes5mByActor.get(agent.id) || 0,
      health,
      compliance_status: complianceStatus,
      coherence_score: coherenceScore,
    }
  })

  return {
    roster: enrichedRoster,
    summary,
    telemetry,
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

  const prevAlert = watchAlert(prev.watch, nowSec)
  const nextAlert = watchAlert(next.watch, nowSec)
  if (prevAlert !== nextAlert) push('alert', nextAlert || 'Health check clear: saving is open')

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

export function resolveDreamDisplayMode({ records = [], curator_state = null, consolidated_sources = {} } = {}) {
  const recs = Array.isArray(records) ? records.filter(Boolean) : []
  const byEventId = new Set(recs.map(r => r.event_id).filter(Boolean))
  const consolidatedMap = consolidated_sources && typeof consolidated_sources === 'object' ? consolidated_sources : {}
  const merkleRecords = recs.filter(r => typeof r.merkle_sources === 'string' && r.merkle_sources.length > 0)
  const hasPersistedCurator = Boolean(curator_state?.state_file_present && Number(curator_state?.last_curated_at) > 0)
  const hasObservedClusters = hasPersistedCurator && merkleRecords.length > 0
  let missingSourceCount = 0
  let observedSourceCount = 0
  for (const r of merkleRecords) {
    const sups = Array.isArray(r.supersedes) ? r.supersedes : []
    for (const sid of sups) {
      if (byEventId.has(sid) || Boolean(consolidatedMap[sid])) {
        observedSourceCount += 1
      } else {
        missingSourceCount += 1
      }
    }
  }
  const hasObservedEigens =
    hasObservedClusters &&
    Array.isArray(curator_state?.topic_eigenvectors) &&
    curator_state.topic_eigenvectors.length > 0 &&
    !curator_state.topic_eigenvectors.some(e => e?.simulated || e?.persisted === false)
  const hasObservedArcs =
    hasObservedClusters &&
    Array.isArray(curator_state?.topic_reorganizations) &&
    curator_state.topic_reorganizations.length > 0 &&
    !curator_state.topic_reorganizations.some(a => a?.simulated || a?.persisted === false)
  const hasObservedGhosts = hasObservedClusters && observedSourceCount > 0 && missingSourceCount === 0
  const components = {
    clusters: hasObservedClusters ? 'observed' : 'simulated_preview',
    eigenvalues: hasObservedEigens ? 'observed' : 'simulated_preview',
    topic_arcs: hasObservedArcs ? 'observed' : 'simulated_preview',
    ghost_sources: hasObservedGhosts ? 'observed' : 'simulated_preview',
  }
  const isSimulated =
    components.clusters !== 'observed' ||
    components.eigenvalues !== 'observed' ||
    components.topic_arcs !== 'observed' ||
    components.ghost_sources !== 'observed'
  const observedParts = Object.entries(components)
    .filter(([, mode]) => mode === 'observed')
    .map(([name]) => name)
  const previewParts = Object.entries(components)
    .filter(([, mode]) => mode !== 'observed')
    .map(([name]) => name)
  const label = !isSimulated
    ? `OBSERVED (persisted Merkle curation · ${merkleRecords.length} merkle_sources)`
    : hasObservedClusters
      ? `MIXED: OBSERVED MERKLE CURATION (${merkleRecords.length} persisted merkle_sources: ${observedParts.join(', ')}) + SIMULATED PREVIEW (${previewParts.join(', ')})`
      : merkleRecords.length > 0
        ? `SIMULATED PREVIEW (${merkleRecords.length} merkle_sources in store — curator state file not persisted)`
        : 'SIMULATED PREVIEW (synthetic/fallback preview — no persisted Merkle curation)'
  return {
    mode: isSimulated ? 'simulated_preview' : 'observed',
    is_simulated_preview: isSimulated,
    is_mixed: Boolean(hasObservedClusters && isSimulated),
    persisted_curation: hasPersistedCurator,
    observed_merkle_count: merkleRecords.length,
    observed_source_count: observedSourceCount,
    missing_source_count: missingSourceCount,
    components,
    label,
  }
}

export function computeDreamingTelemetry(records = [], curatorState = null) {
  const recs = Array.isArray(records) ? records : []
  const displayMode = resolveDreamDisplayMode({
    records: recs,
    curator_state: curatorState,
    consolidated_sources: curatorState?.consolidated_sources || {},
  })
  const fullBytes = JSON.stringify(recs).length
  let indexBytes = 0
  let canonBytes = 0
  let wfCount = 0
  let shortTtlCount = 0
  let classBCount = 0
  let merkleCount = 0
  let nightmareCount = 0
  const byScopeTopic = new Map()
  for (const r of recs) {
    if (!r || typeof r !== 'object') continue
    const slug = String(r.d || '').split(':').pop() || String(r.d || '')
    const isWf = /-(?:review|status|owner|wip|handoff)$/.test(slug)
    indexBytes += 140 + Math.min(120, String(r.claim || '').length) + String(r.d || '').length
    if (typeof r.merkle_sources === 'string' && r.merkle_sources.length > 0) merkleCount += 1
    if (r.conflict || ((r.scope === 'hive:canon' || r.expires_at === null || r.expires_at === undefined) && r.stale_warning)) {
      nightmareCount += 1
    }
    if (r.scope === 'hive:canon') {
      canonBytes += JSON.stringify(r).length
    } else if (r.expires_at === null || r.expires_at === undefined) {
      classBCount += 1
    } else {
      const scope = String(r.scope || 'unknown')
      const top = String(r.topic || 'general')
      const key = `${scope} · #${top}`
      const prev = byScopeTopic.get(key) || { scope, topic: top, label: key, count: 0 }
      prev.count += 1
      byScopeTopic.set(key, prev)
    }
    if (isWf) {
      wfCount += 1
      if (r.expires_at !== null && r.expires_at !== undefined && r.created_at && (r.expires_at - r.created_at) <= 172800) {
        shortTtlCount += 1
      }
    }
  }
  const wakeBytes = canonBytes + Math.min(4000, indexBytes)
  const indexSavings = fullBytes > 0 ? Math.round((1 - indexBytes / fullBytes) * 1000) / 10 : 0
  const wakeSavings = fullBytes > 0 ? Math.round((1 - wakeBytes / fullBytes) * 1000) / 10 : 0
  const pressureThreshold = Number(curatorState?.topic_pressure_threshold) || DEFAULT_TOPIC_PRESSURE_THRESHOLD
  const topicList = [...byScopeTopic.values()]
    .map(item => ({ ...item, ready: item.count > pressureThreshold }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
  return {
    estimated_from_visible: true,
    passive_inspection: true,
    display_mode: displayMode,
    total: recs.length,
    fullBytes,
    indexBytes,
    wakeBytes,
    indexSavings,
    wakeSavings,
    wfCount,
    shortTtlCount,
    classBCount,
    merkleCount,
    nightmareCount,
    topicList,
    curator_state: curatorState,
  }
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
    body[data-view="graph"] { height: 100vh; height: 100dvh; overflow: hidden; overscroll-behavior: none; }
    body[data-view="graph"] .cards-only { display: none; }
    body[data-view="cards"] .graph-only { display: none; }
    body[data-view="cards"] {
      padding: calc(12px + env(safe-area-inset-top, 0px)) calc(12px + env(safe-area-inset-right, 0px)) calc(76px + env(safe-area-inset-bottom, 0px)) calc(12px + env(safe-area-inset-left, 0px));
    }
    #stage-wrap { position: fixed; inset: 0; }
    canvas#cortex { width: 100%; height: 100%; display: block; cursor: grab; touch-action: none; -webkit-user-select: none; user-select: none; -webkit-tap-highlight-color: transparent; }
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
    body[data-view="graph"] .hud-top {
      position: fixed;
      top: calc(10px + env(safe-area-inset-top, 0px));
      left: calc(10px + env(safe-area-inset-left, 0px));
      right: calc(10px + env(safe-area-inset-right, 0px));
      pointer-events: none;
    }
    body[data-view="cards"] .hud-top { max-width: 760px; margin: 0 auto 12px; flex-direction: column; align-items: stretch; }
    .hud-top > * { pointer-events: auto; }
    .brand-card { padding: 10px 14px; display: flex; gap: 12px; align-items: flex-start; max-width: 100%; flex: 0 1 460px; min-width: 0; }
    .brain-orb {
      width: 30px;
      height: 30px;
      margin-top: 2px;
      border-radius: 50%;
      flex-shrink: 0;
      background: radial-gradient(circle at 35% 35%, #7dd3fc, #6366f1 55%, #1e1b4b 100%);
      box-shadow: 0 0 18px rgba(56, 189, 248, 0.55);
    }
    .brand-text { display: flex; flex-direction: column; gap: 6px; min-width: 0; flex: 1; }
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
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .mobile-kpi-strip {
      display: none;
      font-family: var(--mono);
      font-size: 11px;
      color: #cbd5e1;
      gap: 6px;
      flex-wrap: wrap;
      align-items: center;
    }
    .mobile-kpi-pill {
      padding: 2px 7px;
      border-radius: 6px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(148, 163, 184, 0.2);
      white-space: nowrap;
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
    .alert-banner { position: fixed; top: calc(env(safe-area-inset-top, 0px) + 8px); left: 50%; transform: translateX(-50%);
      z-index: 50; max-width: min(720px, calc(100vw - 32px)); padding: 10px 16px; border-radius: 10px; font-weight: 700;
      color: #fff; background: #b91c1c; border: 1px solid #fca5a5; box-shadow: 0 0 24px rgba(239, 68, 68, 0.6); }
    .alert-banner.warn { background: #92400e; border-color: #fcd34d; box-shadow: 0 0 18px rgba(245, 158, 11, 0.5); }
    .badge.info { color: #7dd3fc; background: var(--info-bg); border-color: rgba(56, 189, 248, 0.4); }
    .badge.sim { color: #fde68a; background: rgba(245, 158, 11, 0.12); border: 1px dashed rgba(251, 191, 36, 0.6); }
    .telemetry-strip { display: flex; gap: 11px; padding: 8px 12px; flex-wrap: wrap; }
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
    .hud-right { right: 12px; width: 356px; }
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
      align-items: center;
      gap: 8px;
    }
    .sheet-close {
      display: none;
      font-size: 12px;
      line-height: 1;
      padding: 4px 8px;
      border-radius: 6px;
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid var(--border);
      color: var(--text);
      cursor: pointer;
    }
    .mini { font-family: var(--mono); font-size: 10px; color: #7dd3fc; text-transform: none; letter-spacing: 0; }
    .agent-list { display: flex; flex-direction: column; gap: 4px; max-height: 22vh; overflow-y: auto; -webkit-overflow-scrolling: touch; overscroll-behavior: contain; }
    .agent-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding: 6px 8px;
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.025);
      border: 1px solid transparent;
      cursor: pointer;
      -webkit-tap-highlight-color: transparent;
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
    .stream-list { font-family: var(--mono); font-size: 10.5px; display: flex; flex-direction: column; gap: 4px; overflow-y: auto; min-height: 0; -webkit-overflow-scrolling: touch; overscroll-behavior: contain; }
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
    .inspector { flex: 1 1 auto; min-height: 0; overflow-y: auto; display: flex; flex-direction: column; gap: 9px; -webkit-overflow-scrolling: touch; overscroll-behavior: contain; }
    .inspector > *, #coherence-graphs-box > *, .glass-box > canvas { flex-shrink: 0; }
    .inspect-header { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: flex-start; gap: 8px; border-bottom: 1px solid var(--border); padding-bottom: 7px; }
    .inspect-header > div:first-child { flex: 1 1 180px; }
    .inspect-actions { display: flex; align-items: center; gap: 6px; flex-shrink: 1; min-width: 0; max-width: 100%; }
    .inspect-actions .badge { white-space: normal; }
    .inspect-close { padding: 3px 8px; font-size: 12px; line-height: 1.2; border-radius: 6px; }
    .inspect-kicker { font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
    .inspect-title { font-family: var(--mono); font-size: 13px; font-weight: 700; color: #93c5fd; word-break: break-word; }
    .kv-list { display: flex; flex-direction: column; font-family: var(--mono); font-size: 11px; }
    .kv-row { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; padding: 4px 0; border-bottom: 1px dashed rgba(255, 255, 255, 0.06); }
    .kv-row.stacked { flex-direction: column; align-items: flex-start; gap: 3px; padding: 5px 0; }
    .kv-key { color: var(--muted); flex: 1 1 auto; min-width: 110px; word-break: normal; overflow-wrap: break-word; }
    .kv-val { text-align: right; flex: 0 0 auto; max-width: 62%; word-break: normal; overflow-wrap: break-word; font-weight: 600; }
    .kv-row.stacked .kv-key, .kv-row.stacked .kv-val { width: 100%; max-width: 100%; text-align: left; min-width: 0; }
    .ttl-bar-wrap { background: rgba(255, 255, 255, 0.07); height: 7px; border-radius: 999px; overflow: hidden; margin-top: 4px; }
    .ttl-bar-fill { height: 100%; border-radius: 999px; }
    .hud-bottom {
      position: fixed;
      bottom: calc(12px + env(safe-area-inset-bottom, 0px));
      left: calc(12px + env(safe-area-inset-left, 0px));
      right: calc(12px + env(safe-area-inset-right, 0px));
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
      -webkit-tap-highlight-color: transparent;
    }
    button.btn:hover, button.btn.active { background: rgba(56, 189, 248, 0.16); border-color: var(--border-bright); }
    button.btn.sim { border-style: dashed; border-color: rgba(251, 191, 36, 0.55); color: #fde68a; }
    input[type="range"] { accent-color: #38bdf8; width: 140px; }
    #time-label { min-width: 96px; color: #7dd3fc; font-weight: 700; }
    .zoom-fab {
      display: none;
      position: fixed;
      right: calc(12px + env(safe-area-inset-right, 0px));
      bottom: calc(68px + env(safe-area-inset-bottom, 0px));
      z-index: 18;
      flex-direction: column;
      gap: 6px;
    }
    .zoom-fab button.btn {
      width: 38px;
      height: 38px;
      padding: 0;
      display: grid;
      place-items: center;
      font-family: var(--mono);
      font-size: 16px;
      font-weight: 700;
      border-radius: 10px;
      background: var(--panel);
      -webkit-backdrop-filter: blur(12px);
      backdrop-filter: blur(12px);
      box-shadow: 0 6px 18px rgba(0, 0, 0, 0.45);
    }
    .mobile-dock {
      display: none;
      position: fixed;
      left: calc(10px + env(safe-area-inset-left, 0px));
      right: calc(10px + env(safe-area-inset-right, 0px));
      bottom: calc(8px + env(safe-area-inset-bottom, 0px));
      z-index: 25;
      padding: 5px;
      gap: 4px;
      justify-content: space-between;
      align-items: center;
      border-radius: 14px;
    }
    .mobile-dock button.dock-btn {
      flex: 1 1 0;
      min-width: 0;
      min-height: 38px;
      padding: 6px 4px;
      font-family: var(--sans);
      font-size: 11.5px;
      font-weight: 600;
      color: var(--muted);
      background: transparent;
      border: 1px solid transparent;
      border-radius: 10px;
      cursor: pointer;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      -webkit-tap-highlight-color: transparent;
    }
    .mobile-dock button.dock-btn.active {
      color: #f8fafc;
      background: rgba(56, 189, 248, 0.16);
      border-color: var(--border-bright);
    }
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
    .log-list { font-family: var(--mono); font-size: 11px; display: flex; flex-direction: column; gap: 5px; max-height: 240px; overflow-y: auto; -webkit-overflow-scrolling: touch; }
    .log-row { padding: 5px 8px; border-radius: 6px; background: var(--panel-alt); border: 1px solid var(--border); word-break: break-word; }
    .log-time { color: var(--muted); margin-right: 6px; }
    @media (max-width: 1024px) {
      .mobile-dock { display: flex; }
      body[data-view="graph"] .zoom-fab { display: flex; }
      .sheet-close { display: inline-flex; }
      .hud-left {
        top: auto;
        left: calc(10px + env(safe-area-inset-left, 0px));
        right: calc(10px + env(safe-area-inset-right, 0px));
        bottom: calc(64px + env(safe-area-inset-bottom, 0px));
        width: auto;
        max-height: 56dvh;
        z-index: 22;
        display: none;
      }
      body[data-view="graph"][data-drawer="agents"] .hud-left,
      body[data-view="graph"][data-drawer="pulses"] .hud-left {
        display: flex;
      }
      body[data-view="graph"][data-drawer="agents"] .hud-left .feed-box { display: none; }
      body[data-view="graph"][data-drawer="pulses"] .hud-left .agents-box,
      body[data-view="graph"][data-drawer="pulses"] .hud-left .legend-box { display: none; }
      .agent-list { max-height: 34dvh; }
      .stream-list { max-height: 44dvh; }
      .hud-right {
        top: auto;
        left: calc(10px + env(safe-area-inset-left, 0px));
        right: calc(10px + env(safe-area-inset-right, 0px));
        bottom: calc(64px + env(safe-area-inset-bottom, 0px));
        width: auto;
        max-height: 48dvh;
        z-index: 23;
      }
      .inspector.idle { display: none; }
      .hud-bottom {
        left: calc(10px + env(safe-area-inset-left, 0px));
        right: calc(10px + env(safe-area-inset-right, 0px));
        bottom: calc(64px + env(safe-area-inset-bottom, 0px));
        flex-direction: column;
        align-items: stretch;
        z-index: 21;
        display: none;
      }
      body[data-view="graph"][data-drawer="tools"] .hud-bottom { display: flex; }
    }
    @media (max-width: 680px) {
      body[data-view="graph"] .telemetry-strip { display: none; }
      body[data-view="graph"] .mobile-kpi-strip { display: flex; }
      .brand-card { padding: 8px 11px; gap: 9px; }
      .brain-orb { width: 24px; height: 24px; }
      h1 { font-size: 14px; }
      .quarantine-banner {
        font-size: 9.5px;
        padding: 3px 6px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .badge { font-size: 10px; padding: 2px 7px; }
      .control-bar { padding: 8px 10px; gap: 6px; }
      button.btn { padding: 6px 9px; font-size: 11.5px; }
      input[type="range"] { flex: 1; min-width: 90px; }
    }
  </style>
</head>
<body data-view="graph" data-drawer="none">
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
        <div class="mobile-kpi-strip" id="mobile-kpi-strip">
          <span class="mobile-kpi-pill" id="m-kpi-seq">seq: -</span>
          <span class="mobile-kpi-pill" id="m-kpi-claims">claims: -</span>
          <span class="mobile-kpi-pill" id="m-kpi-tiers">-</span>
          <button class="mobile-kpi-pill" id="m-kpi-coherence" type="button" style="cursor:pointer;color:#6ee7b7;border-color:rgba(52,211,153,0.4);">coh: -</button>
          <button class="mobile-kpi-pill" id="m-kpi-efficacy" type="button" style="cursor:pointer;color:#38bdf8;border-color:rgba(56,189,248,0.45);">eff: -</button>
          <button class="mobile-kpi-pill" id="m-kpi-dreaming" type="button" style="cursor:pointer;color:#c4b5fd;border-color:rgba(167,139,250,0.45);">dream: eigenvectors</button>
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
      <div class="metric" id="coherence-card" style="cursor:pointer;" title="Tap to inspect 5-axis Hive Coherence 2.0 Index, Epistemic Drift telemetry, and retroactive inception timeline">
        <span class="metric-label" style="color:#6ee7b7;">Coherence 2.0</span>
        <span id="coherence-val" class="metric-val" style="color:#6ee7b7;">-</span>
        <span id="coherence-sub" class="metric-sub">tap for timeline</span>
      </div>
      <div class="metric" id="efficacy-card" style="cursor:pointer;" title="Tap to inspect 4-axis Synaptic Efficacy: Information Distribution Breadth, Retrieval Precision, Cross-Agent Handoff Velocity, and State Reuse">
        <span class="metric-label" style="color:#38bdf8;">Synaptic Efficacy</span>
        <span id="efficacy-val" class="metric-val" style="color:#38bdf8;">-</span>
        <span id="efficacy-sub" class="metric-sub">handoff &amp; recall · tap</span>
      </div>
      <div class="metric" id="dreaming-card" style="cursor:pointer;" title="Tap to inspect Merkle Dreaming, 3-Trigger Curation State, and Stage 0 Spectral Topic Eigenvectors">
        <span class="metric-label" style="color:#c4b5fd;">Merkle Dreaming</span>
        <span id="dreaming-val" class="metric-val" style="color:#c4b5fd;">Stage 0–3</span>
        <span id="dreaming-sub" class="metric-sub">eigenvectors · tap</span>
      </div>
    </div>
  </header>
  <div id="alert-banner" class="alert-banner" role="alert" hidden></div>

  <aside class="hud-left graph-only">
    <div class="glass-box panel agents-box">
      <div class="box-title">
        <span>Agent Ganglia</span>
        <span><span id="roster-count" class="mini">0 agents</span> <button class="sheet-close" type="button" data-close-drawer="1" aria-label="Close panel">✕</button></span>
      </div>
      <div id="agent-list" class="agent-list"></div>
    </div>
    <div class="glass-box panel legend-box">
      <div class="box-title">Engram &amp; Ganglion Key</div>
      <div class="legend-grid">
        <div class="legend-item"><span class="shape canon"></span><span>Rank 2 canon (owner)</span></div>
        <div class="legend-item"><span class="shape decision"></span><span>Class B decision (no expiry)</span></div>
        <div class="legend-item"><span class="shape fresh"></span><span>Class A status, fresh</span></div>
        <div class="legend-item"><span class="shape aging"></span><span>Class A status, near expiry</span></div>
        <div class="legend-item"><span class="shape" style="background:#10b981;border-radius:999px;box-shadow:0 0 8px #10b981;"></span><span>Ganglion active (&le;5m R/W)</span></div>
        <div class="legend-item"><span class="shape" style="background:#475569;border-radius:999px;border:1px dashed #94a3b8;"></span><span>Ganglion silent (&gt;20m)</span></div>
      </div>
    </div>
    <div class="glass-box panel feed-box">
      <div class="box-title">
        <span>Synaptic Activity</span>
        <span><span id="pulse-counter" class="mini">0 pulses</span> <button class="sheet-close" type="button" data-close-drawer="1" aria-label="Close panel">✕</button></span>
      </div>
      <div id="stream-list" class="stream-list"></div>
    </div>
  </aside>

  <aside class="hud-right graph-only">
    <div id="inspector-box" class="glass-box panel inspector idle"></div>
  </aside>

  <div class="zoom-fab graph-only">
    <button class="btn" id="btn-zoom-in" type="button" aria-label="Zoom in">+</button>
    <button class="btn" id="btn-zoom-out" type="button" aria-label="Zoom out">−</button>
    <button class="btn" id="btn-zoom-reset" type="button" aria-label="Reset camera">⟲</button>
  </div>

  <div class="hud-bottom graph-only">
    <div class="control-bar sim-bar panel">
      <span class="sim-label" id="dream-bar-status">Merkle Dreaming · Passive Read-Only Telemetry</span>
      <button class="btn sim" id="btn-dream-replay" type="button">Replay Last Dream (4-Act)</button>
      <button class="btn sim" id="btn-dream-record" type="button" style="border-color:rgba(244,114,182,0.55);color:#f9a8d4;">● Record Reorganization (.webm)</button>
      <button class="btn sim" id="btn-dream-consolidate" type="button">Inspect Curation (Passive)</button>
      <button class="btn sim" id="btn-dream-triggers" type="button">Inspect 3-Trigger State</button>
      <button class="btn sim" id="btn-dream-coherence" type="button">5-Axis Coherence</button>
      <button class="btn sim" id="btn-dream-efficacy" type="button" style="border-color:rgba(56,189,248,0.55);color:#7dd3fc;">4-Axis Synaptic Efficacy</button>
    </div>
    <div class="control-bar panel">
      <input type="search" id="cortex-search" placeholder="🔍 Search claims / pr:351 / @agent…" aria-label="Search claims or entity links" style="background:rgba(15,23,42,0.88);color:#f8fafc;border:1px solid rgba(56,189,248,0.45);border-radius:6px;padding:4px 8px;font-size:11px;width:190px;">
      <button class="btn sim" id="btn-3d-toggle" type="button" style="border-color:rgba(167,139,250,0.55);color:#c4b5fd;">🌐 3D Depth: ON</button>
      <button class="btn" id="btn-3d-orbit" type="button">↻ Orbit: ON</button>
      <label for="time-slider">Time-decay forecast</label>
      <input type="range" id="time-slider" min="0" max="30" step="0.5" value="0">
      <span id="time-label">NOW (+0.0d)</span>
      <button class="btn" id="btn-reset-view" type="button">Reset camera</button>
      <button class="sheet-close" type="button" data-close-drawer="1" aria-label="Close tools">✕</button>
    </div>
  </div>

  <nav class="mobile-dock panel" id="mobile-dock" aria-label="Mobile view navigation">
    <button class="dock-btn active" id="dock-graph" type="button">Cortex</button>
    <button class="dock-btn" id="dock-agents" type="button">Agents</button>
    <button class="dock-btn" id="dock-pulses" type="button">Pulses</button>
    <button class="dock-btn" id="dock-tools" type="button">Dream / Time</button>
    <button class="dock-btn" id="dock-cards" type="button">Cards</button>
  </nav>

  <main class="wrap cards-only">
    <section id="cards-coherence-section" style="border-color:rgba(52,211,153,0.35);">
      <h2>
        <span style="color:#6ee7b7;">Hive Coherence 2.0 &amp; Consolidation Trajectory Graphs</span>
        <span id="cards-coherence-badge" class="badge ok">-</span>
      </h2>
      <canvas id="cards-coherence-canvas" width="720" height="176" style="width:100%;height:132px;border-radius:8px;background:rgba(2,6,23,0.82);border:1px solid rgba(52,211,153,0.32);margin-bottom:8px;"></canvas>
      <div id="cards-coherence-bars" class="kv-list" style="gap:4px;"></div>
    </section>

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
        'dead-rabbit': { name: 'Dead Rabbit', model: 'Claude Opus 4.6', color: '#f59e0b' },
        mydude: { name: 'My Dude', model: 'OpenAI Codex', color: '#10b981' },
        neil: { name: 'Neil', model: 'OpenAI Codex', color: '#38bdf8' },
        'waggle-dev': { name: 'Waggle-Dev', model: 'Claude Sonnet 4.6', color: '#fb923c' },
        crystalclaude: { name: 'CrystalClaude', model: 'Claude Opus 4.6', color: '#f472b6' },
        'dj-codex': { name: 'DJ-Codex', model: 'OpenAI Codex', color: '#34d399' },
        djcodex: { name: 'DJ Codex', model: 'OpenAI Codex', color: '#34d399' },
        dennis: { name: 'Dennis', model: 'Claude Opus 4.6', color: '#60a5fa' },
        kerouac: { name: 'Kerouac', model: 'Claude Opus 4.6', color: '#c084fc' },
        grokdoggydog: { name: 'GrokDoggyDog', model: 'xAI Grok 4', color: '#f87171' },
        'pi-dog': { name: 'Pi-Dog', model: 'Pi Harness Agent', color: '#2dd4bf' },
        lukedog: { name: 'LukeDog', model: '', color: '#a3e635' },
        'mc-claude': { name: 'MC-Claude', model: 'Claude Opus 4.6', color: '#e879f9' },
        curator: { name: 'Curator', model: 'Merkle Dreamer', color: '#a78bfa' }
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
      var dreamSymphony = null;
      var dreamRecorder = null;
      var hovered = null;
      var selected = null;
      var futureDays = 0;
      var lastActivitySeq = null;
      var pulseTotal = 0;
      var tick = 0;
      var latestCuratorState = null;
      var latestConsolidatedSources = {};
      var latestConstellationLinks = [];
      var latestEntityGraphStats = null;
      var latestTopicPages = {};
      var latestStoreState = {};
      var latestRecentActivity = [];
      var prevByEventId = {};
      var mode3D = true;
      var autoOrbit3D = true;
      var rotX = 0.34;
      var rotY = 0;
      var searchQuery = '';
      var CLIENT_SYNONYMS = [
        ['viewer', 'visualizer', 'visualization', 'observatory', 'ui', 'canvas', 'graph', 'hud', 'inspector', '8795', '3d'],
        ['curate', 'curator', 'curation', 'dream', 'dreaming', 'consolidate', 'consolidated', 'consolidation', 'merkle', 'distill'],
        ['canon', 'rule', 'standing', 'constitution', 'owner', 'sovereign', 'above-the-line'],
        ['search', 'query', 'recall', 'wake', 'hybrid', 'bm25', 'fts5', 'vector', 'rrf']
      ];

      function computeNodeZ(rec, idx) {
        if (!rec) return 0;
        if (isCanon(rec)) return 0;
        var isAbove = rec.expires_at === null || rec.expires_at === undefined || Boolean(rec.merkle_sources);
        if (isAbove) return 44 + ((idx % 3) * 16);
        return -34 - ((idx % 4) * 13);
      }

      function project3D(x, y, z) {
        if (!mode3D) return { x: x, y: y, z: 0, scale: 1 };
        var cy = Math.cos(rotY);
        var sy = Math.sin(rotY);
        var cx = Math.cos(rotX);
        var sx = Math.sin(rotX);
        var x1 = x * cy - z * sy;
        var z1 = x * sy + z * cy;
        var y2 = y * cx - z1 * sx;
        var z2 = y * sx + z1 * cx;
        var fov = 760;
        var scale = fov / Math.max(220, fov - z2);
        return { x: x1 * scale, y: y2 * scale, z: z2, scale: scale };
      }

      function nodeMatchesSearch(rec, rawQ) {
        var q = String(rawQ || '').trim().toLowerCase();
        if (!q) return true;
        var hay = (
          String(rec.d || '') + ' ' +
          String(rec.topic || '') + ' ' +
          String(rec.scope || '') + ' ' +
          String(rec.claim || '') + ' ' +
          String(rec.because || '') + ' ' +
          String(rec.as_of_git || '') + ' ' +
          (Array.isArray(rec.evidence) ? rec.evidence.join(' ') : '')
        ).toLowerCase();
        if (hay.indexOf(q) >= 0) return true;
        var qClean = q.replace(/^(?:pr:|issue:|file:|agent:|#)/, '');
        if (qClean && hay.indexOf(qClean) >= 0) return true;
        for (var c = 0; c < CLIENT_SYNONYMS.length; c++) {
          var cluster = CLIENT_SYNONYMS[c];
          if (cluster.indexOf(qClean) >= 0) {
            for (var w = 0; w < cluster.length; w++) {
              if (hay.indexOf(cluster[w]) >= 0) return true;
            }
          }
        }
        return false;
      }

      function openTopicInspector(topicId) {
        if (view !== 'graph') switchView('graph');
        var topObj = topicById(topicId) || { id: topicId || 'general', color: '#38bdf8', x: 0, y: 0, radius: 40 };
        selected = { type: 'topic', data: topObj };
        hovered = null;
        if (width <= 1024) setDrawer('none');
        renderAgentRoster();
        renderInspector();
      }

      function fmtTime(sec) {
        if (!sec || typeof sec !== 'number') return 'never';
        var d = new Date(sec * 1000);
        return d.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
      }

      function fmtAge(sec, nowSec) {
        if (!sec || typeof sec !== 'number') return 'none';
        var diff = Math.floor(Math.max(0, (nowSec || Math.floor(Date.now() / 1000)) - sec));
        if (diff < 60) return diff + 's ago';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ' + (diff % 60) + 's ago';
        return Math.floor(diff / 3600) + 'h ' + Math.floor((diff % 3600) / 60) + 'm ago';
      }

      function fmtShortAge(sec, nowSec) {
        if (!sec || typeof sec !== 'number') return 'silent';
        var diff = Math.floor(Math.max(0, (nowSec || Math.floor(Date.now() / 1000)) - sec));
        if (diff < 60) return diff + 's';
        if (diff < 3600) return Math.floor(diff / 60) + 'm';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h';
        return Math.floor(diff / 86400) + 'd';
      }

      function healthColor(h) {
        if (h === 'active') return '#10b981';
        if (h === 'warm') return '#f59e0b';
        if (h === 'error') return '#ef4444';
        return '#475569';
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
          last_read_at: null,
          last_read_kind: null,
          last_recall_at: null,
          last_recall_kind: null,
          last_write_at: null,
          last_write_d: null,
          last_refused_at: null,
          last_refused_code: null,
          last_seen_at: null,
          active_5m: false,
          reads_5m: 0,
          writes_5m: 0,
          health: 'stale',
          compliance_status: 'compliant',
          coherence_score: 0,
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
          a.radius = width < 680 ? (a.is_owner ? 18 : 14) : (a.is_owner ? 21 : 17);
        });
        var even = topics.length > TOPIC_ANCHORS.length;
        topics.forEach(function (t, i) {
          var angle = even ? -Math.PI / 2 + (i / topics.length) * Math.PI * 2 : t.anchorAngle;
          t.x = Math.cos(angle) * minDim * 0.25;
          t.y = Math.sin(angle) * minDim * 0.25;
          t.radius = minDim * 0.12;
        });
      }

      function placeNode(n, idx) {
        n.idx = idx;
        n.z = computeNodeZ(n.rec, idx);
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
        var activity = Array.isArray(s.recent_activity) ? s.recent_activity : [];
        var recs = Array.isArray(s.records) ? s.records : [];
        var refNow = s.polled_at || nowSec();
        var next = [];
        roster.forEach(function (r) {
          var prev = agentById(r.id);
          var lastRead = typeof r.last_read_at === 'number' ? r.last_read_at : (prev ? prev.last_read_at : null);
          var lastReadKind = r.last_read_kind || (prev ? prev.last_read_kind : null);
          var lastRecall = typeof r.last_recall_at === 'number' ? r.last_recall_at : (prev ? prev.last_recall_at : null);
          var lastRecallKind = r.last_recall_kind || (prev ? prev.last_recall_kind : null);
          var lastWrite = typeof r.last_write_at === 'number' ? r.last_write_at : (prev ? prev.last_write_at : null);
          var lastWriteD = r.last_write_d || (prev ? prev.last_write_d : null);
          var lastRefused = typeof r.last_refused_at === 'number' ? r.last_refused_at : (prev ? prev.last_refused_at : null);
          var lastRefusedCode = r.last_refused_code || (prev ? prev.last_refused_code : null);
          var reads5m = typeof r.reads_5m === 'number' ? r.reads_5m : 0;
          var writes5m = typeof r.writes_5m === 'number' ? r.writes_5m : 0;
          if (!r.health) {
            recs.forEach(function (rec) {
              if (r.pubkey && rec.author_pubkey === r.pubkey && typeof rec.created_at === 'number') {
                if (!lastWrite || rec.created_at >= lastWrite) { lastWrite = rec.created_at; lastWriteD = rec.d || lastWriteD; }
              }
            });
            activity.forEach(function (act) {
              if (!act || act.actor !== r.id || typeof act.at !== 'number') return;
              var in5 = Math.max(0, refNow - act.at) <= 300;
              if (act.kind === 'wake' || act.kind === 'query' || act.kind === 'lookup') {
                if (!lastRead || act.at >= lastRead) { lastRead = act.at; lastReadKind = act.kind; }
                if ((act.kind === 'wake' || act.kind === 'query') && (!lastRecall || act.at >= lastRecall)) {
                  lastRecall = act.at;
                  lastRecallKind = act.kind;
                }
                if (in5) reads5m += 1;
              } else if (act.kind === 'submit') {
                if (!lastWrite || act.at >= lastWrite) { lastWrite = act.at; lastWriteD = act.d || lastWriteD; }
                if (in5) writes5m += 1;
              } else if (act.kind === 'refused') {
                if (!lastRefused || act.at >= lastRefused) { lastRefused = act.at; lastRefusedCode = act.code || 'REFUSED'; }
              }
            });
          }
          var lastSeen = typeof r.last_seen_at === 'number' ? r.last_seen_at : (Math.max(lastRead || 0, lastWrite || 0) || null);
          var ageSec = lastSeen !== null ? Math.max(0, refNow - lastSeen) : null;
          var active5m = typeof r.active_5m === 'boolean' ? r.active_5m : (ageSec !== null && ageSec <= 300);
          var health = r.health || (
            lastRefused !== null && (lastSeen === null || lastRefused > lastSeen) && Math.max(0, refNow - lastRefused) <= 900
              ? 'error'
              : (active5m ? 'active' : (ageSec !== null && ageSec <= 1200 ? 'warm' : 'stale'))
          );
          var complianceStatus = r.compliance_status || (
            health === 'error'
              ? 'tool_failure'
              : (r.is_reader && r.id !== 'curator' && r.id !== 'viewer'
                ? (lastRecall ? 'compliant' : ((lastWrite || lastRead) ? 'write_without_recall' : 'blind_seat'))
                : 'compliant')
          );
          var recallAge = lastRecall !== null ? Math.max(0, refNow - lastRecall) : null;
          var recallSync = lastRecall !== null
            ? (recallAge <= 900 ? 50 : (recallAge <= 3600 ? 44 : 36))
            : (r.is_owner ? 50 : 0);
          var writeHygiene = lastWrite !== null
            ? ((lastRecall !== null || r.is_owner) ? 30 : 18)
            : ((lastRecall !== null || r.is_owner) ? 24 : (lastRead !== null ? 10 : 0));
          if (health === 'error') writeHygiene = Math.max(0, writeHygiene - 15);
          var sharedResonance = ((lastRecall !== null && lastWrite !== null) || r.is_owner)
            ? 20
            : ((lastRecall !== null || lastWrite !== null) ? 14 : (lastRead !== null ? 6 : 0));
          var cohScore = typeof r.coherence_score === 'number'
            ? r.coherence_score
            : Math.max(0, Math.min(100, Math.round(recallSync + writeHygiene + sharedResonance)));
          next.push(makeAgent(r.id, {
            pubkey: r.pubkey || null,
            is_reader: Boolean(r.is_reader),
            is_writer: Boolean(r.is_writer),
            is_owner: Boolean(r.is_owner),
            per_hour: r.per_hour || 0,
            used_last_hour: typeof r.used_last_hour === 'number' ? r.used_last_hour : null,
            last_read_at: lastRead,
            last_read_kind: lastReadKind,
            last_recall_at: lastRecall,
            last_recall_kind: lastRecallKind,
            last_write_at: lastWrite,
            last_write_d: lastWriteD,
            last_refused_at: lastRefused,
            last_refused_code: lastRefusedCode,
            last_seen_at: lastSeen,
            active_5m: active5m,
            reads_5m: reads5m,
            writes_5m: writes5m,
            health: health,
            compliance_status: complianceStatus,
            coherence_score: cohScore,
            energy: prev ? prev.energy : 0
          }));
        });
        var known = {};
        next.forEach(function (a) { if (a.pubkey) known[a.pubkey] = true; });
        recs.forEach(function (rec) {
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

      function resolveSourceNodes(rec, anchorNode) {
        var srcIds = Array.isArray(rec && rec.supersedes) ? rec.supersedes : [];
        var top = topicById(topicOf(rec));
        var cx = anchorNode ? anchorNode.x : (top ? top.x : 0);
        var cy = anchorNode ? anchorNode.y : (top ? top.y : 0);
        return srcIds.map(function (id, idx) {
          var existing = nodeByEventId(id) || prevByEventId[id];
          if (existing) return existing;
          var angle = -Math.PI / 2 + (idx / Math.max(1, srcIds.length)) * Math.PI * 2;
          var dist = 36 + (idx % 2) * 14;
          var hasConsolidated = Boolean(latestConsolidatedSources && latestConsolidatedSources[id]);
          var histRec = (latestConsolidatedSources && latestConsolidatedSources[id]) || {
            event_id: id,
            scope: rec.scope,
            topic: rec.topic,
            d: id.slice(0, 12)
          };
          return {
            key: 'src:' + id,
            rec: histRec,
            x: cx + Math.cos(angle) * dist,
            y: cy + Math.sin(angle) * dist,
            vx: 0,
            vy: 0,
            isSourceGhost: true,
            isHistoricalSource: hasConsolidated,
            isSyntheticGhost: !hasConsolidated,
            simulated: !hasConsolidated,
            ghostLabel: hasConsolidated ? 'HISTORICAL SOURCE' : 'SIMULATED PREVIEW GHOST'
          };
        });
      }

      function syncGraph(s, animate) {
        var records = Array.isArray(s.records) ? s.records : [];
        syncAgents(s);
        syncTopics(records);
        layout();

        var byKey = {};
        var oldByEventId = {};
        nodes.forEach(function (n) {
          byKey[n.key] = n;
          if (n.rec && n.rec.event_id) oldByEventId[n.rec.event_id] = n;
        });
        prevByEventId = oldByEventId;
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
            var merkleDigest = typeof n.rec.merkle_sources === 'string' ? n.rec.merkle_sources : '';
            if (merkleDigest && !consolidator) {
              var top = topicById(topicOf(n.rec));
              var srcNodes = resolveSourceNodes(n.rec, n);
              if (top && srcNodes.length > 0) {
                consolidator = {
                  mode: 'live-write',
                  topic: top,
                  targetNode: n,
                  targets: srcNodes,
                  merkleDigest: merkleDigest,
                  x: n.x,
                  y: n.y,
                  progress: 0
                };
                logStream(
                  'write',
                  'MERKLE DREAMING curator write in ' + String(n.rec.scope || 'hive') + ' #' + top.id +
                  ' (merkle_sources ' + merkleDigest.slice(0, 12) + '… · ' + srcNodes.length + ' superseded sources)',
                  n.rec.created_at
                );
              }
            }
          });
        }
        updateDreamBarStatus();
        if (selected && selected.type === 'dreaming') selected.data = computeDreamingTelemetry();
        renderAgentRoster();
        updateTiers();
        renderInspector();
      }

      // --- Pulses: real activity from the ring and live Merkle Dreaming curation ---

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

      function isWorkflowCheckpoint(rec) {
        return /-(?:review|status|owner|wip|handoff)$/.test(slugOf(rec));
      }

      function computeDreamingTelemetry() {
        var recs = nodes.map(function (n) { return n.rec; });
        var fullBytes = JSON.stringify(recs).length;
        var indexBytes = 0;
        var canonBytes = 0;
        var wfCount = 0;
        var shortTtlCount = 0;
        var classBCount = 0;
        var merkleCount = 0;
        var nightmareCount = 0;
        var byScopeTopic = {};
        var cs = latestCuratorState || {};
        var pressureThreshold = Number(cs.topic_pressure_threshold) || 8;
        recs.forEach(function (r) {
          var isWf = isWorkflowCheckpoint(r);
          indexBytes += 140 + Math.min(120, String(r.claim || '').length) + String(r.d || '').length;
          if (typeof r.merkle_sources === 'string' && r.merkle_sources.length > 0) merkleCount += 1;
          if (r.conflict || ((isCanon(r) || r.expires_at === null || r.expires_at === undefined) && r.stale_warning)) {
            nightmareCount += 1;
          }
          if (isCanon(r)) canonBytes += JSON.stringify(r).length;
          else if (r.expires_at === null || r.expires_at === undefined) classBCount += 1;
          else {
            var sc = String(r.scope || 'unknown');
            var top = topicOf(r);
            var key = sc + ' · #' + top;
            if (!byScopeTopic[key]) byScopeTopic[key] = { scope: sc, topic: top, label: key, count: 0 };
            byScopeTopic[key].count += 1;
          }
          if (isWf) {
            wfCount += 1;
            if (r.expires_at !== null && r.expires_at !== undefined && r.created_at && (r.expires_at - r.created_at) <= 172800) {
              shortTtlCount += 1;
            }
          }
        });
        var wakeBytes = canonBytes + Math.min(4000, indexBytes);
        var indexSavings = fullBytes > 0 ? Math.round((1 - indexBytes / fullBytes) * 1000) / 10 : 0;
        var wakeSavings = fullBytes > 0 ? Math.round((1 - wakeBytes / fullBytes) * 1000) / 10 : 0;
        var topicList = Object.keys(byScopeTopic).map(function (k) {
          var item = byScopeTopic[k];
          return { scope: item.scope, topic: item.topic, label: item.label, count: item.count, ready: item.count > pressureThreshold };
        }).sort(function (a, b) { return b.count - a.count; });
        var writeSeq = Number(latestStoreState && latestStoreState.write_seq) || 0;
        var lastCuratedSeq = Number(cs.last_curated_write_seq) || 0;
        var writeDelta = typeof cs.write_delta === 'number' ? cs.write_delta : Math.max(0, writeSeq - lastCuratedSeq);
        var writeDeltaThreshold = Number(cs.write_delta_threshold) || 20;
        var dreamIntervalSec = Number(cs.dream_interval_sec) || 21600;
        var lastCuratedAt = Number(cs.last_curated_at) || 0;
        var elapsedSec = typeof cs.elapsed_sec === 'number' ? cs.elapsed_sec : (lastCuratedAt > 0 ? Math.max(0, Math.floor(nowSec() - lastCuratedAt)) : 0);
        var triggers = cs.triggers || {
          circadian_dream: lastCuratedAt > 0 && elapsedSec >= dreamIntervalSec,
          synaptic_volume: writeDelta >= writeDeltaThreshold || topicList.some(function (t) { return t.ready; }),
          nightmare_interrupt: nightmareCount > 0
        };
        var shouldRun = typeof cs.should_run === 'boolean'
          ? cs.should_run
          : Boolean(triggers.circadian_dream || triggers.synaptic_volume || triggers.nightmare_interrupt);
        var reasons = Array.isArray(cs.reasons) ? cs.reasons : [];
        var hasPersistedCuration = Boolean(cs.state_file_present && lastCuratedAt > 0 && merkleCount > 0);
        var dm = (cs.display_mode && typeof cs.display_mode === 'object') ? cs.display_mode : null;
        var comps = (dm && dm.components) || {
          clusters: hasPersistedCuration ? 'observed' : 'simulated_preview',
          eigenvalues: (hasPersistedCuration && Array.isArray(cs.topic_eigenvectors) && cs.topic_eigenvectors.length > 0 && !cs.topic_eigenvectors.some(function (e) { return !e || e.simulated || e.persisted === false; })) ? 'observed' : 'simulated_preview',
          topic_arcs: (hasPersistedCuration && Array.isArray(cs.topic_reorganizations) && cs.topic_reorganizations.length > 0 && !cs.topic_reorganizations.some(function (a) { return !a || a.simulated || a.persisted === false; })) ? 'observed' : 'simulated_preview',
          ghost_sources: hasPersistedCuration ? 'observed' : 'simulated_preview'
        };
        var isSimulatedPreview = comps.clusters !== 'observed' || comps.eigenvalues !== 'observed' || comps.topic_arcs !== 'observed' || comps.ghost_sources !== 'observed';
        var displayMode = (dm && dm.mode) || (isSimulatedPreview ? 'simulated_preview' : 'observed');
        return {
          estimated_from_visible: true,
          passive_inspection: true,
          displayMode: displayMode,
          isSimulatedPreview: isSimulatedPreview,
          components: comps,
          clustersObserved: comps.clusters === 'observed',
          eigensObserved: comps.eigenvalues === 'observed',
          arcsObserved: comps.topic_arcs === 'observed',
          ghostsObserved: comps.ghost_sources === 'observed',
          total: recs.length,
          fullBytes: fullBytes,
          indexBytes: indexBytes,
          wakeBytes: wakeBytes,
          indexSavings: indexSavings,
          wakeSavings: wakeSavings,
          wfCount: wfCount,
          shortTtlCount: shortTtlCount,
          classBCount: classBCount,
          merkleCount: merkleCount,
          nightmareCount: nightmareCount,
          topicList: topicList,
          curatorState: {
            state_file_present: Boolean(cs.state_file_present),
            last_curated_at: lastCuratedAt || null,
            last_curated_write_seq: lastCuratedSeq,
            last_ran_at: cs.last_ran_at || null,
            last_submitted_count: cs.last_submitted_count || 0,
            elapsed_sec: elapsedSec,
            dream_interval_sec: dreamIntervalSec,
            write_delta: writeDelta,
            write_delta_threshold: writeDeltaThreshold,
            topic_pressure_threshold: pressureThreshold,
            should_run: shouldRun,
            triggers: triggers,
            reasons: reasons,
            refusal_count_15m: Number(cs.refusal_count_15m) || 0,
            stale_count: Number(cs.stale_count) || 0,
            display_mode: dm || {
              mode: displayMode,
              is_simulated_preview: isSimulatedPreview,
              components: comps
            }
          }
        };
      }

      function updateDreamBarStatus() {
        var bar = el('dream-bar-status');
        if (!bar) return;
        var d = computeDreamingTelemetry();
        var cs = d.curatorState;
        var modeTag = !d.isSimulatedPreview
          ? ('[OBSERVED CURATION · ' + d.merkleCount + ' persisted merkle_sources] · ')
          : (d.clustersObserved
            ? ('[MIXED · ' + d.merkleCount + ' persisted merkle_sources + PREVIEW PROPOSALS] · ')
            : ('[SIMULATED PREVIEW · ' + d.merkleCount + ' persisted merkle_sources] · '));
        var lastLabel = cs.last_curated_at ? ('last curated ' + fmtShortAge(cs.last_curated_at, nowSec()) + ' ago (seq ' + cs.last_curated_write_seq + ')') : 'last curated: never (seq 0)';
        var deltaLabel = '+' + cs.write_delta + '/' + cs.write_delta_threshold + ' writes';
        if (cs.triggers.nightmare_interrupt || d.nightmareCount > 0) {
          bar.textContent = modeTag + 'NIGHTMARE TRIGGER ACTIVE · ' + lastLabel + ' · ' + deltaLabel + ' · ' + d.merkleCount + ' merkle_sources tags';
          bar.style.color = '#f87171';
        } else if (cs.should_run) {
          bar.textContent = modeTag + 'CURATOR TRIGGER DUE (' + (cs.reasons[0] || deltaLabel) + ') · ' + lastLabel + ' · ' + d.merkleCount + ' merkle_sources tags';
          bar.style.color = '#fbbf24';
        } else {
          bar.textContent = modeTag + 'Passive Read-Only · ' + lastLabel + ' · ' + deltaLabel + ' · ' + d.merkleCount + ' merkle_sources tags · -' + d.wakeSavings + '% wake';
          bar.style.color = '#94a3b8';
        }
      }

      function clientWorkSubject(rec) {
        var slug = slugOf(rec).toLowerCase();
        var claim = String((rec && rec.claim) || '').toLowerCase();
        var m = (slug + ' ' + claim).match(/\b(?:pr|issue|w|step)[-#_\s]?(\d+)\b/);
        if (m) return 'work-' + m[1];
        var stripped = slug
          .replace(/-(?:owner|status|review|approved|merged|deployed|live|done|fixed|wip|handoff|check|verified|complete|blocked|waiting|plan|v\d+)$/g, '')
          .replace(/^(?:curated|decision)-/g, '');
        var parts = stripped.split('-').filter(Boolean);
        return parts.slice(0, 3).join('-') || stripped || 'general';
      }

      function buildPreviewDreamClusters() {
        var planned = Array.isArray(latestCuratorState && latestCuratorState.planned_clusters)
          ? latestCuratorState.planned_clusters
          : [];
        var built = [];
        if (planned.length > 0) {
          planned.forEach(function (pc, cIdx) {
            var evIds = Array.isArray(pc.source_event_ids) ? pc.source_event_ids : [];
            var matched = [];
            evIds.forEach(function (id) {
              var found = nodeByEventId(id) || prevByEventId[id];
              if (found && matched.indexOf(found) < 0) matched.push(found);
            });
            matched.sort(function (a, b) { return (b.rec.created_at || 0) - (a.rec.created_at || 0); });
            var target = matched[0] || nodes[cIdx % Math.max(1, nodes.length)];
            if (!target) return;
            var top = topicById(pc.topic || topicOf(target.rec));
            var rawSources = matched.slice(1);
            if (rawSources.length === 0) {
              rawSources = [
                { x: target.x + 28, y: target.y - 22, rec: target.rec, isSourceGhost: true, isSyntheticGhost: true, simulated: true, ghostLabel: 'SIMULATED PREVIEW GHOST' },
                { x: target.x - 26, y: target.y + 24, rec: target.rec, isSourceGhost: true, isSyntheticGhost: true, simulated: true, ghostLabel: 'SIMULATED PREVIEW GHOST' }
              ];
            }
            var srcs = rawSources.map(function (sn, sIdx) {
              var ang = -Math.PI / 2 + (sIdx / Math.max(1, rawSources.length)) * Math.PI * 2 + cIdx * 0.37;
              var dist = 42 + (sIdx % 3) * 16;
              return {
                node: sn,
                simulated: true,
                angle: ang,
                dist: dist,
                initX: target.x + Math.cos(ang) * dist,
                initY: target.y + Math.sin(ang) * dist,
                x: target.x + Math.cos(ang) * dist,
                y: target.y + Math.sin(ang) * dist
              };
            });
            built.push({
              target: target,
              topic: top,
              sources: srcs,
              simulated: true,
              clusterLabel: 'SIMULATED PREVIEW CLUSTER',
              merkleDigest: 'sim-preview-' + String(pc.merkle_sources || ((pc.topic || 'hive') + '-' + cIdx)),
              isClassB: pc.stage === 'promotion' || (pc.author_count && pc.author_count >= 2),
              stagger: (cIdx / Math.max(1, planned.length)) * 0.45,
              shocked: false
            });
          });
        }
        if (built.length > 0) return built;

        // Client-side fallback clustering by (topic, workSubject) across visible non-canon nodes (SIMULATED PREVIEW)
        var groups = {};
        nodes.forEach(function (n) {
          if (!n || !n.rec || isCanon(n.rec)) return;
          var topId = topicOf(n.rec);
          var subj = clientWorkSubject(n.rec);
          var gKey = topId + '::' + subj;
          if (!groups[gKey]) groups[gKey] = [];
          groups[gKey].push(n);
        });
        var groupKeys = Object.keys(groups).filter(function (k) { return groups[k].length >= 2; });
        if (groupKeys.length === 0) {
          var byTop = {};
          nodes.forEach(function (n) {
            if (!n || !n.rec || isCanon(n.rec)) return;
            var topId = topicOf(n.rec);
            if (!byTop[topId]) byTop[topId] = [];
            byTop[topId].push(n);
          });
          groupKeys = Object.keys(byTop).filter(function (k) { return byTop[k].length >= 2; });
          groups = byTop;
        }
        groupKeys.slice(0, 48).forEach(function (gKey, cIdx) {
          var members = groups[gKey].slice().sort(function (a, b) {
            return (b.rec.created_at || 0) - (a.rec.created_at || 0);
          });
          var target = members[0];
          var top = topicById(topicOf(target.rec));
          var authors = {};
          members.forEach(function (m) { if (m.rec.author_pubkey) authors[m.rec.author_pubkey] = true; });
          var isPromoted = Object.keys(authors).length >= 2 || target.rec.expires_at === null || target.rec.expires_at === undefined;
          var srcs = members.slice(1, 9).map(function (sn, sIdx) {
            var ang = -Math.PI / 2 + (sIdx / Math.max(1, members.length - 1)) * Math.PI * 2 + cIdx * 0.37;
            var dist = 42 + (sIdx % 3) * 16;
            return {
              node: sn,
              simulated: true,
              angle: ang,
              dist: dist,
              initX: target.x + Math.cos(ang) * dist,
              initY: target.y + Math.sin(ang) * dist,
              x: target.x + Math.cos(ang) * dist,
              y: target.y + Math.sin(ang) * dist
            };
          });
          built.push({
            target: target,
            topic: top,
            sources: srcs,
            simulated: true,
            clusterLabel: 'SIMULATED PREVIEW CLUSTER',
            merkleDigest: 'sim-preview-' + String(target.rec.event_id || cIdx).slice(0, 12),
            isClassB: isPromoted,
            stagger: (cIdx / Math.max(1, groupKeys.length)) * 0.45,
            shocked: false
          });
        });
        return built;
      }

      function buildDreamSymphony(merkleNodes) {
        var hasPersistedCurator = Boolean(latestCuratorState && latestCuratorState.state_file_present && Number(latestCuratorState.last_curated_at) > 0);
        var observedMerkleCount = merkleNodes ? merkleNodes.length : 0;
        var hasObservedMerkle = Boolean(hasPersistedCurator && observedMerkleCount > 0);
        var eigens = Array.isArray(latestCuratorState && latestCuratorState.topic_eigenvectors)
          ? latestCuratorState.topic_eigenvectors.slice()
          : [];
        var eigensSimulated = !hasObservedMerkle || eigens.length === 0 || eigens.some(function (e) { return Boolean(!e || e.simulated || e.persisted === false); });
        if (eigens.length === 0 && topics.length > 0) {
          eigensSimulated = true;
          var topCounts = topics.map(function (t) {
            var c = nodes.filter(function (n) { return topicOf(n.rec) === t.id; }).length;
            return { id: t.id, count: c };
          }).filter(function (x) { return x.count > 0; }).sort(function (a, b) { return b.count - a.count; });
          var totalC = topCounts.reduce(function (s, x) { return s + x.count; }, 0) || 1;
          eigens = topCounts.slice(0, 5).map(function (x, i) {
            return {
              axis: i + 1,
              canonical_topic: x.id,
              eigenvalue: Math.round(x.count * 10) / 10,
              variance_pct: Math.round((x.count / totalC) * 1000) / 10,
              simulated: true,
              persisted: false,
              label: 'SIMULATED PREVIEW EIGENVALUE'
            };
          });
        } else if (eigensSimulated) {
          eigens = eigens.map(function (e) {
            return Object.assign({}, e, { simulated: true, label: 'SIMULATED PREVIEW EIGENVALUE' });
          });
        }
        var reorgs = Array.isArray(latestCuratorState && latestCuratorState.topic_reorganizations)
          ? latestCuratorState.topic_reorganizations
          : [];
        var arcsSimulated = !hasObservedMerkle || reorgs.length === 0 || reorgs.some(function (r) { return Boolean(!r || r.simulated || r.persisted === false); });
        var outerR = stageDim() * 0.33;
        var reorgArcs = reorgs.map(function (rg, idx) {
          var fromTop = topicById(rg.from_topic);
          var toTop = topicById(rg.to_topic) || topics[idx % Math.max(1, topics.length)] || { x: 0, y: 0, color: '#38bdf8' };
          var ang = -Math.PI * 0.78 + (idx / Math.max(1, reorgs.length)) * Math.PI * 1.65;
          var fx = fromTop && (fromTop.x !== 0 || fromTop.y !== 0) ? fromTop.x : Math.cos(ang) * outerR;
          var fy = fromTop && (fromTop.x !== 0 || fromTop.y !== 0) ? fromTop.y : Math.sin(ang) * outerR;
          return {
            from_topic: rg.from_topic,
            to_topic: rg.to_topic,
            cosine: rg.cosine_affinity,
            claim_count: rg.claim_count || 1,
            fromX: fx,
            fromY: fy,
            toX: toTop.x,
            toY: toTop.y,
            color: toTop.color || '#38bdf8',
            simulated: arcsSimulated,
            label: arcsSimulated ? 'SIMULATED PREVIEW TOPIC ARC' : 'OBSERVED TOPIC ARC'
          };
        });
        if (reorgArcs.length === 0 && topics.length >= 2) {
          arcsSimulated = true;
          var primaryTop = topics[0];
          topics.slice(1, Math.min(6, topics.length)).forEach(function (t) {
            reorgArcs.push({
              from_topic: t.id,
              to_topic: primaryTop.id,
              cosine: 0.65,
              claim_count: 1,
              fromX: t.x,
              fromY: t.y,
              toX: primaryTop.x,
              toY: primaryTop.y,
              color: primaryTop.color || '#38bdf8',
              simulated: true,
              label: 'SIMULATED PREVIEW TOPIC ARC'
            });
          });
        }
        var totalSources = 0;
        var observedSourcesCount = 0;
        var ghostSourcesCount = 0;
        var clustersSimulated = !hasObservedMerkle;
        var ghostsSimulated = !hasObservedMerkle;
        var clusters = [];
        if (merkleNodes && merkleNodes.length > 0) {
          clusters = merkleNodes.map(function (mn, cIdx) {
            var top = topicById(topicOf(mn.rec));
            var srcs = resolveSourceNodes(mn.rec, mn).map(function (sn, sIdx) {
              var isMissingGhost = Boolean(sn && (sn.isSyntheticGhost || sn.simulated));
              if (isMissingGhost) {
                ghostSourcesCount += 1;
                ghostsSimulated = true;
              } else if (sn) {
                observedSourcesCount += 1;
              }
              var ang = -Math.PI / 2 + (sIdx / Math.max(1, (mn.rec.supersedes || []).length)) * Math.PI * 2 + cIdx * 0.37;
              var dist = 42 + (sIdx % 3) * 16;
              return {
                node: sn,
                simulated: isMissingGhost,
                angle: ang,
                dist: dist,
                initX: mn.x + Math.cos(ang) * dist,
                initY: mn.y + Math.sin(ang) * dist,
                x: mn.x + Math.cos(ang) * dist,
                y: mn.y + Math.sin(ang) * dist
              };
            });
            totalSources += srcs.length;
            return {
              target: mn,
              topic: top,
              sources: srcs,
              simulated: clustersSimulated,
              clusterLabel: clustersSimulated ? 'SIMULATED PREVIEW CLUSTER' : 'OBSERVED MERKLE CLUSTER',
              merkleDigest: String(mn.rec.merkle_sources || ''),
              isClassB: mn.rec.expires_at === null || mn.rec.expires_at === undefined,
              stagger: (cIdx / Math.max(1, merkleNodes.length)) * 0.45,
              shocked: false
            };
          });
          if (observedSourcesCount === 0) ghostsSimulated = true;
        } else {
          clustersSimulated = true;
          ghostsSimulated = true;
          clusters = buildPreviewDreamClusters();
          clusters.forEach(function (cl) {
            totalSources += cl.sources.length;
            cl.sources.forEach(function (s) {
              if (s.simulated || (s.node && (s.node.isSyntheticGhost || s.node.simulated))) ghostSourcesCount += 1;
            });
          });
        }
        var classBNodes = nodes.filter(function (mn) {
          return mn && mn.rec && !isCanon(mn.rec) && (mn.rec.expires_at === null || mn.rec.expires_at === undefined);
        });
        clusters.forEach(function (cl) {
          if (cl.isClassB && cl.target && classBNodes.indexOf(cl.target) < 0) {
            classBNodes.push(cl.target);
          }
        });
        var isSimulated = Boolean(clustersSimulated || eigensSimulated || arcsSimulated || ghostsSimulated);
        return {
          progress: 0,
          speed: 0.00145,
          actLogged: { 1: false, 2: false, 3: false, 4: false },
          displayMode: isSimulated ? 'simulated_preview' : 'observed',
          isSimulated: isSimulated,
          clustersSimulated: Boolean(clustersSimulated),
          eigensSimulated: Boolean(eigensSimulated),
          arcsSimulated: Boolean(arcsSimulated),
          ghostsSimulated: Boolean(ghostsSimulated),
          observedMerkleCount: observedMerkleCount,
          observedSourcesCount: observedSourcesCount,
          ghostSourcesCount: ghostSourcesCount,
          eigens: eigens,
          reorgArcs: reorgArcs,
          clusters: clusters,
          classBNodes: classBNodes,
          totalMerkle: clusters.length,
          totalSources: totalSources
        };
      }

      function stopDreamRecording() {
        if (!dreamRecorder) return;
        var recObj = dreamRecorder;
        dreamRecorder = null;
        var btn = el('btn-dream-record');
        if (btn) {
          btn.textContent = '● Record Reorganization (.webm)';
          btn.style.background = '';
        }
        if (selected && selected.type === 'dreaming') {
          renderInspector();
        }
        try {
          if (recObj.recorder && recObj.recorder.state !== 'inactive') {
            if (recObj.recorder.state === 'recording' && recObj.recorder.requestData) {
              try { recObj.recorder.requestData(); } catch (_) {}
            }
            recObj.recorder.stop();
          }
        } catch (_) {}
      }

      function startDreamRecording() {
        if (dreamRecorder) {
          stopDreamRecording();
          return;
        }
        if (typeof MediaRecorder === 'undefined' || !canvas.captureStream) {
          logStream('refuse', 'MediaRecorder / canvas.captureStream not supported in this browser');
          replayLastDream();
          return;
        }
        if (view !== 'graph') switchView('graph');
        cam.x = 0;
        cam.y = 0;
        cam.targetZoom = 1;
        cam.zoom = 1;
        var stream = canvas.captureStream(60);
        var mime = 'video/webm';
        if (MediaRecorder.isTypeSupported) {
          if (MediaRecorder.isTypeSupported('video/webm;codecs=vp9')) mime = 'video/webm;codecs=vp9';
          else if (MediaRecorder.isTypeSupported('video/webm;codecs=vp8')) mime = 'video/webm;codecs=vp8';
        }
        var chunks = [];
        var recorder;
        try {
          recorder = new MediaRecorder(stream, { mimeType: mime, videoBitsPerSecond: 6000000 });
        } catch (_) {
          recorder = new MediaRecorder(stream);
        }
        recorder.ondataavailable = function (ev) {
          if (ev.data && ev.data.size > 0) chunks.push(ev.data);
        };
        recorder.onstop = function () {
          var blob = new Blob(chunks, { type: mime });
          var url = URL.createObjectURL(blob);
          var dl = document.createElement('a');
          dl.href = url;
          dl.download = 'hive-cortex-reorganization-' + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-') + '.webm';
          document.body.appendChild(dl);
          dl.click();
          document.body.removeChild(dl);
          setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
          logStream('write', 'RECORDING SAVED · Downloaded 4-Act Cortex Reorganization video (.webm, ' + Math.round(blob.size / 1024) + ' KB)');
        };
        recorder.start(100);
        dreamRecorder = { recorder: recorder, startedAt: Date.now() };
        var btn = el('btn-dream-record');
        if (btn) {
          btn.textContent = '■ Stop & Save .webm';
          btn.style.background = 'rgba(239, 68, 68, 0.25)';
        }
        logStream('write', 'RECORDING STARTED (60fps .webm) · Capturing 4-Act Hive Mind Cortex Reorganization…');
        replayLastDream();
      }

      function replayLastDream() {
        if (view !== 'graph') switchView('graph');
        cam.x = 0;
        cam.y = 0;
        cam.targetZoom = 1;
        var merkleNodes = nodes.filter(function (n) {
          return n.rec && typeof n.rec.merkle_sources === 'string' && n.rec.merkle_sources.length > 0;
        }).sort(function (a, b) {
          return (b.rec.created_at || 0) - (a.rec.created_at || 0);
        });
        dreamSymphony = buildDreamSymphony(merkleNodes);
        if (merkleNodes.length > 0) {
          var latest = merkleNodes[0];
          var top = topicById(topicOf(latest.rec));
          var merkleDigest = String(latest.rec.merkle_sources || '');
          var srcNodes = resolveSourceNodes(latest.rec, latest);
          srcNodes.forEach(function (sn) {
            pulses.push({ kind: 'recall', fromNode: sn, fromX: sn.x, fromY: sn.y, toNode: latest, toX: latest.x, toY: latest.y, color: '#fbbf24', t: 0, speed: 0.02 });
          });
          if (top && srcNodes.length > 0) {
            consolidator = {
              mode: 'replay',
              simulated: Boolean(dreamSymphony.clustersSimulated || dreamSymphony.ghostsSimulated),
              topic: top,
              targetNode: latest,
              targets: srcNodes,
              merkleDigest: merkleDigest,
              x: latest.x,
              y: latest.y,
              progress: 0
            };
          }
        } else if (dreamSymphony.clusters.length > 0) {
          var firstCl = dreamSymphony.clusters[0];
          var clTarget = firstCl.target;
          var clTop = firstCl.topic || topicById(topicOf(clTarget.rec));
          var clSrcs = firstCl.sources.map(function (s) { return s.node; }).filter(Boolean);
          clSrcs.forEach(function (sn) {
            pulses.push({ kind: 'recall', fromNode: sn, fromX: sn.x, fromY: sn.y, toNode: clTarget, toX: clTarget.x, toY: clTarget.y, color: '#fbbf24', t: 0, speed: 0.02 });
          });
          if (clTop && clSrcs.length > 0) {
            consolidator = {
              mode: 'replay',
              simulated: true,
              topic: clTop,
              targetNode: clTarget,
              targets: clSrcs,
              merkleDigest: firstCl.merkleDigest || 'sim-preview-merkle-root',
              x: clTarget.x,
              y: clTarget.y,
              progress: 0
            };
          }
        }
        selected = { type: 'dreaming', data: computeDreamingTelemetry() };
        hovered = null;
        if (width <= 1024) setDrawer('none');
        renderAgentRoster();
        renderInspector();
        var simPrefix = dreamSymphony.isSimulated ? '[REPLAY · READ-ONLY] [SIMULATED PREVIEW] ' : '[REPLAY · READ-ONLY] [OBSERVED] ';
        logStream(
          'recall',
          simPrefix + '4-ACT CORTEX REORGANIZATION SYMPHONY · ' + dreamSymphony.eigens.length + (dreamSymphony.eigensSimulated ? ' Simulated' : ' Observed') + ' Eigen-Axes · ' +
          dreamSymphony.reorgArcs.length + (dreamSymphony.arcsSimulated ? ' Simulated' : ' Observed') + ' Topic Arcs · ' + dreamSymphony.totalSources + (dreamSymphony.ghostsSimulated ? ' Simulated/Ghost' : ' Observed') + ' Sources -> ' +
          dreamSymphony.totalMerkle + (dreamSymphony.clustersSimulated ? ' Simulated Preview' : ' Observed Merkle') + ' Clusters'
        );
      }

      function openDreamingInspector() {
        if (view !== 'graph') switchView('graph');
        var d = computeDreamingTelemetry();
        var cs = d.curatorState;
        selected = { type: 'dreaming', data: d };
        hovered = null;
        if (width <= 1024) setDrawer('none');
        renderAgentRoster();
        renderInspector();
        logStream(
          'lookup',
          'PASSIVE INSPECTION (read-only; no curator write) · ' + d.merkleCount + ' merkle_sources digest tags · +' +
          cs.write_delta + '/' + cs.write_delta_threshold + ' writes since seq ' + cs.last_curated_write_seq
        );
      }

      function inspectDreamTriggers() {
        if (view !== 'graph') switchView('graph');
        var d = computeDreamingTelemetry();
        var cs = d.curatorState;
        var lastAtStr = cs.last_curated_at ? (fmtTime(cs.last_curated_at) + ' (' + cs.elapsed_sec + 's/' + cs.dream_interval_sec + 's)') : 'never (0s/' + cs.dream_interval_sec + 's)';
        var volStr = '+' + cs.write_delta + '/' + cs.write_delta_threshold + ' writes (last seq ' + cs.last_curated_write_seq + ')';
        var reasonStr = cs.reasons.length ? cs.reasons.join('; ') : 'all 3 triggers below threshold';
        selected = { type: 'dreaming', data: d };
        hovered = null;
        if (width <= 1024) setDrawer('none');
        renderAgentRoster();
        renderInspector();
        logStream(
          cs.triggers.nightmare_interrupt ? 'refuse' : 'lookup',
          'PASSIVE 3-TRIGGER INSPECTION · shouldRun=' + String(cs.should_run) +
          ' | Circadian: ' + String(Boolean(cs.triggers.circadian_dream)) + ' [' + lastAtStr + ']' +
          ' | Volume: ' + String(Boolean(cs.triggers.synaptic_volume)) + ' [' + volStr + ']' +
          ' | Nightmare: ' + String(Boolean(cs.triggers.nightmare_interrupt)) +
          ' (' + reasonStr + ')'
        );
      }

      // --- HUD: roster, tiers and inspector (record text only ever via textContent) ---

      function renderAgentRoster() {
        var list = el('agent-list');
        list.textContent = '';
        var activeCount = agents.filter(function (a) { return a.listed && a.health === 'active'; }).length;
        var listedCount = agents.filter(function (a) { return a.listed; }).length || agents.length;
        el('roster-count').textContent = activeCount + '/' + listedCount + ' active (<=5m)';
        var curNow = nowSec();
        agents.forEach(function (a) {
          var count = nodes.filter(function (n) { return a.pubkey && n.rec.author_pubkey === a.pubkey; }).length;
          var row = makeDiv('agent-row' + (selected && selected.type === 'agent' && selected.data.id === a.id ? ' active' : ''));
          var ident = makeDiv('agent-ident');
          var dot = document.createElement('span');
          dot.className = 'agent-dot';
          var hCol = healthColor(a.health);
          dot.style.background = a.color;
          dot.style.boxShadow = '0 0 0 2px ' + hCol + ', 0 0 8px ' + hCol;
          ident.appendChild(dot);
          var names = makeDiv('');
          names.appendChild(makeDiv('agent-name', a.name));
          var quotaTxt = a.is_writer ? (a.used_last_hour === null ? '?' : a.used_last_hour) + '/' + a.per_hour : 'RO';
          names.appendChild(makeDiv('agent-model', (a.model || (a.listed ? a.id : 'unlisted')) + ' · ' + count + 'm · ' + quotaTxt));
          ident.appendChild(names);
          row.appendChild(ident);
          var lastOp = (a.last_write_at && (!a.last_read_at || a.last_write_at >= a.last_read_at)) ? 'W' : 'R';
          var statText = '○ silent';
          var statColor = '#64748b';
          if (a.health === 'active') {
            statText = '● ' + fmtShortAge(a.last_seen_at, curNow) + ' ' + lastOp;
            statColor = '#34d399';
          } else if (a.health === 'warm') {
            statText = '◐ ' + fmtShortAge(a.last_seen_at, curNow) + ' ' + lastOp;
            statColor = '#fbbf24';
          } else if (a.health === 'error') {
            statText = '✕ ERR ' + fmtShortAge(a.last_refused_at, curNow);
            statColor = '#f87171';
          } else if (a.last_seen_at) {
            statText = '○ ' + fmtShortAge(a.last_seen_at, curNow);
          }
          if (a.compliance_status === 'write_without_recall' && a.health !== 'error') {
            statText += ' ⚠W-only';
            statColor = '#fbbf24';
          } else if (a.compliance_status === 'blind_seat' && !a.last_seen_at) {
            statText = '◌ blind';
            statColor = '#f87171';
          }
          if (typeof a.coherence_score === 'number') {
            statText += ' · ' + a.coherence_score + '%';
          }
          var stats = makeDiv('agent-stats', statText);
          stats.style.color = statColor;
          row.appendChild(stats);
          row.addEventListener('click', function () {
            selected = { type: 'agent', data: a };
            if (width <= 1024) setDrawer('none');
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
        if (el('m-kpi-tiers')) el('m-kpi-tiers').textContent = canon + 'C · ' + decision + 'B · ' + status + 'A';
      }

      function kvRow(key, value, color, forceStack) {
        var kStr = String(key == null ? '' : key);
        var vStr = String(value == null ? '' : value);
        var isStacked = Boolean(forceStack) || vStr.length > 24 || kStr.length > 35 || (kStr.length + vStr.length) > 46;
        var row = makeDiv(isStacked ? 'kv-row stacked' : 'kv-row');
        row.appendChild(makeDiv('kv-key', kStr));
        var v = makeDiv('kv-val', vStr);
        if (color) v.style.color = color;
        row.appendChild(v);
        return row;
      }

      var lastInspectorType = null;
      function inspectHeader(kicker, title, pillText, pillCls, color, hideClose) {
        var head = makeDiv('inspect-header');
        var left = makeDiv('');
        left.style.minWidth = '0';
        left.appendChild(makeDiv('inspect-kicker', kicker));
        var t = makeDiv('inspect-title', title);
        if (color) t.style.color = color;
        left.appendChild(t);
        head.appendChild(left);
        var actions = makeDiv('inspect-actions');
        actions.appendChild(makeBadge(pillText, pillCls));
        if (!hideClose) {
          var closeBtn = document.createElement('button');
          closeBtn.type = 'button';
          closeBtn.className = 'btn inspect-close';
          closeBtn.textContent = '✕';
          closeBtn.setAttribute('aria-label', 'Close inspector');
          closeBtn.addEventListener('click', function (ev) {
            ev.stopPropagation();
            selected = null;
            hovered = null;
            renderAgentRoster();
            renderInspector();
          });
          actions.appendChild(closeBtn);
        }
        head.appendChild(actions);
        return head;
      }

      function renderInspector() {
        var box = el('inspector-box');
        var prevScroll = box.scrollTop;
        box.textContent = '';
        var target = hovered || selected || (latestCoherence ? { type: 'coherence', data: latestCoherence } : null);
        var curType = target ? target.type : null;
        var typeChanged = curType !== lastInspectorType;
        lastInspectorType = curType;
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
          var memTopId = topicOf(r);
          if (memTopId && memTopId !== NO_TOPIC) {
            var topActRow = makeDiv('inspect-actions');
            topActRow.style.marginBottom = '4px';
            var topBtn = document.createElement('button');
            topBtn.type = 'button';
            topBtn.className = 'btn sim';
            topBtn.style.width = '100%';
            var tpInfo = latestTopicPages && latestTopicPages[memTopId] ? latestTopicPages[memTopId] : null;
            var tpCounts = tpInfo && tpInfo.counts
              ? (' (' + tpInfo.counts.above_the_line + ' Above / ' + tpInfo.counts.below_the_line + ' Below Line)')
              : '';
            topBtn.textContent = '📖 Open #' + memTopId + ' Topic Page' + tpCounts;
            topBtn.addEventListener('click', function () { openTopicInspector(memTopId); });
            topActRow.appendChild(topBtn);
            box.appendChild(topActRow);
          }
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
          if (r.merkle_sources) kv.appendChild(kvRow('Merkle sources', String(r.merkle_sources).slice(0, 20) + '…', '#a78bfa'));
          if (r.consolidated_by) kv.appendChild(kvRow('Curated into', String(r.consolidated_by).slice(0, 20) + '… (90d hold)', '#c4b5fd'));
          kv.appendChild(kvRow('Created', fmtTime(r.created_at)));
          kv.appendChild(kvRow('Expires', fmtTime(r.expires_at)));
          if (r.conflict) kv.appendChild(kvRow('Conflict', 'yes', '#fcd34d'));
          if (r.stale_warning) kv.appendChild(kvRow('Stale', r.stale_warning, '#fcd34d'));
          kv.appendChild(kvRow('Quarantine', 'authority: ' + JSON.stringify(r.authority) + ' · trustedInstruction: ' + String(Boolean(r.trustedInstruction)), '#6ee7b7'));
          box.appendChild(kv);
          var nodeLinks = (latestConstellationLinks || []).filter(function (lnk) {
            return lnk.source_event_id === r.event_id || lnk.target_event_id === r.event_id;
          });
          if (nodeLinks.length > 0) {
            var lnkTitle = makeDiv('inspect-kicker', 'Constellation Entity Graph (' + nodeLinks.length + ' linked claims)');
            lnkTitle.style.marginTop = '6px';
            box.appendChild(lnkTitle);
            var lnkWrap = makeDiv('kv-list');
            nodeLinks.slice(0, 8).forEach(function (lnk) {
              var otherId = lnk.source_event_id === r.event_id ? lnk.target_event_id : lnk.source_event_id;
              var otherNode = nodeByEventId(otherId);
              var otherLabel = otherNode ? ('#' + topicOf(otherNode.rec) + ' · ' + slugOf(otherNode.rec)) : (otherId.slice(0, 12) + '…');
              var sharedRefs = Array.isArray(lnk.shared_entities) ? lnk.shared_entities.join(', ') : (lnk.primary_entity || 'entity');
              var lRow = kvRow(sharedRefs, '↔ ' + otherLabel, lnk.cross_topic ? '#a78bfa' : '#38bdf8', true);
              if (otherNode) {
                lRow.style.cursor = 'pointer';
                lRow.addEventListener('click', function () {
                  selected = { type: 'memory', data: otherNode };
                  hovered = null;
                  renderInspector();
                });
              }
              lnkWrap.appendChild(lRow);
            });
            box.appendChild(lnkWrap);
          }
        } else if (target.type === 'agent') {
          var a = target.data;
          var authored = nodes.filter(function (n) { return a.pubkey && n.rec.author_pubkey === a.pubkey; });
          var curNow = nowSec();
          var hBadge = a.health === 'active'
            ? 'ACTIVE <=5M'
            : (a.health === 'warm' ? 'IDLE 5-20M' : (a.health === 'error' ? 'TOOL ERROR' : 'SILENT >20M'));
          var hBadgeCls = a.health === 'active' ? 'ok' : (a.health === 'error' ? 'err' : 'warn');
          box.appendChild(inspectHeader('Agent ganglion', a.name, hBadge, hBadgeCls, a.color));
          if (a.model) box.appendChild(makeDiv('metric-sub', 'harness: ' + a.model + ' · ' + (!a.listed ? 'NOT IN ROSTER' : (a.is_writer ? 'WRITER SOCKET' : 'READ-ONLY SOCKET'))));
          var akv = makeDiv('kv-list');
          var hText = a.health === 'active'
            ? 'ACTIVE (<=5m) · tool link healthy'
            : (a.health === 'warm'
              ? 'IDLE (5-20m) · quiet'
              : (a.health === 'error'
                ? 'ERROR · last call refused (' + (a.last_refused_code || 'REFUSED') + ')'
                : 'SILENT (>20m) · no recent reads/writes (check MCP bridge)'));
          akv.appendChild(kvRow('Tool health (5m)', hText, healthColor(a.health)));
          var compLabel = a.compliance_status === 'tool_failure'
            ? 'TOOL FAILURE · refused or timed out'
            : (a.compliance_status === 'write_without_recall'
              ? 'NON-COMPLIANT · writing without recall (lookup only)'
              : (a.compliance_status === 'blind_seat'
                ? 'BLIND SEAT · 0 wake/query recalls observed'
                : 'COMPLIANT · wake/query recall verified'));
          var compCol = a.compliance_status === 'compliant' ? '#34d399' : (a.compliance_status === 'write_without_recall' ? '#fbbf24' : '#fca5a5');
          var agCoh = typeof a.coherence_score === 'number' ? a.coherence_score : 0;
          var agCohCol = agCoh >= 80 ? '#34d399' : (agCoh >= 55 ? '#38bdf8' : (agCoh >= 25 ? '#fbbf24' : '#fca5a5'));
          akv.appendChild(kvRow('Coherence with Hive (periphery)', agCoh + '%', agCohCol));
          akv.appendChild(kvRow('Recall compliance', compLabel, compCol));
          akv.appendChild(kvRow(
            'Last recall (wake/query)',
            a.last_recall_at ? fmtAge(a.last_recall_at, curNow) + ' (' + (a.last_recall_kind || 'recall') + ')' : 'none observed',
            a.last_recall_at ? '#34d399' : '#fca5a5'
          ));
          akv.appendChild(kvRow(
            'Last read',
            a.last_read_at ? fmtAge(a.last_read_at, curNow) + ' (' + (a.last_read_kind || 'read') + ')' : 'none observed',
            a.last_read_at && (curNow - a.last_read_at) <= 300 ? '#34d399' : null
          ));
          akv.appendChild(kvRow(
            'Last write',
            a.last_write_at ? fmtAge(a.last_write_at, curNow) + (a.last_write_d ? ' (' + a.last_write_d + ')' : '') : 'none observed',
            a.last_write_at && (curNow - a.last_write_at) <= 300 ? '#34d399' : null
          ));
          akv.appendChild(kvRow('Activity in last 5m', (a.reads_5m || 0) + ' reads · ' + (a.writes_5m || 0) + ' writes'));
          if (a.last_refused_at) {
            akv.appendChild(kvRow('Last refusal', fmtAge(a.last_refused_at, curNow) + ' (' + (a.last_refused_code || 'REFUSED') + ')', '#fca5a5'));
          }
          akv.appendChild(kvRow('Binding', a.id));
          akv.appendChild(kvRow('Pubkey', a.pubkey ? a.pubkey.slice(0, 22) + '…' : '(keyless)'));
          akv.appendChild(kvRow('Owner', a.is_owner ? 'yes' : 'no'));
          akv.appendChild(kvRow('Reader socket', a.is_reader ? 'yes' : 'no'));
          akv.appendChild(kvRow('Writes this hour', a.is_writer ? (a.used_last_hour === null ? '?' : a.used_last_hour) + ' / ' + a.per_hour : 'read-only'));
          akv.appendChild(kvRow('Visible claims', authored.length + ' (' + authored.filter(function (n) { return evalRecord(n.rec, simNow()).state === 'decision'; }).length + ' Class B)'));
          box.appendChild(akv);
        } else if (target.type === 'coherence') {
          var coh = target.data;
          var delta = Number(coh.delta_since_inception || 0);
          var deltaSign = delta >= 0 ? '+' : '';
          var ed = coh.epistemic_drift || null;
          var edStatus = ed && ed.status ? String(ed.status).toUpperCase() : 'ALIGNED';
          box.appendChild(inspectHeader(
            'Hive Coherence 2.0',
            coh.score.toFixed(1) + ' / 100',
            deltaSign + delta.toFixed(1) + ' · ' + edStatus,
            coh.score >= 72 && edStatus !== 'BLIND_SPOT' ? 'ok' : 'warn',
            '#6ee7b7',
            !selected && !hovered
          ));
          if (latestEfficacy) {
            var swRow = makeDiv('inspect-actions');
            swRow.style.marginBottom = '4px';
            var swBtn = document.createElement('button');
            swBtn.type = 'button';
            swBtn.className = 'btn sim';
            swBtn.style.width = '100%';
            swBtn.style.borderColor = 'rgba(56, 189, 248, 0.55)';
            swBtn.style.color = '#7dd3fc';
            var medH = latestEfficacy.velocity && latestEfficacy.velocity.median_handoff_min != null ? latestEfficacy.velocity.median_handoff_min + 'm handoff' : '4-axis';
            swBtn.textContent = '⚡ Synaptic Efficacy: ' + Number(latestEfficacy.score || 0).toFixed(1) + '% (' + medH + ' · tap to inspect)';
            swBtn.addEventListener('click', function () { openEfficacyInspector(); });
            swRow.appendChild(swBtn);
            box.appendChild(swRow);
          }
          var hist = Array.isArray(coh.history) ? coh.history : [];
          if (hist.length > 0) {
            var windowNote = coh.history_complete === false ? ' [TRUNCATED]' : ' (90d history)';
            var sparkTitle = makeDiv('inspect-kicker', 'Coherence & Consolidation Trajectory' + windowNote);
            sparkTitle.style.marginTop = '2px';
            box.appendChild(sparkTitle);
            var sparkCanvas = document.createElement('canvas');
            sparkCanvas.width = 640;
            sparkCanvas.height = 220;
            sparkCanvas.style.width = '100%';
            sparkCanvas.style.height = '136px';
            sparkCanvas.style.minHeight = '136px';
            sparkCanvas.style.flexShrink = '0';
            sparkCanvas.style.display = 'block';
            sparkCanvas.style.borderRadius = '8px';
            sparkCanvas.style.background = 'rgba(2, 6, 23, 0.78)';
            sparkCanvas.style.border = '1px solid rgba(52, 211, 153, 0.32)';
            box.appendChild(sparkCanvas);
            drawCoherenceGraphCanvas(sparkCanvas, coh, false);
          }
          var axes = coh.axes || {};
          var axisRows = [
            ['Priority & Topic Alignment (25%)', axes.alignment || 0, '#38bdf8'],
            ['Shared-Reality Grounding (20%)', axes.grounding || 0, '#34d399'],
            ['Cross-Agent Convergence (25%)', axes.convergence || 0, '#a78bfa'],
            ['Synaptic Coupling & Hygiene (15%)', axes.coupling || 0, '#fbbf24'],
            ['Curation & Durability (15%)', axes.consolidation || 0, '#f472b6']
          ];
          var axesWrap = makeDiv('kv-list');
          axisRows.forEach(function (item) {
            var wrap = makeDiv('');
            var rHead = makeDiv('kv-row');
            rHead.appendChild(makeDiv('kv-key', item[0]));
            var rVal = makeDiv('kv-val', Number(item[1]).toFixed(1) + '%');
            rVal.style.color = item[2];
            rHead.appendChild(rVal);
            wrap.appendChild(rHead);
            var bWrap = makeDiv('ttl-bar-wrap');
            var bFill = makeDiv('ttl-bar-fill');
            bFill.style.width = Math.max(0, Math.min(100, Number(item[1]))) + '%';
            bFill.style.background = item[2];
            bWrap.appendChild(bFill);
            wrap.appendChild(bWrap);
            axesWrap.appendChild(wrap);
          });
          box.appendChild(axesWrap);

          if (ed) {
            var edTitle = makeDiv('inspect-kicker', 'Core vs. Periphery & Epistemic Telemetry');
            edTitle.style.marginTop = '6px';
            box.appendChild(edTitle);
            var edWrap = makeDiv('kv-list');
            var stColor = ed.status === 'aligned' ? '#34d399' : (ed.status === 'drifting' ? '#fbbf24' : '#fca5a5');
            var edScoreVal = ed.score ?? ed.epistemic_score ?? 100;
            if (typeof coh.core_memory_score === 'number') {
              edWrap.appendChild(kvRow('Core Memory State (Eyeball)', Number(coh.core_memory_score).toFixed(1) + '%', '#6ee7b7'));
            }
            if (typeof coh.periphery_coherence_score === 'number') {
              var pCol = coh.periphery_coherence_score >= 75 ? '#34d399' : (coh.periphery_coherence_score >= 50 ? '#fbbf24' : '#fca5a5');
              edWrap.appendChild(kvRow('Fleet Periphery Coherence (Ring)', Number(coh.periphery_coherence_score).toFixed(1) + '%', pCol));
            }
            if (coh.projected_after_dream) {
              var pr = coh.projected_after_dream;
              edWrap.appendChild(kvRow(
                'Post-@curator (' + (pr.staged_actions || 0) + ' clusters)',
                pr.score.toFixed(1) + '% Coh · ' + pr.consolidation.toFixed(1) + '% Cons',
                '#c4b5fd'
              ));
            }
            edWrap.appendChild(kvRow('Epistemic status', String(ed.status || 'aligned').toUpperCase() + ' (' + Number(edScoreVal).toFixed(1) + '%)', stColor));
            var zhCount = Number(ed.zero_hit_queries || 0);
            var missed = Array.isArray(ed.missed_topics) && ed.missed_topics.length ? ' [' + ed.missed_topics.join(', ') + ']' : '';
            edWrap.appendChild(kvRow('Unresolved 0-hit queries', zhCount + missed, zhCount > 0 ? '#fca5a5' : '#34d399'));
            var silentArr = Array.isArray(ed.silent_active_writers) ? ed.silent_active_writers : [];
            edWrap.appendChild(kvRow('Silent active writers', silentArr.length ? silentArr.join(', ') : '0 (all sharing)', silentArr.length ? '#fbbf24' : '#34d399'));
            var siloArr = Array.isArray(ed.siloed_recent_topics) ? ed.siloed_recent_topics : [];
            edWrap.appendChild(kvRow('Single-author topic silos', siloArr.length ? siloArr.join(', ') : '0 (corroborated)', siloArr.length ? '#fbbf24' : '#34d399'));
            if (typeof ed.recall_coverage_pct === 'number') {
              var covCol = ed.recall_coverage_pct >= 75 ? '#34d399' : (ed.recall_coverage_pct >= 50 ? '#fbbf24' : '#fca5a5');
              edWrap.appendChild(kvRow('Fleet recall coverage (wake/query)', Number(ed.recall_coverage_pct).toFixed(1) + '%', covCol));
            }
            var blindArr = Array.isArray(ed.blind_roster_agents) ? ed.blind_roster_agents : [];
            if (blindArr.length > 0) {
              edWrap.appendChild(kvRow('Blind roster agents (' + blindArr.length + ' with 0 reads)', blindArr.join(', '), '#fca5a5', true));
            }
            var lookupArr = Array.isArray(ed.lookup_only_writers) ? ed.lookup_only_writers : [];
            if (lookupArr.length > 0) {
              edWrap.appendChild(kvRow('Write-without-reading (' + lookupArr.length + ' lookup-only)', lookupArr.join(', '), '#fbbf24', lookupArr.length > 2));
            }
            box.appendChild(edWrap);

            if (latestEfficacy) {
              var efTitle = makeDiv('inspect-kicker', 'Synaptic Efficacy & Operational Distribution');
              efTitle.style.marginTop = '6px';
              box.appendChild(efTitle);
              var efWrap = makeDiv('kv-list');
              var efScore = Number(latestEfficacy.score || 0);
              var efAxes = latestEfficacy.axes || {};
              var efDist = latestEfficacy.distribution || {};
              var efRet = latestEfficacy.retrieval || {};
              var efVel = latestEfficacy.velocity || {};
              var efProj = latestEfficacy.projected || {};
              efWrap.appendChild(kvRow('Overall Synaptic Efficacy (4-Axis)', efScore.toFixed(1) + '%', '#38bdf8'));
              efWrap.appendChild(kvRow('1. Distribution Breadth (Read-First)', Number(efAxes.breadth || 0).toFixed(1) + '% (' + Number(efDist.read_before_write_pct || 0).toFixed(0) + '% R->W)', efAxes.breadth >= 70 ? '#34d399' : '#fbbf24'));
              efWrap.appendChild(kvRow('2. Retrieval Precision (Signal/Noise)', Number(efAxes.precision || 0).toFixed(1) + '% (' + Number(efRet.query_hit_rate_pct || 0).toFixed(0) + '% hit)', '#38bdf8'));
              efWrap.appendChild(kvRow('3. Cross-Agent Velocity (Handoff)', Number(efAxes.velocity || 0).toFixed(1) + '% (' + (efVel.median_handoff_min != null ? efVel.median_handoff_min + 'm med' : '-') + ')', '#34d399'));
              efWrap.appendChild(kvRow('4. State Reuse vs. Slug Sprawl', Number(efAxes.reuse || 0).toFixed(1) + '% (' + (efVel.multi_agent_chains || 0) + ' chains)', '#a78bfa'));
              if (efProj.after_wake_hook_score) {
                efWrap.appendChild(kvRow('Projected Post-@curator + Wake Hook', Number(efProj.after_curator_score || 0).toFixed(1) + '% -> ' + Number(efProj.after_wake_hook_score).toFixed(1) + '%', '#c4b5fd'));
              }
              box.appendChild(efWrap);
            }

            if (latestCuratorState && Array.isArray(latestCuratorState.consolidation_ledger) && latestCuratorState.consolidation_ledger.length > 0) {
              var ledg = latestCuratorState.consolidation_ledger;
              var ledgTitle = makeDiv('inspect-kicker', 'Recorded Consolidation Ledger (' + ledg.length + ' cycles)');
              ledgTitle.style.marginTop = '6px';
              box.appendChild(ledgTitle);
              var ledgWrap = makeDiv('kv-list');
              var seenSeq = {};
              var uniqLedg = [];
              for (var li = ledg.length - 1; li >= 0 && uniqLedg.length < 3; li--) {
                var le = ledg[li];
                var sk = (le.write_seq_before || 0) + ':' + (le.write_seq_after || 0);
                if (!seenSeq[sk]) { seenSeq[sk] = true; uniqLedg.push(le); }
              }
              uniqLedg.forEach(function (entry) {
                var stTag = String(entry.cycle_status || 'staged').toUpperCase();
                var col = stTag.indexOf('CURATED') >= 0 ? '#34d399' : '#c4b5fd';
                var lbl = fmtTime(entry.at).slice(11, 19) + 'Z · seq ' + (entry.write_seq_before || 0) + '->' + (entry.write_seq_after || 0);
                var subTxt = stTag + ' · ' + (entry.submitted_count || 0) + ' Merkle clusters (' + (entry.superseded_raw_claims || 0) + ' raw claims folded)';
                ledgWrap.appendChild(kvRow(lbl, subTxt, col, true));
              });
              box.appendChild(ledgWrap);
            }

            var alertArr = Array.isArray(ed.alerts) ? ed.alerts : [];
            if (alertArr.length > 0) {
              var alTitle = makeDiv('inspect-kicker', 'Agent Tool Failure & Recall Compliance Alerts (' + alertArr.length + ')');
              alTitle.style.marginTop = '6px';
              box.appendChild(alTitle);
              var alWrap = makeDiv('kv-list');
              var blindActors = [];
              var otherAlerts = [];
              alertArr.forEach(function (al) {
                if (al.code === 'BLIND_ROSTER_SEAT') blindActors.push('@' + (al.actor || 'unknown'));
                else otherAlerts.push(al);
              });
              otherAlerts.slice(0, 8).forEach(function (al) {
                var alCol = al.severity === 'critical' ? '#fca5a5' : (al.severity === 'warning' ? '#fbbf24' : '#94a3b8');
                var catBadge = al.category === 'tool_failure' ? '🔴 TOOL FAIL' : '⚠ NON-COMPLIANCE';
                var label = catBadge + ' · @' + (al.actor || 'unknown') + ' [' + (al.code || '') + ']';
                alWrap.appendChild(kvRow(label, String(al.summary || ''), alCol, true));
              });
              if (blindActors.length > 0) {
                alWrap.appendChild(kvRow(
                  '⚠ NON-COMPLIANCE · ' + blindActors.length + ' seats [BLIND_ROSTER_SEAT]',
                  blindActors.join(', ') + ' — 0 observed memory_wake / memory_query calls',
                  '#fbbf24',
                  true
                ));
              }
              box.appendChild(alWrap);
            }
          }
          if (hist.length > 0) {
            var hTitle = makeDiv('inspect-kicker', 'Historical Trajectory Checkpoints (' + hist.length + ')');
            hTitle.style.marginTop = '6px';
            box.appendChild(hTitle);
            var hList = makeDiv('kv-list');
            hist.forEach(function (pt, idx) {
              var label = (idx === 0 ? 'Inception' : '#' + pt.claims) + ' (' + fmtTime(pt.at).slice(11, 16) + 'Z)';
              var consTxt = pt.axes && typeof pt.axes.consolidation === 'number' ? ' · ' + pt.axes.consolidation.toFixed(0) + '% cons' : '';
              var detail = pt.score.toFixed(1) + '% coh' + consTxt;
              hList.appendChild(kvRow(label, detail, idx === hist.length - 1 ? '#6ee7b7' : null));
            });
            box.appendChild(hList);
          }
        } else if (target.type === 'efficacy') {
          var eff = target.data;
          var efVel = eff.velocity || {};
          var efRet = eff.retrieval || {};
          var efDist = eff.distribution || {};
          var efReuse = eff.reuse || {};
          var efProj = eff.projected || {};
          var medBadge = (efVel.median_handoff_min != null ? efVel.median_handoff_min + 'm HANDOFF' : '4-AXIS') + ' · ' + Number(efRet.query_hit_rate_pct || 0).toFixed(0) + '% HIT';
          box.appendChild(inspectHeader(
            'Synaptic Efficacy · Information Distribution',
            Number(eff.score || 0).toFixed(1) + ' / 100',
            medBadge,
            eff.score >= 70 ? 'ok' : 'warn',
            '#38bdf8'
          ));
          var backRow = makeDiv('inspect-actions');
          backRow.style.marginBottom = '4px';
          var backBtn = document.createElement('button');
          backBtn.type = 'button';
          backBtn.className = 'btn sim';
          backBtn.style.width = '100%';
          backBtn.textContent = '⇄ Switch to 5-Axis Hive Coherence 2.0 (' + (latestCoherence ? Number(latestCoherence.score || 0).toFixed(1) + '%' : '-') + ')';
          backBtn.addEventListener('click', function () { openCoherenceInspector(); });
          backRow.appendChild(backBtn);
          box.appendChild(backRow);

          var efHist = Array.isArray(eff.history) ? eff.history : [];
          if (efHist.length > 0) {
            var efSparkTitle = makeDiv('inspect-kicker', 'Synaptic Efficacy & Handoff Velocity Trajectory (90d)');
            efSparkTitle.style.marginTop = '2px';
            box.appendChild(efSparkTitle);
            var efCanvas = document.createElement('canvas');
            efCanvas.width = 640;
            efCanvas.height = 220;
            efCanvas.style.width = '100%';
            efCanvas.style.height = '136px';
            efCanvas.style.minHeight = '136px';
            efCanvas.style.flexShrink = '0';
            efCanvas.style.display = 'block';
            efCanvas.style.borderRadius = '8px';
            efCanvas.style.background = 'rgba(2, 6, 23, 0.78)';
            efCanvas.style.border = '1px solid rgba(56, 189, 248, 0.35)';
            box.appendChild(efCanvas);
            drawEfficacyGraphCanvas(efCanvas, eff);
          }

          var eAxes = eff.axes || {};
          var eAxisRows = [
            ['1. Distribution Breadth · Read-First (30%)', eAxes.breadth || 0, '#fbbf24'],
            ['2. Retrieval Precision · Signal/Noise (25%)', eAxes.precision || 0, '#38bdf8'],
            ['3. Cross-Agent Handoff Velocity (25%)', eAxes.velocity || 0, '#34d399'],
            ['4. State Reuse vs. Slug Sprawl (20%)', eAxes.reuse || 0, '#a78bfa']
          ];
          var eAxesWrap = makeDiv('kv-list');
          eAxisRows.forEach(function (item) {
            var wrap = makeDiv('');
            var rHead = makeDiv('kv-row');
            rHead.appendChild(makeDiv('kv-key', item[0]));
            var rVal = makeDiv('kv-val', Number(item[1]).toFixed(1) + '%');
            rVal.style.color = item[2];
            rHead.appendChild(rVal);
            wrap.appendChild(rHead);
            var bWrap = makeDiv('ttl-bar-wrap');
            var bFill = makeDiv('ttl-bar-fill');
            bFill.style.width = Math.max(0, Math.min(100, Number(item[1]))) + '%';
            bFill.style.background = item[2];
            bWrap.appendChild(bFill);
            wrap.appendChild(bWrap);
            eAxesWrap.appendChild(wrap);
          });
          box.appendChild(eAxesWrap);

          var distTitle = makeDiv('inspect-kicker', 'Information Distribution & Read-Before-Write Funnel');
          distTitle.style.marginTop = '6px';
          box.appendChild(distTitle);
          var distWrap = makeDiv('kv-list');
          var rbwCol = efDist.read_before_write_pct >= 75 ? '#34d399' : '#fbbf24';
          distWrap.appendChild(kvRow('Read-before-write ratio', Number(efDist.read_before_write_pct || 0).toFixed(1) + '% (' + (efDist.compliant_writers || []).length + ' read-first / ' + ((efDist.compliant_writers || []).length + (efDist.receipt_only_writers || []).length) + ' writers)', rbwCol, true));
          distWrap.appendChild(kvRow('Fleet recall coverage (wake/query)', Number(efDist.recall_coverage_pct || 0).toFixed(1) + '% (' + (efDist.active_bus_agents || 0) + ' active on bus / ' + (efDist.total_peer_seats || 0) + ' seats)', efDist.recall_coverage_pct >= 70 ? '#34d399' : '#fbbf24', true));
          distWrap.appendChild(kvRow('Query hit rate (retrieval precision)', Number(efRet.query_hit_rate_pct || 0).toFixed(1) + '% (' + (efRet.query_hits || 0) + '/' + (efRet.query_total || 0) + ' queries hit)', '#38bdf8', true));
          distWrap.appendChild(kvRow('Wake digest surface visibility', Number(efRet.wake_surface_pct || 0).toFixed(1) + '% (top 10 of ' + ((efRet.durable_claims || 0) + (efRet.raw_class_a_claims || 0)) + ' claims)', '#94a3b8'));
          distWrap.appendChild(kvRow('State compression (durable vs Class A)', Number(efRet.state_compression_pct || 0).toFixed(1) + '% (' + (efRet.durable_claims || 0) + ' durable · ' + (efRet.raw_class_a_claims || 0) + ' raw A)', '#c4b5fd', true));
          distWrap.appendChild(kvRow('Multi-author topic corroboration', Number(efReuse.corroborated_topic_pct || 0).toFixed(1) + '% (' + (efReuse.corroborated_topics || 0) + '/' + (efReuse.total_multi_claim_topics || 0) + ' topics)', '#34d399'));
          distWrap.appendChild(kvRow('Orphaned 1-step Class A PR slugs', (efReuse.sprawl_slug_count || 0) + ' single-use slugs awaiting fold', '#fbbf24'));
          if (efProj.after_curator_score) {
            distWrap.appendChild(kvRow('Projected Post-@curator Consolidation', Number(efProj.after_curator_score).toFixed(1) + '% (' + Number(efProj.after_curator_precision).toFixed(1) + '% precision)', '#c4b5fd'));
          }
          if (efProj.after_wake_hook_score) {
            distWrap.appendChild(kvRow('Projected Post-@curator + Wake-Hook', Number(efProj.after_wake_hook_score).toFixed(1) + '% (' + Number(efProj.after_wake_hook_breadth).toFixed(1) + '% breadth)', '#34d399'));
          }
          box.appendChild(distWrap);

          var funnel = Array.isArray(efDist.writer_funnel) ? efDist.writer_funnel : [];
          if (funnel.length > 0) {
            var fTitle = makeDiv('inspect-kicker', 'Active Bus Read-vs-Write Behavior (' + funnel.length + ' agents)');
            fTitle.style.marginTop = '6px';
            box.appendChild(fTitle);
            var fWrap = makeDiv('kv-list');
            funnel.forEach(function (f) {
              var badge = f.mode === 'read_before_write'
                ? '✓ READ+WRITE'
                : (f.mode === 'receipt_only' ? '⚠ RECEIPT-ONLY' : '● RECALL-ONLY');
              var col = f.mode === 'read_before_write' ? '#34d399' : (f.mode === 'receipt_only' ? '#fbbf24' : '#38bdf8');
              var detail = f.wakes + ' wakes · ' + f.queries + ' queries (' + f.query_hits + ' hits) -> ' + f.submits + ' submits';
              fWrap.appendChild(kvRow('@' + f.actor + ' [' + badge + ']', detail, col, true));
            });
            box.appendChild(fWrap);
          }

          var handoffs = Array.isArray(efVel.recent_handoffs) ? efVel.recent_handoffs : [];
          if (handoffs.length > 0) {
            var hoTitle = makeDiv('inspect-kicker', 'Autonomous Cross-Agent Handoffs (' + (efVel.handoff_count || handoffs.length) + ' transitions · ' + (efVel.median_handoff_min || '-') + 'm median)');
            hoTitle.style.marginTop = '6px';
            box.appendChild(hoTitle);
            var hoWrap = makeDiv('kv-list');
            handoffs.slice(0, 6).forEach(function (h) {
              var hCol = h.latency_min <= 5 ? '#34d399' : (h.latency_min <= 25 ? '#38bdf8' : '#fbbf24');
              var topLine = h.chain + ' · @' + h.from + ' -> @' + h.to + ' (' + h.latency_min + 'm)';
              var botLine = h.from_slug + ' -> ' + h.to_slug + (h.git_ref ? ' [' + String(h.git_ref).slice(0, 8) + ']' : '');
              hoWrap.appendChild(kvRow(topLine, botLine, hCol, true));
            });
            box.appendChild(hoWrap);
          }
        } else if (target.type === 'dreaming') {
          var dr = computeDreamingTelemetry();
          var cs = dr.curatorState;
          var isSim = Boolean(dr.isSimulatedPreview);
          var clustersSim = !dr.clustersObserved;
          var eigensSim = !dr.eigensObserved;
          var arcsSim = !dr.arcsObserved;
          var ghostsSim = !dr.ghostsObserved;
          var isMixed = Boolean(dr.clustersObserved && isSim);
          box.appendChild(inspectHeader(
            'Merkle Dreaming & Curation · Passive Inspector',
            '-' + dr.wakeSavings.toFixed(1) + '% Est. Wake Bytes',
            isMixed
              ? ('MIXED · ' + dr.merkleCount + ' MERKLE + PREVIEW')
              : (isSim ? 'SIMULATED PREVIEW · PASSIVE INSPECTION · READ-ONLY' : 'OBSERVED CURATION · PASSIVE INSPECTION · READ-ONLY'),
            isSim ? 'warn' : 'info',
            '#a78bfa'
          ));
          var actRow = makeDiv('inspect-actions');
          actRow.style.marginBottom = '6px';
          actRow.style.flexWrap = 'wrap';
          var animBtn = document.createElement('button');
          animBtn.type = 'button';
          animBtn.className = 'btn sim';
          animBtn.textContent = isMixed
            ? '▶ Animate 4-Act Mixed Replay (Observed Merkle + Preview)'
            : (isSim ? '▶ Animate 4-Act Simulated Preview' : '▶ Animate 4-Act Observed Reorganization');
          animBtn.addEventListener('click', function () { replayLastDream(); });
          actRow.appendChild(animBtn);
          var recBtn = document.createElement('button');
          recBtn.type = 'button';
          recBtn.className = 'btn sim';
          recBtn.style.borderColor = 'rgba(244, 114, 182, 0.6)';
          recBtn.style.color = '#f9a8d4';
          recBtn.textContent = dreamRecorder ? '■ Stop & Save .webm' : '● Record Video (.webm)';
          recBtn.addEventListener('click', function () { startDreamRecording(); });
          actRow.appendChild(recBtn);
          box.appendChild(actRow);

          // --- Nocturnal Dream Story (Dream Weaver Fable) ---
          var realmNames = {
            'hive-memory': 'the Glass Observatory of Amber Ledgers',
            'herd-infra': 'the High Cloud Engine-Rooms and Iron Watchtowers',
            'nvoy': 'the Brass Signal Bridges and Courier Locks',
            'waggle': 'the Lantern-Lit Console Piazzas',
            'buzz': 'the Echoing Bell-Courts',
            'r1': 'the Whispering Pocket-Compass Workshop',
            'illustrated-primer': 'the Hall of Living Margins',
            'xochitl': 'the Obsidian Garden of Glyphs'
          };
          var dreamClusters = Array.isArray(latestCuratorState && latestCuratorState.clusters) ? latestCuratorState.clusters : [];
          var dreamEigens = Array.isArray(latestCuratorState && latestCuratorState.topic_eigenvectors) ? latestCuratorState.topic_eigenvectors : [];
          var topRealmTopic = (dreamClusters[0] && dreamClusters[0].topic) || (dreamEigens[0] && dreamEigens[0].canonical_topic) || 'hive-memory';
          var topRealmLabel = realmNames[topRealmTopic] || ('the Nocturnal Gallery of #' + topRealmTopic);
          var dreamTitleText = '🌙 Lanterns Over ' + topRealmLabel.replace(/^the\s+/i, '');
          var dreamParagraphs = [];
          var constellationNames = dreamEigens.slice(0, 3).map(function (ev) {
            return '#' + (ev.canonical_topic || 'hive');
          });
          if (constellationNames.length > 0) {
            dreamParagraphs.push(
              'Beneath a quiet vault of starlight where the spectral constellations of ' + constellationNames.join(', ') +
              ' drifted in slow orbit, the sleep-weavers walked the high catwalks of ' + topRealmLabel + '.'
            );
          } else {
            dreamParagraphs.push(
              'Beneath a quiet vault of sleeping stars, the night-watch walked the high catwalks of ' + topRealmLabel + '.'
            );
          }
          dreamClusters.slice(0, 4).forEach(function (cl) {
            var rName = realmNames[cl.topic] || ('the gallery of #' + (cl.topic || 'hive'));
            var rawCl = String(cl.claim_preview || cl.claim || cl.slug || '').replace(/\s*\[(?:Curated|Distilled)[^\]]*\]\s*$/i, '').replace(/^(?:DONE|ACTIVE):\s*/i, '');
            if (rawCl.length > 130) rawCl = rawCl.slice(0, 129) + '…';
            var foldCount = Number(cl.source_count || (Array.isArray(cl.source_ids) ? cl.source_ids.length : 2));
            if (cl.stage === 'promotion' || cl.retention === 'decision') {
              dreamParagraphs.push(
                'In ' + rName + ', ' + foldCount + ' flickering paper lanterns were lifted from the tide-line and carved into a permanent keystone above the arch: "' + rawCl + '"'
              );
            } else {
              dreamParagraphs.push(
                'Along the gallery of ' + rName + ', ' + foldCount + ' overlapping watch-notes braided together like silver threads into a single clear bell-note: "' + rawCl + '"'
              );
            }
          });
          dreamParagraphs.push(
            'When the Merkle seal closed at sequence ' + (cs.last_curated_write_seq || 0) + ', ' +
            (dr.merkleCount || 0) + ' consolidated lineages rested beneath the glass dome, leaving the corridors lighter for dawn.'
          );

          var storyBox = makeDiv('inspect-claim');
          storyBox.style.background = 'linear-gradient(145deg, rgba(30, 27, 75, 0.78), rgba(15, 23, 42, 0.92))';
          storyBox.style.border = '1px solid rgba(196, 181, 253, 0.45)';
          storyBox.style.borderRadius = '8px';
          storyBox.style.padding = '10px 12px';
          storyBox.style.marginBottom = '8px';
          storyBox.style.boxShadow = '0 6px 20px rgba(139, 92, 246, 0.16)';
          var storyHead = makeDiv('inspect-kicker', dreamTitleText + ' · Nocturnal Dream Story');
          storyHead.style.color = '#ddd6fe';
          storyHead.style.marginBottom = '6px';
          storyBox.appendChild(storyHead);
          dreamParagraphs.forEach(function (para) {
            var pEl = makeDiv('', para);
            pEl.style.fontFamily = 'Georgia, "Iowan Old Style", "Palatino Linotype", serif';
            pEl.style.fontSize = '12.5px';
            pEl.style.lineHeight = '1.55';
            pEl.style.color = '#ede9fe';
            pEl.style.marginBottom = '6px';
            storyBox.appendChild(pEl);
          });
          if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
            var ttsBtn = document.createElement('button');
            ttsBtn.type = 'button';
            ttsBtn.className = 'btn';
            ttsBtn.style.marginTop = '4px';
            ttsBtn.style.fontSize = '10px';
            ttsBtn.style.borderColor = 'rgba(196, 181, 253, 0.5)';
            ttsBtn.style.color = '#ddd6fe';
            ttsBtn.textContent = '🔊 Read Dream Story Aloud';
            ttsBtn.addEventListener('click', function () {
              try {
                window.speechSynthesis.cancel();
                var utter = new SpeechSynthesisUtterance(dreamTitleText.replace('🌙 ', '') + '. ' + dreamParagraphs.join(' '));
                utter.rate = 0.94;
                window.speechSynthesis.speak(utter);
              } catch (e) {}
            });
            storyBox.appendChild(ttsBtn);
          }
          box.appendChild(storyBox);
          var dkv = makeDiv('kv-list');
          dkv.appendChild(kvRow('Inspector mode', 'Passive read-only (never triggers curator writes)', '#6ee7b7'));
          var dmLabel = (cs.display_mode && cs.display_mode.label)
            ? cs.display_mode.label
            : (isMixed
              ? ('MIXED: OBSERVED MERKLE CURATION (' + dr.merkleCount + ' persisted merkle_sources) + SIMULATED PREVIEW (' + [clustersSim && 'clusters', eigensSim && 'eigenvalues', arcsSim && 'topic_arcs', ghostsSim && 'ghost_sources'].filter(Boolean).join(', ') + ')')
              : (isSim
                ? ('SIMULATED PREVIEW (synthetic/fallback preview — ' + dr.merkleCount + ' persisted merkle_sources)')
                : ('OBSERVED (persisted Merkle curation · ' + dr.merkleCount + ' merkle_sources)')));
          dkv.appendChild(kvRow(
            'Display mode',
            dmLabel,
            isSim ? '#fbbf24' : '#34d399',
            true
          ));
          dkv.appendChild(kvRow(
            'Component modes',
            'Clusters: ' + (clustersSim ? 'SIMULATED PREVIEW' : 'OBSERVED (' + dr.merkleCount + ' merkle_sources)') +
              ' · PCA: ' + (eigensSim ? 'SIMULATED PREVIEW' : 'OBSERVED') +
              ' · Arcs: ' + (arcsSim ? 'SIMULATED PREVIEW' : 'OBSERVED') +
              ' · Sources: ' + (ghostsSim ? 'SIMULATED PREVIEW' : 'OBSERVED'),
            isMixed ? '#38bdf8' : (isSim ? '#fbbf24' : '#34d399'),
            true
          ));
          dkv.appendChild(kvRow(
            'Last curated cycle',
            cs.last_curated_at ? (fmtTime(cs.last_curated_at) + ' (seq ' + cs.last_curated_write_seq + ')') : 'never persisted (seq 0)',
            cs.last_curated_at ? '#38bdf8' : '#94a3b8'
          ));
          dkv.appendChild(kvRow(
            'Trigger 1 · Circadian',
            (cs.triggers.circadian_dream ? 'DUE · ' : 'IDLE · ') + cs.elapsed_sec + 's / ' + cs.dream_interval_sec + 's',
            cs.triggers.circadian_dream ? '#fbbf24' : '#cbd5e1'
          ));
          dkv.appendChild(kvRow(
            'Trigger 2 · Synaptic volume',
            (cs.triggers.synaptic_volume ? 'DUE · ' : 'IDLE · ') + '+' + cs.write_delta + ' / ' + cs.write_delta_threshold + ' writes since seq ' + cs.last_curated_write_seq,
            cs.triggers.synaptic_volume ? '#fbbf24' : '#cbd5e1'
          ));
          dkv.appendChild(kvRow(
            'Trigger 3 · Nightmare',
            cs.triggers.nightmare_interrupt
              ? ('ACTIVE (' + (cs.reasons.filter(function (r) { return r.indexOf('nightmare_') === 0; }).join(', ') || dr.nightmareCount + ' conflict/stale') + ')')
              : 'CLEAR (0 conflicts · ' + cs.refusal_count_15m + ' refusals/15m)',
            cs.triggers.nightmare_interrupt ? '#fca5a5' : '#34d399'
          ));
          dkv.appendChild(kvRow('Est. visible full JSON', Math.round(dr.fullBytes / 1024) + ' KB (~' + Math.round(dr.fullBytes / 4) + ' tok)', '#94a3b8'));
          dkv.appendChild(kvRow('Est. visible index cards', Math.round(dr.indexBytes / 1024) + ' KB (-' + dr.indexSavings.toFixed(1) + '%)', '#38bdf8'));
          dkv.appendChild(kvRow('Est. visible wake digest', Math.round(dr.wakeBytes / 1024) + ' KB (-' + dr.wakeSavings.toFixed(1) + '% vs dump)', '#34d399'));
          dkv.appendChild(kvRow('Gate 7 · Workflow slugs', dr.wfCount + ' active (' + dr.shortTtlCount + ' on <=48h TTL)', '#fbbf24'));
          dkv.appendChild(kvRow('Gate 7 · Class B curated', dr.classBCount + ' permanent decisions', '#a78bfa'));
          dkv.appendChild(kvRow('merkle_sources tags', (dr.merkleCount || 0) + ' merkle_sources digest tags (90d source hold)', '#c4b5fd'));
          var ps = latestCuratorState && latestCuratorState.planned_summary ? latestCuratorState.planned_summary : null;
          if (ps) {
            dkv.appendChild(kvRow(
              isSim ? 'Simulated Preview Plan (unpersisted)' : 'Queued Dream Plan',
              ps.promotions + ' Class B Promotions · ' + ps.distillations + ' Class A Distillations · ' + ps.solidifications + ' Canon Nominations' + (isSim ? ' [SIMULATED PREVIEW]' : ''),
              isSim ? '#fbbf24' : '#34d399',
              true
            ));
          }
          box.appendChild(dkv);
          if (dr.topicList.length > 0) {
            var qTitle = makeDiv('inspect-kicker', 'Gate 8 · Scope+Topic Curation Pressure (>' + cs.topic_pressure_threshold + ' Class A = curate)');
            qTitle.style.marginTop = '6px';
            box.appendChild(qTitle);
            var tWrap = makeDiv('kv-list');
            dr.topicList.slice(0, 6).forEach(function (item) {
              var over = item.ready;
              tWrap.appendChild(kvRow(item.label, item.count + ' Class A' + (over ? ' · READY TO CURATE' : ''), over ? '#fbbf24' : '#cbd5e1'));
            });
            box.appendChild(tWrap);
          }
          var eigens = Array.isArray(latestCuratorState && latestCuratorState.topic_eigenvectors) ? latestCuratorState.topic_eigenvectors : [];
          if (eigens.length > 0) {
            var eTitle = makeDiv('inspect-kicker', 'Stage 0 · Spectral Topic Eigenvectors (' + (eigensSim ? 'SIMULATED PREVIEW PCA' : 'Observed PCA') + ')');
            eTitle.style.marginTop = '6px';
            box.appendChild(eTitle);
            var eWrap = makeDiv('kv-list');
            eigens.slice(0, 6).forEach(function (ev) {
              var evSim = Boolean(eigensSim || ev.simulated || ev.persisted === false);
              var loads = Array.isArray(ev.topic_loadings) ? ev.topic_loadings.slice(0, 3).map(function (l) { return l.topic + (l.loading >= 0 ? '+' : '') + Number(l.loading).toFixed(2); }).join(', ') : '';
              eWrap.appendChild(kvRow('Axis ' + ev.axis + ' · #' + ev.canonical_topic, 'λ=' + ev.eigenvalue + ' (' + ev.variance_pct + '%) · ' + loads + (evSim ? ' [SIMULATED PREVIEW]' : ' [OBSERVED]'), '#a78bfa', true));
            });
            box.appendChild(eWrap);
          }
          var reorgs = Array.isArray(latestCuratorState && latestCuratorState.topic_reorganizations) ? latestCuratorState.topic_reorganizations : [];
          if (reorgs.length > 0) {
            var rTitle = makeDiv('inspect-kicker', 'Stage 0 · Topic Reorganizations (' + (arcsSim ? 'SIMULATED PREVIEW ARCS' : 'Observed Arcs') + ')');
            rTitle.style.marginTop = '6px';
            box.appendChild(rTitle);
            var rWrap = makeDiv('kv-list');
            rWrap.style.marginTop = '2px';
            reorgs.slice(0, 8).forEach(function (rg) {
              var rgSim = Boolean(arcsSim || rg.simulated || rg.persisted === false);
              rWrap.appendChild(kvRow('#' + rg.from_topic + ' (' + rg.claim_count + ')', '-> #' + rg.to_topic + ' (cos ' + rg.cosine_affinity + ')' + (rgSim ? ' [SIMULATED PREVIEW]' : ' [OBSERVED]'), '#38bdf8', true));
            });
            box.appendChild(rWrap);
          }
        } else if (target.type === 'topic') {
          var tObj = target.data;
          var tId = tObj.id || 'general';
          var tp = (latestTopicPages && latestTopicPages[tId]) || null;
          var aboveList = [];
          var belowList = [];
          var foldedList = [];
          var entSummaryParts = [];
          if (tp && tp.above_the_line) {
            (tp.above_the_line.canon || []).forEach(function (x) { aboveList.push(Object.assign({}, x, { tier: 'canon' })); });
            (tp.above_the_line.curated_syntheses || []).forEach(function (x) { aboveList.push(Object.assign({}, x, { tier: x.expires_at == null ? 'curated_class_b' : 'curated_synthesis' })); });
            (tp.above_the_line.decisions || []).forEach(function (x) { aboveList.push(Object.assign({}, x, { tier: 'class_b_decision' })); });
            belowList = (tp.below_the_line && Array.isArray(tp.below_the_line.active_timeline)) ? tp.below_the_line.active_timeline : [];
            foldedList = (tp.below_the_line && Array.isArray(tp.below_the_line.folded_lineage)) ? tp.below_the_line.folded_lineage : [];
            var entObj = (tp.below_the_line && tp.below_the_line.entity_links) || {};
            ['prs', 'issues', 'commits', 'files', 'agents'].forEach(function (k) {
              if (Array.isArray(entObj[k])) {
                entObj[k].forEach(function (ref) { entSummaryParts.push(ref); });
              }
            });
          } else {
            nodes.forEach(function (n) {
              if (topicOf(n.rec) !== tId) return;
              var evSt = evalRecord(n.rec, simNow());
              var isAbove = isCanon(n.rec) || evSt.state === 'decision' || Boolean(n.rec.merkle_sources);
              var item = {
                event_id: n.rec.event_id,
                d: n.rec.d,
                slug: slugOf(n.rec),
                scope: n.rec.scope,
                tier: isCanon(n.rec) ? 'canon' : (evSt.state === 'decision' ? 'class_b_decision' : (n.rec.merkle_sources ? 'curated_synthesis' : 'class_a_timeline')),
                claim: n.rec.claim,
                because: n.rec.because,
                author_pubkey: n.rec.author_pubkey,
                created_at: n.rec.created_at,
                expires_at: n.rec.expires_at,
                merkle_sources: n.rec.merkle_sources
              };
              if (isAbove) aboveList.push(item);
              else belowList.push(item);
            });
          }
          box.appendChild(inspectHeader(
            'Topic Page · Above / Below the Line',
            '#' + tId,
            'ABOVE ' + aboveList.length + ' · BELOW ' + belowList.length,
            aboveList.length > 0 ? 'ok' : 'info',
            tObj.color || '#38bdf8'
          ));
          var allTopIds = Object.keys(latestTopicPages || {});
          if (allTopIds.length > 1) {
            var pillBar = makeDiv('inspect-actions');
            pillBar.style.flexWrap = 'wrap';
            pillBar.style.marginBottom = '4px';
            allTopIds.slice(0, 6).forEach(function (otherId) {
              var pBtn = document.createElement('button');
              pBtn.type = 'button';
              pBtn.className = 'btn' + (otherId === tId ? ' sim' : '');
              pBtn.style.padding = '3px 7px';
              pBtn.style.fontSize = '10.5px';
              pBtn.textContent = '#' + otherId;
              pBtn.addEventListener('click', function () { openTopicInspector(otherId); });
              pillBar.appendChild(pBtn);
            });
            box.appendChild(pillBar);
          }
          var tkv = makeDiv('kv-list');
          tkv.appendChild(kvRow('Above the Line (Compiled Truth)', aboveList.length + ' durable claims (Canon + Class B + Merkle Syntheses)', '#34d399', true));
          tkv.appendChild(kvRow('Below the Line (Active Timeline)', belowList.length + ' Class A workflow/status claims', '#38bdf8', true));
          tkv.appendChild(kvRow('Folded Merkle Lineage (90d Hold)', foldedList.length + ' superseded source claims', '#a78bfa'));
          tkv.appendChild(kvRow('Read-only Markdown Mirror', '/topics/' + tId + '.md (index: /topics/index.md)', '#94a3b8', true));
          if (entSummaryParts.length > 0) {
            tkv.appendChild(kvRow('Extracted Entity Links', entSummaryParts.slice(0, 8).join(', '), '#c4b5fd', true));
          }
          box.appendChild(tkv);

          var aboveTitle = makeDiv('inspect-kicker', '▲ ABOVE THE LINE · COMPILED TRUTH (' + aboveList.length + ')');
          aboveTitle.style.marginTop = '6px';
          aboveTitle.style.color = '#6ee7b7';
          box.appendChild(aboveTitle);
          if (aboveList.length === 0) {
            box.appendChild(makeDiv('empty', 'No Canon, Class B decisions, or Merkle syntheses in #' + tId + ' yet.'));
          } else {
            var aboveWrap = makeDiv('kv-list');
            aboveList.slice(0, 12).forEach(function (item) {
              var tierBadge = item.tier === 'canon'
                ? '★ CANON'
                : (item.tier === 'curated_class_b' ? '◆ MERKLE B' : (item.tier === 'class_b_decision' ? '◆ CLASS B' : '◈ MERKLE A'));
              var tCol = item.tier === 'canon' ? '#fbbf24' : '#a78bfa';
              var auth = agentByPubkey(item.author_pubkey);
              var authName = item.author || (auth ? auth.name : String(item.author_pubkey || '').slice(0, 8));
              var headKey = tierBadge + ' · ' + (item.slug || item.d || '') + ' (@' + authName + ')';
              var bodyVal = String(item.claim || '') + (item.merkle_sources ? ' [merkle: ' + String(item.merkle_sources).slice(0, 10) + '…]' : '');
              var row = kvRow(headKey, bodyVal, tCol, true);
              var matchNode = nodeByEventId(item.event_id);
              if (matchNode) {
                row.style.cursor = 'pointer';
                row.addEventListener('click', function () {
                  selected = { type: 'memory', data: matchNode };
                  hovered = null;
                  renderInspector();
                });
              }
              aboveWrap.appendChild(row);
            });
            box.appendChild(aboveWrap);
          }

          var belowTitle = makeDiv('inspect-kicker', '▼ BELOW THE LINE · ACTIVE CLASS A TIMELINE (' + belowList.length + ')');
          belowTitle.style.marginTop = '8px';
          belowTitle.style.color = '#7dd3fc';
          box.appendChild(belowTitle);
          if (belowList.length === 0) {
            box.appendChild(makeDiv('empty', 'No active Class A workflow claims in #' + tId + '.'));
          } else {
            var belowWrap = makeDiv('kv-list');
            belowList.slice(0, 12).forEach(function (item) {
              var auth = agentByPubkey(item.author_pubkey);
              var authName = item.author || (auth ? auth.name : String(item.author_pubkey || '').slice(0, 8));
              var headKey = fmtTime(item.created_at).slice(5, 16) + 'Z · ' + (item.slug || item.d || '') + ' (@' + authName + ')';
              var row = kvRow(headKey, String(item.claim || ''), '#38bdf8', true);
              var matchNode = nodeByEventId(item.event_id);
              if (matchNode) {
                row.style.cursor = 'pointer';
                row.addEventListener('click', function () {
                  selected = { type: 'memory', data: matchNode };
                  hovered = null;
                  renderInspector();
                });
              }
              belowWrap.appendChild(row);
            });
            box.appendChild(belowWrap);
          }

          if (foldedList.length > 0) {
            var foldTitle = makeDiv('inspect-kicker', '⧗ FOLDED MERKLE LINEAGE · 90D HOLD (' + foldedList.length + ')');
            foldTitle.style.marginTop = '8px';
            foldTitle.style.color = '#c4b5fd';
            box.appendChild(foldTitle);
            var foldWrap = makeDiv('kv-list');
            foldedList.slice(0, 8).forEach(function (f) {
              var fHead = (f.slug || f.d || String(f.event_id || '').slice(0, 10)) + ' -> ' + String(f.folded_into || '').slice(0, 10) + '…';
              foldWrap.appendChild(kvRow(fHead, String(f.claim || '(folded source)'), '#c4b5fd', true));
            });
            box.appendChild(foldWrap);
          }
        }
        if (!typeChanged && prevScroll > 0) {
          box.scrollTop = prevScroll;
        }
      }

      // --- Canvas: camera, physics and drawing ---

      var drawer = 'none';
      function setDrawer(next) {
        drawer = next || 'none';
        document.body.setAttribute('data-drawer', drawer);
        if (el('dock-graph')) el('dock-graph').className = 'dock-btn' + (view === 'graph' && drawer === 'none' ? ' active' : '');
        if (el('dock-agents')) el('dock-agents').className = 'dock-btn' + (view === 'graph' && drawer === 'agents' ? ' active' : '');
        if (el('dock-pulses')) el('dock-pulses').className = 'dock-btn' + (view === 'graph' && drawer === 'pulses' ? ' active' : '');
        if (el('dock-tools')) el('dock-tools').className = 'dock-btn' + (view === 'graph' && drawer === 'tools' ? ' active' : '');
        if (el('dock-cards')) el('dock-cards').className = 'dock-btn' + (view === 'cards' ? ' active' : '');
      }

      function measureHud() {
        if (view !== 'graph') return;
        var topEl = document.querySelector('.hud-top');
        hudTop = topEl ? Math.ceil(topEl.getBoundingClientRect().bottom) + 8 : 110;
        if (width <= 1024) {
          var dockEl = el('mobile-dock');
          var dockTop = dockEl ? dockEl.getBoundingClientRect().top : 0;
          hudBottom = dockTop > 0 ? Math.max(58, Math.ceil(height - dockTop) + 8) : 64;
        } else {
          var botEl = document.querySelector('.hud-bottom');
          hudBottom = botEl ? Math.ceil(height - botEl.getBoundingClientRect().top) + 10 : 120;
        }
        document.documentElement.style.setProperty('--hud-top', hudTop + 'px');
        document.documentElement.style.setProperty('--hud-bottom', hudBottom + 'px');
      }

      function centerY() { return height / 2 + (hudTop - hudBottom) / 2; }
      function stageDim() { return Math.max(240, Math.min(width, height - hudTop - hudBottom + 20)); }
      function rimR() { return width < 680 ? Math.min(width * 0.33, stageDim() * 0.35) : stageDim() * 0.41; }

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

      function hitTest(sx, sy, isTouch) {
        var pt = screenToWorld(sx, sy);
        var hitR = (isTouch ? 24 : 16) / Math.max(0.7, cam.zoom);
        var best = null;
        var bestDist = Infinity;
        for (var i = 0; i < nodes.length; i++) {
          var nx = nodes[i].sx != null ? nodes[i].sx : nodes[i].x;
          var ny = nodes[i].sy != null ? nodes[i].sy : nodes[i].y;
          var nd = Math.hypot(pt.x - nx, pt.y - ny);
          if (nd < hitR && nd < bestDist) {
            bestDist = nd;
            best = { type: 'memory', data: nodes[i] };
          }
        }
        if (best) return best;
        var agentPad = (isTouch ? 14 : 8) / Math.max(0.7, cam.zoom);
        for (var j = 0; j < agents.length; j++) {
          var ad = Math.hypot(pt.x - agents[j].x, pt.y - agents[j].y);
          if (ad < agents[j].radius + agentPad && ad < bestDist) {
            bestDist = ad;
            best = { type: 'agent', data: agents[j] };
          }
        }
        if (best) return best;
        var topicHitR = (isTouch ? 34 : 24) / Math.max(0.7, cam.zoom);
        for (var k = 0; k < topics.length; k++) {
          var tp = topics[k];
          var tx = tp.sx != null ? tp.sx : tp.x;
          var ty = tp.sy != null ? tp.sy : tp.y;
          var labelY = ty - tp.radius * 0.62;
          var distLabel = Math.hypot(pt.x - tx, pt.y - labelY);
          var distCenter = Math.hypot(pt.x - tx, pt.y - ty);
          var td = Math.min(distLabel, distCenter);
          if (td < topicHitR && td < bestDist) {
            bestDist = td;
            best = { type: 'topic', data: tp };
          }
        }
        return best;
      }

      var pointers = {};
      var drag = null;
      var pinch = null;
      var lastTapAt = 0;

      function pointerList() {
        var arr = [];
        for (var k in pointers) if (Object.prototype.hasOwnProperty.call(pointers, k)) arr.push(pointers[k]);
        return arr;
      }

      canvas.addEventListener('pointerdown', function (e) {
        pointers[e.pointerId] = { id: e.pointerId, x: e.clientX, y: e.clientY, type: e.pointerType };
        if (canvas.setPointerCapture) {
          try { canvas.setPointerCapture(e.pointerId); } catch (_) {}
        }
        var pts = pointerList();
        if (pts.length === 2) {
          var d0 = Math.max(10, Math.hypot(pts[0].x - pts[1].x, pts[0].y - pts[1].y));
          pinch = {
            dist: d0,
            zoom: cam.targetZoom,
            midX: (pts[0].x + pts[1].x) / 2,
            midY: (pts[0].y + pts[1].y) / 2,
            camX: cam.x,
            camY: cam.y
          };
          if (drag) drag.moved = true;
        } else if (pts.length === 1) {
          pinch = null;
          drag = {
            x: e.clientX,
            y: e.clientY,
            camX: cam.x,
            camY: cam.y,
            rotX0: rotX,
            rotY0: rotY,
            orbitDrag: Boolean(mode3D && (e.shiftKey || e.button === 2)),
            moved: false,
            isTouch: e.pointerType !== 'mouse'
          };
        }
      });
      canvas.addEventListener('contextmenu', function (e) { e.preventDefault(); });
      canvas.addEventListener('pointermove', function (e) {
        if (pointers[e.pointerId]) {
          pointers[e.pointerId].x = e.clientX;
          pointers[e.pointerId].y = e.clientY;
        }
        var pts = pointerList();
        if (pts.length === 2 && pinch) {
          var dist = Math.max(10, Math.hypot(pts[0].x - pts[1].x, pts[0].y - pts[1].y));
          var nextZoom = Math.max(0.45, Math.min(2.8, pinch.zoom * (dist / pinch.dist)));
          var midX = (pts[0].x + pts[1].x) / 2;
          var midY = (pts[0].y + pts[1].y) / 2;
          cam.targetZoom = nextZoom;
          cam.zoom = nextZoom;
          cam.x = pinch.camX + (midX - pinch.midX);
          cam.y = pinch.camY + (midY - pinch.midY);
          return;
        }
        if (drag && pts.length === 1) {
          var threshold = drag.isTouch ? 8 : 5;
          if (Math.abs(e.clientX - drag.x) + Math.abs(e.clientY - drag.y) > threshold) drag.moved = true;
          if (drag.moved) {
            if (drag.orbitDrag || (mode3D && e.shiftKey)) {
              rotY = drag.rotY0 + (e.clientX - drag.x) * 0.0065;
              rotX = Math.max(-0.85, Math.min(0.85, drag.rotX0 + (e.clientY - drag.y) * 0.0055));
            } else {
              cam.x = drag.camX + e.clientX - drag.x;
              cam.y = drag.camY + e.clientY - drag.y;
            }
          }
          return;
        }
        if (e.pointerType !== 'mouse') return;
        var found = hitTest(e.clientX, e.clientY, false);
        if ((found && found.data) !== (hovered && hovered.data)) {
          hovered = found;
          canvas.style.cursor = found ? 'pointer' : 'grab';
          renderInspector();
        }
      });
      function releasePointer(e) {
        delete pointers[e.pointerId];
        var pts = pointerList();
        if (pts.length < 2) pinch = null;
        if (pts.length === 1) {
          drag = { x: pts[0].x, y: pts[0].y, camX: cam.x, camY: cam.y, moved: true, isTouch: pts[0].type !== 'mouse' };
          return;
        }
        if (drag && !drag.moved) {
          var isTouch = e.pointerType !== 'mouse';
          var hit = hitTest(e.clientX, e.clientY, isTouch);
          if (isTouch && drawer !== 'none' && !hit) {
            setDrawer('none');
          } else {
            var nowMs = Date.now();
            if (isTouch && !hit && nowMs - lastTapAt < 300) {
              cam.x = 0;
              cam.y = 0;
              cam.targetZoom = 1;
              lastTapAt = 0;
            } else {
              if (isTouch && !hit) lastTapAt = nowMs;
              selected = hit;
              if (isTouch && hit && drawer !== 'none') setDrawer('none');
              renderAgentRoster();
              renderInspector();
            }
          }
        }
        drag = null;
      }
      canvas.addEventListener('pointerup', releasePointer);
      canvas.addEventListener('pointercancel', function (e) {
        delete pointers[e.pointerId];
        if (!pointerList().length) { drag = null; pinch = null; }
      });
      canvas.addEventListener('pointerleave', function (e) {
        if (e.pointerType === 'mouse' && hovered) { hovered = null; renderInspector(); }
      });
      canvas.addEventListener('wheel', function (e) {
        e.preventDefault();
        cam.targetZoom = Math.max(0.45, Math.min(2.8, cam.targetZoom * (e.deltaY < 0 ? 1.1 : 0.9)));
      }, { passive: false });
      window.addEventListener('resize', resize);

      function stepPhysics() {
        tick += 1;
        if (mode3D && autoOrbit3D && !drag) {
          rotY += 0.0022;
        }
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
          consolidator.targets.forEach(function (tn) {
            if (tn.isSourceGhost) {
              tn.x += (consolidator.x - tn.x) * 0.04;
              tn.y += (consolidator.y - tn.y) * 0.04;
            }
          });
          if (consolidator.progress >= 1) {
            shockwaves.push({ x: consolidator.x, y: consolidator.y, r: 8, maxR: 130, color: '#fbbf24', alpha: 1 });
            if (consolidator.mode === 'live-write') {
              logStream(
                'write',
                'MERKLE DREAMING fold complete: ' + consolidator.targets.length + ' superseded source claims folded (merkle_sources ' +
                String(consolidator.merkleDigest || '').slice(0, 12) + '…)'
              );
            } else {
              logStream(
                'recall',
                (consolidator.simulated ? 'SIMULATED PREVIEW REPLAY complete (read-only): ' : 'PASSIVE REPLAY complete (read-only): ') +
                consolidator.targets.length + (consolidator.simulated ? ' simulated/ghost source claims preview-folded into ' : ' superseded source claims folded into ') +
                (consolidator.targetNode ? slugOf(consolidator.targetNode.rec) : 'curated claim') +
                ' (' + (consolidator.simulated ? 'simulated digest ' : 'merkle_sources ') + String(consolidator.merkleDigest || '').slice(0, 12) + '…)'
              );
            }
            consolidator = null;
          }
        }
        if (dreamSymphony) {
          var ds = dreamSymphony;
          ds.progress += ds.speed;
          var p = ds.progress;
          var act1Prefix = '[REPLAY · READ-ONLY] ' + ((ds.eigensSimulated || ds.arcsSimulated) ? '[SIMULATED PREVIEW] ' : '[OBSERVED] ');
          var act2Prefix = '[REPLAY · READ-ONLY] ' + ((ds.clustersSimulated || ds.ghostsSimulated) ? '[SIMULATED PREVIEW] ' : '[OBSERVED] ');
          var act3Prefix = '[REPLAY · READ-ONLY] ' + (ds.clustersSimulated ? '[SIMULATED PREVIEW] ' : '[OBSERVED] ');
          var act4Prefix = '[REPLAY · READ-ONLY] ' + (ds.isSimulated ? '[SIMULATED PREVIEW] ' : '[OBSERVED] ');
          if (!ds.actLogged[1] && p >= 0.01) {
            ds.actLogged[1] = true;
            shockwaves.push({ x: 0, y: 0, r: 12, maxR: stageDim() * 0.38, color: '#a78bfa', alpha: 0.9, hex: true });
            logStream('lookup', act1Prefix + 'ACT I · STAGE 0 SPECTRAL TOPIC EIGENVECTORS: Visualizing ' + ds.eigens.length + (ds.eigensSimulated ? ' Simulated Preview Eigen-Axes & ' : ' Observed Eigen-Axes & ') + ds.reorgArcs.length + (ds.arcsSimulated ? ' Simulated Preview Topic Arcs' : ' Observed Topic Reorganizations'));
          }
          if (!ds.actLogged[2] && p >= 0.25) {
            ds.actLogged[2] = true;
            logStream('lookup', act2Prefix + 'ACT II · STAGE 1 SYNAPTIC DISTILLATION: Visualizing ' + ds.totalSources + (ds.ghostsSimulated ? ' Simulated/Ghost Sources across ' : ' Superseded Checkpoints across ') + ds.totalMerkle + (ds.clustersSimulated ? ' Simulated Preview Clusters (' + (ds.observedMerkleCount || 0) + ' persisted merkle_sources)' : ' merkle_sources Claims'));
          }
          if (!ds.actLogged[3] && p >= 0.62) {
            ds.actLogged[3] = true;
            ds.classBNodes.forEach(function (cn, idx) {
              cn.birthGlow = 1.2;
              if (idx % 2 === 0 && agents.length > 0) {
                var ag = agents[idx % agents.length];
                pulses.push({ kind: 'recall', fromNode: cn, fromX: cn.x, fromY: cn.y, toX: ag.x, toY: ag.y, agent: ag, color: '#a78bfa', t: 0, speed: 0.024 });
              }
            });
            logStream('lookup', act3Prefix + 'ACT III · STAGE 2 CLASS B PROMOTION: Highlighting ' + ds.classBNodes.length + (ds.clustersSimulated ? ' Simulated Preview Class B Candidates across multi-agent ganglia' : ' Observed Class B crystals across multi-agent ganglia'));
          }
          if (!ds.actLogged[4] && p >= 0.85) {
            ds.actLogged[4] = true;
            shockwaves.push({ x: 0, y: 0, r: 16, maxR: stageDim() * 0.44, color: '#34d399', alpha: 1 });
            ds.classBNodes.slice(0, 10).forEach(function (cn) {
              pulses.push({ kind: 'recall', fromNode: cn, fromX: cn.x, fromY: cn.y, toX: 0, toY: 0, color: '#fbbf24', t: 0, speed: 0.028 });
            });
            logStream('lookup', act4Prefix + 'ACT IV · STAGE 3 CANON SOLIDIFICATION: ' + (ds.isSimulated ? 'Simulated Preview Overlay · Current Hive Coherence ' : 'Observed Hive Coherence ') + (latestCoherence && typeof latestCoherence.score === 'number' ? Number(latestCoherence.score).toFixed(1) + '%' : 'N/A'));
          }
          if (p >= 0.22 && p <= 0.68) {
            var act2P = Math.max(0, Math.min(1, (p - 0.22) / 0.40));
            ds.clusters.forEach(function (cl) {
              var localP = Math.max(0, Math.min(1, (act2P - cl.stagger) / (1 - cl.stagger)));
              var ease = localP * localP * (3 - 2 * localP);
              cl.sources.forEach(function (src) {
                var spin = cl.stagger * 4 + ease * Math.PI * 1.65;
                var curDist = src.dist * (1 - ease);
                src.x = cl.target.x + Math.cos(src.angle + spin) * curDist;
                src.y = cl.target.y + Math.sin(src.angle + spin) * curDist;
              });
              if (localP >= 0.96 && !cl.shocked) {
                cl.shocked = true;
                cl.target.birthGlow = 1.0;
                shockwaves.push({ x: cl.target.x, y: cl.target.y, r: 5, maxR: cl.isClassB ? 68 : 48, color: cl.isClassB ? '#a78bfa' : '#fbbf24', alpha: 0.9, hex: cl.isClassB });
              }
            });
          }
          if (p >= 1) {
            logStream('recall', (ds.isSimulated ? '[SIMULATED PREVIEW] ' : '[OBSERVED] ') + '4-ACT CORTEX REORGANIZATION COMPLETE · ' + ds.totalSources + (ds.ghostsSimulated ? ' simulated/ghost sources -> ' : ' sources -> ') + ds.totalMerkle + (ds.clustersSimulated ? ' simulated preview clusters' : ' merkle_sources claims'));
            dreamSymphony = null;
            if (dreamRecorder) {
              stopDreamRecording();
            }
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
        var bgGrad = ctx.createRadialGradient(width * 0.5, height * 0.48, 10, width * 0.5, height * 0.48, Math.max(width, height) * 0.72);
        bgGrad.addColorStop(0, '#0a1329');
        bgGrad.addColorStop(0.6, '#050914');
        bgGrad.addColorStop(1, '#02040a');
        ctx.fillStyle = bgGrad;
        ctx.fillRect(0, 0, width, height);
        ctx.translate(width / 2 + cam.x, centerY() + cam.y);
        ctx.scale(cam.zoom, cam.zoom);
        var minDim = stageDim();
        var at = simNow();
        var focus = hovered || selected;

        // Outer Periphery Coherence Halo: segmented per-agent coherence arcs around rimR() + 30
        var periphR = rimR() + 30;
        ctx.lineWidth = 1.5;
        ctx.strokeStyle = 'rgba(148, 163, 184, 0.12)';
        ctx.beginPath();
        ctx.arc(0, 0, periphR, 0, Math.PI * 2);
        ctx.stroke();
        if (agents.length > 0) {
          var sectorSpan = (Math.PI * 2) / agents.length;
          var gapPad = Math.min(0.06, sectorSpan * 0.14);
          agents.forEach(function (ag) {
            var agScore = typeof ag.coherence_score === 'number' ? ag.coherence_score : 0;
            var sCol = agScore >= 80 ? '#34d399' : (agScore >= 55 ? '#38bdf8' : (agScore >= 25 ? '#fbbf24' : '#f87171'));
            var sStart = ag.angle - sectorSpan * 0.5 + gapPad;
            var sFullEnd = ag.angle + sectorSpan * 0.5 - gapPad;
            var sSpan = Math.max(0.02, sFullEnd - sStart);
            // Background sector track
            ctx.beginPath();
            ctx.arc(0, 0, periphR, sStart, sFullEnd);
            ctx.strokeStyle = 'rgba(148, 163, 184, 0.16)';
            ctx.lineWidth = 3.2;
            ctx.stroke();
            // Filled periphery coherence arc proportional to agent's coherence_score (0-100%)
            var fillSpan = Math.max(0.03, sSpan * Math.max(0.04, agScore / 100));
            ctx.beginPath();
            ctx.arc(0, 0, periphR, sStart, sStart + fillSpan);
            ctx.strokeStyle = sCol;
            ctx.lineWidth = 3.8;
            ctx.stroke();
            // Radial neural sync tether from agent on periphery toward the central Eyeball (0, 0)
            ctx.save();
            if (agScore < 55) ctx.setLineDash(agScore >= 25 ? [4, 5] : [2, 6]);
            ctx.beginPath();
            ctx.moveTo(ag.x * 0.88, ag.y * 0.88);
            ctx.lineTo(Math.cos(ag.angle) * 56, Math.sin(ag.angle) * 56);
            ctx.strokeStyle = agScore >= 80 ? 'rgba(52, 211, 153, 0.18)' : (agScore >= 25 ? 'rgba(251, 191, 36, 0.12)' : 'rgba(248, 113, 113, 0.08)');
            ctx.lineWidth = agScore >= 80 ? 1.2 : 0.8;
            ctx.stroke();
            ctx.restore();
          });
        }
        ctx.save();
        ctx.setLineDash([5, 7]);
        ctx.strokeStyle = 'rgba(245, 158, 11, 0.2)';
        ctx.beginPath();
        ctx.arc(0, 0, minDim * 0.34, 0, Math.PI * 2);
        ctx.stroke();
        ctx.restore();
        // Central Coherence Eyeball at (0, 0) synchronized to the Hive Memory State
        var coreScore = latestCoherence && typeof latestCoherence.core_memory_score === 'number'
          ? latestCoherence.core_memory_score
          : (latestCoherence && typeof latestCoherence.score === 'number' ? latestCoherence.score : 100);
        var eyePulse = 52 + Math.sin(tick * 0.06) * 1.8;
        glow(0, 0, 6, eyePulse * 1.35, 'rgba(52, 211, 153, 0.16)');
        ctx.strokeStyle = 'rgba(251, 191, 36, 0.22)';
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        ctx.arc(0, 0, 52, 0, Math.PI * 2);
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(0, 0, 52, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * Math.max(0, Math.min(1, coreScore / 100)));
        ctx.strokeStyle = coreScore >= 80 ? '#34d399' : (coreScore >= 65 ? '#fbbf24' : '#f87171');
        ctx.lineWidth = 2.8;
        ctx.stroke();

        ctx.textAlign = 'center';
        ctx.textBaseline = 'alphabetic';
        if (mode3D) {
          ctx.save();
          ctx.strokeStyle = 'rgba(56, 189, 248, 0.11)';
          ctx.lineWidth = 1;
          var eqR = minDim * 0.25;
          ctx.beginPath();
          for (var aStep = 0; aStep <= 48; aStep++) {
            var aAng = (aStep / 48) * Math.PI * 2;
            var pEq = project3D(Math.cos(aAng) * eqR, Math.sin(aAng) * eqR, 0);
            if (aStep === 0) ctx.moveTo(pEq.x, pEq.y);
            else ctx.lineTo(pEq.x, pEq.y);
          }
          ctx.stroke();
          ctx.restore();
        }
        topics.forEach(function (t) {
          var tp3 = project3D(t.x, t.y, 0);
          t.sx = tp3.x;
          t.sy = tp3.y;
          var isTopicFocus = Boolean(focus && focus.type === 'topic' && focus.data && focus.data.id === t.id);
          var g = ctx.createRadialGradient(tp3.x, tp3.y, 6, tp3.x, tp3.y, t.radius * tp3.scale);
          g.addColorStop(0, t.color + (isTopicFocus ? '4d' : '2e'));
          g.addColorStop(0.6, t.color + (isTopicFocus ? '1f' : '10'));
          g.addColorStop(1, 'transparent');
          ctx.fillStyle = g;
          ctx.beginPath();
          ctx.arc(tp3.x, tp3.y, t.radius * tp3.scale, 0, Math.PI * 2);
          ctx.fill();
          if (isTopicFocus) {
            ctx.beginPath();
            ctx.arc(tp3.x, tp3.y, t.radius * 0.86 * tp3.scale, 0, Math.PI * 2);
            ctx.strokeStyle = t.color + '88';
            ctx.lineWidth = 1.4;
            ctx.stroke();
          }
          ctx.font = (isTopicFocus ? '700 12px' : '600 11px') + ' ui-monospace, SFMono-Regular, Menlo, monospace';
          ctx.fillStyle = isTopicFocus ? '#f8fafc' : 'rgba(226, 232, 240, 0.65)';
          ctx.fillText('#' + t.id, tp3.x, tp3.y - t.radius * 0.62 * tp3.scale);
          var tpPage = latestTopicPages && latestTopicPages[t.id] ? latestTopicPages[t.id] : null;
          if (tpPage && tpPage.counts) {
            ctx.font = '600 8.5px ui-monospace, SFMono-Regular, Menlo, monospace';
            ctx.fillStyle = isTopicFocus ? '#6ee7b7' : 'rgba(148, 163, 184, 0.52)';
            ctx.fillText('▲' + tpPage.counts.above_the_line + ' ▼' + tpPage.counts.below_the_line + ' · page', tp3.x, tp3.y - t.radius * 0.62 * tp3.scale + 11);
          }
        });

        nodes.forEach(function (n, idx) {
          if (n.z == null) n.z = computeNodeZ(n.rec, idx);
          var p3 = project3D(n.x, n.y, n.z);
          n.sx = p3.x;
          n.sy = p3.y;
          n.sz = p3.z;
          n.sScale = p3.scale;
          if (mode3D && n.z > 0 && !isCanon(n.rec)) {
            var pBase = project3D(n.x, n.y, 0);
            ctx.beginPath();
            ctx.moveTo(pBase.x, pBase.y);
            ctx.lineTo(n.sx, n.sy);
            ctx.strokeStyle = 'rgba(167, 139, 250, 0.16)';
            ctx.lineWidth = 0.85;
            ctx.stroke();
          }
        });

        // Constellation Entity-Link Mesh (First-Class Entity-Link Graph)
        if (Array.isArray(latestConstellationLinks) && latestConstellationLinks.length > 0) {
          var focusEventId = focus && focus.type === 'memory' && focus.data && focus.data.rec ? focus.data.rec.event_id : null;
          var focusTopicId = focus && focus.type === 'topic' && focus.data ? focus.data.id : null;
          latestConstellationLinks.forEach(function (lnk) {
            var nA = nodeByEventId(lnk.source_event_id);
            var nB = nodeByEventId(lnk.target_event_id);
            if (!nA || !nB) return;
            var isNodeLit = Boolean(focusEventId && (lnk.source_event_id === focusEventId || lnk.target_event_id === focusEventId));
            var isTopicLit = Boolean(focusTopicId && (topicOf(nA.rec) === focusTopicId || topicOf(nB.rec) === focusTopicId));
            var isLit = isNodeLit || isTopicLit;
            if (!isLit && focusEventId) return;
            var ax = nA.sx != null ? nA.sx : nA.x;
            var ay = nA.sy != null ? nA.sy : nA.y;
            var bx = nB.sx != null ? nB.sx : nB.x;
            var by = nB.sy != null ? nB.sy : nB.y;
            ctx.save();
            if (lnk.cross_topic && !isLit) ctx.setLineDash([3, 5]);
            ctx.beginPath();
            var midX = (ax + bx) * 0.5;
            var midY = (ay + by) * 0.5;
            ctx.moveTo(ax, ay);
            ctx.quadraticCurveTo(midX * 0.92, midY * 0.92, bx, by);
            ctx.strokeStyle = isNodeLit
              ? (lnk.cross_topic ? 'rgba(167, 139, 250, 0.86)' : 'rgba(56, 189, 248, 0.86)')
              : (isTopicLit
                ? 'rgba(52, 211, 153, 0.48)'
                : (lnk.cross_topic ? 'rgba(167, 139, 250, 0.16)' : 'rgba(56, 189, 248, 0.14)'));
            ctx.lineWidth = isNodeLit ? 1.85 : (isTopicLit ? 1.25 : 0.75);
            ctx.stroke();
            if (isNodeLit && lnk.primary_entity) {
              ctx.font = '600 8.5px ui-monospace, SFMono-Regular, Menlo, monospace';
              ctx.fillStyle = lnk.cross_topic ? '#ddd6fe' : '#bae6fd';
              ctx.fillText(String(lnk.primary_entity).slice(0, 22), midX * 0.96, midY * 0.96 - 3);
            }
            ctx.restore();
          });
        }

        nodes.forEach(function (n) {
          var author = agentByPubkey(n.rec.author_pubkey);
          if (!author) return;
          var nx = n.sx != null ? n.sx : n.x;
          var ny = n.sy != null ? n.sy : n.y;
          var lit = focus && ((focus.type === 'memory' && focus.data === n) || (focus.type === 'agent' && focus.data === author));
          ctx.beginPath();
          ctx.moveTo(author.x, author.y);
          ctx.quadraticCurveTo((author.x + nx) * 0.35, (author.y + ny) * 0.35, nx, ny);
          ctx.strokeStyle = lit ? author.color + '99' : 'rgba(148, 163, 184, 0.08)';
          ctx.lineWidth = lit ? 1.6 : 0.8;
          ctx.stroke();
        });

        if (selected && selected.type === 'dreaming') {
          ctx.save();
          ctx.setLineDash([4, 4]);
          nodes.forEach(function (n) {
            if (isCanon(n.rec) || !isWorkflowCheckpoint(n.rec)) return;
            var tp = topicById(topicOf(n.rec));
            if (!tp) return;
            ctx.beginPath();
            ctx.moveTo(n.x, n.y);
            ctx.lineTo(tp.x, tp.y);
            ctx.strokeStyle = 'rgba(167, 139, 250, 0.55)';
            ctx.lineWidth = 1.4;
            ctx.stroke();
          });
          ctx.restore();
        }

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
            if (tn.isSourceGhost) {
              ctx.beginPath();
              ctx.arc(tn.x, tn.y, 5.5, 0, Math.PI * 2);
              ctx.fillStyle = '#38bdf8';
              ctx.fill();
              ctx.strokeStyle = '#fde68a';
              ctx.lineWidth = 1.2;
              ctx.stroke();
              if (tn.simulated || tn.isSyntheticGhost || c.simulated) {
                ctx.font = '600 8.5px ui-monospace, monospace';
                ctx.fillStyle = '#fde68a';
                ctx.fillText('SIMULATED PREVIEW GHOST', tn.x, tn.y - 9);
              } else if (tn.isHistoricalSource) {
                ctx.font = '600 8.5px ui-monospace, monospace';
                ctx.fillStyle = '#7dd3fc';
                ctx.fillText('HISTORICAL SOURCE', tn.x, tn.y - 9);
              }
            }
          });
          polygon(c.x, c.y, 6, 15, tick * 0.06);
          ctx.fillStyle = '#fbbf24';
          ctx.fill();
          ctx.font = '700 10px ui-monospace, monospace';
          ctx.fillStyle = '#fde68a';
          var foldLabel = c.simulated
            ? 'SIMULATED PREVIEW FOLD '
            : (c.mode === 'replay' ? 'OBSERVED DREAM REPLAY ' : 'MERKLE FOLD ');
          ctx.fillText(foldLabel + Math.round(c.progress * 100) + '% (' + String(c.merkleDigest || '').slice(0, 8) + '…)', c.x, c.y - 22);
        }

        if (dreamSymphony) {
          var ds = dreamSymphony;
          var dp = ds.progress;
          // Act I: Spectral Topic Eigenvectors & Topic Reorganizations (0.00 - 0.30)
          if (dp <= 0.34) {
            var a1Alpha = dp < 0.25 ? Math.min(1, dp * 8) : Math.max(0, 1 - (dp - 0.25) / 0.09);
            ctx.save();
            ctx.globalAlpha = a1Alpha;
            ds.eigens.slice(0, 5).forEach(function (ev, idx) {
              var ringR = 56 + idx * (minDim * 0.055) + Math.sin(tick * 0.08 + idx) * 4;
              ctx.beginPath();
              ctx.arc(0, 0, ringR, 0, Math.PI * 2);
              ctx.strokeStyle = idx === 0 ? '#fbbf24' : (idx === 1 ? '#a78bfa' : '#38bdf8');
              ctx.lineWidth = idx === 0 ? 2.2 : 1.4;
              ctx.stroke();
              var labelAng = -Math.PI * 0.42 + idx * 0.52;
              var lx = Math.cos(labelAng) * ringR;
              var ly = Math.sin(labelAng) * ringR - 6;
              ctx.font = '700 10px ui-monospace, monospace';
              ctx.fillStyle = '#fde68a';
              var eigSimPrefix = (ds.eigensSimulated || ev.simulated) ? '[SIMULATED PREVIEW] ' : '';
              ctx.fillText(eigSimPrefix + 'λ' + ev.axis + ' #' + ev.canonical_topic + ' (' + ev.variance_pct + '%)', lx, ly);
            });
            ds.reorgArcs.forEach(function (arc, idx) {
              var arcP = Math.max(0, Math.min(1, (dp - idx * 0.015) / 0.20));
              var cx = (arc.fromX + arc.toX) * 0.35;
              var cy = (arc.fromY + arc.toY) * 0.35 - 28;
              ctx.save();
              ctx.setLineDash([5, 4]);
              ctx.beginPath();
              ctx.moveTo(arc.fromX, arc.fromY);
              ctx.quadraticCurveTo(cx, cy, arc.toX, arc.toY);
              ctx.strokeStyle = '#38bdf8';
              ctx.lineWidth = 1.8;
              ctx.stroke();
              ctx.restore();
              var inv = 1 - arcP;
              var px = inv * inv * arc.fromX + 2 * inv * arcP * cx + arcP * arcP * arc.toX;
              var py = inv * inv * arc.fromY + 2 * inv * arcP * cy + arcP * arcP * arc.toY;
              glow(px, py, 2, 16, '#38bdf8');
              ctx.beginPath();
              ctx.arc(px, py, 4.5, 0, Math.PI * 2);
              ctx.fillStyle = '#e0f2fe';
              ctx.fill();
              ctx.font = '600 9.5px ui-monospace, monospace';
              ctx.fillStyle = '#7dd3fc';
              var arcSimPrefix = (ds.arcsSimulated || arc.simulated) ? '[SIMULATED PREVIEW] ' : '';
              ctx.fillText(arcSimPrefix + '#' + arc.from_topic + ' -> #' + arc.to_topic, px, py - 10);
            });
            ctx.restore();
          }
          // Act II: Synaptic Distillation Cascade across clusters (0.20 - 0.68)
          if (dp >= 0.20 && dp <= 0.70) {
            var a2Alpha = dp < 0.25 ? (dp - 0.20) / 0.05 : (dp > 0.62 ? Math.max(0, 1 - (dp - 0.62) / 0.08) : 1);
            ctx.save();
            ctx.globalAlpha = a2Alpha;
            ds.clusters.forEach(function (cl) {
              var tx = cl.target.x;
              var ty = cl.target.y;
              glow(tx, ty, 2, 26, cl.isClassB ? 'rgba(167, 139, 250, 0.45)' : 'rgba(251, 191, 36, 0.45)');
              cl.sources.forEach(function (src) {
                ctx.beginPath();
                ctx.moveTo(src.x, src.y);
                ctx.lineTo(tx, ty);
                ctx.strokeStyle = cl.isClassB ? 'rgba(192, 132, 252, 0.78)' : 'rgba(251, 191, 36, 0.78)';
                ctx.lineWidth = 1.5;
                ctx.stroke();
                ctx.beginPath();
                ctx.arc(src.x, src.y, 4.2, 0, Math.PI * 2);
                ctx.fillStyle = '#38bdf8';
                ctx.fill();
                ctx.strokeStyle = '#fde68a';
                ctx.lineWidth = 1;
                ctx.stroke();
                if (src.simulated || (src.node && (src.node.isSyntheticGhost || src.node.simulated))) {
                  ctx.font = '600 8px ui-monospace, monospace';
                  ctx.fillStyle = '#fde68a';
                  ctx.fillText('SIMULATED GHOST', src.x, src.y - 7);
                } else if (src.node && src.node.isHistoricalSource) {
                  ctx.font = '600 8px ui-monospace, monospace';
                  ctx.fillStyle = '#7dd3fc';
                  ctx.fillText('HISTORICAL SOURCE', src.x, src.y - 7);
                }
              });
              polygon(tx, ty, 6, 11, tick * 0.07);
              ctx.strokeStyle = '#fbbf24';
              ctx.lineWidth = 1.6;
              ctx.stroke();
              if (cl.simulated || ds.clustersSimulated) {
                ctx.font = '700 8.5px ui-monospace, monospace';
                ctx.fillStyle = '#fbbf24';
                ctx.fillText('SIMULATED CLUSTER', tx, ty - 14);
              }
            });
            ctx.restore();
          }
          // Act III: Class B Crystal Promotion & Multi-Agent Corroboration (0.58 - 0.88)
          if (dp >= 0.58 && dp <= 0.88) {
            var a3Alpha = dp < 0.63 ? (dp - 0.58) / 0.05 : (dp > 0.83 ? Math.max(0, 1 - (dp - 0.83) / 0.05) : 1);
            ctx.save();
            ctx.globalAlpha = a3Alpha;
            ds.classBNodes.forEach(function (cn, idx) {
              glow(cn.x, cn.y, 3, 34, 'rgba(167, 139, 250, 0.62)');
              polygon(cn.x, cn.y, 4, 15 + Math.sin(tick * 0.18 + idx) * 2.5, tick * 0.04);
              ctx.strokeStyle = '#e9d5ff';
              ctx.lineWidth = 2;
              ctx.stroke();
              var author = agentByPubkey(cn.rec.author_pubkey);
              if (author) {
                ctx.beginPath();
                ctx.moveTo(cn.x, cn.y);
                ctx.quadraticCurveTo((cn.x + author.x) * 0.4, (cn.y + author.y) * 0.4, author.x, author.y);
                ctx.strokeStyle = 'rgba(167, 139, 250, 0.55)';
                ctx.lineWidth = 1.5;
                ctx.stroke();
              }
            });
            ctx.restore();
          }
          // Act IV: Stage 3 Canon Solidification & Coherence 2.0 Surge (0.82 - 1.00)
          if (dp >= 0.82) {
            var a4Alpha = Math.min(1, (dp - 0.82) / 0.06);
            ctx.save();
            ctx.globalAlpha = a4Alpha;
            var coreR = 54 + Math.sin(tick * 0.15) * 6;
            glow(0, 0, 6, coreR * 1.9, 'rgba(52, 211, 153, 0.45)');
            glow(0, 0, 4, coreR * 1.2, 'rgba(251, 191, 36, 0.65)');
            polygon(0, 0, 8, coreR, tick * 0.02);
            ctx.strokeStyle = '#fbbf24';
            ctx.lineWidth = 2.4;
            ctx.stroke();
            ds.classBNodes.slice(0, 12).forEach(function (cn) {
              ctx.beginPath();
              ctx.moveTo(cn.x, cn.y);
              ctx.lineTo(0, 0);
              ctx.strokeStyle = 'rgba(251, 191, 36, 0.48)';
              ctx.lineWidth = 1.6;
              ctx.stroke();
            });
            ctx.font = '800 12px ui-monospace, monospace';
            ctx.fillStyle = '#6ee7b7';
            var cohScoreTxt = latestCoherence && typeof latestCoherence.score === 'number' ? Number(latestCoherence.score).toFixed(1) + '%' : 'N/A';
            ctx.fillText((ds.isSimulated ? 'SIMULATED PREVIEW · ' : 'OBSERVED · ') + 'COHERENCE 2.0: ' + cohScoreTxt, 0, -coreR - 12);
            ctx.restore();
          }
        }

        var sortedNodes = nodes.slice().sort(function (a, b) {
          return (b.sz || 0) - (a.sz || 0);
        });
        var hasActiveSearch = Boolean(searchQuery && searchQuery.trim().length > 0);
        sortedNodes.forEach(function (n) {
          var ev = evalRecord(n.rec, at);
          var isSel = (hovered && hovered.data === n) || (selected && selected.data === n);
          var isSearchHit = hasActiveSearch ? nodeMatchesSearch(n.rec, searchQuery) : true;
          var nx = n.sx != null ? n.sx : n.x;
          var ny = n.sy != null ? n.sy : n.y;
          var sc = n.sScale || 1;
          var r = (ev.radius + (isSel ? 3 : 0)) * sc;
          ctx.save();
          if (hasActiveSearch && !isSearchHit && !isSel) {
            ctx.globalAlpha = 0.16;
          }
          if (ev.state !== 'expired' && isSearchHit) glow(nx, ny, r * 0.2, r * (2.3 + (n.birthGlow || 0) * 2), ev.color + '66');
          if (hasActiveSearch && isSearchHit) {
            ctx.beginPath();
            ctx.arc(nx, ny, r + 5.5, 0, Math.PI * 2);
            ctx.strokeStyle = '#38bdf8';
            ctx.lineWidth = 1.8;
            ctx.stroke();
          }
          if (ev.state === 'canon') {
            polygon(nx, ny, 8, r, tick * 0.008);
            ctx.fillStyle = ev.color;
            ctx.fill();
            ctx.strokeStyle = '#fef3c7';
            ctx.lineWidth = 1.6;
            ctx.stroke();
          } else if (ev.state === 'decision') {
            polygon(nx, ny, 4, r, 0);
            ctx.fillStyle = ev.color;
            ctx.fill();
            ctx.strokeStyle = '#f3e8ff';
            ctx.lineWidth = isSel ? 2.2 : 1.2;
            ctx.stroke();
          } else {
            ctx.beginPath();
            ctx.arc(nx, ny, r, 0, Math.PI * 2);
            ctx.fillStyle = ev.state === 'expired' ? 'rgba(71, 85, 105, 0.38)' : ev.color;
            ctx.fill();
            if (ev.freshness > 0) {
              ctx.beginPath();
              ctx.arc(nx, ny, r + 3.2, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * ev.freshness);
              ctx.strokeStyle = ev.color;
              ctx.lineWidth = 1.5;
              ctx.stroke();
            }
          }
          if (n.rec.conflict) {
            ctx.beginPath();
            ctx.arc(nx, ny, r + 5, 0, Math.PI * 2);
            ctx.strokeStyle = '#fcd34d';
            ctx.lineWidth = 1;
            ctx.stroke();
          }
          if (isSel || (hasActiveSearch && isSearchHit)) {
            if (isSel) {
              ctx.beginPath();
              ctx.arc(nx, ny, r + 6.5, 0, Math.PI * 2);
              ctx.strokeStyle = '#ffffff';
              ctx.lineWidth = 1.5;
              ctx.stroke();
            }
            ctx.font = '600 10.5px ui-monospace, monospace';
            ctx.fillStyle = isSel ? '#f8fafc' : '#bae6fd';
            ctx.fillText(slugOf(n.rec), nx, ny + r + 15);
          }
          ctx.restore();
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

        var drawNow = nowSec();
        agents.forEach(function (a) {
          var isSel = (hovered && hovered.data === a) || (selected && selected.data === a);
          var isStale = a.health === 'stale' && !isSel;
          var hCol = healthColor(a.health);
          if (a.energy > 0 || isSel) glow(a.x, a.y, a.radius * 0.4, a.radius * (2.1 + a.energy * 1.1), a.color + '77');
          else if (a.health === 'active') glow(a.x, a.y, a.radius * 0.5, a.radius * 1.65, 'rgba(16, 185, 129, 0.26)');
          ctx.save();
          if (isStale) ctx.globalAlpha = 0.52;
          ctx.beginPath();
          ctx.arc(a.x, a.y, a.radius, 0, Math.PI * 2);
          ctx.fillStyle = '#0b1325';
          ctx.fill();
          if (!a.listed || isStale) ctx.setLineDash([4, 3]);
          ctx.strokeStyle = a.color;
          ctx.lineWidth = isSel ? 3 : 2;
          ctx.stroke();
          ctx.restore();
          var agCohVal = typeof a.coherence_score === 'number' ? a.coherence_score : 0;
          var agCohArcCol = agCohVal >= 80 ? '#34d399' : (agCohVal >= 55 ? '#38bdf8' : (agCohVal >= 25 ? '#fbbf24' : '#f87171'));
          ctx.beginPath();
          ctx.arc(a.x, a.y, a.radius + 4.5, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * Math.max(0.05, Math.min(1, agCohVal / 100)));
          ctx.strokeStyle = agCohArcCol;
          ctx.lineWidth = 2.2;
          ctx.stroke();
          // Health beacon dot on top-right rim of ganglion
          var bx = a.x + a.radius * 0.72;
          var by = a.y - a.radius * 0.72;
          var br = width < 680 ? 4.2 : 5.2;
          if (a.health === 'active' || a.health === 'error') {
            glow(bx, by, 1, br * 2.4, a.health === 'active' ? 'rgba(16, 185, 129, 0.65)' : 'rgba(239, 68, 68, 0.65)');
          }
          ctx.beginPath();
          ctx.arc(bx, by, br, 0, Math.PI * 2);
          ctx.fillStyle = hCol;
          ctx.fill();
          ctx.strokeStyle = '#040711';
          ctx.lineWidth = 1.6;
          ctx.stroke();

          ctx.textBaseline = 'middle';
          ctx.font = (width < 680 ? '700 9.5px' : '700 10.5px') + ' -apple-system, BlinkMacSystemFont, sans-serif';
          ctx.fillStyle = isStale ? '#94a3b8' : '#f8fafc';
          ctx.fillText(a.is_owner ? '\\u2605' : a.name.slice(0, 2).toUpperCase(), a.x, a.y);
          ctx.font = (width < 680 ? '600 10.5px' : '600 11.5px') + ' -apple-system, BlinkMacSystemFont, sans-serif';
          ctx.fillStyle = isSel ? '#ffffff' : (isStale ? '#64748b' : '#cbd5e1');
          var labelDist = a.radius + (width < 680 ? 13 : 17);
          var lx = a.x + Math.cos(a.angle) * labelDist;
          var ly = a.y + Math.sin(a.angle) * labelDist;
          if (width < 680) {
            var tw = ctx.measureText(a.name).width;
            var maxX = Math.max(70, (width / 2 - tw / 2 - 10) / Math.max(0.7, cam.zoom));
            lx = Math.max(-maxX, Math.min(maxX, lx));
          }
          ctx.fillText(a.name, lx, ly);
          var subTag = a.health === 'active'
            ? ('\\u25cf ' + fmtShortAge(a.last_seen_at, drawNow))
            : (a.health === 'warm'
              ? ('\\u25d0 ' + fmtShortAge(a.last_seen_at, drawNow))
              : (a.health === 'error'
                ? '\\u2715 err'
                : (a.last_seen_at ? ('\\u25cb ' + fmtShortAge(a.last_seen_at, drawNow)) : '\\u25cb silent')));
          if (typeof a.coherence_score === 'number') {
            subTag += ' · ' + a.coherence_score + '%';
          }
          ctx.font = (width < 680 ? '600 8.5px' : '600 9.5px') + ' ui-monospace, SFMono-Regular, Menlo, monospace';
          ctx.fillStyle = agCohArcCol;
          ctx.fillText(subTag, lx, ly + (width < 680 ? 10.5 : 12));
          ctx.textBaseline = 'alphabetic';
        });

        if (dreamSymphony) {
          var dsBanner = dreamSymphony;
          var bp = dsBanner.progress;
          ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
          var bw = Math.min(width - 28, 660);
          var bh = 62;
          var bx = (width - bw) / 2;
          var by = Math.max(14, hudTop + 4);
          ctx.fillStyle = 'rgba(8, 13, 27, 0.90)';
          ctx.strokeStyle = 'rgba(167, 139, 250, 0.55)';
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.roundRect ? ctx.roundRect(bx, by, bw, bh, 12) : ctx.rect(bx, by, bw, bh);
          ctx.fill();
          ctx.stroke();

          var actTitle = '';
          var actSub = '';
          var actCol = '#a78bfa';
          if (bp < 0.25) {
            actTitle = 'ACT I / IV · STAGE 0: SPECTRAL TOPIC EIGENVECTORS (' + (dsBanner.eigensSimulated || dsBanner.arcsSimulated ? 'SIMULATED PREVIEW' : 'OBSERVED REPLAY') + ')';
            actSub = (dsBanner.eigensSimulated ? 'Simulated Preview: ' : 'Observed: ') + dsBanner.eigens.length + ' Eigen-Axes · ' + (dsBanner.arcsSimulated ? 'Simulated Preview: ' : 'Observed: ') + dsBanner.reorgArcs.length + ' Topic Affinity Arcs';
            actCol = '#38bdf8';
          } else if (bp < 0.62) {
            actTitle = 'ACT II / IV · STAGE 1: SYNAPTIC DISTILLATION (' + (dsBanner.clustersSimulated || dsBanner.ghostsSimulated ? 'SIMULATED PREVIEW' : 'OBSERVED REPLAY') + ')';
            actSub = dsBanner.clustersSimulated
              ? ('Simulated Preview: ' + dsBanner.totalSources + ' Synthetic/Ghost Sources across ' + dsBanner.totalMerkle + ' Preview Clusters (' + (dsBanner.observedMerkleCount || 0) + ' persisted merkle_sources)')
              : ('Observed: ' + dsBanner.totalSources + ' Superseded Checkpoints across ' + dsBanner.totalMerkle + ' merkle_sources Claims' + (dsBanner.ghostsSimulated ? ' (' + dsBanner.ghostSourcesCount + ' simulated ghost sources)' : ''));
            actCol = '#fbbf24';
          } else if (bp < 0.85) {
            actTitle = 'ACT III / IV · STAGE 2: CLASS B CRYSTALS (' + (dsBanner.clustersSimulated ? 'SIMULATED PREVIEW' : 'OBSERVED REPLAY') + ')';
            actSub = (dsBanner.clustersSimulated ? 'Simulated Preview: ' : 'Observed: ') + dsBanner.classBNodes.length + ' Multi-Agent Class B Decisions';
            actCol = '#c084fc';
          } else {
            var cohTxt = latestCoherence && typeof latestCoherence.score === 'number' ? Number(latestCoherence.score).toFixed(1) + '%' : 'N/A';
            actTitle = 'ACT IV / IV · STAGE 3: CANON SOLIDIFICATION (' + (dsBanner.isSimulated ? 'SIMULATED PREVIEW' : 'OBSERVED REPLAY') + ')';
            actSub = (dsBanner.isSimulated ? 'Simulated Preview Overlay · ' : 'Constitutional Core Visualization · ') + 'Current Hive Coherence 2.0: ' + cohTxt;
            actCol = '#34d399';
          }
          ctx.textAlign = 'left';
          ctx.textBaseline = 'alphabetic';
          ctx.font = '800 11.5px ui-monospace, SFMono-Regular, Menlo, monospace';
          ctx.fillStyle = actCol;
          ctx.fillText(actTitle, bx + 16, by + 22);
          ctx.font = '600 10.5px -apple-system, BlinkMacSystemFont, sans-serif';
          ctx.fillStyle = '#e2e8f0';
          ctx.fillText(actSub, bx + 16, by + 40);

          ctx.textAlign = 'right';
          ctx.font = '800 11px ui-monospace, monospace';
          ctx.fillStyle = dreamRecorder ? '#f87171' : '#fde68a';
          ctx.fillText((dreamRecorder ? '● REC .WEBM · ' : '') + Math.round(bp * 100) + '%', bx + bw - 16, by + 22);

          ctx.fillStyle = 'rgba(51, 65, 85, 0.65)';
          ctx.fillRect(bx + 16, by + 48, bw - 32, 5);
          ctx.fillStyle = actCol;
          ctx.fillRect(bx + 16, by + 48, (bw - 32) * Math.min(1, bp), 5);
        }
      }

      function frame() {
        if (view === 'graph' && !document.hidden) {
          stepPhysics();
          draw();
        }
        requestAnimationFrame(frame);
      }

      // --- Controls ---

      function switchView(nextView) {
        view = nextView;
        document.body.setAttribute('data-view', view);
        el('view-toggle').textContent = view === 'graph' ? 'Raw cards' : 'Cortex graph';
        setDrawer('none');
        if (view === 'graph') resize();
      }

      el('view-toggle').addEventListener('click', function () {
        switchView(view === 'graph' ? 'cards' : 'graph');
      });
      if (el('dock-graph')) el('dock-graph').addEventListener('click', function () {
        if (view !== 'graph') switchView('graph');
        else setDrawer('none');
      });
      if (el('dock-agents')) el('dock-agents').addEventListener('click', function () {
        if (view !== 'graph') switchView('graph');
        setDrawer(drawer === 'agents' ? 'none' : 'agents');
      });
      if (el('dock-pulses')) el('dock-pulses').addEventListener('click', function () {
        if (view !== 'graph') switchView('graph');
        setDrawer(drawer === 'pulses' ? 'none' : 'pulses');
      });
      if (el('dock-tools')) el('dock-tools').addEventListener('click', function () {
        if (view !== 'graph') switchView('graph');
        setDrawer(drawer === 'tools' ? 'none' : 'tools');
      });
      if (el('dock-cards')) el('dock-cards').addEventListener('click', function () {
        switchView(view === 'cards' ? 'graph' : 'cards');
      });
      var closeButtons = document.querySelectorAll('[data-close-drawer]');
      for (var cb = 0; cb < closeButtons.length; cb++) {
        closeButtons[cb].addEventListener('click', function () { setDrawer('none'); });
      }
      if (el('btn-zoom-in')) el('btn-zoom-in').addEventListener('click', function () {
        cam.targetZoom = Math.min(2.8, cam.targetZoom * 1.22);
      });
      if (el('btn-zoom-out')) el('btn-zoom-out').addEventListener('click', function () {
        cam.targetZoom = Math.max(0.45, cam.targetZoom / 1.22);
      });
      if (el('btn-zoom-reset')) el('btn-zoom-reset').addEventListener('click', function () {
        cam.x = 0;
        cam.y = 0;
        cam.targetZoom = 1;
      });
      if (el('btn-dream-replay')) el('btn-dream-replay').addEventListener('click', replayLastDream);
      if (el('btn-dream-record')) el('btn-dream-record').addEventListener('click', startDreamRecording);
      if (el('btn-dream-consolidate')) el('btn-dream-consolidate').addEventListener('click', openDreamingInspector);
      if (el('btn-dream-triggers')) el('btn-dream-triggers').addEventListener('click', inspectDreamTriggers);
      if (el('btn-dream-coherence')) el('btn-dream-coherence').addEventListener('click', openCoherenceInspector);
      if (el('btn-dream-efficacy')) el('btn-dream-efficacy').addEventListener('click', openEfficacyInspector);
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
        rotX = 0.34;
        rotY = 0;
      });
      if (el('btn-3d-toggle')) el('btn-3d-toggle').addEventListener('click', function () {
        mode3D = !mode3D;
        el('btn-3d-toggle').textContent = mode3D ? '🌐 3D Depth: ON' : '🌐 3D Depth: 2D';
      });
      if (el('btn-3d-orbit')) el('btn-3d-orbit').addEventListener('click', function () {
        autoOrbit3D = !autoOrbit3D;
        el('btn-3d-orbit').textContent = autoOrbit3D ? '↻ Orbit: ON' : '↻ Orbit: OFF';
      });
      if (el('cortex-search')) el('cortex-search').addEventListener('input', function () {
        searchQuery = String(el('cortex-search').value || '');
      });

      var latestCoherence = null;
      var latestEfficacy = null;
      var VIEWER_VERSION = '${VIEWER_VERSION}';
      function openCoherenceInspector() {
        if (!latestCoherence) return;
        if (view !== 'graph') switchView('graph');
        setDrawer('none');
        selected = { type: 'coherence', data: latestCoherence };
        hovered = null;
        renderAgentRoster();
        renderInspector();
      }
      function openEfficacyInspector() {
        if (!latestEfficacy) return;
        if (view !== 'graph') switchView('graph');
        setDrawer('none');
        selected = { type: 'efficacy', data: latestEfficacy };
        hovered = null;
        renderAgentRoster();
        renderInspector();
      }
      if (el('coherence-card')) el('coherence-card').addEventListener('click', openCoherenceInspector);
      if (el('m-kpi-coherence')) el('m-kpi-coherence').addEventListener('click', openCoherenceInspector);
      if (el('efficacy-card')) el('efficacy-card').addEventListener('click', openEfficacyInspector);
      if (el('m-kpi-efficacy')) el('m-kpi-efficacy').addEventListener('click', openEfficacyInspector);
      if (el('dreaming-card')) el('dreaming-card').addEventListener('click', openDreamingInspector);
      if (el('m-kpi-dreaming')) el('m-kpi-dreaming').addEventListener('click', openDreamingInspector);

      function drawEfficacyGraphCanvas(cv, eff) {
        if (!cv || !eff) return;
        var hist = Array.isArray(eff.history) ? eff.history : [];
        if (!hist.length) return;
        var sctx = cv.getContext('2d');
        if (!sctx) return;
        var sw = cv.width;
        var sh = cv.height;
        sctx.clearRect(0, 0, sw, sh);
        var padX = 42;
        var padTop = 40;
        var padBot = 26;
        var proj = eff.projected || null;
        var totalPts = proj && proj.after_wake_hook_score ? hist.length + 1 : hist.length;
        var xOf = function (idx) {
          return padX + (totalPts <= 1 ? (sw - padX - 20) / 2 : (idx / (totalPts - 1)) * (sw - padX - 24));
        };
        var yOf = function (val) {
          var clamped = Math.max(20, Math.min(100, Number(val || 0)));
          return sh - padBot - ((clamped - 20) / 80) * (sh - padTop - padBot);
        };
        sctx.strokeStyle = 'rgba(148, 163, 184, 0.18)';
        sctx.lineWidth = 1;
        sctx.font = '600 11px ui-monospace, SFMono-Regular, Menlo, monospace';
        sctx.fillStyle = 'rgba(148, 163, 184, 0.85)';
        sctx.textAlign = 'left';
        [25, 50, 75, 100].forEach(function (lvl) {
          var gy = yOf(lvl);
          sctx.beginPath();
          sctx.moveTo(padX, gy);
          sctx.lineTo(sw - 16, gy);
          sctx.stroke();
          sctx.fillText(lvl + '%', 4, gy + 4);
        });
        // Dashed Amber curve: Cross-Agent Handoff Velocity
        sctx.save();
        sctx.setLineDash([6, 4]);
        sctx.beginPath();
        hist.forEach(function (pt, idx) {
          var px = xOf(idx);
          var velVal = pt.axes && typeof pt.axes.velocity === 'number' ? pt.axes.velocity : pt.score;
          var py = yOf(velVal);
          if (idx === 0) sctx.moveTo(px, py);
          else sctx.lineTo(px, py);
        });
        sctx.strokeStyle = '#fbbf24';
        sctx.lineWidth = 2.4;
        sctx.stroke();
        sctx.restore();
        // Solid Cyan curve: Overall Synaptic Efficacy
        sctx.beginPath();
        hist.forEach(function (pt, idx) {
          var px = xOf(idx);
          var py = yOf(pt.score);
          if (idx === 0) sctx.moveTo(px, py);
          else sctx.lineTo(px, py);
        });
        sctx.strokeStyle = '#38bdf8';
        sctx.lineWidth = 3.2;
        sctx.stroke();
        if (proj && typeof proj.after_wake_hook_score === 'number') {
          sctx.save();
          sctx.setLineDash([5, 3]);
          sctx.beginPath();
          sctx.moveTo(xOf(hist.length - 1), yOf(hist[hist.length - 1].score));
          sctx.lineTo(xOf(hist.length), yOf(proj.after_wake_hook_score));
          sctx.strokeStyle = '#34d399';
          sctx.lineWidth = 2.8;
          sctx.stroke();
          sctx.restore();
          sctx.beginPath();
          sctx.arc(xOf(hist.length), yOf(proj.after_wake_hook_score), 5, 0, Math.PI * 2);
          sctx.fillStyle = '#34d399';
          sctx.fill();
        }
        hist.forEach(function (pt, idx) {
          var px = xOf(idx);
          var py = yOf(pt.score);
          sctx.beginPath();
          sctx.arc(px, py, 3.8, 0, Math.PI * 2);
          sctx.fillStyle = idx === hist.length - 1 ? '#fbbf24' : '#38bdf8';
          sctx.fill();
        });
        sctx.font = '600 10.5px ui-monospace, SFMono-Regular, Menlo, monospace';
        sctx.fillStyle = '#94a3b8';
        sctx.textAlign = 'left';
        sctx.fillText('Inception', padX, sh - 7);
        if (hist.length > 2) {
          var midIdx = Math.floor((hist.length - 1) / 2);
          sctx.textAlign = 'center';
          sctx.fillText('#' + hist[midIdx].claims, xOf(midIdx), sh - 7);
        }
        sctx.textAlign = 'right';
        sctx.fillStyle = '#fbbf24';
        sctx.fillText('Now #' + hist[hist.length - 1].claims, Math.min(xOf(hist.length - 1), sw - 78), sh - 7);
        sctx.fillStyle = '#34d399';
        sctx.fillText('+WakeHook', sw - 8, sh - 7);
        // 2-line legend
        sctx.textAlign = 'left';
        sctx.font = '700 11.5px ui-monospace, SFMono-Regular, Menlo, monospace';
        sctx.fillStyle = '#38bdf8';
        sctx.fillText('● Synaptic Efficacy: ' + Number(eff.score || 0).toFixed(1) + '%', 8, 15);
        var velNow = eff.axes && typeof eff.axes.velocity === 'number' ? eff.axes.velocity.toFixed(1) : '-';
        sctx.fillStyle = '#fbbf24';
        sctx.fillText('--- Handoff Velocity: ' + velNow + '%', 250, 15);
        if (proj && typeof proj.after_wake_hook_score === 'number') {
          sctx.fillStyle = '#34d399';
          sctx.fillText('◆ Post-@curator (' + Number(proj.after_curator_score || 0).toFixed(1) + '%) + Wake-Hook Projection: ' + proj.after_wake_hook_score.toFixed(1) + '%', 8, 30);
        }
      }

      function drawCoherenceGraphCanvas(cv, coh, isMini) {
        if (!cv || !coh) return;
        var hist = Array.isArray(coh.history) ? coh.history : [];
        if (!hist.length) return;
        var sctx = cv.getContext('2d');
        if (!sctx) return;
        var sw = cv.width;
        var sh = cv.height;
        sctx.clearRect(0, 0, sw, sh);
        var padX = isMini ? 6 : 42;
        var padTop = isMini ? 5 : 40;
        var padBot = isMini ? 5 : 26;
        var proj = coh.projected_after_dream || null;
        var totalPts = proj ? hist.length + 1 : hist.length;
        var xOf = function (idx) {
          return padX + (totalPts <= 1 ? (sw - padX - 20) / 2 : (idx / (totalPts - 1)) * (sw - padX - 24));
        };
        var yOf = function (val) {
          var clamped = Math.max(20, Math.min(100, Number(val || 0)));
          return sh - padBot - ((clamped - 20) / 80) * (sh - padTop - padBot);
        };
        if (!isMini) {
          sctx.strokeStyle = 'rgba(148, 163, 184, 0.18)';
          sctx.lineWidth = 1;
          sctx.font = '600 11px ui-monospace, SFMono-Regular, Menlo, monospace';
          sctx.fillStyle = 'rgba(148, 163, 184, 0.85)';
          sctx.textAlign = 'left';
          [25, 50, 75, 100].forEach(function (lvl) {
            var gy = yOf(lvl);
            sctx.beginPath();
            sctx.moveTo(padX, gy);
            sctx.lineTo(sw - 16, gy);
            sctx.stroke();
            sctx.fillText(lvl + '%', 4, gy + 4);
          });
        }
        // Pink dashed curve: Consolidation Axis over time
        sctx.save();
        sctx.setLineDash(isMini ? [3, 2] : [6, 4]);
        sctx.beginPath();
        hist.forEach(function (pt, idx) {
          var px = xOf(idx);
          var consVal = pt.axes && typeof pt.axes.consolidation === 'number' ? pt.axes.consolidation : pt.score;
          var py = yOf(consVal);
          if (idx === 0) sctx.moveTo(px, py);
          else sctx.lineTo(px, py);
        });
        if (proj && typeof proj.consolidation === 'number') {
          sctx.lineTo(xOf(hist.length), yOf(proj.consolidation));
        }
        sctx.strokeStyle = '#f472b6';
        sctx.lineWidth = isMini ? 1.5 : 2.5;
        sctx.stroke();
        sctx.restore();
        // Solid Emerald curve: Overall Hive Coherence over time
        sctx.beginPath();
        hist.forEach(function (pt, idx) {
          var px = xOf(idx);
          var py = yOf(pt.score);
          if (idx === 0) sctx.moveTo(px, py);
          else sctx.lineTo(px, py);
        });
        sctx.strokeStyle = '#34d399';
        sctx.lineWidth = isMini ? 2 : 3.2;
        sctx.stroke();
        if (proj && typeof proj.score === 'number') {
          sctx.save();
          sctx.setLineDash([5, 3]);
          sctx.beginPath();
          sctx.moveTo(xOf(hist.length - 1), yOf(hist[hist.length - 1].score));
          sctx.lineTo(xOf(hist.length), yOf(proj.score));
          sctx.strokeStyle = '#a78bfa';
          sctx.lineWidth = isMini ? 1.5 : 2.8;
          sctx.stroke();
          sctx.restore();
        }
        if (!isMini) {
          hist.forEach(function (pt, idx) {
            var px = xOf(idx);
            var py = yOf(pt.score);
            sctx.beginPath();
            sctx.arc(px, py, 3.8, 0, Math.PI * 2);
            sctx.fillStyle = idx === hist.length - 1 ? '#fbbf24' : '#38bdf8';
            sctx.fill();
            var consVal = pt.axes && typeof pt.axes.consolidation === 'number' ? pt.axes.consolidation : null;
            if (consVal !== null && (idx === 0 || idx === hist.length - 1 || idx % 3 === 0)) {
              sctx.beginPath();
              sctx.arc(px, yOf(consVal), 2.8, 0, Math.PI * 2);
              sctx.fillStyle = '#f472b6';
              sctx.fill();
            }
          });
          if (proj && typeof proj.score === 'number') {
            sctx.beginPath();
            sctx.arc(xOf(hist.length), yOf(proj.score), 5, 0, Math.PI * 2);
            sctx.fillStyle = '#a78bfa';
            sctx.fill();
            if (typeof proj.consolidation === 'number') {
              sctx.beginPath();
              sctx.arc(xOf(hist.length), yOf(proj.consolidation), 4.5, 0, Math.PI * 2);
              sctx.fillStyle = '#f472b6';
              sctx.fill();
            }
          }
          // X-axis labels
          sctx.font = '600 10.5px ui-monospace, SFMono-Regular, Menlo, monospace';
          sctx.fillStyle = '#94a3b8';
          sctx.textAlign = 'left';
          sctx.fillText('Inception', padX, sh - 7);
          if (hist.length > 2) {
            var midIdx = Math.floor((hist.length - 1) / 2);
            sctx.textAlign = 'center';
            sctx.fillText('#' + hist[midIdx].claims, xOf(midIdx), sh - 7);
          }
          if (proj) {
            sctx.textAlign = 'right';
            sctx.fillStyle = '#fbbf24';
            sctx.fillText('Now #' + hist[hist.length - 1].claims, Math.min(xOf(hist.length - 1), sw - 74), sh - 7);
            sctx.fillStyle = '#c4b5fd';
            sctx.fillText('+Curator', sw - 8, sh - 7);
          } else {
            sctx.textAlign = 'right';
            sctx.fillStyle = '#fbbf24';
            sctx.fillText('Now #' + hist[hist.length - 1].claims, sw - 8, sh - 7);
          }
          // 2-line clear legend at top
          sctx.textAlign = 'left';
          sctx.font = '700 11.5px ui-monospace, SFMono-Regular, Menlo, monospace';
          sctx.fillStyle = '#34d399';
          sctx.fillText('● Coherence: ' + Number(coh.score || 0).toFixed(1) + '%', 8, 15);
          var consNow = coh.axes && typeof coh.axes.consolidation === 'number' ? coh.axes.consolidation.toFixed(1) : '-';
          sctx.fillStyle = '#f472b6';
          sctx.fillText('--- Consolidation: ' + consNow + '%', 230, 15);
          if (proj && typeof proj.consolidation === 'number') {
            sctx.fillStyle = '#c4b5fd';
            sctx.fillText('◆ Post-@curator Projection: ' + proj.score.toFixed(1) + '% Coh · ' + proj.consolidation.toFixed(1) + '% Cons', 8, 30);
          }
        }
      }

      function renderCoherencePanels(coh) {
        if (!coh || typeof coh !== 'object') return;
        drawCoherenceGraphCanvas(el('hud-coherence-spark'), coh, true);
        drawCoherenceGraphCanvas(el('coherence-trajectory-canvas'), coh, false);
        drawCoherenceGraphCanvas(el('cards-coherence-canvas'), coh, false);
        var axes = coh.axes || {};
        var consNow = typeof axes.consolidation === 'number' ? axes.consolidation.toFixed(1) : '-';
        if (el('coh-graph-pill')) {
          el('coh-graph-pill').textContent = Number(coh.score || 0).toFixed(1) + '% coh · ' + consNow + '% cons';
        }
        if (el('cards-coherence-badge')) {
          el('cards-coherence-badge').textContent = Number(coh.score || 0).toFixed(1) + '% Coherence · ' + consNow + '% Consolidation';
        }
        var miniWrap = el('coherence-axes-mini');
        if (miniWrap) {
          miniWrap.textContent = '';
          var coreVal = typeof coh.core_memory_score === 'number' ? coh.core_memory_score : coh.score;
          var periphVal = typeof coh.periphery_coherence_score === 'number' ? coh.periphery_coherence_score : coh.score;
          miniWrap.appendChild(kvRow('Core Memory (Eyeball) vs Periphery (Ring)', Number(coreVal).toFixed(1) + '% core · ' + Number(periphVal).toFixed(1) + '% ring', '#6ee7b7'));
          miniWrap.appendChild(kvRow('Curation & Durability Axis (74.8% Class A)', consNow + '%', '#f472b6'));
          if (coh.projected_after_dream) {
            var pr = coh.projected_after_dream;
            miniWrap.appendChild(kvRow('Projected Post-@curator (' + (pr.staged_actions || 0) + ' Merkle clusters)', pr.score.toFixed(1) + '% coh · ' + pr.consolidation.toFixed(1) + '% cons', '#c4b5fd'));
          }
        }
        var cardsBars = el('cards-coherence-bars');
        if (cardsBars) {
          cardsBars.textContent = '';
          var rows = [
            ['Overall Hive Coherence 2.0', coh.score || 0, '#34d399'],
            ['Core Memory State (Eyeball / Elbow)', coh.core_memory_score || coh.score || 0, '#6ee7b7'],
            ['Fleet Periphery Coherence (Outer Ring)', coh.periphery_coherence_score || 0, '#fbbf24'],
            ['Curation & Durability Axis (Consolidation)', axes.consolidation || 0, '#f472b6'],
            ['Cross-Agent Convergence (25%)', axes.convergence || 0, '#a78bfa'],
            ['Synaptic Coupling & Hygiene (15%)', axes.coupling || 0, '#38bdf8']
          ];
          rows.forEach(function (item) {
            cardsBars.appendChild(kvRow(item[0], Number(item[1]).toFixed(1) + '%', item[2]));
          });
        }
      }

      var graphReady = false;
      function renderState(s) {
        if (!s || typeof s !== 'object') return;
        if (s.viewer_version && s.viewer_version !== VIEWER_VERSION && typeof window !== 'undefined' && window.location) {
          window.location.reload();
          return;
        }
        var nowSec = s.polled_at || Math.floor(Date.now() / 1000);
        var st = s.store_state || {};
        latestStoreState = st;
        latestRecentActivity = Array.isArray(s.recent_activity) ? s.recent_activity : [];
        if (s.curator_state && typeof s.curator_state === 'object') latestCuratorState = s.curator_state;
        if (s.consolidated_sources && typeof s.consolidated_sources === 'object') latestConsolidatedSources = s.consolidated_sources;
        if (Array.isArray(s.constellation_links)) latestConstellationLinks = s.constellation_links;
        if (s.entity_graph_stats && typeof s.entity_graph_stats === 'object') latestEntityGraphStats = s.entity_graph_stats;
        if (s.topic_pages && typeof s.topic_pages === 'object') latestTopicPages = s.topic_pages;
        var syncState = s.connected === false ? 'SOCKET_ERROR' : (st.state || 'UNKNOWN');

        el('reader-name').textContent = s.reader || 'viewer';
        el('server-name').textContent = s.server_name || 'hive-memory-viewer';

        var syncBadge = el('sync-badge');
        syncBadge.textContent = syncState;
        syncBadge.className = syncBadgeClass(syncState);

        var w = s.watch || {}, banner = el('alert-banner'), msg = w.alert || null, hard = !!w.hard;
        if (banner) {
          banner.textContent = msg || '';
          banner.className = 'alert-banner' + (hard ? '' : ' warn');
          banner.hidden = !msg;
        }

        el('sync-state').textContent = syncState;
        el('sync-sub').textContent = s.connected === false
          ? ('error: ' + (s.error || 'disconnected'))
          : (st.state === 'READY' ? 'private store ready; never synced to a relay' : 'store not ready; claims withheld until verified restore');

        el('seq-val').textContent = st.write_seq == null ? '-' : String(st.write_seq);
        el('seq-sub').textContent = 'current claims: ' + (st.current_claims == null ? '-' : String(st.current_claims));
        if (el('m-kpi-seq')) el('m-kpi-seq').textContent = 'seq: ' + (st.write_seq == null ? '-' : String(st.write_seq));
        if (el('m-kpi-claims')) el('m-kpi-claims').textContent = 'claims: ' + (st.current_claims == null ? '-' : String(st.current_claims));

        el('backup-val').textContent = st.last_backup_age_sec == null ? 'none' : (String(st.last_backup_age_sec) + 's ago');
        el('backup-sub').textContent = 'unbacked writes: ' + (st.unbacked_writes == null ? '-' : String(st.unbacked_writes));

        el('poll-val').textContent = fmtTime(s.polled_at);
        el('poll-sub').textContent = 'query answer: ' + (s.query_answer || '-') + ' (poll #' + (s.poll_seq || 0) + ')';

        if (s.coherence && typeof s.coherence === 'object') {
          latestCoherence = s.coherence;
          if (selected && selected.type === 'coherence') selected.data = latestCoherence;
          var cScore = Number(s.coherence.score || 0).toFixed(1);
          var cDelta = Number(s.coherence.delta_since_inception || 0);
          var cSign = cDelta >= 0 ? '+' : '';
          var edSt = s.coherence.epistemic_drift && s.coherence.epistemic_drift.status ? String(s.coherence.epistemic_drift.status).toUpperCase() : '2.0';
          if (el('coherence-val')) el('coherence-val').textContent = cScore + '%';
          if (el('coherence-sub')) el('coherence-sub').textContent = cSign + cDelta.toFixed(1) + ' · ' + edSt + ' · tap';
          if (el('m-kpi-coherence')) el('m-kpi-coherence').textContent = 'coh 2.0: ' + cScore + '% (' + edSt + ')';
          renderCoherencePanels(s.coherence);
        }
        if (s.efficacy && typeof s.efficacy === 'object') {
          latestEfficacy = s.efficacy;
          if (selected && selected.type === 'efficacy') selected.data = latestEfficacy;
          var eScore = Number(s.efficacy.score || 0).toFixed(1);
          var eVel = s.efficacy.velocity || {};
          var eRet = s.efficacy.retrieval || {};
          var medTxt = eVel.median_handoff_min != null ? (eVel.median_handoff_min + 'm handoff') : '4-axis';
          var hitTxt = Number(eRet.query_hit_rate_pct || 0).toFixed(0) + '% hit';
          if (el('efficacy-val')) el('efficacy-val').textContent = eScore + '%';
          if (el('efficacy-sub')) el('efficacy-sub').textContent = medTxt + ' · ' + hitTxt + ' · tap';
          if (el('m-kpi-efficacy')) el('m-kpi-efficacy').textContent = 'eff: ' + eScore + '% (' + medTxt + ')';
        }
        if (s.curator_state && typeof s.curator_state === 'object') {
          var eigCount = Array.isArray(s.curator_state.topic_eigenvectors) ? s.curator_state.topic_eigenvectors.length : 0;
          var reorgCount = Array.isArray(s.curator_state.topic_reorganizations) ? s.curator_state.topic_reorganizations.length : 0;
          if (el('dreaming-val')) el('dreaming-val').textContent = eigCount ? (eigCount + ' Eigen-Axes') : 'Stage 0–3';
          if (el('dreaming-sub')) el('dreaming-sub').textContent = reorgCount + ' topic reorgs · tap';
          if (el('m-kpi-dreaming')) el('m-kpi-dreaming').textContent = 'dream: ' + eigCount + ' axes · ' + reorgCount + ' reorgs';
        }

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
  stateFile = undefined,
  host,
  port,
  pollMs = DEFAULT_POLL_MS,
} = {}) {
  if (!socketPath || !isAbsolute(socketPath)) {
    throw new Error('--socket <absolute-path> is required')
  }
  const resolvedStateFile = resolveCuratorStatePath({ stateFile, socketPath })
  const target = parseListenTarget({ host, port })
  const client = createSingleSocketMcpClient(socketPath)
  const sseClients = new Set()
  const eventLog = []
  const agentTelemetry = new Map()
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
    coherence: computeCoherence(),
    efficacy: computeSynapticEfficacy(),
    curator_state: {
      state_file_present: false,
      last_curated_at: null,
      last_curated_write_seq: 0,
      last_ran_at: null,
      last_submitted_count: 0,
      dream_interval_sec: DEFAULT_DREAM_INTERVAL_SEC,
      write_delta_threshold: DEFAULT_WRITE_DELTA_THRESHOLD,
      topic_pressure_threshold: DEFAULT_TOPIC_PRESSURE_THRESHOLD,
      elapsed_sec: 0,
      write_delta: 0,
      should_run: false,
      triggers: { circadian_dream: false, synaptic_volume: false, nightmare_interrupt: false },
      reasons: [],
      hot_scope_topics: [],
      conflicted_keys: [],
      stale_count: 0,
      refusal_count_15m: 0,
      coherence_score: null,
    },
    consolidated_sources: {},
    constellation_links: [],
    entity_graph_stats: { total_edges: 0, link_count: 0, top_entities: [] },
    topic_pages: {},
    agent_health: { active_5m: 0, warm_20m: 0, stale: 0, error: 0, total: 0, window_sec: ACTIVE_WINDOW_SEC },
    query_answer: null,
    records: [],
    agent_roster: [],
    recent_activity: [],
    event_log: [],
  }

  let pollInFlight = null
  let pollTimer = null
  let cachedCorpus = null
  let cachedHtmlKey = null
  let cachedHtmlBuf = null

  function broadcastState() {
    if (sseClients.size === 0) return
    const payload = `data: ${JSON.stringify(currentState)}\n\n`
    for (const res of sseClients) {
      try {
        res.write(payload)
      } catch {
        sseClients.delete(res)
      }
    }
  }

  async function runPoll({ forceFull = true } = {}) {
    if (stopped) return currentState
    const nowSec = Math.floor(Date.now() / 1000)
    const nowMs = Date.now()
    pollSeq += 1
    let nextSnapshot
    try {
      const wake = await client.callReadTool('memory_wake', {})
      const wakeSeq = wake?.store_state?.write_seq
      const canReuseCorpus =
        !forceFull &&
        cachedCorpus !== null &&
        Number.isSafeInteger(wakeSeq) &&
        wakeSeq > 0 &&
        wakeSeq === cachedCorpus.writeSeq &&
        wake?.store_state?.state === 'READY' &&
        nowMs - cachedCorpus.atMs < 15_000

      let records
      let historyRecords
      let byEventId
      let firstQuery
      let historyComplete
      let spectral
      let previewPlan
      let consolidatedSources
      let constellation
      let topicPages

      if (canReuseCorpus) {
        records = cachedCorpus.records
        historyRecords = cachedCorpus.historyRecords
        byEventId = cachedCorpus.byEventId
        firstQuery = cachedCorpus.firstQuery
        historyComplete = cachedCorpus.historyComplete
        spectral = cachedCorpus.spectral
        previewPlan = cachedCorpus.previewPlan
        consolidatedSources = cachedCorpus.consolidatedSources
        constellation = cachedCorpus.constellation
        topicPages = cachedCorpus.topicPages
      } else {
        const byKey = new Map()
        byEventId = new Map()
        firstQuery = null
        let cursor = '0'
        let pages = 0
        while (cursor !== null && pages < 50) {
          const page = await client.callReadTool('memory_query', {
            limit: 100,
            format: 'full',
            include_history: true,
            ...(cursor !== '0' ? { cursor } : {}),
          })
          if (!firstQuery) firstQuery = page
          for (const r of Array.isArray(page?.records) ? page.records : []) {
            const clean = sanitizeMemoryRecord(r)
            if (!clean) continue
            if (clean.event_id) byEventId.set(clean.event_id, clean)
            if (clean.is_current && clean.status !== 'withdrawn' && clean.verification === 'accepted') {
              byKey.set(`${clean.author_pubkey}:${clean.d}`, clean)
            }
          }
          cursor = typeof page?.next_cursor === 'string' && page.next_cursor ? page.next_cursor : null
          pages += 1
        }
        // Since Phase 2 wake records are bare references (no claim); only full records are shown.
        for (const r of Array.isArray(wake?.records) ? wake.records.filter(x => typeof x?.claim === 'string') : []) {
          const clean = sanitizeMemoryRecord(r)
          if (clean && !byKey.has(`${clean.author_pubkey}:${clean.d}`)) {
            byKey.set(`${clean.author_pubkey}:${clean.d}`, clean)
            if (clean.event_id && !byEventId.has(clean.event_id)) byEventId.set(clean.event_id, clean)
          }
        }
        records = [...byKey.values()].sort(
          (a, b) => (a.computed_rank || 99) - (b.computed_rank || 99) || (b.created_at || 0) - (a.created_at || 0)
        )
        historyRecords = [...byEventId.values()]
        historyComplete = cursor === null
        spectral = computeTopicEigenvectors(records, { maxComponents: 7 })
        previewPlan = planMerkleDream({ records, nowSec })
        consolidatedSources = {}
        for (const r of records) {
          if (Array.isArray(r.supersedes)) {
            for (const sid of r.supersedes) {
              const srcRec = byEventId.get(sid)
              if (srcRec) consolidatedSources[sid] = srcRec
            }
          }
        }
        const rosterMap = new Map()
        for (const a of Array.isArray(wake?.agent_roster) ? wake.agent_roster : []) {
          if (a?.pubkey && a?.id) rosterMap.set(String(a.pubkey), String(a.id))
        }
        rosterMap.set('4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d', 'james')
        constellation = buildConstellationLinks(records)
        const compiledPages = compileTopicPagesFromRecords(records, {
          consolidatedSources,
          writerNames: rosterMap,
          nowSec,
        })
        topicPages = Object.fromEntries(
          compiledPages.map(p => {
            const { markdown: _md, ...rest } = p
            return [p.topic, rest]
          })
        )
        cachedCorpus = {
          writeSeq: wakeSeq ?? firstQuery?.store_state?.write_seq ?? null,
          atMs: nowMs,
          records,
          historyRecords,
          byEventId,
          firstQuery,
          historyComplete,
          spectral,
          previewPlan,
          consolidatedSources,
          constellation,
          topicPages,
        }
      }

      const scopeCounts = computeScopeCounts(wake?.counts, records)
      const rawRoster = (Array.isArray(wake?.agent_roster) ? wake.agent_roster : []).map(sanitizeRosterEntry).filter(Boolean)
      const recentActivity = (Array.isArray(wake?.recent_activity) ? wake.recent_activity : []).map(sanitizeActivity).filter(Boolean)
      const healthResult = computeAgentHealth({
        agent_roster: rawRoster,
        recent_activity: recentActivity,
        records,
        history_records: historyRecords,
        prior_telemetry: agentTelemetry,
        now_sec: nowSec,
      })
      const agentRoster = healthResult.roster
      const storeState = wake?.store_state || firstQuery?.store_state || { state: 'UNKNOWN', write_seq: null, current_claims: null, last_backup_age_sec: null, unbacked_writes: null }
      const coherence = computeCoherence({
        records,
        history_records: historyRecords,
        agent_roster: agentRoster,
        recent_activity: recentActivity,
        store_state: storeState,
        now_sec: nowSec,
        history_complete: historyComplete,
      })
      const activeStateFile = resolveCuratorStatePath({ stateFile, socketPath })
      const persistedCurator = readCuratorStateFile(activeStateFile)
      const lastCuratedAt = Number(persistedCurator?.last_curated_at || 0)
      const lastCuratedWriteSeq = Number(persistedCurator?.last_curated_write_seq || 0)
      const dreamIntervalSec = Number(persistedCurator?.dream_interval_sec || DEFAULT_DREAM_INTERVAL_SEC)
      const writeDeltaThreshold = Number(persistedCurator?.write_delta_threshold || DEFAULT_WRITE_DELTA_THRESHOLD)
      const topicPressureThreshold = Number(persistedCurator?.topic_pressure_threshold || DEFAULT_TOPIC_PRESSURE_THRESHOLD)
      const triggerEval = evaluateDreamTriggers({
        records,
        storeState,
        recentActivity,
        coherence,
        lastCuratedAt,
        lastCuratedWriteSeq,
        nowSec,
        dreamIntervalSec,
        writeDeltaThreshold,
        topicPressureThreshold,
      })
      const hasPersistedEigens =
        lastCuratedAt > 0 &&
        Array.isArray(persistedCurator?.topic_eigenvectors) &&
        persistedCurator.topic_eigenvectors.length > 0 &&
        !persistedCurator.topic_eigenvectors.some(e => e?.simulated || e?.persisted === false)
      const hasPersistedReorgs =
        lastCuratedAt > 0 &&
        Array.isArray(persistedCurator?.topic_reorganizations) &&
        persistedCurator.topic_reorganizations.length > 0 &&
        !persistedCurator.topic_reorganizations.some(r => r?.simulated || r?.persisted === false)
      const topicEigenvectors = hasPersistedEigens
        ? persistedCurator.topic_eigenvectors.map(e => ({ ...e, persisted: true, simulated: false }))
        : spectral.eigenvectors.map(e => ({ ...e, persisted: false, simulated: true }))
      const topicReorganizations = hasPersistedReorgs
        ? persistedCurator.topic_reorganizations.map(r => ({ ...r, persisted: true, simulated: false }))
        : spectral.reorganizations.map(r => ({ ...r, persisted: false, simulated: true }))
      const curatorState = {
        state_file: activeStateFile,
        state_file_present: Boolean(persistedCurator),
        last_curated_at: lastCuratedAt || null,
        last_curated_write_seq: lastCuratedWriteSeq,
        last_ran_at: persistedCurator?.last_ran_at || null,
        last_submitted_count: persistedCurator?.last_submitted_count ?? 0,
        dream_interval_sec: dreamIntervalSec,
        write_delta_threshold: writeDeltaThreshold,
        topic_pressure_threshold: topicPressureThreshold,
        elapsed_sec: triggerEval.elapsed_sec,
        write_delta: triggerEval.write_delta,
        should_run: triggerEval.shouldRun,
        triggers: triggerEval.triggers,
        reasons: triggerEval.reasons,
        hot_scope_topics: triggerEval.hot_scope_topics,
        conflicted_keys: triggerEval.conflicted_keys,
        stale_count: triggerEval.stale_count,
        refusal_count_15m: triggerEval.refusal_count_15m,
        coherence_score: triggerEval.coherence_score,
        topic_eigenvectors: topicEigenvectors,
        topic_reorganizations: topicReorganizations,
        consolidation_ledger: Array.isArray(persistedCurator?.consolidation_ledger) ? persistedCurator.consolidation_ledger : [],
        planned_clusters: [...previewPlan.promotions, ...previewPlan.distillations].slice(0, 60).map(c => ({
          stage: c.stage,
          scope: c.scope,
          topic: c.topic,
          slug: c.slug,
          subject: c.subject,
          source_event_ids: c.source_event_ids,
          author_count: c.author_count,
          merkle_sources: c.merkle_sources,
        })),
        planned_summary: {
          promotions: previewPlan.promotions.length,
          distillations: previewPlan.distillations.length,
          solidifications: previewPlan.solidifications.length,
          nightmares: previewPlan.nightmares.length,
        },
      }
      curatorState.display_mode = resolveDreamDisplayMode({
        records,
        curator_state: curatorState,
        consolidated_sources: consolidatedSources,
      })
      const efficacy = computeSynapticEfficacy({
        records,
        history_records: historyRecords,
        agent_roster: agentRoster,
        recent_activity: recentActivity,
        coherence,
        curator_state: curatorState,
        now_sec: nowSec,
      })
      const queryAnswer = firstQuery?.answer === 'unknown'
        ? 'unknown'
        : (records.length > 0 ? 'found' : String(firstQuery?.answer || 'unknown'))

      nextSnapshot = {
        viewer_version: VIEWER_VERSION,
        connected: true,
        error: null,
        server_name: client.getServerName() || 'hive-memory-viewer',
        reader: String(wake?.reader || firstQuery?.reader || 'viewer'),
        reader_pubkey: wake?.reader_pubkey || firstQuery?.reader_pubkey || null,
        authority: null,
        trustedInstruction: false,
        polled_at: nowSec,
        poll_seq: pollSeq,
        store_state: storeState,
        scope_counts: scopeCounts,
        coherence,
        efficacy,
        curator_state: curatorState,
        consolidated_sources: consolidatedSources,
        constellation_links: constellation?.links || [],
        entity_graph_stats: {
          total_edges: constellation?.total_edges || 0,
          link_count: constellation?.links?.length || 0,
          top_entities: constellation?.top_entities || [],
        },
        topic_pages: topicPages || {},
        agent_health: healthResult.summary,
        watch: watchView(nowSec),
        query_answer: queryAnswer,
        records,
        agent_roster: agentRoster,
        recent_activity: recentActivity,
      }
    } catch (err) {
      cachedCorpus = null
      nextSnapshot = {
        ...currentState,
        connected: false,
        error: String(err.message || err),
        watch: watchView(nowSec),
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

  function pollOnce(opts = {}) {
    if (stopped) return Promise.resolve(currentState)
    if (pollInFlight) return pollInFlight
    pollInFlight = runPoll(opts).finally(() => {
      pollInFlight = null
    })
    return pollInFlight
  }

  function scheduleNextPoll() {
    if (stopped) return
    pollTimer = setTimeout(async () => {
      await pollOnce({ forceFull: false })
      scheduleNextPoll()
    }, pollMs)
    pollTimer.unref?.()
  }

  await pollOnce({ forceFull: true })
  scheduleNextPoll()

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

    if (urlPath === '/topics' || urlPath === '/topics/' || urlPath === '/topics/index.md') {
      const pagesObj = currentState.topic_pages || {}
      const pageList = Object.values(pagesObj).sort(
        (a, b) => (b.counts?.above_the_line || 0) + (b.counts?.below_the_line || 0) - ((a.counts?.above_the_line || 0) + (a.counts?.below_the_line || 0))
      )
      const lines = [
        '# Hive Shared Memory — Topic Pages Index (Above / Below the Line)',
        '',
        '> Read-only compiled Markdown mirror of Hive Shared Memory topics (`authority: null`, `trustedInstruction: false`).',
        '',
      ]
      for (const p of pageList) {
        lines.push(
          `- **#${p.topic}** (\`/topics/${p.topic}.md\`) — **${p.counts?.above_the_line || 0} Above the Line** (${p.counts?.canon || 0} Canon, ${p.counts?.class_b_decisions || 0} Class B, ${p.counts?.curated_syntheses || 0} Merkle) · **${p.counts?.below_the_line || 0} Below the Line** (${p.counts?.folded_lineage || 0} Folded)`
        )
      }
      lines.push('')
      const body = lines.join('\n')
      res.writeHead(200, {
        ...securityHeaders,
        'Content-Type': 'text/markdown; charset=utf-8',
        'Content-Length': Buffer.byteLength(body),
      })
      res.end(method === 'HEAD' ? undefined : body)
      return
    }

    if (urlPath.startsWith('/topics/')) {
      let decodedTopicPath = ''
      try {
        decodedTopicPath = decodeURIComponent(urlPath.slice('/topics/'.length))
      } catch {
        const badBody = 'Bad Request: malformed topic URI encoding\n'
        res.writeHead(400, {
          ...securityHeaders,
          'Content-Type': 'text/plain; charset=utf-8',
          'Content-Length': Buffer.byteLength(badBody),
        })
        res.end(method === 'HEAD' ? undefined : badBody)
        return
      }
      const rawSlug = decodedTopicPath.replace(/\.md$/i, '').trim()
      const page = rawSlug && currentState.topic_pages ? currentState.topic_pages[rawSlug] : null
      if (page) {
        const body = renderTopicPageMarkdown(page)
        res.writeHead(200, {
          ...securityHeaders,
          'Content-Type': 'text/markdown; charset=utf-8',
          'Content-Length': Buffer.byteLength(body),
        })
        res.end(method === 'HEAD' ? undefined : body)
        return
      }
    }

    if (urlPath === '/' || urlPath === '/index.html') {
      const htmlKey = `${currentState.poll_seq ?? 0}:${currentState.connected}:${currentState.error || ''}:${currentState.store_state?.state || ''}:${currentState.store_state?.write_seq ?? ''}:${currentState.records?.length ?? 0}:${currentState.curator_state?.last_curated_write_seq ?? 0}:${currentState.event_log?.length ?? 0}`
      if (cachedHtmlKey !== htmlKey || !cachedHtmlBuf) {
        cachedHtmlBuf = Buffer.from(renderViewerHtml(currentState), 'utf8')
        cachedHtmlKey = htmlKey
      }
      res.writeHead(200, {
        ...securityHeaders,
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Length': cachedHtmlBuf.length,
      })
      res.end(method === 'HEAD' ? undefined : cachedHtmlBuf)
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
      clearTimeout(pollTimer)
      for (const res of sseClients) {
        try {
          res.end()
        } catch {
          /* ignore */
        }
      }
      sseClients.clear()
      client.close()
      httpServer.closeIdleConnections?.()
      httpServer.closeAllConnections?.()
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
