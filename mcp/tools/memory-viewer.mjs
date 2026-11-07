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
  readCuratorStateFile,
  resolveCuratorStatePath,
} from './memory-curate.mjs'

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
  // Coherence 2.0 Convergence: blends cumulative cross-author artifact density (which scales with store size
  // rather than saturating permanently at 12 refs) with recent-window cross-agent topic corroboration.
  const targetSharedRefs = slice.length <= 15 ? Math.max(1, slice.length * 0.4) : Math.max(6, nonCanon.length * 0.14)
  const refDensityScore = Math.min(100, (sharedRefs / targetSharedRefs) * 100)

  const recentNonCanon = nonCanon.slice(-18)
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
  let reuseBonus = 1
  if (Number.isSafeInteger(writeSeqEst) && writeSeqEst > slice.length) {
    reuseBonus = Math.min(1, 0.7 + 0.3 * ((writeSeqEst - slice.length) / Math.max(1, writeSeqEst)))
  }
  const consolidation = Math.round(Math.min(100, (0.6 * Math.min(1, durableRatio / 0.35) + 0.4 * reuseBonus) * 100) * 10) / 10

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
  const recentNonCanon = chronological.filter(r => r && r.scope !== 'hive:canon' && r.status !== 'withdrawn').slice(-18)
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
  const writesByActor = new Map()
  for (let idx = 0; idx < activityList.length; idx++) {
    const a = activityList[idx]
    if (!a || typeof a !== 'object') continue
    const actor = String(a.actor || '')
    if (a.kind === 'query' || a.kind === 'wake' || a.kind === 'lookup') {
      if (actor) readsByActor.set(actor, (readsByActor.get(actor) || 0) + 1)
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

  const writerIdSet = new Set(
    (Array.isArray(agent_roster) ? agent_roster : []).filter(a => a?.is_writer && a?.id).map(a => a.id)
  )
  const silentActiveWriters = []
  for (const [actor, readCount] of readsByActor.entries()) {
    if (writerIdSet.has(actor) && readCount >= 4 && !writesByActor.has(actor) && !recentWriterIds.has(actor)) {
      silentActiveWriters.push(actor)
    }
  }

  const missedTopics = [...missedTopicsSet]
  const epistemicPenalty = Math.min(
    65,
    zeroHitQueries * 16 + silentActiveWriters.length * 12 + siloedRecentTopics.length * 8
  )
  const epistemicScore = Math.max(0, Math.round((100 - epistemicPenalty) * 10) / 10)
  const epistemicStatus =
    zeroHitQueries >= 2 || epistemicPenalty >= 28
      ? 'blind_spot'
      : epistemicPenalty > 0
        ? 'drifting'
        : 'aligned'

  if (activityList.length > 0 || siloedRecentTopics.length > 0) {
    if (activityList.length > 0) {
      const refusals = activityList.filter(a => a?.kind === 'refused').length
      const gateHygiene = Math.max(0, 1 - refusals / activityList.length)
      const silencePenalty = silentActiveWriters.length * 12 + zeroHitQueries * 6
      const liveCoupling = Math.max(0, gateHygiene * 100 - silencePenalty)
      current.axes.coupling = Math.round((0.7 * current.axes.coupling + 0.3 * liveCoupling) * 10) / 10
    }
    if (zeroHitQueries > 0 || siloedRecentTopics.length > 0) {
      const convPenalty = Math.min(45, zeroHitQueries * 14 + siloedRecentTopics.length * 8)
      current.axes.convergence = Math.max(0, Math.round((current.axes.convergence - convPenalty) * 10) / 10)
    }
    if (missedTopics.length > 0) {
      const alignPenalty = Math.min(30, missedTopics.length * 10)
      current.axes.alignment = Math.max(0, Math.round((current.axes.alignment - alignPenalty) * 10) / 10)
    }
    current.score = Math.round((
      0.25 * current.axes.alignment +
      0.2 * current.axes.grounding +
      0.25 * current.axes.convergence +
      0.15 * current.axes.coupling +
      0.15 * current.axes.consolidation
    ) * 10) / 10
  }

  return {
    score: current.score,
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
    },
    history,
  }
}

export const ACTIVE_WINDOW_SEC = 300
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
    total: 0,
    window_sec: ACTIVE_WINDOW_SEC,
  }

  const enrichedRoster = (Array.isArray(agent_roster) ? agent_roster : []).map(agent => {
    const e = telemetry.get(agent.id) || {
      last_read_at: null,
      last_read_kind: null,
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
    summary.total += 1
    return {
      ...agent,
      last_read_at: e.last_read_at,
      last_read_kind: e.last_read_kind,
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

export function computeDreamingTelemetry(records = [], curatorState = null) {
  const recs = Array.isArray(records) ? records : []
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
    .inspector { flex: 0 1 auto; min-height: 0; overflow-y: auto; display: flex; flex-direction: column; gap: 9px; -webkit-overflow-scrolling: touch; overscroll-behavior: contain; }
    .inspect-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; border-bottom: 1px solid var(--border); padding-bottom: 7px; }
    .inspect-actions { display: flex; align-items: center; gap: 6px; flex-shrink: 0; }
    .inspect-close { padding: 3px 8px; font-size: 12px; line-height: 1.2; border-radius: 6px; }
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
    </div>
  </header>

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
      <button class="btn sim" id="btn-dream-replay" type="button">Replay Last Dream</button>
      <button class="btn sim" id="btn-dream-consolidate" type="button">Inspect Curation (Passive)</button>
      <button class="btn sim" id="btn-dream-triggers" type="button">Inspect 3-Trigger State</button>
      <button class="btn sim" id="btn-dream-coherence" type="button">5-Axis Coherence</button>
    </div>
    <div class="control-bar panel">
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
      var hovered = null;
      var selected = null;
      var futureDays = 0;
      var lastActivitySeq = null;
      var pulseTotal = 0;
      var tick = 0;
      var latestCuratorState = null;
      var latestConsolidatedSources = {};
      var latestStoreState = {};
      var latestRecentActivity = [];
      var prevByEventId = {};

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
          last_write_at: null,
          last_write_d: null,
          last_refused_at: null,
          last_refused_code: null,
          last_seen_at: null,
          active_5m: false,
          reads_5m: 0,
          writes_5m: 0,
          health: 'stale',
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
          next.push(makeAgent(r.id, {
            pubkey: r.pubkey || null,
            is_reader: Boolean(r.is_reader),
            is_writer: Boolean(r.is_writer),
            is_owner: Boolean(r.is_owner),
            per_hour: r.per_hour || 0,
            used_last_hour: typeof r.used_last_hour === 'number' ? r.used_last_hour : null,
            last_read_at: lastRead,
            last_read_kind: lastReadKind,
            last_write_at: lastWrite,
            last_write_d: lastWriteD,
            last_refused_at: lastRefused,
            last_refused_code: lastRefusedCode,
            last_seen_at: lastSeen,
            active_5m: active5m,
            reads_5m: reads5m,
            writes_5m: writes5m,
            health: health,
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
            isSourceGhost: true
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
        return {
          estimated_from_visible: true,
          passive_inspection: true,
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
            stale_count: Number(cs.stale_count) || 0
          }
        };
      }

      function updateDreamBarStatus() {
        var bar = el('dream-bar-status');
        if (!bar) return;
        var d = computeDreamingTelemetry();
        var cs = d.curatorState;
        var lastLabel = cs.last_curated_at ? ('last curated ' + fmtShortAge(cs.last_curated_at, nowSec()) + ' ago (seq ' + cs.last_curated_write_seq + ')') : 'last curated: never (seq 0)';
        var deltaLabel = '+' + cs.write_delta + '/' + cs.write_delta_threshold + ' writes';
        if (cs.triggers.nightmare_interrupt || d.nightmareCount > 0) {
          bar.textContent = 'NIGHTMARE TRIGGER ACTIVE · ' + lastLabel + ' · ' + deltaLabel + ' · ' + d.merkleCount + ' merkle_sources tags';
          bar.style.color = '#f87171';
        } else if (cs.should_run) {
          bar.textContent = 'CURATOR TRIGGER DUE (' + (cs.reasons[0] || deltaLabel) + ') · ' + lastLabel + ' · ' + d.merkleCount + ' merkle_sources tags';
          bar.style.color = '#fbbf24';
        } else {
          bar.textContent = 'Passive Read-Only · ' + lastLabel + ' · ' + deltaLabel + ' · ' + d.merkleCount + ' merkle_sources tags · -' + d.wakeSavings + '% wake';
          bar.style.color = '#94a3b8';
        }
      }

      function replayLastDream() {
        var merkleNodes = nodes.filter(function (n) {
          return n.rec && typeof n.rec.merkle_sources === 'string' && n.rec.merkle_sources.length > 0;
        }).sort(function (a, b) {
          return (b.rec.created_at || 0) - (a.rec.created_at || 0);
        });
        if (merkleNodes.length > 0) {
          var latest = merkleNodes[0];
          var top = topicById(topicOf(latest.rec));
          var merkleDigest = String(latest.rec.merkle_sources || '');
          var srcIds = Array.isArray(latest.rec.supersedes) ? latest.rec.supersedes : [];
          var srcNodes = resolveSourceNodes(latest.rec, latest);
          srcNodes.forEach(function (sn) {
            pulses.push({ kind: 'recall', fromNode: sn, fromX: sn.x, fromY: sn.y, toNode: latest, toX: latest.x, toY: latest.y, color: '#fbbf24', t: 0, speed: 0.02 });
          });
          if (top && srcNodes.length > 0) {
            consolidator = {
              mode: 'replay',
              topic: top,
              targetNode: latest,
              targets: srcNodes,
              merkleDigest: merkleDigest,
              x: latest.x,
              y: latest.y,
              progress: 0
            };
          }
          selected = { type: 'memory', data: latest };
          hovered = null;
          if (width <= 1024) setDrawer('none');
          renderAgentRoster();
          renderInspector();
          logStream(
            'recall',
            'PASSIVE REPLAY (read-only) · ' + String(latest.rec.scope || 'hive') + ' #' + topicOf(latest.rec) +
            ' -> ' + slugOf(latest.rec) + ' (merkle_sources ' + merkleDigest.slice(0, 12) + '… · ' + srcIds.length + ' superseded sources)',
            latest.rec.created_at
          );
          return;
        }
        openDreamingInspector();
        logStream('recall', 'PASSIVE REPLAY (read-only) · no curated records with merkle_sources in store yet');
      }

      function openDreamingInspector() {
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
        var actions = makeDiv('inspect-actions');
        actions.appendChild(makeBadge(pillText, pillCls));
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
        head.appendChild(actions);
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
          if (r.merkle_sources) kv.appendChild(kvRow('Merkle sources', String(r.merkle_sources).slice(0, 20) + '…', '#a78bfa'));
          if (r.consolidated_by) kv.appendChild(kvRow('Curated into', String(r.consolidated_by).slice(0, 20) + '… (90d hold)', '#c4b5fd'));
          kv.appendChild(kvRow('Created', fmtTime(r.created_at)));
          kv.appendChild(kvRow('Expires', fmtTime(r.expires_at)));
          if (r.conflict) kv.appendChild(kvRow('Conflict', 'yes', '#fcd34d'));
          if (r.stale_warning) kv.appendChild(kvRow('Stale', r.stale_warning, '#fcd34d'));
          kv.appendChild(kvRow('Quarantine', 'authority: ' + JSON.stringify(r.authority) + ' · trustedInstruction: ' + String(Boolean(r.trustedInstruction)), '#6ee7b7'));
          box.appendChild(kv);
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
            'Hive Coherence 2.0 (Epistemic + Retroactive)',
            coh.score.toFixed(1) + ' / 100',
            deltaSign + delta.toFixed(1) + ' SINCE INCEPTION · ' + edStatus,
            coh.score >= 72 && edStatus !== 'BLIND_SPOT' ? 'ok' : 'warn',
            '#6ee7b7'
          ));
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
            var edTitle = makeDiv('inspect-kicker', 'Coherence 2.0 · Epistemic Drift & Blind-Spot Telemetry');
            edTitle.style.marginTop = '6px';
            box.appendChild(edTitle);
            var edWrap = makeDiv('kv-list');
            var stColor = ed.status === 'aligned' ? '#34d399' : (ed.status === 'drifting' ? '#fbbf24' : '#fca5a5');
            var edScoreVal = ed.score ?? ed.epistemic_score ?? 100;
            edWrap.appendChild(kvRow('Epistemic status', String(ed.status || 'aligned').toUpperCase() + ' (' + Number(edScoreVal).toFixed(1) + '%)', stColor));
            var zhCount = Number(ed.zero_hit_queries || 0);
            var missed = Array.isArray(ed.missed_topics) && ed.missed_topics.length ? ' [' + ed.missed_topics.join(', ') + ']' : '';
            edWrap.appendChild(kvRow('Unresolved 0-hit queries', zhCount + missed, zhCount > 0 ? '#fca5a5' : '#34d399'));
            var silentArr = Array.isArray(ed.silent_active_writers) ? ed.silent_active_writers : [];
            edWrap.appendChild(kvRow('Silent active writers', silentArr.length ? silentArr.join(', ') : '0 (all active readers sharing)', silentArr.length ? '#fbbf24' : '#34d399'));
            var siloArr = Array.isArray(ed.siloed_recent_topics) ? ed.siloed_recent_topics : [];
            edWrap.appendChild(kvRow('Single-author topic silos', siloArr.length ? siloArr.join(', ') : '0 (multi-agent corroborated)', siloArr.length ? '#fbbf24' : '#34d399'));
            box.appendChild(edWrap);
          }

          var hist = Array.isArray(coh.history) ? coh.history : [];
          if (hist.length > 0) {
            var windowNote = coh.history_complete === false ? ' [TRUNCATED AT 5,000 EVENTS]' : ' (90d retained history)';
            var sparkTitle = makeDiv('inspect-kicker', 'Retroactive Trajectory (Inception -> Now)' + windowNote);
            sparkTitle.style.marginTop = '6px';
            box.appendChild(sparkTitle);
            var sparkCanvas = document.createElement('canvas');
            sparkCanvas.width = 560;
            sparkCanvas.height = 120;
            sparkCanvas.style.width = '100%';
            sparkCanvas.style.height = '64px';
            sparkCanvas.style.borderRadius = '8px';
            sparkCanvas.style.background = 'rgba(2, 6, 23, 0.55)';
            sparkCanvas.style.border = '1px solid rgba(148, 163, 184, 0.16)';
            box.appendChild(sparkCanvas);
            var sctx = sparkCanvas.getContext('2d');
            if (sctx) {
              var sw = sparkCanvas.width;
              var sh = sparkCanvas.height;
              var padX = 24;
              var padY = 18;
              sctx.strokeStyle = 'rgba(148, 163, 184, 0.15)';
              sctx.lineWidth = 1;
              [50, 75, 100].forEach(function (lvl) {
                var gy = sh - padY - ((lvl - 40) / 60) * (sh - padY * 2);
                sctx.beginPath();
                sctx.moveTo(padX, gy);
                sctx.lineTo(sw - padX, gy);
                sctx.stroke();
              });
              sctx.beginPath();
              hist.forEach(function (pt, idx) {
                var px = padX + (hist.length === 1 ? (sw - padX * 2) / 2 : (idx / (hist.length - 1)) * (sw - padX * 2));
                var clamped = Math.max(40, Math.min(100, Number(pt.score || 0)));
                var py = sh - padY - ((clamped - 40) / 60) * (sh - padY * 2);
                if (idx === 0) sctx.moveTo(px, py);
                else sctx.lineTo(px, py);
              });
              sctx.strokeStyle = '#34d399';
              sctx.lineWidth = 3;
              sctx.stroke();
              hist.forEach(function (pt, idx) {
                var px = padX + (hist.length === 1 ? (sw - padX * 2) / 2 : (idx / (hist.length - 1)) * (sw - padX * 2));
                var clamped = Math.max(40, Math.min(100, Number(pt.score || 0)));
                var py = sh - padY - ((clamped - 40) / 60) * (sh - padY * 2);
                sctx.beginPath();
                sctx.arc(px, py, 4, 0, Math.PI * 2);
                sctx.fillStyle = idx === hist.length - 1 ? '#fbbf24' : '#38bdf8';
                sctx.fill();
              });
            }
            var hList = makeDiv('kv-list');
            hist.forEach(function (pt, idx) {
              var label = (idx === 0 ? 'Inception' : '#' + pt.claims) + ' (' + fmtTime(pt.at).slice(11, 16) + 'Z)';
              var detail = pt.score.toFixed(1) + ' · ' + pt.authors + 'a · ' + pt.shared_refs + ' shared';
              hList.appendChild(kvRow(label, detail, idx === hist.length - 1 ? '#6ee7b7' : null));
            });
            box.appendChild(hList);
          }
        } else if (target.type === 'dreaming') {
          var dr = computeDreamingTelemetry();
          var cs = dr.curatorState;
          box.appendChild(inspectHeader(
            'Merkle Dreaming & Curation · Passive Inspector',
            '-' + dr.wakeSavings.toFixed(1) + '% Est. Wake Bytes',
            'PASSIVE INSPECTION · READ-ONLY',
            'info',
            '#a78bfa'
          ));
          var dkv = makeDiv('kv-list');
          dkv.appendChild(kvRow('Inspector mode', 'Passive read-only (never triggers curator writes)', '#6ee7b7'));
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
            var eTitle = makeDiv('inspect-kicker', 'Stage 0 · Spectral Topic Eigenvectors (PCA)');
            eTitle.style.marginTop = '6px';
            box.appendChild(eTitle);
            var eWrap = makeDiv('kv-list');
            eigens.slice(0, 6).forEach(function (ev) {
              var loads = Array.isArray(ev.topic_loadings) ? ev.topic_loadings.slice(0, 3).map(function (l) { return l.topic + (l.loading >= 0 ? '+' : '') + Number(l.loading).toFixed(2); }).join(', ') : '';
              eWrap.appendChild(kvRow('Axis ' + ev.axis + ' · #' + ev.canonical_topic, 'λ=' + ev.eigenvalue + ' (' + ev.variance_pct + '%) · ' + loads, '#a78bfa'));
            });
            box.appendChild(eWrap);
          }
          var reorgs = Array.isArray(latestCuratorState && latestCuratorState.topic_reorganizations) ? latestCuratorState.topic_reorganizations : [];
          if (reorgs.length > 0) {
            var rTitle = makeDiv('inspect-kicker', 'Stage 0 · Topic Reorganizations (Outliers -> Eigen-Topics)');
            rTitle.style.marginTop = '6px';
            box.appendChild(rTitle);
            var rWrap = makeDiv('kv-list');
            reorgs.slice(0, 8).forEach(function (rg) {
              rWrap.appendChild(kvRow('#' + rg.from_topic + ' (' + rg.claim_count + ')', '-> #' + rg.to_topic + ' (cos ' + rg.cosine_affinity + ')', '#38bdf8'));
            });
            box.appendChild(rWrap);
          }
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
          var nd = Math.hypot(pt.x - nodes[i].x, pt.y - nodes[i].y);
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
          drag = { x: e.clientX, y: e.clientY, camX: cam.x, camY: cam.y, moved: false, isTouch: e.pointerType !== 'mouse' };
        }
      });
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
            cam.x = drag.camX + e.clientX - drag.x;
            cam.y = drag.camY + e.clientY - drag.y;
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
                'PASSIVE REPLAY complete (read-only): ' + consolidator.targets.length + ' superseded source claims folded into ' +
                (consolidator.targetNode ? slugOf(consolidator.targetNode.rec) : 'curated claim') +
                ' (merkle_sources ' + String(consolidator.merkleDigest || '').slice(0, 12) + '…)'
              );
            }
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
            }
          });
          polygon(c.x, c.y, 6, 15, tick * 0.06);
          ctx.fillStyle = '#fbbf24';
          ctx.fill();
          ctx.font = '700 10px ui-monospace, monospace';
          ctx.fillStyle = '#fde68a';
          var foldLabel = c.mode === 'replay' ? 'PASSIVE DREAM REPLAY ' : 'MERKLE FOLD ';
          ctx.fillText(foldLabel + Math.round(c.progress * 100) + '% (' + String(c.merkleDigest || '').slice(0, 8) + '…)', c.x, c.y - 22);
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
          if (a.is_writer && a.per_hour > 0 && a.used_last_hour) {
            ctx.beginPath();
            ctx.arc(a.x, a.y, a.radius + 4.5, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * Math.min(1, a.used_last_hour / a.per_hour));
            ctx.strokeStyle = a.color;
            ctx.lineWidth = 2.2;
            ctx.stroke();
          }
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
          ctx.font = (width < 680 ? '600 8.5px' : '600 9.5px') + ' ui-monospace, SFMono-Regular, Menlo, monospace';
          ctx.fillStyle = a.health === 'active' ? '#34d399' : (a.health === 'warm' ? '#fbbf24' : (a.health === 'error' ? '#f87171' : '#64748b'));
          ctx.fillText(subTag, lx, ly + (width < 680 ? 10.5 : 12));
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
      if (el('btn-dream-consolidate')) el('btn-dream-consolidate').addEventListener('click', openDreamingInspector);
      if (el('btn-dream-triggers')) el('btn-dream-triggers').addEventListener('click', inspectDreamTriggers);
      if (el('btn-dream-coherence')) el('btn-dream-coherence').addEventListener('click', openCoherenceInspector);
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

      var latestCoherence = null;
      function openCoherenceInspector() {
        if (!latestCoherence) return;
        if (view !== 'graph') switchView('graph');
        setDrawer('none');
        selected = { type: 'coherence', data: latestCoherence };
        hovered = null;
        renderAgentRoster();
        renderInspector();
      }
      if (el('coherence-card')) el('coherence-card').addEventListener('click', openCoherenceInspector);
      if (el('m-kpi-coherence')) el('m-kpi-coherence').addEventListener('click', openCoherenceInspector);

      var graphReady = false;
      function renderState(s) {
        if (!s || typeof s !== 'object') return;
        var nowSec = s.polled_at || Math.floor(Date.now() / 1000);
        var st = s.store_state || {};
        latestStoreState = st;
        latestRecentActivity = Array.isArray(s.recent_activity) ? s.recent_activity : [];
        if (s.curator_state && typeof s.curator_state === 'object') latestCuratorState = s.curator_state;
        if (s.consolidated_sources && typeof s.consolidated_sources === 'object') latestConsolidatedSources = s.consolidated_sources;
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
    agent_health: { active_5m: 0, warm_20m: 0, stale: 0, error: 0, total: 0, window_sec: ACTIVE_WINDOW_SEC },
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
      const byKey = new Map()
      const byEventId = new Map()
      let firstQuery = null
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
      const records = [...byKey.values()].sort(
        (a, b) => (a.computed_rank || 99) - (b.computed_rank || 99) || (b.created_at || 0) - (a.created_at || 0)
      )
      const historyRecords = [...byEventId.values()]
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
      const historyComplete = cursor === null
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
      const spectral = computeTopicEigenvectors(records, { maxComponents: 7 })
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
        topic_eigenvectors: spectral.eigenvectors,
        topic_reorganizations: spectral.reorganizations,
      }
      const consolidatedSources = {}
      for (const r of records) {
        if (Array.isArray(r.supersedes)) {
          for (const sid of r.supersedes) {
            const srcRec = byEventId.get(sid)
            if (srcRec) consolidatedSources[sid] = srcRec
          }
        }
      }
      const queryAnswer = firstQuery?.answer === 'unknown'
        ? 'unknown'
        : (records.length > 0 ? 'found' : String(firstQuery?.answer || 'unknown'))

      nextSnapshot = {
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
        curator_state: curatorState,
        consolidated_sources: consolidatedSources,
        agent_health: healthResult.summary,
        query_answer: queryAnswer,
        records,
        agent_roster: agentRoster,
        recent_activity: recentActivity,
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
