// mcp/tools/memory-curate.mjs — Phase 2 Merkle Dreaming, Curation & Nightmare Engine.
//
// Operates strictly over the pure read/write socket path (never mutating SQLite directly):
//   1. Evaluates the Three Triggers:
//      - Circadian Dream (periodic, default every 6 hours = 21,600s)
//      - Synaptic Volume (every N writes, default 20, or >8 Class A claims in any scope+topic)
//      - Nightmare Interrupt (active conflict, stale-git drift, refusal spike, or coherence drop)
//   2. Runs the Three-Stage Curation Pipeline:
//      - Stage 1 (Distillation): folds multi-step Class A trails and completed workflow handoffs
//        into a single curated Class A claim with cryptographic `merkle_sources`.
//      - Stage 2 (Promotion): elevates multi-author / recurring settled Class A claims into
//        durable Class B decisions (`ttl_sec: 0`, `retention: "decision"`) with `merkle_sources`.
//      - Stage 3 (Solidification): nominates converged Class B truths (>=3 authors or linked sources)
//        for owner promotion into `hive:canon`.
//   3. Handles Nightmares deterministically:
//      - Auto-resolves conflicts only when strict causal provenance (`as_of_evt`, `evidence`, or
//        caller-verified git ancestry) orders one claim after the other.
//      - Escalates ambiguous conflicts to `@james` and `@mydude` without guessing.

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { createConnection } from 'node:net'
import { dirname, join, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure'
import {
  DEFAULT_TTL_SEC,
  buildClaimTemplate,
  computeSourceMerkleRoot,
  isWorkflowSlug,
  normalizeMemoryTopic,
  parseFactKey,
} from './memory.mjs'
import { computeCoherence, createSingleSocketMcpClient } from './memory-viewer.mjs'

export function defaultCuratorStatePath(readerSocket) {
  if (!readerSocket || typeof readerSocket !== 'string') return null
  const sockDir = dirname(resolve(readerSocket))
  if (sockDir === '/run/hive-memory') {
    if (existsSync('/var/lib/hive-memory-curator')) {
      return '/var/lib/hive-memory-curator/curator-state.json'
    }
    if (existsSync('/run/hive-memory-curator')) {
      return '/run/hive-memory-curator/curator-state.json'
    }
  }
  return join(sockDir, 'curator-state.json')
}

export function resolveCuratorStatePath({ stateFile = undefined, socketPath = null } = {}) {
  if (stateFile === null || stateFile === '') return null
  if (typeof stateFile === 'string' && stateFile.trim()) return resolve(stateFile.trim())
  if (typeof process.env.HIVE_MEMORY_CURATOR_STATE_FILE === 'string' && process.env.HIVE_MEMORY_CURATOR_STATE_FILE.trim()) {
    return resolve(process.env.HIVE_MEMORY_CURATOR_STATE_FILE.trim())
  }
  return defaultCuratorStatePath(socketPath)
}

export function readCuratorStateFile(stateFilePath) {
  if (!stateFilePath || typeof stateFilePath !== 'string') return null
  let text
  try {
    text = readFileSync(stateFilePath, 'utf8')
  } catch (err) {
    if (err && err.code === 'ENOENT') return null
    const wrapped = new Error(`curator state file read failed (${stateFilePath}): ${err?.message || err}`)
    wrapped.code = 'HIVE_MEMORY_CURATOR_STATE_READ_FAILED'
    throw wrapped
  }
  let raw
  try {
    raw = JSON.parse(text)
  } catch (err) {
    const wrapped = new Error(`curator state file corrupt JSON (${stateFilePath}): ${err?.message || err}`)
    wrapped.code = 'HIVE_MEMORY_CURATOR_STATE_READ_FAILED'
    throw wrapped
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    const wrapped = new Error(`curator state file must contain a JSON object (${stateFilePath})`)
    wrapped.code = 'HIVE_MEMORY_CURATOR_STATE_READ_FAILED'
    throw wrapped
  }
  const parseCursorField = (fieldName) => {
    const val = raw[fieldName]
    if (val === undefined) return 0
    if (typeof val !== 'number' || !Number.isFinite(val) || val < 0) {
      const wrapped = new Error(`curator state file invalid ${fieldName} (${stateFilePath}): must be a non-negative finite number`)
      wrapped.code = 'HIVE_MEMORY_CURATOR_STATE_READ_FAILED'
      throw wrapped
    }
    return val
  }
  return {
    last_curated_at: parseCursorField('last_curated_at'),
    last_curated_write_seq: parseCursorField('last_curated_write_seq'),
    last_ran_at: typeof raw.last_ran_at === 'number' && Number.isFinite(raw.last_ran_at) ? raw.last_ran_at : null,
    last_submitted_count: typeof raw.last_submitted_count === 'number' && Number.isFinite(raw.last_submitted_count) ? raw.last_submitted_count : 0,
    dream_interval_sec: typeof raw.dream_interval_sec === 'number' && Number.isFinite(raw.dream_interval_sec) ? raw.dream_interval_sec : DEFAULT_DREAM_INTERVAL_SEC,
    write_delta_threshold: typeof raw.write_delta_threshold === 'number' && Number.isFinite(raw.write_delta_threshold) ? raw.write_delta_threshold : DEFAULT_WRITE_DELTA_THRESHOLD,
    topic_pressure_threshold: typeof raw.topic_pressure_threshold === 'number' && Number.isFinite(raw.topic_pressure_threshold) ? raw.topic_pressure_threshold : DEFAULT_TOPIC_PRESSURE_THRESHOLD,
    triggers: raw.triggers && typeof raw.triggers === 'object' ? raw.triggers : null,
    coherence_score: typeof raw.coherence_score === 'number' ? raw.coherence_score : null,
  }
}

export function writeCuratorStateFile(stateFilePath, state) {
  if (!stateFilePath || typeof stateFilePath !== 'string') {
    const wrapped = new Error('curator state file path is required')
    wrapped.code = 'HIVE_MEMORY_CURATOR_STATE_WRITE_FAILED'
    throw wrapped
  }
  try {
    const resolved = resolve(stateFilePath)
    mkdirSync(dirname(resolved), { recursive: true, mode: 0o755 })
    const tmpPath = `${resolved}.tmp.${process.pid}`
    writeFileSync(tmpPath, JSON.stringify(state, null, 2) + '\n', { encoding: 'utf8', mode: 0o644 })
    chmodSync(tmpPath, 0o644)
    renameSync(tmpPath, resolved)
    return true
  } catch (err) {
    const wrapped = new Error(`curator state file write failed (${stateFilePath}): ${err?.message || err}`)
    wrapped.code = 'HIVE_MEMORY_CURATOR_STATE_WRITE_FAILED'
    throw wrapped
  }
}

function createCuratorWriteClient(socketPath) {
  let socket = null
  let nextId = 1
  const pending = new Map()
  let connected = false
  let initialized = false

  function disconnect() {
    connected = false
    initialized = false
    if (socket) {
      try { socket.destroy() } catch { /* ignore */ }
      socket = null
    }
  }

  function sendRaw(obj) {
    return new Promise((resolve, reject) => {
      if (!socket || !connected) return reject(new Error('curator writer socket not connected'))
      const id = nextId++
      pending.set(id, { resolve, reject })
      socket.write(JSON.stringify({ jsonrpc: '2.0', id, ...obj }) + '\n')
    })
  }

  async function ensureConnected() {
    if (connected && initialized && socket) return
    await new Promise((resolveConn, rejectConn) => {
      const sock = createConnection(socketPath)
      sock.once('connect', () => {
        socket = sock
        connected = true
        resolveConn()
      })
      sock.once('error', rejectConn)
      const rl = createInterface({ input: sock, crlfDelay: Infinity })
      rl.on('line', line => {
        if (!line.trim()) return
        let msg
        try { msg = JSON.parse(line) } catch { return }
        if (msg && msg.id !== undefined && pending.has(msg.id)) {
          const entry = pending.get(msg.id)
          pending.delete(msg.id)
          if (msg.error) entry.reject(new Error(msg.error.message || 'MCP error'))
          else entry.resolve(msg.result)
        }
      })
    })
    await sendRaw({
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'hive-memory-curator', version: '0.1.0' },
      },
    })
    socket.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} }) + '\n')
    initialized = true
  }

  async function callWriteTool(name, args = {}) {
    if (name !== 'memory_lookup_prior' && name !== 'memory_submit') {
      throw new Error(`refusing non-writer tool in curator write client: ${name}`)
    }
    await ensureConnected()
    const res = await sendRaw({
      method: 'tools/call',
      params: { name, arguments: args },
    })
    const text = res?.content?.[0]?.text || '{}'
    return JSON.parse(text)
  }

  return { callWriteTool, close: disconnect }
}

export const DEFAULT_DREAM_INTERVAL_SEC = 6 * 3600
export const DEFAULT_WRITE_DELTA_THRESHOLD = 20
export const DEFAULT_TOPIC_PRESSURE_THRESHOLD = 8
export const NIGHTMARE_REFUSAL_WINDOW_SEC = 900
export const NIGHTMARE_REFUSAL_THRESHOLD = 3

const STOPWORDS = new Set([
  'the', 'and', 'for', 'with', 'that', 'this', 'from', 'into', 'over', 'under', 'after', 'before',
  'are', 'was', 'were', 'has', 'have', 'had', 'not', 'but', 'all', 'any', 'can', 'will', 'just',
  'now', 'only', 'when', 'where', 'which', 'who', 'whom', 'whose', 'why', 'how', 'than', 'then',
  'its', 'our', 'their', 'his', 'her', 'your', 'via', 'per', 'out', 'off', 'onto', 'upon',
  'claim', 'claims', 'memory', 'hive', 'room', 'scope', 'status', 'active', 'ready',
])

function tokenize(text) {
  return new Set(
    String(text || '')
      .toLowerCase()
      .replace(/[^a-z0-9#-]+/g, ' ')
      .split(/\s+/)
      .filter(w => w.length >= 3 && !STOPWORDS.has(w))
  )
}

export function tokenJaccard(aText, bText) {
  const a = tokenize(aText)
  const b = tokenize(bText)
  if (!a.size || !b.size) return 0
  let inter = 0
  for (const w of a) if (b.has(w)) inter += 1
  const union = a.size + b.size - inter
  return union > 0 ? inter / union : 0
}

function extractWorkSubject(rec) {
  const combined = `${rec.d || ''} ${rec.claim || ''} ${(rec.evidence || []).join(' ')}`
  const prMatch = combined.match(/(?:\bpr[-_\s#]*|\bpull\/|\bissue[-_\s#]*)(\d{1,6})\b/i)
  if (prMatch) return `pr${prMatch[1]}`
  const parsed = parseFactKey(rec.d)
  const rawSlug = parsed?.slug || String(rec.d || '').split(':').pop() || 'item'
  const stripped = rawSlug
    .replace(/-(?:review-status|ready-status|release-hold|review|status|owner|wip|handoff|merged|deployed|fix|v\d+)$/g, '')
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return stripped || 'cluster'
}

function sanitizeSlugPart(str) {
  return String(str || '')
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'cluster'
}

const CORE_EIGEN_TOPICS = new Set([
  'herd-infra',
  'hive-memory',
  'r1',
  'illustrated-primer',
  'nvoy',
  'waggle',
  'buzz',
  'hive',
])

function extractClaimFeatures(rec) {
  const weights = new Map()
  const add = (feat, w) => {
    if (!feat) return
    weights.set(feat, (weights.get(feat) || 0) + w)
  }
  const tokens = tokenize(`${rec.claim || ''} ${rec.because || ''}`)
  for (const tok of tokens) {
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(tok) || /^[0-9a-f]{12,}$/i.test(tok)) continue
    add(tok, 1.0)
  }

  const gitStr = `${rec.as_of_git || ''} ${(Array.isArray(rec.evidence) ? rec.evidence : []).join(' ')}`
  const repoMatches = gitStr.match(/\b(nvoy|rabidrabbit|herd-infra|waggle)(?=@)/gi) || []
  for (const rm of repoMatches) add(`repo:${rm.toLowerCase()}`, 2.4)

  const pathMatches = gitStr.match(/\b(?:tools\/[a-z0-9_-]+|mcp\/tools|WONDER_LAB|r1-primer|illustrated-primer|xochitl)\b/gi) || []
  for (const pm of pathMatches) add(`path:${pm.toLowerCase()}`, 2.0)

  const subj = extractWorkSubject(rec)
  if (subj && subj !== 'cluster' && subj !== 'item') add(`subj:${subj}`, 1.8)
  return weights
}

// Computes the spectral principal components (eigenvectors + eigenvalues) of the active memory store's
// topic-by-feature space via Power Iteration with Hotelling Deflation, and identifies fragmented or
// mis-tagged topics that should reorganize into canonical eigen-topics during Dreaming.
export function computeTopicEigenvectors(records = [], { maxComponents = 7 } = {}) {
  const active = (Array.isArray(records) ? records : []).filter(
    r => r && r.verification !== 'withdrawn' && r.status !== 'withdrawn' && r.scope !== 'hive:canon'
  )
  if (active.length === 0) {
    return { eigenvectors: [], topic_map: {}, reorganizations: [], total_variance: 0 }
  }

  // 1. Build document frequency for IDF weighting and group claims by raw topic
  const docFreq = new Map()
  const claimFeatures = new Map()
  const rawTopicGroups = new Map()

  for (const r of active) {
    const feats = extractClaimFeatures(r)
    claimFeatures.set(r.event_id || r.d, feats)
    for (const f of feats.keys()) {
      docFreq.set(f, (docFreq.get(f) || 0) + 1)
    }
    const rawTop = String(r.topic || 'untagged').trim()
    if (!rawTopicGroups.has(rawTop)) rawTopicGroups.set(rawTop, [])
    rawTopicGroups.get(rawTop).push(r)
  }

  const N = active.length
  const vocab = [...docFreq.entries()]
    .filter(([f, df]) => df >= 2 || f.startsWith('repo:') || f.startsWith('path:'))
    .map(([f]) => f)
    .sort()
  const vocabIndex = new Map(vocab.map((f, i) => [f, i]))
  const F = vocab.length

  const rawTopics = [...rawTopicGroups.keys()].sort((a, b) => {
    const diff = rawTopicGroups.get(b).length - rawTopicGroups.get(a).length
    return diff !== 0 ? diff : a.localeCompare(b)
  })
  const T = rawTopics.length

  if (F === 0 || T === 0) {
    return { eigenvectors: [], topic_map: {}, reorganizations: [], total_variance: 0 }
  }

  // 2. Build L2-normalized TF-IDF centroid vectors per topic: V[t][f]
  const V = Array.from({ length: T }, () => new Float64Array(F))
  const topicCounts = new Float64Array(T)

  for (let ti = 0; ti < T; ti++) {
    const top = rawTopics[ti]
    const group = rawTopicGroups.get(top)
    topicCounts[ti] = group.length
    const vec = V[ti]
    for (const r of group) {
      const feats = claimFeatures.get(r.event_id || r.d)
      if (!feats) continue
      for (const [f, w] of feats.entries()) {
        const fi = vocabIndex.get(f)
        if (fi === undefined) continue
        const idf = Math.log(1 + N / Math.max(1, docFreq.get(f) || 1))
        vec[fi] += w * idf
      }
    }
    let norm = 0
    for (let fi = 0; fi < F; fi++) norm += vec[fi] * vec[fi]
    norm = Math.sqrt(norm) || 1
    for (let fi = 0; fi < F; fi++) vec[fi] /= norm
  }

  // 3. Build mass-weighted symmetric Topic Covariance Matrix C[i][j] = sqrt(n_i * n_j) * <V[i], V[j]>
  const C = Array.from({ length: T }, () => new Float64Array(T))
  let totalTrace = 0
  for (let i = 0; i < T; i++) {
    for (let j = i; j < T; j++) {
      let dot = 0
      for (let fi = 0; fi < F; fi++) dot += V[i][fi] * V[j][fi]
      const val = Math.sqrt(topicCounts[i] * topicCounts[j]) * dot
      C[i][j] = val
      C[j][i] = val
      if (i === j) totalTrace += val
    }
  }

  // 4. Power Iteration + Hotelling Deflation to extract top K eigenvectors of C
  const K = Math.min(maxComponents, T)
  const W = C.map(row => Float64Array.from(row))
  const eigenvectors = []
  const usedCanonical = new Set()

  for (let k = 0; k < K; k++) {
    // Seed with row having largest remaining diagonal mass
    let bestSeed = 0
    let bestDiag = -1
    for (let i = 0; i < T; i++) {
      if (W[i][i] > bestDiag) {
        bestDiag = W[i][i]
        bestSeed = i
      }
    }
    if (bestDiag <= 1e-6) break

    let u = new Float64Array(T)
    u[bestSeed] = 1
    let lambda = 0

    for (let iter = 0; iter < 45; iter++) {
      const next = new Float64Array(T)
      for (let i = 0; i < T; i++) {
        let s = 0
        for (let j = 0; j < T; j++) s += W[i][j] * u[j]
        next[i] = s
      }
      let norm = 0
      for (let i = 0; i < T; i++) norm += next[i] * next[i]
      norm = Math.sqrt(norm)
      if (norm <= 1e-9) break
      lambda = norm
      for (let i = 0; i < T; i++) u[i] = next[i] / norm
    }

    if (lambda <= 1e-5) break
    // Orient sign convention so the highest-magnitude unused core topic (or overall max) is positive
    let anchorIdx = -1
    for (let i = 0; i < T; i++) {
      const normTop = normalizeMemoryTopic(rawTopics[i])
      if (normTop && CORE_EIGEN_TOPICS.has(normTop) && !usedCanonical.has(normTop)) {
        if (anchorIdx < 0 || Math.abs(u[i]) > Math.abs(u[anchorIdx])) anchorIdx = i
      }
    }
    if (anchorIdx < 0) {
      anchorIdx = 0
      for (let i = 1; i < T; i++) {
        if (Math.abs(u[i]) > Math.abs(u[anchorIdx])) anchorIdx = i
      }
    }
    if (u[anchorIdx] < 0) {
      for (let i = 0; i < T; i++) u[i] = -u[i]
    }

    // Deflate W <- W - lambda * u * u^T
    for (let i = 0; i < T; i++) {
      for (let j = 0; j < T; j++) {
        W[i][j] -= lambda * u[i] * u[j]
      }
    }

    // Compute feature-space eigenvector projection: f_vec = sum_t (u[t] * sqrt(n_t) * V[t])
    const fVec = new Float64Array(F)
    for (let ti = 0; ti < T; ti++) {
      if (u[ti] <= 0) continue
      const scale = u[ti] * Math.sqrt(topicCounts[ti])
      for (let fi = 0; fi < F; fi++) fVec[fi] += scale * V[ti][fi]
    }
    const topFeatures = []
    for (let fi = 0; fi < F; fi++) {
      if (fVec[fi] > 0.01) topFeatures.push({ feature: vocab[fi], weight: Math.round(fVec[fi] * 1000) / 1000 })
    }
    topFeatures.sort((a, b) => b.weight - a.weight)

    const loadings = []
    for (let ti = 0; ti < T; ti++) {
      if (Math.abs(u[ti]) >= 0.04) {
        loadings.push({
          topic: rawTopics[ti],
          count: topicCounts[ti],
          loading: Math.round(u[ti] * 1000) / 1000,
        })
      }
    }
    loadings.sort((a, b) => Math.abs(b.loading) - Math.abs(a.loading))

    // Pick the canonical topic name for this eigen-mode
    const primaryLoading =
      loadings.find(l => l.loading > 0 && CORE_EIGEN_TOPICS.has(normalizeMemoryTopic(l.topic)) && !usedCanonical.has(normalizeMemoryTopic(l.topic))) ||
      loadings.find(l => l.loading > 0 && normalizeMemoryTopic(l.topic)) ||
      loadings[0]
    const canonicalTopic = normalizeMemoryTopic(primaryLoading?.topic) || primaryLoading?.topic || `eigen-${k + 1}`
    usedCanonical.add(canonicalTopic)

    eigenvectors.push({
      axis: k + 1,
      canonical_topic: canonicalTopic,
      eigenvalue: Math.round(lambda * 100) / 100,
      variance_pct: totalTrace > 0 ? Math.round((lambda / totalTrace) * 1000) / 10 : 0,
      topic_loadings: loadings.slice(0, 6),
      top_features: topFeatures.slice(0, 8).map(x => x.feature),
    })
  }

  // 5. Build Topic Normalization Map & Reorganization Recommendations:
  // Map fragmented/alias/outlier topics (count <= 3 or non-core) onto their highest-affinity core topic
  const coreIndices = []
  for (let ti = 0; ti < T; ti++) {
    const norm = normalizeMemoryTopic(rawTopics[ti])
    if (norm && rawTopics[ti] === norm && CORE_EIGEN_TOPICS.has(norm)) {
      coreIndices.push(ti)
    }
  }

  const topicMap = {}
  const reorganizations = []

  for (let ti = 0; ti < T; ti++) {
    const rawTop = rawTopics[ti]
    const aliasNorm = normalizeMemoryTopic(rawTop)
    if (coreIndices.includes(ti)) {
      topicMap[rawTop] = rawTop
      continue
    }
    // Check cosine similarity against all core topic centroids (require strictly positive affinity)
    let bestCoreTopic = null
    let bestCosine = 0
    let sharedBasis = []

    for (const ci of coreIndices) {
      let cos = 0
      const shared = []
      for (let fi = 0; fi < F; fi++) {
        const prod = V[ti][fi] * V[ci][fi]
        if (prod > 0) {
          cos += prod
          shared.push({ feature: vocab[fi], prod })
        }
      }
      if (cos > bestCosine) {
        bestCosine = cos
        bestCoreTopic = rawTopics[ci]
        shared.sort((a, b) => b.prod - a.prod)
        sharedBasis = shared.slice(0, 5).map(s => s.feature)
      }
    }

    const isKnownCoreAlias = Boolean(aliasNorm && aliasNorm !== rawTop && CORE_EIGEN_TOPICS.has(aliasNorm))
    const targetTopic = isKnownCoreAlias
      ? aliasNorm
      : bestCosine > 0 && bestCoreTopic
        ? bestCoreTopic
        : rawTop

    topicMap[rawTop] = targetTopic
    if (targetTopic !== rawTop && (isKnownCoreAlias || bestCosine > 0)) {
      const group = rawTopicGroups.get(rawTop) || []
      reorganizations.push({
        from_topic: rawTop,
        to_topic: targetTopic,
        claim_count: group.length,
        cosine_affinity: Math.round(Math.max(0, bestCosine) * 1000) / 1000,
        shared_features: sharedBasis,
        event_ids: group.map(r => r.event_id).filter(Boolean),
      })
    }
  }

  return {
    eigenvectors,
    topic_map: topicMap,
    reorganizations,
    total_variance: Math.round(totalTrace * 100) / 100,
  }
}

// Evaluates the 3 Dream & Nightmare triggers against current store state and telemetry.
export function evaluateDreamTriggers({
  records = [],
  storeState = {},
  recentActivity = [],
  coherence = null,
  lastCuratedAt = 0,
  lastCuratedWriteSeq = 0,
  nowSec = Math.floor(Date.now() / 1000),
  dreamIntervalSec = DEFAULT_DREAM_INTERVAL_SEC,
  writeDeltaThreshold = DEFAULT_WRITE_DELTA_THRESHOLD,
  topicPressureThreshold = DEFAULT_TOPIC_PRESSURE_THRESHOLD,
} = {}) {
  const active = (Array.isArray(records) ? records : []).filter(
    r => r && r.verification === 'accepted' && r.status !== 'withdrawn'
  )
  const earliestCreated = active.reduce(
    (min, r) => (typeof r.created_at === 'number' && r.created_at > 0 && r.created_at < min ? r.created_at : min),
    Infinity
  )
  const hasCuratedBaseline = Number(lastCuratedAt || 0) > 0 || Number.isFinite(earliestCreated)
  const baselineTime = Number(lastCuratedAt || 0) > 0
    ? Number(lastCuratedAt)
    : Number.isFinite(earliestCreated)
      ? earliestCreated
      : nowSec
  const elapsedSec = Math.max(0, nowSec - baselineTime)
  const circadianDream = hasCuratedBaseline ? elapsedSec >= dreamIntervalSec : false

  const writeSeq = Number(storeState?.write_seq || 0)
  const writeDelta = Math.max(0, writeSeq - Number(lastCuratedWriteSeq || 0))

  const byScopeTopic = new Map()
  const conflictedKeys = new Set()
  const staleRecords = []

  for (const r of active) {
    if (r.conflict && r.d) conflictedKeys.add(r.d)
    if (r.stale_warning) staleRecords.push(r.d || r.event_id)
    if (r.scope !== 'hive:canon' && r.expires_at !== null && r.expires_at !== undefined) {
      const sc = String(r.scope || 'unknown')
      const top = normalizeMemoryTopic(r.topic) || String(r.topic || 'general')
      const key = `${sc} · #${top}`
      const cur = byScopeTopic.get(key) || { scope: sc, topic: top, label: key, count: 0 }
      cur.count += 1
      byScopeTopic.set(key, cur)
    }
  }

  const hasNewWritesSinceCurate = Number(lastCuratedWriteSeq || 0) === 0 || writeDelta > 0
  const hotScopeTopics = hasNewWritesSinceCurate
    ? [...byScopeTopic.values()]
        .filter(x => x.count > topicPressureThreshold)
        .sort((a, b) => b.count - a.count)
    : []

  const synapticVolume = hasNewWritesSinceCurate && (writeDelta >= writeDeltaThreshold || hotScopeTopics.length > 0)

  const refusalCount15m = (Array.isArray(recentActivity) ? recentActivity : []).filter(
    a => a && a.kind === 'refused' && typeof a.at === 'number' && Math.max(0, nowSec - a.at) <= NIGHTMARE_REFUSAL_WINDOW_SEC
  ).length

  const actArr = Array.isArray(recentActivity) ? recentActivity : []
  const zeroHitQueries15m = actArr.filter((a, idx) => {
    if (!a || a.kind !== 'query' || a.count !== 0 || !a.topic) return false
    if (a.actor === 'curator' || a.actor === 'viewer') return false
    if (typeof a.at === 'number' && Math.max(0, nowSec - a.at) > NIGHTMARE_REFUSAL_WINDOW_SEC) return false
    const resolvedSoon = actArr.slice(idx + 1, idx + 12).some(
      next =>
        next &&
        next.actor === a.actor &&
        ((next.kind === 'query' && Number(next.count) > 0) ||
          (next.kind === 'submit' && next.accepted !== false))
    )
    return !resolvedSoon
  }).length
  const epistemicBlindSpot =
    zeroHitQueries15m >= 2 || coherence?.epistemic_drift?.status === 'blind_spot'

  const coherenceScore =
    typeof coherence === 'number'
      ? coherence
      : typeof coherence?.score === 'number' && (coherence.total_events === undefined || coherence.total_events > 0)
        ? coherence.score
        : null
  const isHealthyComputedBaseline =
    coherence &&
    typeof coherence === 'object' &&
    coherence.axes &&
    !epistemicBlindSpot &&
    Number(coherence.delta_since_inception || 0) >= -5 &&
    Number(coherence.axes.grounding || 0) >= 80 &&
    Number(coherence.axes.alignment || 0) >= 50
  const coherenceAlert = coherenceScore !== null && coherenceScore < 70 && !isHealthyComputedBaseline

  const nightmareInterrupt =
    conflictedKeys.size > 0 ||
    staleRecords.length > 0 ||
    refusalCount15m >= NIGHTMARE_REFUSAL_THRESHOLD ||
    epistemicBlindSpot ||
    coherenceAlert

  const reasons = []
  if (circadianDream) reasons.push(`circadian_dream: ${elapsedSec}s elapsed (>= ${dreamIntervalSec}s)`)
  if (writeDelta >= writeDeltaThreshold) reasons.push(`synaptic_volume: +${writeDelta} writes since last curate (>= ${writeDeltaThreshold})`)
  if (hotScopeTopics.length > 0) {
    reasons.push(`synaptic_volume: ${hotScopeTopics.map(h => `${h.label} (${h.count} Class A)`).join(', ')} > ${topicPressureThreshold}`)
  }
  if (conflictedKeys.size > 0) reasons.push(`nightmare_conflict: ${conflictedKeys.size} conflicted fact key(s)`)
  if (staleRecords.length > 0) reasons.push(`nightmare_stale_git: ${staleRecords.length} stale git anchor(s)`)
  if (refusalCount15m >= NIGHTMARE_REFUSAL_THRESHOLD) reasons.push(`nightmare_refusal_spike: ${refusalCount15m} gate refusals in 15m`)
  if (epistemicBlindSpot) {
    reasons.push(
      `nightmare_epistemic_drift: ${zeroHitQueries15m} zero-hit memory queries in 15m (status=${coherence?.epistemic_drift?.status || 'blind_spot'})`
    )
  }
  if (coherenceAlert) reasons.push(`nightmare_coherence_drop: score ${coherenceScore}% (< 70%)`)

  return {
    shouldRun: circadianDream || synapticVolume || nightmareInterrupt,
    triggers: {
      circadian_dream: circadianDream,
      synaptic_volume: synapticVolume,
      nightmare_interrupt: nightmareInterrupt,
    },
    reasons,
    elapsed_sec: elapsedSec,
    write_delta: writeDelta,
    hot_scope_topics: hotScopeTopics,
    conflicted_keys: [...conflictedKeys],
    stale_count: staleRecords.length,
    refusal_count_15m: refusalCount15m,
    zero_hit_queries_15m: zeroHitQueries15m,
    coherence_score: coherenceScore,
  }
}

// Checks whether claim B has direct causal provenance superseding claim A.
function causallySupersedes(b, a, gitAncestryCheck = null) {
  if (!b || !a || b.event_id === a.event_id) return false
  if ((b.created_at || 0) < (a.created_at || 0)) return false
  const bSupersedes = Array.isArray(b.supersedes) ? b.supersedes : []
  if (bSupersedes.includes(a.event_id)) return true
  if (b.as_of_evt && b.as_of_evt === a.event_id) return true
  const bEv = Array.isArray(b.evidence) ? b.evidence : []
  if (bEv.some(e => String(e).includes(a.event_id))) return true
  if ((b.created_at || 0) > (a.created_at || 0) && a.as_of_git && b.as_of_git && a.as_of_git === b.as_of_git) {
    const aEv = new Set(Array.isArray(a.evidence) ? a.evidence : [])
    if (bEv.some(e => aEv.has(e))) return true
  }
  if (typeof gitAncestryCheck === 'function' && a.as_of_git && b.as_of_git && a.as_of_git !== b.as_of_git) {
    if (gitAncestryCheck(a.as_of_git, b.as_of_git) === true) return true
  }
  return false
}

// Plans a complete Merkle Dreaming & Curation pass over visible active records:
//   - Stage 1: Distillations (many Class A -> 1 curated Class A claim with merkle_sources)
//   - Stage 2: Promotions (settled/multi-author Class A -> durable Class B decision with merkle_sources)
//   - Stage 3: Solidifications (converged Class B -> hive:canon owner nomination with merkle_sources)
//   - Nightmares: deterministic auto-resolutions + owner escalations for ambiguous conflicts
export function planMerkleDream({
  records = [],
  curatorPubkey,
  memoryGlobalChannelId = '',
  nowSec = Math.floor(Date.now() / 1000),
  gitAncestryCheck = null,
} = {}) {
  const cleanCuratorPk = String(curatorPubkey || '').toLowerCase()
  const active = (Array.isArray(records) ? records : []).filter(
    r => r && r.verification === 'accepted' && r.status !== 'withdrawn' && typeof r.event_id === 'string'
  )

  const nightmares = []
  const conflictedFactKeys = new Set()

  // 1. Inspect conflicts per (scope, d)
  const byFactKey = new Map()
  for (const r of active) {
    const key = `${r.scope}::${r.d}`
    if (!byFactKey.has(key)) byFactKey.set(key, [])
    byFactKey.get(key).push(r)
  }

  for (const [, group] of byFactKey.entries()) {
    const distinctClaims = new Set(group.map(r => String(r.claim || '').trim()))
    if (group.length > 1 && distinctClaims.size > 1) {
      const sample = group[0]
      conflictedFactKeys.add(sample.d)
      const sorted = [...group].sort((a, b) => (b.created_at || 0) - (a.created_at || 0))
      const newest = sorted[0]
      const older = sorted.slice(1)
      const deterministic = older.every(old => causallySupersedes(newest, old, gitAncestryCheck))

      if (deterministic && sample.scope !== 'hive:canon') {
        const sourceIds = sorted.map(r => r.event_id).sort()
        const merkleRoot = computeSourceMerkleRoot(sourceIds)
        const topic = normalizeMemoryTopic(newest.topic) || 'hive-memory'
        const subj = sanitizeSlugPart(extractWorkSubject(newest))
        const slug = `curated-${topic}-${subj}-resolved`
        const mergedEvidence = [...new Set(sorted.flatMap(r => Array.isArray(r.evidence) ? r.evidence : []))].slice(0, 24)
        const maxCreated = Math.max(...sorted.map(r => r.created_at || 0))
        const template = cleanCuratorPk
          ? buildClaimTemplate({
              pubkey: cleanCuratorPk,
              scope: sample.scope,
              slug,
              topic,
              claim: newest.claim,
              because: `Merkle Dreaming auto-resolved causal conflict at ${sample.d} in favor of ${newest.event_id.slice(0, 12)} (${newest.because || 'causal descendant'}).`,
              evidence: mergedEvidence.length ? mergedEvidence : [newest.event_id],
              asOfGit: newest.as_of_git || null,
              asOfEvt: newest.as_of_git ? null : newest.event_id,
              ttlSec: newest.expires_at == null ? 0 : DEFAULT_TTL_SEC,
              supersedes: sourceIds,
              merkleSources: true,
              memoryGlobalChannelId,
              nowSec,
              priorCreatedAt: maxCreated,
            })
          : null
        nightmares.push({
          kind: 'conflict',
          action: 'auto_resolve',
          scope: sample.scope,
          d: sample.d,
          winner_event_id: newest.event_id,
          source_event_ids: sourceIds,
          merkle_sources: merkleRoot,
          template,
        })
      } else {
        const sourceIds = sorted.map(r => r.event_id)
        const authors = [...new Set(sorted.map(r => r.author_pubkey))]
        nightmares.push({
          kind: 'conflict',
          action: 'escalate_to_owner',
          scope: sample.scope,
          d: sample.d,
          conflicting_event_ids: sourceIds,
          authors,
          channel: memoryGlobalChannelId || null,
          mentions: ['james', 'mydude'],
          message: `NIGHTMARE ESCALATION (@james @mydude): Ambiguous cross-author memory conflict at \`${sample.d}\` in \`${sample.scope}\` (${sorted.length} competing claims: ${sorted.map(r => `${r.event_id.slice(0, 10)} by ${String(r.author_pubkey).slice(0, 8)} ["${String(r.claim).slice(0, 80)}"]`).join(' vs. ')}). No strict causal/git ordering found; Curator withheld auto-consolidation pending owner resolution.`,
        })
      }
    }
  }

  // Flag stale git anchors as nightmare warnings
  for (const r of active) {
    if (r.stale_warning) {
      nightmares.push({
        kind: 'stale_git_anchor',
        action: 'stale_anchor_warning',
        scope: r.scope,
        d: r.d,
        event_id: r.event_id,
        as_of_git: r.as_of_git,
        stale_warning: r.stale_warning,
      })
    }
  }

  // 2. Stage 0: Spectral Topic Eigenvector Analysis & Topic Normalization
  const spectral = computeTopicEigenvectors(active)
  const resolveEigenTopic = rawTopic => {
    const trimmed = String(rawTopic || '').trim()
    return spectral.topic_map[trimmed] || normalizeMemoryTopic(trimmed) || 'hive-memory'
  }

  // 3. Group non-conflicted Class A claims by (scope, eigen-topic, subject/similarity) for Stage 1 (Distillation) & Stage 2 (Promotion)
  const distillations = []
  const promotions = []
  const classAByScopeTopic = new Map()

  for (const r of active) {
    if (r.scope === 'hive:canon') continue
    if (conflictedFactKeys.has(r.d)) continue
    // Skip claims already authored by Curator so Curator doesn't re-curate its own solitary summary
    if (cleanCuratorPk && r.author_pubkey === cleanCuratorPk && String(r.d || '').includes(':curated-')) continue
    if (r.expires_at !== null && r.expires_at !== undefined) {
      const sc = String(r.scope || '')
      const top = resolveEigenTopic(r.topic)
      const key = `${sc}::${top}`
      if (!classAByScopeTopic.has(key)) classAByScopeTopic.set(key, { scope: sc, topic: top, items: [] })
      classAByScopeTopic.get(key).items.push(r)
    }
  }

  for (const { scope, topic, items } of classAByScopeTopic.values()) {
    if (items.length < 2) continue
    // Cluster items within (scope, topic) by shared work subject (e.g. pr336) or token Jaccard >= 0.42
    const clusters = []
    for (const item of items) {
      const subj = extractWorkSubject(item)
      let placed = false
      for (const cl of clusters) {
        if (cl.subject === subj || cl.members.some(m => tokenJaccard(`${m.d} ${m.claim}`, `${item.d} ${item.claim}`) >= 0.42)) {
          cl.members.push(item)
          placed = true
          break
        }
      }
      if (!placed) clusters.push({ subject: subj, members: [item] })
    }

    for (const cl of clusters) {
      if (cl.members.length < 2) continue
      const sorted = [...cl.members].sort((a, b) => (b.created_at || 0) - (a.created_at || 0) || (a.event_id < b.event_id ? -1 : 1))
      const head = sorted[0]
      const sourceIds = sorted.map(r => r.event_id).sort()
      const merkleRoot = computeSourceMerkleRoot(sourceIds)
      const distinctAuthors = new Set(sorted.map(r => r.author_pubkey))
      const mergedEvidence = [...new Set(sorted.flatMap(r => Array.isArray(r.evidence) ? r.evidence : []))].slice(0, 24)
      const anyStale = sorted.some(r => Boolean(r.stale_warning))
      const nonWorkflowCount = sorted.filter(r => !isWorkflowSlug(parseFactKey(r.d)?.slug)).length
      const maxCreated = Math.max(...sorted.map(r => r.created_at || 0))
      const cleanSubj = sanitizeSlugPart(cl.subject)
      const reorganizedFromTopics = [
        ...new Set(sorted.map(r => String(r.topic || '').trim()).filter(t => t && t !== topic)),
      ]

      // Stage 2 Promotion criterion: >=2 distinct authors (or >=3 non-workflow claims with >=3 evidence citations)
      // and at least one non-workflow claim with zero stale warnings -> Promote to Class B Durable Decision!
      const shouldPromote = !anyStale && nonWorkflowCount >= 1 && (distinctAuthors.size >= 2 || (nonWorkflowCount >= 2 && mergedEvidence.length >= 3))

      if (shouldPromote) {
        const slug = `decision-${topic}-${cleanSubj}`.slice(0, 120)
        const synthesizedClaim = `${head.claim} [Curated Class B decision from ${sorted.length} claims across ${distinctAuthors.size} author(s)]`
        const synthesizedBecause = `Promoted to Class B durable decision by Merkle Dreaming: ${sorted.length} converging claims (${sourceIds.map(id => id.slice(0, 8)).join(', ')}) established settled state in ${topic}. Latest rationale: ${head.because}`
        const template = cleanCuratorPk
          ? buildClaimTemplate({
              pubkey: cleanCuratorPk,
              scope,
              slug,
              topic,
              claim: synthesizedClaim.slice(0, 1950),
              because: synthesizedBecause.slice(0, 1950),
              evidence: mergedEvidence.length ? mergedEvidence : [head.event_id],
              asOfGit: head.as_of_git || null,
              asOfEvt: head.as_of_git ? null : head.event_id,
              ttlSec: 0,
              supersedes: sourceIds,
              merkleSources: true,
              memoryGlobalChannelId,
              nowSec,
              priorCreatedAt: maxCreated,
            })
          : null

        promotions.push({
          stage: 'promotion',
          scope,
          topic,
          reorganized_from_topics: reorganizedFromTopics,
          slug,
          subject: cl.subject,
          source_event_ids: sourceIds,
          author_count: distinctAuthors.size,
          merkle_sources: merkleRoot,
          claim: synthesizedClaim.slice(0, 1950),
          template,
        })
      } else {
        // Stage 1 Distillation: fold noisy Class A trail / workflow checkpoints into 1 curated Class A claim
        const slug = `curated-${topic}-${cleanSubj}`.slice(0, 120)
        const synthesizedClaim = `${head.claim} [Distilled from ${sorted.length} Class A claims]`
        const synthesizedBecause = `Distilled ${sorted.length} Class A claims in #${topic} (${sourceIds.map(id => id.slice(0, 8)).join(', ')}). Latest rationale: ${head.because}`
        const template = cleanCuratorPk
          ? buildClaimTemplate({
              pubkey: cleanCuratorPk,
              scope,
              slug,
              topic,
              claim: synthesizedClaim.slice(0, 1950),
              because: synthesizedBecause.slice(0, 1950),
              evidence: mergedEvidence.length ? mergedEvidence : [head.event_id],
              asOfGit: head.as_of_git || null,
              asOfEvt: head.as_of_git ? null : head.event_id,
              ttlSec: DEFAULT_TTL_SEC,
              supersedes: sourceIds,
              merkleSources: true,
              memoryGlobalChannelId,
              nowSec,
              priorCreatedAt: maxCreated,
            })
          : null

        distillations.push({
          stage: 'distillation',
          scope,
          topic,
          reorganized_from_topics: reorganizedFromTopics,
          slug,
          subject: cl.subject,
          source_event_ids: sourceIds,
          author_count: distinctAuthors.size,
          merkle_sources: merkleRoot,
          claim: synthesizedClaim.slice(0, 1950),
          template,
        })
      }
    }
  }

  // 4. Stage 3: Solidification — Nominate high-convergence Class B decisions for `hive:canon`
  const solidifications = []
  const classBByTopic = new Map()
  for (const r of active) {
    if (r.scope === 'hive:canon' || conflictedFactKeys.has(r.d) || r.stale_warning) continue
    if (r.expires_at === null || r.expires_at === undefined || r.retention === 'decision') {
      const top = resolveEigenTopic(r.topic)
      if (!classBByTopic.has(top)) classBByTopic.set(top, [])
      classBByTopic.get(top).push(r)
    }
  }

  for (const [topic, decisions] of classBByTopic.entries()) {
    const authors = new Set(decisions.map(r => r.author_pubkey))
    const allSuperseded = decisions.flatMap(r => Array.isArray(r.supersedes) ? r.supersedes : [])
    const totalSupport = decisions.length + allSuperseded.length
    if (authors.size >= 3 || (decisions.length >= 2 && totalSupport >= 4)) {
      const sorted = [...decisions].sort((a, b) => (b.created_at || 0) - (a.created_at || 0))
      const head = sorted[0]
      const sourceIds = [...new Set([...sorted.map(r => r.event_id), ...allSuperseded])].sort()
      const merkleRoot = computeSourceMerkleRoot(sourceIds)
      const mergedEvidence = [...new Set(sorted.flatMap(r => Array.isArray(r.evidence) ? r.evidence : []))].slice(0, 24)
      const canonSlug = `canon-${topic}-${sanitizeSlugPart(extractWorkSubject(head))}`.slice(0, 100)
      solidifications.push({
        stage: 'solidification',
        target_scope: 'hive:canon',
        topic,
        slug: canonSlug,
        d: `hive-memory:hive:canon:${canonSlug}`,
        claim: head.claim,
        because: `Solidified across ${authors.size} author(s) and ${sourceIds.length} supporting memory events in #${topic}: ${head.because}`,
        evidence: mergedEvidence,
        as_of_git: head.as_of_git || null,
        as_of_evt: head.as_of_evt || head.event_id,
        source_event_ids: sourceIds,
        merkle_sources: merkleRoot,
        requires_owner_signature: true,
      })
    }
  }

  return {
    planned_at: nowSec,
    topic_eigenvectors: spectral.eigenvectors,
    topic_reorganizations: spectral.reorganizations,
    distillations,
    promotions,
    solidifications,
    nightmares,
    summary: {
      topic_eigenvectors: spectral.eigenvectors.length,
      topic_reorganizations: spectral.reorganizations.length,
      distillations: distillations.length,
      promotions: promotions.length,
      solidifications: solidifications.length,
      nightmares_auto_resolved: nightmares.filter(n => n.action === 'auto_resolve').length,
      nightmares_escalated: nightmares.filter(n => n.action === 'escalate_to_owner').length,
      stale_warnings: nightmares.filter(n => n.action === 'stale_anchor_warning').length,
    },
  }
}

// Formats a concise, structured Curatorial Dream Briefing for @curator to post on Nvoy channels (#waggle-test / #hive-ops).
export function formatCuratorBriefing({
  cycleStatus = 'idle',
  triggers = null,
  plan = null,
  submitted = [],
  refused = [],
  coherence = null,
  lastCuratedWriteSeq = 0,
  nextCuratedWriteSeq = 0,
} = {}) {
  const lines = []
  const cohScore = coherence && typeof coherence.score === 'number' ? `${coherence.score.toFixed(1)}%` : 'n/a'
  const edStatus = coherence?.epistemic_drift?.status ? String(coherence.epistemic_drift.status).toUpperCase() : 'ALIGNED'
  const reasons = Array.isArray(triggers?.reasons) && triggers.reasons.length ? triggers.reasons.join(', ') : 'manual/scheduled inspection'

  lines.push(`🧠 **MERKLE DREAMING CURATOR BRIEFING** · status=\`${cycleStatus}\` · seq \`${lastCuratedWriteSeq} -> ${nextCuratedWriteSeq}\` · Coherence 2.0: **${cohScore}** (\`${edStatus}\`)`)
  lines.push(`- **Triggers Evaluated:** ${reasons}`)

  const eigens = Array.isArray(plan?.topic_eigenvectors) ? plan.topic_eigenvectors : []
  const reorgs = Array.isArray(plan?.topic_reorganizations) ? plan.topic_reorganizations : []
  if (eigens.length > 0) {
    const topAxes = eigens.slice(0, 4).map(e => `λ${e.axis} \`#${e.canonical_topic}\` (${e.variance_pct}%)`).join(', ')
    const reorgStr = reorgs.length > 0
      ? ` | Reorganized ${reorgs.length} outlier topic(s): ${reorgs.slice(0, 5).map(r => `\`#${r.from_topic} -> #${r.to_topic}\``).join(', ')}`
      : ''
    lines.push(`- **Stage 0 (Spectral Topic PCA):** ${topAxes}${reorgStr}`)
  }

  const proms = Array.isArray(plan?.promotions) ? plan.promotions : []
  const dists = Array.isArray(plan?.distillations) ? plan.distillations : []
  const totalSources = [...proms, ...dists].reduce((acc, x) => acc + (Array.isArray(x.source_event_ids) ? x.source_event_ids.length : 0), 0)
  lines.push(
    `- **Stage 1 & 2 (Distillation & Promotion):** ${proms.length} Class B Decision Promotion(s) + ${dists.length} Class A Distillation(s) across ${totalSources} source claims (${submitted.length} submitted${refused.length ? `, ${refused.length} refused` : ''})`
  )

  const solids = Array.isArray(plan?.solidifications) ? plan.solidifications : []
  if (solids.length > 0) {
    lines.push(
      `- **Stage 3 (Canon Nominations for @james):** ${solids.length} converged Class B topic(s) ready for \`hive:canon\`: ${solids.slice(0, 4).map(s => `\`${s.d}\` (merkle \`${String(s.merkle_sources || '').slice(0, 10)}…\`)`).join(', ')}`
    )
  }

  const escalations = (Array.isArray(plan?.nightmares) ? plan.nightmares : []).filter(n => n.action === 'escalate_to_owner')
  if (escalations.length > 0) {
    for (const esc of escalations) {
      lines.push(`- 🚨 **NIGHTMARE ESCALATION:** ${esc.message}`)
    }
  }

  return lines.join('\n')
}

// Executes a full Curator Dream & Nightmare cycle over the daemon's reader and writer sockets.
export async function runCuratorCycle({
  readerSocket,
  writerSocket = null,
  curatorSecretKey = null,
  curatorSigner = null,
  curatorPubkey: explicitCuratorPubkey = null,
  memoryGlobalChannelId = '',
  force = false,
  dryRun = false,
  stateFile = undefined,
  lastCuratedAt = null,
  lastCuratedWriteSeq = null,
  coherence = null,
  recentActivity = null,
  dreamIntervalSec = DEFAULT_DREAM_INTERVAL_SEC,
  writeDeltaThreshold = DEFAULT_WRITE_DELTA_THRESHOLD,
  topicPressureThreshold = DEFAULT_TOPIC_PRESSURE_THRESHOLD,
  gitAncestryCheck = null,
  maxPages = 500,
  pageSize = 100,
  nowSec = Math.floor(Date.now() / 1000),
} = {}) {
  const resolvedStateFile = resolveCuratorStatePath({ stateFile, socketPath: readerSocket })
  const persisted = resolvedStateFile ? readCuratorStateFile(resolvedStateFile) : null
  const effectiveLastCuratedAt =
    lastCuratedAt !== null && lastCuratedAt !== undefined
      ? Number(lastCuratedAt)
      : Number(persisted?.last_curated_at || 0)
  const effectiveLastCuratedWriteSeq =
    lastCuratedWriteSeq !== null && lastCuratedWriteSeq !== undefined
      ? Number(lastCuratedWriteSeq)
      : Number(persisted?.last_curated_write_seq || 0)

  const reader = createSingleSocketMcpClient(readerSocket)
  try {
    const wake = await reader.callReadTool('memory_wake', {})
    const records = []
    const historyRecords = []
    let cursor = '0'
    let pages = 0
    const pageLimit = Math.max(1, Number(maxPages) || 500)
    const effectivePageSize = Math.max(1, Math.min(200, Number(pageSize) || 100))
    while (cursor !== null && pages < pageLimit) {
      const page = await reader.callReadTool('memory_query', {
        limit: effectivePageSize,
        format: 'full',
        include_history: true,
        ...(cursor !== '0' ? { cursor } : {}),
      })
      for (const r of Array.isArray(page?.records) ? page.records : []) {
        historyRecords.push(r)
        if ((r.is_current === undefined || r.is_current === true) && r.status !== 'withdrawn' && r.verification === 'accepted') {
          records.push(r)
        }
      }
      cursor = typeof page?.next_cursor === 'string' && page.next_cursor ? page.next_cursor : null
      pages += 1
    }

    const historyComplete = cursor === null
    const storeState = wake?.store_state || {}
    const resolvedRecentActivity = Array.isArray(recentActivity)
      ? recentActivity
      : (Array.isArray(wake?.recent_activity) ? wake.recent_activity : [])
    const resolvedCoherence =
      coherence !== null && coherence !== undefined
        ? (typeof coherence === 'number' ? { score: coherence } : coherence)
        : computeCoherence({
            records,
            history_records: historyRecords,
            agent_roster: Array.isArray(wake?.agent_roster) ? wake.agent_roster : [],
            recent_activity: resolvedRecentActivity,
            store_state: storeState,
            now_sec: nowSec,
            history_complete: historyComplete,
          })

    const triggerEval = evaluateDreamTriggers({
      records,
      storeState,
      recentActivity: resolvedRecentActivity,
      coherence: resolvedCoherence,
      lastCuratedAt: effectiveLastCuratedAt,
      lastCuratedWriteSeq: effectiveLastCuratedWriteSeq,
      nowSec,
      dreamIntervalSec,
      writeDeltaThreshold,
      topicPressureThreshold,
    })

    const curatorPubkey = explicitCuratorPubkey
      ? String(explicitCuratorPubkey).toLowerCase()
      : curatorSecretKey
        ? getPublicKey(curatorSecretKey)
        : curatorSigner
          ? (curatorSigner.pubkey || (typeof curatorSigner.getPublicKey === 'function' ? await curatorSigner.getPublicKey() : null))
          : null
    const plan = planMerkleDream({
      records,
      curatorPubkey,
      memoryGlobalChannelId,
      nowSec,
      gitAncestryCheck,
    })

    const plannedActions = [
      ...plan.nightmares.filter(n => n.action === 'auto_resolve'),
      ...plan.promotions,
      ...plan.distillations,
    ]
    const submitted = []
    const refused = []
    const triggerFired = Boolean(force || triggerEval.shouldRun)
    const hasWriteCapability = Boolean(!dryRun && writerSocket && (curatorSecretKey || curatorSigner))

    if (triggerFired && hasWriteCapability && historyComplete && plannedActions.length > 0) {
      const writer = createCuratorWriteClient(writerSocket)
      try {
        for (const item of plannedActions.filter(a => a.template)) {
          const dTag = item.template.tags.find(t => t[0] === 'd')?.[1]
          const prior = await writer.callWriteTool('memory_lookup_prior', { d: dTag })
          const priorCreatedAt = prior?.found ? Number(prior.created_at || 0) : 0
          const expectedPriorId = prior?.found ? prior.id : null
          const adjustedTemplate = {
            ...item.template,
            created_at: Math.max(item.template.created_at, priorCreatedAt + 1),
          }
          // Recompute exp if Class A so exp stays aligned with adjusted created_at
          const expIdx = adjustedTemplate.tags.findIndex(t => t[0] === 'exp')
          if (expIdx >= 0) {
            adjustedTemplate.tags[expIdx] = ['exp', String(adjustedTemplate.created_at + DEFAULT_TTL_SEC)]
          }
          const signed = curatorSigner
            ? await curatorSigner.signEvent(adjustedTemplate)
            : finalizeEvent(adjustedTemplate, curatorSecretKey)
          const res = await writer.callWriteTool('memory_submit', {
            event: signed,
            expected_prior_id: expectedPriorId,
          })
          if (res?.accepted) {
            submitted.push({ id: res.id, d: dTag, stage: item.stage || item.action, merkle_sources: item.merkle_sources })
          } else {
            refused.push({ d: dTag, code: res?.code || 'REFUSED', message: res?.message || '' })
          }
        }
      } finally {
        writer.close()
      }
    }

    // Advance the durable curation cursor ONLY when a write-capable pass either:
    //   (a) submits all planned curations without refusal (`submitted.length === plannedActions.length && refused.length === 0`), or
    //   (b) executes an explicit, verified no-op curation pass (`plannedActions.length === 0 && !triggerEval.triggers.nightmare_interrupt`).
    // Read-only passes (no writerSocket/curatorSecretKey or dryRun) and refused write passes NEVER advance the cursor.
    let cycleStatus = 'idle'
    let cursorAdvanced = false
    if (!historyComplete) {
      cycleStatus = 'history_incomplete'
      cursorAdvanced = false
    } else if (!hasWriteCapability) {
      cycleStatus = triggerFired ? 'read_only_pending' : 'read_only_idle'
      cursorAdvanced = false
    } else if (!triggerFired) {
      cycleStatus = 'idle'
      cursorAdvanced = false
    } else if (plannedActions.length > 0) {
      if (submitted.length === plannedActions.length && refused.length === 0) {
        cycleStatus = 'curated'
        cursorAdvanced = true
      } else {
        cycleStatus = 'write_refused'
        cursorAdvanced = false
      }
    } else if (!triggerEval.triggers.nightmare_interrupt) {
      cycleStatus = 'noop_verified'
      cursorAdvanced = true
    } else {
      cycleStatus = 'nightmare_unresolved'
      cursorAdvanced = false
    }

    const postWriteSeq = Number(storeState.write_seq || 0) + submitted.length
    const nextCuratedAt = cursorAdvanced ? nowSec : effectiveLastCuratedAt
    const nextCuratedWriteSeq = cursorAdvanced ? postWriteSeq : effectiveLastCuratedWriteSeq

    if (hasWriteCapability && resolvedStateFile && cursorAdvanced) {
      writeCuratorStateFile(resolvedStateFile, {
        last_curated_at: nextCuratedAt,
        last_curated_write_seq: nextCuratedWriteSeq,
        last_ran_at: nowSec,
        last_submitted_count: submitted.length,
        dream_interval_sec: dreamIntervalSec,
        write_delta_threshold: writeDeltaThreshold,
        topic_pressure_threshold: topicPressureThreshold,
        triggers: triggerEval,
        coherence_score: triggerEval.coherence_score,
      })
    }

    const cycleOk = cycleStatus !== 'write_refused' && cycleStatus !== 'history_incomplete'
    const briefing = formatCuratorBriefing({
      cycleStatus,
      triggers: triggerEval,
      plan,
      submitted,
      refused,
      coherence: resolvedCoherence,
      lastCuratedWriteSeq: effectiveLastCuratedWriteSeq,
      nextCuratedWriteSeq,
    })
    return {
      ok: cycleOk,
      history_complete: historyComplete,
      cycle_status: cycleStatus,
      cursor_advanced: cursorAdvanced,
      ran_at: nowSec,
      forced: Boolean(force),
      dry_run: Boolean(dryRun),
      state_file: resolvedStateFile || null,
      last_curated_at: effectiveLastCuratedAt,
      last_curated_write_seq: effectiveLastCuratedWriteSeq,
      next_curated_at: nextCuratedAt,
      next_curated_write_seq: nextCuratedWriteSeq,
      coherence: resolvedCoherence,
      recent_activity_count: resolvedRecentActivity.length,
      triggers: triggerEval,
      plan,
      submitted,
      refused,
      briefing,
    }
  } finally {
    reader.close()
  }
}
