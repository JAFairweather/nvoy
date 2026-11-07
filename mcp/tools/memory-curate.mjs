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

import { createConnection } from 'node:net'
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
import { createSingleSocketMcpClient } from './memory-viewer.mjs'

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
  const elapsedSec = Math.max(0, nowSec - Number(lastCuratedAt || 0))
  const circadianDream = lastCuratedAt > 0 ? elapsedSec >= dreamIntervalSec : false

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

  const hotScopeTopics = [...byScopeTopic.values()]
    .filter(x => x.count > topicPressureThreshold)
    .sort((a, b) => b.count - a.count)

  const synapticVolume = writeDelta >= writeDeltaThreshold || hotScopeTopics.length > 0

  const refusalCount15m = (Array.isArray(recentActivity) ? recentActivity : []).filter(
    a => a && a.kind === 'refused' && typeof a.at === 'number' && Math.max(0, nowSec - a.at) <= NIGHTMARE_REFUSAL_WINDOW_SEC
  ).length

  const coherenceScore = typeof coherence?.score === 'number' ? coherence.score : null
  const coherenceAlert = coherenceScore !== null && coherenceScore < 70

  const nightmareInterrupt =
    conflictedKeys.size > 0 ||
    staleRecords.length > 0 ||
    refusalCount15m >= NIGHTMARE_REFUSAL_THRESHOLD ||
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

      if (deterministic && cleanCuratorPk && sample.scope !== 'hive:canon') {
        const sourceIds = sorted.map(r => r.event_id).sort()
        const merkleRoot = computeSourceMerkleRoot(sourceIds)
        const topic = normalizeMemoryTopic(newest.topic) || 'hive-memory'
        const subj = sanitizeSlugPart(extractWorkSubject(newest))
        const slug = `curated-${topic}-${subj}-resolved`
        const mergedEvidence = [...new Set(sorted.flatMap(r => Array.isArray(r.evidence) ? r.evidence : []))].slice(0, 24)
        const maxCreated = Math.max(...sorted.map(r => r.created_at || 0))
        const template = buildClaimTemplate({
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

  // 2. Group non-conflicted Class A claims by (scope, topic, subject/similarity) for Stage 1 (Distillation) & Stage 2 (Promotion)
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
      const top = normalizeMemoryTopic(r.topic) || 'hive-memory'
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

  // 3. Stage 3: Solidification — Nominate high-convergence Class B decisions for `hive:canon`
  const solidifications = []
  const classBByTopic = new Map()
  for (const r of active) {
    if (r.scope === 'hive:canon' || conflictedFactKeys.has(r.d) || r.stale_warning) continue
    if (r.expires_at === null || r.expires_at === undefined || r.retention === 'decision') {
      const top = normalizeMemoryTopic(r.topic) || 'hive-memory'
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
    distillations,
    promotions,
    solidifications,
    nightmares,
    summary: {
      distillations: distillations.length,
      promotions: promotions.length,
      solidifications: solidifications.length,
      nightmares_auto_resolved: nightmares.filter(n => n.action === 'auto_resolve').length,
      nightmares_escalated: nightmares.filter(n => n.action === 'escalate_to_owner').length,
      stale_warnings: nightmares.filter(n => n.action === 'stale_anchor_warning').length,
    },
  }
}

// Executes a full Curator Dream & Nightmare cycle over the daemon's reader and writer sockets.
export async function runCuratorCycle({
  readerSocket,
  writerSocket = null,
  curatorSecretKey = null,
  memoryGlobalChannelId = '',
  force = false,
  dryRun = false,
  lastCuratedAt = 0,
  lastCuratedWriteSeq = 0,
  dreamIntervalSec = DEFAULT_DREAM_INTERVAL_SEC,
  writeDeltaThreshold = DEFAULT_WRITE_DELTA_THRESHOLD,
  topicPressureThreshold = DEFAULT_TOPIC_PRESSURE_THRESHOLD,
  gitAncestryCheck = null,
  nowSec = Math.floor(Date.now() / 1000),
} = {}) {
  const reader = createSingleSocketMcpClient(readerSocket)
  try {
    const wake = await reader.callReadTool('memory_wake', {})
    const records = []
    let cursor = '0'
    let pages = 0
    while (cursor !== null && pages < 50) {
      const page = await reader.callReadTool('memory_query', {
        limit: 100,
        format: 'full',
        ...(cursor !== '0' ? { cursor } : {}),
      })
      for (const r of Array.isArray(page?.records) ? page.records : []) {
        records.push(r)
      }
      cursor = typeof page?.next_cursor === 'string' && page.next_cursor ? page.next_cursor : null
      pages += 1
    }

    const triggerEval = evaluateDreamTriggers({
      records,
      storeState: wake?.store_state || {},
      recentActivity: wake?.recent_activity || [],
      lastCuratedAt,
      lastCuratedWriteSeq,
      nowSec,
      dreamIntervalSec,
      writeDeltaThreshold,
      topicPressureThreshold,
    })

    const curatorPubkey = curatorSecretKey ? getPublicKey(curatorSecretKey) : null
    const plan = planMerkleDream({
      records,
      curatorPubkey,
      memoryGlobalChannelId,
      nowSec,
      gitAncestryCheck,
    })

    const submitted = []
    const refused = []

    if ((force || triggerEval.shouldRun) && !dryRun && writerSocket && curatorSecretKey) {
      const writer = createCuratorWriteClient(writerSocket)
      try {
        const actions = [
          ...plan.nightmares.filter(n => n.action === 'auto_resolve' && n.template),
          ...plan.promotions.filter(p => p.template),
          ...plan.distillations.filter(d => d.template),
        ]
        for (const item of actions) {
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
          const signed = finalizeEvent(adjustedTemplate, curatorSecretKey)
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

    return {
      ok: true,
      ran_at: nowSec,
      forced: Boolean(force),
      dry_run: Boolean(dryRun),
      triggers: triggerEval,
      plan,
      submitted,
      refused,
    }
  } finally {
    reader.close()
  }
}
