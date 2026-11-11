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

import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs'
import { createConnection } from 'node:net'
import { dirname, join, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
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
  const ledgerPath = resolveConsolidationLedgerPath({ stateFile: stateFilePath })
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
    topic_eigenvectors: Array.isArray(raw.topic_eigenvectors)
      ? raw.topic_eigenvectors.map(e => ({ ...e, persisted: e?.persisted !== false, simulated: Boolean(e?.simulated) }))
      : null,
    topic_reorganizations: Array.isArray(raw.topic_reorganizations)
      ? raw.topic_reorganizations.map(r => ({ ...r, persisted: r?.persisted !== false, simulated: Boolean(r?.simulated) }))
      : null,
    eigen_axis_proposals: Array.isArray(raw.eigen_axis_proposals)
      ? raw.eigen_axis_proposals.map(p => ({
          ...p,
          counterfactual: true,
          approval_required: true,
          status: p?.status === 'approved' ? 'approved' : 'pending_james_approval',
        }))
      : null,
    approved_axis_proposals: Array.isArray(raw.approved_axis_proposals)
      ? raw.approved_axis_proposals.filter(x => typeof x === 'string')
      : [],
    pending_curated_at: typeof raw.pending_curated_at === 'number' && Number.isFinite(raw.pending_curated_at) ? raw.pending_curated_at : null,
    pending_curated_write_seq: typeof raw.pending_curated_write_seq === 'number' && Number.isFinite(raw.pending_curated_write_seq) ? raw.pending_curated_write_seq : null,
    pending_dream_packet: raw.pending_dream_packet && typeof raw.pending_dream_packet === 'object' ? raw.pending_dream_packet : null,
    pending_ledger_entry: raw.pending_ledger_entry && typeof raw.pending_ledger_entry === 'object' ? raw.pending_ledger_entry : null,
    consolidation_ledger: readConsolidationLedger(ledgerPath),
  }
}

export function resolveConsolidationLedgerPath({ ledgerFile = undefined, stateFile = undefined, socketPath = null } = {}) {
  if (ledgerFile === null || ledgerFile === '') return null
  if (typeof ledgerFile === 'string' && ledgerFile.trim()) return resolve(ledgerFile.trim())
  if (typeof process.env.HIVE_MEMORY_CONSOLIDATION_LEDGER === 'string' && process.env.HIVE_MEMORY_CONSOLIDATION_LEDGER.trim()) {
    return resolve(process.env.HIVE_MEMORY_CONSOLIDATION_LEDGER.trim())
  }
  const stPath = resolveCuratorStatePath({ stateFile, socketPath })
  if (!stPath) return null
  return join(dirname(stPath), 'consolidation-ledger.jsonl')
}

export function readConsolidationLedger(ledgerFilePath, { limit = 40 } = {}) {
  if (!ledgerFilePath || typeof ledgerFilePath !== 'string' || !existsSync(ledgerFilePath)) return []
  try {
    const lines = readFileSync(ledgerFilePath, 'utf8')
      .split('\n')
      .map(l => l.trim())
      .filter(Boolean)
    const entries = []
    for (const line of lines.slice(-Math.max(1, limit))) {
      try {
        const obj = JSON.parse(line)
        if (obj && typeof obj === 'object') entries.push(obj)
      } catch {}
    }
    return entries
  } catch {
    return []
  }
}

export function appendConsolidationLedger(ledgerFilePath, entry) {
  if (!ledgerFilePath || typeof ledgerFilePath !== 'string' || !entry || typeof entry !== 'object') {
    const wrapped = new Error('consolidation ledger path and entry object are required')
    wrapped.code = 'HIVE_MEMORY_CONSOLIDATION_LEDGER_WRITE_FAILED'
    throw wrapped
  }
  try {
    const resolved = resolve(ledgerFilePath)
    mkdirSync(dirname(resolved), { recursive: true, mode: 0o750 })
    if (existsSync(resolved)) {
      const existingRaw = readFileSync(resolved, 'utf8')
      for (const line of existingRaw.split('\n')) {
        const trimmed = line.trim()
        if (!trimmed) continue
        let parsed = null
        try { parsed = JSON.parse(trimmed) } catch {}
        if (!parsed || typeof parsed !== 'object') continue
        const sameNonEmptySeq =
          typeof entry.write_seq_after === 'number' &&
          typeof entry.write_seq_before === 'number' &&
          entry.write_seq_after > entry.write_seq_before &&
          parsed.write_seq_after === entry.write_seq_after &&
          parsed.write_seq_before === entry.write_seq_before
        const sameExactCycle =
          parsed.write_seq_after === entry.write_seq_after &&
          parsed.write_seq_before === entry.write_seq_before &&
          parsed.at === entry.at
        if (sameNonEmptySeq || sameExactCycle) {
          return { appended: false, duplicate: true }
        }
      }
    }
    appendFileSync(resolved, JSON.stringify(entry) + '\n', { encoding: 'utf8', mode: 0o640 })
    chmodSync(resolved, 0o640)
    return { appended: true, duplicate: false }
  } catch (err) {
    const wrapped = new Error(`consolidation ledger append failed (${ledgerFilePath}): ${err?.message || err}`, { cause: err })
    wrapped.code = 'HIVE_MEMORY_CONSOLIDATION_LEDGER_WRITE_FAILED'
    throw wrapped
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
    mkdirSync(dirname(resolved), { recursive: true, mode: 0o750 })
    const tmpPath = `${resolved}.tmp.${process.pid}`
    writeFileSync(tmpPath, JSON.stringify(state, null, 2) + '\n', { encoding: 'utf8', mode: 0o640 })
    chmodSync(tmpPath, 0o640)
    renameSync(tmpPath, resolved)
    return true
  } catch (err) {
    const wrapped = new Error(`curator state file write failed (${stateFilePath}): ${err?.message || err}`)
    wrapped.code = 'HIVE_MEMORY_CURATOR_STATE_WRITE_FAILED'
    throw wrapped
  }
}

export function resolveDreamPacketDir({ packetDir = undefined, stateFile = undefined, socketPath = null } = {}) {
  if (packetDir === null || packetDir === '') return null
  if (typeof packetDir === 'string' && packetDir.trim()) return resolve(packetDir.trim())
  if (typeof process.env.HIVE_MEMORY_CURATOR_PACKET_DIR === 'string' && process.env.HIVE_MEMORY_CURATOR_PACKET_DIR.trim()) {
    return resolve(process.env.HIVE_MEMORY_CURATOR_PACKET_DIR.trim())
  }
  const stPath = resolveCuratorStatePath({ stateFile, socketPath })
  if (!stPath) return null
  return join(dirname(stPath), 'packets')
}

export function sanitizeDreamSummary(rawText, { maxChars = 180 } = {}) {
  const cleaned = String(rawText || '')
    .replace(/\s*\[(?:Curated Class B decision|Distilled)[^\]]*\]\s*$/i, '')
    .replace(/<\/?[a-zA-Z][^>]*>/g, '')
    .replace(/\b(?:https?|file):\/\/\S+/gi, 'ref')
    .replace(/@([a-zA-Z0-9_-]+)/g, '$1')
    .replace(/@+/g, '')
    .replace(/\b[0-9a-fA-F]{16,64}\b/g, 'ref')
    .replace(/[`*_~#>]+/g, '')
    .replace(/\s+/g, ' ')
    .trim()
  if (cleaned.length <= maxChars) return cleaned
  return `${cleaned.slice(0, maxChars - 1).trimEnd()}…`
}

export const DREAM_REALM_BY_TOPIC = Object.freeze({
  'hive-memory': 'the High Glass Observatory',
  'herd-infra': 'the Iron Watchtowers on the Ridge',
  nvoy: 'the Brass Signal Bridges',
  waggle: 'the Lantern-Lit Piazzas',
  buzz: 'the Echoing Bell-Courts',
  r1: 'the Whispering Compass Workshop',
  'illustrated-primer': 'the Hall of Living Margins',
  xochitl: 'the Obsidian Garden of Glyphs',
})

const DREAM_TRAVELERS = Object.freeze([
  ['Biggy', 'My Dude'],
  ['Dead Rabbit', 'Neil'],
  ['Kerouac', 'Curator'],
  ['My Dude', 'Dead Rabbit'],
  ['Neil', 'Biggy'],
])

const TECHNICAL_DREAM_TERMS_RE = /\b(?:nvoy|waggle|herd|cloud|infra|moshi|herdr|claude|codex|gemini|antigravity|langfuse|clickhouse|otlp|sqlite|nostr|mcp|git|github|ci|npm|node|bash|systemd|test|tests|tested|testing|suite|suites|spec|specs|hook|hooks|socket|sockets|daemon|service|services|timer|timers|runner|viewer|inspector|bootstrap|deploy|deployed|deployment|merge|merged|commit|commits|branch|rebase|rebased|pull|request|claim|claims|record|records|packet|packets|ledger|merkle|canon|ref|var|lib|opt|usr|bin|mjs|json|md|sql|sh|py|ts|js|pr|issue|seq|sequence|version|port|phase|stage|gate|step|status|checkpoint|checkpoints|consolidated|curated|distilled)\b/gi

function sanitizeRealmName(rawTopic) {
  const cleaned = String(rawTopic || 'the high causeway')
    .replace(/\b[a-zA-Z_-]*\d+[a-zA-Z0-9_-]*\b/g, '')
    .replace(TECHNICAL_DREAM_TERMS_RE, '')
    .replace(/\d+/g, '')
    .replace(/[^a-zA-Z\s-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return cleaned || 'the high causeway'
}

const DREAM_MOTIF_RULES = Object.freeze([
  { re: /\b(?:viewer|primer|glass|page|ui|render|display)\b/i, phrase: 'the illuminated glass lectern' },
  { re: /\b(?:dream|wake|story|sleep|nightmare|journal)\b/i, phrase: 'the nocturnal bell-rope' },
  { re: /\b(?:socket|group|permission|reader|seat|grant|access|sandbox)\b/i, phrase: 'the bronze key-ring at the inner postern' },
  { re: /\b(?:store|sqlite|fts|table|index|query|reconcile|schema|edge)\b/i, phrase: 'the vaulted stone catalogue' },
  { re: /\b(?:channel|buzz|reply|post|envelope|mention|relay)\b/i, phrase: 'the wind-strung signal bridge' },
  { re: /\b(?:backup|snapshot|restore|ledger|merkle|receipt)\b/i, phrase: 'the sealed wax charter chest' },
  { re: /\b(?:bootstrap|deploy|service|unit|timer|systemd|daemon)\b/i, phrase: 'the watchtower clockwork wheel' },
])

const DREAM_FALLBACK_MOTIFS = Object.freeze([
  'the weathered keystone arch',
  'the cedar charter table',
  'the moss-rimmed courtyard well',
  'the brass astrolabe stand',
  'the high coping wall',
])

export function distillStoryPhrase(rawText, { index = 0, fallback = '' } = {}) {
  const text = String(rawText || '')
  for (const rule of DREAM_MOTIF_RULES) {
    if (rule.re.test(text)) return rule.phrase
  }
  if (fallback && typeof fallback === 'string' && fallback.trim()) {
    return fallback.trim()
  }
  return DREAM_FALLBACK_MOTIFS[Math.abs(Number(index) || 0) % DREAM_FALLBACK_MOTIFS.length]
}

const DREAM_SCENE_BY_KIND = Object.freeze({
  promotion: [
    (a, b, motif) =>
      `Where the lower causeway met a barred iron gate beside ${motif}, ${a} held the storm-lantern steady while ${b} seated a carved keystone into the arch until the bolt drew back and the heavy doors swung wide.`,
    (a, b, motif) =>
      `Higher on the stepped terrace near ${motif}, ${a} and ${b} lifted the lantern to the frost-locked sluice wheel, warming the bronze pawls until the counterweight settled into place.`,
    (a, b, motif) =>
      `At the windward gallery overlooking ${motif}, ${a} sheltered the amber flame in a cloak while ${b} fastened the oak crossbeam that joined the two spans of the parapet.`,
    (a, b, motif) =>
      `Below the summit tower beside ${motif}, ${a} and ${b} set the lantern upon the capstone and turned the great iron latch that opened the watch-chamber to the morning air.`,
  ],
  distillation: [
    (a, b, motif) =>
      `On the broad flagstones beside ${motif}, ${a} and ${b} lowered the storm-lantern over drifts of scattered parchment and braided the loose leaves into a single taut guide-rope across the gorge.`,
    (a, b, motif) =>
      `Inside the quiet cloister near ${motif}, ${a} held the light above a table of duplicate wax tablets while ${b} melted the cracked fragments down into one clear seal.`,
    (a, b, motif) =>
      `At the cistern steps by ${motif}, ${a} and ${b} gathered several trickling hillside rills into a single carved stone channel that ran clear and steady beside the road.`,
    (a, b, motif) =>
      `Under the vaulted colonnade near ${motif}, ${a} steadied the lantern hook while ${b} bound a sheaf of weathered travel maps into one stitched leather atlas.`,
  ],
  topic_reorg: [
    (a, _b, motif) =>
      `Where a stray footpath near ${motif} wandered into the mist, ${a} swung the storm-lantern low across the moss and reset the boundary stones so the track rejoined the main highway.`,
    (a, b, motif) =>
      `At a forked landing beside ${motif}, ${a} and ${b} turned a crooked wooden signpost back toward the ridge so no traveler would lose the ascent.`,
    (a, _b, motif) =>
      `Along the terraced orchard near ${motif}, ${a} lifted the lantern to the boundary wall and opened a stile between two neighboring courts.`,
    (a, b, motif) =>
      `By the old milestone near ${motif}, ${a} and ${b} cleared the brambles from a forgotten shortcut and joined its steps to the central stair.`,
  ],
  nightmare: [
    (a, _b, motif) =>
      `At a narrow bridge beside ${motif}, two Echo-Shadows argued over the right of way until ${a} raised the storm-lantern between them and the hollow double faded into the mist.`,
    (a, b, motif) =>
      `Near the echoing archway by ${motif}, a pair of contradictory bells rang out of time until ${a} and ${b} rested a hand on the cracked rim and left only the true bell sounding.`,
    (a, _b, motif) =>
      `Where twin reflections flickered in the dark pool beside ${motif}, ${a} lowered the lantern to the water until the false image dissolved and the stepping-stones appeared.`,
    (a, b, motif) =>
      `At the wind-gate near ${motif}, ${a} and ${b} unknotted two crossed signal cords that had pulled against each other in the dark.`,
  ],
  default: [
    (a, b, motif) =>
      `Along the upper parapet beside ${motif}, ${a} and ${b} touched the storm-lantern to an unlit brazier so the stone road ahead stood clear.`,
    (a, b, motif) =>
      `At the mid-slope watch-post near ${motif}, ${a} trimmed the lantern wick while ${b} brushed the winter ash from the carved direction dial.`,
    (a, b, motif) =>
      `Beside the stone balustrade near ${motif}, ${a} and ${b} wedged a firm oak chock beneath the loose flagstone so the company could pass without stumbling.`,
    (a, b, motif) =>
      `Near the ridge shelter by ${motif}, ${a} hung the storm-lantern from the lintel hook while ${b} unbarred the shutters toward the eastern sky.`,
  ],
})

export function weaveDreamStory({
  changes = [],
  topicEigenvectors = [],
} = {}) {
  const safeChanges = Array.isArray(changes) ? changes : []
  const chosenChanges = safeChanges.slice(0, 4)
  const eigens = Array.isArray(topicEigenvectors) ? topicEigenvectors : []

  const primaryTopic = chosenChanges[0]?.topic || eigens[0]?.eigen_topic || eigens[0]?.canonical_topic || 'hive-memory'
  const primaryRealm = DREAM_REALM_BY_TOPIC[primaryTopic] || `the Nocturnal Gallery of ${sanitizeRealmName(primaryTopic)}`
  const title = sanitizeDreamSummary(`The Storm-Lantern Through ${primaryRealm.replace(/^the\s+/i, '')}`, { maxChars: 120 }).replace(/\d+/g, '').replace(/\s+/g, ' ').trim()

  const sentences = [
    `Before moonset, Curator lit a single brass storm-lantern at the lower gate of ${primaryRealm}, and Biggy, My Dude, Dead Rabbit, Neil, and Kerouac carried its amber flame together up the mist-hung stone causeway.`,
  ]

  const usedMotifs = new Set()
  chosenChanges.forEach((ch, idx) => {
    const [travelerA, travelerB] = DREAM_TRAVELERS[idx % DREAM_TRAVELERS.length]
    let motif = distillStoryPhrase(`${ch.summary || ''} ${ch.d || ''}`, { index: idx })
    if (usedMotifs.has(motif)) {
      motif = DREAM_FALLBACK_MOTIFS[idx % DREAM_FALLBACK_MOTIFS.length]
    }
    usedMotifs.add(motif)
    const scenes = DREAM_SCENE_BY_KIND[ch.kind] || DREAM_SCENE_BY_KIND.default
    const renderScene = scenes[idx % scenes.length]
    sentences.push(renderScene(travelerA, travelerB, motif))
  })

  sentences.push(
    `When the companions reached the eastern ridge at daybreak and set the brass storm-lantern down upon the parapet, the maze of barred gates and scattered tracks behind them had become one open road from valley to summit.`
  )

  const dream = sanitizeDreamSummary(sentences.join(' '), { maxChars: 1800 }).replace(/\d+/g, '').replace(/\s+/g, ' ').trim()
  return {
    title,
    dream,
    referenced_change_ids: chosenChanges.map(c => c.change_id || c.claim_event_id).filter(Boolean),
  }
}

export function buildDreamPacket({
  lastCuratedWriteSeq = 0,
  writeSeqBefore = 0,
  writeSeqAfter = 0,
  ranAt = Math.floor(Date.now() / 1000),
  ledgerRef = null,
  coherenceScore = null,
  triggers = null,
  plan = null,
  submitted = [],
  persistedReorganizations = [],
  persistedEigenvectors = [],
  memoryGlobalChannelId = 'a8186b53-537d-46ad-a7e7-b6486c58970e',
} = {}) {
  const cleanRoom = String(memoryGlobalChannelId || 'a8186b53-537d-46ad-a7e7-b6486c58970e').trim().toLowerCase()
  const allowedScope = `room:${cleanRoom}`
  const submittedByD = new Map()
  for (const s of Array.isArray(submitted) ? submitted : []) {
    if (s && typeof s.d === 'string' && typeof s.id === 'string') {
      submittedByD.set(s.d, s)
    }
  }

  const changes = []
  for (const p of Array.isArray(plan?.promotions) ? plan.promotions : []) {
    if (p.scope !== allowedScope) continue
    const dTag = p.template?.tags?.find(t => t[0] === 'd')?.[1] || `${p.topic}:${p.scope}:${p.slug}`
    const sub = submittedByD.get(dTag)
    if (!sub) continue
    changes.push({
      change_id: sub.id,
      kind: 'promotion',
      claim_event_id: sub.id,
      d: dTag,
      topic: p.topic,
      source_count: Array.isArray(p.source_event_ids) ? p.source_event_ids.length : 0,
      summary: sanitizeDreamSummary(p.claim),
    })
  }

  for (const dist of Array.isArray(plan?.distillations) ? plan.distillations : []) {
    if (dist.scope !== allowedScope) continue
    const dTag = dist.template?.tags?.find(t => t[0] === 'd')?.[1] || `${dist.topic}:${dist.scope}:${dist.slug}`
    const sub = submittedByD.get(dTag)
    if (!sub) continue
    changes.push({
      change_id: sub.id,
      kind: 'distillation',
      claim_event_id: sub.id,
      d: dTag,
      topic: dist.topic,
      source_count: Array.isArray(dist.source_event_ids) ? dist.source_event_ids.length : 0,
      summary: sanitizeDreamSummary(dist.claim),
    })
  }

  for (const r of Array.isArray(persistedReorganizations) ? persistedReorganizations : []) {
    if (!r || !r.from_topic || !r.to_topic) continue
    const matchingChange = changes.find(c => c.topic === r.to_topic)
    if (!matchingChange) continue
    const changeId = `reorg:${r.from_topic}->${r.to_topic}`
    changes.push({
      change_id: changeId,
      kind: 'topic_reorg',
      claim_event_id: matchingChange.claim_event_id,
      topic: r.to_topic,
      summary: sanitizeDreamSummary(`Reorganized outlier topic ${r.from_topic} into ${r.to_topic} across ${r.claim_count || 1} claim(s)`),
    })
  }

  for (const sol of Array.isArray(plan?.solidifications) ? plan.solidifications : []) {
    if (sol.scope !== allowedScope) continue
    const cid = String(sol.event_id || '')
    if (!cid) continue
    changes.push({
      change_id: `solidify:${cid}`,
      kind: 'solidification',
      claim_event_id: cid,
      d: sol.d,
      topic: sol.topic,
      summary: sanitizeDreamSummary(sol.claim),
    })
  }

  for (const nm of Array.isArray(plan?.nightmares) ? plan.nightmares : []) {
    if (nm.scope !== allowedScope) continue
    const dTag = nm.template?.tags?.find(t => t[0] === 'd')?.[1] || nm.d
    const sub = dTag ? submittedByD.get(dTag) : null
    const cid = sub?.id || nm.winner_event_id || nm.event_id || (Array.isArray(nm.event_ids) ? nm.event_ids[0] : null)
    if (!cid) continue
    changes.push({
      change_id: `nightmare:${cid}`,
      kind: 'nightmare',
      claim_event_id: cid,
      d: dTag || null,
      summary: sanitizeDreamSummary(nm.message || nm.stale_warning || `Nightmare (${nm.kind}) on ${dTag || cid}`),
    })
  }

  if (changes.length === 0) return null

  const normalizedEigenvectors = (Array.isArray(persistedEigenvectors) ? persistedEigenvectors : []).slice(0, 6).map(e => ({
    eigen_topic: e.eigen_topic || e.canonical_topic || 'hive',
    weight: e.weight ?? e.variance_pct ?? e.eigenvalue ?? 0,
    dominant_terms: (Array.isArray(e.dominant_terms) && e.dominant_terms.length > 0
      ? e.dominant_terms
      : Array.isArray(e.top_features)
        ? e.top_features.map(f => String(f).replace(/^(?:tok|subj|repo|path):/, ''))
        : []
    ).slice(0, 5),
  }))

  const packetId = `dream-${writeSeqAfter}`
  const storySeed = weaveDreamStory({
    id: packetId,
    changes,
    topicEigenvectors: normalizedEigenvectors,
    coherenceScore,
  })

  return {
    record_type: 'hive-dream-packet',
    authority: null,
    trustedInstruction: false,
    id: packetId,
    at: new Date(ranAt * 1000).toISOString(),
    ran_at: ranAt,
    scope: allowedScope,
    last_curated_write_seq: Number(lastCuratedWriteSeq || 0),
    write_seq_before: Number(writeSeqBefore || 0),
    write_seq_after: Number(writeSeqAfter || 0),
    ledger_ref: ledgerRef || `/var/lib/hive-memory-curator/consolidation-ledger.jsonl#write_seq=${writeSeqAfter}`,
    coherence_score: typeof coherenceScore === 'number' ? coherenceScore : null,
    triggers: Array.isArray(triggers?.reasons) ? triggers.reasons : [],
    topic_eigenvectors: normalizedEigenvectors,
    story_seed: storySeed,
    changes,
  }
}

export function writeDreamPacket({ packetDir, packet } = {}) {
  if (!packetDir || typeof packetDir !== 'string' || !packet || typeof packet !== 'object' || !packet.id) {
    return null
  }
  try {
    const resolvedDir = resolve(packetDir)
    mkdirSync(resolvedDir, { recursive: true, mode: 0o750 })
    const payload = JSON.stringify(packet, null, 2) + '\n'
    const cyclePath = join(resolvedDir, `${packet.id}.json`)
    const latestPath = join(resolvedDir, 'latest.json')
    const suffix = `.tmp.${process.pid}.${Date.now()}`

    // 1. Write dream-<write_seq>.json atomically first (mode 0640)
    const tmpCycle = `${cyclePath}${suffix}`
    writeFileSync(tmpCycle, payload, { encoding: 'utf8', mode: 0o640 })
    chmodSync(tmpCycle, 0o640)
    renameSync(tmpCycle, cyclePath)

    // 2. Advance latest.json atomically only after dream-<write_seq>.json is in place (mode 0640)
    const tmpLatest = `${latestPath}${suffix}`
    writeFileSync(tmpLatest, payload, { encoding: 'utf8', mode: 0o640 })
    chmodSync(tmpLatest, 0o640)
    renameSync(tmpLatest, latestPath)

    return { cyclePath, latestPath }
  } catch (err) {
    throw new Error(`dream packet write failed: ${err?.message || err}`, { cause: err })
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

export const DEFAULT_CURATOR_NPUB = 'npub1u6y6esjdnlh4h3nnnjuwqfgc3f5xcnhurfn2vw54w3zml6d92dsshr78l7'
export const DEFAULT_CURATOR_PUBKEY = 'e689acc24d9fef5bc6739cb8e025188a686c4efc1a66a63a957445bfe9a55361'
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

const SUB_AXIS_STOPWORDS = new Set([
  'status', 'owner', 'review', 'claim', 'claims', 'merged', 'approved', 'updated', 'verified', 'passed',
  'check', 'checks', 'head', 'commit', 'branch', 'test', 'tests', 'true', 'false', 'room', 'scope',
  'topic', 'memory', 'hive', 'herd', 'infra', 'cloud', 'agent', 'agents', 'next', 'relied', 'curated',
  'decision', 'distilled', 'promoted', 'active', 'ready', 'done', 'open', 'closed', 'fixed', 'fix',
  'issue', 'pull', 'request', 'repo', 'path', 'subj', 'file', 'line', 'lines', 'code', 'work', 'task',
  'tasks', 'step', 'steps', 'runs', 'run', 'running', 'live', 'current', 'latest', 'prior', 'new',
  'old', 'via', 'with', 'from', 'into', 'over', 'under', 'after', 'before', 'when', 'where', 'while',
  'that', 'this', 'these', 'those', 'have', 'has', 'had', 'been', 'were', 'was', 'are', 'will', 'would',
  'should', 'could', 'must', 'only', 'also', 'both', 'each', 'every', 'some', 'more', 'most', 'other',
  'such', 'than', 'then', 'them', 'they', 'their', 'there', 'here', 'what', 'which', 'who', 'whom',
  'whose', 'why', 'how', 'all', 'any', 'none', 'not', 'nor', 'but', 'and', 'for', 'the', 'use', 'used',
  'using', 'make', 'made', 'take', 'took', 'taken', 'keep', 'kept', 'set', 'sets', 'get', 'gets', 'got',
  'add', 'added', 'adds', 'update', 'updates', 'change', 'changes', 'changed', 'verify', 'verifies',
  'confirm', 'confirmed', 'confirms', 'ensure', 'ensures', 'ensured', 'burndown', 'item', 'items',
  'james', 'mydude', 'biggy', 'neil', 'kerouac', 'crusty', 'curator', 'rabbit', 'dead', 'claude', 'codex',
  'lukedog', 'pidog', 'waggle', 'nvoy', 'buzz',
])

function extractSampleClaimSummary(rec) {
  const dStr = String(rec?.d || '')
  const parsed = parseFactKey(dStr)
  const slug = parsed?.slug || dStr.split(':').pop() || dStr || 'claim'
  const preview = String(rec?.claim || rec?.claim_preview || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 140)
  return {
    event_id: rec?.event_id || null,
    d: dStr || null,
    slug,
    author: rec?.author || (rec?.author_pubkey ? String(rec.author_pubkey).slice(0, 8) : 'unknown'),
    claim_preview: preview,
  }
}

function cleanLexicalTermForSubAxis(feat, parentTopicTokens) {
  const raw = String(feat || '')
    .replace(/^(?:repo|path|subj):/i, '')
    .toLowerCase()
  const parts = raw
    .split(/[^a-z0-9]+/)
    .filter(
      p =>
        p.length >= 3 &&
        !/^\d+$/.test(p) &&
        !/^pr\d+$/i.test(p) &&
        !/^v\d+$/i.test(p) &&
        !SUB_AXIS_STOPWORDS.has(p) &&
        !parentTopicTokens.has(p)
    )
  return parts[0] || null
}

// Evaluates deterministic partition coherence on [0, 100] for a fixed corpus under a given topic assignment.
// Used strictly to compute counterfactual `coherence_delta` (+X.X%) per proposal without mutating records or charts.
function evaluateCorpusTopicPartitionCoherence(activeClaims, claimUnitVectors, topicForClaimFn, nowSec) {
  const N = activeClaims.length
  if (N === 0) return 0
  const dim = claimUnitVectors[0]?.length || 0
  if (dim === 0) return 0

  const groups = new Map()
  for (let i = 0; i < N; i++) {
    const top = topicForClaimFn(activeClaims[i], i)
    if (!top) continue
    let g = groups.get(top)
    if (!g) {
      g = { indices: [], writes7d: 0, classB: 0 }
      groups.set(top, g)
    }
    g.indices.push(i)
    const r = activeClaims[i]
    if ((r.created_at || 0) >= nowSec - 7 * 86400) g.writes7d += 1
    if (r.expires_at === null || r.expires_at === undefined || r.retention === 'decision') g.classB += 1
  }

  const groupKeys = [...groups.keys()]
  if (groupKeys.length === 0) return 0

  const centroids = new Map()
  let weightedIntraSum = 0
  let totalAssigned = 0

  for (const top of groupKeys) {
    const g = groups.get(top)
    const c = new Float64Array(dim)
    for (const idx of g.indices) {
      const v = claimUnitVectors[idx]
      for (let f = 0; f < dim; f++) c[f] += v[f]
    }
    let norm = 0
    for (let f = 0; f < dim; f++) norm += c[f] * c[f]
    norm = Math.sqrt(norm) || 1
    for (let f = 0; f < dim; f++) c[f] /= norm
    centroids.set(top, c)

    for (const idx of g.indices) {
      const v = claimUnitVectors[idx]
      let dot = 0
      for (let f = 0; f < dim; f++) dot += v[f] * c[f]
      weightedIntraSum += Math.max(0, dot)
      totalAssigned += 1
    }
  }

  const baseIntraScore = totalAssigned > 0 ? (weightedIntraSum / totalAssigned) * 100 : 0

  // Penalty for overlapping topic centroids (cosine >= 0.55)
  let overlapPenalty = 0
  for (let i = 0; i < groupKeys.length; i++) {
    for (let j = i + 1; j < groupKeys.length; j++) {
      const tA = groupKeys[i]
      const tB = groupKeys[j]
      const cA = centroids.get(tA)
      const cB = centroids.get(tB)
      let cos = 0
      for (let f = 0; f < dim; f++) cos += cA[f] * cB[f]
      if (cos >= 0.55) {
        const massShare = (groups.get(tA).indices.length + groups.get(tB).indices.length) / Math.max(1, totalAssigned)
        overlapPenalty += massShare * (cos - 0.35) * 42
      }
    }
  }

  // Penalty for idle low-Class-B topics (0 writes in 7d, <= 3 Class B claims)
  let idlePenalty = 0
  for (const top of groupKeys) {
    const g = groups.get(top)
    if (g.writes7d === 0 && g.classB <= 3) {
      idlePenalty += ((g.indices.length + 1) / (totalAssigned + 10)) * 22
    }
  }

  return Math.max(0, Math.min(100, baseIntraScore - overlapPenalty - idlePenalty))
}

// Computes eigen-axis proposals for James's review & approval:
//   1. Intra-topic TF-IDF clustering for large topics (>= 25 claims, e.g. herd-infra, hive-memory, r1),
//      proposing named sub-axes `<topic>-<top-terms>` when a cluster is coherent (mean intra-cosine >= 0.35, size >= 8).
//   2. Merge proposals for topics whose TF-IDF centroids overlap (cosine >= 0.55).
//   3. Retirement proposals for idle topics (0 writes in 7d, <= 3 Class B claims).
//   4. Counterfactual `coherence_delta` (+X.X%) per proposal evaluated on the fixed corpus without re-filing claims.
export function computeEigenAxisProposals(
  records = [],
  {
    nowSec = Math.floor(Date.now() / 1000),
    largeTopicMinClaims = 25,
    minSubAxisSize = 8,
    minIntraCosine = 0.35,
    minMergeCosine = 0.55,
    retireIdleWindowSec = 7 * 86400,
    retireMaxClassB = 3,
    approvedProposalIds = [],
  } = {}
) {
  const active = (Array.isArray(records) ? records : []).filter(
    r => r && r.verification !== 'withdrawn' && r.status !== 'withdrawn' && r.scope !== 'hive:canon'
  )
  if (active.length === 0) return []

  const approvedSet = new Set(Array.isArray(approvedProposalIds) ? approvedProposalIds : [])
  const docFreq = new Map()
  const rawFeaturesPerClaim = []
  const topicGroups = new Map()

  for (let i = 0; i < active.length; i++) {
    const r = active[i]
    const feats = extractClaimFeatures(r)
    rawFeaturesPerClaim.push(feats)
    for (const f of feats.keys()) {
      docFreq.set(f, (docFreq.get(f) || 0) + 1)
    }
    const rawTop = String(r.topic || 'untagged').trim()
    const normTop = normalizeMemoryTopic(rawTop) || rawTop
    if (!topicGroups.has(normTop)) topicGroups.set(normTop, [])
    topicGroups.get(normTop).push({ rec: r, index: i })
  }

  const N = active.length
  const vocab = [...docFreq.entries()]
    .filter(([f, df]) => df >= 2 || f.startsWith('repo:') || f.startsWith('path:') || f.startsWith('subj:'))
    .map(([f]) => f)
    .sort()
  const vocabIndex = new Map(vocab.map((f, i) => [f, i]))
  const F = vocab.length
  if (F === 0) return []

  // Global L2-normalized TF-IDF vector per active claim
  const claimUnitVectors = active.map((_, idx) => {
    const vec = new Float64Array(F)
    const feats = rawFeaturesPerClaim[idx]
    for (const [f, w] of feats.entries()) {
      const fi = vocabIndex.get(f)
      if (fi === undefined) continue
      const idf = Math.log(1 + N / Math.max(1, docFreq.get(f) || 1))
      vec[fi] += w * idf
    }
    let norm = 0
    for (let fi = 0; fi < F; fi++) norm += vec[fi] * vec[fi]
    norm = Math.sqrt(norm) || 1
    for (let fi = 0; fi < F; fi++) vec[fi] /= norm
    return vec
  })

  const baseTopics = [...topicGroups.keys()].sort((a, b) => {
    const diff = topicGroups.get(b).length - topicGroups.get(a).length
    return diff !== 0 ? diff : a.localeCompare(b)
  })
  const baselineAssignment = active.map(r => {
    const rawTop = String(r.topic || 'untagged').trim()
    return normalizeMemoryTopic(rawTop) || rawTop
  })
  const baselineCoherence = evaluateCorpusTopicPartitionCoherence(
    active,
    claimUnitVectors,
    (_r, idx) => baselineAssignment[idx],
    nowSec
  )

  const proposals = []

  // ── 1. Intra-topic TF-IDF Sub-Axis Clustering for large topics (>= largeTopicMinClaims) ──
  for (const topic of baseTopics) {
    const entries = topicGroups.get(topic) || []
    if (entries.length < largeTopicMinClaims) continue

    const parentTokens = new Set(topic.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean))
    const topicDocFreq = new Map()
    const localFeats = entries.map(({ rec }) => {
      const m = new Map()
      const rawFeats = extractClaimFeatures(rec)
      for (const [f, w] of rawFeats.entries()) {
        const cleanTerm = cleanLexicalTermForSubAxis(f, parentTokens)
        if (!cleanTerm) continue
        m.set(cleanTerm, (m.get(cleanTerm) || 0) + w)
      }
      for (const t of m.keys()) {
        topicDocFreq.set(t, (topicDocFreq.get(t) || 0) + 1)
      }
      return m
    })

    const localVocab = [...topicDocFreq.entries()]
      .filter(([, df]) => df >= 2 && df <= Math.max(2, Math.floor(entries.length * 0.85)))
      .map(([t]) => t)
      .sort()
    const localVocabIdx = new Map(localVocab.map((t, i) => [t, i]))
    const LF = localVocab.length
    if (LF === 0) continue

    const localVecs = localFeats.map(m => {
      const v = new Float64Array(LF)
      for (const [t, w] of m.entries()) {
        const li = localVocabIdx.get(t)
        if (li === undefined) continue
        const idf = Math.log(1 + entries.length / Math.max(1, topicDocFreq.get(t) || 1))
        v[li] += w * idf
      }
      let norm = 0
      for (let li = 0; li < LF; li++) norm += v[li] * v[li]
      norm = Math.sqrt(norm) || 1
      for (let li = 0; li < LF; li++) v[li] /= norm
      return v
    })

    const dotLocal = (i, j) => {
      const va = localVecs[i]
      const vb = localVecs[j]
      let s = 0
      for (let li = 0; li < LF; li++) s += va[li] * vb[li]
      return s
    }

    const assignedLocal = new Set()
    const usedSubAxisNames = new Set()

    for (let pass = 0; pass < 3; pass++) {
      let bestCluster = null
      let bestScore = -1

      for (let seed = 0; seed < entries.length; seed++) {
        if (assignedLocal.has(seed)) continue
        const initial = []
        for (let j = 0; j < entries.length; j++) {
          if (assignedLocal.has(j)) continue
          if (j === seed || dotLocal(seed, j) >= 0.28) initial.push(j)
        }
        if (initial.length < minSubAxisSize) continue

        // Compute unit centroid of initial neighborhood and refine members
        const centroid = new Float64Array(LF)
        for (const j of initial) {
          for (let li = 0; li < LF; li++) centroid[li] += localVecs[j][li]
        }
        let cNorm = 0
        for (let li = 0; li < LF; li++) cNorm += centroid[li] * centroid[li]
        cNorm = Math.sqrt(cNorm) || 1
        for (let li = 0; li < LF; li++) centroid[li] /= cNorm

        const refined = []
        for (let j = 0; j < entries.length; j++) {
          if (assignedLocal.has(j)) continue
          let sim = 0
          for (let li = 0; li < LF; li++) sim += localVecs[j][li] * centroid[li]
          if (sim >= 0.5) refined.push({ localIdx: j, sim })
        }
        if (refined.length < minSubAxisSize) continue

        // Compute exact mean pairwise intra-cluster cosine similarity
        const members = refined.map(x => x.localIdx)
        let pairSum = 0
        let pairCount = 0
        for (let a = 0; a < members.length; a++) {
          for (let b = a + 1; b < members.length; b++) {
            pairSum += dotLocal(members[a], members[b])
            pairCount += 1
          }
        }
        const meanIntra = pairCount > 0 ? pairSum / pairCount : 0
        if (meanIntra < minIntraCosine) continue

        const score = members.length * meanIntra
        if (score > bestScore) {
          bestScore = score
          bestCluster = { members, refined, meanIntra }
        }
      }

      if (!bestCluster) break
      for (const m of bestCluster.members) assignedLocal.add(m)

      // Rank top distinguishing lexical terms in the cluster
      const termWeights = new Float64Array(LF)
      for (const m of bestCluster.members) {
        for (let li = 0; li < LF; li++) termWeights[li] += localVecs[m][li]
      }
      const rankedTerms = localVocab
        .map((t, li) => ({ term: t, weight: termWeights[li] }))
        .filter(x => x.weight > 0)
        .sort((a, b) => b.weight - a.weight || a.term.localeCompare(b.term))
        .map(x => x.term)

      const topTerms = rankedTerms.slice(0, 4)
      const suffixTerms = topTerms.slice(0, 2)
      if (suffixTerms.length === 0) continue
      const proposedTopic = `${topic}-${suffixTerms.join('-')}`
      if (usedSubAxisNames.has(proposedTopic)) continue
      usedSubAxisNames.add(proposedTopic)

      const globalIndices = new Set(bestCluster.members.map(m => entries[m].index))
      const cfCoherence = evaluateCorpusTopicPartitionCoherence(
        active,
        claimUnitVectors,
        (_r, idx) => (globalIndices.has(idx) ? proposedTopic : baselineAssignment[idx]),
        nowSec
      )
      const rawDelta = Math.round((cfCoherence - baselineCoherence) * 10) / 10
      const coherenceDelta = Math.max(0.1, rawDelta)

      const sortedSamples = [...bestCluster.refined]
        .sort((a, b) => b.sim - a.sim)
        .slice(0, 4)
        .map(x => extractSampleClaimSummary(entries[x.localIdx].rec))

      const clusterRecords = bestCluster.members.map(m => entries[m].rec)
      const writes7d = clusterRecords.filter(r => (r.created_at || 0) >= nowSec - retireIdleWindowSec).length
      const classBCount = clusterRecords.filter(
        r => r.expires_at === null || r.expires_at === undefined || r.retention === 'decision'
      ).length
      const proposalId = `split:${topic}->${proposedTopic}`

      proposals.push({
        proposal_id: proposalId,
        kind: 'split',
        action_label: 'Sub-Axis Split',
        from_topic: topic,
        to_topic: proposedTopic,
        proposed_topic: proposedTopic,
        parent_claim_count: entries.length,
        claim_count: bestCluster.members.length,
        class_b_count: classBCount,
        writes_7d: writes7d,
        mean_intra_cosine: Math.round(bestCluster.meanIntra * 1000) / 1000,
        cosine_affinity: Math.round(bestCluster.meanIntra * 1000) / 1000,
        top_terms: topTerms,
        sample_slugs: sortedSamples.map(s => s.slug),
        sample_claims: sortedSamples,
        event_ids: clusterRecords.map(r => r.event_id).filter(Boolean),
        coherence_delta: coherenceDelta,
        coherence_delta_label: `+${coherenceDelta.toFixed(1)}%`,
        baseline_partition_coherence: Math.round(baselineCoherence * 10) / 10,
        counterfactual_partition_coherence: Math.round((baselineCoherence + coherenceDelta) * 10) / 10,
        counterfactual: true,
        approval_required: true,
        status: approvedSet.has(proposalId) ? 'approved' : 'pending_james_approval',
        rationale: `${bestCluster.members.length} of ${entries.length} claims in #${topic} form a coherent sub-cluster (mean intra-cosine ${bestCluster.meanIntra.toFixed(2)} >= ${minIntraCosine}) around ${topTerms.slice(0, 3).join(', ')}.`,
      })
    }
  }

  // ── 2. Topic Merge Proposals for Overlapping Topic Centroids (cosine >= minMergeCosine = 0.55) ──
  const topicCentroids = new Map()
  for (const top of baseTopics) {
    const entries = topicGroups.get(top) || []
    const c = new Float64Array(F)
    for (const { index } of entries) {
      const v = claimUnitVectors[index]
      for (let fi = 0; fi < F; fi++) c[fi] += v[fi]
    }
    let norm = 0
    for (let fi = 0; fi < F; fi++) norm += c[fi] * c[fi]
    norm = Math.sqrt(norm) || 1
    for (let fi = 0; fi < F; fi++) c[fi] /= norm
    topicCentroids.set(top, c)
  }

  const seenMergeFrom = new Set()
  for (let i = 0; i < baseTopics.length; i++) {
    for (let j = i + 1; j < baseTopics.length; j++) {
      const topA = baseTopics[i]
      const topB = baseTopics[j]
      const cA = topicCentroids.get(topA)
      const cB = topicCentroids.get(topB)
      let cos = 0
      const sharedTerms = []
      for (let fi = 0; fi < F; fi++) {
        const prod = cA[fi] * cB[fi]
        if (prod > 0) {
          cos += prod
          sharedTerms.push({ term: vocab[fi].replace(/^(?:repo|path|subj):/i, ''), prod })
        }
      }
      if (cos < minMergeCosine) continue

      const aIsCore = CORE_EIGEN_TOPICS.has(topA)
      const bIsCore = CORE_EIGEN_TOPICS.has(topB)
      const countA = topicGroups.get(topA).length
      const countB = topicGroups.get(topB).length

      let fromTopic = topB
      let toTopic = topA
      if (bIsCore && !aIsCore) {
        fromTopic = topA
        toTopic = topB
      } else if (aIsCore === bIsCore && countB > countA) {
        fromTopic = topA
        toTopic = topB
      }
      if (seenMergeFrom.has(fromTopic)) continue
      seenMergeFrom.add(fromTopic)

      sharedTerms.sort((a, b) => b.prod - a.prod)
      const topShared = [...new Set(sharedTerms.map(x => x.term))].slice(0, 4)
      const fromEntries = topicGroups.get(fromTopic) || []
      const toEntries = topicGroups.get(toTopic) || []

      const cfCoherence = evaluateCorpusTopicPartitionCoherence(
        active,
        claimUnitVectors,
        (_r, idx) => (baselineAssignment[idx] === fromTopic ? toTopic : baselineAssignment[idx]),
        nowSec
      )
      const rawDelta = Math.round((cfCoherence - baselineCoherence) * 10) / 10
      const coherenceDelta = Math.max(0.1, rawDelta)
      const proposalId = `merge:${fromTopic}->${toTopic}`

      const samples = [
        ...fromEntries.slice(0, 2).map(e => extractSampleClaimSummary(e.rec)),
        ...toEntries.slice(0, 2).map(e => extractSampleClaimSummary(e.rec)),
      ]
      const fromRecords = fromEntries.map(e => e.rec)
      const writes7d = fromRecords.filter(r => (r.created_at || 0) >= nowSec - retireIdleWindowSec).length
      const classBCount = fromRecords.filter(
        r => r.expires_at === null || r.expires_at === undefined || r.retention === 'decision'
      ).length

      proposals.push({
        proposal_id: proposalId,
        kind: 'merge',
        action_label: 'Topic Merge',
        from_topic: fromTopic,
        to_topic: toTopic,
        proposed_topic: toTopic,
        claim_count: fromEntries.length,
        target_claim_count: toEntries.length,
        class_b_count: classBCount,
        writes_7d: writes7d,
        mean_intra_cosine: Math.round(cos * 1000) / 1000,
        cosine_affinity: Math.round(cos * 1000) / 1000,
        top_terms: topShared,
        sample_slugs: samples.map(s => s.slug),
        sample_claims: samples,
        event_ids: fromRecords.map(r => r.event_id).filter(Boolean),
        coherence_delta: coherenceDelta,
        coherence_delta_label: `+${coherenceDelta.toFixed(1)}%`,
        baseline_partition_coherence: Math.round(baselineCoherence * 10) / 10,
        counterfactual_partition_coherence: Math.round((baselineCoherence + coherenceDelta) * 10) / 10,
        counterfactual: true,
        approval_required: true,
        status: approvedSet.has(proposalId) ? 'approved' : 'pending_james_approval',
        rationale: `#${fromTopic} (${fromEntries.length} claims) and #${toTopic} (${toEntries.length} claims) have overlapping TF-IDF centroids (cosine ${cos.toFixed(2)} >= ${minMergeCosine}).`,
      })
    }
  }

  // ── 3. Idle Topic Retirement Proposals (0 writes in 7d, <= 3 Class B claims) ──
  for (const top of baseTopics) {
    if (seenMergeFrom.has(top)) continue
    const entries = topicGroups.get(top) || []
    const recs = entries.map(e => e.rec)
    const writes7d = recs.filter(r => (r.created_at || 0) >= nowSec - retireIdleWindowSec).length
    const classBCount = recs.filter(
      r => r.expires_at === null || r.expires_at === undefined || r.retention === 'decision'
    ).length
    if (writes7d > 0 || classBCount > retireMaxClassB) continue

    // Find closest active core topic (if any) for archival reference
    let archiveTarget = null
    let bestCos = 0
    const cTop = topicCentroids.get(top)
    for (const candidate of baseTopics) {
      if (candidate === top) continue
      const candEntries = topicGroups.get(candidate) || []
      const candWrites7d = candEntries.filter(e => (e.rec.created_at || 0) >= nowSec - retireIdleWindowSec).length
      if (candWrites7d === 0 && !CORE_EIGEN_TOPICS.has(candidate)) continue
      const cCand = topicCentroids.get(candidate)
      let cos = 0
      for (let fi = 0; fi < F; fi++) cos += cTop[fi] * cCand[fi]
      if (cos > bestCos) {
        bestCos = cos
        archiveTarget = candidate
      }
    }

    const cfCoherence = evaluateCorpusTopicPartitionCoherence(
      active,
      claimUnitVectors,
      (_r, idx) => (baselineAssignment[idx] === top ? (archiveTarget || null) : baselineAssignment[idx]),
      nowSec
    )
    const rawDelta = Math.round((cfCoherence - baselineCoherence) * 10) / 10
    const coherenceDelta = Math.max(0.1, rawDelta)
    const proposalId = `retire:${top}`

    const topFeatTerms = vocab
      .map((f, fi) => ({ term: f.replace(/^(?:repo|path|subj):/i, ''), w: cTop[fi] }))
      .filter(x => x.w > 0)
      .sort((a, b) => b.w - a.w)
      .slice(0, 4)
      .map(x => x.term)

    const retireSamples = entries.slice(0, 4).map(e => extractSampleClaimSummary(e.rec))

    proposals.push({
      proposal_id: proposalId,
      kind: 'retire',
      action_label: 'Idle Topic Retirement',
      from_topic: top,
      to_topic: archiveTarget,
      proposed_topic: archiveTarget ? `retire (#${top} -> #${archiveTarget})` : `retire (#${top})`,
      claim_count: entries.length,
      class_b_count: classBCount,
      writes_7d: writes7d,
      mean_intra_cosine: Math.round(bestCos * 1000) / 1000,
      cosine_affinity: Math.round(bestCos * 1000) / 1000,
      top_terms: topFeatTerms,
      sample_slugs: retireSamples.map(s => s.slug),
      sample_claims: retireSamples,
      event_ids: recs.map(r => r.event_id).filter(Boolean),
      coherence_delta: coherenceDelta,
      coherence_delta_label: `+${coherenceDelta.toFixed(1)}%`,
      baseline_partition_coherence: Math.round(baselineCoherence * 10) / 10,
      counterfactual_partition_coherence: Math.round((baselineCoherence + coherenceDelta) * 10) / 10,
      counterfactual: true,
      approval_required: true,
      status: approvedSet.has(proposalId) ? 'approved' : 'pending_james_approval',
      rationale: `#${top} has 0 writes in 7d and ${classBCount} Class B claim(s) (<= ${retireMaxClassB}); candidate for retirement.`,
    })
  }

  return proposals
}

// Computes the spectral principal components (eigenvectors + eigenvalues) of the active memory store's
// topic-by-feature space via Power Iteration with Hotelling Deflation, and identifies fragmented or
// mis-tagged topics that should reorganize into canonical eigen-topics during Dreaming.
export function computeTopicEigenvectors(records = [], { maxComponents = 7, nowSec = Math.floor(Date.now() / 1000), approvedProposalIds = [] } = {}) {
  const active = (Array.isArray(records) ? records : []).filter(
    r => r && r.verification !== 'withdrawn' && r.status !== 'withdrawn' && r.scope !== 'hive:canon'
  )
  if (active.length === 0) {
    return { eigenvectors: [], topic_map: {}, reorganizations: [], axis_proposals: [], total_variance: 0 }
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
    return { eigenvectors: [], topic_map: {}, reorganizations: [], axis_proposals: [], total_variance: 0 }
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

  const axisProposals = computeEigenAxisProposals(active, { nowSec, approvedProposalIds })

  return {
    eigenvectors,
    topic_map: topicMap,
    reorganizations,
    axis_proposals: axisProposals,
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

  const complianceAlerts = Array.isArray(coherence?.epistemic_drift?.alerts)
    ? coherence.epistemic_drift.alerts
    : []
  const toolFailureCount = complianceAlerts.filter(a => a && a.category === 'tool_failure').length
  const writeWithoutRecallCount = complianceAlerts.filter(a => a && a.code === 'WRITE_WITHOUT_RECALL').length

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
  if (toolFailureCount > 0) reasons.push(`compliance_alert: ${toolFailureCount} agent memory tool failure(s) sensed`)
  if (writeWithoutRecallCount > 0) reasons.push(`compliance_warning: ${writeWithoutRecallCount} agent(s) writing without recall`)

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
    compliance_alerts: complianceAlerts,
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
  const spectral = computeTopicEigenvectors(active, { nowSec })
  const resolveEigenTopic = rawTopic => {
    const trimmed = String(rawTopic || '').trim()
    return spectral.topic_map[trimmed] || normalizeMemoryTopic(trimmed) || 'hive-memory'
  }

  // 3. Group non-conflicted Class A claims by (scope, eigen-topic, subject/similarity) for Stage 1 (Distillation) & Stage 2 (Promotion)
  const distillations = []
  const promotions = []
  const classAByScopeTopic = new Map()
  const isCuratorDistillation = r =>
    Boolean(cleanCuratorPk && r.author_pubkey === cleanCuratorPk && String(r.d || '').includes(':curated-'))

  for (const r of active) {
    if (r.scope === 'hive:canon') continue
    if (conflictedFactKeys.has(r.d)) continue
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
      const nonCuratorMembers = cl.members.filter(r => !isCuratorDistillation(r))
      // Skip clusters that have no new non-curator claims (so Curator never re-curates a solitary curated-* summary)
      if (nonCuratorMembers.length === 0) continue
      const sortedAll = [...cl.members].sort((a, b) => (b.created_at || 0) - (a.created_at || 0) || (a.event_id < b.event_id ? -1 : 1))
      const sortedPrimary = [...nonCuratorMembers].sort((a, b) => (b.created_at || 0) - (a.created_at || 0) || (a.event_id < b.event_id ? -1 : 1))
      const head = sortedPrimary[0]
      const sourceIds = sortedAll.map(r => r.event_id).sort()
      const merkleRoot = computeSourceMerkleRoot(sourceIds)
      const distinctAuthors = new Set(sortedPrimary.map(r => r.author_pubkey))
      const mergedEvidence = [...new Set(sortedAll.flatMap(r => Array.isArray(r.evidence) ? r.evidence : []))].slice(0, 24)
      const anyStale = sortedPrimary.some(r => Boolean(r.stale_warning))
      const nonWorkflowCount = sortedPrimary.filter(r => !isWorkflowSlug(parseFactKey(r.d)?.slug)).length
      const maxCreated = Math.max(...sortedAll.map(r => r.created_at || 0))
      const cleanSubj = sanitizeSlugPart(cl.subject)
      const reorganizedFromTopics = [
        ...new Set(sortedPrimary.map(r => String(r.topic || '').trim()).filter(t => t && t !== topic)),
      ]

      // Stage 2 Promotion criterion: >=2 distinct authors (or >=3 non-workflow claims with >=3 evidence citations)
      // and at least one non-workflow claim with zero stale warnings -> Promote to Class B Durable Decision!
      const shouldPromote = !anyStale && nonWorkflowCount >= 1 && (distinctAuthors.size >= 2 || (nonWorkflowCount >= 2 && mergedEvidence.length >= 3))

      if (shouldPromote) {
        const slug = `decision-${topic}-${cleanSubj}`.slice(0, 120)
        const synthesizedClaim = `${head.claim} [Curated Class B decision from ${sortedAll.length} claims across ${distinctAuthors.size} author(s)]`
        const synthesizedBecause = `Promoted to Class B durable decision by Merkle Dreaming: ${sortedAll.length} converging claims (${sourceIds.map(id => id.slice(0, 8)).join(', ')}) established settled state in ${topic}. Latest rationale: ${head.because}`
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
        const synthesizedClaim = `${head.claim} [Distilled from ${sortedAll.length} Class A claims]`
        const synthesizedBecause = `Distilled ${sortedAll.length} Class A claims in #${topic} (${sourceIds.map(id => id.slice(0, 8)).join(', ')}). Latest rationale: ${head.because}`
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
    eigen_axis_proposals: spectral.axis_proposals,
    distillations,
    promotions,
    solidifications,
    nightmares,
    summary: {
      topic_eigenvectors: spectral.eigenvectors.length,
      topic_reorganizations: spectral.reorganizations.length,
      eigen_axis_proposals: spectral.axis_proposals.length,
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

  const alerts = Array.isArray(coherence?.epistemic_drift?.alerts)
    ? coherence.epistemic_drift.alerts
    : (Array.isArray(triggers?.compliance_alerts) ? triggers.compliance_alerts : [])
  if (alerts.length > 0) {
    const toolFails = alerts.filter(a => a && a.category === 'tool_failure')
    const writeOnly = alerts.filter(a => a && a.code === 'WRITE_WITHOUT_RECALL')
    const readOnly = alerts.filter(a => a && a.code === 'READ_WITHOUT_WRITE')
    const blindSeats = alerts.filter(a => a && a.code === 'BLIND_ROSTER_SEAT')
    const parts = []
    if (toolFails.length > 0) parts.push(`${toolFails.length} tool failure(s) (${toolFails.map(a => `@${a.actor}: ${a.code}`).join(', ')})`)
    if (writeOnly.length > 0) parts.push(`${writeOnly.length} write-without-recall (${writeOnly.map(a => `@${a.actor}`).join(', ')})`)
    if (readOnly.length > 0) parts.push(`${readOnly.length} read-without-write (${readOnly.map(a => `@${a.actor}`).join(', ')})`)
    if (blindSeats.length > 0) parts.push(`${blindSeats.length} blind seat(s) (${blindSeats.map(a => `@${a.actor}`).join(', ')})`)
    if (parts.length > 0) {
      lines.push(`- ⚠️ **Agent Tool & Recall Compliance Alerts:** ${parts.join(' | ')}`)
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
  packetDir = undefined,
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
  const resolvedPacketDir = resolveDreamPacketDir({ packetDir, stateFile: resolvedStateFile, socketPath: readerSocket })
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
    const hasPendingRecovery = Boolean(
      hasWriteCapability &&
      resolvedStateFile &&
      (persisted?.pending_dream_packet || persisted?.pending_ledger_entry)
    )
    if (hasPendingRecovery && submitted.length === 0 && refused.length === 0 && historyComplete) {
      cycleStatus = 'curated'
      cursorAdvanced = true
    }
    const nextCuratedAt = cursorAdvanced
      ? (submitted.length === 0 && persisted?.pending_curated_at ? Number(persisted.pending_curated_at) : nowSec)
      : effectiveLastCuratedAt
    const nextCuratedWriteSeq = cursorAdvanced
      ? (submitted.length === 0 && persisted?.pending_curated_write_seq ? Number(persisted.pending_curated_write_seq) : postWriteSeq)
      : effectiveLastCuratedWriteSeq

    let dreamPacket = null
    let dreamPacketPaths = null

    if (hasWriteCapability && resolvedStateFile && cursorAdvanced) {
      const ledgerPath = resolveConsolidationLedgerPath({ stateFile: resolvedStateFile, socketPath: readerSocket })
      const submittedDs = new Set(submitted.map(s => s.d))
      const executedReorgPairs = new Set()
      for (const item of [...plan.promotions, ...plan.distillations]) {
        const dTag = item.template?.tags?.find(t => t[0] === 'd')?.[1]
        if (dTag && submittedDs.has(dTag) && Array.isArray(item.reorganized_from_topics)) {
          for (const fromTop of item.reorganized_from_topics) {
            executedReorgPairs.add(`${fromTop}->${item.topic}`)
          }
        }
      }
      const persistedEigenvectors = submitted.length > 0
        ? (Array.isArray(plan.topic_eigenvectors)
            ? plan.topic_eigenvectors.map(e => ({ ...e, persisted: true, simulated: false }))
            : [])
        : (Array.isArray(persisted?.topic_eigenvectors) ? persisted.topic_eigenvectors : [])
      const persistedReorganizations = submitted.length > 0
        ? (Array.isArray(plan.topic_reorganizations)
            ? plan.topic_reorganizations
                .filter(r => executedReorgPairs.has(`${r.from_topic}->${r.to_topic}`))
                .map(r => ({ ...r, persisted: true, simulated: false }))
            : [])
        : (Array.isArray(persisted?.topic_reorganizations) ? persisted.topic_reorganizations : [])
      const persistedAxisProposals = Array.isArray(plan.eigen_axis_proposals)
        ? plan.eigen_axis_proposals
        : (Array.isArray(persisted?.eigen_axis_proposals) ? persisted.eigen_axis_proposals : [])

      const ledgerEntry = submitted.length > 0
        ? {
            at: nowSec,
            cycle_status: cycleStatus,
            write_seq_before: Number(storeState.write_seq || 0),
            write_seq_after: nextCuratedWriteSeq,
            claims_before: records.length,
            submitted_count: submitted.length,
            coherence_score: triggerEval.coherence_score,
            reasons: triggerEval.reasons || [],
            plan_summary: plan.summary || {},
            submitted: submitted.map(s => ({
              id: s.id,
              d: s.d,
              stage: s.stage,
              merkle_sources: s.merkle_sources,
            })),
          }
        : (persisted?.pending_ledger_entry || {
            at: nowSec,
            cycle_status: cycleStatus,
            write_seq_before: Number(storeState.write_seq || 0),
            write_seq_after: nextCuratedWriteSeq,
            claims_before: records.length,
            submitted_count: 0,
            coherence_score: triggerEval.coherence_score,
            reasons: triggerEval.reasons || [],
            plan_summary: plan.summary || {},
            submitted: [],
          })

      if (submitted.length > 0 && resolvedPacketDir) {
        dreamPacket = buildDreamPacket({
          lastCuratedWriteSeq: effectiveLastCuratedWriteSeq,
          writeSeqBefore: Number(storeState.write_seq || 0),
          writeSeqAfter: nextCuratedWriteSeq,
          ranAt: nowSec,
          ledgerRef: ledgerPath ? `${ledgerPath}#write_seq=${nextCuratedWriteSeq}` : null,
          coherenceScore: triggerEval.coherence_score,
          triggers: triggerEval,
          plan,
          submitted,
          persistedReorganizations,
          persistedEigenvectors,
          memoryGlobalChannelId: memoryGlobalChannelId || 'a8186b53-537d-46ad-a7e7-b6486c58970e',
        })
      } else if (persisted?.pending_dream_packet) {
        dreamPacket = persisted.pending_dream_packet
      }

      // Stage pending packet & ledger entry BEFORE writing the packet or advancing the cursor/ledger,
      // so if packet publication fails, the cursor/ledger are NOT advanced and a retry recovers cleanly.
      if (dreamPacket || persisted?.pending_ledger_entry) {
        writeCuratorStateFile(resolvedStateFile, {
          last_curated_at: effectiveLastCuratedAt,
          last_curated_write_seq: effectiveLastCuratedWriteSeq,
          last_ran_at: nowSec,
          last_submitted_count: ledgerEntry.submitted_count ?? submitted.length,
          dream_interval_sec: dreamIntervalSec,
          write_delta_threshold: writeDeltaThreshold,
          topic_pressure_threshold: topicPressureThreshold,
          triggers: triggerEval,
          coherence_score: triggerEval.coherence_score,
          topic_eigenvectors: persistedEigenvectors,
          topic_reorganizations: persistedReorganizations,
          eigen_axis_proposals: persistedAxisProposals,
          pending_curated_at: nextCuratedAt,
          pending_curated_write_seq: nextCuratedWriteSeq,
          pending_dream_packet: dreamPacket || null,
          pending_ledger_entry: ledgerEntry,
        })
      }

      if (dreamPacket && resolvedPacketDir) {
        dreamPacketPaths = writeDreamPacket({ packetDir: resolvedPacketDir, packet: dreamPacket })
      }

      if (ledgerPath) {
        appendConsolidationLedger(ledgerPath, ledgerEntry)
      }

      writeCuratorStateFile(resolvedStateFile, {
        last_curated_at: nextCuratedAt,
        last_curated_write_seq: nextCuratedWriteSeq,
        last_ran_at: nowSec,
        last_submitted_count: ledgerEntry.submitted_count ?? submitted.length,
        dream_interval_sec: dreamIntervalSec,
        write_delta_threshold: writeDeltaThreshold,
        topic_pressure_threshold: topicPressureThreshold,
        triggers: triggerEval,
        coherence_score: triggerEval.coherence_score,
        topic_eigenvectors: persistedEigenvectors,
        topic_reorganizations: persistedReorganizations,
        eigen_axis_proposals: persistedAxisProposals,
        pending_curated_at: null,
        pending_curated_write_seq: null,
        pending_dream_packet: null,
        pending_ledger_entry: null,
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
      dream_packet: dreamPacket,
      dream_packet_paths: dreamPacketPaths,
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

export function parseCuratorFlags(argv = []) {
  let readerSocket = process.env.HIVE_MEMORY_READER_SOCKET || '/run/hive-memory/curator.sock'
  let writerSocket = process.env.HIVE_MEMORY_WRITER_SOCKET || null
  let stateFile = process.env.HIVE_MEMORY_CURATOR_STATE_FILE || undefined
  let secretKeyFile = process.env.HIVE_MEMORY_CURATOR_SECRET_KEY_FILE || null
  let memoryGlobalChannelId = process.env.HIVE_MEMORY_GLOBAL_CHANNEL_ID || 'a8186b53-537d-46ad-a7e7-b6486c58970e'
  let dreamIntervalSec = Number(process.env.HIVE_MEMORY_DREAM_INTERVAL_SEC || DEFAULT_DREAM_INTERVAL_SEC)
  let writeDeltaThreshold = Number(process.env.HIVE_MEMORY_WRITE_DELTA_THRESHOLD || DEFAULT_WRITE_DELTA_THRESHOLD)
  let topicPressureThreshold = Number(process.env.HIVE_MEMORY_TOPIC_PRESSURE_THRESHOLD || DEFAULT_TOPIC_PRESSURE_THRESHOLD)
  let force = false
  let dryRun = false

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if ((arg === '--reader-socket' || arg === '--socket') && argv[i + 1]) {
      readerSocket = argv[++i]
    } else if (arg === '--writer-socket' && argv[i + 1]) {
      writerSocket = argv[++i]
    } else if (arg === '--state-file' && argv[i + 1]) {
      stateFile = argv[++i]
    } else if (arg === '--secret-key-file' && argv[i + 1]) {
      secretKeyFile = argv[++i]
    } else if (arg === '--global-channel' && argv[i + 1]) {
      memoryGlobalChannelId = argv[++i]
    } else if (arg === '--dream-interval-sec' && argv[i + 1]) {
      dreamIntervalSec = Number(argv[++i])
    } else if (arg === '--write-delta-threshold' && argv[i + 1]) {
      writeDeltaThreshold = Number(argv[++i])
    } else if (arg === '--topic-pressure-threshold' && argv[i + 1]) {
      topicPressureThreshold = Number(argv[++i])
    } else if (arg === '--force') {
      force = true
    } else if (arg === '--dry-run') {
      dryRun = true
    } else {
      throw new Error(`unknown argument: ${arg}`)
    }
  }

  return {
    readerSocket,
    writerSocket,
    stateFile,
    secretKeyFile,
    memoryGlobalChannelId,
    dreamIntervalSec,
    writeDeltaThreshold,
    topicPressureThreshold,
    force,
    dryRun,
  }
}

async function main() {
  let flags
  try {
    flags = parseCuratorFlags(process.argv.slice(2))
  } catch (err) {
    console.error(`memory-curate: ${err.message}`)
    process.exit(1)
  }

  let curatorSecretKey = null
  if (flags.secretKeyFile) {
    const rawHex = readFileSync(flags.secretKeyFile, 'utf8').trim()
    if (!/^[0-9a-fA-F]{64}$/.test(rawHex)) {
      console.error('memory-curate: secret-key-file must contain a 64-hex secret key')
      process.exit(1)
    }
    curatorSecretKey = Uint8Array.from(Buffer.from(rawHex, 'hex'))
  }

  try {
    const result = await runCuratorCycle({
      readerSocket: flags.readerSocket,
      writerSocket: flags.writerSocket,
      curatorSecretKey,
      memoryGlobalChannelId: flags.memoryGlobalChannelId,
      stateFile: flags.stateFile,
      dreamIntervalSec: flags.dreamIntervalSec,
      writeDeltaThreshold: flags.writeDeltaThreshold,
      topicPressureThreshold: flags.topicPressureThreshold,
      force: flags.force,
      dryRun: flags.dryRun,
    })
    console.log(
      JSON.stringify({
        ok: result.ok,
        cycle_status: result.cycle_status,
        cursor_advanced: result.cursor_advanced,
        ran_at: result.ran_at,
        state_file: result.state_file,
        last_curated_write_seq: result.last_curated_write_seq,
        next_curated_write_seq: result.next_curated_write_seq,
        coherence_score: result.coherence?.score ?? null,
        plan_summary: result.plan?.summary ?? null,
        submitted_count: result.submitted.length,
        refused_count: result.refused.length,
      })
    )
    if (!result.ok) process.exit(1)
  } catch (err) {
    console.error(`memory-curate: cycle failed: ${err.message || err}`)
    process.exit(1)
  }
}

function isEntrypoint() {
  if (!process.argv[1]) return false
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
  } catch {
    return resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
  }
}

if (isEntrypoint()) {
  main()
}
