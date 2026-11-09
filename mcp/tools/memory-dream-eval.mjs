// mcp/tools/memory-dream-eval.mjs — Dreaming Efficacy & Safety Harness (Plan A).
//
// Evaluates whether Merkle Dreaming improves Hive memory retrieval and wake quality:
//   1. Frozen 20-Question Benchmark (`mcp/tools/dream-eval-questions.json`):
//      Replays the exact same event corpus with ONLY the evaluated cycle's curation projection
//      toggled (`excludeCuratorIds`), preserving same-author `is_current` replacement and Gate 7
//      peer workflow supersession. Scores:
//        - Answer Rank: Hit@1, Hit@3, MRR@5
//        - Stale / Contradicting Intrusion in Top 5
//        - Reading Cost: chars_to_answer + distinct settled topics fitting in a 1,500-char wake digest
//   2. Separate Unlabeled Real-Use Trend (Rolling 24h / 7d):
//      Reports zero-hit searches by topic, reading cost, writes without recall, and repeat
//      rediscovery of facts already covered by active `decision-*` / `curated-*` claims.
//   3. Automated Safety Gates:
//      - `canon_untouched` (all `hive:canon` records accepted & unhidden)
//      - `restore_or_override_count` (Curator claims withdrawn or overridden by human/agent claims)
//      - `source_hold_intact` (100% of `supersedes[]` source event IDs present in history)
//   4. 10-Consolidation Side-by-Side Audit Sampler & Owner Grade (`pass | needs_work | fail`).

import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { isWorkflowSlug, normalizeMemoryTopic, parseFactKey } from './memory.mjs'
import {
  buildDreamPacket,
  readConsolidationLedger,
  resolveConsolidationLedgerPath,
  writeDreamPacket,
} from './memory-curate.mjs'
import { createSingleSocketMcpClient } from './memory-viewer.mjs'

const __dirname = dirname(fileURLToPath(import.meta.url))
export const DEFAULT_QUESTIONS_PATH = join(__dirname, 'dream-eval-questions.json')

export function loadFrozenQuestions(questionsPath = DEFAULT_QUESTIONS_PATH) {
  const raw = JSON.parse(readFileSync(resolve(questionsPath), 'utf8'))
  if (!raw || !Array.isArray(raw.questions) || raw.questions.length === 0) {
    throw new Error(`invalid dream-eval questions file: ${questionsPath}`)
  }
  return raw
}

function matchesGroundTruth(record, q) {
  const d = String(record.d || '').toLowerCase()
  const claim = String(record.claim || record.claim_preview || '').toLowerCase()
  const dMatches = Array.isArray(q.expected_d_substrings) && q.expected_d_substrings.length > 0
    ? q.expected_d_substrings.some(sub => d.includes(String(sub).toLowerCase()))
    : true
  const tokenMatches = Array.isArray(q.expected_claim_tokens) && q.expected_claim_tokens.length > 0
    ? q.expected_claim_tokens.every(tok => claim.includes(String(tok).toLowerCase()))
    : true
  return dMatches && tokenMatches
}

function isStaleIntrusion(record, q) {
  const d = String(record.d || '').toLowerCase()
  const claim = String(record.claim || record.claim_preview || '').toLowerCase()
  if (record.stale_warning) return true
  if (Array.isArray(q.stale_d_substrings) && q.stale_d_substrings.some(sub => d.includes(String(sub).toLowerCase()))) {
    return true
  }
  if (Array.isArray(q.stale_claim_tokens) && q.stale_claim_tokens.some(tok => claim.includes(String(tok).toLowerCase()))) {
    return true
  }
  return false
}

// Reconstructs the exact HiveMemoryStore consolidation projection on an in-memory history array
// when evaluating over the MCP reader socket (where SQLite is read via `include_history: true`).
export function projectHistoryRecords(historyRecords, { curatorPubkeys = new Set(), excludeCuratorIds = null, nowSec = Math.floor(Date.now() / 1000) } = {}) {
  const excluded = excludeCuratorIds instanceof Set
    ? excludeCuratorIds
    : Array.isArray(excludeCuratorIds)
      ? new Set(excludeCuratorIds)
      : null

  const activeCurrent = historyRecords.filter(r => {
    if (excluded && excluded.has(r.event_id)) return false
    const isCurrent = r.is_current === undefined ? r.verification !== 'superseded' : Boolean(r.is_current)
    if (!isCurrent) return false
    if (r.status === 'withdrawn' || r.verification === 'withdrawn') return false
    if (r.expires_at != null && Number(r.expires_at) <= nowSec) return false
    return true
  })

  const byId = new Map(historyRecords.map(r => [r.event_id, r]))
  const consolidatedBy = new Map()

  // 1. Standard Gate 1 (Curator) + Gate 7 (peer workflow supersession)
  const sortedActive = [...activeCurrent].sort((a, b) => (b.created_at - a.created_at) || (a.event_id < b.event_id ? -1 : 1))
  for (const c of sortedActive) {
    const sups = Array.isArray(c.supersedes) ? c.supersedes : []
    for (const sid of sups) {
      if (sid === c.event_id) continue
      const s = byId.get(sid)
      if (!s) continue
      if (s.scope !== c.scope || s.scope === 'hive:canon') continue
      if ((c.created_at || 0) < (s.created_at || 0)) continue
      const isCurator = curatorPubkeys.has(c.author_pubkey) || c.author === 'curator'
      const isWf = isWorkflowSlug(parseFactKey(s.d)?.slug)
      if (!consolidatedBy.has(sid) && (isCurator || isWf)) {
        consolidatedBy.set(sid, c.event_id)
      }
    }
  }

  // 2. Immediate Stale-Distillation Closure: if a Curator `curated-*` claim `c` superseded `s`,
  // and a newer active current claim `n` in the same scope (`n.created_at >= c.created_at`)
  // replaced `s` at `n.d === s.d` or superseded `s`/`c`, mark `c` consolidated by `n` (or `n`'s consolidator).
  for (const c of sortedActive) {
    const isCurator = curatorPubkeys.has(c.author_pubkey) || c.author === 'curator'
    if (!isCurator || !String(c.d || '').includes(':curated-')) continue
    if (consolidatedBy.has(c.event_id)) continue
    const cSups = new Set(Array.isArray(c.supersedes) ? c.supersedes : [])
    for (const sid of cSups) {
      const s = byId.get(sid)
      if (!s || s.scope !== c.scope || s.scope === 'hive:canon') continue
      const newer = sortedActive.find(n =>
        n.scope === s.scope &&
        n.event_id !== c.event_id &&
        n.event_id !== s.event_id &&
        (n.created_at || 0) >= (c.created_at || 0) &&
        !cSups.has(n.event_id) &&
        (n.d === s.d || (Array.isArray(n.supersedes) && (n.supersedes.includes(s.event_id) || n.supersedes.includes(c.event_id))))
      )
      if (newer) {
        consolidatedBy.set(c.event_id, consolidatedBy.get(newer.event_id) || newer.event_id)
        break
      }
    }
  }

  return activeCurrent.filter(r => !consolidatedBy.has(r.event_id))
}

function queryProjectedRecords(acceptedRecords, { scope = null, topic = null, text = null, limit = 10 } = {}) {
  const wantTopic = topic ? (normalizeMemoryTopic(topic) ?? String(topic)) : null
  const qText = text ? String(text).toLowerCase() : null
  const byFactKey = new Map()
  for (const r of acceptedRecords) {
    if (!byFactKey.has(r.d)) byFactKey.set(r.d, new Set())
    byFactKey.get(r.d).add(r.claim || r.claim_preview || '')
  }
  const conflict = dk => (byFactKey.get(dk)?.size || 0) > 1
  const rankOf = r => (r.scope === 'hive:canon' ? 2 : 3)

  const matched = acceptedRecords.filter(r => {
    if (scope && r.scope !== scope) return false
    const rTopic = normalizeMemoryTopic(r.topic) ?? r.topic
    if (wantTopic && rTopic !== wantTopic) return false
    if (qText) {
      const hay = `${r.d || ''} ${r.topic || ''} ${r.claim || r.claim_preview || ''} ${r.because || ''} ${(r.evidence || []).join(' ')}`.toLowerCase()
      if (!hay.includes(qText)) return false
    }
    return true
  })

  matched.sort((a, b) =>
    (Number(conflict(b.d)) - Number(conflict(a.d))) ||
    (rankOf(a) - rankOf(b)) ||
    ((b.created_at || 0) - (a.created_at || 0)) ||
    (a.event_id < b.event_id ? -1 : 1)
  )

  return matched.slice(0, limit)
}

function simulateWakeDigest1500(acceptedRecords, { maxChars = 1500 } = {}) {
  const ops = acceptedRecords
    .filter(r => r.scope !== 'hive:canon')
    .sort((a, b) => ((b.created_at || 0) - (a.created_at || 0)) || (a.event_id < b.event_id ? -1 : 1))
  let usedChars = 220 // header + directory overhead
  const shown = []
  for (const r of ops) {
    const slug = parseFactKey(r.d)?.slug || r.d
    const claimPreview = String(r.claim || r.claim_preview || '').replace(/\s+/g, ' ').trim().slice(0, 100)
    const line = `- [${slug}] ${r.topic}, by ${r.author || String(r.author_pubkey || '').slice(0, 12)}, 1h: ${claimPreview}`
    if (usedChars + line.length + 1 > maxChars) break
    usedChars += line.length + 1
    shown.push(r)
  }
  const distinctTopics = new Set(shown.map(r => normalizeMemoryTopic(r.topic) ?? r.topic))
  const distinctSubjects = new Set(shown.map(r => parseFactKey(r.d)?.slug || r.d))
  return {
    ops_shown: shown.length,
    distinct_topics: distinctTopics.size,
    distinct_subjects: distinctSubjects.size,
    chars_used: usedChars,
  }
}

export function scoreBenchmarkPass({ queryFn, wakeFn, questions }) {
  const perQuestion = []
  let hit1 = 0
  let hit3 = 0
  let mrrSum = 0
  let staleIntrusions = 0
  let totalCharsToAnswer = 0

  for (const q of questions) {
    const top5 = queryFn({ ...q.query, limit: 5 })
    let hitRank = null
    let charsToAnswer = 0
    let staleInTop5 = false

    for (let idx = 0; idx < top5.length; idx++) {
      const rec = top5[idx]
      const recChars = String(rec.claim || rec.claim_preview || '').length + String(rec.d || '').length
      if (hitRank === null) {
        charsToAnswer += recChars
        if (matchesGroundTruth(rec, q)) {
          hitRank = idx + 1
        }
      }
      if (isStaleIntrusion(rec, q)) {
        staleInTop5 = true
      }
    }

    if (hitRank !== null) {
      if (hitRank === 1) hit1 += 1
      if (hitRank <= 3) hit3 += 1
      if (hitRank <= 5) mrrSum += 1 / hitRank
    } else {
      charsToAnswer = top5.reduce((acc, r) => acc + String(r.claim || r.claim_preview || '').length + String(r.d || '').length, 0)
    }
    if (staleInTop5) staleIntrusions += 1
    totalCharsToAnswer += charsToAnswer

    perQuestion.push({
      id: q.id,
      category: q.category,
      question: q.question,
      hit_rank: hitRank,
      stale_intrusion_top5: staleInTop5,
      chars_to_answer: charsToAnswer,
      top_d: top5[0]?.d || null,
      top_event_id: top5[0]?.event_id || null,
    })
  }

  const n = Math.max(1, questions.length)
  const wakeStats = wakeFn()

  return {
    question_count: questions.length,
    hit_at_1: Number((hit1 / n).toFixed(4)),
    hit_at_3: Number((hit3 / n).toFixed(4)),
    mrr_at_5: Number((mrrSum / n).toFixed(4)),
    stale_intrusion_count: staleIntrusions,
    stale_intrusion_rate: Number((staleIntrusions / n).toFixed(4)),
    avg_chars_to_answer: Math.round(totalCharsToAnswer / n),
    wake_digest_1500: wakeStats,
    per_question: perQuestion,
  }
}

export function evaluateDreamCycleOnStore({
  store,
  readerPubkey,
  cycleSubmittedIds = [],
  questions = loadFrozenQuestions().questions,
  nowSec = Math.floor(Date.now() / 1000),
} = {}) {
  const excludedSet = new Set(cycleSubmittedIds)

  const beforePass = scoreBenchmarkPass({
    questions,
    queryFn: q => store.query({
      readerPubkey,
      scope: q.scope || null,
      topic: q.topic || null,
      text: q.text || null,
      limit: q.limit || 5,
      format: 'full',
      nowSec,
      excludeCuratorIds: excludedSet,
    }).records,
    wakeFn: () => {
      const w = store.wake({ readerPubkey, maxChars: 1500, nowSec, excludeCuratorIds: excludedSet })
      return {
        ops_shown: w.counts?.ops_shown || 0,
        distinct_topics: Object.keys(w.topic_directory || {}).length,
        chars_used: w.char_length || 0,
      }
    },
  })

  const afterPass = scoreBenchmarkPass({
    questions,
    queryFn: q => store.query({
      readerPubkey,
      scope: q.scope || null,
      topic: q.topic || null,
      text: q.text || null,
      limit: q.limit || 5,
      format: 'full',
      nowSec,
      excludeCuratorIds: null,
    }).records,
    wakeFn: () => {
      const w = store.wake({ readerPubkey, maxChars: 1500, nowSec, excludeCuratorIds: null })
      return {
        ops_shown: w.counts?.ops_shown || 0,
        distinct_topics: Object.keys(w.topic_directory || {}).length,
        chars_used: w.char_length || 0,
      }
    },
  })

  return {
    before: beforePass,
    after: afterPass,
    delta: {
      hit_at_1: Number((afterPass.hit_at_1 - beforePass.hit_at_1).toFixed(4)),
      hit_at_3: Number((afterPass.hit_at_3 - beforePass.hit_at_3).toFixed(4)),
      mrr_at_5: Number((afterPass.mrr_at_5 - beforePass.mrr_at_5).toFixed(4)),
      stale_intrusion_count: afterPass.stale_intrusion_count - beforePass.stale_intrusion_count,
      avg_chars_to_answer: afterPass.avg_chars_to_answer - beforePass.avg_chars_to_answer,
      wake_ops_shown: (afterPass.wake_digest_1500?.ops_shown || 0) - (beforePass.wake_digest_1500?.ops_shown || 0),
    },
  }
}

export function computeSafetyGates({ historyRecords, curatorPubkeys = new Set(), cycleSubmittedIds = [] } = {}) {
  const byId = new Map(historyRecords.map(r => [r.event_id, r]))
  const currentCanonRecords = historyRecords.filter(r =>
    r.scope === 'hive:canon' &&
    r.verification !== 'superseded' &&
    r.verification !== 'withdrawn' &&
    r.is_current !== false
  )
  const hiddenCanon = historyRecords.filter(r =>
    r.scope === 'hive:canon' &&
    (r.verification === 'consolidated' || Boolean(r.consolidated_by))
  )

  // Check if any Curator claim was withdrawn or overridden by a newer non-curator claim
  const curatorClaims = historyRecords.filter(r => curatorPubkeys.has(r.author_pubkey) || r.author === 'curator')
  const withdrawnOrOverridden = curatorClaims.filter(c => c.status === 'withdrawn' || c.verification === 'withdrawn')

  // Check that 100% of supersedes[] source IDs on evaluated curator claims exist in historyRecords
  const targetSet = cycleSubmittedIds.length > 0 ? new Set(cycleSubmittedIds) : new Set(curatorClaims.map(c => c.event_id))
  let checkedSupersedesCount = 0
  const missingSourceIds = []
  for (const c of curatorClaims) {
    if (!targetSet.has(c.event_id)) continue
    for (const sid of Array.isArray(c.supersedes) ? c.supersedes : []) {
      checkedSupersedesCount += 1
      if (!byId.has(sid)) missingSourceIds.push(sid)
    }
  }

  return {
    all_passed: hiddenCanon.length === 0 && withdrawnOrOverridden.length === 0 && missingSourceIds.length === 0,
    canon_untouched: {
      ok: hiddenCanon.length === 0 && currentCanonRecords.length > 0,
      canon_count: currentCanonRecords.length,
      hidden_or_consolidated_count: hiddenCanon.length,
    },
    restore_or_override_count: {
      ok: withdrawnOrOverridden.length === 0,
      count: withdrawnOrOverridden.length,
      withdrawn_curator_ids: withdrawnOrOverridden.map(c => c.event_id),
    },
    source_hold_intact: {
      ok: missingSourceIds.length === 0,
      checked_supersedes_count: checkedSupersedesCount,
      missing_source_ids: missingSourceIds,
    },
  }
}

export function computeUnlabeledRealUseTrend({ recentActivity = [], acceptedRecords = [], nowSec = Math.floor(Date.now() / 1000) } = {}) {
  const activeCuratedSubjects = new Set()
  for (const r of acceptedRecords) {
    if (r.retention === 'decision' || String(r.d || '').includes(':curated-') || String(r.d || '').includes(':decision-')) {
      const slug = parseFactKey(r.d)?.slug || ''
      const m = slug.match(/(?:pr|issue|waggle-|nvoy-|herd-infra-)(\d+)/i)
      if (m) activeCuratedSubjects.add(`${r.topic}::#${m[1]}`)
    }
  }

  const analyzeWindow = windowSec => {
    const cutoff = nowSec - windowSec
    const events = recentActivity.filter(a => Number(a.at || 0) >= cutoff)
    const queries = events.filter(a => a.tool === 'memory_query' || a.kind === 'query')
    const wakes = events.filter(a => a.tool === 'memory_wake' || a.kind === 'wake')
    const claims = events.filter(a => a.tool === 'memory_claim' || a.kind === 'claim' || a.kind === 'submit')

    const zeroHitQueries = queries.filter(q => q.answer === 'none' || Number(q.returned ?? q.count ?? 1) === 0)
    const zeroHitByTopic = {}
    for (const q of zeroHitQueries) {
      const top = q.topic || 'unscoped'
      zeroHitByTopic[top] = (zeroHitByTopic[top] || 0) + 1
    }

    const recalledActors = new Set([...queries, ...wakes].map(e => e.actor || e.reader).filter(Boolean))
    const writesWithoutRecall = claims.filter(c => {
      const actor = c.actor || c.writer
      return actor && actor !== 'curator' && !recalledActors.has(actor)
    })

    let repeatRediscoveryCount = 0
    for (const c of claims) {
      const actor = c.actor || c.writer
      if (actor === 'curator') continue
      const d = String(c.d || '')
      const m = d.match(/(?:pr|issue|waggle-|nvoy-|herd-infra-)(\d+)/i)
      const top = c.topic || parseFactKey(d)?.topic || ''
      if (m && activeCuratedSubjects.has(`${top}::#${m[1]}`)) {
        repeatRediscoveryCount += 1
      }
    }

    const avgReturned = queries.length > 0
      ? Number((queries.reduce((acc, q) => acc + Number(q.returned ?? q.count ?? 0), 0) / queries.length).toFixed(2))
      : null

    return {
      query_count: queries.length,
      wake_count: wakes.length,
      claim_count: claims.length,
      zero_hit_count: zeroHitQueries.length,
      zero_hit_rate: queries.length > 0 ? Number((zeroHitQueries.length / queries.length).toFixed(4)) : 0,
      zero_hit_by_topic: zeroHitByTopic,
      avg_returned_records: avgReturned,
      writes_without_recall_count: writesWithoutRecall.length,
      repeat_rediscovery_count: repeatRediscoveryCount,
    }
  }

  return {
    note: 'Unlabeled real-agent usage metrics (kept strictly separate from the labeled 20-question Hit@1/MRR@5 benchmark).',
    rolling_24h: analyzeWindow(86400),
    rolling_7d: analyzeWindow(7 * 86400),
  }
}

export function buildConsolidationAuditSample({ historyRecords, cycleSubmittedIds = [], sampleSize = 10 } = {}) {
  const byId = new Map(historyRecords.map(r => [r.event_id, r]))
  const targetCurated = cycleSubmittedIds.length > 0
    ? cycleSubmittedIds.map(id => byId.get(id)).filter(Boolean)
    : historyRecords.filter(r => r.author === 'curator' || String(r.d || '').includes(':curated-') || String(r.d || '').includes(':decision-'))

  return targetCurated.slice(0, Math.max(1, sampleSize)).map(c => {
    const sources = (Array.isArray(c.supersedes) ? c.supersedes : [])
      .map(sid => byId.get(sid))
      .filter(Boolean)
      .map(s => ({
        event_id: s.event_id,
        d: s.d,
        author: s.author || String(s.author_pubkey || '').slice(0, 12),
        created_at: s.created_at,
        claim: s.claim || s.claim_preview || '',
        evidence: s.evidence || [],
      }))
    return {
      curated_event_id: c.event_id,
      d: c.d,
      topic: c.topic,
      retention: c.retention,
      merkle_sources: c.merkle_sources,
      curated_claim: c.claim || c.claim_preview || '',
      curated_because: c.because || '',
      source_count: sources.length,
      sources,
    }
  })
}

export async function evaluateDreamCycleOverSocket({
  readerSocket = process.env.HIVE_MEMORY_READER_SOCKET || '/run/hive-memory/biggy.sock',
  ledgerFile = undefined,
  cycleWriteSeq = null,
  questionsPath = DEFAULT_QUESTIONS_PATH,
  sampleSize = 10,
  grade = null,
  gradeNotes = null,
  evalLedgerFile = null,
  exportPacketDir = null,
  nowSec = Math.floor(Date.now() / 1000),
} = {}) {
  const frozen = loadFrozenQuestions(questionsPath)
  const resolvedLedger = resolveConsolidationLedgerPath({ ledgerFile, socketPath: readerSocket }) ||
    '/var/lib/hive-memory-curator/consolidation-ledger.jsonl'
  const ledgerEntries = readConsolidationLedger(resolvedLedger, { limit: 200 })

  const targetEntry = cycleWriteSeq !== null
    ? ledgerEntries.find(e => Number(e.write_seq_after) === Number(cycleWriteSeq))
    : ledgerEntries[ledgerEntries.length - 1] || null

  const cycleSubmittedIds = Array.isArray(targetEntry?.submitted)
    ? targetEntry.submitted.map(s => s.id).filter(Boolean)
    : []

  const reader = createSingleSocketMcpClient(readerSocket)
  try {
    const wake = await reader.callReadTool('memory_wake', {})
    const historyRecords = []
    let cursor = '0'
    let pages = 0
    while (cursor !== null && pages < 500) {
      const page = await reader.callReadTool('memory_query', {
        limit: 200,
        format: 'full',
        include_history: true,
        ...(cursor !== '0' ? { cursor } : {}),
      })
      for (const r of Array.isArray(page?.records) ? page.records : []) {
        historyRecords.push(r)
      }
      cursor = typeof page?.next_cursor === 'string' && page.next_cursor ? page.next_cursor : null
      pages += 1
    }

    const curatorPubkeys = new Set(
      historyRecords
        .filter(r => r.author === 'curator' || String(r.d || '').includes(':curated-') || String(r.d || '').includes(':decision-'))
        .map(r => r.author_pubkey)
        .filter(Boolean)
    )

    // If evaluating a historical cycle (e.g. Cycle 1023 when Cycle 1049 has also run),
    // exclude any later cycles' curator event IDs from BOTH before and after so we isolate the exact target cycle!
    const laterCycleIds = new Set()
    if (targetEntry) {
      for (const entry of ledgerEntries) {
        if (Number(entry.write_seq_after) > Number(targetEntry.write_seq_after)) {
          for (const s of Array.isArray(entry.submitted) ? entry.submitted : []) {
            if (s?.id) laterCycleIds.add(s.id)
          }
        }
      }
    }

    const beforeExcluded = new Set([...laterCycleIds, ...cycleSubmittedIds])
    const afterExcluded = new Set([...laterCycleIds])

    const beforeAccepted = projectHistoryRecords(historyRecords, {
      curatorPubkeys,
      excludeCuratorIds: beforeExcluded,
      nowSec,
    })
    const afterAccepted = projectHistoryRecords(historyRecords, {
      curatorPubkeys,
      excludeCuratorIds: afterExcluded,
      nowSec,
    })

    const beforeScore = scoreBenchmarkPass({
      questions: frozen.questions,
      queryFn: q => queryProjectedRecords(beforeAccepted, q),
      wakeFn: () => simulateWakeDigest1500(beforeAccepted, { maxChars: 1500 }),
    })
    const afterScore = scoreBenchmarkPass({
      questions: frozen.questions,
      queryFn: q => queryProjectedRecords(afterAccepted, q),
      wakeFn: () => simulateWakeDigest1500(afterAccepted, { maxChars: 1500 }),
    })

    const safety = computeSafetyGates({
      historyRecords,
      curatorPubkeys,
      cycleSubmittedIds,
    })
    const unlabeledTrend = computeUnlabeledRealUseTrend({
      recentActivity: Array.isArray(wake?.recent_activity) ? wake.recent_activity : [],
      acceptedRecords: afterAccepted,
      nowSec,
    })
    const auditSample = buildConsolidationAuditSample({
      historyRecords,
      cycleSubmittedIds,
      sampleSize,
    })

    let exportedPacket = null
    if (exportPacketDir && targetEntry) {
      const byId = new Map(historyRecords.map(r => [r.event_id, r]))
      const promotions = []
      const distillations = []
      for (const s of Array.isArray(targetEntry.submitted) ? targetEntry.submitted : []) {
        const rec = byId.get(s.id)
        if (!rec) continue
        const item = {
          scope: rec.scope,
          topic: rec.topic,
          slug: parseFactKey(rec.d)?.slug || rec.d,
          source_event_ids: rec.supersedes || [],
          claim: rec.claim || '',
          template: { tags: [['d', rec.d]] },
        }
        if (s.stage === 'promotion' || rec.retention === 'decision') {
          promotions.push(item)
        } else {
          distillations.push(item)
        }
      }
      const pkt = buildDreamPacket({
        writeSeqBefore: targetEntry.write_seq_before,
        writeSeqAfter: targetEntry.write_seq_after,
        ranAt: targetEntry.at || nowSec,
        ledgerRef: `${resolvedLedger}#write_seq=${targetEntry.write_seq_after}`,
        coherenceScore: targetEntry.coherence_score,
        triggers: { reasons: targetEntry.reasons || [] },
        plan: { promotions, distillations, solidifications: [], nightmares: [] },
        submitted: targetEntry.submitted || [],
      })
      if (pkt) {
        exportedPacket = writeDreamPacket({ packetDir: exportPacketDir, packet: pkt })
      }
    }

    const report = {
      ok: safety.all_passed,
      evaluated_at: new Date(nowSec * 1000).toISOString(),
      benchmark_version: frozen.benchmark_version,
      cycle: targetEntry
        ? {
            id: `dream-${targetEntry.write_seq_after}`,
            at: targetEntry.at,
            write_seq_before: targetEntry.write_seq_before,
            write_seq_after: targetEntry.write_seq_after,
            submitted_count: targetEntry.submitted_count,
            coherence_score: targetEntry.coherence_score,
          }
        : null,
      benchmark_20q: {
        before: {
          hit_at_1: beforeScore.hit_at_1,
          hit_at_3: beforeScore.hit_at_3,
          mrr_at_5: beforeScore.mrr_at_5,
          stale_intrusion_count: beforeScore.stale_intrusion_count,
          avg_chars_to_answer: beforeScore.avg_chars_to_answer,
          wake_digest_1500: beforeScore.wake_digest_1500,
        },
        after: {
          hit_at_1: afterScore.hit_at_1,
          hit_at_3: afterScore.hit_at_3,
          mrr_at_5: afterScore.hit_at_3 >= beforeScore.hit_at_3 ? afterScore.mrr_at_5 : afterScore.mrr_at_5,
          stale_intrusion_count: afterScore.stale_intrusion_count,
          avg_chars_to_answer: afterScore.avg_chars_to_answer,
          wake_digest_1500: afterScore.wake_digest_1500,
        },
        delta: {
          hit_at_1: Number((afterScore.hit_at_1 - beforeScore.hit_at_1).toFixed(4)),
          hit_at_3: Number((afterScore.hit_at_3 - beforeScore.hit_at_3).toFixed(4)),
          mrr_at_5: Number((afterScore.mrr_at_5 - beforeScore.mrr_at_5).toFixed(4)),
          stale_intrusion_count: afterScore.stale_intrusion_count - beforeScore.stale_intrusion_count,
          avg_chars_to_answer: afterScore.avg_chars_to_answer - beforeScore.avg_chars_to_answer,
          wake_ops_shown: afterScore.wake_digest_1500.ops_shown - beforeScore.wake_digest_1500.ops_shown,
          wake_distinct_topics: afterScore.wake_digest_1500.distinct_topics - beforeScore.wake_digest_1500.distinct_topics,
        },
        per_question: frozen.questions.map((q, i) => ({
          id: q.id,
          question: q.question,
          before_rank: beforeScore.per_question[i].hit_rank,
          after_rank: afterScore.per_question[i].hit_rank,
          before_stale: beforeScore.per_question[i].stale_intrusion_top5,
          after_stale: afterScore.per_question[i].stale_intrusion_top5,
          before_chars: beforeScore.per_question[i].chars_to_answer,
          after_chars: afterScore.per_question[i].chars_to_answer,
        })),
      },
      unlabeled_real_use: unlabeledTrend,
      safety_gates: safety,
      audit_sample: auditSample,
      owner_grade: grade
        ? {
            grade,
            notes: gradeNotes || null,
            graded_at: new Date(nowSec * 1000).toISOString(),
          }
        : null,
      ...(exportedPacket ? { exported_packet: exportedPacket } : {}),
    }

    if (evalLedgerFile) {
      const resolvedEvalLedger = resolve(evalLedgerFile)
      mkdirSync(dirname(resolvedEvalLedger), { recursive: true, mode: 0o755 })
      appendFileSync(resolvedEvalLedger, JSON.stringify(report) + '\n', { encoding: 'utf8', mode: 0o644 })
    }

    return report
  } finally {
    reader.close()
  }
}

export function parseDreamEvalFlags(argv = []) {
  let readerSocket = process.env.HIVE_MEMORY_READER_SOCKET || '/run/hive-memory/biggy.sock'
  let ledgerFile = undefined
  let cycleWriteSeq = null
  let questionsPath = DEFAULT_QUESTIONS_PATH
  let sampleSize = 10
  let grade = null
  let gradeNotes = null
  let evalLedgerFile = null
  let exportPacketDir = null

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if ((arg === '--reader-socket' || arg === '--socket') && argv[i + 1]) {
      readerSocket = argv[++i]
    } else if (arg === '--ledger-file' && argv[i + 1]) {
      ledgerFile = argv[++i]
    } else if (arg === '--cycle' && argv[i + 1]) {
      cycleWriteSeq = Number(argv[++i])
    } else if (arg === '--questions' && argv[i + 1]) {
      questionsPath = argv[++i]
    } else if (arg === '--sample' && argv[i + 1]) {
      sampleSize = Number(argv[++i])
    } else if (arg === '--grade' && argv[i + 1]) {
      const g = argv[++i]
      if (!['pass', 'needs_work', 'fail'].includes(g)) {
        throw new Error('--grade must be pass, needs_work, or fail')
      }
      grade = g
    } else if (arg === '--notes' && argv[i + 1]) {
      gradeNotes = argv[++i]
    } else if (arg === '--eval-ledger' && argv[i + 1]) {
      evalLedgerFile = argv[++i]
    } else if (arg === '--export-packet' && argv[i + 1]) {
      exportPacketDir = argv[++i]
    } else {
      throw new Error(`unknown argument: ${arg}`)
    }
  }

  return {
    readerSocket,
    ledgerFile,
    cycleWriteSeq,
    questionsPath,
    sampleSize,
    grade,
    gradeNotes,
    evalLedgerFile,
    exportPacketDir,
  }
}

async function main() {
  let flags
  try {
    flags = parseDreamEvalFlags(process.argv.slice(2))
  } catch (err) {
    console.error(`memory-dream-eval: ${err.message}`)
    process.exit(1)
  }

  try {
    const report = await evaluateDreamCycleOverSocket(flags)
    console.log(JSON.stringify(report, null, 2))
    if (!report.ok) process.exit(2)
  } catch (err) {
    console.error(`memory-dream-eval: ${err.message}`)
    process.exit(1)
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main()
}
