// Pure B4 recall scoring. No corpus, network, file IO or production-store mutation.
import { createHash } from 'node:crypto'
export const RECALL_CUTOFF = 10
// Sensitivity floors confirmed for v2; amendments still require exact-version method review.
export const QUALITY_FLOORS = Object.freeze({ hit_at_1: 0.5, mrr_at_10: 0.5 })
export function checkRecallMutation(cases, options) {
  const baseline = scoreRecall(cases, options)
  // Gold-independent output-ranking mutation; never edits queries, gold or the live store.
  const mutant = scoreRecall(cases.map(row => ({ ...row, ranking: row.ranking.slice(0, RECALL_CUTOFF).reverse() })), options)
  const passes = report => ['original', 'paraphrase'].every(variant =>
    Object.entries(QUALITY_FLOORS).every(([key, floor]) => typeof report[variant][key] === 'number' && report[variant][key] >= floor))
  const baseline_passes = passes(baseline), mutant_passes = passes(mutant)
  const status = !baseline_passes ? 'INCONCLUSIVE' : mutant_passes ? 'NOT_DETECTED' : 'DETECTED'
  const short_list_note = ['original', 'paraphrase'].some(variant => baseline[variant].answerable_short_list_count > 0)
    ? 'Short lists reverse over their actual length; singleton lists are unchanged. Report the per-variant answerable short-list counts and rates beside this mutation result.'
    : null
  return { mutation: 'reverse-top10-v1', floors: QUALITY_FLOORS, baseline, mutant, baseline_passes, mutant_passes, status, short_list_note, detected: status === 'DETECTED' }
}
export function scoreRecall(cases, { expectedQuestions = 100 } = {}) {
  if (!Array.isArray(cases) || !Number.isSafeInteger(expectedQuestions) || expectedQuestions < 1) throw new Error('invalid cases')
  const questions = new Map()
  for (const row of cases) {
    if (!row || typeof row.question_id !== 'string' || !row.question_id ||
        !['original', 'paraphrase'].includes(row.variant) ||
        !['answerable', 'unanswerable', 'ambiguous'].includes(row.answerability) ||
        !Array.isArray(row.ranking) || !Array.isArray(row.gold) || typeof row.abstained !== 'boolean' ||
        [...row.ranking, ...row.gold].some(id => typeof id !== 'string' || !id.length || id !== id.trim()) ||
        (row.abstained && row.ranking.length) || row.error) throw new Error('invalid or errored case')
    if ((row.answerability === 'answerable') !== (row.gold.length > 0)) throw new Error('invalid gold/answerability')
    if (!Array.isArray(row.labelers) || row.labelers.length !== 2 || new Set(row.labelers).size !== 2 ||
        row.labelers.some(name => typeof name !== 'string' || !name.trim())) throw new Error('two distinct labelers required')
    if (typeof row.adjudicator !== 'string' || !row.adjudicator.trim() || typeof row.disagreement !== 'boolean') {
      throw new Error('adjudicator and disagreement required')
    }
    if (!questions.has(row.question_id)) questions.set(row.question_id, new Map())
    const pair = questions.get(row.question_id)
    if (pair.has(row.variant)) throw new Error('duplicate question variant')
    pair.set(row.variant, row)
  }
  if (questions.size !== expectedQuestions) throw new Error('question count does not match frozen set')
  for (const pair of questions.values()) {
    const a = pair.get('original'), b = pair.get('paraphrase')
    if (!a || !b || a.answerability !== b.answerability ||
        JSON.stringify([...a.gold].sort()) !== JSON.stringify([...b.gold].sort()) ||
        JSON.stringify([...a.labelers].sort()) !== JSON.stringify([...b.labelers].sort()) ||
        a.adjudicator !== b.adjudicator || a.disagreement !== b.disagreement) throw new Error('incomplete or inconsistent question pair')
  }
  const summarize = variant => {
    const rows = cases.filter(row => row.variant === variant)
    const answerable = rows.filter(row => row.answerability === 'answerable')
    const unanswerable = rows.filter(row => row.answerability === 'unanswerable')
    const scores = answerable.map(row => scoreRanking(row.ranking, row.gold))
    const shortLists = answerable.filter(row => row.ranking.length < RECALL_CUTOFF).length
    const rate = key => scores.length ? scores.reduce((sum, score) => sum + score[key], 0) / scores.length : null
    return {
      answerable_count: answerable.length, unanswerable_count: unanswerable.length,
      ambiguous_count: rows.filter(row => row.answerability === 'ambiguous').length,
      answerable_short_list_count: shortLists,
      answerable_short_list_rate: answerable.length ? shortLists / answerable.length : null,
      hit_at_1: rate('hit_at_1'), hit_at_3: rate('hit_at_3'), mrr_at_10: rate('mrr_at_10'),
      correct_abstain_rate: unanswerable.length ? unanswerable.filter(row => row.abstained).length / unanswerable.length : null,
      false_answer_rate: unanswerable.length ? unanswerable.filter(row => !row.abstained).length / unanswerable.length : null,
    }
  }
  const gold_disagreement_count = [...questions.values()].filter(pair => pair.get('original').disagreement).length
  return {
    cutoff: RECALL_CUTOFF, question_count: questions.size,
    gold_disagreement_count, gold_disagreement_rate: gold_disagreement_count / questions.size,
    original: summarize('original'), paraphrase: summarize('paraphrase'),
  }
}

export function scoreRanking(ranking, gold) {
  if (!Array.isArray(ranking) || !Array.isArray(gold) || !gold.length ||
      [...ranking, ...gold].some(id => typeof id !== 'string' || !id.length || id !== id.trim())) throw new Error('invalid ranking/gold')
  const index = ranking.slice(0, RECALL_CUTOFF).findIndex(id => gold.includes(id))
  return { hit_at_1: Number(index === 0), hit_at_3: Number(index >= 0 && index < 3), mrr_at_10: index < 0 ? 0 : 1 / (index + 1) }
}

// Versioned agreement-only path; v3 APIs above deliberately retain their contract.
export const V31_RESULT_LABEL = 'agreement-filtered; floors not comparable to v3'
export const V31_PARAPHRASE_LIMITATION = 'paraphrase gold inherited from the base question; equivalence unverified'
export const V31_PROTOCOL_SHA256 = 'ddf45d7f0d0a37622688f7da18af57cf4a6e0e211c825c53e0d426ab0f25db5f'
export const V31_MINIMA = Object.freeze({ answerable: 20, unanswerable: 10, ambiguous: 5 })
const V31_CATEGORIES = ['answerable', 'unanswerable', 'ambiguous']
const v31Counts = () => Object.fromEntries(V31_CATEGORIES.map(c => [c, 0]))
const v31Disclosures = () => ({ protocol_version: '3.1', result_label: V31_RESULT_LABEL,
  paraphrase_gold_limitation: V31_PARAPHRASE_LIMITATION,
  author_exposure: 'author exposure: self-reported, not log-verified' })

const v31Text = s => typeof s === 'string' && s.length > 0 && s === s.trim()
const v31Hex = s => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s)
const v31Ids = a => Array.isArray(a) && [...a].every(v31Hex) && new Set(a).size === a.length

function validateFreezeV31(f) {
  if (!f || f.protocol_version !== '3.1' || f.protocol_sha256 !== V31_PROTOCOL_SHA256 ||
      f.paraphrase_gold_limitation !== V31_PARAPHRASE_LIMITATION || !v31Text(f.round_id) ||
      !Array.isArray(f.questions) || f.questions.length !== 100 ||
      !Array.isArray(f.labelers) || f.labelers.length !== 2 || new Set(f.labelers).size !== 2 ||
      !f.labelers.every(v31Text) || !f.disclosed_at) throw new Error('invalid frozen manifest')
  if ('adjudicator' in f || 'minima' in f || 'expectedQuestions' in f) throw new Error('fixed v3.1 rules; no adjudicator')
  for (const name of f.labelers) {
    const date = f.disclosed_at[name]
    if (!Object.hasOwn(f.disclosed_at, name) || typeof date !== 'string' ||
        !Number.isFinite(Date.parse(date)) || new Date(date).toISOString() !== date) throw new Error('invalid dated disclosure')
  }
  const ids = new Set()
  for (const q of f.questions) {
    if (!q || !v31Text(q.question_id) || ids.has(q.question_id) ||
        !v31Text(q.original) || !v31Text(q.paraphrase) || !Array.isArray(q.votes) ||
        q.votes.length !== 2 || 'adjudicator' in q) throw new Error('invalid frozen question or adjudicator')
    ids.add(q.question_id)
    const voters = new Set()
    for (const v of q.votes) {
      if (!v || !f.labelers.includes(v.labeler) || voters.has(v.labeler) ||
          !V31_CATEGORIES.includes(v.answerability) || !v31Ids(v.gold) || !v31Text(v.reason) ||
          (v.answerability === 'answerable') !== (v.gold.length > 0)) throw new Error('invalid frozen vote')
      voters.add(v.labeler)
    }
  }
  // Binds the ordered question strings/IDs, not the authenticity of their author.
  const questions = f.questions.map(({ question_id, original, paraphrase }) => ({ question_id, original, paraphrase }))
  const digest = createHash('sha256').update(JSON.stringify(questions)).digest('hex')
  if (!v31Hex(f.question_set_sha256) || f.question_set_sha256 !== digest) throw new Error('frozen question set changed')
}

export function prepareRecallV31(frozen) {
  validateFreezeV31(frozen)
  const category_confusion = Object.fromEntries(V31_CATEGORIES.map(c => [c, v31Counts()]))
  const exact_agreement = v31Counts()
  const before = frozen.labelers.map(() => v31Counts())
  const retained = [], excluded = []
  for (const q of frozen.questions) {
    const votes = frozen.labelers.map(name => q.votes.find(v => v.labeler === name))
    votes.forEach((v, i) => before[i][v.answerability]++)
    const [a, b] = votes
    category_confusion[a.answerability][b.answerability]++
    if (a.answerability === b.answerability &&
        JSON.stringify([...a.gold].sort()) === JSON.stringify([...b.gold].sort())) {
      exact_agreement[a.answerability]++
      retained.push({ question_id: q.question_id, original: q.original, paraphrase: q.paraphrase,
        answerability: a.answerability, gold: [...a.gold] })
    } else excluded.push(q.question_id)
  }
  const marginals = Object.fromEntries(frozen.labelers.map((name, i) => [name,
    Object.fromEntries(V31_CATEGORIES.map(c => [c, {
      pre_filter: before[i][c], survivors: exact_agreement[c], dropped: before[i][c] - exact_agreement[c],
      agreement_rate: before[i][c] ? exact_agreement[c] / before[i][c] : null,
    }]))]))
  const coverage = Object.fromEntries(V31_CATEGORIES.map(c => [c, {
    ...v31Disclosures(), count: exact_agreement[c], minimum: V31_MINIMA[c],
    status: exact_agreement[c] >= V31_MINIMA[c] ? 'PASS' : 'INCONCLUSIVE',
    metric_status: exact_agreement[c] < V31_MINIMA[c] ? 'NOT_RUN' : c === 'answerable' ? 'QUALITY_FLOORS' : 'REPORTED_ONLY',
  }]))
  const stop_reasons = []
  if (retained.length < 80) stop_reasons.push({ code: 'AGREEMENT_BELOW_80', count: retained.length, minimum: 80 })
  for (const c of V31_CATEGORIES) {
    if (coverage[c].status === 'INCONCLUSIVE') stop_reasons.push({ code: 'CATEGORY_BELOW_MINIMUM',
      category: c, count: exact_agreement[c], minimum: V31_MINIMA[c] })
  }
  const retrieval_allowed = stop_reasons.length === 0
  const escalation = retrieval_allowed ? null : retained.length < 80
    ? 'Dead Rabbit batches fourth-seat grant yes/no to James; no automatic access.'
    : 'DJ returns coverage shortfall to Curator and Dead Rabbit; changed route needs new frozen questions and labeling.'
  return { ...v31Disclosures(), protocol_sha256: frozen.protocol_sha256,
    question_set_sha256: frozen.question_set_sha256, round_id: frozen.round_id, question_count: frozen.questions.length,
    retained_count: retained.length, dropped_count: excluded.length,
    agreement_rate: retained.length / frozen.questions.length,
    category_confusion, exact_agreement, marginals, retained, excluded,
    coverage, stop_reasons, escalation, retrieval_allowed, status: retrieval_allowed ? 'READY' : 'INCONCLUSIVE' }
}

function validateResultV31(r, byQuestion) {
  if (!r || !byQuestion.has(r.question_id) || !['original', 'paraphrase'].includes(r.variant) ||
      r.query_status !== 'ok' || r.error != null || !v31Ids(r.ranking) ||
      typeof r.abstained !== 'boolean' || r.abstained !== (r.ranking.length === 0) ||
      ['gold', 'answerability', 'adjudicator'].some(k => k in r)) throw new Error('invalid or errored result')
}

export function scoreRecallV31(frozen, results = []) {
  const plan = prepareRecallV31(frozen)
  if (!plan.retrieval_allowed) {
    if (!Array.isArray(results) || results.length) throw new Error('retrieval forbidden after coverage stop')
    const unmeasured = () => ({ ...v31Disclosures(), answerable_count: plan.exact_agreement.answerable,
      unanswerable_count: plan.exact_agreement.unanswerable, ambiguous_count: plan.exact_agreement.ambiguous,
      hit_at_1: null, hit_at_3: null, mrr_at_10: null, correct_abstain_rate: null, false_answer_rate: null,
      answerable_short_list_count: null, answerable_short_list_rate: null })
    return { ...plan, cutoff: RECALL_CUTOFF, scoring_complete: false,
      original: unmeasured(), paraphrase: unmeasured() }
  }
  const byQuestion = new Map(plan.retained.map(q => [q.question_id, q]))
  if (!Array.isArray(results) || results.length !== plan.retained_count * 2) throw new Error('incomplete result pairs')
  const seen = new Map()
  for (const r of results) {
    validateResultV31(r, byQuestion)
    if (!seen.has(r.question_id)) seen.set(r.question_id, new Set())
    const pair = seen.get(r.question_id)
    if (pair.has(r.variant)) throw new Error('duplicate result variant')
    pair.add(r.variant)
  }
  const summarize = variant => {
    const rows = results.filter(r => r.variant === variant)
    const answerable = rows.filter(r => byQuestion.get(r.question_id).answerability === 'answerable')
    const unanswerable = rows.filter(r => byQuestion.get(r.question_id).answerability === 'unanswerable')
    const scores = answerable.map(r => scoreRanking(r.ranking, byQuestion.get(r.question_id).gold))
    const rate = key => scores.length ? scores.reduce((sum, s) => sum + s[key], 0) / scores.length : null
    const short = answerable.filter(r => r.ranking.length < RECALL_CUTOFF).length
    return { ...v31Disclosures(), answerable_count: answerable.length, unanswerable_count: unanswerable.length,
      ambiguous_count: rows.length - answerable.length - unanswerable.length,
      hit_at_1: rate('hit_at_1'), hit_at_3: rate('hit_at_3'), mrr_at_10: rate('mrr_at_10'),
      correct_abstain_rate: unanswerable.length ? unanswerable.filter(r => r.abstained).length / unanswerable.length : null,
      false_answer_rate: unanswerable.length ? unanswerable.filter(r => !r.abstained).length / unanswerable.length : null,
      answerable_short_list_count: short, answerable_short_list_rate: answerable.length ? short / answerable.length : null }
  }
  return { ...plan, cutoff: RECALL_CUTOFF, scoring_complete: true,
    original: summarize('original'), paraphrase: summarize('paraphrase') }
}

export function checkRecallMutationV31(frozen, results = []) {
  const baseline = scoreRecallV31(frozen, results)
  if (!baseline.retrieval_allowed) return { ...v31Disclosures(), mutation: 'reverse-top10-v1',
    floors: QUALITY_FLOORS, baseline, mutant: null, baseline_passes: null, mutant_passes: null,
    status: 'INCONCLUSIVE', detected: false, short_list_note: null }
  const mutant = scoreRecallV31(frozen, results.map(r => ({ ...r,
    ranking: r.ranking.slice(0, RECALL_CUTOFF).reverse() })))
  const passes = r => ['original', 'paraphrase'].every(v => Object.entries(QUALITY_FLOORS).every(
    ([key, floor]) => typeof r[v][key] === 'number' && r[v][key] >= floor))
  const baseline_passes = passes(baseline), mutant_passes = passes(mutant)
  const status = !baseline_passes ? 'INCONCLUSIVE' : mutant_passes ? 'NOT_DETECTED' : 'DETECTED'
  const short_list_note = ['original', 'paraphrase'].some(v => baseline[v].answerable_short_list_count > 0)
    ? 'Short lists reverse over their actual length; singleton lists are unchanged. Report per-variant answerable counts/rates.' : null
  return { ...v31Disclosures(), mutation: 'reverse-top10-v1', floors: QUALITY_FLOORS,
    baseline, mutant, baseline_passes, mutant_passes, status, detected: status === 'DETECTED', short_list_note }
}

// Caller-supplied retrieval adapter only: no built-in corpus/socket/network access.
// The caller still owns consent, private provenance and retained private artifacts.
// Returned plans contain private questions/gold; do not publish the full object.
export async function runRecallV31(frozen, retrieve) {
  const round = structuredClone(frozen)
  const plan = prepareRecallV31(round)
  if (!plan.retrieval_allowed) return { ...checkRecallMutationV31(round), results: [] }
  if (typeof retrieve !== 'function') throw new Error('invalid retrieval adapter')
  const allowed = new Map(plan.retained.map(q => [q.question_id, q]))
  const results = []
  for (const q of plan.retained) {
    for (const variant of ['original', 'paraphrase']) {
      const raw = await retrieve({ question_id: q.question_id, variant, query: q[variant] })
      if (!raw || ('question_id' in raw && raw.question_id !== q.question_id) ||
          ('variant' in raw && raw.variant !== variant)) throw new Error('invalid retrieval identity')
      const row = structuredClone({ ...raw, ...v31Disclosures(), question_id: q.question_id, variant })
      validateResultV31(row, allowed)
      results.push(row)
    }
  }
  return { ...checkRecallMutationV31(round, results), results }
}

export function formatRecallV31(report) {
  if (!report || !['READY', 'INCONCLUSIVE', 'DETECTED', 'NOT_DETECTED'].includes(report.status) ||
      Object.entries(v31Disclosures()).some(([k, v]) => report[k] !== v)) throw new Error('invalid v3.1 report')
  return `${report.status} | ${V31_RESULT_LABEL} | ${report.author_exposure} | ${V31_PARAPHRASE_LIMITATION}`
}
