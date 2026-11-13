// Pure B4 recall scoring. No corpus, network, file IO or production-store mutation.
export const RECALL_CUTOFF = 10
// Proposed v2 floors, fixed before any real-corpus run; method re-review still required.
export const QUALITY_FLOORS = Object.freeze({ hit_at_1: 0.5, mrr_at_10: 0.5 })
export function checkRecallMutation(cases, options) {
  const baseline = scoreRecall(cases, options)
  // Gold-independent output-ranking mutation; never edits queries, gold or the live store.
  const mutant = scoreRecall(cases.map(row => ({ ...row, ranking: row.ranking.slice(0, RECALL_CUTOFF).reverse() })), options)
  const passes = report => ['original', 'paraphrase'].every(variant =>
    Object.entries(QUALITY_FLOORS).every(([key, floor]) => typeof report[variant][key] === 'number' && report[variant][key] >= floor))
  const baseline_passes = passes(baseline), mutant_passes = passes(mutant)
  return { mutation: 'reverse-top10-v1', floors: QUALITY_FLOORS, baseline, mutant, baseline_passes, mutant_passes, detected: baseline_passes && !mutant_passes }
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
    const rate = key => scores.length ? scores.reduce((sum, score) => sum + score[key], 0) / scores.length : null
    return {
      answerable_count: answerable.length, unanswerable_count: unanswerable.length,
      ambiguous_count: rows.filter(row => row.answerability === 'ambiguous').length,
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
