import assert from 'node:assert/strict'
import test from 'node:test'
import { scoreRanking, scoreRecall, checkRecallMutation } from '../mcp/tools/memory-recall-benchmark.mjs'
import * as recall from '../mcp/tools/memory-recall-benchmark.mjs'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

// Entirely synthetic v3.1 inputs; no private corpus, questions or votes.
const id31 = n => n.toString(16).padStart(64, '0')
const disclosure31 = 'paraphrase gold inherited from the base question; equivalence unverified'
const warning31 = 'agreement-filtered; floors not comparable to v3'
const questionDigest31 = questions => createHash('sha256').update(JSON.stringify(
  questions.map(({ question_id, original, paraphrase }) => ({ question_id, original, paraphrase })))).digest('hex')
const freeze31 = (a = 65, u = 20) => {
  const questions = Array.from({ length: 100 }, (_, i) => {
    const answerability = i < a ? 'answerable' : i < a + u ? 'unanswerable' : 'ambiguous'
    return {
      question_id: `synthetic-${i}`, original: `Synthetic original ${i}`, paraphrase: `Synthetic paraphrase ${i}`,
      votes: ['first', 'second'].map(labeler => ({ labeler, answerability,
        gold: answerability === 'answerable' ? [id31(i + 1)] : [], reason: 'Synthetic fixture vote' })),
    }
  })
  return { protocol_version: '3.1',
    protocol_sha256: 'ddf45d7f0d0a37622688f7da18af57cf4a6e0e211c825c53e0d426ab0f25db5f',
    round_id: 'synthetic-round-1', question_set_sha256: questionDigest31(questions),
    paraphrase_gold_limitation: disclosure31, labelers: ['first', 'second'],
    disclosed_at: { first: '2026-11-16T00:00:00.000Z', second: '2026-11-16T00:00:00.000Z' }, questions }
}

test('v3.1 filters exact support/category disagreements and preserves both 100-question marginals', () => {
  assert.equal(typeof recall.prepareRecallV31, 'function', 'missing v3.1 agreement preparation')
  const f = freeze31()
  f.questions[0].votes[1].gold = [id31(999)]
  f.questions[1].votes[1] = { labeler: 'second', answerability: 'unanswerable', gold: [], reason: 'Different vote' }
  const p = recall.prepareRecallV31(f)
  assert.equal(p.question_count, 100)
  assert.equal(p.retained_count, 98)
  assert.equal(p.dropped_count, 2)
  assert.equal(p.agreement_rate, 0.98)
  assert.equal(p.category_confusion.answerable.answerable, 64)
  assert.equal(p.category_confusion.answerable.unanswerable, 1)
  assert.equal(p.exact_agreement.answerable, 63)
  assert.equal(p.marginals.first.answerable.pre_filter, 65)
  assert.equal(p.marginals.second.answerable.pre_filter, 64)
  assert.equal(p.marginals.first.answerable.dropped, 2)
  assert.equal(p.marginals.second.answerable.dropped, 1)
  for (const labeler of f.labelers) assert.equal(
    Object.values(p.marginals[labeler]).reduce((sum, row) => sum + row.pre_filter, 0), 100)
  assert.equal(p.retrieval_allowed, true)
  assert.equal(p.result_label, warning31)
  assert.equal(p.paraphrase_gold_limitation, disclosure31)
})

test('v3.1 rejects invalid frozen inputs before treating any vote as disagreement', () => {
  const edits = [
    f => f.questions.pop(),
    f => f.questions.push(structuredClone(f.questions[0])),
    f => { f.questions[0].question_id = f.questions[1].question_id },
    f => { f.questions[99].votes.pop() },
    f => { f.questions[99].votes[1].labeler = 'first' },
    f => { f.questions[99].votes[1].gold = [' '+id31(1)] },
    f => { f.questions[99].votes[1].gold = ['A'.repeat(64)] },
    f => { f.questions[99].votes[1].gold = [id31(1), id31(1)] },
    f => { f.questions[0].votes[1].gold = [] },
    f => { f.questions[99].votes[1].gold = [id31(1)] },
    f => { f.questions[0].votes[1].answerability = 'unknown' },
    f => { f.questions[0].votes[1].reason = '' },
    f => { f.questions[0].adjudicator = 'fictional' },
    f => { f.labelers[1] = 'first' },
    f => { f.disclosed_at.second = 'not-a-date' },
    f => { f.paraphrase_gold_limitation = 'verified' },
    f => { f.protocol_sha256 = id31(1) },
    f => { f.protocol_version = '3' },
    f => { f.questions[0].paraphrase = 'Replacement question' },
    f => { f.minima = { answerable: 1 } },
    f => { f.questions[0].votes[1].gold = Array(1) },
  ]
  edits.forEach((edit, i) => {
    const f = freeze31(); edit(f)
    assert.throws(() => recall.prepareRecallV31(f), /invalid|frozen|fixed|adjudicator/, `invalid fixture ${i}`)
  })
  assert.throws(() => recall.prepareRecallV31(null), /invalid/)
})

test('v3.1 coverage uses the fixed 80/79 stop and each category minimum/below-minimum', () => {
  for (const [a, u, allowed, deficient] of [
    [20, 10, true, null], [19, 10, false, 'answerable'],
    [80, 10, true, null], [81, 9, false, 'unanswerable'],
    [85, 10, true, null], [86, 10, false, 'ambiguous'],
  ]) {
    const p = recall.prepareRecallV31(freeze31(a, u))
    assert.equal(p.retrieval_allowed, allowed, `${a}/${u}`)
    assert.equal(p.status, allowed ? 'READY' : 'INCONCLUSIVE')
    if (deficient) {
      assert.equal(p.coverage[deficient].status, 'INCONCLUSIVE')
      assert.equal(p.coverage[deficient].metric_status, 'NOT_RUN')
      assert.equal(p.stop_reasons[0].category, deficient)
      assert.match(p.escalation, /Curator.*Dead Rabbit/)
    }
  }
  for (const dropped of [20, 21]) {
    const f = freeze31()
    for (let i = 0; i < dropped; i++) f.questions[i].votes[1].gold = [id31(1000 + i)]
    const p = recall.prepareRecallV31(f)
    assert.equal(p.retained_count, 100 - dropped)
    assert.equal(p.retrieval_allowed, dropped === 20)
    if (dropped === 21) {
      assert.equal(p.stop_reasons[0].code, 'AGREEMENT_BELOW_80')
      assert.match(p.escalation, /fourth-seat/)
    }
  }
})

const results31 = f => recall.prepareRecallV31(f).retained.flatMap(q => ['original', 'paraphrase'].map(variant => ({
  question_id: q.question_id, variant, query_status: 'ok',
  ranking: q.answerability === 'answerable' ? [q.gold[0], ...Array.from({ length: 9 }, (_, i) => id31(1000 + i))] : [],
  abstained: q.answerability !== 'answerable',
})))

test('v3.1 scores only survivors with inherited paraphrase gold and separate A/U denominators', () => {
  assert.equal(typeof recall.scoreRecallV31, 'function', 'missing v3.1 scorer')
  const f = freeze31()
  f.questions[0].votes[1].gold = [id31(999)]
  const rows = results31(f)
  const drift = rows.find(r => r.question_id === 'synthetic-1' && r.variant === 'paraphrase')
  drift.ranking = [id31(900)]
  const falsePositive = rows.find(r => r.question_id === 'synthetic-65' && r.variant === 'original')
  falsePositive.ranking = [id31(900)]; falsePositive.abstained = false
  const before = structuredClone(f)
  const p = recall.scoreRecallV31(f, rows)
  assert.equal(p.original.answerable_count, 64)
  assert.equal(p.paraphrase.answerable_count, 64)
  assert.equal(p.original.unanswerable_count, 20)
  assert.equal(p.original.ambiguous_count, 15)
  assert.equal(p.original.hit_at_1, 1)
  assert.equal(p.paraphrase.hit_at_1, 63/64)
  assert.equal(p.paraphrase.mrr_at_10, 63/64)
  assert.equal(p.original.correct_abstain_rate, 19/20)
  assert.equal(p.original.false_answer_rate, 1/20)
  assert.equal(p.paraphrase.correct_abstain_rate, 1)
  assert.equal(p.paraphrase.answerable_short_list_count, 1)
  assert.equal(p.scoring_complete, true)
  assert.equal(p.original.result_label, warning31)
  assert.equal(p.paraphrase.paraphrase_gold_limitation, disclosure31)
  assert.deepEqual(f, before)
})

test('v3.1 refuses incomplete, errored, duplicated or relabeled retrieval results', () => {
  const f = freeze31()
  const edits = [
    r => r.pop(), r => r.push(structuredClone(r[0])),
    r => { r[0].question_id = 'replacement' }, r => { r[0].query_status = 'unknown' },
    r => { r[0].error = 'query failed' }, r => { r[0].ranking = ['A'.repeat(64)] },
    r => { r[0].ranking = [id31(1), id31(1)] }, r => { r[0].abstained = true },
    r => { r[0].gold = [id31(999)] }, r => { r[0].answerability = 'unanswerable' },
    r => { r[0].adjudicator = 'invented' }, r => { r[0].variant = 'other' },
    r => { r[0].ranking = []; r[0].abstained = false },
    r => { r[0].ranking = Array(1) },
    r => { r[1] = structuredClone(r[0]) },
  ]
  edits.forEach((edit, i) => {
    const r = results31(f); edit(r)
    assert.throws(() => recall.scoreRecallV31(f, r), /invalid|incomplete|duplicate/, `bad result ${i}`)
  })
  f.questions[0].votes[1].gold = [id31(999)]
  const r = results31(f)
  r[0].question_id = 'synthetic-0'
  assert.throws(() => recall.scoreRecallV31(f, r), /invalid/)
})

test('v3.1 coverage stops refuse supplied query results and emit unmeasured/null metrics', () => {
  for (const f of [freeze31(0, 100), freeze31(86, 10), freeze31(19, 20)]) {
    const p = recall.scoreRecallV31(f, [])
    assert.equal(p.status, 'INCONCLUSIVE')
    assert.equal(p.scoring_complete, false)
    assert.equal(p.original.hit_at_1, null)
    assert.equal(p.original.mrr_at_10, null)
    assert.equal(p.original.correct_abstain_rate, null)
    assert.equal(p.paraphrase.answerable_short_list_rate, null)
    assert.throws(() => recall.scoreRecallV31(f, results31(f)), /retrieval forbidden/)
  }
  const p = recall.prepareRecallV31(freeze31(0, 100))
  assert.equal(p.marginals.first.answerable.agreement_rate, null)
  assert.equal(p.marginals.first.ambiguous.agreement_rate, null)
})

test('v3.1 mutation emits DETECTED, NOT_DETECTED and INCONCLUSIVE without retuning floors', () => {
  assert.equal(typeof recall.checkRecallMutationV31, 'function', 'missing v3.1 mutation scorer')
  const f = freeze31(64, 20), rows = results31(f), saved = structuredClone(rows)
  const full = recall.checkRecallMutationV31(f, rows)
  assert.equal(full.status, 'DETECTED')
  assert.equal(full.baseline.original.mrr_at_10, 1)
  assert.ok(Math.abs(full.mutant.original.mrr_at_10 - 0.1) < 1e-12)
  assert.equal(full.short_list_note, null)
  assert.equal(full.result_label, warning31)
  assert.deepEqual(rows, saved)
  const singleton = rows.map(r => ({ ...r, ranking: r.ranking.slice(0, 1) }))
  const same = recall.checkRecallMutationV31(f, singleton)
  assert.equal(same.status, 'NOT_DETECTED')
  assert.equal(same.baseline.original.answerable_short_list_rate, 1)
  assert.equal(same.mutant.paraphrase.mrr_at_10, 1)
  assert.match(same.short_list_note, /actual length.*singleton/)
  const short = rows.map(r => ({ ...r, ranking: r.ranking.slice(0, 3) }))
  const reversed = recall.checkRecallMutationV31(f, short)
  assert.equal(reversed.status, 'DETECTED')
  assert.ok(Math.abs(reversed.mutant.original.mrr_at_10 - 1/3) < 1e-12)
  for (const variant of ['original', 'paraphrase']) {
    const misses = rows.map(r => ({ ...r, ranking: r.variant === variant && r.ranking.length ? [id31(900)] : r.ranking }))
    assert.equal(recall.checkRecallMutationV31(f, misses).status, 'INCONCLUSIVE')
  }
  const half = rows.map(r => ({ ...r, ranking: Number(r.question_id.split('-')[1]) < 32 ? [id31(900)] : r.ranking }))
  const edge = recall.checkRecallMutationV31(f, half)
  assert.equal(edge.baseline.original.hit_at_1, 0.5)
  assert.equal(edge.baseline.original.mrr_at_10, 0.5)
  assert.equal(edge.status, 'DETECTED')
  const beyond = rows.map(r => ({ ...r, ranking: r.ranking.length
    ? [...r.ranking.slice(1), id31(1100), r.ranking[0]] : [] }))
  assert.equal(recall.checkRecallMutationV31(f, beyond).baseline.original.mrr_at_10, 0)
  const stopped = recall.checkRecallMutationV31(freeze31(86, 10), [])
  assert.equal(stopped.status, 'INCONCLUSIVE')
  assert.equal(stopped.baseline_passes, null)
  assert.equal(stopped.mutant, null)
})

test('v3.1 runner makes zero queries on coverage stops and sends neither gold nor peer votes', async () => {
  assert.equal(typeof recall.runRecallV31, 'function', 'missing guarded v3.1 runner')
  let calls = 0
  const stopped = [freeze31(0, 100), freeze31(19, 10), freeze31(81, 9), freeze31(86, 10)]
  const lowAgreement = freeze31()
  for (let i = 0; i < 21; i++) lowAgreement.questions[i].votes[1].gold = [id31(2000+i)]
  stopped.push(lowAgreement)
  for (const f of stopped) {
    const p = await recall.runRecallV31(f, async () => { calls++; throw new Error('MUST NOT QUERY') })
    assert.equal(p.status, 'INCONCLUSIVE')
    assert.equal(p.baseline.scoring_complete, false)
  }
  assert.equal(calls, 0)
  const f = freeze31()
  f.questions[0].votes[1].gold = [id31(999)]
  const expected = new Map(results31(f).map(r => [r.question_id+'/'+r.variant, r]))
  const seen = []
  const p = await recall.runRecallV31(f, async request => {
    assert.deepEqual(Object.keys(request).sort(), ['query', 'question_id', 'variant'])
    assert.notEqual(request.question_id, 'synthetic-0')
    seen.push(request)
    const r = expected.get(request.question_id+'/'+request.variant)
    return { query_status: r.query_status, ranking: r.ranking, abstained: r.abstained }
  })
  assert.equal(seen.length, 198)
  assert.equal(p.results.length, 198)
  assert.equal(p.status, 'DETECTED')
  await assert.rejects(() => recall.runRecallV31(f, async () => ({ query_status: 'unknown', ranking: [], abstained: true })), /invalid/)
  await assert.rejects(() => recall.runRecallV31(f, async () => { throw new Error('retrieval failed') }), /retrieval failed/)
  await assert.rejects(() => recall.runRecallV31(f, async () => ({ question_id: 'foreign', query_status: 'ok', ranking: [], abstained: true })), /invalid retrieval identity/)
  await assert.rejects(() => recall.runRecallV31(f, async () => ({ variant: 'foreign', query_status: 'ok', ranking: [], abstained: true })), /invalid retrieval identity/)
})

test('v3.1 async runner snapshots the manifest and detaches each returned ranking', async () => {
  const f = freeze31(), digest = f.question_set_sha256
  const lookup = new Map(results31(f).map(r => [r.question_id+'/'+r.variant, r]))
  let earlierRanking = null
  const p = await recall.runRecallV31(f, async request => {
    await Promise.resolve()
    if (earlierRanking) earlierRanking[0] = id31(9999)
    f.questions[0].original = 'Caller changed the live manifest during await'
    const row = lookup.get(request.question_id+'/'+request.variant)
    if (!earlierRanking) earlierRanking = row.ranking
    return row
  })
  assert.equal(p.baseline.question_set_sha256, digest)
  assert.equal(p.baseline.retained[0].original, 'Synthetic original 0')
  assert.equal(p.results[0].ranking[0], id31(1))
  assert.equal(p.status, 'DETECTED')
})

test('v3.1 pins the protocol bytes and labels raw results and every formatted result line', async () => {
  assert.equal(typeof recall.formatRecallV31, 'function', 'missing disclosure-preserving formatter')
  const protocol = readFileSync(new URL('../docs/B4_RECALL_PROTOCOL_V3_1.md', import.meta.url))
  assert.equal(createHash('sha256').update(protocol).digest('hex'), recall.V31_PROTOCOL_SHA256)
  const f = freeze31(), rows = results31(f)
  const lookup = new Map(rows.map(r => [r.question_id+'/'+r.variant, r]))
  const p = await recall.runRecallV31(f, async ({ question_id, variant }) => lookup.get(question_id+'/'+variant))
  for (const r of [p, p.baseline, p.mutant, p.baseline.original, p.baseline.paraphrase, ...p.results]) {
    assert.equal(r.result_label, warning31)
    assert.equal(r.paraphrase_gold_limitation, disclosure31)
    assert.equal(r.author_exposure, 'author exposure: self-reported, not log-verified')
  }
  const line = recall.formatRecallV31(p)
  for (const text of [warning31, disclosure31, 'author exposure: self-reported, not log-verified']) assert.ok(line.includes(text))
  assert.equal(line.includes('\n'), false)
  assert.equal(line.includes('Synthetic'), false)
  assert.throws(() => recall.formatRecallV31({ ...p, result_label: 'comparable' }), /invalid/)
})

test('MRR@10 scores the first supporting claim, with misses and rank11 scored zero', () => {
  assert.deepEqual(scoreRanking(['gold'], ['gold']), { hit_at_1: 1, hit_at_3: 1, mrr_at_10: 1 })
  assert.deepEqual(scoreRanking(['wrong', 'gold'], ['gold']), { hit_at_1: 0, hit_at_3: 1, mrr_at_10: 0.5 })
  assert.equal(scoreRanking(Array(10).fill('wrong').concat('gold'), ['gold']).mrr_at_10, 0)
  assert.equal(scoreRanking([], ['gold']).mrr_at_10, 0)
})

const item = (question_id, variant, answerability, ranking, abstained = false) => ({
  question_id, variant, answerability, ranking, abstained,
  gold: answerability === 'answerable' ? ['gold'] : [],
  labelers: ['first', 'second'], adjudicator: 'judge', disagreement: false,
})
const mixed = () => [
  item('a', 'original', 'answerable', ['gold']),
  item('u', 'original', 'unanswerable', [], true),
  item('m', 'original', 'ambiguous', ['other']),
  item('a', 'paraphrase', 'answerable', ['other']),
  item('u', 'paraphrase', 'unanswerable', ['other']),
  item('m', 'paraphrase', 'ambiguous', [], true),
]

test('answerable-only denominators, separate abstention and paired variants', () => {
  const report = scoreRecall(mixed(), { expectedQuestions: 3 })
  assert.notEqual(report, null)
  assert.equal(report.original.answerable_count, 1)
  assert.equal(report.original.hit_at_1, 1)
  assert.equal(report.paraphrase.hit_at_1, 0)
  assert.equal(report.original.correct_abstain_rate, 1)
  assert.equal(report.paraphrase.false_answer_rate, 1)
  assert.equal(report.original.ambiguous_count, 1)
  assert.equal(report.paraphrase.ambiguous_count, 1)
  assert.throws(() => scoreRecall(mixed()), /question count/)
})

test('require two distinct gold reviewers and retain disagreement by base question', () => {
  const invalid = mixed()
  invalid[0].labelers = ['first', 'first']
  assert.throws(() => scoreRecall(invalid, { expectedQuestions: 3 }), /labelers/)
  const rows = mixed()
  rows[0].disagreement = rows[3].disagreement = true
  assert.equal(scoreRecall(rows, { expectedQuestions: 3 }).gold_disagreement_count, 1)
  assert.equal(scoreRecall(rows, { expectedQuestions: 3 }).gold_disagreement_rate, 1 / 3)
  rows[0].adjudicator = ''
  assert.throws(() => scoreRecall(rows, { expectedQuestions: 3 }), /adjudicator/)
})

test('fixed reverse-top10 recall mutation fails the predeclared quality floors on perfect rankings', () => {
  const ranking = ['gold', ...Array.from({ length: 9 }, (_, i) => `wrong${i}`)]
  const rows = ['original', 'paraphrase'].map(v => item('a', v, 'answerable', [...ranking]))
  const report = checkRecallMutation(rows, { expectedQuestions: 1 })
  assert.notEqual(report, null)
  assert.equal(report.baseline.original.mrr_at_10, 1)
  assert.equal(report.mutant.original.mrr_at_10, 0.1)
  assert.equal(report.baseline_passes, true)
  assert.equal(report.mutant_passes, false)
  assert.equal(report.detected, true)
  assert.deepEqual(rows[0].ranking, ranking)
  const worst = rows.map(row => ({ ...row, ranking: ['not-gold'] }))
  const negative = checkRecallMutation(worst, { expectedQuestions: 1 })
  assert.equal(negative.baseline.original.hit_at_1, 0)
  assert.equal(negative.baseline.original.mrr_at_10, 0)
  assert.equal(negative.detected, false)
})

test('reject malformed opaque identifiers instead of silently repairing them', () => {
  assert.throws(() => scoreRanking([' gold '], ['gold']), /invalid/)
  assert.throws(() => scoreRanking([], ['']), /invalid/)
})

test('mutation status is INCONCLUSIVE if either baseline variant misses a floor', () => {
  const full = ['gold', ...Array.from({ length: 9 }, (_, i) => `wrong${i}`)]
  const rows = ['original', 'paraphrase'].map(v => item('a', v, 'answerable', [...full]))
  assert.equal(checkRecallMutation(rows, { expectedQuestions: 1 }).status, 'DETECTED')
  rows[1].ranking = ['wrong', 'gold']
  const report = checkRecallMutation(rows, { expectedQuestions: 1 })
  assert.equal(report.baseline_passes, false)
  assert.equal(report.status, 'INCONCLUSIVE')
  assert.equal(report.detected, false)
  rows[1].ranking = [...full]
  rows[0].ranking = ['wrong', 'gold']
  assert.equal(checkRecallMutation(rows, { expectedQuestions: 1 }).status, 'INCONCLUSIVE')
})

test('empty answerable denominator is null, while all questions remain counted', () => {
  const rows = ['original', 'paraphrase'].map(v => item('u', v, 'unanswerable', [], true))
  const result = scoreRecall(rows, { expectedQuestions: 1 })
  assert.equal(result.original.hit_at_1, null)
  assert.equal(result.original.mrr_at_10, null)
  assert.equal(result.original.correct_abstain_rate, 1)
  assert.equal(result.original.answerable_short_list_count, 0)
  assert.equal(result.original.answerable_short_list_rate, null)
  assert.equal(checkRecallMutation(rows, { expectedQuestions: 1 }).status, 'INCONCLUSIVE')
  assert.equal(checkRecallMutation(rows, { expectedQuestions: 1 }).detected, false)
})

test('baseline equality at both floors passes, with no short-list note for full lists', () => {
  const full = ['gold', ...Array.from({ length: 9 }, (_, i) => `wrong${i}`)]
  const rows = ['original', 'paraphrase'].flatMap(v => [
    item('a', v, 'answerable', [...full]),
    item('b', v, 'answerable', full.map(id => id === 'gold' ? 'miss' : id)),
  ])
  const report = checkRecallMutation(rows, { expectedQuestions: 2 })
  assert.equal(report.baseline.original.hit_at_1, 0.5)
  assert.equal(report.baseline.original.mrr_at_10, 0.5)
  assert.equal(report.baseline_passes, true)
  assert.equal(report.status, 'DETECTED')
  assert.equal(report.short_list_note, null)
})

test('actual-length reversal discloses answerable short lists separately by variant', () => {
  const full = ['gold', ...Array.from({ length: 9 }, (_, i) => `wrong${i}`)]
  const rows = ['original', 'paraphrase'].flatMap(v => [
    item('single', v, 'answerable', ['gold']),
    item('short', v, 'answerable', v === 'original' ? ['gold', 'wrong', 'other'] : [...full]),
    item('full', v, 'answerable', [...full]),
    item('empty', v, 'answerable', [], true),
    item('u', v, 'unanswerable', [], true),
    item('m', v, 'ambiguous', ['other']),
  ])
  const report = checkRecallMutation(rows, { expectedQuestions: 6 })
  assert.equal(report.baseline.original.answerable_short_list_count, 3)
  assert.equal(report.baseline.original.answerable_short_list_rate, 3 / 4)
  assert.equal(report.baseline.paraphrase.answerable_short_list_count, 2)
  assert.equal(report.baseline.paraphrase.answerable_short_list_rate, 2 / 4)
  assert.equal(report.mutant.original.mrr_at_10, (1 + 1 / 3 + 0.1) / 4)
  assert.match(report.short_list_note, /actual length/)
  const single = ['original', 'paraphrase'].map(v => item('a', v, 'answerable', ['gold']))
  const unchanged = checkRecallMutation(single, { expectedQuestions: 1 })
  assert.equal(unchanged.mutant.original.mrr_at_10, 1)
  assert.equal(unchanged.status, 'NOT_DETECTED')
  assert.equal(unchanged.detected, false)
})

test('missing, duplicated, mismatched and errored cases refuse a complete evaluation', () => {
  const rows = mixed()
  assert.throws(() => scoreRecall(rows.slice(0, -1), { expectedQuestions: 3 }), /pair/)
  assert.throws(() => scoreRecall([...rows, rows[0]], { expectedQuestions: 3 }), /duplicate/)
  const mismatch = mixed(); mismatch[3].gold = ['different']
  assert.throws(() => scoreRecall(mismatch, { expectedQuestions: 3 }), /pair/)
  const error = mixed(); error[0].error = true
  assert.throws(() => scoreRecall(error, { expectedQuestions: 3 }), /errored/)
})
