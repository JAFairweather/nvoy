import assert from 'node:assert/strict'
import test from 'node:test'
import { scoreRanking, scoreRecall, checkRecallMutation } from '../mcp/tools/memory-recall-benchmark.mjs'

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

test('empty answerable denominator is null, while all questions remain counted', () => {
  const rows = ['original', 'paraphrase'].map(v => item('u', v, 'unanswerable', [], true))
  const result = scoreRecall(rows, { expectedQuestions: 1 })
  assert.equal(result.original.hit_at_1, null)
  assert.equal(result.original.mrr_at_10, null)
  assert.equal(result.original.correct_abstain_rate, 1)
  assert.equal(checkRecallMutation(rows, { expectedQuestions: 1 }).detected, false)
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
