// nvoy#195 offline proof: a read that could not open everything says so instead of exiting 0.
//
//   node test/inbox-wrap-selection.mjs
//
// The failure this pins is nvoy#9 in a second reader. A gift wrap's created_at is fuzzed up to two
// days backward, so inbox.mjs sorting the whole set by it and keeping the newest --max-wraps was a
// ranking on noise: on 2026-08-15 the newest message in a live mailbox sat on the sixth-oldest
// -looking wrap, and eleven messages were absent from a read that exited 0 and printed "(none)"
// under every heading.
//
// This suite deliberately asserts what the fix CANNOT do as well as what it can. Classification
// does not reorder anything — the classes are thresholds on the same timestamp, so they are
// already in descending order — and it cannot rescue an unlucky message. What closes the bug is
// the alarm. If someone later "simplifies" the alarm away on the theory that the ranking handles
// it, the first three cases below are what should stop them.
//
// Every alarm assertion is paired with a healthy run that does NOT raise it: a verdict that always
// returns INCONCLUSIVE would pass a one-directional suite and be worthless.
import assert from 'node:assert'
import { selectWraps, rankWrap, shouldPaginate, describeUnopened, NIP59_FUZZ_SEC } from '../mcp/tools/inbox_wrap_select.mjs'
import { inboxVerdict } from '../mcp/tools/inbox_reach.mjs'

const now = 1_755_000_000
const since = now - 4 * 3600                       // the default --since-min 240
const wrap = (id, createdAt) => ({ id, created_at: createdAt, pubkey: 'e'.repeat(64), content: 'x' })

// The selection the fix replaces, kept verbatim so the repro compares against the real thing
// rather than against a description of it.
const oldSelection = (wraps, budget) =>
  [...wraps].sort((a, b) => Number(b.created_at || 0) - Number(a.created_at || 0)).slice(0, budget)

// A reachable, fully-answered read, so that anything the verdict raises below comes from the
// budget and not from some other branch of inboxVerdict.
const healthy = {
  reachedWraps: ['wss://a'], relayCount: 1, answered10050: ['wss://a'], dmRelayLists: 1,
  envelopesSeen: 4, opened: 4, total: 4,
}

let n = 0, pass = 0
const t = (name, fn) => {
  n++
  try { fn(); pass++; console.log(`ok  - ${name}`) } catch (e) { console.error(`FAIL - ${name}\n   ${e.stack || e.message}`) }
}

// The live shape of #195, built to NIP-59's own rule that a wrap is never NEWER than its rumor:
// 30 messages whose rumors sit outside a 4h window and whose wraps were fuzzed only slightly, plus
// one genuinely fresh review whose wrap was fuzzed ~22h back. Every wrap here is <= its rumor.
const mailbox195 = () => [
  ...Array.from({ length: 30 }, (_, i) => wrap(`older${i}`, since - 600 - i * 1800)),
  wrap('the-review', now - 22 * 3600),
]

t('the #195 repro: with a budget under the candidate set, the fresh review is still lost', () => {
  const mailbox = mailbox195()
  assert.ok(!oldSelection(mailbox, 16).some(w => w.id === 'the-review'),
    'precondition: the old ranking must actually lose it, or this test proves nothing')

  // And so does the new one. Every wrap in this mailbox is below `since`, so ranking has nothing
  // left to discriminate on and the tie-break is the fuzzed field again. Asserted rather than
  // glossed: the fix is NOT that ordering rescues the message.
  const { selected, unopenedByRank } = selectWraps(mailbox, { since, budget: 16 })
  assert.ok(!selected.some(w => w.id === 'the-review'), 'ranking alone does not recover it')
  assert.ok(unopenedByRank.certain + unopenedByRank.possible > 0, 'and it knows it left candidates behind')
})

t('the #195 fix: that same lossy read REFUSES to exit 0', () => {
  const r = selectWraps(mailbox195(), { since, budget: 16 })
  const v = inboxVerdict({ ...healthy, unopened: r.unopened, unopenedByRank: r.unopenedByRank })
  assert.equal(v.code, 3, 'a partial view must never print as an empty inbox')
  assert.ok(v.inconclusive.some(s => /partial view of the inbox/.test(s)))
})

t('the #195 fix, other direction: a budget that covers the mailbox opens the review and exits 0', () => {
  const r = selectWraps(mailbox195(), { since, budget: 48 })
  assert.ok(r.selected.some(w => w.id === 'the-review'), 'the review is read at the new default budget')
  const v = inboxVerdict({ ...healthy, unopened: r.unopened, unopenedByRank: r.unopenedByRank })
  assert.equal(v.code, 0, 'and a complete read must not cry wolf')
})

t('classification does NOT reorder — same sequence as the old line, on purpose', () => {
  // The classes are thresholds on `created_at`, so class-then-timestamp is descending timestamp.
  // Pinned so the file's own header cannot quietly become untrue, and so nobody claims the
  // ordering fixed anything.
  const mailbox = [
    wrap('a', since + 500), wrap('b', since - 10), wrap('c', since - NIP59_FUZZ_SEC - 1),
    wrap('d', since + 900), wrap('e', since - 20000),
  ]
  assert.deepEqual(
    selectWraps(mailbox, { since, budget: 5 }).selected.map(w => w.id),
    oldSelection(mailbox, 5).map(w => w.id),
  )
})

t('the one ordering difference: an undated wrap is promoted toward being opened, not buried', () => {
  const mailbox = [wrap('ancient', since - NIP59_FUZZ_SEC - 1), { id: 'nodate' }]
  assert.deepEqual(selectWraps(mailbox, { since, budget: 1 }).selected.map(w => w.id), ['nodate'])
  assert.deepEqual(oldSelection(mailbox, 1).map(w => w.id), ['ancient'],
    'precondition: the old line coerced the missing field to 0 and sorted it dead last')
})

t('a wrap at or after `since` is CERTAIN, and outranks every undecidable one', () => {
  const certain = wrap('certain', since + 1)
  const possible = wrap('possible', since - 1)
  const { selected, counts } = selectWraps([possible, certain], { since, budget: 1 })
  assert.deepEqual(selected.map(w => w.id), ['certain'])
  assert.equal(counts.certain, 1)
  assert.equal(counts.possible, 1)
})

t('a wrap older than the fuzz floor is ranked LAST but never dropped', () => {
  const ancient = wrap('ancient', since - NIP59_FUZZ_SEC - 1)
  const possible = wrap('possible', since - 60)
  assert.equal(rankWrap(ancient, since), 2)

  // Ranked last...
  assert.deepEqual(selectWraps([ancient, possible], { since, budget: 1 }).selected.map(w => w.id), ['possible'])
  // ...and still reachable, because the 48h bound is a SHOULD in NIP-59, not a guarantee.
  assert.deepEqual(selectWraps([ancient, possible], { since, budget: 9 }).selected.map(w => w.id).sort(),
    ['ancient', 'possible'])
})

t('an unusable created_at ranks POSSIBLE, not old — being told nothing is a reason to look', () => {
  for (const bad of [undefined, null, 'yesterday', NaN]) {
    assert.equal(rankWrap({ created_at: bad }, since), 1, `created_at=${String(bad)}`)
  }
  const { selected } = selectWraps([wrap('ancient', since - NIP59_FUZZ_SEC - 1), { id: 'nodate' }], { since, budget: 1 })
  assert.deepEqual(selected.map(w => w.id), ['nodate'])
})

t('what the budget could not reach is counted by rank, not just totalled', () => {
  const mailbox = [
    wrap('c1', since + 10), wrap('c2', since + 20),
    wrap('p1', since - 10), wrap('o1', since - NIP59_FUZZ_SEC - 5),
  ]
  const r = selectWraps(mailbox, { since, budget: 2 })
  assert.equal(r.total, 4)
  assert.equal(r.unopened, 2)
  assert.deepEqual(r.unopenedByRank, { certain: 0, possible: 1, presumedOld: 1 })
  // The whole-set counts answer a different question and must not be the same numbers.
  assert.deepEqual(r.counts, { certain: 2, possible: 1, presumedOld: 1 })
})

t('a budget that covers the mailbox reports nothing left behind', () => {
  const r = selectWraps([wrap('a', since + 1), wrap('b', since - 1)], { since, budget: 16 })
  assert.equal(r.unopened, 0)
  assert.equal(describeUnopened(r), null, 'no caveat when there is nothing to caveat')
})

t('describeUnopened distinguishes "missed real mail" from "skipped what could not qualify"', () => {
  const missed = describeUnopened({ unopened: 3, unopenedByRank: { certain: 2, possible: 1, presumedOld: 0 }, total: 10 })
  assert.match(missed, /2 certainly and 1 possibly inside the window/)
  assert.match(missed, /RAISE --max-wraps/)

  const harmless = describeUnopened({ unopened: 3, unopenedByRank: { certain: 0, possible: 0, presumedOld: 3 }, total: 10 })
  assert.match(harmless, /none of which can be inside the window/)
  assert.ok(!/RAISE --max-wraps/.test(harmless), 'no alarm language when nothing was actually missed')
})

// --- fix half (1): the walk that makes the classified set the mailbox, not one capped page ---

t('pagination continues while a page brings something new and stays above the fuzz floor', () => {
  assert.equal(shouldPaginate({ freshThisPage: 200, page: 0, maxPages: 6, oldestThisPage: now, fuzzFloor: since - NIP59_FUZZ_SEC }), true)
})

t('pagination stops for three distinct reasons, each on its own', () => {
  const walking = { freshThisPage: 200, page: 0, maxPages: 6, oldestThisPage: now, fuzzFloor: since - NIP59_FUZZ_SEC }
  assert.equal(shouldPaginate({ ...walking, freshThisPage: 0 }), false, 'exhausted, or the relay repeated itself')
  assert.equal(shouldPaginate({ ...walking, page: 5 }), false, 'the page cap bounds a remote-driven loop')
  assert.equal(shouldPaginate({ ...walking, oldestThisPage: since - NIP59_FUZZ_SEC - 1 }), false, 'past the fuzz floor')
  // ...and the negative control for all three: the walking case above must still walk, or these
  // would pass against a function that simply never paginates.
  assert.equal(shouldPaginate(walking), true)
})

t('a page that returned no events at all does not paginate on an infinite floor', () => {
  assert.equal(shouldPaginate({ freshThisPage: 5, page: 0, maxPages: 6, oldestThisPage: Infinity, fuzzFloor: 0 }), false)
})

// --- the verdict half: exit 3 must mean something, which means it must also stay quiet ---

t('unopened CERTAIN envelopes make the read INCONCLUSIVE', () => {
  const v = inboxVerdict({ ...healthy, unopened: 5, unopenedByRank: { certain: 2, possible: 3, presumedOld: 0 } })
  assert.equal(v.code, 3)
  assert.ok(v.inconclusive.some(s => /partial view of the inbox/.test(s)))
})

t('unopened POSSIBLE envelopes are ALSO inconclusive — undecidable is not the same as fine', () => {
  // The 2026-08-15 loss was entirely in this class. An earlier draft of this fix made it a note
  // on the reasoning that it would fire too often; that reasoning would have shipped the bug.
  const v = inboxVerdict({ ...healthy, unopened: 4, unopenedByRank: { certain: 0, possible: 4, presumedOld: 0 } })
  assert.equal(v.code, 3)
  assert.ok(v.inconclusive.some(s => /0 certainly, 4 possibly/.test(s)))
})

t('unopened PRESUMED_OLD envelopes are a note, not an alarm', () => {
  const v = inboxVerdict({ ...healthy, unopened: 5, unopenedByRank: { certain: 0, possible: 0, presumedOld: 5 } })
  assert.equal(v.code, 0, 'an old backlog must not fire the alarm on every mailbox that ever received mail')
  assert.ok(v.notes.some(s => /none of which can be inside the window/.test(s)))
})

t('the negative control: a read that opened everything raises neither', () => {
  const v = inboxVerdict({ ...healthy, unopened: 0, unopenedByRank: { certain: 0, possible: 0, presumedOld: 0 } })
  assert.equal(v.code, 0)
  assert.deepEqual(v.inconclusive, [])
  assert.ok(!v.notes.some(s => /--max-wraps/.test(s)), 'no budget caveat when the budget was not reached')
})

console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
