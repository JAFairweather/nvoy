// inbox_wrap_select.mjs — classify envelopes against the read window BEFORE decrypting (#195).
//
// ⚠ READ THIS BEFORE ASSUMING THIS FILE REORDERS ANYTHING. It does not, and the reason is the
// point of the file.
//
// A NIP-59 wrap's `created_at` is fuzzed BACKWARD, up to two days, so the wire reveals nothing
// about when a message was actually sent. inbox.mjs sorted the whole set by that field and kept
// the newest `--max-wraps`, which is a ranking on a value engineered to defeat exactly that
// inference. On 2026-08-15 the newest message in a live mailbox sat on the sixth-oldest-looking
// wrap, and eleven messages — two of them 9 KB reviews — were absent from a read that exited 0
// and printed "(none)" under every heading. The operator's conclusion was that nobody had replied.
//
// The obvious fix is to rank better. THAT FIX DOES NOT EXIST, and it is worth being exact about
// why, because the comfortable reading of this file is that it found one.
//
// The fuzz is bounded and one-directional, which does yield a classification without decrypting:
//
//     rumor.created_at - FUZZ  <=  wrap.created_at  <=  rumor.created_at
//
//   wrap.created_at >= since          the rumor is in-window FOR CERTAIN      CERTAIN
//   wrap.created_at >= since - FUZZ   undecidable from the wire               POSSIBLE
//   older than that                   out of window, unless the sender fuzzed
//                                     further back than the NIP allows        PRESUMED_OLD
//
// But every one of those boundaries is a threshold on `created_at`, so the classes are already
// in descending `created_at` order — sorting by class and then by timestamp produces the SAME
// sequence the old line produced. There is no better order available either: for a wrap at w the
// rumor lies in [w, w+FUZZ], so P(in-window) = (w + FUZZ - since) / FUZZ, which rises with w.
// Newest-first is already maximum likelihood. It is a lottery, and an unlucky fresh message
// still loses it. The 2026-08-15 message was fuzzed ~22h back into a band it shared with the
// older messages that displaced it; no ordering separates them.
//
// So what this file is FOR is the classification, not the sequence — and the classification is
// what lets the caller say, without opening anything, whether the budget it just ran out of left
// real mail behind. Two things actually close #195, and both are in the caller:
//
//   1. inbox.mjs paginates the fetch with `until`, so the set being classified is the mailbox
//      rather than one relay's arbitrary capped page. That is nvoy#9 applied to a second reader;
//      unwrapRumors was fixed then and this one never was.
//   2. inbox.mjs REFUSES TO EXIT 0 when CERTAIN or POSSIBLE envelopes went unopened, so a partial
//      view can no longer be mistaken for an empty inbox.
//
// Do not weaken (2) on the strength of the classification. The classification cannot recover a
// message; it can only tell you one may be missing.
//
// PRESUMED_OLD is classified, never dropped — the bound is a SHOULD in NIP-59, not a guarantee,
// and a reader that silently discards what it cannot justify opening is this same bug wearing a
// different hat. It is simply the one class that does not raise the alarm, because counting it
// would fire on every mailbox that has ever received mail.
//
// Note which direction is safe to be wrong in. Classifying a wrap too HIGH costs one wasted
// decrypt and the window filter downstream drops the message anyway. Too LOW is how a message
// goes missing and how the alarm fails to fire. Every judgement here is therefore biased toward
// opening: a malformed or absent `created_at` is POSSIBLE, not PRESUMED_OLD, because "this
// envelope tells me nothing" is a reason to look, not a reason to skip. That case is also the
// only one where this file's order differs from the old line's at all.

/** NIP-59's stated bound: "up to two days in the past". */
export const NIP59_FUZZ_SEC = 172800

export const RANK_CERTAIN = 0
export const RANK_POSSIBLE = 1
export const RANK_PRESUMED_OLD = 2

const RANK_NAME = ['certain', 'possible', 'presumedOld']

/** Rank one wrap against the window. Unusable timestamps rank POSSIBLE — see the bias note above. */
export function rankWrap(wrap, since, fuzz = NIP59_FUZZ_SEC) {
  // Type-checked before coercion, deliberately: `Number(null)` and `Number('')` are 0, which is
  // finite and lands below any real fuzz floor, so a coercing guard would rank an undated wrap as
  // ancient — the exact direction the bias note above says never to be wrong in.
  const at = wrap?.created_at
  if (typeof at !== 'number' || !Number.isFinite(at)) return RANK_POSSIBLE
  if (at >= since) return RANK_CERTAIN
  if (at >= since - fuzz) return RANK_POSSIBLE
  return RANK_PRESUMED_OLD
}

/**
 * Order envelopes by how likely they are to be in-window, then spend `budget` down that order.
 *
 * Returns { selected, counts, total, unopened, unopenedByRank } where `counts` is keyed by rank
 * name over the WHOLE set and `unopenedByRank` covers only what the budget could not reach —
 * the two answer different questions, and conflating them is what made the old reader's one
 * diagnostic line ("read newest N of M") useless.
 */
export function selectWraps(wraps, { since, budget, fuzz = NIP59_FUZZ_SEC } = {}) {
  const ranked = [...(wraps ?? [])]
    .filter(wrap => wrap && typeof wrap === 'object')
    .map(wrap => ({ wrap, rank: rankWrap(wrap, since, fuzz), at: Number(wrap.created_at) || 0 }))

  // Rank first; within a rank, newest-looking first. The secondary sort is still the fuzzed
  // field, but inside a rank it is only choosing between envelopes the ranking has already
  // called equivalent, and something has to break the tie deterministically.
  ranked.sort((a, b) => a.rank - b.rank || b.at - a.at)

  const cap = Math.max(0, Math.trunc(Number(budget)) || 0)
  const taken = ranked.slice(0, cap)
  const missed = ranked.slice(cap)

  const tally = list => list.reduce((acc, item) => {
    acc[RANK_NAME[item.rank]]++
    return acc
  }, { certain: 0, possible: 0, presumedOld: 0 })

  return {
    selected: taken.map(item => item.wrap),
    counts: tally(ranked),
    total: ranked.length,
    unopened: missed.length,
    unopenedByRank: tally(missed),
  }
}

/**
 * Whether the wrap query has another page worth asking for — fix half (1), the one that actually
 * recovers messages.
 *
 * A relay answers a capped query with its own newest-N by `created_at`, and for gift wraps that is
 * the fuzzed field, so one page is an arbitrary slice of the mailbox however large the limit. The
 * walk is `until = oldest seen - 1`, exactly as unwrapRumors does it (nvoy#9).
 *
 * Three independent stops, and each one is a different claim:
 *   - nothing fresh on this page — exhausted, or the relay is repeating itself
 *   - the page cap — a bound on a loop driven by remote input, which must always have one
 *   - past the fuzz floor — no wrap this old can carry an in-window rumor, so there is nothing
 *     left to find; this is the stop that normally fires, and the only one that is not a giving-up
 *
 * `freshThisPage` must be counted PER SOCKET. Judged against the shared cross-relay map, the first
 * page another relay had already covered would end this relay's walk, and its later pages are
 * exactly where a wrap only it holds would be.
 */
export function shouldPaginate({
  freshThisPage = 0, page = 0, maxPages = 0, oldestThisPage = Infinity, fuzzFloor = 0,
} = {}) {
  if (freshThisPage <= 0) return false
  if (page + 1 >= maxPages) return false
  if (!Number.isFinite(oldestThisPage)) return false
  return oldestThisPage > fuzzFloor
}

/**
 * One line for the operator, or null when the budget covered everything.
 *
 * It names what was left unopened AND how certain we were about it, because "12 envelopes not
 * opened, none of which could have been in the window" and "12 not opened, 9 of them certainly
 * in the window" call for opposite reactions and the old message could not tell them apart.
 */
export function describeUnopened({ unopened, unopenedByRank, total } = {}) {
  if (!unopened) return null
  const { certain = 0, possible = 0 } = unopenedByRank ?? {}
  const missed = certain + possible
  const detail = missed
    ? `${certain} certainly and ${possible} possibly inside the window — RAISE --max-wraps`
    : 'none of which can be inside the window'
  return `opened ${total - unopened} of ${total} envelopes; ${unopened} left unopened by --max-wraps, ${detail}`
}
