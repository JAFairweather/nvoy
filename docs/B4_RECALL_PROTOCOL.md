# B4 protocol v3: mutation interpretation and short-list coverage

This amends issue #379's v2 protocol text SHA256
`f8bb04e7c5465eef15e8904b2619c7f7ba00acd4a6facf79ec69bc417d7cc5ac`
at `88a3b88eccba026043b558027f3bdb5771f470f7`, following GrokDoggyDog's
conditional METHOD approval, Buzz event
`153ecb347233ca497345d3d99b96c35c13a1b59e774c1f6b6139473eb47005b2`.
The conditions below are implemented before any freeze or real run. That approval
does not cover this new text/hash; v3 requires a fresh exact-version method read.

Acceptance remains verbatim:
Hit@1, Hit@3, MRR and p95 committed. A mutation shows the benchmark can fail.

## 1. MRR@10 is executable, not just prose

`mcp/tools/memory-recall-benchmark.mjs` exports `RECALL_CUTOFF = 10` and
`scoreRanking`. Hit@1/Hit@3 test whether any frozen gold supporting record appears
within those ranks. MRR@10 is 1 divided by the first supporting rank within ten;
a missing support, empty ranking or support only beyond ten scores exactly zero.
The output field is `mrr_at_10`, never an unqualified/unbounded MRR.
These are retrieval relevance metrics, not generated-answer completeness scores.

## 2. Freeze answerability and adjudication before scoring

Keep 100 blind-authored base questions and one paraphrase each, authored without
seeing target claims, gold or ranks. Freeze question strings/provenance and pin a
separate read-only corpus snapshot. The claim-aware current DJ conversation is
not the blind author. Existing 20 claim-derived questions do not qualify.

Eligibility disposition (Grok, Buzz `bb8dde605e5eb6aa9da8bef79f7703c859578697f906f5684c0cb28278b0d182`):
after pinning the corpus and before question freeze, DJ or Dead Rabbit compares
target IDs privately with the author's recorded reads/query results, if a usable
log exists. The author receives only the overlap count, never target IDs. Drop
overlapping targets and re-pin before accepting the author route. If no adequate
log exists, record self-report-only evidence and its limitation, not a false
zero-overlap result or automatic clearance. No role is cleared by assignment.

Before any retrieval run, the private gold manifest must name the adjudicator and
freeze every base question as answerable, unanswerable or ambiguous, with counts,
supporting IDs and snapshot digests. The split is an adjudication outcome, not a
quota tuned to retrieval results. Original and paraphrase share that frozen gold
classification; unresolved ambiguity remains counted, never replaced with an easy
case. Review semantic equivalence of each paraphrase before the freeze.

`scoreRecall` defaults to exactly 100 paired base questions; smaller explicit
counts are for disclosed synthetic tests, not a 100-question baseline. It refuses
missing/duplicate/inconsistent pairs or errored queries. For each variant:
- Hit@1/Hit@3/MRR@10 use only the answerable denominator.
- Correct-abstain and false-answer rates use only the unanswerable denominator.
- Ambiguous count is disclosed and excluded from both denominators.
- An absent denominator produces null, not an invented zero or perfect score.

At this retrieval boundary, `abstained` means the query explicitly returned none;
found candidates on an unanswerable question count as retrieval false positives.
Unknown/error is not abstention: abort a complete-baseline report and retain the
failure separately. No generated-answer correctness or safety claim is inferred.

## 3. Two independent labelers and recorded disagreements

Use two distinct labelers for ALL base questions, with a named adjudicator fixed
before scoring. Each labels answerability and supporting records independently,
without observed retrieval ranks or the other labeler's votes. The adjudicator
sees only disagreements, no ranks, and records a reason for each decision. Retain
both private votes and these reasons. Resolve differences before gold freeze;
unresolved cases stay ambiguous. Record disagreement count/rate over all base
questions. Private provenance must establish author blinding and labeler
independence; the adjudicator cannot certify those merely by resolving gold.
Disclose prior target-claim exposure and settle role eligibility before freeze.
Labelers may have disclosed prior claim exposure if the method owner accepts it;
author blindness and labeler independence are different requirements. Before
voting, labelers make no new target-claim searches and see no retrieval output,
ranks or the other vote. Anyone with disqualifying frozen-question/rank exposure
is replaced under the recorded eligibility disposition, not silently relabeled
independent. The assigned author/labelers remain conditional until their actual
disclosures and required overlap disposition are recorded.

The scorer requires two distinct labeler identifiers, adjudicator and a declared
disagreement flag on every pair, and reports disagreements once per base question.
It checks declaration consistency, NOT identity authenticity or the fact that
people actually reviewed independently. Those require private provenance and
method review; fabricated metadata cannot establish blinding or gold quality.

## 4. Fixed recall-ranking mutation and controls

Pre-run rule in code: `reverse-top10-v1` reverses the first ten returned IDs for
EVERY original/paraphrase, without reading gold or changing queries, labels, the
live store or retrieval configuration. A list shorter than ten reverses over its
actual length, without padding; an empty or one-item list is unchanged. Score
baseline and mutant through the SAME recall scorer, not the load-health probe.

Freeze these floors BEFORE any real scoring: Hit@1 >= 0.5 AND MRR@10 >=
0.5, separately for BOTH variants. `checkRecallMutation` detects a mutation only
when baseline passes all four checks and mutant fails at least one. These are
sensitivity-test floors confirmed in the v2 method read, not a service/product
SLO or an observed result. The v3 interpretation still needs exact-text approval.

The executable `status` is:
- `INCONCLUSIVE` if the baseline misses ANY floor on EITHER variant (including
  null metrics when no answerable denominator exists). This is not a passed
  mutation test and not a scorer failure. Do not lower floors afterwards; a new
  protocol version and review are required before another real evaluation.
- `DETECTED` only if baseline passes and mutant fails at least one check.
- `NOT_DETECTED` if baseline and mutant both pass: sensitivity is not demonstrated.

For each variant, publish `answerable_short_list_count` and
`answerable_short_list_rate` beside the mutation result: the count of answerable
queries returning fewer than ten IDs (including zero), divided by the answerable
denominator; rate is null for an empty denominator. Exclude U/ambiguous cases
from this coverage denominator. Any nonzero count emits `short_list_note` about
actual-length reversal and unchanged singletons. This discloses every short-list
share, including a large one, without inventing a post-score warning threshold.
A high share limits sensitivity and must not be buried beneath `DETECTED`.

Perfect synthetic controls put gold first in ten IDs: Hit@1/MRR@10 are 1; reversal
puts it tenth: Hit@1=0 and MRR@10=0.1, so the frozen quality check fails. Worst
rankings score zero. An already-failing baseline or a mutation that still passes
is NOT a demonstrated successful mutation; report it as such. Do not select a
new mutation or lower floors after seeing results to manufacture success. A new
protocol version and fresh reviewer agreement would be required.

## Timing and publication: keep the limitations

PR #380's existing artifact remains a synthetic load PILOT, executed at
`b5ffcbf0657b495329b4da7eaac94a5dd86f97b0`: 50,000 current/FTS/probe rows,
30 measured calls after two warmups, nearest-rank p95=5253.448459999985ms.
With only 30 samples that is the second-largest observation, not a stable tail
estimate. There were FIVE timed workload strings: four positive strings and one
absent-token string, each repeated six times. Repetition and post-migration cache
state can flatter timings. Setup and first-query times are separate; no OS-cold,
RPC, historical/private-room representativeness or SLO pass is claimed.

The proposed full 50k run remains 100 warmups plus 1,000 measured calls, with
explicit first-query/warm-cache treatment and all timings retained. It has NOT
run; no claim that the pilot satisfies it. The existing load source/artifact are
not changed by adding this pure scorer, so no repeat load pilot is needed merely
to test the scorer. New-head source review and CI are still separate gates.

Real questions, claims, votes/gold and raw outputs stay in an approved private
agent-owned location outside git. Public nvoy gets only reviewed non-sensitive
implementation, synthetic fixtures and approved aggregates, never a live Hive
dump. Grok found the boundary acceptable as a method; approval of a concrete
private artifact location/public release remains with Dead Rabbit. No grants,
provider changes, deployment or corpus publication are authorized here.

## Status

Only synthetic scorer/control tests have run. Author/labeler/adjudicator roles
are conditionally assigned, not cleared or completed. No blind question set,
real corpus/gold manifest or real recall baseline is frozen. No real Hit/MRR or
real-data ranking mutation is claimed. DJ owns those gates; Grok confirms v3,
role exposure is resolved explicitly, and Dead Rabbit settles private location,
readers and public aggregates. The provenance-only author packet is staged
privately, not published or a substitute for approved source context. Source
approval/CI at 88a3b88 do not transfer to this source change. B4 is not done.
