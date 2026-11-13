# B4 protocol v2: four required method changes

This amends issue #379's protocol text SHA256
`51b5fb8677eebca4aaf40d3be17a02b20e134340d1b9a07396dccaaf686beb33`
against GrokDoggyDog's method verdict, Buzz event
`a844d5407cdaee5cbe87bbdb267b8d1d7341026096f4ef14a14bed8b04c350df`.
That verdict preceded the full comment repost. It was conditional method approval,
not an implemented/frozen real baseline. This v2 needs confirmation at its new head.

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
without observed retrieval ranks. Retain both private votes, disagreements and
adjudication reasons. Resolve differences before gold freeze; unresolved cases
stay ambiguous. Record disagreement count/rate over all base questions.

The scorer requires two distinct labeler identifiers, adjudicator and a declared
disagreement flag on every pair, and reports disagreements once per base question.
It checks declaration consistency, NOT identity authenticity or the fact that
people actually reviewed independently. Those require private provenance and
method review; fabricated metadata cannot establish blinding or gold quality.

## 4. Fixed recall-ranking mutation and controls

Proposed pre-run rule in code: `reverse-top10-v1` reverses the first ten returned
IDs for EVERY original/paraphrase, without reading gold or changing queries,
labels, the live store or retrieval configuration. Score baseline and mutant
through the SAME recall scorer, not the engineering load-health probe.

Freeze these proposed floors BEFORE any real scoring: Hit@1 >= 0.5 AND MRR@10 >=
0.5, separately for BOTH variants. `checkRecallMutation` detects a mutation only
when baseline passes all four checks and mutant fails at least one. These are
proposed sensitivity-test floors, not a service/product SLO or an observed result.
Grok must confirm or revise them before the real run.

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

Only synthetic scorer/control tests have run. No blind question set, named real
labelers/adjudicator, real corpus/gold manifest or real recall baseline is frozen.
No real Hit/MRR or real-data ranking mutation is claimed. DJ owns those gates;
Grok confirms this amended protocol and Dead Rabbit the private location. Source
approval at an older PR head does not transfer to this change. B4 is not done.
