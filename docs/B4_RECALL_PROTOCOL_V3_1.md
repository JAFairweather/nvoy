# B4 v3.1: agreement-filtered, not adjudicated

DRAFT for Curator's exact-SHA read, not freeze/execution consent. Amends v3 at
8af534d3b04aad9ea31ec3845cb62fe04e6cc5ad. Concrete rules/minima below remain
proposed. Existing v3 scorer is incompatible; no fictional adjudicator.

1. Freeze 100 originals plus one equivalent paraphrase each before labeling.
No replacements or post-drop sampling. Dennis/Biggy independently label every
base question against the pinned corpus: dated disclosures; no new target
searches, peer votes or system results/ranks. Preserve sealed votes/reasons.

2. Each vote declares answerable (A), unanswerable (U) or ambiguous (X), and a
supporting-ID set. A requires nonempty gold; U/X require empty gold. Reject
missing votes, duplicate IDs and non-literal/lowercase-64-hex IDs as invalid
input, not disagreement. Agreement requires identical category AND exact gold
set (order irrelevant). Distinct defensible A support sets still disagree.
Two U votes agree; two X votes agree but remain ambiguous, never U. Reasons
need not match. Agreement retains the entire original/paraphrase pair with
shared category/gold; disagreement excludes both from scoring, not the ledger.
No adjudicator, peer reconciliation or gold re-judgment.
paraphrase gold inherited from the base question; equivalence unverified

3. Report all 100 in a 3x3 category-confusion table and exact-support agreement
within its diagonals. Also publish a table per labeler/category: pre-filter
count (that labeler's original count), survivors (exact-agreement pairs in that
category), dropped=pre-filter minus survivors, agreement=survivors/pre-filter
(null if zero). Each labeler's table totals 100; never sum the two tables.
Cross-category drops remain in both marginal tables; no invented consensus.
Overall agreement=retained/100; total dropped=100-retained.

4. Proposed minimum survivors: A=20, U=10, X=5. Coverage guards, not confidence
intervals, SLOs or authoring quotas. No manufactured categories or relaxed
minima after votes. Below minimum => that category INCONCLUSIVE; U/X otherwise
REPORTED_ONLY (no ranking mutation floor); X has no correctness metric.
Below 80/100 total agreement => STOP before retrieval, INCONCLUSIVE with stop
reason; Dead Rabbit batches fourth-seat grant yes/no to James. No agent adds
access. Any changed route needs a new pre-run review/pin. At >=80, any category
below minimum still forces overall sensitivity INCONCLUSIVE.

5. Hit@1/Hit@3/MRR@10 use surviving A only; abstention/false-positive rates use
surviving U only. Report X/exclusions separately; empty denominator => null.
Unknown/error is not abstention: no complete-baseline claim on query failure.
Keep private ranks/timings and independently recompute aggregates.
Keep reverse-top10-v1 over actual length, singletons unchanged, and Hit@1 AND
MRR@10 floors 0.5 for both variants. After coverage/agreement guards: baseline
misses any floor => INCONCLUSIVE; baseline passes/mutant fails => DETECTED;
both pass => NOT_DETECTED. Report per-variant answerable short-list counts/rates.
Every result line/object includes "agreement-filtered; floors not comparable to v3".
Filtering can favor easy cases and inflate scores; no full-set/adjudicated-gold
accuracy claim. Minima do not remove that selection bias.

6. Before ANY corpus/question/gold freeze or retrieval: approve and pin protocol,
v3.1 scorer/denominator rules and executable source by commit/SHA-256. Validate
all 100 paired votes, not just survivors. Required synthetic controls: support
and category disagreements; 80/79; each minimum/below-minimum; null denominators;
replacement refusal; all mutation states. This document is not executable proof.
Required control: paraphrase inherits base category and gold, and the pair drops together.

7. Targets only after corpus pin/question freeze into labelers' own 0660 drops;
remove after seal/audit under authorized disposal. Dennis checks sealed digests/
provenance only, labelled "audit by a labeler". Preserve "author exposure:
self-reported, not log-verified" and unknown overlap. Real bodies/IDs/questions/
votes/ranks stay outside public Git/shared memory. Scope/location, eligibility,
consent and actual freezes remain separate gates; no refused-snapshot retry.
Full load remains 50k rows, 100 warmups/1000 measured calls, retained timings and
cache/transport limits; 30-call pilot insufficient. Bounded method review is not
private-input audit, source/CI approval, deployment or B4 completion. No real run.
