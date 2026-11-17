# B4 v3.1 implementation interface

Source candidate only; not permission to freeze, collect, retrieve or publish private
inputs. The normative method is `B4_RECALL_PROTOCOL_V3_1.md` at protocol commit
`55b96e39fd55eca257a59a552c11e84d0f94ab2a`, SHA-256
`ddf45d7f0d0a37622688f7da18af57cf4a6e0e211c825c53e0d426ab0f25db5f`.
The source pin is `benchmarks/b4-v31-source-pin.json`. A pin identifies bytes;
it does not confer method/source approval or execution consent.

## Versioned entry points

`mcp/tools/memory-recall-benchmark.mjs` preserves the historical v3 exports.
Use the explicit v3.1 exports; do not pass agreement-filtered cases to `scoreRecall`.

- `prepareRecallV31(frozen)` validates the full 100-question manifest and both
  votes for every base question, then returns agreement accounting and coverage.
- `scoreRecallV31(frozen, results)` scores both variants of every survivor.
  A coverage stop permits only an empty result array and yields unmeasured/null
  metrics, never a complete scoring claim.
- `checkRecallMutationV31(frozen, results)` applies `reverse-top10-v1` to copied
  rankings and returns the coverage-gated three-state sensitivity verdict.
- `runRecallV31(frozen, retrieve)` clones the round, validates all votes and guards
  before invoking the caller's adapter, and returns the report plus private raw
  result rows. Every excluded pair produces zero adapter calls. Every coverage
  stop produces zero calls. The first errored/unknown result aborts the run.
- `formatRecallV31(report)` emits a one-line status with the required selection,
  author-exposure and inherited-paraphrase limitations. It emits no private IDs.

## Frozen input contract

The manifest contains `protocol_version: "3.1"`, the exact `protocol_sha256` above,
`round_id`, `question_set_sha256`, `paraphrase_gold_limitation`, two distinct string
`labelers`, their `disclosed_at` timestamps in ISO UTC millisecond form, and exactly
100 `questions`. Rule/count/minimum overrides and an adjudicator are refused.

Each question contains `question_id`, `original`, `paraphrase`, and exactly two
`votes`. Each vote contains `labeler`, `answerability` (answerable, unanswerable or
ambiguous), `gold` (unique literal lowercase 64-hex IDs), and a nonempty `reason`.
Only answerable votes may have nonempty gold, and they must have it. A vote missing
from even an excluded question invalidates the entire input, not just that pair.

The question digest is SHA-256 of UTF-8 `JSON.stringify` of the ordered array of
objects with keys inserted in this order: `question_id`, `original`, `paraphrase`.
This detects replacement against the supplied digest; it does not authenticate the
freeze or stop a malicious caller from supplying a newly fabricated manifest.

Disclosures, labeler identities, timestamps and round IDs are schema/provenance
references, NOT proof of blindness, independent voting, sealing or authentic gold.
The caller must separately verify approved private artifacts, corpus pin, seals,
author exposure, freeze chronology and execution consent. Changed rules require a
new frozen question set and labeling round, never rescoring old votes.

## Retrieval results and private retention

The adapter receives only `{question_id, variant, query}`; no gold or votes. It
returns `query_status: "ok"`, `ranking` (unique literal lowercase 64-hex IDs), and
`abstained`, which must be true exactly for an empty ranking. Optional identity
fields must match the request; supplied gold, answerability or adjudicator fields
are refused. Unknown/error is not abstention. The caller records raw observations,
timings, query failures and transport/cache boundaries in its authorized private
artifacts; the scorer does not fabricate or persist them.

Preparation/report objects contain private question strings, supporting IDs and
exclusion IDs. Raw rows contain ranks. Do not publish these objects to Git, Buzz or
shared memory. Publish only the authorized aggregate projection with its warnings.
No built-in socket/network/corpus reader, private exporter, seal verifier, cleanup
operation or production activation is added. Synthetic tests prove code behavior,
not real recall, transport, labeler authenticity, 50k load or B4 completion.
