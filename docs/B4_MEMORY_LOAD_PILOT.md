# B4 synthetic text-query load pilot

Issue: #379. This is one engineering step, not the B4 recall baseline.

## Run

Requires the repository's Node/SQLite runtime and installed dependencies. No daemon,
network, production configuration, provider credentials or live store is used.
The command creates and removes only its own temporary fixture under `TMPDIR`.

    node mcp/tools/memory-load-benchmark.mjs 50000 30 2

Positional arguments are rows, measured samples, warmups. Defaults are 50,000,
1,000, 100. Start with the explicit 30-sample pilot above: signed generation,
verified migration and repeated full-corpus ranking can be expensive. The small
regression suite runs through npm's `posttest` lifecycle:

    npm run posttest

## What is timed

Synthetic deterministic text is signed with an ephemeral local fixture identity,
validated and imported through `migrateStoreJson`, then reopened/reconciled by
`HiveMemoryStore.start`. No direct SQL insertion, copied retrieval algorithm,
forced READY state or patched ranking is used. The benchmark asserts both the
current-row count and FTS-row count and queries for a token in every row to verify
all requested rows participate. Setup/signing/migration/startup time is separate.

Every timed call invokes the real synchronous `HiveMemoryStore.query`, including
SQLite reads, ACL checks, parsing, lexical/FTS/vector ranking and projection. The
mixed workload includes common text, phrases and a no-hit token, with ten returned
cards maximum. All timings, query texts, answer states, counts and warmup/sample
counts are preserved. Unknown responses fail instead of appearing as fast searches.
Percentiles use the nearest-rank definition, `ceil(p*n)`, over every measured call.

The first query after migration/startup is recorded separately. It is NOT an
OS-cold-cache measurement. Later timings follow the declared warmups; no CPU
pinning, cache flushing or claim of an uncontended host is made. Code hashes,
revision, Node/platform/CPU and deterministic fixture-text hash accompany results.
Random fixture signers/event IDs can affect tie ordering across runs.

## Limits and remaining B4 work

All rows are current, accepted, one writer, one ops scope, with short repetitive
claims. This measures a simple engineering load, not a representative historical,
conflicting, private-room or multi-reader corpus. It does not measure socket/RPC
latency, human answer usefulness or private-data correctness. A fast-empty-query
mutant is rejected by the engineering probe; that is NOT the required real recall
quality mutation.

The 100 blind-authored questions, paraphrases, independently adjudicated gold,
real-corpus Hit@1/Hit@3/MRR and quality mutation remain open. No private corpus,
question set or benchmark score is published here. Agree on private artifact and
publication boundaries before exporting live Hive material. Review protocol and
actual pilot numbers are also posted inline in the crew channel for Curator.
