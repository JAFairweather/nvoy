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

## Recorded 30-sample pilot

The committed `docs/benchmarks/b4-synthetic-load-pilot.json` was executed at
`b5ffcbf0657b495329b4da7eaac94a5dd86f97b0`, with 50,000 current rows, 50,000
FTS rows and a 50,000-match participation probe. There are 30 measured calls
after 2 warmups (six calls per workload string), not the proposed 1,000-call
baseline. Node was v22.22.1 on Linux x64, AMD EPYC 9354P, on a shared host.

| Measurement | Milliseconds |
|---|---:|
| Setup, signing, verified migration and reconciliation | 909230.591369 |
| First query after startup (not OS-cold) | 4303.900125000044 |
| Nearest-rank p50 | 3419.1988980000606 |
| Nearest-rank p95 (29th sorted sample) | 5253.448459999985 |
| Maximum | 5425.294401000021 |

All 30 raw durations are retained without trimming. The 24 positive calls each
matched 12,500 rows and returned ten cards; six absent-token calls matched and
returned zero. No unknown response occurred. Artifact code hashes were verified
against both the executed git revision and unchanged working source. Earlier
foreground timeout produced no data and is not included in these statistics.

These are measured engineering observations, not a service SLO pass, population
estimate, real-recall quality score or completion of B4.

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
