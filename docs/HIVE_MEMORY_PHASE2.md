# Hive Shared Memory — Phase 2: Consolidation, Curator Attestation, Store Merkle Root & Write Hygiene

- **Date:** 2026-11-06
- **Status:** Proposed Technical Design (for review by My Dude and approval by James)
- **Builds On:** `HIVE_MEMORY_PRIVATE_STORE.md` (`a1e8e49bd74dca67c5db3baa56f94565c3ef761fe4d6120f47e20fc8c53bdf34`)
- **Source Requirements:** James's *Notes on Hive Memory: Private Store Architecture (5 Nov 2026)* (Items 1–6)

---

## Executive Summary & Core Invariants

Phase 1 established the private SQLite store (`/var/lib/hive-memory/memory.sqlite`), per-reader/per-writer socket isolation, two-phase SQLite-then-ledger commit (`/var/backups/hive-memory/accepted-ledger.jsonl`), and verified half-hourly Backblaze B2 `restic` backups with a 1-hour stale-backup admission fence (`maxUnbackedSec: 3600`).

Phase 1 pruning is strictly mechanical (Class A TTL expiry and the 90-day retention purge), and cross-author conflicts are flagged (`conflict: true`) without resolution. **Phase 2 adds semantic consolidation, cryptographic source and whole-store Merkle attestation, write-time duplicate/conflict filtering, and deterministic backup-fence refusal handling—without weakening any Phase 1 invariant:**

1. **Nightly Curator Agent (`curator`) with Pure Write-Path Operation (Items 1 & 2):**
   - Runs on a nightly schedule (`hive-memory-curator.timer`) under its own Nostr keypair and writer socket (`/run/hive-memory/writers/writer.curator.sock`).
   - Never edits SQLite directly. Every merge, early retirement, Class A $\to$ Class B promotion, or unambiguous conflict resolution is a normal signed `kind: 30078` event submitted via `memory_submit` with `supersedes: [<source-event-ids>]`. Ambiguous conflicts are escalated to James in `waggle-test`.
   - A new **Curator Supersession Read-Projection Rule** hides source events consolidated by an active, current `curator` claim in the same scope from default `memory_wake` and `memory_query(include_history: false)` results, while leaving the source rows untouched in SQLite.
2. **Merkle-Style Source Attestation (`merkle_sources`) & 90-Day Source Retention Hold (Item 3):**
   - Every Curator consolidation event carries `["merkle_sources", "<64-hex-sha256-merkle-root>"]` computed over its sorted `supersedes` event IDs (each already a Nostr SHA-256 event hash).
   - `memory_submit` cryptographically verifies that all source IDs exist in the same scope and match `merkle_sources` before accepting the event.
   - Source events remain readable via `memory_query({ include_history: true })` for at least **90 days after consolidation** so any reader can verify whether the Curator's summary is faithful.
3. **Whole-Store Merkle Root (`store_merkle_root`) in `store_meta`, Ledger, and Backup Receipts (Item 4):**
   - Every commit and purge computes a canonical SHA-256 Merkle root over all stored events (`id`, `is_current`, `SHA256(raw_json)`) ordered by `id ASC`, recording `store_merkle_root` in `store_meta`, `accepted-ledger.jsonl`, and `/var/backups/hive-memory/last-verified-backup.json`.
   - Daemon startup and `hive-memory-restore` verify `store_merkle_root` in full, proving zero alteration of any stored event or current-head flag.
4. **Write-Time Near-Duplicate & Unacknowledged-Conflict Filtering (Item 5):**
   - `memory_lookup_prior` and `memory_submit` reject submissions that closely match an existing active claim in the same scope (`HIVE_MEMORY_NEAR_DUPLICATE`) or collide with another author's active fact key `d` (`HIVE_MEMORY_CONFLICT_REQUIRES_SUPERSEDES`) unless the writer explicitly cites the prior `event_id` in `supersedes`.
5. **Defined Broker & Agent Behavior on Write Refusal (Item 6):**
   - Distinguishes **Class 1 transient fence refusals** (`HIVE_MEMORY_BACKUP_STALE_WRITES_FENCED`, `HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE`, `HIVE_MEMORY_STORE_NOT_READY`, `HIVE_MEMORY_RATE_LIMITED`), **Class 2 duplicate/conflict refusals**, and **Class 3 hard policy refusals**.
   - During a backup outage (`HIVE_MEMORY_BACKUP_STALE_WRITES_FENCED`), the broker holds the signed memory in a bounded `deferred_fenced` queue (up to 24h) and auto-drains it once verified backups resume, returning `{ queued: true, deferred: true }` so the agent continues its task without retry-looping.

---

## 1. Nightly Curator Agent & Pure Write-Path Consolidation (Gate 1 — Items 1 & 2)

### 1.1 Curator Identity, Socket Binding, and Schedule
- **Identity & Keypair:** The Curator runs as a dedicated identity `curator` using its own Nostr keypair (held by its broker on `herd-cloud`, never by the SQLite daemon).
- **Config Schema Addition (`/etc/hive-memory/config.json`):**
  - Adds optional top-level `"curators": ["<64-hex-curator-pubkey>"]` (validated by `validateAndResolveConfig`: every entry in `config.curators` must be a 64-char lowercase hex pubkey that is also a configured writer in `config.writers`).
  - `config.readers.curator` and `config.writers.curator` (`perHour: 60`) bind `/run/hive-memory/curator.sock` (read-only) and `/run/hive-memory/writers/writer.curator.sock` (submit-only).
- **Schedule:** `hive-memory-curator.timer` triggers `hive-memory-curator.service` nightly at `03:15 UTC` (and can be triggered manually via `systemctl start hive-memory-curator.service`).

### 1.2 Pure Write-Path Invariant (No Direct SQLite Access)
- The Curator process runs under its own non-`hive-memory` Unix user (`nvoy-curator`) with **zero filesystem access** to `/var/lib/hive-memory/memory.sqlite` or `/var/backups/hive-memory/accepted-ledger.jsonl`.
- Its only interface to Hive Memory is:
  1. Reading active claims via `memory_wake` and `memory_query` over `/run/hive-memory/curator.sock`;
  2. Submitting signed `kind: 30078` consolidation or withdrawal events via `memory_lookup_prior` and `memory_submit` over `/run/hive-memory/writers/writer.curator.sock`.

### 1.3 Cross-Author `supersedes` Read-Projection Rule (`verification: 'consolidated'`)
In Phase 1, `events.is_current` is scoped strictly to `(pubkey, d)` so no author can overwrite another author's row. To allow the Curator to consolidate claims across multiple authors in a room without mutating their `events` rows:
- **Database Rows Remain Immutable:** Submitting a Curator claim `C` with `supersedes: [id_1, id_2, ...]` inserts `(C.id, 'supersedes', id_i)` into `links` and leaves `is_current = 1` on each source row `id_i` under its original author `(pubkey_i, d_i)`.
- **Read-Time Projection (`consolidatedByCurator` in `HiveMemoryStore`):**
  - A stored event `S` is marked **consolidated (`verification: 'consolidated'`, `consolidated_by: C.id`)** at read time (`nowSec`) if and only if there exists a stored event `C` in `events` joined via `links` where:
    1. `links.from_id = C.id AND links.relation = 'supersedes' AND links.target = S.id`;
    2. `C.pubkey` is in `config.curators`;
    3. `C.scope = S.scope` (cross-scope consolidation is forbidden);
    4. `C.is_current = 1 AND C.status = 'active' AND (C.exp IS NULL OR C.exp > nowSec)`; and
    5. `C.created_at >= S.created_at` (a consolidation never suppresses a source event created *after* `C`).
- **Effect on `memory_wake` and `memory_query`:**
  - `memory_wake`: excludes rows with `verification === 'consolidated'`, showing the Curator's consolidated claim `C` in their place.
  - `memory_query({ include_history: false })` (default): excludes rows with `verification === 'consolidated'`, returning `C`.
  - `memory_query({ include_history: true })` or `memory_query({ linked_to: S.id, include_history: true })`: returns `S` with `verification: 'consolidated'` and `consolidated_by: C.id` so any verifier can inspect the exact source claims behind `C`.
  - **Reversibility:** If the Curator (or James) withdraws `C` (`status: 'withdrawn'`) or if `C` expires, `S` immediately reverts to `verification: 'accepted'` without re-signing or mutating `S`.

### 1.4 The Four Nightly Curator Tasks & Conflict Escalation Rule
On each nightly run, for each authorized scope (`room:<uuid>` and `hive:ops`):
1. **Merge Near-Duplicates:** Groups active claims by `topic` and semantic/token overlap; synthesizes redundant status/fact claims into one signed claim at `hive-memory:<scope>:curated-<topic>-<slug>` with `supersedes: [id_1, ..., id_k]` and `merkle_sources`.
2. **Retire Obsolete Class A Status Claims Early:** Identifies in-flight status claims (`"PR #313 open"`, `"investigating lock bug"`) whose work is superseded by a newer shipped/resolved claim in the same topic; folds them into the resolved claim via `supersedes`.
3. **Promote Recurring Status Claims to Class B Durable Decisions (`ttl_sec: 0`):** When $\ge 2$ expiring Class A claims establish a standing project fact, invariant, or architectural decision, the Curator publishes a Class B decision (`["retention", "decision"]`, no `exp`) superseding the ephemeral status claims.
4. **Resolve Deterministic Conflicts & Escalate Ambiguous Conflicts to James:**
   - Queries all claims with `conflict: true`.
   - **Auto-Resolution Condition:** Resolves only when one claim has provably newer causal provenance (e.g., `B.as_of_git` is a git descendant of `A.as_of_git` in the local repo mirror, or `B` already links `A.id` in `as_of_evt` / `evidence`).
   - **Mandatory Escalation Condition:** If two conflicting claims lack strict causal/git ordering, the Curator **does not publish a consolidation**. Instead, it posts a structured escalation message in `waggle-test` mentioning `james` with the conflicting `d`, `event_id`s, authors, `as_of_git` anchors, and claim texts, recording the escalated pair in its local state so it does not spam duplicate escalations.

---

## 2. Merkle-Style Source Attestation & 90-Day Source Hold (Gate 2 — Item 3)

### 2.1 Canonical Source Merkle Root (`merkle_sources`)
Each Nostr `event.id` is already the 64-hex SHA-256 digest of `[0, pubkey, created_at, kind, tags, content]`. To bind a consolidated claim to the exact, immutable set of source records it summarizes:
1. Let $S = [\text{id}_1, \text{id}_2, \dots, \text{id}_k]$ be the deduplicated list of 64-hex `supersedes` event IDs sorted in ascending lexicographical order ($\text{id}_1 < \text{id}_2 < \dots < \text{id}_k$).
2. Compute leaf hashes with domain separation:
   $$h_i^{(0)} = \text{SHA256}(\texttt{"hive-memory-source-leaf-v1:"} \parallel \text{id}_i) \quad (1 \le i \le k)$$
3. Fold level by level until a single 64-hex root remains:
   - For each pair $(h_{2j}^{(m)}, h_{2j+1}^{(m)})$:
     $$h_j^{(m+1)} = \text{SHA256}(\texttt{"hive-memory-source-node-v1:"} \parallel h_{2j}^{(m)} \parallel \texttt{":"} \parallel h_{2j+1}^{(m)})$$
   - If a level has an odd number of nodes, the trailing node $h_{2j}^{(m)}$ is promoted unchanged to level $m+1$.
4. The signed event includes the tag `["merkle_sources", "<64-hex-root>"]`.

### 2.2 Service-Side Enforcement in `validateMemoryEvent` and `memory_submit`
1. **Structural Validation (`validateMemoryEvent` in `mcp/tools/memory.mjs`):**
   - If an event carries a `["merkle_sources", root]` tag:
     - `root` must be 64 lowercase hex characters;
     - The event must carry at least one valid 64-hex `["supersedes", "<event-id>"]` tag; and
     - `computeSourceMerkleRoot(supersedes)` must equal `root` (`merkle_sources does not match supersedes`).
2. **Store Verification (`submit` in `mcp/tools/hive_memory_store.mjs`):**
   - If `config.curators.has(event.pubkey)` and `v.supersedes.length > 0`, the event **must** carry a valid `merkle_sources` tag (`HIVE_MEMORY_CURATOR_MISSING_MERKLE`).
   - Whenever an event carries `merkle_sources`, inside the Phase 1 SQLite transaction (`BEGIN IMMEDIATE`):
     - Verify that every `id` in `v.supersedes` exists in `events` and has `scope === v.scope`. If any source event ID is absent from `events` or belongs to a different scope, abort with `HIVE_MEMORY_CURATOR_SOURCE_MISSING`.
3. **Envelope & Viewer Exposure:**
   - `envelope()` includes `merkle_sources: row.merkle_sources || null` and `superseded_ids: [...]` so any reader or viewer can independently recompute `computeSourceMerkleRoot(superseded_ids)` and fetch the source events.

### 2.3 90-Day Source-Retention Hold (`retentionDue`)
Because `merkle_sources` proves *which* source records went into a consolidation and that none changed—while the *faithfulness* of the summary is the Curator's attestation—source records must remain readable in `events` for verification:
- In `retentionDue(db, nowSec)`:
  - For any event `e`, let `lastCuratorConsolidationAt` be:
    ```sql
    SELECT MAX(c.created_at)
    FROM links l
    JOIN events c ON c.id = l.from_id
    WHERE l.relation = 'supersedes' AND l.target = e.id
    ```
  - An event `e` referenced as a `supersedes` target by an active, current Curator claim (`c.is_current = 1 AND c.status = 'active' AND (c.exp IS NULL OR c.exp > ?)`) is **held while its consolidating claim is within its 90-day verification window** (`lastCuratorConsolidationAt > nowSec - RETENTION_PURGE_AFTER_SEC`).
  - Even if `e` was an expired Class A claim whose own `exp` was 89 days ago when the Curator consolidated it into a Class B decision, `e`'s 90-day purge clock resets to `lastCuratorConsolidationAt + 90 days` (`7,776,000`s), guaranteeing at least 90 days of full source readability after any consolidation.

---

## 3. Whole-Store Merkle Root in `store_meta`, Ledger, and Backup Receipts (Gate 3 — Item 4)

### 3.1 Canonical Whole-Store Merkle Tree (`computeStoreMerkleRoot`)
To prove at startup and during any same-host or full-host B2 restore that the SQLite `events` table has not been altered, truncated, or had any `is_current` flag flipped:
1. Query all rows in `events` ordered deterministically by `id ASC`:
   ```sql
   SELECT id, is_current, raw_json FROM events ORDER BY id ASC
   ```
2. If `events` has 0 rows:
   $$\text{store\_merkle\_root} = \text{SHA256}(\texttt{"hive-memory-store-empty-v1:"} \parallel \text{store\_id})$$
3. If `events` has $n \ge 1$ rows:
   - For each row $r_i$ ($1 \le i \le n$), compute:
     $$\ell_i = \text{SHA256}(\texttt{"hive-memory-store-leaf-v1:"} \parallel r_i.\text{id} \parallel \texttt{":"} \parallel String(r_i.\text{is\_current}) \parallel \texttt{":"} \parallel \text{SHA256}(r_i.\text{raw\_json}))$$
   - Fold pairwise using domain prefix `"hive-memory-store-node-v1:"` (promoting any odd trailing node unchanged at each level) to obtain the 64-hex `store_merkle_root`.

### 3.2 Recording & Verifying `store_merkle_root`
1. **SQLite `store_meta`:**
   - Adds column `store_merkle_root TEXT NOT NULL` (migrated automatically via `ALTER TABLE store_meta ADD COLUMN store_merkle_root TEXT` + immediate backfill on first Phase 2 startup if absent).
   - Inside every Phase 1 transaction (`init`, `cutover`, `submit`, `purge`, `restore-gap-ack`), after updating `events`, recompute `store_merkle_root` and store it in `store_meta.store_merkle_root` and in the staged ledger JSON line (`store_merkle_root: "<64-hex>"`).
2. **Accepted-Write Ledger (`accepted-ledger.jsonl`):**
   - Every new ledger line carries `"store_merkle_root": "<64-hex>"`.
3. **Backup Snapshot & Verified Backup Receipt (`last-verified-backup.json`):**
   - `hive-memory-backup.mjs snapshot` reads `store_merkle_root` from the staged snapshot's `store_meta`, verifies `computeStoreMerkleRoot(snap) === meta.store_merkle_root`, and outputs `store_merkle_root` in the snapshot summary JSON.
   - `hive-memory-backup.mjs record-verified` records:
     ```json
     {
       "at": 1793971200,
       "write_seq": 18,
       "snapshot_id": "9f41c8...",
       "store_merkle_root": "4b825dc642cb6eb9a060e54bf8d69288fbee4904..."
     }
     ```
4. **Startup & Restore Verification:**
   - On daemon startup (`reconcileStoreAndLedger`) and during `bin/hive-memory-restore`, recompute `computeStoreMerkleRoot(db)` over `events` and verify:
     - `actualRoot === store_meta.store_merkle_root`, and
     - (when the latest ledger line carries `store_merkle_root`) `actualRoot === ledger.lastStoreMerkleRoot`.
   - Any mismatch fails closed immediately with `DB_MERKLE_MISMATCH` (`answer: 'unknown'`, writer sockets fenced).

---

## 4. Write-Time Near-Duplicate & Unacknowledged-Conflict Filtering (Gate 4 — Item 5)

### 4.1 Deterministic Shingle & Fact-Key Similarity (`computeClaimSimilarity`)
To enforce write hygiene inside `hive_memory_store.mjs` with zero external dependencies and sub-millisecond latency:
1. **Normalization (`normalizeClaimTokens`):**
   - Lowercase `claim`, strip punctuation (`[^\p{L}\p{N}\s]`), collapse whitespace, remove common English stopwords (`the`, `and`, `for`, `that`, `with`, `this`, `from`, `are`, `was`, `were`, `has`, `have`, `had`, `into`), and extract:
     - $W(c)$: set of normalized word tokens of length $\ge 3$;
     - $B(c)$: set of adjacent word bigrams `"w1_w2"`.
2. **Similarity Score (`claimSimilarity(a, b)`):**
   $$\text{sim}(a, b) = \max\left(\text{Jaccard}(W(a), W(b)),\; \frac{|W(a) \cap W(b)|}{\min(|W(a)|, |W(b)|)} \cdot 0.85,\; \text{Jaccard}(B(a), B(b)) \cdot 1.15\right)$$
   clamped to $[0, 1]$.

### 4.2 Service-Side Gate in `memory_submit` (and Preflight in `memory_lookup_prior`)
When `memory_submit` evaluates a new active claim (`v.status === 'active'`) in `v.scope`:
- Query all active, current, non-expired, non-consolidated rows `r` in `events` where `r.scope = v.scope` and `r.pubkey <> v.pubkey` (or `r.d <> v.d` for the same author):
- Let `supersededSet = new Set(v.supersedes)`.
1. **Rule 4A — Unacknowledged Cross-Author Collision at the Same Fact Key `d` (`HIVE_MEMORY_CONFLICT_REQUIRES_SUPERSEDES`):**
   - If there exists an active row `r` with `r.d === v.d` and `r.pubkey !== v.pubkey` and `!supersededSet.has(r.id)`:
     - Refuse with:
       ```json
       {
         "accepted": false,
         "code": "HIVE_MEMORY_CONFLICT_REQUIRES_SUPERSEDES",
         "existing_id": "<r.id>",
         "existing_pubkey": "<r.pubkey>",
         "existing_d": "<r.d>",
         "message": "another author already holds an active claim at this fact key; query it first and include its event_id in supersedes if replacing or contesting it"
       }
       ```
2. **Rule 4B — Near-Duplicate Claim in the Same Scope (`HIVE_MEMORY_NEAR_DUPLICATE`):**
   - For each active row `r` in `v.scope` where `!supersededSet.has(r.id)` and `!(r.pubkey === v.pubkey && r.d === v.d)`:
     - Compute `sim = claimSimilarity(v.claim, rBody.claim)`.
     - If `sim >= 0.72` (or `sim >= 0.65` when `r.topic === v.topic` and both claims have $\ge 6$ significant tokens):
       - Refuse with:
         ```json
         {
           "accepted": false,
           "code": "HIVE_MEMORY_NEAR_DUPLICATE",
           "existing_id": "<r.id>",
           "existing_pubkey": "<r.pubkey>",
           "existing_d": "<r.d>",
           "existing_topic": "<r.topic>",
           "similarity": 0.81,
           "message": "claim closely matches an existing active memory in this scope; skip duplicate write or pass supersedes: [existing_id]"
         }
         ```
3. **Preflight Support in `memory_lookup_prior({ d, topic, claim })`:**
   - `memory_lookup_prior` accepts optional `topic` and `claim` parameters and returns `near_duplicate: { id, d, pubkey, similarity } | null` and `conflict_at_d: { id, d, pubkey } | null` alongside `found`/`id`, allowing the broker (or preflight check) to catch duplicates immediately.

---

## 5. Defined Broker & Agent Behavior When a Write Is Refused (Gate 5 — Item 6)

Because `maxUnbackedSec: 3600` fences all new writes whenever off-host B2 `restic` backups are stale for $>1$ hour, a backup outage stops live `memory_submit` admissions across every writer at once. Phase 2 defines a strict 3-tier refusal contract across the broker (`instance-broker-memory.mjs`), channel MCP (`claude-channel.mjs` / `agent_memory.mjs`), and agent instructions (`agents/hive-rules.md`):

### 5.1 Three Refusal Classes

| Class | Refusal Codes | Meaning | Broker Action (`instance-broker-memory.mjs`) | Agent Action |
| :--- | :--- | :--- | :--- | :--- |
| **Class 1: Transient Fence / Outage** | `HIVE_MEMORY_BACKUP_STALE_WRITES_FENCED`<br>`HIVE_MEMORY_PURGE_BACKUP_INCOMPLETE`<br>`HIVE_MEMORY_STORE_NOT_READY`<br>`HIVE_MEMORY_RATE_LIMITED`<br>Socket / SSH transport timeout | Store or backup gate is temporarily closed; the signed claim itself is valid. | **Hold & Auto-Drain:** Unlinks `<runtimeDir>/memory-requests/<id>.json` but keeps `<stateDir>/memory/<requestId>.json` in `status: "deferred_fenced"` (up to 24h, max 32 queued per writer). Retries with exponential backoff (`30s` $\to$ `60s` $\to$ `300s`). As soon as backups verify and `memory_submit` returns `accepted: true`, scrubs plaintext in-place. | **Do not retry `memory_claim` and do not block work.** Continue the task, state key conclusions in git/PR/channel output, and let the broker drain the queued claim automatically when the fence clears. |
| **Class 2: Duplicate / Unlinked Conflict** | `HIVE_MEMORY_NEAR_DUPLICATE`<br>`HIVE_MEMORY_CONFLICT_REQUIRES_SUPERSEDES`<br>`HIVE_MEMORY_PRIOR_MISMATCH`<br>`HIVE_MEMORY_NOT_NEWER` | A matching or conflicting claim already exists in the store and wasn't acknowledged. | Scrubs plaintext from `<stateDir>/memory/<requestId>.json`, unlinks the spool file, and appends a metadata-only refusal notice `{ request_id, code, existing_id, existing_d, similarity, at }` to `<runtimeDir>/memory-refusals.jsonl` (`0640` `brokerUid:workerGid`). | Run `memory_query` for `existing_d` / `existing_id`. If the fact is already captured, **stop**. If genuinely superseding it, call `memory_claim` once with `supersedes: [existing_id]`. |
| **Class 3: Hard Policy / Invalid** | `HIVE_MEMORY_SECRET_WITHHELD`<br>`HIVE_MEMORY_SCOPE_NOT_AUTHORIZED`<br>`HIVE_MEMORY_WRITER_MISMATCH`<br>`HIVE_MEMORY_INVALID_EVENT`<br>`HIVE_MEMORY_NOTHING_TO_WITHDRAW` | Payload violates security, scope ACL, or schema invariants. | Terminal refusal: scrubs plaintext immediately, unlinks spool file, records metadata in `terminal-memory.jsonl`. | **Never retry** the rejected payload. |

### 5.2 Synchronous Fence Visibility on `memory_claim`
- The broker maintains a metadata-only status file `<runtimeDir>/memory-status.json` (`0640` `brokerUid:workerGid`):
  ```json
  {
    "version": 1,
    "state": "ready",
    "last_code": null,
    "deferred_count": 0,
    "last_refusal": null,
    "updated_at": 1793971200
  }
  ```
- When `queueMemory` (`mcp/tools/agent_memory.mjs`) runs:
  - If `<runtimeDir>/memory-status.json` shows `state === "fenced"` (e.g., `last_code === "HIVE_MEMORY_BACKUP_STALE_WRITES_FENCED"`), `memory_claim` still queues the request into `<runtimeDir>/memory-requests/<id>.json` (unless `deferred_count >= 32`, in which case it returns an immediate error `HIVE_MEMORY_DEFERRED_QUEUE_FULL`) and returns:
    ```json
    {
      "queued": true,
      "deferred": true,
      "store_fence": "HIVE_MEMORY_BACKUP_STALE_WRITES_FENCED",
      "request": "<requestId>",
      "message": "Off-host backup fence is active; your claim is held by the broker and will auto-submit when backups verify. Do not retry memory_claim."
    }
    ```
  - If `<runtimeDir>/memory-status.json` has a recent `last_refusal` from Class 2 (`HIVE_MEMORY_NEAR_DUPLICATE` or `HIVE_MEMORY_CONFLICT_REQUIRES_SUPERSEDES`), it surfaces that refusal metadata in the tool response so the agent knows immediately if its prior write was flagged as a duplicate.

---

## 6. Required Phase 2 Acceptance Tests (`test/memory.mjs` & `test/agent-memory.mjs`)

1. **Curator Cross-Author Supersession & Reversibility Test:**
   - Agent A and Agent B submit Class A claims `E_A` and `E_B` in `room:R1`.
   - Curator submits consolidated Class B claim `E_C` with `supersedes: [E_A, E_B]` and valid `merkle_sources`.
   - Verifies that `memory_wake` and `memory_query()` (default `include_history: false`) return `E_C` and omit `E_A` and `E_B`, while `memory_query({ include_history: true })` returns `E_A` and `E_B` with `verification: 'consolidated'` and `consolidated_by: E_C.id`.
   - Verifies that if Curator withdraws `E_C`, `E_A` and `E_B` immediately return to `verification: 'accepted'`.
2. **Source Merkle Attestation & 90-Day Source Hold Test:**
   - Verifies that a Curator consolidation without `merkle_sources`, with a tampered `merkle_sources`, or citing a non-existent/cross-scope source ID is refused (`HIVE_MEMORY_CURATOR_MISSING_MERKLE`, `HIVE_MEMORY_CURATOR_MERKLE_MISMATCH`, `HIVE_MEMORY_CURATOR_SOURCE_MISSING`).
   - Verifies that when `E_A` is 89 days past its own `exp` and is consolidated by `E_C` at `t_0`, running `purgeRetention` at `t_0 + 10 days` (when `E_A` is 99 days past its own `exp` but only 10 days past `E_C.created_at`) **retains `E_A`**, and only purges `E_A` once `nowSec > E_C.created_at + 90 days` (and `E_C` is itself superseded/withdrawn).
3. **Whole-Store Merkle Root Verification Test:**
   - Verifies that `store_meta.store_merkle_root`, `accepted-ledger.jsonl`, and `last-verified-backup.json` match `computeStoreMerkleRoot(db)` across `init`, `cutover`, `submit`, `purge`, and `restore`.
   - Mutating a single character of `raw_json` or flipping `is_current` directly in SQLite causes daemon startup and `hive-memory-restore` to fail closed with `DB_MERKLE_MISMATCH`.
4. **Write-Time Near-Duplicate & Conflict Gate Test:**
   - Submitting a claim with $\ge 0.72$ token/bigram similarity to an existing active claim in the same scope without `supersedes` is refused with `HIVE_MEMORY_NEAR_DUPLICATE` (returning `existing_id` and `existing_d`).
   - Submitting a claim at the same `d` as another author's active claim without `supersedes: [existing_id]` is refused with `HIVE_MEMORY_CONFLICT_REQUIRES_SUPERSEDES`.
   - Re-submitting with `supersedes: [existing_id]` succeeds.
5. **Broker Deferred Hold & Auto-Drain on Backup Fence Test (`test/agent-memory.mjs`):**
   - Simulates `HIVE_MEMORY_BACKUP_STALE_WRITES_FENCED` from `memory_submit`.
   - Verifies the broker unlinks `<runtimeDir>/memory-requests/<id>.json`, retains `<stateDir>/memory/<requestId>.json` in `deferred_fenced` state, writes `state: "fenced"` to `memory-status.json`, and then automatically submits and scrubs the record once the backup receipt is refreshed.
6. **Progressive-Disclosure Token Budget Test (`memory_wake` & `memory_query`):**
   - Seeds 100 active claims (~130 KB raw JSON) across 8 topics.
   - Verifies that `memory_wake` returns all `hive:canon` claims in full, at most 8 compact index cards (`format: "index"`), and `topic_directory` counts, with total serialized payload strictly `< 4,000` bytes (~1,000 tokens).
   - Verifies that `memory_query({ topic: "herd-infra" })` defaults to `format: "index"` (~150 bytes/record) and `memory_query({ d: "<slug>", format: "full" })` returns the full `because`, `evidence`, and `as_of_git` payload.
7. **Peer Workflow-Checkpoint Supersession & 24h TTL Cap Test:**
   - Agent `mydude` writes `herd-infra-pr22-review-status` (`E_1`); verifies the broker caps `ttl_sec` to `86400` (24h).
   - Agent `neil` writes `herd-infra-pr22-merged` (`E_2`) with `supersedes: [E_1.id]`; verifies `E_1` is immediately marked `verification: 'consolidated'` (`consolidated_by: E_2.id`) and hidden from default `memory_wake` and `memory_query()` without waiting for the Curator daemon.
8. **Canonical Topic Normalization & Alias Mapping Test:**
   - Verifies that submitting claims with `topic: "primer"`, `"illustrated_primer"`, or `"Illustrated Primer"` normalizes to `"illustrated-primer"`, and sentence-length topics containing spaces/uppercase outside the alias map are rejected with `HIVE_MEMORY_INVALID_TOPIC`.

---

## 7. Read-Time Context Budgeting & Progressive Disclosure (Gate 6 — Anti-Bloat Guard)

### 7.1 Live Telemetry Motivation (2026-11-06)
On Day 1 of active fleet operation, the store reached `97` active records totaling `124,864` bytes (~`31,216` tokens, or `~322` tokens per full record). At 25–30 writes/hour across 14 agents, unbudgeted `memory_wake` or `memory_query` responses would inject tens of thousands of tokens into agent contexts, causing token starvation and "lost-in-the-middle" attention dilution.

### 7.2 Two-Tier Progressive Disclosure (`format: "index" | "full"`)
Just as Antigravity skills expose only `name + 1-line description` in the system prompt and load `SKILL.md` on demand, Hive Memory separates **Discovery (`index`)** from **Inspection (`full`)**:

1. **Compact Index Card (`format: "index"`, default for `memory_query` when `d` / `id` is not specified):**
   - Each record is projected to ~150 bytes (`~38` tokens — an **8.5× reduction** from `1,287` bytes):
     ```json
     {
       "event_id": "a1b2c3d4...",
       "scope": "room:a8186b53-537d-46ad-a7e7-b6486c58970e",
       "d": "hive-memory:room:...:herd-infra-github-installer-pr22",
       "slug": "herd-infra-github-installer-pr22",
       "topic": "herd-infra",
       "author": "neil",
       "authority": "peer",
       "created_at": 1793988100,
       "retention": "ttl_14d",
       "claim_preview": "PR 22 merged at a1cf98e on 2026-11-06. Repeated installer runs for agent-crystalclaude..."
     }
     ```
   - Omitted in `index` mode: `because`, `evidence`, `as_of_git`, `as_of_evt`, `checked_at`, `reader_pubkey`, `verification_reason`.
2. **Full Record Inspection (`format: "full"`, default when querying a specific `d` or `event_id`):**
   - Returns the complete envelope including `claim`, `because`, `evidence`, `as_of_git`, `as_of_evt`, `supersedes`, and `merkle_sources`.

### 7.3 Hard 1,000-Token Ceiling on `memory_wake`
`memory_wake` is strictly bounded to `< 4,000` bytes (`~1,000` tokens) regardless of how many thousands of records exist in the store:
1. **Tier 1 — Canonical Rules in Full (`hive:canon`):** Up to 10 active `hive:canon` records returned in full (`~400` tokens).
2. **Tier 2 — Top-8 Relevant Index Cards (`format: "index"`):** At most 8 non-consolidated, active claims ranked by `(topic match to agent's active repo/role, recency, Class B durability)` (`~300` tokens).
3. **Tier 3 — Topic Directory Map (`topic_directory`):** A lightweight map of active claim counts per canonical topic (`{ "herd-infra": 21, "hive-memory": 20, "nvoy": 12, "r1": 9, "illustrated-primer": 9, ... }`, `~60` tokens) so the agent knows what knowledge clusters exist and can query a specific topic on demand.

---

## 8. Three-Tier Retention Contract, Peer Workflow Supersession & Quotas (Gate 7)

### 8.1 Three-Tier TTL Contract (Stopping 14-Day PR Checkpoint Bloat)
Live telemetry showed `herd-infra` (21 claims) and `nvoy` (12 claims) accumulating step-by-step PR review checkpoints (`nvoy-pr310-review-status`, `nvoy-pr319-review-status`, `herd-infra-pr22-review`) with 14-day TTLs. Phase 2 enforces three retention tiers in `agent_memory.mjs`:

| Tier | Purpose | Slug / Tag Pattern | Default & Max `ttl_sec` |
| :--- | :--- | :--- | :--- |
| **Class A-Workflow (`ttl_24h`)** | PR approvals, review handoffs, active task locks, WIP checkpoints | Slug ends in `-review`, `-review-status`, `-owner`, `-wip`, `-handoff`, `-status` | **Default `86,400` (24h)**, Max `172,800` (48h) |
| **Class A-State (`ttl_14d`)** | Sprint milestones, deployment states, operational incidents | Standard Class A claims | **Default `1,209,600` (14d)**, Max `2,592,000` (30d) |
| **Class B-Decision (`decision`)** | Standing architectural invariants, canonical rules, non-obvious gotchas | `ttl_sec: 0` (`["retention", "decision"]`) | **Durable (`0`)** until superseded or withdrawn |

### 8.2 Immediate Peer Supersession for Workflow Checkpoints (`superseded_by_peer`)
While general multi-author consolidation requires a `config.curators` key, a workflow handoff explicitly invites the next agent in the chain to close the loop (e.g., `mydude` writes `herd-infra-pr22-review` and hands off to `neil`, who merges PR 22 and writes `herd-infra-github-installer-pr22`).
- **Rule:** If a new claim `C` by any authorized writer in `scope` explicitly cites `S.id` in `supersedes: [S.id]`, AND `S` is a **Class A-Workflow** claim (or `S.claim` / `C.claim` share the same PR/issue number in `S.topic === C.topic` and `C.created_at >= S.created_at`), `HiveMemoryStore` immediately projects `S` as `verification: 'consolidated'` (`consolidated_by: C.id`) at read time—hiding the obsolete review/handoff checkpoint from default `wake` and `query` immediately without waiting for the Curator timer.

### 8.3 Orchestrator Write Quota Adjustment (`/etc/hive-memory/config.json`)
- Live telemetry showed `mydude` hitting `20/20` writes/hour (`2` `HIVE_MEMORY_RATE_LIMITED` refusals) due to cross-thread orchestration.
- Update `perHour` quotas in `/etc/hive-memory/config.json`:
  - `mydude`: `50` writes/hour
  - `curator`: `120` writes/hour
  - Standard specialist agents: `20` writes/hour
- Also purge retired pubkeys (`waggle`, `armada-probe`, `armada-probe-2`) from `config.writers` on `herd-cloud` so they no longer appear in `agent_roster` with `is_reader: false, is_writer: true`.

---

## 9. Canonical Topic Normalization & Volume-Triggered Active Grooming (Gate 8)

### 9.1 Broker Topic Normalizer & Allowlist (`normalizeMemoryTopic`)
Live telemetry revealed 16 distinct topic strings including duplicates (`primer`, `illustrated-primer`, `illustrated_primer`) and sentence-length topics (`Active Hive priorities (Canon)`, `where DJ Codex runs`).
1. **Alias Map in `mcp/tools/memory.mjs`:**
   - `"primer"`, `"illustrated_primer"`, `"illustrated-primer"` $\to$ `"illustrated-primer"`
   - `"rabidrabbit"`, `"rabid-rabbit"`, `"r1"` $\to$ `"r1"`
   - `"active hive priorities (canon)"`, `"canon"` $\to$ `"hive-canon"`
   - `"where dj codex runs"`, `"armada"` $\to$ `"herd-infra"`
   - `"viewer-test"` $\to$ `"hive-memory"`
2. **Format Constraint:** After alias mapping, `topic` must match `^[a-z0-9][a-z0-9-]{0,39}$` (lowercase kebab-case, max 40 chars) or be refused with `HIVE_MEMORY_INVALID_TOPIC`.

### 9.2 Volume-Triggered + 2-Hour Active Grooming Cadence
Instead of waiting 24 hours for a nightly run while topics balloon past 20 claims:
1. **Cadence:** `hive-memory-curator.timer` runs every **2 hours** (aligned with Dead Rabbit's check-in loop).
2. **Volume Threshold Trigger (`MAX_UNCURATED_PER_TOPIC = 8`):**
   - Whenever any topic in a scope has `> 8` active, non-consolidated claims (currently triggered on `herd-infra` [21], `hive-memory` [20], `nvoy` [12], `hive` [9], and `r1` [9]), the Curator prioritizes that topic:
     1. Folds all completed PR review/merge pairs (`*-review*` + `*-pr*`) into the merged claim.
     2. Synthesizes multi-step investigation trails (such as the 5 `r1-juke-*` claims) into a single `<topic>-<subtopic>-current-state` claim citing all source `event_id`s in `supersedes` (with `merkle_sources`) and all commits/PRs in `evidence`, bringing each topic back down to $\le 5$ high-signal active claims.
