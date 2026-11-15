# q-160: James's grant correction runbook

**Operator: James.** This is the signing route for the proposed q-145 correction
set, not permission for another seat to sign it. The source of operations is
[`Q145_GRANT_CORRECTIONS.tsv`](Q145_GRANT_CORRECTIONS.tsv); the audit and its
roster assumptions are in [`Q145_GRANT_AUDIT.md`](Q145_GRANT_AUDIT.md). Review
the named targets and grant IDs there before signing. If the roster has changed,
refresh and review the correction set first. Never put a Bunker URI, client
secret, or signing key in a command argument, log, PR, or message.

## What the three batches change

| Order | Rows in the 15 Nov proposal | Signed event | Result to prove |
| --- | ---: | --- | --- |
| 1. Revokes | 6 | James-signed kind 441, `e` = the exact old 440 ID | Four direct task grants to parked HR/LukeDog and two direct Dead Rabbit task grants end. Dead Rabbit's shadow grant remains; the two direct grants no longer bypass its single revocation switch. |
| 2. Fleet task grants | 97 | James-signed kind 440, `p` = instructor, target-scoped `da-scope`, `da-cap=task` | The listed active instructors may task the listed active fleet targets. Neil → DJ Codex is the first grant in the proposal. |
| 3. Mention permissions | 67 | James-signed kind 440, `p` = mentionable key, target-scoped `da-scope`, `da-cap=mention`, `name` = handle | The listed fleet seat may mention that key; this does **not** give the key task authority over the seat. |

The same TSV also has 41 `respond-to-add` and two `respond-to-remove` rows for
Buzz seats. Those are host configuration changes, not 440/441 signing. They
need their own reviewed herd-infra change and host read-back; none of the three
signing batches completes them.

## Read-only preflight

From a checkout containing the merged q-145 runner, with dependencies installed:

```sh
node bin/q145-grants.mjs
```

This dry-run opens no signer. It reads James's signed 440/441 events from
`relay.nave.pub` (the anchor) and `relay.ditto.pub`, `nos.lol`, and
`relay.primal.net` (the broker set), then folds the anchor and broker union
separately.

For the manual steps, use the existing Nvoy console or start the checkout's
console with `npm run console` and open `http://localhost:4443/` (see
`README.md`). James must verify the console signer
reports his public key
`4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d`.
The runner checks that identity itself before its `--apply` signs anything.

**Before the first 441, check the console's actual relay configuration.** Open
Settings → Relays on that device. Its list must include all four grant relays,
spelled exactly `wss://relay.nave.pub`, `wss://relay.ditto.pub`,
`wss://nos.lol`, and `wss://relay.primal.net`. The four are defaults, but this
device may have a saved override. If any is absent, use *Restore defaults* or
add it and *Save & reload*, then reopen Settings and check the loaded list.
Stop before signing until the four are present. Keep this configuration for
the manual revoke and task-grant batches; run the fresh dry-run after each
signature as below. The console can report a successful publish after one
relay acknowledges, so its success message alone is never the read-back.

Before any batch, require `broker_gaps_safe_or_recoverable: true`,
`anchor_gaps_recoverable: true`, and inspect `missing_on_anchor` and
`missing_on_all_broker_relays`. A missing event is acceptable only when the
runner identifies it as an already revoked 440 or as a recoverable correction.
A relay result-cap error, an unrelated missing live grant or 441, a source
validation error, or a changed roster stops signing. The 15 Nov read returned
200 anchor events, zero missing on the anchor, three old revoked 440s absent
from the entire broker set, and pending counts of 6 revokes, 97 task grants,
67 mention grants, and 43 host-config rows. These are a baseline, not a target
count to force if the live fold changes.

## Operator sequence with today's tools

1. **Revokes.** In the Nvoy console Ledger, paste each of the six full
   `grant_id` values from the TSV into the search field and open that external
   grant. Check the grantee and `task`
   capability against the row before James confirms *Revoke*. The console
   builds a public 441 against that ID. Do one row at a time. After each, run
   the read-only command above. Continue only after `revoke-task` falls by one
   on both folded sides; after all six, it must be absent from `pending`.
   A console success message alone proves only its publish call, so the fresh
   runner read is required. If a 441 reached only one side, stop this manual
   sequence. Do not sign a replacement: the runner can find the same signed
   event, but its present `--apply` would also sign the other pending batches.

2. **Fleet task grants.** The console's task-authority screen can sign a
   prefilled `task` grant for one instructor and target at a time. Use the
   `holder_pubkey` as sender and `target_pubkey` as agent from each
   `grant-task` row; start with Neil → DJ Codex. Check the displayed pair and
   capability before James signs. Re-run the read-only command after each
   small group and require `grant-task` to decrease; when all 97 are done, it
   must be absent from `pending`. If a grant reached only one side, stop this
   manual sequence; it needs delivery of its existing signed event, not a
   second signature or an all-batch `--apply`.

3. **Mention permissions.** The console task-authority prefill accepts
   `task`, `task+act`, and `task-relay`, but not `mention`. When revokes and
   task grants are absent from `pending`, James can use the q-145 runner for
   the remaining mention rows. First re-run the dry-run, check that only
   `grant-mention` remains among signed-event operations, and verify the
   count and each target/holder in the TSV. The signing command is:

   ```sh
   node bin/q145-grants.mjs --apply \
     --bunker-uri-file /path/to/james.bunker-uri \
     --bunker-client-file /path/to/james.nip46-client
   ```

   Supply **paths** to James's existing credential files, never their
   contents. The runner requires an interactive terminal and a typed
   `APPLY <pending-count>` before it opens the Bunker, verifies the signer is
   James, signs each unchanged draft, publishes to all four relays, and reads
   each ID back from the anchor **and at least one broker relay**. It prints
   each event ID. Keep that bounded output as the batch receipt, then run a
   fresh dry-run. `grant-mention` must be absent from `pending`.

**Stop if the dry-run before step 3 still lists a revoke or task grant.** The
runner will sign every pending signed-event row, in its own order. Do not use
its `--apply` switch as a shortcut for the three-batch sequence. After an
interruption, run the dry-run again. The runner can recover and republish a
one-sided signed event, but only resume `--apply` when its pending set still
contains **mention grants alone**. Never create a fresh signature just to retry.

## What proves completion

The runner's per-event read-back proves a newly delivered 440/441 exists on
`relay.nave.pub` and at least one broker grant relay. A fresh dry-run proves
the fold on each side sees the intended result: `revoke-task`, `grant-task`,
and `grant-mention` are all absent from `pending`; gap guards remain true;
`signed_events_to_republish` is zero. The revokes end the six exact old grant
IDs, task grants appear as live `task` edges for their target, and mention
grants appear in that target's mention set. Keep the output and event IDs with
the operator record. The remaining `respond-to-*` counts are separate host
work, not a failed grant batch.

## Tooling gap for a one-paste run

Today's runner cannot execute these three batches in order from one paste:
`signingOrder()` moves all grants ahead of revokes, and `parseCorrections()`
requires Neil → DJ Codex to be the first row, so a revoke-only or mention-only
filtered TSV fails validation. It has no `--batch` selector. Its dry-run
prints counts and a first row, not a complete per-row signing preview. The
console can do the six revokes and 97 task grants only one at a time; its
task-authority prefill cannot issue `mention`. A reviewed tool change would
need to select and display one batch, retain the fresh anchor/broker guards
and same-event recovery, and read every signed event back on both sides before
James can paste one command per batch. Until then, use the staged route above
or leave the corrections unsigned.

Source: `bin/q145-grants.mjs` (`parseCorrections`, `signingOrder`,
`publishAndReadBack`, `confirmApply`); `console/task-authority-lib.mjs`;
`console/ledger.mjs`; `mcp/tools/grant_fold.mjs`; and the q-145 audit and TSV.
