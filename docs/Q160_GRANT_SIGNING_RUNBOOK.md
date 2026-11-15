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

## One-time set-up: James's signer files

The runner signs through a Bunker46 connection for James's own key, which needs
two files on the Mac. James makes them once.

### 1. In Bunker46

Create a connection for his own key (the bunker:// flow). Under permissions:
- Leave every "all kinds" toggle **off**, including the encrypt and decrypt
  methods.
- Use "Add kind" to add `sign_event` kind `440`, then `sign_event` kind `441`.
  Add nothing else.

Bunker46 then refuses to sign any other kind. Source, at
dsbaars/bunker46@1a9c6c3:
- `apps/server/src/bunker/bunker-rpc.handler.ts:157-164`: sign_event is denied
  unless a granted permission matches.
- `packages/shared-types/src/permissions.ts:54-61`: a permission with a kind
  matches only that kind; one with no kind matches every kind.
- `apps/web/src/views/ConnectionsView.vue:135-143`: the per-kind picker. It
  adds no kind while an all-kinds sign_event grant is set.

Kinds a client asks for when it connects are only recorded as pending, and they
grant nothing until approved (`bunker-rpc.handler.ts:80-89, 110-126`), so
approve nothing more. Reading the public key needs no permission
(`bunker-rpc.handler.ts:139-142`).

Copy the bunker:// connection.

### 2. On the Mac

From the checkout (`npm ci` done), run:

```sh
node bin/q145-james-signer-setup.mjs
```

1. It makes `~/.nvoy-harness/credentials/james-bunker-client`, a 64-hex NIP-46
   client key, mode 0600 (directory 0700). It never prints the key, and keeps
   an existing file.
2. It asks for the connection at a hidden prompt; paste it there. The
   connection is never echoed and never read from argv, so it stays out of
   shell history.
3. It asks the Bunker only for its public key, and refuses unless that is
   James's. It signs nothing.
4. Only after that check does it store the connection in
   `~/.nvoy-harness/credentials/james-bunker-uri`, mode 0600.
5. It prints the dry-run line and the three lines below, with both paths
   filled in.

These are the paths herd-infra `mac/bin/herd-memory --bunker` reads. Use
`--uri-file` and `--client-file` to choose others, and `--new-uri` to replace a
stored connection.

The client file is what can sign through the connection. With the kinds
limited as above, it can sign only grants (440) and revokes (441) as James. When
the q-145 batches are done, remove the connection in Bunker46 and delete both
files.

## The three paste lines

From a checkout of the merged runner (`npm ci` done), James pastes these one at
a time, in this order. The set-up script prints them with his two paths filled
in. Paste **paths**, never file contents.

```sh
node bin/q145-grants.mjs --apply --batch revokes --bunker-uri-file /path/to/james.bunker-uri --bunker-client-file /path/to/james.nip46-client
node bin/q145-grants.mjs --apply --batch task --bunker-uri-file /path/to/james.bunker-uri --bunker-client-file /path/to/james.nip46-client
node bin/q145-grants.mjs --apply --batch mention --bunker-uri-file /path/to/james.bunker-uri --bunker-client-file /path/to/james.nip46-client
```

Each line does the following, and opens no signer until the last steps:

1. It reads James's signed 440/441 events from `relay.nave.pub` (the anchor)
   and from `relay.ditto.pub`, `nos.lol` and `relay.primal.net` (the broker
   set). It folds the anchor and the broker union separately and prints the
   summary JSON.
2. It prints a preview of every row in the batch, one line each:
   `n/N`, the operation, holder name and full key, target name and full key,
   the full old grant ID for a revoke (`ends=`), the handle for a mention
   (`name=`), whether it signs a new event (`sign=new`) or redelivers an
   existing signed one (`deliver-existing=<id>`), and the side or sides it
   publishes to.
3. It stops before the prompt if any guard fails. A guard fails when
   `broker_gaps_safe_or_recoverable` or `anchor_gaps_recoverable` is false,
   on a relay result-cap error, on a source validation error, when the anchor
   holds fewer than 200 events, or when an earlier batch still has a pending
   row on either side: `batch task blocked: earlier batch still pending (6
   revoke-task)`.
4. James checks the preview against
   [`Q145_GRANT_CORRECTIONS.tsv`](Q145_GRANT_CORRECTIONS.tsv), then types the
   exact phrase it asks for, for example `APPLY revokes 6`. Anything else
   stops the run. It needs an interactive terminal.
5. It opens the Bunker, refuses unless the signer is James, and signs each
   unchanged draft. It refuses a signature that changes the draft. It
   publishes to all four relays and reads each event ID back from the anchor
   **and at least one broker relay**, printing `n/N: … read back as <id>`.

Keep each line's output as that batch's receipt.

**Before line 1**, run the line without `--apply` and its two path flags
(`node bin/q145-grants.mjs --batch revokes`). That is a read-only dry-run
with the same preview. The 15 Nov read returned 200 anchor events, none
missing on the anchor, and three old revoked 440s absent from the whole
broker set (allowed). It showed 6 pending revokes, 97 task grants, 67 mention
grants and 43 host-config rows. These numbers are a baseline, not a count to
force. If the live fold differs or the roster has changed, stop and refresh
the review first.

**After an interruption**, paste the same line again. A signed event that
reached only one side shows as `deliver-existing=<id>` and is redelivered
without a new signature. The next batch stays blocked until it lands. Never
sign a replacement by another route.

## What proves completion

The per-event read-back proves that each newly delivered 440/441 exists on
`relay.nave.pub` and on at least one broker grant relay. A final dry-run
(`node bin/q145-grants.mjs --batch mention`) proves the fold on each side:
- `next_batch` is `null`;
- `revoke-task`, `grant-task` and `grant-mention` are absent from `pending`;
- the gap guards are still true;
- `signed_events_to_republish` is 0.

Keep the outputs and event IDs with the operator record. The remaining
`respond-to-*` counts are separate host work, not a failed batch.

Source: `bin/q145-grants.mjs` (`run`, `selectBatch`, `previewLines`,
`confirmApply`, `deliveryPlan`, `publishAndReadBack`); tests in
`test/q145-grants.mjs`; `mcp/tools/grant_fold.mjs`; and the q-145 audit and TSV.
