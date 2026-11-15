# Design: an unadmitted mention leaves a trace (q-198 follow-up)

**Status: proposal.** Nothing here is implemented or approved. James decides the
open questions at the end before any code is written.

## The gap

On 15 Nov, Neil (18:51:57 UTC) and Dennis (18:55:03 UTC) each posted a PR 422
review that mentioned waggle-dev. James's task grants for those two pairs were
signed at 20:09, so the native broker dropped both posts at
`mcp/tools/instance-broker-native.mjs:125`:

```js
if (!grant) finish(`author … holds no live task grant; heard as data only [...]`)
```

`finish()` renames the spool marker to `.done` and writes one stderr line. So:

- the seat never learns the mention existed;
- the sender sees nothing different from a slow answer;
- the only record is in the broker container's log. That log went with the
  container when the 27c7fc9 deploy recreated it at 19:50:43, so the drop could
  not be confirmed afterwards.

The two reviews were found an hour later in Hive memory, by chance. The same
silent drop applies to these other `finish()` refusals:
- a DM from someone other than the owner (line 110);
- the hop limit and the per-sender hourly limit (line 133);
- the carried path's own no-grant drop, `mcp/tools/instance-broker.mjs:85-93`, which logs the same line.

"Heard as data only" names the intended behaviour, but the broker hears nothing:
the words are discarded.

## Proposal

Three layers. Each can ship on its own, and none admits the message, exposes
its text, or grants any capability.

### 1. A durable refusal record (always on)

Before `finish()` for any of the refusals above, the broker appends one row to
`stateDir/unadmitted-mentions.jsonl` (mode 0600, broker-owned, beside
`channel-source-admissions.jsonl`):

```json
{"version":1,"source_event":"<64hex>","author":"<64hex>","channel":"<uuid>",
 "reason":"no-grant|dm-not-owner|hop-limit|rate-limit","verdict":"<noGrantVerdict text>","at":1794772317000}
```

- It holds no content and no tags beyond the four ids.
- It lives in the `broker_state` volume, so a container recreate keeps it.
- The rows are deduped on `source_event`, like the source index.
- The file is capped: past 10,000 rows, the oldest half is rewritten away. A
  refusal must not become a disk-fill route for an ungranted sender.
- `bin/q183-admitted-classify.mjs` reads it and reports counts by reason and the
  newest `at`. `fleet-deploy`'s status read can do the same.

With this layer alone, the q-198 drop would have been one row an operator could
read the same day.

### 2. A content-free notice to the seat (rate-limited, default on)

Through the adapter socket, the broker also delivers a new closed-schema record,
alongside `verified-notification` (`mcp/tools/verified_notification.mjs`):

```json
{"type":"unadmitted-mention","instance":"<id>","envelope":"<source_event>",
 "notice":{"version":1,"source_author":"<64hex>","source_event":"<64hex>",
           "source_channel":"<uuid>","reason":"no-grant","observed_at":1794772317}}
```

- It carries no body, no receipt and no `authority`. `nvoy_channel_reply`
  refuses it, as it refuses any record that is not an `admitted-task` today
  (`claude-channel.mjs`, `NVOY_REPLY_REQUIRES_ONE_SENDER`). The reader shows it
  as `trustedInstruction: false`.
- Every queue consumer must learn the new type before the broker emits it:
  `instance-adapter.mjs`, `admitted_task.mjs`, `admitted_queue.mjs`, the Claude
  and Codex channel readers, the Codex app-server and macOS Desktop adapters,
  and the portable harness. Until a consumer knows it, the broker must not send
  it to that seat's delivery mode.
- At most one per author per hour, and at most 6 per hour per seat in total.
  Past either bound, only layer 1 records it. Grantors are never counted, since
  a grantor always holds the grant.
- `hop-limit` and `rate-limit` refusals never produce a notice. They are brakes
  on loops, and a notice would wake the agent the brake exists to stop.

This turns the drop into an interop gap the agent can report the same turn:
"neil mentioned me at 18:51:57 and holds no grant for me". The person who can
fix it (James, for a grant) can then be asked.

The cost is that an ungranted room member can wake the seat up to once an hour.
The per-seat cap bounds the total, and the notice has no text an injection
could ride on.

### 3. A visible refusal on the source message (opt-in, default off)

The status keeper (`mcp/tools/buzz_status.mjs`) already puts 👀 and 💬 on
admitted messages. A third status, such as `unheard`, could react on a refused
mention so the sender knows it did not land. This proposal keeps it **off** by
default:

- It makes the broker publish, signed as the seat, in response to someone with
  no authority over it.
- It tells the room which authors lack a grant for which seat.

If James wants it, it should be a per-seat manifest switch, with layer 2's rate
limits.

## Not proposed

- Admitting the body as data. The grant gate exists so ungranted text never
  reaches the model. Layers 1 and 2 report that a mention happened, not what
  it said.
- Retrying the drop when a grant later appears. Grants are not retroactive, and
  replay would turn a grant into a flood of old tasks. The sender re-sends, as
  Neil and Dennis did.

## Tests the implementation must carry

- A no-grant mention writes exactly one layer 1 row and one notice. A second
  mention by the same author within the hour writes a row and no notice.
- `hop-limit` and `rate-limit` refusals write a row and never a notice.
- The row and the notice hold no `content` and no unlisted key. The adapter
  refuses a notice with any extra key, as `validateVerifiedNotification` does.
- `nvoy_channel_reply` on an `unadmitted-mention` envelope is refused.
- A full refusal file is trimmed and never grows past the cap.

## Open questions for James

1. Should the seat see the author identity of ungranted senders (layer 2), or
   only a count?
2. Is layer 3 wanted at all, and if so on which seats?
3. Is one notice per author per hour, and six per seat, the right budget?

Evidence: Buzz events ad7e6219 and 15eb8c37 (the dropped reviews); grants
a97ddc0a and 7513ae5c on relay.nave.pub (created 20:09:40 and 20:09:35 UTC);
Dead Rabbit's fleet read, event 68201e8c; Hive `nvoy-q198-mention-drop-cause`.
