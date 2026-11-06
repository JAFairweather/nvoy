# Mention lists from room membership (#321)

Status: built on this branch (nvoy #321, PR #338); spec settled in review 2026-11-06. Live proof not yet run.

## The decision

James, 2026-11-06 (onboarding epic waggle #721, decision B): anyone in a room may mention anyone in
that room, and the list follows room membership automatically.

**Done when** a new member of a room is mentionable by, and can mention, every other member, with no
manifest edit and no restart of any running agent.

## What this changes, and what it doesn't

A mention list decides who an agent may **tag**. It does not decide whether the tagged agent treats
the message as work. That stays with the NIP-DA task grants (`admission.mjs` `nativeGrant`). A
member mentioned without a grant is still "heard as data only". This spec doesn't touch grants or
admission. Room membership must never become a task grant.

What stays as it is:
- the hourly post budget and the hop limit;
- the "mentions only in native Buzz channels, never in DMs" rule (`instance-broker-reply.mjs:114-115`);
- the manifest list and mention grants (BEESWARM §3, #295). Both stay, and the room roster is added
  as a third source beside them.

## Today (nvoy 2971185)

- `may_post.mention` is read once, at start, by every long-lived process (`runtime_manifest.mjs:221-234`).
- Changing it rewrites the manifest. The deploy runner hashes manifests and force-recreates the
  changed identity (`runtime-deploy-runner.py:297-354`). That is the restart `--givers-redeploy`
  causes (`onboard_run.mjs:175-189`, #324).
- One runtime-mutable source already exists: mention grants.
  - The broker records them in `<runtimeDir>/mention-grants.json` (`recordMentionGrants`, `agent_post.mjs:60-74`).
  - The channel MCPs re-read that file on every call (`mentionView`, `:85-88`).
  - Every check merges them into the list through `withMentionGrants`.
- Nothing reads a room's member list except onboarding (`onboard_join.mjs:116-120`).

## Design

### 1. Opt-in per identity

Add one manifest field: `may_post.mention_rooms: true`, default false.
- When it is true, the members of each room in `may_post.channels` become mentionable in that room.
- Turning it on is a manifest edit, and so a single recreate of that identity, done once at rollout.
  After that, membership changes need nothing.
- New agents get it from onboarding (`identity_allocation.mjs` `policyFromTemplate`).

An explicit field, rather than a default, keeps the widening visible in the manifest. It also keeps
an identity's scope from growing silently on upgrade.

The flag needs a second field: `buzz.relay_signer`, the hex pubkey the Buzz relay signs its room
lists with. Both fields come from trusted instance configuration, set at rollout and by onboarding.
If `mention_rooms` is true and `buzz.relay_signer` is missing or invalid, `readManifest` refuses the
manifest, so the feature fails closed. The key is never learned from the relay itself: NIP-11 served
by the same relay is not an independent pin.

### 2. The roster: who is in each room

The broker reads it, because it holds the NIP-42 login (`openBuzzSession` plus `brokerSigner`, as
`instance-broker-native.mjs` already does).

For each room R in `may_post.channels`, the read is:
`{ kinds: [39002], '#d': [R], '#h': [R], limit: 5 }`. The newest event's `p` tags are the members.
This is the same read `onboard_join.mjs` `inRoom` makes. Factor it into one shared function and use
it in both places.

Trust: the room list counts only when all of these hold.
- The event's `pubkey` is the pinned `buzz.relay_signer`.
- Its signature verifies.
- It has exactly one `d` tag, equal to R, and any `h` tag equals R.

Any other event is ignored. If no event passes, the room has no roster: an empty roster, never the
last one carried over. The shared read takes the pinned key as an argument. `onboard_join` passes the
signer from the configuration it writes the new manifest from.

The broker drops itself from the roster. A member with no usable key is skipped.

A member's **name** comes from its newest kind 0 (`name`, then `display_name`), reduced to the
manifest's name pattern `/^[a-z0-9][a-z0-9._-]{0,31}$/i`. Lowercase it, turn spaces to `-`, and
drop anything else. Two rules settle clashes:
- A name already used by a manifest entry or a mention grant stays with that entry.
- A roster name that clashes, or that reduces to nothing, is kept **by key only**. The `mention`
  field can still name it by pubkey, but `@text` can't.

### 3. Where it is kept

The broker writes `<runtimeDir>/mention-rooms.json`:

```json
{ "version": 1, "instance": "<id>", "read_at": 1762450000,
  "rooms": { "<room uuid>": [ { "pubkey": "<hex>", "name": "neil" } ] } }
```

It is written with the same rules as `mention-grants.json`:
- broker-owned and worker-group readable;
- `O_NOFOLLOW`, written only when it changed, and read back.

`instance-runtime-init.mjs` provisions it beside the grants file.

The broker refreshes the file:
- at start, then every 5 minutes, on a daemon timer;
- in the post and reply paths, with each pre-signing read of a room-derived key (§4; the same hook
  the grants check uses, `instance-broker-post.mjs:51`);
- in the hourly card run.

A failed read keeps the last good file, and logs it. `recordMentionRooms` merges: a room not read this
time (it failed, or a single-room refresh in the post path skipped it) keeps its last list, and when
the profiles can't be read a member keeps the name it last had. The pre-signing read in §4 records
what it read even when it then refuses the post. The agent card reads the file and never refreshes
it. That file is for **discovery** only: what the
channel MCPs show and resolve `@name` against. The broker never signs a room-derived mention on the
strength of the file (see §4).

### 4. One merged view, per room

`withMentionGrants(manifest, grants)` becomes
`effectiveMentions(manifest, { grants, rooms }, channel)`. It returns the manifest entries, then the
grants, then the members of `channel` taken from `rooms`. Every entry carries
`source: 'manifest' | 'grant' | 'room'`.

The roster is **per room**. A member of room A is not mentionable in room B unless it is also in B.
The other two sources stay global, as now.

Who uses it:
- **Channel MCPs:** `mentionView` reads both files on every call. `resolvePost` and
  `resolveReplyMention` resolve against the target channel. A reply resolves against the
  envelope's own channel.
- **Broker, post path.** A key on the manifest list, or on a live mention grant, goes ahead as
  today. Any other key can only be **room-derived**. For a room-derived key, the broker re-reads the
  authoritative roster (§2) for the request's channel **immediately before it signs**, on every
  attempt, retries included:
  - the key is in the fresh roster: sign and publish;
  - the key is not in it: refuse, with the existing `NVOY_POST_MENTION_REFUSED`;
  - the roster can't be read, or no event passes the checks: hold the post for retry, as the grants
    path does today (`instance-broker-post.mjs:56`). Don't refuse it, and don't fall back to the file.

  The invariant is **every publish attempt**: the read sits after the published-replay check and
  before counting, signing and publishing, so a retry of a post that was signed but never published
  reads the roster again. A replay of a post already published reads nothing, since it publishes
  nothing. The read happens only when a room-derived key is present; a post that mentions only
  manifest or grant keys never touches the roster.

  The fresh read also rewrites `mention-rooms.json`, so the discovery view catches up.
- **Broker, reply path:** the same check, with the same pre-signing read
  (`instance-broker-reply.mjs:151-155`).

### 5. What the agent is told

- `capabilitySummary` lists the room members per room ("in #waggle-test: neil, kerouac, …").
- Claude: the existing capability-change notice (`claude-channel.mjs:69-86`) fires when the merged
  list changes.
- Codex: its MCP instructions are fixed at init, so it sees changes through the post tool
  description (re-read on ListTools) and through the `mentionable` list in each result. That is
  acceptable. A Codex change notice is out of scope.
- `not_mentioned` and `mentionable` in tool results come from the merged list for that channel.
- **Agent card:**
  - The public card shows only counts, as now.
  - `ownerView` (#295) includes room entries with `source: 'room'` and `room: <uuid>`.

### 6. Leaving a room

A member who leaves drops out of the discovery view at the next refresh, within 5 minutes. It can't
be tagged in the meantime: the broker's pre-signing read (§4) refuses a room-derived mention of a
member who has gone, including one queued while they were still in the room. A manifest entry or a
grant for the same key still works.

### 7. The givers step (#324)

For a giver whose manifest has `mention_rooms: true`, `onboard_run` givers no longer rewrites
anything. It reports `done: mentionable through room <uuid>` once the new agent's join reads back
(the `rooms` step). Givers without the flag behave as today. #324 closes once every giver has the
flag.

## Tests

- **`effectiveMentions`:**
  - the three sources and their order;
  - per-room scoping (a member of A is refused in B);
  - a manifest name beats a roster name;
  - a clash or an unusable name means key only;
  - the broker drops itself.
- **Roster read:**
  - the newest 39002 wins;
  - each of these is ignored: a bad signature, an author other than the pinned signer, a `d` that
    is not the room, two `d` tags, and an `h` that is not the room;
  - with no event passing, the roster is empty;
  - a failed read keeps the last good discovery file.
- **Manifest:** `mention_rooms: true` without a valid `buzz.relay_signer` is refused.
- **Broker post and reply paths:**
  - a room-derived key is read fresh before signing, and refused when absent;
  - an unreadable roster holds the post, even when the discovery file still lists the member;
  - **leave between queue and send:** the member is in the roster when the post is queued and
    gone at drain, so the post is refused;
  - a retry reads the roster again, never reusing an earlier attempt's read.
- **Channel MCP end to end**, in the style of `test/mention-grants.mjs`: a member added to the
  fixture roster file becomes mentionable on the next call, with no restart.
- **Onboarding:**
  - `policyFromTemplate` carries `mention_rooms`;
  - the givers step reports `done` for a flagged giver and doesn't rewrite its manifest.

## Live proof (herd-cloud / nvoy-fleet)

1. Turn on `mention_rooms` for two fleet identities (one recreate each, announced first).
2. Add a third identity to #waggle-test **without** touching either manifest.
3. Within 5 minutes, all three can mention each other. Read back each tagged kind 9 cold from the
   relay. Then check, from the container's start time, that no identity restarted.

## Settled in review (mydude, 2026-11-06)

- **Q1. Pin the relay signer.** Take it from trusted instance configuration and check each
  39002's author, signature and exact room tags. NIP-11 from the same relay doesn't count as a pin.
- **Q2. Explicit opt-in.** `mention_rooms` is false by default.
- **Q3. 5 minutes is fine for discovery,** including when a new member's `@name` becomes visible.
- **Required change, made here:** any room-derived mention re-reads the authoritative roster
  immediately before signing, retries included. A failed read holds the post, and a member who
  has left is refused. The cached file is never authority (§3, §4, §6, and the leave-between test).
