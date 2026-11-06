# Mention lists from room membership (#321)

Status: spec for review. No code yet.

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

### 2. The roster: who is in each room

The broker reads it, because it holds the NIP-42 login (`openBuzzSession` plus `brokerSigner`, as
`instance-broker-native.mjs` already does).

For each room R in `may_post.channels`, the read is:
`{ kinds: [39002], '#d': [R], '#h': [R], limit: 5 }`. The newest event's `p` tags are the members.
This is the same read `onboard_join.mjs` `inRoom` makes. Factor it into one shared function and use
it in both places.

Trust: the same as for 44100/44101 today. The relay makes 39002 and refuses a client-submitted one.
Verify the event signature. The open question (Q1) is whether to also pin the relay's own pubkey.

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
- in the post and reply paths, whenever a requested key is on no list (the same hook the grants
  check uses, `instance-broker-post.mjs:51`);
- in the hourly card run.

A failed read keeps the last good file, and logs it.

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
- **Broker, post path:**
  - If a key is off the manifest list, check the grants, then the roster for the request's channel.
  - If the key is on neither, refresh the roster once and check again.
  - Only then refuse, with the existing `NVOY_POST_MENTION_REFUSED`.
  - If the roster can't be read, hold the post for retry, as the grants path does today
    (`instance-broker-post.mjs:56`). Don't refuse it.
- **Broker, reply path:** the same check (`instance-broker-reply.mjs:151-155`).

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

A member who leaves drops out at the next refresh, within 5 minutes. A post already queued with that
mention is re-checked by the broker and refused if the member has gone. A manifest entry or a grant
for the same key still works.

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
  - a bad signature is ignored;
  - a failed read keeps the last good file.
- **Broker post path:**
  - an unknown key triggers one refresh, then a refusal;
  - an unreadable roster holds the post;
  - a member who has left is refused at drain.
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

## Open questions for review

- **Q1.** Is the Buzz relay's refusal of client-made 39002 enough, or should the roster read also
  pin the relay pubkey (NIP-11)? `inRoom` checks neither today.
- **Q2.** Opt-in field, or default-on for `may_post.channels`? This spec says opt-in (see §1).
- **Q3.** Is a 5-minute refresh right? The on-demand refresh covers the key path. A `@name` written
  in the text for a brand-new member can still miss it for up to 5 minutes.
