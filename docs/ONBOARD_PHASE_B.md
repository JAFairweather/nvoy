# Onboarding, phase B: the fleet runs the add itself

Phase A (#289) is an operator command: `nvoy-onboard run <name>` on the fleet host, with the
pairing link handed to the owner by hand. Phase B removes the operator. A signed setup request on
the relays is the whole instruction, and the owner follows the add on waggle's page. This is waggle
epic 721, stage 2, and nvoy #322–#325.

It changes who runs the steps and how their results reach the owner. The steps themselves, and what
makes each one done, stay as `onboard_run.mjs` has them.

## What runs

- **`deploy/nvoy-onboard.sh`** (#322) runs `nvoy-onboard.mjs` in the deployed runtime image, with
  the host paths the steps write mounted at the same paths.
- **`nvoy-onboard.timer`** fires **`nvoy-onboard.service`** every 30 s. The service is a oneshot:
  `nvoy-onboard.sh watch`. systemd never starts a second tick while one runs, so a pairing that waits
  for the owner holds the next tick back instead of racing it.
- **`watch`** (#323) reads every owner's setup requests from the grant relays and every installed
  agent's relays: kind 30078 by an installed agent's grantor, `d` = `nvoy-onboard/<name>/add_agent`.
  For each name whose newest request is not finished in the ledger, it runs the same steps as
  `run`, in watch mode. Requests are processed one at a time, oldest first. The read pages back
  through every owner event of the last 7 days (the age past which a request is refused anyway), so
  newer owner events never push an unfinished request out of a fixed window. A relay cannot be asked
  for the rest of one second, so if more events share a second than a page holds, or a relay stops
  answering part way, or the page cap ends the walk, that relay's read is reported incomplete: the tick
  logs a warning naming the relay and exits 1. A request on it may be missing from that tick's queue.
- When the service is down, nothing happens. Nothing else does the steps instead, and the page shows
  the last receipt with its age.

Watch mode differs from `run` in three ways.

1. **It never redeploys a giver.** A seat giver that shares a room with the new agent, and has
   `may_post.mention_rooms` on (#321), can mention it with no manifest change. Any other seat giver
   leaves the givers step pending with the reason. `--givers-redeploy` stays an operator flag (#324).
2. **The pairing link goes to the owner, sealed.** `instance-pair` runs in-process. Its
   `nostrconnect://` link is sealed to the owner (NIP-44) inside the next receipt, and is never
   printed or logged. An unapproved link times out after 300 s; the next tick makes a new one, and
   the receipt carries the newest.
3. **Every receipt is published** (below), not only written to `/var/lib/nvoy-onboard`.

## The runner key

The fleet has no signing identity of its own, and sealing needs a sender key. The open question in
waggle's `DESIGN_ADD_AN_AGENT.md` ("the agent's connection decrypts, or a runner key") is settled
here as **a runner key**:

- It is a Bunker-held key named `nvoy-onboard`, made by the owner. Its secret never leaves the
  Bunker.
- It is paired once on the fleet by `nvoy-onboard.mjs runner-pair`, with the same client-initiated
  flow as an agent (`pairInstance`). The link goes to the owner by the operator's clipboard, once.
- The connection asks for exactly `get_public_key`, `nip44_encrypt`, `sign_event:27235` (the
  pairing probe, never published) and `sign_event:30078` (receipts). It cannot decrypt, post, react
  or join a room.
- Its config is `/etc/nvoy/onboard/runner.json`: `pubkey`, `relays`, `bunker_client_ref`,
  `bunker_uri_ref` (root 0600 files beside it), `authorized_keys` (the channel account's, for
  apply), and `ssh_target` (for the install details). It is outside `/etc/nvoy/instances`, so the
  deploy runner never reads it as an agent.
- It is a static writer on relay.nave.pub (nave.pub `allowlist.json`), so its receipts are stored.
- The page pins its pubkey. A receipt from any other key is not shown.

The agent's own connection does not gain `nip44_decrypt` for this; it already has it for DMs, and
the hive invite inside the request stays sealed to the agent as before.

## The receipt event

One addressable event per request, replaced on each change:

```
kind    30078
pubkey  the runner
tags    ["d", "nvoy-onboard:<request id>"], ["p", <owner>], ["e", <request id>],
        ["expiration", <now + 30 days>]
content NIP-44 (runner → owner) of:
{
  "v": 1,
  "name": "<name>",
  "request": "<request id>",
  "instance": "<instance id>",
  "steps": [ { "step": "staged", "state": "done|pending|refused", "at": <ms>, "detail": "…" }, … ],
  "pairing": { "uri": "nostrconnect://…", "made_at": <s>, "expires_at": <s> },   // only while pending
  "install": { "instance": "…", "ssh_target": "…", "host_key": "ssh-ed25519 …", "commit": "<40 hex>" }
}
```

- `steps` is the newest state of every step, in order, as the ledger has them.
- `pairing` is present only while a pairing waits for the owner. The receipt that ends the wait
  (approved, or timed out after 300 s) drops it. The link's secret is spent by the handshake either
  way, and the next tick seals a new link.
- `channel_key` is a step row that appears only for a hosted agent (no staged file, no row). An operator
  helper on herd-cloud reads the agent's `channel.pub`, and only that file, and writes it atomically to
  `<state dir>/<request id>.staged-channel.pub` on the fleet host: a regular file under 1 KiB, one OpenSSH
  line (`ssh-ed25519` or `ecdsa-sha2-nistp256`) whose comment is `nvoy-stage:<instance>:<request id>`. The
  runner checks that and reports `<type> <key> (SHA256:<fingerprint>)` in the row's `detail`, a public key
  only. Anything private-looking, a link, a second line or another binding is `refused` and never echoed.
  If the owner's `bind_runtime` names a different key, the row is `refused`. It is reported work, not proof:
  the bind is the owner's act and the presence event stays the proof. The helper is herd-infra's
  `bin/stage-channel-key`.
- `feed_key` is the same row for a Pi or Codex agent's second key, its wake feed (`mcp/tools/principal_family.mjs`:
  `pi` and `codex` are the two-key family; every other harness has one key). The file is
  `<request id>.staged-feed.pub` with the comment `nvoy-stage-feed:<instance>:<request id>`, under the same rules, and
  the row is also `refused` when it is the same key as the channel key. The owner's `bind_runtime` carries `channel_key`
  and, for these harnesses, `feed_key`; a bind without it, or with one for a one-key harness, is refused when the
  request is read. Before the apply both staged keys are read again against the bind, so a swapped, replaced or
  mismatched file seats nothing. The apply plans both principal lines before changing anything and seats the channel
  key under `codex-channel-mcp.mjs` and the feed key under `codex-channel-feed.mjs`, the same lines
  `instance-codex-channel-authorized-key.mjs` prints; `instance-unit.mjs verify --family codex` checks both. The Claude
  baseline is not run for this family: the wake feed baselines on its first start.
- `install` is present once the agent is staged. It holds the four fields waggle's step 4 builds the
  install line from (`DESIGN_ADD_AN_AGENT.md`, "What the page checks"):
  - `host_key` is the fleet's own `/etc/ssh/ssh_host_ed25519_key.pub`;
  - `commit` is `DEPLOYED_SHA`;
  - `ssh_target` comes from the runner config.
  All three are sealed, so the fleet's address is not public. The page checks each field against
  its rule before it renders anything, exactly as for an agent-signed event.
- It is published to the runner's relays and to the owner's request relays, and read back. A relay
  that refuses it is logged; the step state is unaffected.

The page treats receipts as **progress**, never as proof. Its proofs are what it reads cold: the
agent card, the profile, the writer list, the 39002 membership, and the presence event.

## The relay writer step

Today the step is a fixed pending line. With nave.pub #157 it is:

- **done** when the request owner's newest writer list on relay.nave.pub (kind 30000, `d` =
  `nave-relay-writers`) verifies and names the agent's key. The relay itself admits only lists from
  its `owners`, so a list it stores is one it acts on;
- **pending** otherwise, with "sign the writer list on the page (step 3)".

The page signs that list; the runner only reads it. An operator's `run` reads it the same way, from
relay.nave.pub or `--writer-relay`.

## Failure and replay

- A request id is run once to completion. The ledger's `finished` row stops every later tick. It is
  written only once the receipt that shows every step done has been taken by a relay; if that last
  receipt is refused, the request stays open and the next tick runs it again and resends it.
- An operator's `run` has no runner key, so it publishes no receipt and never writes `finished`. When
  every step is done it logs that the request is left open; the next watch tick, which finds each step
  done, sends the owner the finished receipt and then finishes it.
- An unchanged receipt is not sent again each tick. It goes out when a step's state or reason
  changes, or every 10 minutes as a heartbeat, so the page can tell a live runner from a stopped one.
- A tick and an operator's `run` never overlap: the wrapper holds `/var/lib/nvoy-onboard/.lock`, and
  the second exits 75, which the service counts as success.
- A newer request for the same name restages, as in phase A.
- A refused step stops that request. Its receipt says why, and the next tick does not retry it,
  unless a newer request arrives. A request that does not qualify at all (a bad tag, an unknown
  owner) is set aside by id in `watch-refused.jsonl`, with the same rule.
- No relay answering is not a refusal. That tick logs it and the next one tries again.
- A tick that crashes leaves the ledger as it was. The next tick resumes, because each step checks
  the state it makes, not a receipt.

## Tests

- **Wrapper** (`test/onboard-wrapper.mjs`): mounts, the socket, the host key, and the lock.
- **Receipt** (`test/onboard-receipt.mjs`): the runner config, the install fields by the installer's
  rules, the seal, and `created_at` order.
- **Watch** (`test/onboard-watch.mjs`):
  - one tick finds a new request and runs it to the pairing;
  - the receipt is sealed to the owner, opens with the owner's key, and carries the link;
  - a finished request is skipped;
  - a request whose finished receipt is refused stays open, and the next tick sends it and finishes;
  - owner events are read page by page, past any one page, and a relay that stops part way keeps
    what it gave; a read that did not reach the end (a crowded second, a relay that stops, the page
    cap) is marked incomplete, and the tick logs it and reports it;
  - an operator's `run` that gets every step done leaves the request open, and the watch tick then
    sends the finished receipt and finishes it;
  - `run` reads and verifies the writer list as watch does;
  - a giver outside a shared room stays pending, with no rewrite;
  - the relay-writer step follows the stored list;
  - a receipt is never published in the clear, and the link is never logged;
  - a runner connection that signs as another key publishes nothing.
- **Capability start** (`test/capability-start.mjs`, #325): for each capability a manifest can turn
  on, a rendered compose and the broker's start accept a manifest with it on.

## Channel presence (step 4 of the proof)

The page's step 4 needs a signed kind 30078 `nvoy-channel-presence` from the agent's own key (#345).
Two halves, because only the host sees channel processes and only the broker may sign.

- **Host collector.** `nvoy-presence.timer` runs `nvoy-presence.service` every 30 s as root. It reads
  `/proc`, the adapter container id and the installed authorized_keys line, and writes one
  counts-only snapshot per instance to `/var/lib/nvoy/presence`. It signs nothing. A process counts
  only if its cgroup is the adapter container, its uid is the worker uid, and its whole argv is
  exactly the channel command naming the line's own key fingerprint.
- **Broker.** Mounts that directory read-only, and every 30 s judges the snapshot. It signs only on a
  change, and re-signs an unchanged event every 30 minutes (its expiry is 2 h). A missing, stale or other-key snapshot,
  or one with only older untagged sessions, signs nothing; that reads as unproven, never as a drop.

**One-time root install on the fleet host** (the deploy runner fetches the files into `/opt/nvoy-hub`;
it does not install units):

    install -m 0644 /opt/nvoy-hub/deploy/nvoy-presence.service /etc/systemd/system/
    install -m 0644 /opt/nvoy-hub/deploy/nvoy-presence.timer /etc/systemd/system/
    # edit --authorized-keys in the service to the channel account's file (see /etc/nvoy/onboard/runner.json)
    systemctl daemon-reload && systemctl enable --now nvoy-presence.timer
    ls -l /var/lib/nvoy/presence/        # one <instance>.json per instance, refreshed every 30 s

Seats installed before #345 have no `--key-fp` on their line: they stay present and report unproven,
and are not rewritten. A new seat's line carries it. The broker's compose gains the read-only mount
when the deploy runner next re-renders and recreates it.

**Proven by tests, not yet live:** counting, judging, deciding and the collector against a fake
`/proc`. **Live gates:** the Bunker seat allows kind 30078; the unit points at the real
authorized_keys; a presence event newer than the bind receipt reads back on the relay.
