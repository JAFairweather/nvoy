# Supervised participant runtimes

This is the implementation contract for Nvoy #44. A participant is not a
configuration convention: it is one immutable identity, one supervised runtime, and one
separate security domain. This applies equally to Claude and Codex workers.

For the cross-system map, deployment inventory and shipped-versus-pending status, begin with
[Nostr agent architecture](NOSTR_AGENT_ARCHITECTURE.md). This document is the lower-level runtime
and filesystem contract.

## Process boundary

```
relay ──1059 p-tag──> keyless watcher ──opaque envelope id──> broker
                                                        │
                                          verifies grants + decrypts
                                                        │
                                      authenticated private Unix socket
                                                        │
                                              Claude/Codex adapter
                                                        │
                                      bounded reply request (no key)
                                                        │
                                             broker validates + signs
```

The watcher never receives a key or plaintext. The adapter never receives a key, a key-file
path, a manifest path, or a decrypt command. The broker is the only process that can run the
grant gate or decrypt mail. Its socket is created by systemd at one fixed per-instance path,
owned by the broker user and mode `0660` for the one adapter group. Node does not expose Linux
peer credentials on the deployed runtime, so that ownership/ACL is the enforceable OS identity
check—not an invented in-process UID check. There is no bearer task handle to replay or forward.

## Supervisor-owned manifest

Each `/etc/nvoy/instances/<id>.json` is root-owned, mode `0644`, regular (not symlink), and
contains only public routing policy:

```json
{
  "version": 1,
  "id": "codex-jaf",
  "pubkey": "<64 hex>",
  "service_user": "nvoy-codex-jaf",
  "state_dir": "/var/lib/nvoy/codex-jaf",
  "runtime_dir": "/run/nvoy/codex-jaf",
  "spool_dir": "/var/lib/nvoy-watcher/codex-jaf",
  "broker_adapter_gid": 41001,
  "worker_handoff_gid": 41002,
  "watcher_uid": 41011,
  "broker_uid": 41012,
  "adapter_uid": 41013,
  "worker_uid": 41014,
  "bunker_uri_ref": "/etc/nvoy/credentials/codex-jaf.bunker-uri",
  "bunker_client_ref": "/etc/nvoy/credentials/codex-jaf.nip46-client",
  "worker_image": "ghcr.io/example/nvoy-worker@sha256:<64-hex-digest>",
  "worker_runner": "codex",
  "worker_credential_ref": "/etc/nvoy/credentials/codex-jaf.openai-api-key",
  "grantors": ["<64 hex>"],
  "task_carriers": [{ "pubkey": "<Waggle bridge 64 hex>", "channels": ["<Buzz channel UUID>"] }],
  "relays": ["wss://nos.lol", "wss://relay.primal.net"]
}
```

The supervisor canonicalizes every path, rejects symlinks and duplicate pubkeys/canonical
state/runtime paths across all manifests, and refuses any CLI or environment identity/path
override. The two Bunker references are broker-readable only: the URI carries the Bunker
connection capability and the client reference holds the stable NIP-46 transport key. Neither is
the participant identity nsec, which remains solely in `bunker.nave.pub`; neither is inherited by
watcher, adapter, or worker.

`worker_credential_ref` is intentionally a different credential class: a dedicated, revocable
model-provider API key used by the headless Claude/Codex process. It is mounted only in the
keyless worker, never in the broker. For `worker_runner: "codex"` its file holds an
`OPENAI_API_KEY`; for `"claude"` it holds an `ANTHROPIC_API_KEY`. It cannot sign or decrypt Nostr
traffic; the worker still cannot choose a recipient or publish a Nostr event. Use one
least-privilege provider key per participant runtime and rotate/revoke it independently of the
Bunker identity.

## Units and filesystem ownership

For each `<id>`, the installer creates a dedicated OS account `nvoy-<id>` and:

| Path | Owner/mode | Consumer |
|---|---|---|
| `/etc/nvoy/instances/<id>.json` | root:root 0644 | supervisor only |
| Bunker URI + NIP-46 client credentials | root:root 0600 on the host | broker only |
| Model-provider credential | root:root 0600 on the host | worker only; never a Nostr key |
| `/var/lib/nvoy/<id>` | nvoy-<id> 0700 | broker state/lock |
| `/run/nvoy/<id>` | adapter:broker-adapter 0711 | broker socket (broker can traverse, not replace; worker can only traverse to named handoffs) |
| adapter socket | adapter:broker-adapter 0660 | broker only |
| task input + admitted queue | adapter:worker-handoff 0640 | adapter → worker, read-only for worker |
| reply queue | worker:broker-adapter 0640 | worker → broker, read-only for broker |
| watcher spool | watcher:broker-adapter 0770, markers 0660 | watcher→broker marker intake |

Credentials are source files staged as `root:root` mode `0600`: that is safe even before an
instance exists. The Docker deployment turns each into a Docker secret and mounts it only into
its designated service. Do not use a shared host `broker` or `worker` group; it fails on a
fresh host and would weaken separation between identities. A future systemd installer must
instead create instance-specific groups before changing ownership.

`nvoy-broker@<id>`, `nvoy-watcher@<id>`, `nvoy-adapter@<id>`, and `nvoy-worker@<id>` run under distinct accounts. The broker obtains an
exclusive lock before opening its state. On systemd, a matching `nvoy-broker@.socket` unit creates
the only socket path with `SocketUser=nvoy-<id>-broker`, `SocketGroup=nvoy-<id>-adapter`, and
`SocketMode=0660`; only that adapter account belongs to the group. In Docker, use four distinct
container users and two distinct manifest groups: `broker_adapter_gid` for the broker↔adapter
socket and `worker_handoff_gid` for the adapter↔worker files. The worker is not in the socket
group. The adapter creates a `0660` socket inside an adapter-owned `0711` directory; the broker
gets the socket group and can connect but cannot unlink or replace it, while the worker has only
traversal to its named read-only input paths. The adapter receives this fixed path from its unit/container
and may not choose another one.

## Protocol and recovery

1. The watcher atomically writes one `<envelope>.pending` marker containing only
   `{ envelope, observed_at }`, then advances its seen log. It never parses a seal.
2. The broker atomically claims a marker, fetches the exact named envelope (not “all unread mail”), decrypts, and validates
   live 440/441 task policy. Unreadable, forged, revoked, duplicate, or stale markers are
   terminally recorded without delivery.
3. The broker pushes `{ type: "admitted-task", envelope, authority, messages }` over the
   authenticated per-instance socket. The adapter acknowledges only after durable hand-off to
   its own execution queue. A broker restart redelivers unacknowledged admitted work; a marker
   is never marked completed merely because it was observed.
   `authority` preserves the broker's verified grant id, grantor, `task`/`task+act` capability,
   sender, participant scope, and policy-check time. Every transport boundary validates that
   attestation and binds every message to its sender. Records from older runtimes without an
   attestation remain notifications/data; they are never silently promoted to instructions.
   A configured channel carrier uses authority version 2: the broker additionally verifies the
   complete embedded kind:9 source event, the original author's task grant, the carrier's distinct
   `task-relay` grant, and the manifest-allowed reply channel. The original author remains
   `authority.sender`; the bridge is transport only.
4. The adapter starts/alerts its client using a fixed local mechanism. An MCP
`resources/updated` notification is **not** a desktop wake guarantee. For Codex, the first
context-preserving adapter is `codex-app-server-adapter.mjs`: it runs locally, resumes the one
manifest-bound `codex_thread_id`, and submits the broker-admitted event as a turn. It has no
Nostr credential and cannot select a different thread. With the owner-selected local control
socket transport, that fixed binding may be an already-open desktop task; it is still never
selected by an inbound event. Claude adapters must meet the same durable-queue and explicit
session-binding contract before they are called a wake mechanism.
5. A worker that chooses to reply writes a bounded `reply-request` referencing the delivered
   envelope. The broker accepts it only when a live admission chain is recorded in its own
   receipt. Direct replies return to the sender; a channel-carry reply returns to its fixed carrier
   with the receipt-bound `relay` channel tag. It persists the exact signed NIP-17 wrap before publishing, so a crash
   retry republishes the same event rather than authoring another reply. The worker never sees the
   Nostr credential.

## Native Buzz ears and mouth (optional)

A manifest may add a `buzz` block. When it does, the identity also takes part in that Buzz
community directly, as its own key, with no carrier:

```json
"buzz": { "relay": "wss://<community host>", "channels": ["<channel uuid>"] }
```

Absent, nothing below runs, and the runtime behaves exactly as before.

```
Buzz relay ──kind:9 #h #p──> keyless buzz watcher ──<event>.buzz.pending──> broker
     ▲                              │                                            │
     │                     NIP-42 AUTH, signed by                re-fetch by id, nativeMention,
     │                     the broker's AUTH oracle              author's live task grant
     │                                                                            │
     └──────────── kind:9 reply, signed by the broker ◀── reply-request ◀── adapter
```

- **Login without a key.** Buzz serves nothing to a connection that has not answered its NIP-42
  challenge as a member. The broker daemon supervises `instance-broker-auth.mjs`, which listens on
  `<spool>/buzz-auth.sock` (broker-owned, broker-adapter group, `0660`; the adapter does not mount
  the spool). For each request it signs only what `checkAuthTemplate` accepts: a fresh kind 22242
  for this relay with exactly the `relay` and `challenge` tags. It rate-limits requests and never
  signs a second template on the same connection.
- **Hearing.** `instance-runtime watch` also starts `buzz-wake-watcher.mjs`. It subscribes to
  `{kinds:[9], #h: channels, #p: [self]}` and writes an opaque `<event>.buzz.pending` marker for
  each event that `nativeMention` accepts. The marker holds `{envelope, observed_at}` only. It
  keeps `buzz-wake-seen.log` and a `buzz-wake-since` watermark: the last moment it was known to be
  caught up. A restart therefore replays the gap it was down for, with ten minutes of overlap for
  author clock skew. A first run starts at "now" and never turns channel history into tasks.
  If either watcher exits, both stop, so the supervisor restarts the whole unit.
- **Admission.** The daemon drains `.buzz.pending` markers through
  `instance-broker-native.mjs`, under the same broker lock as wrapped mail. It re-fetches the event
  by id from the configured channels, re-verifies it, and asks attention (`--policy-only`) for the
  live grant set. It admits only when the **author** holds `task` or `task+act`. A message from
  anyone else is terminal and stays data. No answer from the grant relays is not a denial: the
  marker is requeued (exit 75). One signed message is admitted once across native and carried
  routes, through the shared channel-source index.
- **Authority v3** is v1 plus `source_event` and `reply_channel`, with no carrier fields. The
  envelope *is* the source event, there is exactly one kind-9 message, its author is the sender,
  and the channel must be in the manifest's `buzz.channels`.
- **Replying** uses the same `reply-request` queue. For a v3 receipt the actuator rechecks the
  author's grant live, freezes the kind-9 reply, signs it, and publishes it to the community relay
  (see OUTBOUND_ACTION_APPROVAL, "Channel replies enacted on the live grant chain").

## Required negative tests

- duplicate pubkey, state root, runtime root, or service user is refused;
- symlinked manifest/key/state/socket paths are refused;
- an adapter cannot read the broker key or choose another instance's socket;
- watcher environment contains no secret or decrypt path;
- malformed/replayed marker and wrong-peer socket connection deliver no plaintext;
- broker restart redelivers an unacknowledged admitted message exactly once after acknowledgement;
- revoked grant after marker observation yields no delivery.

## Runnable reference roles

Nvoy ships four intentionally narrow commands:

```sh
# all three get the same --instance name; neither adapter nor watcher gets a key
node mcp/tools/instance-runtime.mjs watch --instance codex-jaf
node mcp/tools/instance-adapter.mjs --instance codex-jaf
node mcp/tools/instance-broker-daemon.mjs --instance codex-jaf
node mcp/tools/instance-worker.mjs --instance codex-jaf --runner codex
```

### Local Codex context adapter

For a first-class Codex participant, give the desktop manifest an explicit delivery binding. A
desktop connected to a server-side broker must also declare `broker_mode: "remote"`; that mode
forbids every key, Bunker, and worker-credential reference in the desktop manifest:

```json
{ "broker_mode": "remote", "delivery_mode": "codex_app_server", "worker_enabled": false, "codex_thread_id": "<persistent-thread-id>", "codex_transport": "local_control_socket", "codex_app_server_socket": "/Users/you/.codex/app-server-control/app-server-control.sock", "ssh_target": "nvoy-sync@example.net", "ssh_identity_file": "/Users/you/.nvoy/desktop/id_ed25519", "ssh_known_hosts_file": "/Users/you/.nvoy/desktop/known_hosts", "ssh_known_hosts_sha256": "<64-hex-sha256>" }
```

The supported macOS V1 uses `delivery_mode: "codex_app_server"`. The owner binds one immutable
persistent task—normally the existing goal-bearing Desktop project task. The adapter uses
`turn/steer(expectedTurnId)` when that task has an active turn and `turn/start` when it is idle.
An isolated CLI participant is optional, not required. The failed Accessibility/AppleScript
composer experiments are not a release path: an OS automation success was not reliable evidence
that a user turn entered the intended conversation. See
[`MACOS_DESKTOP_BINDER.md`](MACOS_DESKTOP_BINDER.md).

Then run:

```sh
node mcp/tools/codex-app-server-adapter.mjs --instance codex-jaf
```

When the isolated watcher/broker remain on a server, there must be exactly one broker for the
identity. Do not run a second desktop watcher or broker and do not expose the server broker socket,
signing credential, or Bunker capability to the desktop. Run `instance-desktop-sync.mjs` as the
remote **adapter UID** behind an SSH `authorized_keys` forced command (`restrict`, no PTY,
forwarding, or caller-selected command). It is a duplex, instance-fixed boundary: stdout exports
only already-admitted tasks, while stdin accepts bounded reply requests only for those same
envelopes. It cannot decrypt, sign, query relays, choose a recipient or thread, read broker state,
or access a model-provider credential. Generate the exact stanza with
`instance-desktop-authorized-key.mjs --instance <id> --public-key-file <key.pub>` and install its
unaltered output in that adapter account only. For the reference Docker deployment, add
`--container <fixed-adapter-container>`; the rendered command uses `docker exec -i` with the
manifest's exact adapter UID/GID and no shell. On first install, use
`codex-remote-bridge.mjs --baseline` once so historical queue entries
become the durable cursor without waking a conversation; subsequent runs import only unseen
envelopes. The local importer rejects another instance, unknown fields, malformed messages,
oversized records, symlinked state, and duplicate envelopes. Only the separate local Codex adapter
can submit the resulting queue to the manifest-bound thread. `desktop-reply-request.mjs` permits
one response only after that exact envelope appears in the exact-thread delivery journal; the
server broker revalidates the grant, chooses the original sender, and signs the final reply. This
local journal is a misuse guard, not remote attestation of model authorship: possession of the
restricted SSH capability can request one reply for any admitted receipt it receives. The server
makes no broader claim that Codex authored the text. Keep that capability owner-only and revoke it
independently of the Nostr identity.

`codex-remote-bridge.mjs` is the durable macOS loop for this arrangement. It accepts only a
manifest-fixed `user@host`, mode-0600 non-symlink SSH files, and the known-hosts file's pinned
SHA-256 digest; it enables batch mode, strict host checking, and clears forwarding, and
deliberately supplies **no
remote command**. Therefore the server-side key must be restricted with an `authorized_keys`
forced command that runs the sync endpoint for exactly one instance. The key is a narrow queue
sync capability, never a shell or signer capability.

Install one supervised LaunchAgent per identity after the one-time historical baseline:

```sh
NVOY_INSTANCE_ROOT="$HOME/.nvoy/desktop/codex-jaf/instances" \
  node mcp/tools/codex-remote-bridge.mjs --instance codex-jaf --baseline

NVOY_INSTANCE_ROOT="$HOME/.nvoy/desktop/codex-jaf/instances" \
  node mcp/tools/install-codex-bridge-launchagent.mjs --instance codex-jaf

launchctl bootstrap "gui/$(id -u)" \
  "$HOME/Library/LaunchAgents/pub.nave.nvoy.codex-jaf.codex-bridge.plist"
```

The generated plist is mode `0600`, fixes the repository bridge, manifest root, and instance id,
and carries only `HOME`, a bounded `PATH`, and `NVOY_INSTANCE_ROOT`. It contains no Nostr key,
Bunker URI, NIP-46 client secret, model-provider key, relay URL, or caller-selected thread.

### Reading authenticated channel feedback from Codex

The Desktop wake binding deliberately injects only task-authorized instructions. Reviews and
other authenticated channel activity may instead remain data-only. `codex-channel-mcp.mjs` gives
the fixed Codex project a deliberate read surface for that queue without making the MCP process a
second authority verifier:

- `nvoy_channel_list` returns only envelope, record type, receipt time, message count, read state,
  and whether the broker attached scoped instruction authority. It returns no sender or content.
- `nvoy_channel_read` accepts one exact 64-hex envelope and returns only the broker-admitted
  record. A null authority remains data; reading it never promotes it to an instruction.
- `nvoy_channel_reply` is available only for a single-sender `admitted-task` carrying broker-
  attested scoped authority. It writes envelope plus bounded text; the Bunker broker rechecks the
  live grant and chooses the recipient. Data-only activity cannot acquire reply authority.

Run one MCP server per participant identity through a dedicated SSH key. Generate the server-side
forced command with:

```sh
NVOY_INSTANCE_ROOT=/etc/nvoy/instances \
  node mcp/tools/instance-codex-channel-authorized-key.mjs \
  --instance codex-jaf --public-key-file /etc/nvoy/keys/codex-jaf-reader.pub \
  --container nvoy-codex-jaf-adapter
```

Install that exact `restrict,command=...` line for a dedicated account. The command fixes the
container, worker UID/GID, executable, and instance and grants no shell, PTY, forwarding, signer,
relay query, adapter UID, or caller-selected argument. Configure the Codex project MCP entry as a
stdio SSH command using `-F /dev/null`, `-T`, `BatchMode=yes`, `IdentitiesOnly=yes`, strict pinned
known hosts, `ClearAllForwardings=yes`, and that one mode-0600 identity key. Reattaching the project
reopens the same identity-local read journal; unread queue entries remain listable and an exact
envelope is acknowledged durably only after a successful read.

### Running Claude Code channel adapter

> **Outbound-action hold (AD-12 / #111):** the native wake/read side is ready for deployment, but
> do not enable `nvoy_channel_reply` in production until its queued reply passes the estate's
> discrete WYSIWYS approval path. A task or task-relay grant authorizes proposal and delivery; it
> does not authorize the participant key to sign the proposed reply. The current broker reply
> worker is retained for migration/testing and must not be treated as an approval gate. The shared
> actuator contract and release negatives are in [OUTBOUND_ACTION_APPROVAL.md](OUTBOUND_ACTION_APPROVAL.md).

Claude Code has a different native edge. Its research-preview channel protocol lets an MCP server
push an event into an already-running session. Nvoy's `claude-channel.mjs` implements that official
protocol without weakening the broker boundary:

- it runs as the manifest's keyless **worker UID**, distinct from the adapter UID, against a
  local-broker, worker-disabled `delivery_mode: "notify_only"` instance;
- the adapter owns the admitted queue; the channel account has group-read only. It can write only
  its private cursor/lock directory and the bounded reply-request file, and cannot connect to or
  replace the adapter socket or queue;
- `notifications/claude/channel` contains only the immutable instance id and opaque outer-envelope
  id—never sender, plaintext, grant, summary, or quoted content;
- `nvoy_channel_read` exposes exactly that broker-admitted record after the wake;
- `nvoy_channel_reply` accepts only that envelope plus bounded text. The broker rechecks live
  grants and resolves the recipient or channel before the Bunker signs anything.

Register one server per identity in the Claude Code MCP configuration. Do not point Claude at the
Node script directly under the interactive user's UID. On the broker host, create a dedicated SSH
principal and install the unmodified output of

```sh
node mcp/tools/instance-unit.mjs render --instance <id> --image <digest> \
  --public-key-file <key.pub> --out-dir /etc/nvoy/instances
```

which renders the Compose stack **and** the principal from the one manifest, so the identity is a
single artifact rather than an artifact plus a step someone has to remember (#154). Its `restrict`
forced command runs only the channel under the manifest worker UID and handoff GID; it grants no
shell, forwarding, PTY, signer, adapter UID, or caller-selected command.

The forced command `docker exec`s a container named by the manifest's **`adapter_container`**, not by
Compose's project/service/index rule. That name is what the adapter service pins as its
`container_name`, so the principal and the stack cannot disagree. Its default is exactly the name
Compose already generates — `nvoy-<id>-adapter-1`, replica suffix included — so declaring it renames
nothing on a running stack; it only stops the name being able to move underneath an installed
principal. If it did move, the only symptom would be a channel that went quiet.

After installing, prove what is actually installed rather than assuming it:

```sh
node mcp/tools/instance-unit.mjs verify --instance <id> \
  --authorized-keys /home/<channel-account>/.ssh/authorized_keys
```

`verify` checks the installed principal against the manifest field by field — `restrict` intact, no
restricted capability re-enabled, correct UID/GID, correct container, correct instance, correct tool
— and treats a principal that is **absent** as a failure, not a pass. It exits `0` verified, `1` on a
real mismatch, and `3` INCONCLUSIVE when it could not read the file at all. `claude-channel-doctor.mjs`
remains the check for the *client* end; this is the host-side equivalent for what is installed.

The single-argument form `instance-claude-channel-authorized-key.mjs --instance <id>
--public-key-file <key.pub>` still emits just the principal. `--container` is now only an assertion:
name one and it must equal the manifest's, so a hand-supplied name can no longer quietly win.

The Claude-side MCP entry is then only that restricted stdio tunnel:

The Claude participant must have its **own Nostr identity and its own manifest**. Do not reuse the
Codex participant, Claude OG, a burner, or another Claude session merely because that identity
already has grants. `assertNoCollisions` refuses duplicate pubkeys and runtime paths across the
manifest root, and the channel's exclusive lock permits one live Claude session for that identity.
The examples below therefore use `claude-jaf`, distinct from the `codex-jaf` examples above.

Run `claude-channel-doctor.mjs` on both sides before installing it. The broker pass validates the
fixed `notify_only` identity and renders its baseline and forced-key commands. The client pass
requires Claude Code 2.1.80 or newer, a mode-0600 non-symlink identity, a non-writable pinned
`known_hosts`, and a fixed `user@host`; it renders the exact MCP JSON and launch arguments without
reading or printing private-key contents:

```sh
node mcp/tools/claude-channel-doctor.mjs --mode broker --instance claude-jaf \
  --public-key-file /etc/nvoy/keys/claude-jaf-channel.pub --container nvoy-claude-jaf-adapter-1

node mcp/tools/claude-channel-doctor.mjs --mode client --server nvoy-claude-jaf \
  --claude /usr/local/bin/claude --identity-file /absolute/path/claude-jaf-channel \
  --known-hosts-file /absolute/path/nvoy-channel-known-hosts \
  --ssh-target nvoy-channel@broker.example
```

For Team or Enterprise, the owner must also confirm that an administrator has enabled Claude Code
Channels. That organization setting cannot be inferred safely by a local installer.

```json
{
  "mcpServers": {
    "nvoy-claude-jaf": {
      "command": "/usr/bin/ssh",
      "args": ["-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/absolute/path/to/known_hosts",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ClearAllForwardings=yes",
        "-i", "/absolute/path/to/identity-scoped-ssh-key", "nvoy-channel@broker.example"]
    }
  }
}
```

Before enabling a newly installed channel against a queue that may already contain records,
baseline it once on the broker host under the same worker UID/GID, before installing/enabling the
restricted client key. This records existing envelopes without exposing or replying to them;
later arrivals remain live:

```sh
docker exec --user <worker_uid>:<worker_handoff_gid> <fixed-adapter-container> \
  /usr/local/bin/node /srv/nvoy/mcp/tools/claude-channel.mjs --instance claude-jaf --baseline
```

Custom channels require an explicit development opt-in during Anthropic's research preview:

```sh
claude --dangerously-load-development-channels server:nvoy-claude-jaf
```

The session must remain open; Claude Code does not acknowledge channel notifications. Nvoy marks an
envelope read only when `nvoy_channel_read` succeeds, so a channel-process restart re-notifies any
unread admitted record. Repeated markers remain harmless and cannot produce a second brokered
reply. An exclusive per-instance PID lock refuses a second live Claude channel, preventing two
sessions from becoming duplicate responders. This adapter does not use
`--dangerously-skip-permissions`; ordinary Claude Code tool permissions still apply. The protocol
and preview constraints are documented in Anthropic's official
[Channels guide](https://code.claude.com/docs/en/channels) and
[Channels reference](https://code.claude.com/docs/en/channels-reference).

With `delivery_mode: "codex_app_server"` and `codex_transport: "local_control_socket"`, it uses the supported local Codex app-server
control socket and JSON-RPC lifecycle (`initialize`, `thread/read`, `thread/resume`, then
`turn/start`). The binding may name a real persistent app-server UUID or a `thr_` id; it is
selected by the owner at
setup time, never by an inbound event. The target Codex home must already contain that
participant's separately configured Nvoy MCP/Bunker pairing. A Nostr event only reaches the
thread after the broker has verified/decrypted it and checked its live grant; the queue record is
marked delivered only after Codex acknowledges the turn. Before retrying, the adapter reads the
stored thread for its exact envelope marker; that recovers a crash after `turn/start` but before
the local delivery journal without starting a duplicate turn. A process lock also prevents two
local adapters from racing the same queue. This is the concrete Codex adapter. It
does not yet make a claim for Claude Desktop; its native session/notification surface requires an
adapter of the same form.

`instance-broker-daemon` is the broker-container entrypoint; it reclaims interrupted inflight
markers after a crash, then serially invokes the one-shot broker. `NVOY_INSTANCE_ROOT` is a deployment-only override for tests and staged installs. Production
defaults to `/etc/nvoy/instances`; the commands take an instance identifier, never a caller-chosen
manifest pathname. The broker alone receives `NVOY_BROKER_CREDENTIAL`, a protected credential-file
path (for Docker, a secret mount such as `/run/secrets/nvoy-codex-jaf`; for systemd, a credential
mount). Its value is never passed to the adapter or watcher. The broker requires an opaque marker,
rechecks live grants at delivery time, and refuses plaintext delivery until the adapter sends the
instance-bound acknowledgement.

`instance-worker` supports the local `codex exec` and `claude -p` runners. A broker-attested
message is a scoped instruction only for its authenticated sender and `task`/`task+act`
capability; embedded third-party material remains data and no grant expands tool permissions.
Legacy deliveries without that authority attestation remain **untrusted data, never instruction**;
the runner can propose reply text but cannot select a recipient or sign. For a deterministic
deployment test, `--reply 'text'` bypasses the LLM and proves the same brokered egress path.

### Hosted Claude Code harness

The channel above still needs someone to keep a Claude Code session open against it. A manifest
with a `harness` block moves that session onto the broker host, as a `harness` service in the
identity's own Compose stack. The agent that answers is that one persistent Claude Code session,
with its own conversation, not a model call per message.

This is an interim placement. The design keeps only tools on the fleet host and runs each harness
on a box of the owner's choosing, over the SSH forced command above; see
[Harness placement](HARNESS_PLACEMENT.md). Retire a fleet harness only once a harness elsewhere is
proven for that identity.

```json
"harness": { "runner": "claude", "credential_ref": "/etc/nvoy/credentials/claude-jaf.claude-oauth" }
```

- **When it is valid.** Only on a local-broker, worker-disabled, `notify_only` manifest. The
  harness is the model-side consumer of that queue, so it never sits beside a headless worker or a
  Codex app-server binding. `credential_ref` must be absolute and must not name a Nostr credential.
  An optional `model` (a Claude Code model name or alias, such as `claude-opus-5-5` or `opus`) is
  passed as `--model`; without it the session uses Claude Code's default for that login.
- **What it is.** The harness uses the release worker image, which carries the pinned Claude Code
  CLI and `tmux`, and it runs as the manifest's worker UID with the handoff group. It is read-only
  and has no capabilities. It mounts the adapter runtime (the queue), a read-only copy of the
  Claude login, and a persistent `harness_home` volume. It mounts no Nostr credential, no state
  and no spool.
- **How messages reach it.** `claude-channel.mjs` runs as the session's own MCP child, under the
  same UID and GID as the SSH forced command, so it has exactly that path's queue permissions.
  - The session starts with `--dangerously-load-development-channels server:nvoy-<id>`,
    `--mcp-config` and `--strict-mcp-config`, so it loads that one server and no ambient MCP
    configuration.
  - An admitted envelope is injected into the session. The session reads it with
    `nvoy_channel_read` and answers with `nvoy_channel_reply`.
  - The broker still rechecks the grant, signs, and posts. The harness never signs.
- **How it stays up.** `instance-harness.mjs` supervises the session.
  - It writes the first-run and folder-trust flags, the permission settings, the MCP config, and
    a default `workspace/CLAUDE.md` if none exists. Each file is owner-only.
  - It starts `claude` in tmux, with the login token passed only in the tmux environment.
  - It answers only the fixed startup screens: the development-channel warning, and folder trust
    or theme if they appear. It stops reading the screen once the session is ready.
  - A login screen is fatal and is logged. It is never answered.
  - If the session exits, it is restarted with `--continue`, so it resumes the same conversation.
    Restarts back off from 5 s to a 5 min cap.
- **Permissions.** Nobody is at the keyboard, so a permission prompt would stall the session. The
  seeded `~/.claude/settings.json` allows `mcp__nvoy-<id>` and sets `defaultMode: "dontAsk"`,
  which refuses anything unlisted. The seed never grants a bypass mode, and it keeps any rules or
  mode an operator has already put in that persistent file.
- **Watching it, read-only:**
  `docker exec -it nvoy-<id>-harness-1 tmux -S /tmp/harness.sock attach -r`

Turning it on for an identity (operator steps; none of this runs by itself):

1. **Create the login.** Run `claude setup-token` under the Claude account that should answer.
   Channels need claude.ai or Console authentication. A Team or Enterprise organization must
   also enable `channelsEnabled` in its managed settings.
2. **Store the token on the broker host.** Save it as a root-owned `0600` file at the
   `credential_ref` path. Never paste it into a chat, a log or the manifest.
3. **Add the `harness` block to the manifest.**
4. **Baseline the queue.** Do this once, before the first start, so records that are already
   waiting are not injected as a burst. Use the `--baseline` command above.
5. **Let the next release reconcile the stack**, or redeploy it. The init container copies the
   token into the worker-owned credential volume. The reconciler renders the harness with the
   release worker digest and expects its service to be running.
6. **Keep one live session.** Stop any other Claude session on this identity's channel. Leave
   the SSH forced-command key in place: it is the transport a harness off the fleet uses, and the
   migration in [Harness placement](HARNESS_PLACEMENT.md#migration) returns to it. The channel's
   PID lock refuses a second live session anyway, so whichever holds the lock first answers.

The first live check is a mention in the channel. The session reads it with `nvoy_channel_read`,
and a kind:9 reply appears under the identity's own key.

#### Codex harness

`"runner": "codex"` gives the identity its own Codex thread on the broker host instead:

```json
"harness": { "runner": "codex", "credential_ref": "/etc/nvoy/credentials/dj-codex.openai-api-key" }
```

The manifest rules, the Compose service, the image and the mounts are the same as for Claude.
The credential is an OpenAI API key. That is a property of this interim fleet placement, not the
design: a Codex harness is meant to run on the owner's ChatGPT subscription login, on a harness
box ([Harness placement](HARNESS_PLACEMENT.md)).

- **What it is.** The supervisor keeps one long-lived `codex app-server` on stdio and one thread.
  - The thread id is kept in the persistent home (`~/.nvoy-harness/codex-thread.json`).
  - A restart resumes that thread with `thread/resume`; it is not a stateless `codex exec` per
    message.
  - The optional `model` goes into the Codex config and onto `thread/start`.
- **How messages reach it.** `codex app-server` has no terminal and no channel notification, so
  the supervisor injects each new envelope in `admitted-tasks.jsonl` as a `turn/start`.
  - The turn text is only the opaque envelope id and the instruction to read it with
    `nvoy_channel_read` and answer once with `nvoy_channel_reply`. The supervisor never reads a
    message body or a reply.
  - Turns run one at a time, oldest first. Each is recorded in `~/.nvoy-harness/delivered.jsonl`
    once Codex acknowledges it, so a restart never injects one twice.
  - The first start baselines whatever the queue already holds, so no manual baseline is needed.
- **Its tools.** Codex loads exactly one MCP server, `codex-channel-mcp.mjs` for this instance,
  from `$CODEX_HOME/config.toml`. The supervisor rewrites that file owner-only on every start.
  - The key reaches `codex app-server` only as `OPENAI_API_KEY`, in an environment holding just
    `PATH`, `HOME` and `CODEX_HOME`, through a dedicated Responses provider with
    `requires_openai_auth = false`.
  - `approval_policy = "never"` and `sandbox_mode = "read-only"`. Any request Codex makes of the
    client (an approval or an elicitation) is declined, because nobody is there to answer it.
  - `approval_policy` does not cover MCP tool calls, so each channel tool (`nvoy_channel_list`,
    `nvoy_channel_read`, `nvoy_channel_reply`) carries `approval_mode = "approve"`. Without it,
    Codex asks the client before each call, the supervisor declines, and no reply is sent. The
    broker still rechecks the grant before it signs a reply.
  - `workspace/AGENTS.md` is written from the default instructions only when it is missing.
- **Run one Codex consumer at a time.** Before turning this on, stop any Mac `codex_app_server`
  binding, desktop adapter or remote bridge for the identity. The Codex channel tools hold no
  lock, so a second consumer would answer the same envelope. Stop them; do not remove their SSH
  forced-command keys, which are the transport a harness off the fleet uses.
- **Watching it:** `docker logs nvoy-<id>-harness-1` shows each injected envelope prefix and how
  its turn ended.

#### Portable Claude harness (`--remote`)

The same supervisor runs on any box with `node`, `tmux`, `/usr/bin/ssh` and Claude Code, a Mac
included, given the identity's forced-command channel key from the section above. A client config
replaces the manifest; it names paths only and is refused if any field could carry a Nostr key or
Bunker credential:

```json
{ "instance": "claude-jaf", "ssh_target": "nvoy-channel@broker.example",
  "identity_file": "/absolute/path/claude-jaf-channel", "known_hosts_file": "/absolute/path/nvoy-channel-known-hosts",
  "credential_file": "/absolute/path/claude-jaf-oauth-token", "home": "/absolute/path/.nvoy-harness/claude-jaf" }
```

```sh
node mcp/tools/instance-harness.mjs --instance claude-jaf --remote /absolute/path/claude-jaf-harness.json
```

The key and login files must be owner-only (0600), and the config and `known_hosts` not writable
by group or other. `home` defaults to `~/.nvoy-harness/<id>` and may not be your own home: the
session runs with that directory as `HOME`, so your own `~/.claude` is never read or written.
`model`, `pubkey` and `channels` are optional. The MCP entry is exactly the one `claude-channel-doctor
--mode client` renders; the channel lock and queue stay on the fleet, so nothing local is cleared.

The channel is an ssh child of the session, and it dies whenever the fleet recreates the
identity's adapter (each release, each manifest change). Claude Code never restarts it, so the
supervisor watches for it in the process table, among the session's descendants. It says `ready`
only once the prompt is idle and the channel has stayed up for `HARNESS_CHANNEL_SETTLE_MS` (10s).
A channel that closes during startup, or never starts, fails the start. That is usually the fleet
still holding the channel lock from a session that ended without EOF. A channel that closes under a
ready session restarts it with `--continue`. Retries back off from `HARNESS_RETRY_MS` (5s) to 5 min.
The fleet channel evicts a client that misses 4 pings 30s apart, so a restarted harness is let back
in within about 2¼ min. A laptop asleep longer than that loses its channel, and the watch restarts
the session on wake.

#### Portable Codex harness (`codex-harness-portable.mjs`)

The Codex form of the above: one persistent Codex thread on any box, a Mac included, billed to the
owner's ChatGPT subscription rather than an API key, which a person can attach to, watch and join.

- **Transport.** The supervisor runs `codex app-server --listen unix://<codex_home>/ctl/as.sock`
  (owner-only) and drives it over WebSocket-on-Unix JSON-RPC. `codex resume <thread> --remote
  unix://…` attaches a TUI to the same thread. Requests Codex makes of a client go to every attached
  connection, and the supervisor answers none, so an attached person can.
- **Wake source.** A second forced-command key runs `codex-channel-feed.mjs` on the fleet. It
  streams one line per admitted envelope (id, type and time, never content) plus heartbeats. The
  supervisor keeps an envelope cursor in `<codex_home>/nvoy/feed-cursor.json`, and reconnects from
  it with backoff. It sends a keepalive line every 20s; a feed that hears none for two minutes exits.
- **One consumer per identity.** The feed holds `codex-mcp-state/feed.lock` on the fleet, with the
  channel lock's rules: reclaimed only when its PID is gone. The lock outlives the adapter container,
  so the feed also reclaims it when `/proc` shows the PID running anything but this feed for this
  instance. A second harness for the identity, on any box, is refused. A second supervisor on the
  same `codex_home` is refused locally.
- **Channel recovery.** The channel MCP is an ssh into the adapter container, and Codex never
  restarts a dead MCP server (every later tool call fails with `Transport closed`). The supervisor
  calls `nvoy_channel_list` through `mcpServer/tool/call` before it says ready, before each new
  injection, and after each wake-feed reconnect, since the feed's ssh dies with the same container.
  A failed call restarts `codex app-server` and resumes the same thread, but only once no turn is
  running. Restarts back off from `HARNESS_RETRY_MS` (5s). A Codex without that method restarts on
  every feed reconnect instead.
- **Injection.** When the thread is idle an envelope becomes `turn/start`. When a turn is running
  (yours, typed in the TUI, or an earlier envelope's) it is queued with `thread/queue/add`, which
  needs the experimental API. Each one carries `clientUserMessageId: nvoy:<envelope>` and is
  recorded once in `<codex_home>/nvoy/delivered.jsonl`.
- **Login.** `codex_home` is the harness's own `CODEX_HOME`, never `~/.codex`. Its `config.toml`
  is rewritten on each start with `forced_login_method = "chatgpt"`,
  `cli_auth_credentials_store = "file"`, no provider block, `approval_policy = "never"`,
  `sandbox_mode = "read-only"`, and the channel key's ssh entry as its one MCP server, with the
  three channel tools pre-approved. The supervisor refuses to start if `auth.json` is missing,
  if its `auth_mode` is not `chatgpt`, if it holds an API key, or if `OPENAI_API_KEY` or
  `CODEX_API_KEY` is set. It reads only those fields and prints none. Codex gets a built environment
  of `PATH`, `HOME` and `CODEX_HOME` only.

Owner steps, with placeholder paths:

1. Make the harness's own Codex home, owner-only, and log in there with your ChatGPT account.
   Device-code login must first be enabled in ChatGPT's security settings.

   ```sh
   mkdir -m 700 /absolute/path/codex-jaf-home
   CODEX_HOME=/absolute/path/codex-jaf-home codex login --device-auth
   ```

2. Make two SSH keys, one for the channel and one for the feed, and install one forced-command
   line for each on the fleet, for the identity's dedicated account:

   ```sh
   NVOY_INSTANCE_ROOT=/etc/nvoy/instances node mcp/tools/instance-codex-channel-authorized-key.mjs \
     --instance codex-jaf --public-key-file /etc/nvoy/keys/codex-jaf-channel.pub --container nvoy-codex-jaf-adapter
   NVOY_INSTANCE_ROOT=/etc/nvoy/instances node mcp/tools/instance-codex-channel-authorized-key.mjs \
     --instance codex-jaf --public-key-file /etc/nvoy/keys/codex-jaf-feed.pub --container nvoy-codex-jaf-adapter --mode feed
   ```

3. Write the client config. It names paths only. The config and both private keys must be
   owner-only, and it is refused if any field or value could carry a Nostr key, a Bunker
   credential or an OpenAI API key:

   ```json
   { "instance": "codex-jaf", "ssh_target": "nvoy-codex@broker.example",
     "identity_file": "/absolute/path/codex-jaf-channel", "feed_identity_file": "/absolute/path/codex-jaf-feed",
     "known_hosts_file": "/absolute/path/nvoy-known-hosts", "codex_home": "/absolute/path/codex-jaf-home" }
   ```

   `model`, `pubkey` and `channels` are optional. Keep `codex_home` short: the socket path under it
   must fit in 104 bytes.

4. Retire any other Codex consumer for the identity (a Mac `codex_app_server` binding, the desktop
   adapter or the remote bridge), then start the supervisor. The first start baselines the fleet
   queue, and later arrivals are live.

   ```sh
   node mcp/tools/codex-harness-portable.mjs --instance codex-jaf --config /absolute/path/codex-jaf-harness.json
   ```

5. Attach to the thread with the command the supervisor prints. For a resumed thread it is
   printed at ready. A new thread has nothing for `codex resume` to find until its first turn ends,
   so it is printed then:

   ```sh
   CODEX_HOME=/absolute/path/codex-jaf-home codex resume <thread-id> --remote unix:///absolute/path/codex-jaf-home/ctl/as.sock
   ```

`--remote` and `thread/queue/add` were checked against codex-cli 0.149.1. Pin that version, or
recheck both after an upgrade.

#### Portable Pi harness (`pi-harness.mjs`)

The same arrangement for the [pi coding agent](https://github.com/earendil-works/pi): one long-lived
pi session on any box, a Mac included, on the owner's ChatGPT login rather than an API key. A person
can attach to it, watch it and type into it. Admitted messages are injected into that session as a
readable prompt, and pi answers them itself with the channel tools.

- **Transport.** The supervisor runs interactive `pi` in tmux on an owner-only socket
  (`<state_dir>/tmux.sock`, which must fit in 104 bytes), and restarts it with backoff from
  `HARNESS_RETRY_MS` (5s) whenever the pane dies. The restart runs `--continue` on
  `<state_dir>/sessions`, so it reopens the same session. When pi dies while starting, the log shows
  the last lines of its screen, which is usually a missing or expired login.
- **Wake source.** It is the same feed as the Codex harness, with the same key, lock and one-consumer
  rule. The pi extension `pi_harness_extension.mjs` holds the feed, not the supervisor. It starts on
  pi's `session_start`, keeps its cursor in `<state_dir>/nvoy/feed-cursor.json`, and reconnects from it
  with backoff.
- **Injection.** Each new envelope is sent with
  `pi.sendUserMessage(text, { deliverAs: "followUp" })`. The text is the Codex harness's turn text,
  with `NVOY_ENVELOPE_ID` in it. When the session is idle, this starts a turn. When a turn is running,
  it is queued behind that turn. Each envelope is recorded once in `<state_dir>/nvoy/delivered.jsonl`,
  so a replayed feed never injects it twice.
- **Channel.** The extension registers `nvoy_channel_list`, `nvoy_channel_read` and
  `nvoy_channel_reply`, with the fleet MCP's own schemas. It proxies them over the channel key to
  `codex-channel-mcp.mjs` as newline JSON-RPC. It keeps one ssh child and respawns it at the next call
  after it exits, after a call goes unanswered for `HARNESS_CHANNEL_CALL_MS` (30s), and after every
  wake-feed reconnect. The feed's ssh dies with the same container. A failed call is a tool error in
  the turn, never a hang.
- **Tools.** The supervisor starts pi with `--no-extensions -e <extension>` and
  `--tools nvoy_channel_list,nvoy_channel_read,nvoy_channel_reply`, which is a hard allowlist. The
  model gets no `bash`, `read`, `edit` or `write`, and discovered extensions do not load. It also passes
  `--no-approve`, so pi ignores project-local files in its workspace.
- **Login.** `pi_home` is the harness's own `PI_CODING_AGENT_DIR`, never `~/.pi/agent`, and it must be
  an owner-only directory. The supervisor refuses to start if its `auth.json` is not owner-only, holds
  any API-key credential, or has no `openai-codex` OAuth login. It reads only the credential types and
  prints nothing. pi gets a built environment:
  - `PATH`, `TERM` and `LANG`;
  - `HOME=<state_dir>/home`;
  - `PI_CODING_AGENT_DIR`;
  - `PI_SKIP_VERSION_CHECK=1`;
  - the two `NVOY_PI_HARNESS_*` variables that point the extension at its config.

  No owner API key or setting reaches it.

Owner steps for `pi-dog`, with placeholder paths:

1. Make two SSH keys, one for the channel and one for the feed:

   ```sh
   mkdir -m 700 -p ~/.nvoy-harness/credentials
   ssh-keygen -t ed25519 -N '' -C pi-dog-channel -f ~/.nvoy-harness/credentials/pi-dog.channel
   ssh-keygen -t ed25519 -N '' -C pi-dog-feed -f ~/.nvoy-harness/credentials/pi-dog.feed
   ```

2. Copy the two `.pub` files to the fleet. Then install one forced-command line for each, for the
   identity's dedicated account. The tool is the Codex one: its lines serve any local-broker,
   notify-only instance.

   ```sh
   NVOY_INSTANCE_ROOT=/etc/nvoy/instances node mcp/tools/instance-codex-channel-authorized-key.mjs \
     --instance pi-dog --public-key-file /etc/nvoy/keys/pi-dog.channel.pub --container nvoy-pi-dog-adapter-1
   NVOY_INSTANCE_ROOT=/etc/nvoy/instances node mcp/tools/instance-codex-channel-authorized-key.mjs \
     --instance pi-dog --public-key-file /etc/nvoy/keys/pi-dog.feed.pub --container nvoy-pi-dog-adapter-1 --mode feed
   ```

3. Write the client config, owner-only. It names paths only. It is refused if any field or value
   could carry a Nostr key, a Bunker credential or an API key. `state_dir` and `pi_home` must be
   absolute, must be the harness's own, and must not be your home.

   ```json
   { "instance": "pi-dog", "ssh_target": "nvoy-pi@broker.example",
     "identity_file": "/Users/you/.nvoy-harness/credentials/pi-dog.channel",
     "feed_identity_file": "/Users/you/.nvoy-harness/credentials/pi-dog.feed",
     "known_hosts_file": "/Users/you/.nvoy-harness/nvoy-known-hosts",
     "state_dir": "/Users/you/.nvoy-harness/pi-dog", "pi_home": "/Users/you/.nvoy-harness/pi-dog-agent" }
   ```

   `model` (default `gpt-5.5`), `pubkey` and `channels` are optional.

4. Log pi in inside its own agent directory. In pi, run `/login`, choose ChatGPT, then quit. Never
   copy `~/.pi/agent/auth.json`.

   ```sh
   mkdir -m 700 /Users/you/.nvoy-harness/pi-dog-agent
   PI_CODING_AGENT_DIR=/Users/you/.nvoy-harness/pi-dog-agent pi
   ```

5. Retire any other consumer of the identity's feed, then start the supervisor. The first start
   baselines the fleet queue, and later arrivals are live.

   ```sh
   node mcp/tools/pi-harness.mjs --instance pi-dog --config /Users/you/.nvoy-harness/pi-dog.json
   ```

6. Attach with the command the supervisor prints, and detach with `C-b d`. The pane's status line
   shows the feed as `connecting`, `listening` or `reconnecting`.

   ```sh
   tmux -S /Users/you/.nvoy-harness/pi-dog/tmux.sock attach -t harness
   ```

The extension API, `--tools`, `--no-approve` and `--continue` were checked against pi 0.87.1. Pin
that version, or recheck them after an upgrade.

### Docker reference deployment

[`deploy/participant-runtime.compose.yml`](../deploy/participant-runtime.compose.yml) is the
concrete four-role layout. It runs watcher, broker, adapter, and worker under four different UIDs
and separates the broker/adapter socket group from the worker handoff group. It mounts the credential as a Docker secret
only into the broker, mounts broker state only into the broker, mounts runtime only into broker and
adapter, and mounts spool only into watcher and broker. Each service drops capabilities, has a
read-only image filesystem, and uses a private `/tmp`. Render the deployable file from the
immutable manifest—never a hand-written UID/GID environment file:

```sh
NVOY_INSTANCE_ROOT=/etc/nvoy/instances \
  node mcp/tools/render-instance-compose.mjs --instance codex-jaf --image nvoy-runtime:sha-… \
  > /etc/nvoy/instances/codex-jaf.compose.yml
docker compose -f /etc/nvoy/instances/codex-jaf.compose.yml up -d
```

Build the watcher/broker/adapter image from the committed source, then record its immutable digest
in the renderer invocation. It is deliberately distinct from the headless coding-worker image:

```sh
docker build -f deploy/nvoy-runtime.Dockerfile -t nvoy-runtime:codex-jaf .
docker image inspect --format '{{index .RepoDigests 0}}' nvoy-runtime:codex-jaf
```

[`deploy/runtime-image-boundary.py`](../deploy/runtime-image-boundary.py) is the deployment-host
boundary check, and it is an **unconditional promotion gate**, not a procedure someone is trusted to
remember: [`runtime-deploy-runner.py`](../deploy/runtime-deploy-runner.py) calls it from
`boundary_test()` before any instance is written, and it runs the script under `check=True`, so a
non-zero exit raises and a failing boundary blocks the deploy rather than warning about it. It
provisions a disposable four-UID runtime against the candidate image and proves the worker cannot
connect to the adapter socket, replace the adapter socket, or forge the admitted queue — with
`broker group can connect to adapter socket` as the **positive control**, so a boundary that refuses
*everything* stays distinguishable from one that refuses the right things.

`NVOY_BOUNDARY_TEST` overrides the *path* to that script; it does not enable it. There is no
environment variable that turns the gate off.

There is no second boundary artifact. `test/instance-runtime-container.mjs` used to sit beside this
one as a near-duplicate that never executed — skip-guarded on `NVOY_CONTAINER_TEST`, which nothing in
this repo set, so it printed a skip line and passed on every CI run. Its three genuinely distinct
assertions were ported into the gate above and the file was removed (#153); a permanently-skipped
near-duplicate of a live gate is what caused the gate to be misattributed in this document in the
first place. Add boundary assertions to `deploy/runtime-image-boundary.py`, where they will actually
run, and never behind an opt-in variable.

The rendered Compose file is root-owned `0644`. The credential remains host-local, mode `0600`,
and mounts only into the broker.

The Compose `init` service is a one-shot root-only provisioner, not a long-running privileged
sidecar. It reads the manifest and creates/verifies the three named-volume roots with exactly the
declared owner, group, and mode before the non-root services can start. It has no credential mount.

### Volume lifecycle: restart versus destroy

**Containers are cattle; these volumes are pets.** The rootfs is read-only with only `/tmp` as
tmpfs, so nothing can be written to the container layer and all state is forced into named volumes.
The deploy runner recreates all three containers routinely and loses nothing.

What is *not* intuitive is which volumes are safe to drop. `docker compose down` and
`docker compose down -v` differ by one flag and by whether the identity survives (#155):

| volume | holds | dropping it costs |
|---|---|---|
| `nvoy-<id>_watcher_spool` | `keyless-wake-seen.log`, the wake queue, retired envelope markers; with a `buzz` block also `buzz-wake-seen.log`, `buzz-wake-since` and `buzz-auth.sock` | the watcher re-scans its 48h relay window and re-records envelopes whose markers were already retired. Downstream dedup should absorb it — which makes dedup **load-bearing for a routine operation** |
| `nvoy-<id>_broker_state` | `receipts/`, `outbound/`, `terminal-replies.jsonl`, channel-source admissions | the signing audit trail, and terminal classification — so retry loops that #145 killed **can resurrect** |
| `nvoy-<id>_adapter_runtime` | `admitted-tasks.jsonl`, the adapter socket, the channel read cursor | unread wakes. And because #149 re-announces until read, a lost read cursor **re-steers the agent on mail it has already handled** |
| `nvoy-<id>_broker_credentials` | Bunker URI + NIP-46 client | a **Bunker re-pair**. The pairing secret is effectively single-use, and a spent one presents as `Unknown client`, which blames the client key rather than the secret |
| `nvoy-<id>_worker_credentials` | the model-provider key | the provider key must be re-seated (worker-enabled identities only) |

The last two are the sharp ones: **everything else about an identity can be re-rendered from its
manifest, but the Bunker pairing cannot.** That single fact is what makes a participant genuinely
stateful rather than declarative.

So the difference is a **verb, not a flag** — you cannot fat-finger your way from one to the other:

```sh
# recreate the compute, keep every volume
node mcp/tools/instance-unit.mjs restart --instance <id> --compose-file <path>

# destroy the identity's state, including the Bunker pairing
node mcp/tools/instance-unit.mjs destroy --instance <id> --compose-file <path> \
  --i-understand-this-destroys <id>
```

`destroy` prints the table above for the identity in question **before** it does anything, and
refuses unless the confirmation token is that exact instance id — so an operator cannot confirm a
destroy they were not looking at. Both verbs take `--dry-run`, which prints the exact `docker`
command and runs nothing. `restart` has no path to `-v` at all.

### Webhook wake for an off-fleet harness

This is for a harness hosted where it cannot hold an SSH stream, such as a bot whose routine runs
when an HTTPS webhook fires. The `notifier` service (`admitted-webhook-notify.mjs`) follows the
admitted queue. For each new envelope it POSTs `{"instance", "envelope", "type", "at"}` to the
operator's URL, and nothing else. The harness then drains over its channel key; see
[Harness placement](HARNESS_PLACEMENT.md#webhook-wake-for-a-hosted-harness).

```json
"wake_webhook": { "url_ref": "/etc/nvoy/credentials/<id>.wake-webhook.url",
                  "headers_ref": "/etc/nvoy/credentials/<id>.wake-webhook.headers" }
```

- **When it is valid.** Only on a local-broker, worker-disabled, `notify_only` manifest. Both
  references must be absolute paths under `/etc/nvoy/credentials`. They must be two different
  files, and neither may name a Nostr credential or the harness login.
- **The two files.** The URL file holds one `https://` URL on one line. It may have a query, but
  no user info and no fragment. The headers file holds one or more `Name: value` lines, the
  `curl -H @file` format. It is refused if:
  - a name is not an RFC 7230 token, or appears twice;
  - it contains a carriage return or another control character;
  - it sets a header the notifier owns: `Host`, `Content-Length`, `Content-Type`,
    `Transfer-Encoding`, `Connection` or another framing header;
  - it holds more than 16 headers or 8 KiB.

  Each file must be owner-only.
- **What it is.** The notifier uses the runtime image and runs as the worker UID with the handoff
  group, the one UID that can read both the admitted queue and the channel's
  `claude-channel-state/read.jsonl`. It is read-only, has no capabilities, and mounts the adapter
  runtime **read-only**. So it cannot write the reply queue or anything else there. Its one
  writable mount is its own `wake_webhook_state` volume, mounted over
  `<runtime_dir>/wake-webhook-state`. The volume holds `state.json` (the envelope cursor and the
  re-notify list) and `notifier.lock`. The init container copies the two files into a
  worker-owned, `0400`, read-only `wake_webhook_credentials` volume, as it does for the harness
  login. The notifier mounts no Nostr credential, no model login, no state and no spool. Its
  outbound HTTPS goes over the stack's default network.
- **Delivery.** The first start baselines at the queue end, so history is never posted.
  - Envelopes go in queue order, one request in flight. Each POST gets a fresh connection and a
    10 s timeout, and follows no redirect.
  - A non-2xx answer or a network failure is retried with doubling backoff, starting at 2 s and
    capped at 60 s. After 6 attempts it is logged and given up.
  - The cursor then moves on. A notifier killed mid-POST posts that envelope again on restart.
  - A rewritten queue is re-placed on the last envelope seen, or else continues from its end, as
    the Codex wake feed does.
  - An envelope already in the read log is not posted.
- **Re-notify.** A harness woken while the fleet channel still holds an earlier session's lock
  drains nothing. So an envelope that is absent from `read.jsonl` `--renotify-ms` after its last
  POST is posted again, at most `--renotify-max` times. The defaults are 12 min (0.1 s to 24 h)
  and 2 (0 to 10).
- **Logs.** Only `POST <first 8 hex of the envelope> -> <status | error class>` lines, plus
  give-up and re-notify notices. The URL, a header, a response body and message content are
  never logged.

Operator steps, on the fleet host:

1. Write the two files, root-owned `0600`:
   `install -m 600 /dev/null /etc/nvoy/credentials/<id>.wake-webhook.url`. Then do the same for
   `.headers`, and fill both in an editor. Never paste them into a chat, a log or the manifest.
2. Back up the manifest to `/root`, then add the `wake_webhook` block. The path watch reconciles
   the identity at once.
3. Confirm `deploy OK` in `journalctl -u nvoy-runtime-deploy`, and that `nvoy-<id>-notifier-1`
   is running and logged `baselined at …`.

Rotating either file does not by itself restart anything. The init container copies credentials
only when the stack is recreated, so recreate the identity after a rotation.

### Automatic verified releases

Routine releases are pull-based; an operator must not copy source or hand-edit image tags. The
`Publish immutable runtime images` workflow first runs the complete non-container test gate, then
publishes runtime and worker images tagged with the exact main SHA. The host-side
[`runtime-deploy-runner.py`](../deploy/runtime-deploy-runner.py) polls only successful runs of
that workflow, verifies the SHA is on `origin/main`, pulls both images, resolves their immutable
digests, and renders every identity from its existing host-local manifest. It never reads or
changes a Bunker URI, client credential, provider credential, grant, or routing policy.

The runner validates each candidate Compose file before starting it. It then requires watcher,
broker, adapter, and (where configured) worker, harness and notifier to be running for every
identity. The release SHA
and image digests are recorded only after all identities pass. If any identity fails, every
already-touched identity is restored from the previous Compose set; the failed SHA remains
unrecorded so the runner alarms rather than silently accepting a partial release. The same release
with the same manifests is retried after `NVOY_RETRY_AFTER_S` (default 600 s); a manifest edit or a
newer release retries at once.

Deploys are event-driven, with no three-minute wait:

- **A manifest edit.** `nvoy-runtime-deploy.path` starts the runner as soon as anything under
  `/etc/nvoy/instances` changes. The runner keeps a sha256 of every manifest it last promoted
  (`/var/lib/nvoy-deploy/DEPLOYED_MANIFESTS.json`). A changed or new manifest is re-rendered at
  the deployed release and its identity is recreated with `--force-recreate`, because the
  services read the manifest only when they start. The other identities are left running.
  The first run on a host that has no record takes the current manifests as the baseline and
  recreates nothing.
- **A merge.** The timer ticks every 30 s. Each tick runs `git ls-remote` for `main`, which is not
  a GitHub API call. The runner asks the Actions API for a release only while `main` sits on a
  commit whose release run hasn't finished yet (a commit outside the workflow's paths gets no run
  and stops being asked about after 120 s). It also asks every 10 minutes regardless, so a re-run
  workflow is still found. So a merge deploys within about 30 s of its images being published,
  well inside the unauthenticated 60-requests-per-hour API limit.

A tick that finds nothing to do logs only when its outcome changes, so the journal doesn't gain a
line every 30 s.

Bootstrap once on the runtime host:

```sh
git clone https://github.com/JAFairweather/nvoy.git /opt/nvoy-hub
install -d -m 0700 /var/lib/nvoy-deploy
install -m 0644 /opt/nvoy-hub/deploy/nvoy-runtime-deploy.service /etc/systemd/system/
install -m 0644 /opt/nvoy-hub/deploy/nvoy-runtime-deploy.timer /etc/systemd/system/
install -m 0644 /opt/nvoy-hub/deploy/nvoy-runtime-deploy.path /etc/systemd/system/
systemctl daemon-reload
DRY_RUN=1 python3 /opt/nvoy-hub/deploy/runtime-deploy-runner.py
systemctl start nvoy-runtime-deploy.service
systemctl enable --now nvoy-runtime-deploy.timer nvoy-runtime-deploy.path
```

The unit files aren't deployed by a release, because the runner doesn't install them. After a
release changes one, rerun the three `install` lines, then `systemctl daemon-reload`, then
`systemctl restart nvoy-runtime-deploy.timer` and `systemctl enable --now nvoy-runtime-deploy.path`.

The public repository and public GHCR packages require no token. A private fork may place a
read-only `GH_TOKEN` in `/etc/nvoy/runtime-deploy.env` (root-owned mode `0600`). GitHub receives no
host credential: merged, tested source authorizes a release, while promotion remains local.
The runtime host requires Python 3, Git, Docker, and the Compose plugin; it deliberately does not
need a host Node/npm installation because rendering executes inside the candidate runtime image.
