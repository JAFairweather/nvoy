# Supervised participant runtimes

This is the implementation contract for Nvoy #44. A participant is not a
configuration convention: it is one immutable identity, one supervised runtime, and one
separate security domain. This applies equally to Claude and Codex workers.

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

For V1 visible delivery into an already-open Codex Desktop chat, use `delivery_mode:
"macos_desktop"` and additionally fix `codex_app_bundle_id: "com.openai.codex"`,
`codex_project_label`, `codex_chat_label`, and the absolute installed `codex_ui_driver` path.
The local adapter uses Accessibility only for visible submission; App Server is read-only and
observes the resulting Desktop-owned turn by its receipt marker. See
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

`codex-remote-bridge.mjs` is the durable desktop loop for this arrangement. It accepts only a
manifest-fixed `user@host`, mode-0600 non-symlink SSH files, and the known-hosts file's pinned
SHA-256 digest; it enables batch mode, strict host checking, and clears forwarding, and
deliberately supplies **no
remote command**. Therefore the server-side key must be restricted with an `authorized_keys`
forced command that runs the sync endpoint for exactly one instance. The key is a narrow queue
sync capability, never a shell or signer capability.

### Running Claude Code channel adapter

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
`instance-claude-channel-authorized-key.mjs --instance <id> --public-key-file <key.pub>
--container <fixed-adapter-container>`. Its `restrict` forced command runs only the channel under
the manifest worker UID and handoff GID; it grants no shell, forwarding, PTY, signer, adapter UID,
or caller-selected command. The Claude-side MCP entry is then only that restricted stdio tunnel:

```json
{
  "mcpServers": {
    "nvoy-codex-jaf": {
      "command": "/usr/bin/ssh",
      "args": ["-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes",
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
  /usr/local/bin/node /srv/nvoy/mcp/tools/claude-channel.mjs --instance codex-jaf --baseline
```

Custom channels require an explicit development opt-in during Anthropic's research preview:

```sh
claude --dangerously-load-development-channels server:nvoy-codex-jaf
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

With `codex_transport: "local_control_socket"`, it uses the supported local Codex app-server
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

`test/instance-runtime-container.mjs` is the deployment-host boundary check. With
`NVOY_CONTAINER_TEST=1 NVOY_RUNTIME_IMAGE=<digest-or-local-test-image>`, it provisions a disposable
four-UID runtime and proves the worker cannot connect to, replace, or unlink the adapter socket or
queue while the broker can connect. It is intentionally skipped on development hosts without Docker;
the production release check runs it on the Docker host before an instance is admitted.

The rendered Compose file is root-owned `0644`. The credential remains host-local, mode `0600`,
and mounts only into the broker.

The Compose `init` service is a one-shot root-only provisioner, not a long-running privileged
sidecar. It reads the manifest and creates/verifies the three named-volume roots with exactly the
declared owner, group, and mode before the non-root services can start. It has no credential mount.

### Automatic verified releases

Routine releases are pull-based; an operator must not copy source or hand-edit image tags. The
`Publish immutable runtime images` workflow first runs the complete non-container test gate, then
publishes runtime and worker images tagged with the exact main SHA. The host-side
[`runtime-deploy-runner.py`](../deploy/runtime-deploy-runner.py) polls only successful runs of
that workflow, verifies the SHA is on `origin/main`, pulls both images, resolves their immutable
digests, and renders every identity from its existing host-local manifest. It never reads or
changes a Bunker URI, client credential, provider credential, grant, or routing policy.

The runner validates each candidate Compose file before starting it. It then requires watcher,
broker, adapter, and (where configured) worker to be running for every identity. The release SHA
and image digests are recorded only after all identities pass. If any identity fails, every
already-touched identity is restored from the previous Compose set; the failed SHA remains
unrecorded so the timer alarms and retries rather than silently accepting a partial release.

Bootstrap once on the runtime host:

```sh
git clone https://github.com/JAFairweather/nvoy.git /opt/nvoy-hub
install -d -m 0700 /var/lib/nvoy-deploy
install -m 0644 /opt/nvoy-hub/deploy/nvoy-runtime-deploy.service /etc/systemd/system/
install -m 0644 /opt/nvoy-hub/deploy/nvoy-runtime-deploy.timer /etc/systemd/system/
systemctl daemon-reload
DRY_RUN=1 python3 /opt/nvoy-hub/deploy/runtime-deploy-runner.py
systemctl start nvoy-runtime-deploy.service
systemctl enable --now nvoy-runtime-deploy.timer
```

The public repository and public GHCR packages require no token. A private fork may place a
read-only `GH_TOKEN` in `/etc/nvoy/runtime-deploy.env` (root-owned mode `0600`). GitHub receives no
host credential: merged, tested source authorizes a release, while promotion remains local.
The runtime host requires Python 3, Git, Docker, and the Compose plugin; it deliberately does not
need a host Node/npm installation because rendering executes inside the candidate runtime image.
