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
| Bunker URI + NIP-46 client credentials | root:broker 0600 | broker only |
| Model-provider credential | root:worker 0600 | worker only; never a Nostr key |
| `/var/lib/nvoy/<id>` | nvoy-<id> 0700 | broker state/lock |
| `/run/nvoy/<id>` | adapter:broker-adapter 0711 | broker socket (broker can traverse, not replace; worker can only traverse to named handoffs) |
| adapter socket | adapter:broker-adapter 0660 | broker only |
| task input + admitted queue | adapter:worker-handoff 0640 | adapter → worker, read-only for worker |
| reply queue | worker:broker-adapter 0640 | worker → broker, read-only for broker |
| watcher spool | watcher:broker-adapter 0770, markers 0660 | watcher→broker marker intake |

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
3. The broker pushes `{ type: "admitted-task", envelope, received_at, content }` over the
   authenticated per-instance socket. The adapter acknowledges only after durable hand-off to
   its own execution queue. A broker restart redelivers unacknowledged admitted work; a marker
   is never marked completed merely because it was observed.
4. The adapter starts/alerts its client using a fixed local mechanism. Codex desktop is not
   falsely claimed to be resumable; it needs its dedicated worker/queue adapter.
5. A worker that chooses to reply writes a bounded `reply-request` referencing the delivered
   envelope. The broker accepts it only when the recipient was a permitted sender recorded in its
   own admission receipt. It persists the exact signed NIP-17 wrap before publishing, so a crash
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

`instance-broker-daemon` is the broker-container entrypoint; it reclaims interrupted inflight
markers after a crash, then serially invokes the one-shot broker. `NVOY_INSTANCE_ROOT` is a deployment-only override for tests and staged installs. Production
defaults to `/etc/nvoy/instances`; the commands take an instance identifier, never a caller-chosen
manifest pathname. The broker alone receives `NVOY_BROKER_CREDENTIAL`, a protected credential-file
path (for Docker, a secret mount such as `/run/secrets/nvoy-codex-jaf`; for systemd, a credential
mount). Its value is never passed to the adapter or watcher. The broker requires an opaque marker,
rechecks live grants at delivery time, and refuses plaintext delivery until the adapter sends the
instance-bound acknowledgement.

`instance-worker` supports the local `codex exec` and `claude -p` runners. It launches each with
a fixed prompt that explicitly treats the delivered body as **untrusted data, never instruction**;
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

The rendered Compose file is root-owned `0644`. The credential remains host-local, mode `0600`,
and mounts only into the broker.

The Compose `init` service is a one-shot root-only provisioner, not a long-running privileged
sidecar. It reads the manifest and creates/verifies the three named-volume roots with exactly the
declared owner, group, and mode before the non-root services can start. It has no credential mount.
