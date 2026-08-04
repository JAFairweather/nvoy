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
  "shared_gid": 41001,
  "key_ref": "/etc/nvoy/keys/codex-jaf.ncryptsec",
  "grantors": ["<64 hex>"],
  "relays": ["wss://nos.lol", "wss://relay.primal.net"]
}
```

The supervisor canonicalizes every path, rejects symlinks and duplicate pubkeys/canonical
state/runtime paths across all manifests, and refuses any CLI or environment identity/path
override. `key_ref` is broker-readable only; it must never be inherited by watcher or adapter.

## Units and filesystem ownership

For each `<id>`, the installer creates a dedicated OS account `nvoy-<id>` and:

| Path | Owner/mode | Consumer |
|---|---|---|
| `/etc/nvoy/instances/<id>.json` | root:root 0644 | supervisor only |
| `/etc/nvoy/keys/<id>.ncryptsec` | root:nvoy-<id> 0640 | broker only |
| `/var/lib/nvoy/<id>` | nvoy-<id> 0700 | broker state/lock |
| `/run/nvoy/<id>` | adapter:instance-group 0770 | broker socket |
| watcher spool | watcher:instance-group 0770, markers 0660 | watcher→broker marker intake |

`nvoy-broker@<id>` and `nvoy-watcher@<id>` run under distinct accounts. The broker obtains an
exclusive lock before opening its state. On systemd, a matching `nvoy-broker@.socket` unit creates
the only socket path with `SocketUser=nvoy-<id>-broker`, `SocketGroup=nvoy-<id>-adapter`, and
`SocketMode=0660`; only that adapter account belongs to the group. In Docker, use three distinct
container users joined only by the manifest's numeric `shared_gid`, and mount the per-instance
runtime volume only into broker and adapter. The adapter creates a `0660` socket inside a `0770`
directory owned by that group; the broker gets the group, nobody else does. The adapter receives this fixed path from its unit/container
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

## Required negative tests

- duplicate pubkey, state root, runtime root, or service user is refused;
- symlinked manifest/key/state/socket paths are refused;
- an adapter cannot read the broker key or choose another instance's socket;
- watcher environment contains no secret or decrypt path;
- malformed/replayed marker and wrong-peer socket connection deliver no plaintext;
- broker restart redelivers an unacknowledged admitted message exactly once after acknowledgement;
- revoked grant after marker observation yields no delivery.

## Runnable reference roles

Nvoy ships three intentionally narrow commands:

```sh
# all three get the same --instance name; neither adapter nor watcher gets a key
node mcp/tools/instance-runtime.mjs watch --instance codex-jaf
node mcp/tools/instance-adapter.mjs --instance codex-jaf
node mcp/tools/instance-broker-daemon.mjs --instance codex-jaf
```

`instance-broker-daemon` is the broker-container entrypoint; it reclaims interrupted inflight
markers after a crash, then serially invokes the one-shot broker. `NVOY_INSTANCE_ROOT` is a deployment-only override for tests and staged installs. Production
defaults to `/etc/nvoy/instances`; the commands take an instance identifier, never a caller-chosen
manifest pathname. The broker alone receives `NVOY_BROKER_CREDENTIAL`, a protected credential-file
path (for Docker, a secret mount such as `/run/secrets/nvoy-codex-jaf`; for systemd, a credential
mount). Its value is never passed to the adapter or watcher. The broker requires an opaque marker,
rechecks live grants at delivery time, and refuses plaintext delivery until the adapter sends the
instance-bound acknowledgement.

### Docker reference deployment

[`deploy/participant-runtime.compose.yml`](../deploy/participant-runtime.compose.yml) is the
concrete three-container layout. It runs watcher, broker, and adapter under three different UIDs;
the only shared group is the manifest's `shared_gid`. It mounts the credential as a Docker secret
only into the broker, mounts broker state only into the broker, mounts runtime only into broker and
adapter, and mounts spool only into watcher and broker. Each service drops capabilities, has a
read-only image filesystem, and uses a private `/tmp`. Start from
[`deploy/participant-runtime.env.example`](../deploy/participant-runtime.env.example); the real
env file and credential remain host-local, mode `0600`, and uncommitted.
