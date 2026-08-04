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
| `/run/nvoy/<id>` | nvoy-<id> 0700 | broker socket |
| watcher spool | separate keyless account, append-only | watcher→broker marker intake |

`nvoy-broker@<id>` and `nvoy-watcher@<id>` run under distinct accounts. The broker obtains an
exclusive lock before opening its state. On systemd, a matching `nvoy-broker@.socket` unit creates
the only socket path with `SocketUser=nvoy-<id>-broker`, `SocketGroup=nvoy-<id>-adapter`, and
`SocketMode=0660`; only that adapter account belongs to the group. In Docker, use three distinct
container users and mount the per-instance runtime volume only into broker and adapter; the socket
is `0600` and created by the adapter. The adapter receives this fixed path from its unit/container
and may not choose another one.

## Protocol and recovery

1. The watcher writes `{ envelope, observed_at }` opaque marker records. A tiny supervisor-owned
   dispatcher materializes one regular marker file per record; it never parses a seal.
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
node mcp/tools/instance-broker.mjs deliver --instance codex-jaf --marker /spool/<envelope>.json
```

`NVOY_INSTANCE_ROOT` is a deployment-only override for tests and staged installs. Production
defaults to `/etc/nvoy/instances`; the commands take an instance identifier, never a caller-chosen
manifest pathname. The broker alone receives `NVOY_BROKER_CREDENTIAL`, a protected credential-file
path (for Docker, a secret mount such as `/run/secrets/nvoy-codex-jaf`; for systemd, a credential
mount). Its value is never passed to the adapter or watcher. The broker requires an opaque marker,
rechecks live grants at delivery time, and refuses plaintext delivery until the adapter sends the
instance-bound acknowledgement.
