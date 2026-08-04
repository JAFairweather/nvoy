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
grant gate or decrypt mail. It pushes an admitted message only after it verifies the adapter's
OS peer identity on its instance socket. There is no bearer task handle to replay or forward.

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
exclusive lock before opening its state or socket. The adapter connects to the broker socket
through a supervisor-created, identity-bound credential; it may not choose a socket path.

## Protocol and recovery

1. The watcher appends `{ envelope, observed_at }` to its own spool. It never parses a seal.
2. The broker atomically claims a marker, fetches the exact envelope, decrypts, and validates
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
