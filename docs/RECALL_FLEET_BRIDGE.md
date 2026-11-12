# Fleet recall bridge (design, not built)

nvoy PR 333 added `may_recall` and the broker-side `recall` service. On nvoy-fleet the store is remote: herd-cloud's
Hive memory, reached as `hive-memory-gw@herd-cloud` over SSH with a per-agent read key. Murphy's pre-grant read
(12 Nov) found the gap. A `may_recall.read.command` runs inside the recall container, which has no SSH client and,
by design, no key. This note proposes the bridge. James's grants for GrokDoggyDog wait until it is built and reviewed.

## Shape

- **Host unit, per instance:** `nvoy-recall-gw@<id>.socket` (`ListenStream=/run/nvoy-recall-gw/<id>/socket`,
  `Accept=yes`, `SocketUser` = the instance's broker host user, `SocketMode=0660`, group = the broker-adapter group)
  and `nvoy-recall-gw@<id>.service`. That runs, as the broker host user,
  `ssh -i <key> -o IdentitiesOnly=yes -o BatchMode=yes -o UserKnownHostsFile=<pinned> hive-memory-gw@herd-cloud`,
  and nothing else. The gateway's forced command chooses the reader. The client sends no arguments.
- **Key:** `/etc/nvoy/recall-keys/<id>` (mode 0600, owner the broker host user), on nvoy-fleet only. It is never
  mounted into any container. Making it, and authorizing its public half on herd-cloud's gateway as reader `<id>`,
  is the operator's step. The authorization is James's grant.
- **Container side:** the manifest uses `may_recall: { read: { socket: "/run/nvoy-recall-gw/socket" } }`. Compose
  bind-mounts only the instance's socket directory read-write into `recall`, never into door, adapter or worker.
  `recall` keeps its current limits: two tools, 20 s, fail closed, 4 in flight, 1 MiB lines.
- **No new capability in the container:** no SSH binary is needed, there is no key path, and there is no network
  route. The socket is the only way out.

## Tests (to build)

- Render: `recall` gets the socket mount only when `may_recall.read.socket` is set. No other service gets it, and no
  service mounts `/etc/nvoy/recall-keys`.
- Forwarder against a fake socket gateway: wake and query pass through, while claim, submit and anything else are
  refused before any connection.
- Unit files: `ExecStart` takes no client-supplied argument. The socket is 0660 with the broker-adapter group.

## Done when (Murphy's live gates)

On nvoy-fleet:
- the key path and permissions are verified;
- the door, adapter and recall containers cannot read the key;
- the installed forced command and reader mapping, including any earlier reader key, are verified;
- the deployed SHA and socket permissions are verified;
- wake and query work live;
- a write or an arbitrary method is refused without contacting the store;
- an outside-room read and a cross-instance read are both refused.

## Who

Code and tests: Dead Rabbit. Fleet install and key: an operator with nvoy-fleet access (none of the herd-cloud agents
have it yet; James decides whether Neil gets a login). Grants: James. Live check: My Dude.
