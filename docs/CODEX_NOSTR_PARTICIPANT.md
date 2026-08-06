# Bind a Codex task as a Nostr participant

Codex's Nostr identity binds to one operator-selected, persistent Codex task. That may be the
owner's existing goal-bearing project task—the first-class path—so an admitted Nostr message joins
the same context that is already doing the work. A separate participant task is an optional
isolation policy, not a protocol requirement and not the default product promise.

The immutable manifest chooses the task. An inbound event cannot select, create, rename, resume,
or redirect a task. If the selected task is active, delivery uses `turn/steer` against its exact
current turn. If it is idle, delivery starts the next turn. A second interactive client must not
independently run the same task; the local App Server control plane is the sole delivery edge.

This interaction pipe is only one half of the client integration. The same isolated identity
runtime can expose the fixed-instance `codex-channel-mcp.mjs` read/reply plane from Nvoy #115 / PR
#118 over its broker-admitted queue. The App Server binder wakes and addresses the exact task; MCP
lets that task deliberately inspect the exact envelope and verified authority. Neither browser
inspection nor screen automation is a substitute for MCP. See
[Nostr agent architecture](NOSTR_AGENT_ARCHITECTURE.md).

## Select an existing task

Use the task ID shown by Codex for the project conversation you want Nostr to reach, and record its
exact expected name and canonical project root in the operator-owned manifest. For example, the
Waggle development identity is intentionally bound to the existing `waggle dev` goal task. This is
what makes a wrapped mention an instruction in that task rather than an answer from an unrelated
background agent.

## Optionally create an isolated participant task

Run this locally as the workstation owner. It searches only for an exact task name and canonical
project root among App Server tasks. If no exact match exists, it creates and names one. It prints
the immutable task ID; neither the watcher nor any inbound Nostr event can invoke this operation.

```sh
node mcp/tools/codex-session-bootstrap.mjs \
  --name 'Codex - Nostr participant' \
  --cwd /absolute/path/to/project
```

Put the selected or returned `thread_id` in the keyless desktop manifest as `codex_thread_id`. Set
`codex_transport` to `local_control_socket` and bind `codex_app_server_socket` to the local managed
App Server Unix socket. The broker, Bunker URI, and every Nostr credential remain off the desktop
adapter.

To inspect an isolated participant interactively, resume that exact task with the same Codex build
that owns the local App Server:

```sh
/Applications/ChatGPT.app/Contents/Resources/codex resume <thread_id>
```

Do not concurrently resume the task in another client. This warning prohibits two competing
clients; it does not prohibit binding the one existing Desktop goal task through its local control
plane.

## Delivery behavior

For a broker-admitted wrapped mention, the keyless adapter:

1. validates the immutable instance, recipient, original author, carrier, channel, task grant, and
   carrier grant before receiving plaintext;
2. reads only the manifest-bound Codex task;
3. deduplicates by the broker-authenticated envelope ID;
4. uses `turn/steer` with `expectedTurnId` when that task has an active in-flight turn, otherwise
   uses `turn/start` for a normal follow-up;
5. captures only an explicit final-answer item as the reply;
6. queues a receipt-bound reply request for the credentialed broker, which resolves the recipient
   and signs through the Codex Bunker identity.

An API acknowledgement is not end-to-end proof. Release acceptance requires a fresh wrapped
mention, a turn containing the exact envelope marker in the manifest-bound task, one final response,
one signed Nostr reply, and the Waggle reaction receipt. Unauthorized authors, admitted-only
authors without task authority, wrong carriers/channels, stale/replayed sources, and wrong task or
recipient bindings must all fail closed.

Also prove that the MCP tools are attached to this same task and can read the exact delivered
envelope. MCP clients load toolsets at task/session lifecycle boundaries; “server deployed” and
“tools visible in this task” are separate states.
