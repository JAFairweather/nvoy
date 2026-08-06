# Codex macOS session binder (V1)

## Supported outcome

An owner-authorized Nostr instruction can enter one immutable Codex project/thread as a genuine
user turn or steer. A response is returned only through a receipt-bound Nostr path. The supported V1
uses Codex App Server protocol through the local control socket; it does not automate the Desktop
composer.

The owner binds the exact persistent task already used for the project. It may remain open in
Codex Desktop; no Accessibility automation, pasted composer text, foreground focus, or second CLI
client is required. For an active turn Nvoy calls
`turn/steer` with the exact current `expectedTurnId`; for an idle thread it calls `turn/start`.
The immutable manifest chooses the thread. No inbound event may choose a project, thread,
recipient, signer, or reply channel.

## Proven path

```text
signed Nostr/Buzz channel event
  -> Waggle verifies and carries the original signed source
  -> Nvoy broker verifies the sender task grant and separate carrier task-relay grant
  -> restricted SSH forced command exports only admitted records
  -> keyless macOS bridge imports and deduplicates the envelope
  -> App Server adapter reads the fixed thread
       active: turn/steer(expectedTurnId), delivery-only
       idle:   turn/start, whose final answer is receipt-bound
  -> an eligible final answer or explicit receipt-bound reply is durably queued
  -> remote broker revalidates authority and signs/publishes one reply
  -> Waggle reacts 👍 to the original user message after relay acceptance
```

The 2026-08-05 shared-thread experiment was **not** an end-to-end proof. App Server accepted a
`turn/steer` for the development task, but a competing CLI client was also resumed against that
task and a blind nonce did not return from model context. The correction is one control-plane
client bound to the existing goal task—not silently substituting a separate background agent.
Release remains unproven until a fresh wrapped mention visibly joins that task and completes the
acceptance path below. Historical queue entries must be baselined rather than replayed.

## Security boundary

1. The remote broker alone decrypts and verifies live grants. The Mac receives only
   broker-admitted records.
2. A channel carry requires both the original author's live `task` authority and the configured
   carrier's distinct `task-relay` authority. The carrier never becomes the author.
3. The desktop manifest fixes one participant identity, broker endpoint, pinned SSH host key,
   local control socket, and full Codex thread id.
4. The SSH key is restricted server-side to one forced sync command. It is not a shell, signer,
   relay credential, or decryption capability.
5. The local bridge and App Server adapter hold no nsec, Bunker URI, NIP-46 client secret, or
   recipient-selection capability.
6. Every envelope has one durable import cursor, one delivery record, and at most one reply
   request. A crash retries from those records rather than inventing a second identity or turn.
7. Only the final answer from a new envelope-owned protocol turn is automatically eligible for
   reply. A steer joins a pre-existing owner turn, so its eventual final answer is never
   auto-exported; replying to a steer requires a separate explicit receipt-bound reply action.
   Commentary and tool events are never published.
8. A durable task may retain stale historical `inProgress` rows. If `expectedTurnId` rejects one,
   the adapter may reconcile exactly once to the server-reported active id only when that id was
   also present as in-progress in the same immutable task snapshot. The failed first steer is
   non-mutating; another race fails closed for a fresh read.
9. A verified notification without task authority remains data-only and cannot acquire a reply
   capability.
10. The reply broker rechecks the live admission chain before signing. Revocation therefore closes
   the path even after observation.
11. The confirmation reaction belongs only on the original user event, after relay acceptance;
    Waggle must not react to its own carried message.

## Desktop manifest

```json
{
  "version": 1,
  "id": "codex-jaf",
  "pubkey": "<Codex 64-hex pubkey>",
  "broker_mode": "remote",
  "delivery_mode": "codex_app_server",
  "worker_enabled": false,
  "codex_thread_id": "<operator-selected-project-task-id>",
  "codex_transport": "local_control_socket",
  "codex_app_server_socket": "/Users/you/.codex/app-server-control/app-server-control.sock",
  "ssh_target": "nvoy-sync@broker.example",
  "ssh_identity_file": "/Users/you/.nvoy/desktop/id_ed25519",
  "ssh_known_hosts_file": "/Users/you/.nvoy/desktop/known_hosts",
  "ssh_known_hosts_sha256": "<64-hex sha256>"
}
```

Run `codex-remote-bridge.mjs --baseline` once before live delivery. Then install the per-identity
LaunchAgent with `install-codex-bridge-launchagent.mjs`; it runs the same keyless bridge with only
`HOME`, `PATH`, and `NVOY_INSTANCE_ROOT` in its environment.

## Why Accessibility is not V1

Live experiments showed that Electron Accessibility calls can report success while leaving text
staged in the composer. Background `AXConfirm`, semantic Send, process-targeted Return, focus
changes, and AppleScript did not provide reliable proof that a turn entered the intended Codex
conversation. Those experiments are removed from the release path. UI automation is not delivery
evidence and must not acknowledge an envelope.

The local managed App Server control socket is the native protocol edge used by V1. A separate
CLI resume remains useful for an intentionally isolated headless participant, but it must not be
opened concurrently against an already active Desktop task.

## Claude Code parallel

Claude Code should implement the same authority, queue, deduplication, fixed-session, and
receipt-bound reply contracts. Its preferred ingress is the official Claude Code Channel/MCP
notification mechanism, not terminal or UI automation. See the Claude channel section in
`RUNTIME_SUPERVISOR.md`; a live same-session proof is still required before declaring parity.
