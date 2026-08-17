# DJ Codex wake adapter

DJ Codex is the existing Codex identity bound to one Nvoy instance and one persistent Codex
app-server thread. The adapter is intentionally not a Nostr client and does not hold a signer.

## Boundary

Waggle core performs NIP-59 opening, sender/carrier policy, first-seen claiming, bootstrap handling,
and the wake decision. It writes classified records to the instance spool. The adapter consumes only
records whose core-owned `wake` field is exactly `true`.

It must not reconstruct wake from `mayAct`, `receipt`, `disposition`, an `@mention`, or message text.
Receipts and untrusted mail may remain visible in the spool while never starting a Codex turn.

## Cursor and failure behavior

The cursor is a durable byte offset in `codex-wake-cursor.json`. Non-wake records advance it without
starting a turn. A wake record advances it only after the local app-server acknowledges `turn/start`
or `turn/steer`; completion is not the cursor commit point. If dispatch fails, the wake record remains
owed for retry. A partial trailing JSONL frame is held for the next cycle and a malformed complete
frame stops the reader loudly.

The adapter has a bounded per-minute start limit and a circuit breaker after repeated app-server
failures. This is a spend and execution safety boundary: a bad or unexpectedly noisy wake stream must
hold rather than start unlimited model turns.

## Local invocation

The instance manifest supplies the fixed Codex thread and local control socket. No incoming record can
select an identity, project, or thread:

```sh
node mcp/tools/codex-wake-adapter.mjs --instance codex-jaf --once
```

The long-running service may omit `--once`. Production should run it with the instance supervisor,
explicit sandbox/approval settings, and the same role separation used by the existing Codex app-server
adapter. A non-loopback WebSocket is not supported by this adapter; if a future transport crosses a
host boundary it must use authenticated WebSocket transport (`--ws-auth`) and a pinned endpoint.

## Verification

The focused contract suite is:

```sh
npm run test:wake
```

It covers the wake-only gate, non-wake skipping, cursor commit timing, retry after dispatch failure,
replay idempotence, byte-framed JSONL, and the circuit breaker.
