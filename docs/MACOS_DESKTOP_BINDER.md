# macOS visible session binder (V1)

## Outcome

An owner-authorized Nostr instruction appears as a real user message in one explicitly bound
macOS agent conversation. The already-open client owns the turn, so the instruction and response
belong to the same visible branch the owner is using. Nvoy observes that exact turn, publishes its
final answer once, and only then acknowledges the admitted envelope.

The common binder is agent-neutral. Codex Desktop and Claude Desktop/Code provide narrow adapters
for target discovery, submission, and response observation. An engine control protocol may be an
observer after visible submission, but it must never manufacture a sibling background turn and
call that a wake of the open client.

## Live findings that define V1

Two tempting paths have been disproved against the live Codex Desktop client:

- `AXConfirm` can return success while Electron leaves the exact text in the composer. An API
  return is not delivery evidence.
- App Server `thread/resume` + `turn/start` can run the model and produce a reply under the same
  durable thread id while the already-open Desktop client neither displays nor adopts that turn.
  That is a useful headless participant, but it is a sibling execution, not an inline Desktop wake.

V1 therefore requires visible, client-owned submission. Neither staged text, an Accessibility
success result, an App Server turn id, nor a generated model answer is sufficient proof.

## Fixed path

```text
signed channel event
  -> Waggle verifies source and carries it
  -> Nvoy broker decrypts and verifies task + task-relay grants
  -> keyless local queue import
  -> macOS binder verifies identity + app + workspace + chat + composer
  -> binder sets the composer directly (no clipboard) and submits
  -> binder confirms the exact visible user bubble
  -> App Server observes the Desktop-owned turn by envelope token
  -> final answer is queued for the identity signer
  -> reply is published once
```

## Security invariants

1. The binder accepts only `validateAdmittedTask(...).trustedInstruction === true` records.
   A notification, malformed record, participant without task authority, or carrier without
   task-relay authority never reaches Accessibility.
2. The manifest fixes the participant pubkey, app bundle id, workspace label, chat label, and,
   where the engine exposes one, durable thread/session id. Network input cannot select any of
   them.
3. The Mac must be awake and unlocked. Exactly one configured application process, workspace,
   conversation, and enabled empty composer must be provable. The application need not own global
   OS focus when its adapter can submit to a process-targeted control, but no action may depend on
   whichever app happens to be frontmost. Any ambiguity fails closed.
4. Plaintext travels over a local stdin pipe. It is never an argument, environment variable,
   clipboard value, temporary file, log line, or delivery journal field.
5. The visible message contains a short receipt marker derived from the authenticated envelope.
   The marker binds UI confirmation and the later durable Codex turn to the same delivery.
6. Delivery is not acknowledged when text is merely placed in the composer. The exact visible
   user bubble and receipt marker must appear after submission.
7. The binder never reads or stores ChatGPT credentials and never signs a Nostr event.
8. A response is accepted only from the visible client-owned turn containing the exact receipt
   marker. A background/sibling `turn/start` is forbidden from satisfying visible delivery.
9. The reply request is durably queued before the delivery journal advances. Both deduplicate by
   the 64-hex envelope id.
10. Accessibility denial, screen lock, wrong chat, app update, missing composer, duplicate bubble,
    timeout, or uncertain response ownership leaves the envelope pending and emits no reply.

## Visible message

The authenticated sender's words remain first:

```text
<exact signed message>

—
Verified Nostr instruction from <sender-short> via Waggle/Nvoy.
[nvoy:<envelope-first-16>]
```

The full envelope stays in the local admitted queue and is used for cryptographic/durable binding;
the UI marker is deliberately short and non-secret.

## Common adapter contract

Each engine adapter must implement the same fail-closed contract:

1. `inspect` returns one process, workspace, conversation, empty composer, and submission control.
2. `stage` writes exact bytes directly to that composer without clipboard or pasteboard use.
3. `submit` performs exactly one process-targeted mutation. Preferred order is a semantic Send
   action; when Electron does not dispatch it, a narrowly scoped Quartz key event may be posted to
   the already-verified application PID after focusing that exact composer. A global key event,
   coordinate click, menu search, or frontmost-application assumption is forbidden.
4. `prove-visible` finds exactly one user bubble containing the envelope receipt in the configured
   conversation. No retry may issue another submit mutation after an uncertain first mutation;
   observation/recovery must settle that uncertainty first.
5. `observe-response` binds one final assistant response to that same visible receipt and engine
   session. Commentary, another branch, another window, or another agent process cannot satisfy it.

Codex may use App Server read/observation only after visible submission. Claude may use its native
session stream when the visible UI and stream can be bound to the same session; otherwise its
adapter must observe the transcript through a separately reviewed local interface.

## Identity-visible workspace naming

The workspace/conversation label is a useful human safety signal, but never the cryptographic
identity boundary. Setup should offer an identity-bearing display label such as:

```text
Codex - 231952cb
Claude - 78856ed6
Codex · npub1yvv49…cc0v4
```

The full 64-hex participant pubkey and full npub remain visible in Nvoy Console and immutable in
the runtime manifest. If an application accepts the complete npub as a workspace name, setup may
offer it; correctness must not depend on undocumented UI length limits. The adapter binds the exact
owner-approved displayed label plus the full manifest pubkey. A truncated label alone never
selects an identity or authorizes delivery.

## Engine adapters

- **Codex Desktop:** fixed `com.openai.codex` process, selected local project, project-qualified
  task, composer, and durable thread id. App Server can confirm the resulting visible turn but
  cannot create it.
- **Claude Desktop:** fixed Claude bundle/process, owner-selected conversation label and visible
  composer. A durable Claude session id must be bound when the client exposes one.
- **Claude Code CLI/IDE:** prefer official streaming-input, Channels, or ACP ownership of the
  session loop. Terminal UI automation is a fallback only when it can bind one workspace, pane,
  process, and live session as tightly as a native adapter.

## Required functional tests

- wrong or duplicate app process, workspace, conversation, composer, or Send control fails closed;
- workspace label with another identity's fingerprint fails closed even when the chat title matches;
- a full manifest pubkey cannot be replaced by a matching/truncated display label;
- nonempty user draft is never overwritten;
- global focus changes between staging and submission cannot redirect the event;
- process PID, workspace, chat, composer element, exact staged bytes, and receipt are re-proved
  immediately before the one submission mutation;
- semantic submit returning success without a visible bubble remains pending and is not retried;
- a sibling App Server `turn/start` and its valid model answer do not satisfy visible delivery;
- crash after submit recovers by receipt observation and never submits twice;
- only the visible receipt-bound final answer can enter the Bunker signing queue.

## V1 operating boundary

V1 requires the Mac to be awake and unlocked with the configured conversation already open. It
does not navigate between chats. It may operate while another application is frontmost only when
the engine adapter proves a process-targeted submission path; otherwise it reports unavailable.
Automatic navigation could deliver an instruction into the wrong context after a layout or title
change and requires a separately reviewed state machine.

The supported long-term target remains a vendor-supported, authenticated multi-client attach
protocol. Until that exists, V1 is a local macOS session binder because Codex App Server does not
make turns created by a separate client appear in the existing Desktop client's active branch.
