# macOS visible Desktop binder (V1)

## Outcome

An owner-authorized Nostr instruction appears as a real user message in one explicitly bound
Codex Desktop chat. The Desktop-owned turn produces the response. Nvoy observes that exact turn,
publishes its final answer once, and only then acknowledges the admitted envelope.

App Server is an observer after visible submission. It must never create a background turn.

## Fixed path

```text
signed channel event
  -> Waggle verifies source and carries it
  -> Nvoy broker decrypts and verifies task + task-relay grants
  -> keyless local queue import
  -> macOS binder verifies app + project + chat + composer
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
2. The manifest fixes the app bundle id, project label, chat label, and Codex thread id. Network
   input cannot select any of them.
3. ChatGPT must be frontmost, unlocked, showing exactly the configured project and chat, with one
   enabled message composer. Any ambiguity fails closed.
4. Plaintext travels over a local stdin pipe. It is never an argument, environment variable,
   clipboard value, temporary file, log line, or delivery journal field.
5. The visible message contains a short receipt marker derived from the authenticated envelope.
   The marker binds UI confirmation and the later durable Codex turn to the same delivery.
6. Delivery is not acknowledged when text is merely placed in the composer. The exact visible
   user bubble and receipt marker must appear after submission.
7. The binder never reads or stores ChatGPT credentials and never signs a Nostr event.
8. A response is accepted only from the Desktop-owned turn containing the exact receipt marker.
   Background `turn/start` is forbidden.
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

## V1 operating boundary

V1 requires the Mac to be awake and unlocked, ChatGPT frontmost, and the configured chat visible.
It does not navigate between chats. This is intentional: automatic navigation could deliver an
instruction into the wrong context after a layout or title change. A later version may add a
separately reviewed navigation state machine.

The supported long-term target remains scoped headless Remote Control ingress. V1 is a local
Accessibility binder because Codex App Server does not make turns created by a separate client
appear in the existing Desktop client's visible stream.
