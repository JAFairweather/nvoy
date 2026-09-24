# Outbound action approval for Nostr participants

**Status:** proposed implementation contract for Nvoy #111  
**Governing decision:** nave.pub AD-12  
**Applies to:** Codex App Server, Claude Code Channels, headless workers, and direct MCP chat tools

## Decision

A durable `task`, `task+act`, or `task-relay` grant authorizes an agent to place a bounded action
proposal in the Director's queue. It never authorizes the participant key to sign that proposal.
Every outbound action follows one state machine:

```text
admitted inbound → model result → frozen proposal → Director tap → exact signing → publish
                                     │                  │
                                     ├─ expiry/revoke ──┴→ withdrawn
                                     └─ reject ──────────→ rejected
```

The model-facing process remains keyless. The broker may construct and queue a proposal, but the
signer is not invoked until a discrete, authenticated approval names that exact proposal and its
fingerprint. A proposal is inert and may be retried or displayed without signing anything.

## Common proposal envelope

The durable proposal record is closed and canonical:

```json
{
  "version": 1,
  "proposal_id": "32 lowercase hex",
  "instance": "manifest id",
  "receipt": "64 lowercase hex",
  "action": "nostr-public-event | nostr-private-reply",
  "fingerprint": "64 lowercase hex",
  "frozen": {},
  "created_at_ms": 0,
  "expires_at_ms": 0,
  "grant_ids": ["64 lowercase hex"]
}
```

- `instance`, participant identity, relays, recipients, channels, TTL ceiling, and rate ceiling
  come only from the immutable manifest and broker admission receipt.
- `frozen` is actuator-specific and contains every byte the acting identity will sign.
- `fingerprint` is the Nostr event ID of that frozen unsigned event.
- `grant_ids` records the complete live chain that admitted the proposal. Revocation of any member
  withdraws every still-pending proposal that names it.
- The broker fsyncs the proposal and parent directory before notifying an approval surface.
- A `(proposal_id, fingerprint)` pair is immutable. Reuse with different bytes fails closed.

The approval response is signed by the configured Director and binds the proposal ID, fingerprint,
verb, and decision time. Approval is single-use. Unknown, duplicate, expired, stale-grant, foreign-
approver, or fingerprint-mismatched responses cannot open the signer.

## Public-event actuator

For kind `1` posts and replies, `frozen` is the complete unsigned Nostr event:

```text
[0, acting_pubkey, created_at, kind, every_tag, exact_content]
```

The approval surface renders the kind, exact content, content length, every tag, invisible
characters, risk tier, and fingerprint. After approval the signer receives those exact frozen
bytes. A signer that changes any field is refused before publication.

## Private NIP-17 reply actuator

A private reply cannot approve the throwaway kind-1059 wrap: its ephemeral key is not the acting
identity and its randomized envelope is transport, not the authored act. The broker instead:

1. constructs the exact kind-14 rumor from the receipt-bound peer/channel and proposed text;
2. asks the participant's encryption capability to produce the NIP-44 ciphertext;
3. freezes the complete unsigned kind-13 seal, including participant pubkey, timestamp, empty tags,
   and that exact ciphertext;
4. queues the seal event ID as the WYSIWYS fingerprint;
5. after approval, asks the participant signer to sign that exact seal and verifies the returned
   event ID equals the approved fingerprint;
6. creates the ephemeral kind-1059 wrap and publishes it.

Encryption before approval does not author or publish an action. Signing the seal does, which is why
the gate sits immediately before `signEvent` and rechecks live grants immediately before opening it.
Retry persists and republishes the identical signed wrap; it never signs a second seal.

## Channel replies enacted on the live grant chain

One class of reply does not wait for a Director tap: an answer, in a Buzz channel, to a message
that was addressed to this identity in that channel and admitted on a live grant. The audience is
the channel's membership, the identity is already admitted to it, and the grant chain that admitted
the inbound message is rechecked live immediately before the signer opens. That chain is the
authorization; there is no second act for a human to approve. Two routes qualify, and only these:

| Route | Receipt | Chain rechecked live | What is frozen and signed | `enactment` |
|---|---|---|---|---|
| Channel carry | v2, `mode: channel-carry` | author's `task` grant + carrier's `task-relay` grant, same source event and channel | the kind-13 seal of a NIP-17 reply to the carrier, tagged with the receipt's channel | `channel-carry-direct` |
| Native Buzz | v3, `mode: buzz-native` | author's own `task`/`task+act` grant, same grant id | the kind-9 reply itself: one `h` tag (the receipt's channel, which must be in the manifest's `buzz.channels`), `e` root/reply to the source event, `p` to its author | `buzz-native-direct` |

The actuator, not its caller, decides which route applies: `--prepare` reports `approval_required:
false` with action `nostr-private-reply` or `buzz-channel-reply`, and `--direct` refuses anything
else. A public event is permanent and world-readable, so it always keeps its discrete approval.
Every enacted record names exactly one of `approval_id` or `enactment`, never both and never
neither. As with the seal, the native kind:9 is frozen before the signer opens, its event id is the
fingerprint, and a retry republishes that identical event to the community relay.

## Direct MCP tools

`nvoy_chat_post` and `nvoy_dm_send` become proposal tools by default. Their success response means
`awaiting-approval`, never `published`. A direct-signing form is permitted only when the call carries
a discrete approval bound to the exact frozen fingerprint. An environment variable, standing grant,
tool permission, or "trusted sender" entry is not a discrete approval.

## Revocation, expiry, and limits

- The standing capability tier is capped at `low`.
- Manifest TTL and rate limits may tighten the estate defaults, never widen them.
- Grant revocation withdraws all pending proposals whose `grant_ids` include the revoked grant and
  reports the exact proposal IDs withdrawn.
- A proposal expiring while its approval UI is open remains expired; a late tap cannot revive it.
- A fresh proposal after rejection or expiry receives a new ID and fingerprint.

## Unresolved provenance atom

The estate text currently describes an enacted public event carrying:

```text
["approval", "<approval-event-id>", "<approver-pubkey>"]
```

while also requiring the approved event bytes to be frozen before that approval event exists. Those
requirements are circular: adding the future approval event ID changes the frozen event ID. No
implementation may guess around this. Before public provenance ships, the governing protocol must
choose one non-circular construction, for example a proposal nonce carried by both events or a
documented fingerprint derivation that excludes exactly the provenance tag. Private NIP-17 replies
also cannot expose a public provenance tag without weakening their privacy. Until that ruling,
Nvoy's authoritative proof is the signed approval response plus the private proposal/outcome journal;
the outbound action gate itself does not depend on public provenance.

## Release gates

1. Negative tests prove no timer, worker, Codex adapter, Claude Channel, or direct MCP tool can reach
   `signEvent` without one live exact approval.
2. Mutation, duplicate approval, foreign approval, stale grant, revoked grant, expired proposal,
   wrong instance, wrong recipient/channel, and crash/retry tests all fail closed.
3. A live test shows proposal visibility, one human tap, exactly one signed publication, and a
   withdrawal that kills an already queued proposal.
4. Only after those gates may the outbound-action hold in the runtime docs be removed.
