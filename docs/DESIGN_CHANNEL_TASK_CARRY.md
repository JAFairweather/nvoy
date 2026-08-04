# Design: grant-authorized channel instructions through a carrier

**Status:** implementation contract · **Tracks:** Nvoy #44 and Waggle #110

## 1. Outcome

An owner-authorized person can instruct one specific Nvoy participant from a Buzz or Armada
channel even when that participant cannot read the channel relay directly. The instruction reaches
the exact bound Claude/Codex runtime and a reply returns to the exact source channel.

The bridge is a carrier, never the instructor. Two independently revocable grants are required:

1. the original channel author holds `task` or `task+act`, scoped to the participant identity;
2. the Waggle bridge holds `task-relay`, scoped to the same participant identity.

Neither grant is sufficient alone. Granting `task-relay` does not authorize the bridge's own prose
as an instruction, and granting an author `task` does not authorize an arbitrary intermediary to
claim that the author spoke in a private channel.

## 2. Trust chain

```text
signed Buzz/Concord channel event (original author)
        │ exact wire event, including id/signature/channel tags
        ▼
Waggle verifies + seals a typed carry (carrier signature)
        │ NIP-59 to one fixed participant key
        ▼
Nvoy broker verifies both signatures + both live grants
        │ emits original author as authority.sender
        ▼
fixed Desktop/headless runtime and fixed conversation
        │ reply contains text + opaque admitted envelope only
        ▼
Nvoy signs to Waggle, receipt fixes bridge + source channel
        │ existing relay-ingress lane
        ▼
the exact Buzz/Armada channel
```

The keyless adapter, Desktop session, and model choose none of: identity, recipient, carrier,
channel, grant, or thread.

## 3. Encrypted carry format

The NIP-59 rumor remains authored by the bridge and addressed to the participant. Its `content` is
strict JSON, not display prose:

```json
{
  "v": 1,
  "type": "waggle-channel-task-carry",
  "channel": "<Buzz channel UUID>",
  "reason": "mention",
  "source": {
    "id": "<64 hex>",
    "pubkey": "<64 hex>",
    "created_at": 1785870000,
    "kind": 9,
    "tags": [],
    "content": "the exact source content",
    "sig": "<128 hex>"
  }
}
```

`reason` is exactly `mention` or `reply`. `channel` is the resolved Buzz channel UUID from the
bridge's configured scan pass. The source event's signed `h` tag is a Concord address, not
necessarily that UUID; the carrier's signature attests their mapping. `source` is the complete event as received,
not a reconstruction or rendered quotation. Waggle verifies it before carrying; Nvoy verifies it
again after decrypting. Unknown fields, malformed events, wrong kinds, signatures, ids, channels,
or future versions fail closed.

Legacy human-readable `return_carry` remains data-only. A return-lane recipient opts into the typed
format with `protocol: "nvoy-task-carry-v1"`; there is no global semantic change for existing
recipients.

## 4. Grant and admission rules

All grants are public signed kind `440`, revocable by the same grantor's kind `441`, and use the
existing salted participant scope hash. The broker rebuilds policy from live relay state for every
arrival.

For a typed carry, the broker requires all of the following:

- the outer seal signer equals the configured carrier identity;
- that carrier holds `task-relay` for this participant;
- the embedded source event has a valid id and Schnorr signature;
- its signer holds `task` or `task+act` for this participant;
- the carrier attests the resolved carry channel while preserving the source event's signed tags;
- the carry channel is allowed for that carrier by the participant manifest;
- the carry is addressed to this participant and has not already been admitted.

The admitted record identifies the original signer as `authority.sender`. Version 2 authority adds
`carrier`, `carrier_grant_id`, `carrier_grantor`, `source_event`, and `reply_channel`. Every keyless boundary validates
all fields and rejects a mixed or downgraded record. Ordinary direct DMs continue to use version 1.

## 5. Reply confinement

The broker's one-use, five-minute receipt records whether an arrival is `direct` or
`channel-carry`. For a channel carry it binds:

- original sender and original event id;
- carrier and carrier grant id;
- exact reply channel;
- participant identity and both policy grant ids.

A Desktop reply request still supplies only `{ envelope, content }`. The keyed broker resolves the
rest from the receipt, signs a NIP-17 rumor to the carrier, and adds the existing `relay` tag fixed
to `reply_channel`. Waggle's existing relay lane authenticates the participant seal, checks its
admission and destination allowlist, and posts the text. A consumed, expired, revoked, or missing
receipt is terminal. A reply can never be redirected to a private DM or another channel.

## 6. Failure, privacy, and operations

- No relay response means policy unverifiable, therefore no instruction is admitted.
- Either revoked grant immediately breaks the chain; no process restart is required.
- The keyless watcher sees only outer `1059` metadata and an opaque event id.
- Channel id, content, source author, and grant decisions remain inside encrypted carries and the
  broker's identity-private state.
- Existing durable marker, receipt, retry, and published-reply records provide at-least-once input
  with idempotent completion. Dead letters and policy outages are loud.
- Logs name only bounded ids/pubkey prefixes and never channel content.

## 7. Acceptance proof

1. A granted author mentions the participant in an allowed channel; the exact Desktop thread wakes
   with authority naming that author, not Waggle.
2. The participant replies; the response lands once in that exact channel under the participant's
   attributed relay-lane identity.
3. Revoke the author's `task` grant: the same author becomes data-only/no wake.
4. Restore it and revoke Waggle's `task-relay`: the same carry becomes data-only/no wake.
5. Tamper independently with source content, signature, channel, carrier, either grant id, or
   receipt: every case fails before model delivery or signing.
6. A bridge-authored ordinary DM with `task-relay` alone never becomes an instruction.

## 8. Trade-offs and future revisit

This adds a second grant and a typed carrier protocol, but preserves end-to-end author provenance
and narrow revocation. The simpler alternative—granting Waggle `task`—would erase who instructed
the agent and authorize every bridge-authored byte, so it is rejected.

If Buzz/Concord later exposes independently readable, native signed channel events to external
participants, remove the carrier grant and consume those events directly. Until then, this is the
smallest chain that proves both *who spoke* and *who transported the private channel assertion*.
