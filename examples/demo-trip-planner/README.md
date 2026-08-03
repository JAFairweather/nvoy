# The 90-second demo — trip planner

The headline Nvoy flow, scripted end-to-end (spec §9). This is the artifact to
record and attach to the [NIP-DA PR](https://github.com/nostr-protocol/nips/pull/2411):

> A delegator grants a travel-preferences scope to a Claude-style agent → the
> agent plans a trip via `nvoy_scope_read` → the delegator taps **Revoke**
> mid-conversation → the agent's next tool call returns `NVOY_GRANT_REVOKED`
> and the model says so, cleanly. **Nobody in the OAuth world can show that.**

`demo.mjs` drives the **real Nvoy MCP server binary** (`mcp/dist/server.js`)
through the official MCP SDK client, exactly as Claude Desktop would. The
delegator side issues a real grant and a real key rotation over nostr. Nothing
is faked; the revocation is a scope-key rotation, and the agent's runtime
detects it on the next dereference.

## Run it

```
npm run build           # ensure mcp/dist is current
npm run demo            # in-memory relay (deterministic, offline)
npm run demo:live       # real public relays (nos.lol / primal)
```

Throwaway keys, demo data only. The script exits non-zero if any of the
observable shapes (`NVOY_GRANT_REVOKED`, the gift-wrapped notice, the
`revoked-detected` status) is wrong, so it doubles as an acceptance check.

## What each act proves

1. **Curate + grant** — an opaque `d`-tagged 30440 (relays learn nothing) and
   a gift-wrapped 440 carrying the `nvoy` terms (`purpose`, `no_persist`,
   `redelegate: false`, `expires_at`).
2. **Read** — the agent lists its grant and dereferences the scope live;
   the result attests `nvoy_no_persist: true`.
3. **Revoke** — one key rotation (v1 → v2), republished, re-granted to nobody,
   plus a courtesy kind-441 notice. No server was asked for permission.
4. **Next call** — the agent's `nvoy_scope_read` returns
   `NVOY_GRANT_REVOKED` with the delegator's notice; the runtime has zeroized
   its cached plaintext and scope key.

## Transcript (offline run)

```
NVOY — scoped, revocable data delegation to agents, over nostr
relay: in-memory (run with --live for real public relays)
delegator npub1kfsfwuj6255gmhn…   agent npub1lykrxqw8n6ygz4l…

━━ ACT 1 — The delegator curates and grants ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
published encrypted scope 30440 d=bdjoww (opaque id — relays learn nothing)
granted to the agent inside a gift wrap, with terms:
  purpose: "Plan the Lisbon trip within stated preferences"
  no_persist: true, redelegate: false, expires in 24h

━━ ACT 2 — The agent plans the trip (real MCP server, real SDK client) ━━
nvoy_grants_list → 1 grant: "travel-preferences" — Plan the Lisbon trip within stated preferences [active]
nvoy_scope_read  → v1, no_persist attested: true

  Agent: "Booking within your preferences —
     aisle seat on Air Canada, out of YYZ,
     Marriott under $250/night, vegetarian meals.
     Prefers morning departures; no red-eyes."

━━ ACT 3 — The delegator taps Revoke, mid-conversation ━━━━━━━━━━━━━━━━━
scope key rotated (v1 → v2), data republished under the new key,
re-granted to nobody. Plus a courtesy kind-441 notice, gift-wrapped.
That is the entire revocation. No server was asked for permission.

━━ ACT 4 — The agent's next tool call ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
nvoy_scope_read → isError: true
  code:   NVOY_GRANT_REVOKED
  notice: "trip planned — delegation complete, thanks"

  Agent: "My access to your travel preferences was revoked by the
     delegator ('trip planned — delegation complete, thanks'). I have destroyed my cached
     copy and can no longer read updates."

nvoy_grants_list → status: revoked-detected

━━ CURTAIN ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Revocation enforced by cryptography, not policy: the next dereference
simply failed to decrypt. Scope key + cached plaintext zeroized in the
agent runtime. Try that with a bearer token.
```
