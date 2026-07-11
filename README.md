# Nvoy

**Scoped, revocable data delegation to agentic workflows — over nostr.** A
delegator curates exactly the data an agent needs into an encrypted scope,
grants it to the agent's keypair, and can revoke at any time — with revocation
enforced by cryptography, not by a policy server. The agent side mounts as an
**MCP server**, so any MCP-speaking framework (Claude Desktop, or your own)
consumes delegated data with zero nostr knowledge.

> OAuth/Okta delegate *access* — a bearer token into a system that keeps the
> data. Nvoy delegates *data* — end-to-end encrypted to the agent,
> dereferenced live at run time, severable in one keystroke. Complement, not
> competitor: **"Okta secures what your agent can do; Nvoy secures what your
> agent can see — and lets you un-see it."**

Revocation is a scope-key rotation: the agent's next dereference simply fails
to decrypt and returns a clean `NVOY_GRANT_REVOKED` error. No token to expire,
no admin panel, no ACL. Nobody in the OAuth world can show that.

## Two components

- **`mcp/`** — the Nvoy MCP server (Node/TypeScript). Holds the agent's key;
  serves `nvoy_whoami` / `nvoy_grants_list` / `nvoy_scope_read` /
  `nvoy_scope_subscribe` / `nvoy_outbox_write` / `nvoy_request_access` /
  `nvoy_grant_relinquish`, plus scopes as MCP resources. stdio **and**
  Streamable HTTP transports. Stateless dereference: delegated data is working
  context, never state — `no_persist` scopes never touch disk or logs and are
  zeroized on revocation/expiry/shutdown. See [`mcp/README.md`](mcp/README.md).
- **`console/`** — the delegator console (browser, vanilla ESM, no build step).
  Agent registry, scope authoring with templates + terms, a TTL rotation
  scheduler, and the **ledger**: a live answer to *"exactly what data do my
  agents hold right now, under what terms — and show me the revocations."* The
  whole record reconstitutes from the delegator nsec alone, on any device.

## The nvoy terms extension

A grant payload MAY carry an `nvoy` object — `purpose`, `expires_at`,
`no_persist`, `redelegate`, `reply_scope_requested`, `auto_relinquish`,
`contact`. It is **payload-level and backward-compatible**: a vanilla NIP-DA
client ignores it entirely. Every term is disclosed honestly as
*compliance, not cryptography* — enforced mechanically by a compliant runtime,
never by the protocol. The delegator's real lever is rotation. See
[`SECURITY.md`](SECURITY.md).

## Quick start

```
npm install
npm run build         # compiles the MCP server (mcp/dist), vendors lib/ into it
npm run demo          # the 90-second demo (§9): grant → agent reads via a REAL
                      #   MCP server → revoke mid-conversation → next read fails,
                      #   in-memory (npm run demo:live for real public relays)
npm run console       # delegator console at http://localhost:4443/
```

Then point an MCP client at the server — see [`mcp/README.md`](mcp/README.md)
and [`examples/claude-desktop.json`](examples/claude-desktop.json).

## Tests

```
npm test              # build + smoke + ledger + conformance + nopersist + accept + egress
npm run smoke         # protocol smoke, in-memory (smoke:live = real relays) + observer view
npm run ledger        # console↔MCP cross-impl: signer-issued grants parse via mcp/dist
npm run conformance   # MCP SDK client against the built server, BOTH transports
npm run nopersist     # fs/log interception: zero scope plaintext leaves memory
npm run accept        # §7 M4 acceptance: granted → relinquished → rotated arc
npm run egress        # zero-egress: console + MCP reach only relays / esm.sh
```

The `mcp/` tarball is **not published to npm** (it depends on a draft
protocol): `cd mcp && npm pack` produces a self-contained
`nvoy-mcp-0.1.0.tgz` whose `nvoy-mcp` bin launches the stdio server via
`npx ./nvoy-mcp-0.1.0.tgz` — local pack + docs only.

## The NIP-DA family

Nvoy is the fourth reference client built on draft **NIP-DA Scoped Data
Grants** (PR [nostr-protocol/nips#2411](https://github.com/nostr-protocol/nips/pull/2411)) —
each a self-contained app exploring a different shape of the same primitive
(one encrypted, self-maintained record + a revocable grant; the useful view
is emergent), **not** a suite:

- [Nontact](https://github.com/JAFairweather/nostr-scoped-data-grants) — the
  protocol repo + a live contact-card manager (the address book as emergent
  view).
- [Nvelope](https://github.com/JAFairweather/nvelope) — live document sharing:
  revocation instead of expiring links, one-key recovery.
- [Notegate](https://github.com/JAFairweather/notegate) — serverless secure
  tip intake: the Grant Index *is* the case docket.
- **Nvoy** (this repo) — scoped, revocable data delegation to agents; the
  agent side is an MCP server.

Built on **draft** NIP-DA
([review pending](https://github.com/nostr-protocol/nips/pull/2411)); kind
numbers are placeholders and may change. Use throwaway keys; treat delegations
as ephemeral. `lib/` is vendored from the protocol repo (`npm run sync-lib`).

MIT.
