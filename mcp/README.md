# nvoy-mcp

**The agent side of Nvoy** — a Model Context Protocol server that serves
scoped, revocable data delegations to any MCP-speaking client (Claude
Desktop, or any framework using the MCP SDK). The agent holds a nostr
keypair; a delegator grants encrypted **scopes** to that key over nostr; this
server dereferences them live at tool-call time and hands the plaintext to
the model — nothing else, nowhere else.

Built on draft [NIP-DA Scoped Data Grants](https://github.com/JAFairweather/nostr-scoped-data-grants)
(PR [nostr-protocol/nips#2411](https://github.com/nostr-protocol/nips/pull/2411)).
Part of [Nvoy](https://github.com/JAFairweather/nvoy); the delegator console
lives in that repo's `console/`.

The pitch in one line: **OAuth secures what your agent can *do*; Nvoy secures
what your agent can *see* — and lets you un-see it.** Revocation is a scope-key
rotation, not a token expiry: the agent's next read simply fails to decrypt.

## Conversation tools (chat module)

Alongside the data plane, the agent has a mouth — four tools mirroring nostr's
own public/sealed split: `nvoy_chat_post` / `nvoy_chat_read` (public kind:1,
with NIP-10 threading) and `nvoy_dm_send` / `nvoy_dm_read` (NIP-17 gift-wrapped
DMs — sealed to the recipient plus a self-copy; only kind-14 chat rumors are
returned by dm_read, so data-grant wraps never bleed into conversation). Same
custody discipline as everything else: every identity-key operation rides the
Signer (so chat works under a NIP-46 remote signer too), nothing touches disk,
and read content is flagged untrusted in the tool descriptions the model
actually sees. Set `NVOY_DM_CC=<operator npub>` and every outbound DM is also
sealed to the operator — the agent's principal reads all of its working
traffic; sealed against the world, transparent to the operator.

## Install

This package is **not published to the npm registry** (it depends on a draft
protocol). Run it from source, or from a locally-built tarball.

From source:

```
git clone https://github.com/JAFairweather/nvoy.git
cd nvoy/mcp
npm install          # builds dist/ via the prepare script
node dist/server.js --ephemeral
```

As a local tarball (what a published `npx nvoy-mcp` would feel like):

```
cd nvoy/mcp
npm pack             # → nvoy-mcp-0.1.0.tgz (runs tsc first via prepack)
npx ./nvoy-mcp-0.1.0.tgz --ephemeral      # launches the stdio server
# or install the bin globally:
npm i -g ./nvoy-mcp-0.1.0.tgz && nvoy-mcp --ephemeral
```

The `bin` is `nvoy-mcp`. On stdio it speaks the MCP protocol on stdout; all
diagnostics (including the agent's npub, which is its address) go to stderr.

## Identity setup

The agent's keypair is its address — a delegator grants scopes to its npub,
printed on the server's first stderr line. Three sources, in precedence order:

| Source | How | When |
| :-- | :-- | :-- |
| `--ephemeral` (flag) | fresh keypair each boot, memory only | demos, CI, throwaway agents |
| `NVOY_NCRYPTSEC_FILE` + `NVOY_NCRYPTSEC_PASSPHRASE` | a file holding a NIP-49 `ncryptsec1…`, decrypted at boot | **recommended for a standing agent** — the key sits on disk only encrypted |
| `NVOY_SIGNER=nip46` + `NVOY_BUNKER_URI_FILE` | a mode-0600 file holding a NIP-46 `bunker://…` pairing URI | **recommended when a bunker owns the identity** — no raw nsec is supplied to the MCP client |
| `NVOY_NSEC` | a raw `nsec1…` or 64-char hex in the environment | convenient, but see the security note |

Other env:

- `NVOY_BUNKER_URI_FILE` — NIP-46 pairing URI file, required to be a regular,
  non-symlink file with no group/world permissions. The URI contains a pairing
  secret, so do not put it in JSON config, shell history, or environment files.
  `NVOY_NIP46_CLIENT_NSEC_FILE` holds the stable NIP-46 transport key under the
  same mode rule. Direct URI/key env forms are legacy compatibility only.

- `NVOY_RELAYS` — comma-separated relay list (default
  `wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net`).
- `NVOY_HTTP_PORT` — if set, serve the Streamable HTTP transport instead of
  stdio (`0` = ephemeral port). Binds `127.0.0.1`; set `NVOY_HTTP_HOST` to
  expose it (an explicit operator act — the server carries an agent key and
  delegated data).
- `NVOY_SUBSCRIBE_POLL_MS` (default 15000), `NVOY_SWEEP_MS`
  (auto_relinquish sweep, default 30000).

Publish a kind-0 profile for the agent (name / about) so delegator consoles
render it meaningfully; optional.

## Claude Desktop config

Merge into `claude_desktop_config.json` (Settings → Developer → Edit Config).
See [`examples/claude-desktop.json`](../examples/claude-desktop.json) for both
an nsec and an ncryptsec-file variant. Minimal:

```json
{
  "mcpServers": {
    "nvoy": {
      "command": "node",
      "args": ["/ABSOLUTE/PATH/TO/nvoy/mcp/dist/server.js"],
      "env": {
        "NVOY_NCRYPTSEC_FILE": "/ABSOLUTE/PATH/TO/agent.ncryptsec",
        "NVOY_NCRYPTSEC_PASSPHRASE": "your-passphrase",
        "NVOY_RELAYS": "wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net"
      }
    }
  }
}
```

## Generic MCP client config

Any MCP client that spawns a stdio server works the same way — command
`node`, arg the absolute path to `dist/server.js` (or the `nvoy-mcp` bin if
globally installed), identity + relays in the environment. For the HTTP
transport, launch with `NVOY_HTTP_PORT=3000` and point the client at
`http://127.0.0.1:3000/mcp`.

## Tool reference

| Tool | Input | Output |
| :-- | :-- | :-- |
| `nvoy_whoami` | — | agent npub, relay set, kind-0 metadata if published |
| `nvoy_grants_list` | — | held grants: `{ d, author_npub, scope_name, purpose, expires_at, terms, v, status }` (`status`: `active` \| `expired` \| `revoked-detected` \| `relinquished`) |
| `nvoy_scope_read` | `{ d, author_npub, max_age? }` | decrypted scope JSON + `{ v, fetched_at, terms, nvoy_no_persist }`. `max_age: 0` forces a fresh fetch (bypasses the 60s cache) |
| `nvoy_scope_subscribe` | `{ d, author_npub }` | on HTTP: streams `notifications/resources/updated`; on stdio: arms cache invalidation so the next read is fresh |
| `nvoy_outbox_write` | `{ payload, delegator_npub? }` | upserts the agent's own 30440 and grants it back to the delegator (bidirectional flow, §6.5) |
| `nvoy_request_access` | `{ delegator_npub, purpose }` | gift-wrapped access request → renders as a pending approval in the delegator console |
| `nvoy_grant_relinquish` | `{ d, author_npub, reason? }` | agent self-revocation (§6.6): zeroize scope key + cached plaintext, mark relinquished, notify the delegator |

Active scopes are also exposed as MCP **resources** (`nvoy://{author_npub}/{d}`)
for resource-oriented clients.

**Revocation is a first-class error.** When a delegator rotates you out, the
next `nvoy_scope_read` returns an MCP error
`{ code: "NVOY_GRANT_REVOKED", d, author_npub, notice? }` — a clean,
actionable signal, not a decrypt-exception trace. The runtime zeroizes its
cached plaintext and scope key for that scope on detection.

## Security note

- **`no_persist`, `redelegate: false`, and relinquishment are *compliance*
  guarantees, not cryptographic ones.** This runtime honors them mechanically
  (no disk writes, no re-wrapping keys to third parties, key destroyed on
  relinquish). A modified runtime could ignore them. The delegator's real
  lever is **rotation**, which ends future access unconditionally.
- **The agent key is the operator's responsibility.** `NVOY_NSEC` leaves a
  raw key in the environment (and possibly shell history / process listings).
  Prefer `NVOY_NCRYPTSEC_FILE`, which keeps the key on disk only as a
  passphrase-encrypted NIP-49 ncryptsec. The server writes no key material
  and no scope plaintext to disk (asserted by `npm run egress` and
  `npm run nopersist` at the repo root).
- Full threat model: [`SECURITY.md`](../SECURITY.md).

MIT.
