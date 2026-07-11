# Security — what Nvoy protects, and what it honestly cannot

Nvoy has two halves and no server of its own. The **console** is a pure
browser client: all delegator cryptography runs in your browser, and the
only things that leave it are ciphertext and routing envelopes. The **MCP
server** is the agent's runtime: it holds one agent key, dereferences
granted scopes at tool-call time, and writes nothing to disk. This document
is the threat model in plain language, starting with the build
specification's §2 **verbatim** — read the "NOT protected" half as carefully
as the first half. Tools that overclaim get people hurt.

## The one thing to understand first: terms are compliance, not cryptography

Nvoy delegates *data*, not access. A grant end-to-end-encrypts a scope to
the agent's key; revocation rotates that key so the agent's next dereference
simply fails to decrypt. **That** is cryptographic — it does not depend on
any server, policy engine, or the agent's goodwill.

The **terms** attached to a grant — `no_persist`, `redelegate: false`,
`expires_at`, `auto_relinquish` (§4 of the spec) — are a different class of
guarantee. They are honored *mechanically* by a compliant runtime, but they
are **not enforced by cryptography**. An agent operator who runs a modified
runtime can ignore every one of them. Their value is not enforcement against
a hostile operator; it is that:

1. a *compliant* runtime (this one) honors them automatically — no persist,
   no re-wrapping keys to third parties, key destroyed on relinquish; and
2. the delegator's Grant Index becomes a queryable ledger — *"exactly what
   data do my agents hold right now, under what terms, and show me the
   revocations"* — a ledger query, not archaeology across SaaS admin panels.

Every term is disclosed here and in the console UI as non-cryptographic.
Where a guarantee **is** cryptographic (encryption, revocation-by-rotation),
this document says so explicitly. Everywhere else, assume the honest weaker
claim.

## The threat model (spec §2, verbatim)

| **Actor** | **Holds** | **Role** |
| :-: | :-: | :-: |
| **Delegator** (human or org) | Own keypair; authors scopes; issues/rotates grants | Decides what each agent may see, for how long |
| **Agent** (workflow, MCP-attached LLM, automation) | Own keypair, held by its Nvoy MCP server | Dereferences granted scopes at run time; optionally publishes results back |
| **Agent operator** (may differ from delegator) | The agent's runtime + nsec | Semi-trusted: bound by grant terms it can honor mechanically, not by cryptography |
| **Relays** (untrusted) | Ciphertext only | Transport + storage |

**Protected:** scope contents; the delegation graph (who granted what to
which agent — invisible via gift wrap); revocation (rotated scope key =
agent's next dereference fails to decrypt).

**Explicitly NOT protected — state in SECURITY.md and in the delegator UI:**

- An agent that has read data may have persisted or acted on it before
  revocation. Mitigated by the stateless-dereference contract (§5), which
  compliant runtimes honor mechanically, but this is a *terms* guarantee,
  not a cryptographic one.
- Key holders can leak keys. Symmetric scope keys cannot be cryptographically
  attenuated (contrast macaroons/Biscuit). Attenuation is the **delegator's**
  job: issue separate, narrower scopes per sub-agent from the source.
  `redelegate: false` is an auditable term, not an enforcement.
- Relay-level metadata (IP, timing) as inherited from the base protocol.

## How the protections are implemented

**Scope contents.** A scope is a NIP-DA Scoped Data Set (kind 30440,
addressable, opaque `d` tag). Its payload is a NIP-44 v2 ciphertext under a
random 32-byte scope key that never touches a relay. Relays store the
ciphertext and the opaque id; they learn neither the field names nor the
values.

**The delegation graph.** Grants (kind 440) ride inside NIP-59 gift wraps
(kind 1059): a relay sees an ephemeral pubkey handing an opaque blob to a
recipient. Who granted what to which agent never appears on the wire in
readable form. Access-request and relinquish notices (an app-level rumor
kind that exists *only* inside gift wraps, never naked on a relay) are hidden
the same way. Every test suite asserts this from the adversary's side: after
each flow an "observer view" check confirms a hostile relay saw only kinds
30440 / 1059 / 10440 — no grant kind, no naked notices, no purpose strings,
no reasons, no grantee keys.

**Revocation, cryptographically.** Revoke rotates the scope key, bumps the
generation `v`, republishes the 30440 under the new key, and re-grants only
the survivors. A compliant agent's next `nvoy_scope_read` fails to decrypt,
is verified against a fresh fetch, and returns a well-shaped
`NVOY_GRANT_REVOKED` error — the runtime zeroizes its cached plaintext and
scope key for that scope. This is enforced by rotation, not by asking a
server for permission. For addressable events, the republish **is** the
destruction of the prior ciphertext on conforming relays.

**Hard expiry without agent cooperation.** `expires_at` is a *soft* term the
runtime honors. **Hard** expiry is the delegator console's TTL scheduler:
scheduled scope-key rotation at the deadline, re-granting only unexpired
grantees. Expiry never depends on the agent choosing to stop.

**The stateless-dereference contract (§5).** The runtime treats delegated
data as working context, never state: it dereferences the 30440 at tool-call
time through a short memory-only cache (default 60s; `max_age: 0` forces a
fresh fetch). With `no_persist: true` it makes no disk writes and keeps the
plaintext out of its logs; the cache is zeroized on TTL expiry, on
revocation, on relinquish, and on shutdown; tool results carry
`"nvoy_no_persist": true` so downstream frameworks can propagate the hint.
A conformance test (`npm run nopersist`) intercepts every `fs` write path
before app modules link and fails on any write containing scope plaintext,
and watches stderr for the same. **Consequence:** for a compliant agent,
rotation ≈ total revocation — the next run simply fails to decrypt.

**Zeroization, honestly.** The 32-byte scope keys are genuinely overwritten
(`Uint8Array.fill(0)`). Decoded JSON plaintext is JavaScript strings, which
are immutable — "scrub" there means severing every reference and letting GC
reclaim it. JavaScript cannot reliably zero all memory; a hostile OS-level
snapshot of a running process still sees whatever the GC has not reclaimed.
Disclosed, not hidden.

**Agent self-revocation (§6.6).** `nvoy_grant_relinquish` (or
`auto_relinquish` on expiry/completion) destroys the agent's scope key and
cached plaintext locally and sends a gift-wrapped relinquish notice to the
delegator, who rotates to make severance cryptographically final regardless
of agent honesty in phase 1. Ledger records the full arc: granted →
relinquished → rotated.

**Keys at rest — the console.** Nothing is persisted unless you opt in.
With a NIP-07 extension your key never touches the page. With the "protect
this key" offer, the only secret written to `localStorage` is a NIP-49
`ncryptsec` — your key encrypted with your passphrase (scrypt) — decrypted
locally on each visit. An unprotected pasted/generated key lives in
`sessionStorage` for the tab session only, until you take the protect offer
or close the tab. Other `localStorage` writes are non-secret: your relay
list and the ids of access requests you dismissed. The `npm run egress` test
asserts that the *only* key material reaching `localStorage` goes through
`nip49.encrypt`.

**Keys at rest — the MCP server.** The recommended identity is
`NVOY_NCRYPTSEC_FILE` + `NVOY_NCRYPTSEC_PASSPHRASE`: the agent key sits on
disk only as a NIP-49 ncryptsec, decrypted into memory at boot. `--ephemeral`
holds a fresh key in memory only (good for demos/CI). The server writes **no**
key material to disk and no scope plaintext anywhere but the in-memory cache
and MCP tool results; the egress test asserts `mcp/src` contains no
file-write of the key, and the only `fs.writeSync` is the stderr shutdown
line.

**No hidden egress.** `npm run egress` statically asserts that the console
and the MCP server contain no network destination beyond the configured
relays and esm.sh (the pinned module CDN the console loads), cross-checked
against the live config modules, plus import-time traps proving nothing
phones home just by being loaded. What that test does and does not cover is
documented in its header.

## What is NOT protected — the longer, honest version

**A compliant runtime is an assumption, not a guarantee.** `no_persist`,
`redelegate: false`, and relinquishment are enforced by *this* runtime. An
operator who runs a modified server can persist your data, re-wrap the scope
key to a third party, or keep a copy after relinquishing. The cryptographic
floor under all of it is the same as physics: once someone can read
plaintext, encryption cannot control what they do next. This is why the
delegator's real lever is **rotation** — it ends *future* access
unconditionally — and why narrow, short-lived scopes beat broad standing
ones.

**No attenuation / sub-delegation.** Symmetric scope keys cannot be
cryptographically narrowed the way a macaroon or Biscuit token can. If a
sub-agent needs less, the delegator must author a separate, narrower scope
and grant that — do not rely on `redelegate: false` to stop a determined
operator; it is an audit term. (Macaroon-style attenuable tokens are named
future work — spec §10.)

**Revoked parties keep what they already read.** Revocation ends access to
future updates and, on conforming relays, to the stored ciphertext. It
cannot reach into a machine that already decrypted the data. That is physics,
and the console says so at the moment you revoke.

**No audit log of reads.** There is no Nvoy server, so there is no record of
which agent decrypted which scope, when. The Grant Index is the delegator's
own ledger of what was *granted* and *rotated*; it is not a read log. If you
need provable access logs, this is the wrong tool.

**Deletion is a request.** NIP-01 addressable-event replacement destroys
prior ciphertext on honest relays; a malicious or negligent relay may keep
old ciphertext forever. Rotation makes the old scope key useless on
conforming relays; assume a hostile relay still holds the (now
undecryptable) bytes.

**Traffic metadata.** Relays see each pubkey's activity: when you publish,
how often, from what IP (use Tor/VPN if that matters). A global observer can
correlate who talks to which relays when. Nvoy hides scope contents and the
delegation graph, not the fact that you use it.

**A seized or compromised device.** An unlocked console decrypts everything
the delegator key can; a running MCP server holds its agent key and any
live-cached scope in memory. The at-rest artifacts are passphrase-encrypted
ncryptsecs, only as strong as the passphrase — a weak one falls to offline
guessing. And the nsec itself is the account: anyone holding it IS that
delegator or agent. There is no reset.

**The agent key is the operator's responsibility.** Passing `NVOY_NSEC` (a
raw nsec) in the environment or a shell profile is convenient but leaves the
key in process memory, environment listings, and possibly shell history and
process managers. Prefer `NVOY_NCRYPTSEC_FILE`. However you provision it,
custody of the agent key — and of the runtime that holds it — is the agent
operator's job, outside anything Nvoy can enforce. The optional TTL daemon
(`bin/nvoy-ttl.mjs`) likewise holds the *delegator's* nsec to rotate on
schedule while the console is closed; its header and the console banner say
so plainly. Run it only where that custody is acceptable.

**The code delivery path.** The console loads pinned modules from esm.sh
with no build step. You are trusting that CDN (and whoever serves you the
page) not to tamper with the code. Auditable, but not trustless — serve the
repo yourself if your threat model requires it. The MCP server is a Node
package you build and run locally; its supply chain is npm and the pinned
dependencies in `mcp/package.json`.

**Draft protocol.** Nvoy is built on draft NIP-DA
([review pending](https://github.com/nostr-protocol/nips/pull/2411)); kind
numbers are placeholders and may change. The app-level `nvoy` terms
extension and its notice kind are payload-level and claim nothing from the
NIP kind registry, but until the NIP settles, use throwaway keys and treat
delegations as ephemeral.

## Reporting

Found a hole? Open an issue at
<https://github.com/JAFairweather/nvoy/issues> — or, for anything sensitive,
contact the maintainer privately first.
