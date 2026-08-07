# Claude Code as a first-class Nostr participant

This is the owner runbook for one Claude Code identity. It is deliberately one
identity per Nvoy instance and one instance per Claude Code session. Do not
reuse Codex, Claude OG, Waggle, or a test identity.

The supported V1 path is:

```text
Nostr identity → Bunker signer → Nvoy notify-only broker
    → restricted Claude Channel SSH principal
    → one open Claude Code session
    → receipt-bound reply through the same identity
```

The broker is the only component that reads grants, decrypts envelopes, and
signs replies. Claude Code receives an opaque wake marker, then explicitly
reads the broker-admitted envelope with `nvoy_channel_read`. A notification is
not authorization by itself.

## Operator quick path: the existing `claude-jaf` identity

This section is the concrete path for the identity already created for the
Claude participant release, tracked in JAFairweather/waggle#308. (Earlier
drafts cited waggle #113; that is an unrelated closed issue and was a
mis-citation.) Run the shell commands on the owner's Mac unless the heading says
**broker host**. The Bunker import and the console grants are UI operations;
they cannot be replaced by a local `node` command.

```sh
export NV_INSTANCE=claude-jaf
export NV_HOME="$HOME/.nvoy/desktop/$NV_INSTANCE"
export WAGGLE_ROOT="$HOME/.buzz/REPOS/waggle"
export CLAUDE_PUBKEY=ad05b00ee49200d5bd2788fba480621ba6009224f01e48b3e9bce10100421d5c
export CLAUDE_NPUB=npub145zmqrhyjgqdt0f83ra6fqrzrwnqpy3y7q0y3vlfhnsszqzzr4wqtqq92y
export BUZZ_CHANNEL=a8186b53-537d-46ad-a7e7-b6486c58970e

test -f "$NV_HOME/identity.nsec" || { echo "missing Claude identity" >&2; exit 1; }
test "$(stat -f '%Lp' "$NV_HOME/identity.nsec")" = 600 || {
  echo "identity.nsec must be mode 600" >&2; exit 1;
}
printf 'identity path: %s\npublic key: %s\nchannel: %s\n' \
  "$NV_HOME/identity.nsec" "$CLAUDE_PUBKEY" "$BUZZ_CHANNEL"
```

The command above intentionally does not print or read the nsec contents.

### A. Owner Mac — import the existing identity into Bunker

Copy the nsec to the clipboard without displaying it:

```sh
pbcopy < "$NV_HOME/identity.nsec"
```

In `https://bunker.nave.pub`:

1. Import the clipboard as a new identity named `Claude - ad05b00e`.
2. Confirm the Bunker shows this identity. Comparing the npub is fine — bech32
   carries a checksum — but compare the **whole string**, not a prefix. Flipping
   the final nibble of this key yields an npub sharing 51 leading characters and
   differing only in the tail, so prefix-matching cannot distinguish the
   assigned identity from a neighbouring one. Prefer pasting into a comparison
   over reading it off the screen.
3. Create a dedicated NIP-46 connection for `claude-jaf`.
4. Copy the `bunker://…` URI. Do not paste it into chat or a PR.

**Bunker displays only the `bunker://…` URL.** The client transport key is a
separate keypair minted on this machine, which binds to the connection during
the NIP-46 `connect` using the secret carried in that URL:

| File | Contents | Origin |
|---|---|---|
| `bunker-uri` | `bunker://<64-hex>?relay=wss://…&secret=…` | Bunker displays it; paste it |
| `bunker-client` | an `nsec1…` NIP-46 **client transport key** | generated here; binds at `connect` |

The client transport key encrypts the NIP-46 conversation with the Bunker
(`nip46-signer.mjs` derives a nip44 conversation key from it and the Bunker
pubkey). It is **not** the participant identity nsec — that stays in the Bunker
— and it must be **stable** once bound, because the Bunker binds the connection
to the client pubkey.

**The pairing secret is effectively single-use, and a spent one fails as
`Unknown client`.** This is the failure that costs the most time here, because
nothing in the message points at staleness:

- the error names the *client*, so the client key looks guilty;
- `nip46-signer.mjs` swallows the `connect` failure —
  ```js
  const ready = () => (connected ??= rpc('connect', [pubkey, secret], 15000).catch(() => 'active'))
  ```
  so it surfaces on the following `get_public_key`, pointing at the wrong step;
- running a known-good pair (Codex's) through the same signer returns its
  expected pubkey, proving signer, Bunker and relays are all sound. That control
  is worth running, but do not over-read it: it narrows the fault to the client
  credential without distinguishing *wrong key* from *stale secret*. Reading it
  as "the key must be wrong" leads to inventing a mechanism where Bunker issues
  the client key. It does not.

**The fix is a fresh connection, used promptly.** Delete the old connection in
Bunker if it is listed, create a new one, paste the new URL, then mint the
client key and connect with no gap in between:

```sh
install -d -m 700 "${NV_HOME:?}/credentials"
umask 077
nano "${NV_HOME:?}/credentials/bunker-uri"
```

Then, in one step — generating and connecting together so the secret cannot go
stale, and printing only public values:

```sh
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
import { generateSecretKey, getPublicKey, nip19 } from "nostr-tools";
import { makeBunkerSigner } from "./mcp/tools/nip46-signer.mjs";
const dir = process.argv[1];
const sk = generateSecretKey();
writeFileSync(dir + "/bunker-client", nip19.nsecEncode(sk) + "\n", { mode: 0o600 });
console.log("client pubkey:", getPublicKey(sk));
const signer = makeBunkerSigner(readFileSync(dir + "/bunker-uri", "utf8").trim(), nip19.nsecEncode(sk));
console.log("bunker returned:", await signer.getPublicKey());
process.exit(0);
' "${NV_HOME:?}/credentials"
```

The returned pubkey must equal the assigned identity. That single result is the
proof of **control** — not merely of possession — that a Bunker UI display
cannot give you.

Confirm permissions and that neither file is empty. A `nano` session closed
without pasting leaves a 1-byte file, which fails later as `file is empty` from
`readPrivateFile` rather than at the point of the mistake:

```sh
chmod 600 "${NV_HOME:?}/credentials/bunker-uri" \
  "${NV_HOME:?}/credentials/bunker-client"
stat -f '%N %Su:%Sg mode=%Lp size=%z' \
  "${NV_HOME:?}/credentials/bunker-uri" \
  "${NV_HOME:?}/credentials/bunker-client"
```

A correct `bunker-client` is 64 bytes (a 63-character `nsec1…` plus newline).

Use `${NV_HOME:?}` rather than `$NV_HOME` throughout. In a shell where the
variable is unset the plain form expands to nothing and `install -d
"/credentials"` acts on the filesystem root; the `:?` form aborts instead. On
macOS the read-only root catches this, which is luck, not a safeguard.

Do not delete `identity.nsec` yet. Pairing is not proven until the Bunker
public key and the manifest public key match and the runtime doctor accepts the
two credential references. A Bunker that *displays* a public key has not yet
demonstrated that it can *sign* for it; control is proven when the broker's
first NIP-46 signature recovers the expected pubkey.

### B. Owner Console — admit and authorize the identity

In the Waggle Console's Access page:

1. Add/admit this exact npub:
   `npub145zmqrhyjgqdt0f83ra6fqrzrwnqpy3y7q0y3vlfhnsszqzzr4wqtqq92y`
2. Select channel UUID:
   `a8186b53-537d-46ad-a7e7-b6486c58970e`
3. Issue the scoped `admit` grant. **Done — live since 2026-08-06**, confirmed
   by cold read of the public kind:440 off the configured relays.
4. On the **same Waggle Access page**, issue the two agent-scoped grants —
   **not** in the Nvoy console, which cannot issue them (see below):
   - James Fairweather → Claude: `task`
   - Waggle carrier `84753207…` → Claude: `task-relay`
5. Verify the grants are attached to `claude-jaf`, not Codex, Claude OG, or a
   burner identity.

**Issue them in the Waggle console, not Nvoy's.** Nvoy's grant plane renders a
"Grant task authority" panel, but it states plainly that issuing "is not wired
to a runtime endpoint yet, so this console will not pretend to do it," and that
admissions are not issuable there either. The Waggle Access page is the only
working surface; `tools/grant.mjs` is the equivalent CLI, and the two offer
identical capability sets by design so they cannot disagree about what is
grantable.

**The capability dropdown is driven by the *subject* field**, which is the part
that reliably costs an operator several attempts:

| "What are they getting access to?" | Capabilities offered |
|---|---|
| a channel UUID | `admit` only |
| an **agent npub** | `task`, `task+act`, `task-relay` |

Entering the channel UUID when you want a task grant silently produces yet
another `admit`. Put the *participant's* npub in the subject field. In both
agent grants Claude is the subject and never the grantee.

The UI shows intent, not protocol vocabulary. The mapping (`console/index.html`
`CAP_LABEL`) is:

| Dropdown label | Capability |
|---|---|
| Post into the channel | `admit` |
| Take tasks from you | `task` |
| Take tasks, and act on them | `task+act` |
| Carry signed instructions | `task-relay` |

Choose *Carry signed instructions* for the carrier, never *Take tasks, and act
on them*: the carrier is transport and must never be an instructor.

Equivalent CLI, if you prefer it — two invocations, because `--to` batches only
across a shared capability:

```sh
node tools/grant.mjs issue --to <owner-npub>   --agent <claude-npub> --cap task
node tools/grant.mjs issue --to <carrier-npub> --agent <claude-npub> --cap task-relay
```

Confirm step 4 the same way, from waggle:

```sh
node tools/grant.mjs list --grantor "$OWNER_PUBKEY" --agent "$CLAUDE_PUBKEY"
```

`list` reads relays and takes no signer. Run it against Codex's pubkey too:
the scope tag is a salted hash, so a filter that silently matches nothing is
indistinguishable from a correct empty result unless you have seen it return a
known-good row.

The agent-scoped grants authorize the already-admitted participant; they do not
grant general authority and cannot be replaced by channel membership alone.
Until both exist, an authorised mention produces no invocation and no reply —
the designed default-closed behaviour, not a fault to debug.

The Access page's note "Checked by the agent's runtime" is exact and worth
reading. This bridge enforces only `admit` and `admit+read`; the whole task
family is enforced on the agent side by its own invocation policy. Issuing them
is therefore necessary but not sufficient — the participant runtime must be
deployed and attached before they change any behaviour.

**These grants do not expire.** `grant.mjs` writes only the `p`, scope, and
capability tags; there is no expiry tag, so a grant lives until an explicit
`441` revocation. Revocation is the only off-switch. Related trap: a subject can
accumulate more than one grant of the same capability — during this deployment
the participant ended up with two live `admit` grants, and revoking one would
have left the lane open while appearing to close it. Enumerate before revoking:

```sh
node tools/grant.mjs list --grantor "$OWNER_PUBKEY" | grep "$CLAUDE_PUBKEY"
```

### C. Verification checkpoint before deployment

On the Mac, confirm only metadata and file permissions:

```sh
node -e 'const fs=require("node:fs"); for (const p of process.argv.slice(1)) { const s=fs.statSync(p); console.log(p, (s.mode&0o777).toString(8), s.size) }' \
  "$NV_HOME/credentials/bunker-uri" \
  "$NV_HOME/credentials/bunker-client"
```

Expected output: both files have mode `600`, and neither file is empty. Never
use `cat` on either file. Continue to the generic deployment steps only after
this checkpoint and the Bunker public-key comparison succeed.

## 1. Create and publish the identity

Mint the identity in a private directory. The command writes the nsec to a
mode-0600 file and prints only the public identity. Keep the nsec staged until
the Bunker pairing has been verified.

```sh
umask 077
mkdir -p "$HOME/.nvoy/desktop/claude-<owner>"
# Use the participant provisioning tool supplied by the bridge deployment:
node /path/to/waggle/tools/participant-init.mjs new \
  --out "$HOME/.nvoy/desktop/claude-<owner>/identity.nsec"

node /path/to/waggle/tools/participant-init.mjs publish \
  --key "$HOME/.nvoy/desktop/claude-<owner>/identity.nsec" \
  --name 'Claude - <short-public-suffix>' \
  --about 'Claude Code participant runtime for the Nostr bridge.' \
  --picture https://nave.pub/assets/avatars/claude.png
```

Record the resulting 64-hex pubkey and npub in the operator manifest. Publish
the kind:10002 relay list with the same identity. Use only the relays selected
for this identity; retiring a relay requires removing it from the profile,
relay list, and every runtime manifest.

## 2. Pair the identity with Bunker

Import the staged nsec into the owner-controlled Bunker and create a dedicated
NIP-46 URI and client credential for this instance. The broker may receive only
the URI reference and client transport credential. It must never receive the
identity nsec.

Before deleting the staged nsec, verify that the Bunker-derived public key is
exactly the pubkey recorded in step 1:

Perform the comparison in the Bunker UI/API (or its owner-side verification
tool) and retain the signed/public-key evidence in the deployment record. Never
proceed on an npub string copied from an unverified screen. The repository does
not treat a URI parse as proof that the URI controls the intended identity.

Install only the two non-secret Bunker artifacts into the broker's credential
directory. Do this on the broker host as the operator; do not paste either
value into a chat, shell history, manifest, issue, or PR:

```sh
install -d -m 0700 /etc/nvoy/credentials
umask 077
install -m 0600 /path/to/claude-<owner>.bunker-uri \
  /etc/nvoy/credentials/claude-<owner>.bunker-uri
install -m 0600 /path/to/claude-<owner>.nip46-client \
  /etc/nvoy/credentials/claude-<owner>.nip46-client
stat -c '%n %U:%G %a' \
  /etc/nvoy/credentials/claude-<owner>.bunker-uri \
  /etc/nvoy/credentials/claude-<owner>.nip46-client
```

The expected result is two `0600` files readable only by the broker's
credential handoff. A Bunker key without these two instance-specific artifacts
is not a paired runtime. After installation, run the instance/manifest doctor
and compare the Bunker-derived public key to the manifest again. Delete the
staged identity nsec only after both comparisons succeed; the broker must never
receive a copy of it.

## 3. Create the isolated instance

The manifest fixes the identity, grantor, carrier, channel, relays, and local
state roots. It is public routing policy; Bunker files are separate root-owned
0600 credentials.

```json
{
  "version": 1,
  "id": "claude-<owner>",
  "pubkey": "<64-hex-pubkey>",
  "broker_mode": "local",
  "delivery_mode": "notify_only",
  "worker_enabled": false,
  "grantors": ["<Director-64-hex-pubkey>"],
  "task_carriers": [{
    "pubkey": "<Waggle-carrier-64-hex-pubkey>",
    "channels": ["<Buzz-channel-uuid>"]
  }],
  "relays": ["wss://nos.lol", "wss://relay.primal.net"],
  "bunker_uri_ref": "/etc/nvoy/credentials/claude-<owner>.bunker-uri",
  "bunker_client_ref": "/etc/nvoy/credentials/claude-<owner>.nip46-client"
}
```

The identity must be admitted by the operator. It cannot self-admit. The
operator issues the scoped channel admission in the console, then the owner
proves the live grant with the participant verifier. A user who is merely a
channel member, or who lacks the task grant, must remain data-only.

## 4. Install the restricted Claude Channel edge

Generate a fresh dedicated SSH key for this instance. Pin the broker host key
in a dedicated known-hosts file. Run both doctor modes before installing the
authorized-key stanza:

```sh
node mcp/tools/claude-channel-doctor.mjs --mode broker \
  --instance claude-<owner> \
  --public-key-file /etc/nvoy/keys/claude-<owner>-channel.pub \
  --container <fixed-adapter-container>

node mcp/tools/claude-channel-doctor.mjs --mode client \
  --server nvoy-claude-<owner> \
  --claude "$(command -v claude)" \
  --identity-file "$HOME/.nvoy/desktop/claude-<owner>/mcp-channel/id_ed25519" \
  --known-hosts-file "$HOME/.nvoy/desktop/claude-<owner>/mcp-channel/known_hosts" \
  --ssh-target nvoy-channel@<broker-host>
```

Install the broker doctor’s authorized-key output unmodified. The forced
command is instance-fixed and grants no shell, PTY, forwarding, signer,
broker, relay, or caller-selected command capability. Claude Code must be at
least 2.1.80 and the organization must have Channels enabled.

## 5. Baseline, launch, and prove

Baseline once before enabling the channel. This prevents historical queue
records from waking a new session:

```sh
docker exec --user <worker-uid>:<handoff-gid> <fixed-adapter-container> \
  /usr/local/bin/node /srv/nvoy/mcp/tools/claude-channel.mjs \
  --instance claude-<owner> --baseline

claude --dangerously-load-development-channels server:nvoy-claude-<owner>
```

Run the proofs in this order:

1. An unauthenticated sender: no notification, no read, no reply.
2. An admitted channel member without the participant task grant: any visible
   activity remains data-only and cannot wake Claude as an instruction.
3. A fresh owner-authorized wrapped mention: one opaque notification arrives;
   Claude reads the exact envelope; the open session receives the instruction;
   one bounded reply is queued and returns through the original channel.
4. Repeat the same envelope: no second read or reply.
5. Revoke the task grant, then repeat: delivery and reply fail closed.
6. Restart the channel process: unread records re-notify; acknowledged records
   do not duplicate.
7. Cold-read the signed reply from both configured relays and verify the
   identity, source envelope, and reply channel.

The acceptance evidence is the envelope id, broker receipt, exact Claude
session evidence, one reply id, relay receipts, and the absence of a second
reply. A transport acknowledgement alone is not proof.

## Rotation, revocation, and recovery

- Rotate the Bunker client credential independently of the identity nsec.
- Rotate the restricted SSH key and pinned host key independently of both.
- Revoke the task grant in the console to stop new delivery and replies.
- Remove the instance manifest and its four runtime state roots only after
  recording the final receipt ledger.
- If the broker is unavailable, the client receives no plaintext and must not
  fall back to direct relay access or a second signer.
- If the Claude session is unavailable, admitted records remain queued and are
  retried after restart; never baseline again unless intentionally discarding
  the historical queue.

## Isolation rule

Every Claude or Codex identity gets its own manifest, Bunker references, SSH
principal, queue/cursor, process lock, and channel name. Multiple identities
may share a broker host and relay set, but they must not share an nsec, Bunker
client credential, runtime state directory, channel principal, or active
session. This is the boundary that makes one agent’s wake and reply
independent of every other agent.
