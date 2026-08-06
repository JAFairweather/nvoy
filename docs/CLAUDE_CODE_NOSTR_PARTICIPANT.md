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

This section is the concrete path for the identity already created for issue
#113. Run the shell commands on the owner's Mac unless the heading says
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
2. Confirm the Bunker shows public key `$CLAUDE_PUBKEY` (not merely the npub).
3. Create a dedicated NIP-46 connection for `claude-jaf`.
4. Copy the URI and the separate NIP-46 client credential; do not paste either
   into chat or a PR.

Save the two returned values locally, one value per file. This opens a local
editor; it does not print the values:

```sh
install -d -m 700 "$NV_HOME/credentials"
umask 077
${EDITOR:-vi} "$NV_HOME/credentials/bunker-uri"
${EDITOR:-vi} "$NV_HOME/credentials/bunker-client"
chmod 600 "$NV_HOME/credentials/bunker-uri" \
  "$NV_HOME/credentials/bunker-client"
stat -f '%N %Su:%Sg mode=%Lp size=%z' \
  "$NV_HOME/credentials/bunker-uri" \
  "$NV_HOME/credentials/bunker-client"
```

Do not delete `identity.nsec` yet. Pairing is not proven until the Bunker
public key and the manifest public key match and the runtime doctor accepts the
two credential references.

### B. Owner Console — admit and authorize the identity

In the Waggle Console's Access page:

1. Add/admit this exact npub:
   `npub145zmqrhyjgqdt0f83ra6fqrzrwnqpy3y7q0y3vlfhnsszqzzr4wqtqq92y`
2. Select channel UUID:
   `a8186b53-537d-46ad-a7e7-b6486c58970e`
3. Issue the scoped `admit` grant.
4. In Nvoy Console, create exactly these two grants:
   - James Fairweather → Claude: `task`
   - Waggle carrier → Claude: `task-relay`
5. Verify the grants are attached to `claude-jaf`, not Codex, Claude OG, or a
   burner identity.

The Nvoy grants authorize the already-admitted participant; they do not grant
general authority and cannot be replaced by channel membership alone.

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
