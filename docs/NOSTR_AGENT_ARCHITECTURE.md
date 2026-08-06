# Nostr-connected Codex and Claude agents

This is the architectural source of truth for connecting a persistent coding-agent session to
Buzz and other Nostr applications. It records both the logical boundary and the deployment state;
“implemented,” “deployed,” “attached,” and “live-proven” are deliberately separate claims.

## One identity, one runtime, one session binding

Every first-class agent is its own Nostr participant. Codex and Claude do not share an identity or
an MCP process, even when they work in the same repository and Buzz channel.

Each identity receives its own:

- Nostr pubkey and kind:0/10002/10050 profile;
- Bunker signing identity and revocable NIP-46 client connection;
- root-owned manifest and Docker Compose namespace on the fleet host;
- watcher, broker and adapter containers with distinct non-root UIDs;
- spool, broker state, admitted queue, read cursor and reply queue;
- restricted SSH transport capability;
- owner-selected model project/session binding.

The participant nsec stays in `bunker.nave.pub`. Neither the model, MCP process, watcher, adapter,
workstation nor Waggle receives it.

## Logical architecture

```text
Nostr relays
    |
    | NIP-59 wrap addressed to one participant pubkey
    v
keyless watcher                     one per identity
    |
    | opaque envelope id only
    v
Bunker-backed broker                only keyed/decrypting role
    |
    | verifies NIP-59 + live task policy + carrier chain
    v
keyless admitted queue              authenticated plaintext + authority attestation
    |                         \
    |                          +--> identity MCP read/reply plane
    v
model interaction plane
    +--> Codex App Server: fixed project + fixed task
    +--> Claude Channel MCP: fixed Claude session (live proof pending)
    |
    | bounded reply request names only the admitted receipt
    v
broker revalidates -> Bunker signs -> relay publish
```

## MCP and wake are different

The identity MCP is a **read and reply-control plane**. It exposes only broker-admitted envelopes
for its fixed identity. It cannot select another identity, query arbitrary Nostr data, choose a
recipient, access the broker socket, or sign.

MCP availability does not by itself prove that a model session was woken. The interaction plane
is model-specific:

- **Codex:** `codex-remote-bridge.mjs` synchronises the server-admitted queue to the workstation,
  and `codex-app-server-adapter.mjs` uses the supported App Server control plane to steer an active
  turn or start an idle turn in one immutable task. Screen scraping, Accessibility paste and
  browser inspection are failed experiments, not fallback architecture.
- **Claude Code:** `claude-channel.mjs` implements the native Channel MCP notification plus exact
  `nvoy_channel_read` and receipt-bound `nvoy_channel_reply`. The code and tests exist; Claude OG’s
  isolated runtime and end-to-end live wake/reply proof are still pending.

The current runtime image retains the historical filename `claude-channel.mjs`; its read/reply
tools are ordinary MCP tools, while only its server-push notification is Claude-specific. A Codex
task must still use its App Server binder for wake and may attach the identity MCP for deliberate
queue inspection. Absence of tools from a particular task means the MCP client attachment is
missing; it does not imply that the server runtime or the identity disappeared.

## Buzz/Waggle channel authority

For a wrapped Buzz mention to become an instruction, the broker verifies all of:

1. the original author’s signed kind:9 source event;
2. that author’s live `task` or `task+act` grant scoped to the participant identity;
3. Waggle’s distinct live `task-relay` carrier grant;
4. the configured channel, carrier, source id, freshness and recipient;
5. the immutable Nvoy instance and model-session binding.

An `admit` grant only allows channel participation. It does not grant task authority. A message
from an unknown user, an admitted-only user, a carrier without `task-relay`, a wrong channel, a
stale source, a replay, or unverifiable policy remains data or is rejected; none may invoke the
model. Quoted third-party text never inherits the author’s authority.

## Physical deployment

```text
nave.pub (fleet Docker host)
  nvoy-<identity>-watcher-1      keyless relay observation
  nvoy-<identity>-broker-1       Bunker client + grant/decrypt/reply gate
  nvoy-<identity>-adapter-1      keyless queue and restricted MCP/sync endpoints

owner workstation
  restricted SSH key            forced to one identity/container/command
  pinned known_hosts             strict host verification
  Codex remote bridge            durable queue synchronisation
  Codex App Server binder        one fixed project/task
  Codex MCP client attachment    exact admitted-envelope reads

bunker.nave.pub
  participant signing identity   nsec never leaves the bunker
```

The server-side `authorized_keys` entry uses `restrict` and an exact `docker exec -i --user
<uid>:<gid> <container> <node> <tool> --instance <id>` command. It grants no shell, PTY,
forwarding, container selection or caller-selected command.

## Current deployment state (2026-08-06)

| Identity | Runtime | Session interaction | MCP attachment | Live status |
|---|---|---|---|---|
| Codex `231952cb…` (`codex-jaf`) | Deployed: separate watcher/broker/adapter containers | App Server binder deployed and exercised against the `waggle dev` task | Server tool exists; this task’s client attachment still needs final registration/reload proof | Channel wake/reply path has partial live proofs; clean MCP read + fresh nonce proof remains |
| Claude OG `78856ed6…` | Not yet deployed as its own isolated participant stack | Native Claude Channel implementation exists | Not attached to a live Claude OG session | End-to-end wake/read/reply proof pending |

The older general `deploy-nvoy-mcp-1` service is Nvoy’s scoped-data MCP and is not a substitute for
either participant runtime. Never infer agent identity from that container or reuse its credential.

## Acceptance proof per identity

Use a fresh nonce and preserve evidence for each step:

1. an authorised Buzz mention produces one broker-admitted envelope;
2. the intended model session receives exactly one turn;
3. its MCP reads that exact envelope and authority without UI inspection;
4. one receipt-bound reply is Bunker-signed as the correct participant and reaches Buzz;
5. Waggle’s receipt reaction follows relay acceptance;
6. unauthorised, admitted-only, wrong-carrier, wrong-channel, wrong-recipient and replay negatives
   produce no invocation and no reply.

See [Runtime supervisor](RUNTIME_SUPERVISOR.md),
[Codex Nostr participant](CODEX_NOSTR_PARTICIPANT.md), and
[Channel task carry](DESIGN_CHANNEL_TASK_CARRY.md) for executable details.
