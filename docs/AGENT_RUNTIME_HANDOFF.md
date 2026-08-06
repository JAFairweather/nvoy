# Handoff: first-class Codex and Claude participants on Nostr

**Status:** continuity runbook · **Updated:** 2026-08-06

This is the shortest complete path for a successor agent to continue the Nvoy/Waggle participant
runtime work without rediscovering the architecture or repeating failed experiments. The intended
product is reusable: Nostr ingestion, identity custody, grant verification, durable queues, MCP
read/reply tools, and receipt-bound egress are shared. Only the final delivery edge into the model
session differs between Codex and Claude Code.

## 1. Product promise

An owner can mention a named agent in Buzz or another Nostr application and have that signed
message enter one preselected coding-agent project/task as an instruction. The agent can inspect
the exact authenticated envelope through its own MCP and propose a reply. A reply is published as
that participant only through the broker's receipt-bound, grant-revalidated signing path.

This is not a generic chatbot endpoint. An inbound event may not select an identity, runtime,
project, task, recipient, signer, channel, or tool permission.

## 2. Shared core and replaceable final mile

```text
signed Buzz/other-Nostr event
        |
        v
Waggle carrier (preserves complete signed source)
        |
        v
participant-specific relay watcher (keyless; envelope id only)
        |
        v
participant-specific Nvoy broker (Bunker-backed)
  - verifies NIP-59 and exact source signature
  - verifies live task + task-relay grant chain
  - decrypts only after those boundaries hold
  - writes an authenticated, durable admitted record
        |
        +------------------ identity MCP ------------------+
        |       exact list/read + receipt-bound reply      |
        |                                                   |
        v                                                   v
final-mile adapter                                  bounded reply request
  Codex: App Server control plane                           |
  Claude: native Claude Code Channel MCP                    v
        |                                           broker revalidates
        v                                                   |
one immutable project/task                                 v
                                                    Bunker signs NIP-17
                                                           |
                                                           v
                                                  Waggle -> source channel
```

The Docker-side implementation must not fork into “Codex Nvoy” and “Claude Nvoy.” Both use the
same watcher, broker, policy, admitted queue, MCP semantics, reply receipts, and deployment model.
The adapter is the plug-in boundary:

| Concern | Codex | Claude Code |
|---|---|---|
| Session ingress | local Codex App Server (`thread/read`, `thread/resume`, `turn/steer` or `turn/start`) | native Claude Code custom Channel notification |
| Session selection | immutable `codex_thread_id` and project root | one open Claude session configured with exactly one identity-scoped Channel server |
| Exact read/reply | fixed-instance Codex channel MCP | `nvoy_channel_read` / `nvoy_channel_reply` |
| UI automation | forbidden | forbidden |
| Current proof | partial live wake/reply; clean same-task MCP proof remains | implementation exists; distinct live runtime and end-to-end proof remain |

Do not restore Accessibility paste, AppleScript, global keystrokes, browser automation, or a
second competing CLI client. Those paths staged text without reliably creating a turn and are not
delivery evidence.

## 3. Identity assignment: never infer it from a name

The four values below are public identifiers, not credentials:

| Name | Hex pubkey | npub | Intended status |
|---|---|---|---|
| Codex - 231952cb | `231952cb5eb0652c04075f6a1b93e727819ed2ac0bf5238a96c6d2ca51617edd` | `npub1yvv49j67kpjjcpq8ta4phyl8y7qea54vp06j8z5kcmfv55tp0mws3cc0v4` | assigned to runtime `codex-jaf` and Codex task `waggle dev` |
| Claude - OG | `78856ed6c671b816290e3b390c9ab180933e33ba99125ce2f71aaf399904e148` | `npub10zzka4kxwxupv2gw8vusex43szfnuva6nyf9echhr2hnnxgyu9yqrkf56w` | historical Claude persona; user prefers this visible identity for Claude, but it is not automatically assigned to a new runtime |
| superseded Claude staging candidate | `89ca35f0b4a3d10a23d75e8e67aeca34dcb45b2869284d64f33d2011b70eb6c5` | `npub1389rtu9550gs5g7ht68x0tk2xnwtgkegdy5y6e8n85sprdcwkmzsadwpsw` | historical staging reference; do not admit, pair, or deploy |
| Claude participant (`claude-jaf`) | `ad05b00ee49200d5bd2788fba480621ba6009224f01e48b3e9bce10100421d5c` | `npub145zmqrhyjgqdt0f83ra6fqrzrwnqpy3y7q0y3vlfhnsszqzzr4wqtqq92y` | current distinct Claude identity; kind:0/10002 published; admission and isolated runtime deployment pending |

The current release assignment is `ad05b00e…`; `89ca35f0…` is retained only as a superseded
staging reference and must not be admitted or paired. Claude OG remains historical and is not
part of this runtime. Never read, copy, print, or use Claude OG's nsec merely because its public
identity is desired. Before starting `claude-jaf`, verify the Bunker-derived public key equals
`ad05b00e…` and record that evidence; do not proceed on a manifest or UI label alone.

## 4. One identity means one complete security domain

For each assigned participant create exactly one:

- Bunker identity and stable, revocable NIP-46 client pairing;
- root-owned instance manifest;
- Docker Compose namespace;
- watcher, broker, adapter, and optional worker identities with separate UIDs;
- spool, broker state, admitted queue, cursor, reply queue, and locks;
- restricted SSH key forced to one container, UID/GID, command, and instance;
- MCP server registration;
- immutable model project/task binding.

The participant nsec remains in `bunker.nave.pub`. The broker receives only its Bunker URI and
NIP-46 transport credential. The watcher, adapter, MCP client, model session, workstation, Waggle,
and worker receive neither the nsec nor the Bunker capability.

The older general `deploy-nvoy-mcp-1` scoped-data service is not either agent's participant
runtime. Never infer Codex or Claude identity from that container.

## 5. Required grants and configuration

Three authority classes are deliberately separate:

| Capability | Grantee | Grantor | Meaning |
|---|---|---|---|
| `admit` | participant identity | Buzz hive owner/operator | participant may speak through the configured Waggle channel lane |
| `task` or `task+act` | original human author | participant authority owner | that author may invoke this participant; `task+act` still does not expand OS/tool permissions |
| `task-relay` | Waggle carrier pubkey | participant authority owner | Waggle may carry independently signed channel instructions; it is never the instructor |

For a Buzz wrapped mention, all of these must also agree:

- original signed source event and author;
- participant recipient;
- configured Waggle carrier pubkey;
- allowed Buzz channel UUID;
- fresh live grants and non-revocation;
- manifest identity and fixed model session.

James's owner/grantor pubkey is `4010ac438206dc10018b814be3ea01ca6c92bcc22e9719e841d2413b287ea84d`.
The deployed Waggle carrier prefix is `84753207…`; re-read the production manifest/control state
for its complete current key rather than copying an old inventory. The `waggle-test` channel UUID
used by the present configuration is `a8186b53-537d-46ad-a7e7-b6486c58970e`.

An `admit` grant alone cannot wake an agent. A `task` grant without `task-relay` cannot trust a
private-channel carrier. A `task-relay` grant never authorizes Waggle's own prose as instruction.
Unknown, admitted-only, revoked, wrong-recipient, wrong-channel, wrong-carrier, stale, replayed, or
tampered traffic must produce no model invocation and no reply.

## 6. Current Codex deployment

- identity/runtime: `codex-jaf`, pubkey `231952cb…`;
- target task: `waggle dev`;
- task id: `019fce57-063d-7f50-b837-967d33ee384a`;
- Docker host: `nave.pub`, with separate watcher/broker/adapter containers;
- workstation bridge: restricted SSH queue sync plus local App Server adapter;
- App Server socket: operator-local, fixed by the desktop manifest;
- credential custody: Bunker-backed; desktop final mile is keyless;
- current status: wake/reply has partial live evidence, but the exact task still needs a clean
  proof that its identity MCP is attached, reads the same fresh envelope, and returns one
  receipt-bound reply without duplicate responders.

Before another live test, baseline historical queue state, prove only one local bridge/adapter is
running, and use a fresh nonce. Do not replay the accumulated review backlog.

## 7. Claude handoff: reuse the core, replace only the edge

After resolving the identity decision in section 3:

1. Put the chosen identity in a new root-owned `claude-jaf` manifest; never edit the Codex
   manifest into Claude.
2. Pair that identity to Bunker and stage only the Bunker URI plus stable NIP-46 client credential
   for the broker.
3. Issue and cold-read the participant's `admit` grant, James's `task`/`task+act` grant, and
   Waggle's `task-relay` grant for the same participant scope.
4. Render and start a separate Docker instance with its own watcher/broker/adapter users, volumes,
   queue, and restricted SSH principal.
5. Baseline the existing admitted queue under the exact worker UID/GID before enabling the live
   Channel.
6. Register one identity-scoped Claude Code MCP server whose command is only the restricted SSH
   stdio tunnel. Do not run `claude-channel.mjs` directly as the interactive user.
7. Start Claude Code with the research-preview custom Channel opt-in and keep that one session
   open. The channel emits only an opaque envelope notification; Claude must call
   `nvoy_channel_read` to obtain broker-admitted content.
8. Use `nvoy_channel_reply` for the exact envelope. The broker rechecks grants, chooses the fixed
   destination, signs through Bunker, and records completion.
9. Run the acceptance matrix in section 9 before claiming parity.

The Claude adapter is allowed to differ only where the model runtime requires it. It must preserve
the same identity isolation, admission chain, durable semantics, fixed-session selection, bounded
reply, and negative controls as Codex.

## 8. Deployment and release map

Canonical implementation files:

- `docs/NOSTR_AGENT_ARCHITECTURE.md` — architecture and deployment-state source of truth;
- `docs/RUNTIME_SUPERVISOR.md` — process, filesystem, Docker, and Claude Channel contract;
- `docs/CODEX_NOSTR_PARTICIPANT.md` — exact-task Codex behavior;
- `docs/MACOS_DESKTOP_BINDER.md` — Codex workstation/App Server edge;
- `docs/DESIGN_CHANNEL_TASK_CARRY.md` — dual-grant carrier protocol;
- `mcp/tools/instance-*` — isolated runtime roles and restricted endpoints;
- `mcp/tools/codex-remote-bridge.mjs` and `codex-app-server-adapter.mjs` — Codex edge;
- `mcp/tools/codex-channel-mcp.mjs` — Codex fixed-instance MCP read/reply plane;
- `mcp/tools/claude-channel.mjs` — Claude native Channel edge;
- `deploy/participant-runtime.compose.yml` and `render-instance-compose.mjs` — reference isolation;
- Waggle `docs/AGENT_PARTICIPANT_ARCHITECTURE.md` and Nvoy
  `docs/DESIGN_CHANNEL_TASK_CARRY.md` — both sides of the carry boundary.

Routine runtime release is pull-based from tested, merged `main` into immutable images. The host
runner changes images only; it must not rewrite manifests, grants, identities, Bunker pairings, or
routing policy. Production deploy evidence must identify the exact commit/image digest and all
instance health checks.

## 9. Required live acceptance matrix

For each identity use a fresh nonce and retain event, envelope, turn, reply, and reaction ids:

1. authorised mention -> exactly one admitted envelope;
2. exact intended project/task -> exactly one instruction turn;
3. same task's MCP -> exact-envelope read with original author and complete authority chain;
4. one bounded response -> one broker receipt-bound, Bunker-signed Nostr reply;
5. relay acceptance -> one Waggle thumbs-up reaction on the original source event;
6. restart between admission and delivery -> no loss and no duplicate turn;
7. revoke author `task` -> no invocation;
8. restore it, revoke carrier `task-relay` -> no invocation;
9. admitted-only author -> no invocation;
10. unknown author, wrong recipient, wrong channel, wrong carrier, stale source, replay, altered
    source content/signature/hash, and forged outer wrap -> no invocation and no reply;
11. second adapter/channel process -> refused by the per-instance lock;
12. secret-boundary checks -> watcher, adapter, MCP, worker, and workstation cannot read the nsec,
    Bunker pairing, broker socket, or another identity's queue.

“Published,” “admitted,” “runtime deployed,” “MCP attached,” “task woken,” “reply signed,” and
“reaction observed” are separate checkpoints. Report each independently.

## 10. Immediate continuation order

1. Preserve and finish any already-open exact-head PRs; do not duplicate them.
2. Verify the Bunker pairing for the assigned `ad05b00e…` Claude identity; keep `89ca…` staging-only.
3. Finish the Codex same-task MCP + fresh-nonce proof with one responder.
4. Deploy the selected Claude identity as a separate runtime and run the same proof through the
   Claude Code Channel edge.
5. Ask for design/code review only in private Buzz `waggle-test`; mention Buzz identities there,
   never similarly named GitHub accounts.
6. Continue the remaining Waggle/Nvoy issue queue after preserving live proof artifacts.

## 11. Successor orientation

Start with the private `~/.buzz/GUIDES/LAUNCH_PROMPT.md`, then read this file and the canonical
files in section 8. Inspect live manifests and public grant state before making claims. Never
print or move a secret during orientation. If local MCP tools are absent, distinguish “client not
attached to this task” from “server/runtime does not exist”; do not fall back to screen reading.
