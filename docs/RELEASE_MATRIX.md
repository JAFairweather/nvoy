# Nostr participant release evidence

This matrix is the release boundary for the Codex and Claude Code participant paths. A green
unit test is evidence for the named invariant only; it is not evidence that a remote host,
organization setting, relay, or live recipient has been configured.

| Area | Evidence | Status |
|---|---|---|
| Grant-authorized channel carry | `test/channel-task-carry.mjs`, `test/invocation-threat-chain.mjs` | Proven locally |
| Two-grant wake policy | original author `task` + carrier `task-relay`, fixed channel and identity | Proven locally |
| Unauthenticated / wrong-grant / wrong-carrier / stale / replay / revoked negatives | `test/invocation-threat-chain.mjs`, `test/instance-runtime.mjs` | Proven locally |
| Keyless broker boundary | watcher, broker, adapter, and worker credential separation tests | Proven locally |
| Codex desktop binding | `test/codex-app-server-completion.mjs`, `test/codex-app-server-long-thread.mjs`, `test/macos-desktop-adapter.mjs` | Proven locally |
| Codex crash/retry and duplicate protection | app-server delivery, durable journal, reply-queue, and restart tests | Proven locally |
| Claude Channel/MCP boundary | `test/claude-channel.mjs`, `test/claude-channel-doctor.mjs` | Proven locally |
| Claude notification → explicit read → bounded reply | `test/claude-channel.mjs` | Proven locally |
| Claude identity isolation | `test/instance-runtime.mjs` and channel lock/manifest checks | Proven locally |
| Historical queue safety | baseline tests for Codex and Claude channel paths | Proven locally |
| Full Nvoy suite | `npm test` | Passed locally; Docker-only container test is host-dependent |
| Codex/Claude operator documentation | `docs/MACOS_DESKTOP_BINDER.md`, `docs/CLAUDE_CODE_NOSTR_PARTICIPANT.md`, `docs/RUNTIME_SUPERVISOR.md` | Published in this release branch |
| Fresh live Codex wrapped mention | requires the configured Mac App Server session, grants, and relay path | Live operator proof required |
| Claude channel `admit` grant | cold-read of the public kind:440 off the configured relays, 2026-08-06 | Live, verified |
| Claude participant-scoped `task` / `task-relay` grants | same cold read, filtered to `ad05b00e…` as agent subject | **Absent** — `admit` alone cannot wake; wake path fails closed until both are issued |
| Claude Bunker pairing | derived public key compared against `ad05b00e…` | Not proven; dedicated NIP-46 client credential not yet created |
| Fresh live Claude wrapped mention | requires the grants above, Claude Code Channels enabled by the organization, and a running session | Live operator proof required |
| Independent tripwire delivery | requires Bunker pairing, root installation, and recipient cold-read drill | Live host proof required |
| Native foreign-signed rendering | requires Buzz platform support | Upstream dependency |
| Correct Buzz broadcast help | requires Buzz upstream merge | Upstream dependency |

## Release rule

The implementation is not called live merely because an MCP process starts. A live release needs
one fresh wrapped mention visibly handled by the intended session, one receipt-bound reply in the
source channel, a duplicate/restart check, and the corresponding negative control. The operator
must record the exact identity, instance, project/session binding, source event, reply receipt,
and time of the proof without recording any nsec, Bunker URI, or plaintext secret.

## Deployment rule

The broker is the only place that decrypts, revalidates grants, selects a recipient, signs, and
publishes. The Mac/Desktop or Claude process is a keyless consumer. Install one supervised
instance per participant identity, baseline its queue before enabling live delivery, and use the
doctor command before accepting a fresh wrapped mention.
