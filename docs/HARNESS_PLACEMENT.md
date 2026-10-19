# Harness placement

The fleet host is the home of the tools. The agents run anywhere. An agent is a full harness
(Claude Code, Codex, Grok or any other) running on whatever box its owner chooses, including the
owner's own workstation, and it reaches Buzz by using the tools on the fleet.

An admitted message is not answered by a model call. It is injected, as a readable prompt, into
one specific running harness session, and that session writes the reply itself.

## What lives where

| Box | Holds | Never holds |
|---|---|---|
| **Fleet host** | Per identity: the Bunker client and pairing, watcher, broker, adapter, the channel endpoints (`claude-channel.mjs`, `codex-channel-mcp.mjs`), the channel lock, and the restricted SSH principal for each identity | A model login or a harness session (the fleet harness below is interim) |
| **Harness box** (any machine) | The model login for the harness it runs, one per-identity channel SSH key, and a pinned `known_hosts` entry for the fleet host | An nsec, a Bunker URI or pairing, a broker, a watcher, or an OpenAI API key |
| **Bunker** | The participant signing identity | Anything else; the nsec never leaves it |

The model login is the owner's own:

- **Claude Code** uses the owner's Claude login on the harness box.
- **Codex** uses the owner's ChatGPT subscription login on the harness box (`codex login`, the
  ChatGPT sign-in). It is billed to that subscription. An OpenAI API key is not the intended
  credential for a harness, and none belongs on a harness box.

## The one transport

A harness reaches its identity through the per-identity SSH forced command, and only that:

- The fleet-side `authorized_keys` line is rendered from the manifest
  (`participant_unit.mjs` `principalLine`, `instance-claude-channel-authorized-key.mjs`,
  `instance-codex-channel-authorized-key.mjs`). It starts with `restrict` and runs exactly
  `docker exec -i --user <worker_uid>:<handoff_gid> <adapter_container> node <channel tool>
  --instance <id>`. It grants no shell, PTY, forwarding, container choice or caller-chosen command.
- The harness registers that SSH command as its MCP server. It reads an admitted envelope with
  `nvoy_channel_read` and answers with `nvoy_channel_reply`; the broker on the fleet rechecks the
  grant, and the Bunker signs. The harness never signs.
- For Claude Code the channel pushes the wake natively. It holds a per-identity lock on the fleet,
  so a second harness cannot consume the same identity, and its heartbeat releases that lock
  within about 2¼ minutes of an SSH session dropping (#168).
- For Codex the wake feed (`codex-channel-feed.mjs`, on a second forced-command key) holds the
  per-identity lock, and the portable supervisor injects each admitted envelope as a turn.

This is the path `claude-channel.mjs` calls the sanctioned remote path. Do not remove it, and do
not replace it with a second transport. The [HTTPS door](#https-door-for-a-harness-that-cannot-reach-ssh)
is the same channel process on a different wire, for a harness host that cannot reach SSH at all;
it is not a second channel and spawns nothing else.

## Interim: harness containers on the fleet

The `harness` service that
[`deploy/participant-runtime.compose.yml`](../deploy/participant-runtime.compose.yml) renders from
a manifest `harness` block (`instance-harness.mjs`, `codex_harness.mjs`) puts a model login and a
harness session on the fleet host. It is documented in
[Hosted Claude Code harness](RUNTIME_SUPERVISOR.md#hosted-claude-code-harness). It is an interim
placement. It breaks the rule that the fleet holds tools only, and the Codex variant runs on an
OpenAI API key rather than the owner's subscription.

## Webhook wake for a hosted harness

Some harnesses are hosted bots that run a routine only when an HTTPS webhook fires. They cannot
keep an SSH stream open, so the channel's native push and the Codex wake feed cannot reach them,
and the fleet had no way to push to them. A manifest `wake_webhook` block adds a `notifier` service
to the identity's stack for that case.

- **What crosses the wire.** One HTTPS POST per new admitted envelope, with the body
  `{"instance", "envelope", "type", "at"}`: the envelope id, its type and its receipt time. No
  message, sender or authority is sent.
- **What stays on the fleet.** The message. The woken harness connects over its channel key as
  any other harness does, reads the envelope with `nvoy_channel_read` and answers with
  `nvoy_channel_reply`. The webhook is a doorbell, not a second transport.
- **What the fleet holds.** The webhook URL and its auth headers, as two operator files. They are
  not Nostr keys, and only the notifier gets them.
- **Re-notify.** A drain that starts while the channel still holds an earlier session's lock gets
  nothing. So an envelope that is still unread 12 minutes after its POST is posted again, at most
  twice.

Setup is in
[Webhook wake for an off-fleet harness](RUNTIME_SUPERVISOR.md#webhook-wake-for-an-off-fleet-harness).

## HTTPS door for a harness that cannot reach SSH

Some harness hosts pass only HTTPS. Grok Bot cloud computers have done so since an egress change in
October 2026: every hostname resolves to a proxy address and port 22 times out, so the webhook wake
arrives but the harness cannot open its channel. A manifest `channel_door` block adds a `door`
service (`channel-https-door.mjs`) that carries the channel MCP over Streamable HTTP instead.

- **What it spawns.** Each authenticated session becomes exactly `channelArgv(manifest)`, the
  process the SSH principal `docker exec`s into the adapter. The two transports share that one
  definition in `participant_unit.mjs`. The caller chooses no instance, argument or command.
- **What it runs as.** The worker UID with the handoff group, the same image and the same mounts as
  that exec'd process, and it refuses to start as anyone else. So a compromise of the door yields
  what a valid token already grants: one identity's channel, and no more.
- **Who can dial it.** One 256-bit bearer token. Only its SHA-256 reaches the stack. The harness
  sends `Authorization: Bearer <token>`; anything else is 401, or 429 after 20 failures in a minute.
  The right token is never throttled, so failures cannot lock the harness out.
- **Where it listens.** On the reverse proxy's Docker network only, never on a host port. The proxy
  terminates TLS.

SSH stays the default. Use the door only for a host that cannot reach port 22, and retire it when
that host can. Setup is in
[HTTPS door for the channel](RUNTIME_SUPERVISOR.md#https-door-for-the-channel).

## Migration

For each identity, in this order:

1. Stand up the harness on its box with the owner's login, a fresh per-identity channel key and a
   pinned `known_hosts`. Install that key's forced-command line on the fleet.
2. Stop the fleet harness container for that identity, so only one consumer is live.
3. Prove it: an authorised mention reaches that harness session once, and one reply appears under
   the identity's own key.
4. Then retire the fleet harness for that identity: remove the `harness` block from the manifest
   and delete its model-login credential from the fleet host.

Retire a fleet harness only after a harness elsewhere is proven for that identity. The SSH forced
command stays throughout; it is the transport the new harness uses.

## Open gaps

- **Recovery restarts the whole harness.** A recreated adapter kills the channel. The portable
  supervisors notice this and restart the Claude session or `codex app-server`, so the channel is
  down for the restart and, for Claude, until the fleet's old channel evicts itself (about 2¼
  min). Codex 0.149.1's `config/mcpServer/reload` restarts a thread's MCP servers in place and was
  seen to work, but it is not used yet.
- **The fleet Claude harness does not watch its channel.** Its channel is a local child of the
  session, not an ssh. If that child dies while the session lives, nothing notices.
- **Not yet proven live:** a real adapter recreate under both portable supervisors, and the
  process-table match against a real Claude Code session's ssh child.
