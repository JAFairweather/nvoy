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
not replace it with a second transport.

## Interim: harness containers on the fleet

The `harness` service that
[`deploy/participant-runtime.compose.yml`](../deploy/participant-runtime.compose.yml) renders from
a manifest `harness` block (`instance-harness.mjs`, `codex_harness.mjs`) puts a model login and a
harness session on the fleet host. It is documented in
[Hosted Claude Code harness](RUNTIME_SUPERVISOR.md#hosted-claude-code-harness). It is an interim
placement. It breaks the rule that the fleet holds tools only, and the Codex variant runs on an
OpenAI API key rather than the owner's subscription.

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
