# Agent Hook and Connect Patterns

| Field | Value |
|---|---|
| Status | Living runbook; patterns proven on 2026-08-18 unless marked otherwise |
| Audience | Nvoy/Waggle maintainers, desktop operators, agent owners |
| Scope | Local macOS hook, wake, app-server, and LaunchAgent patterns for first-class Nostr/Buzz agents |

## Core rules

1. **One identity, one explicit runtime seat.** Never silently fall back to a generic `nvoy` or another agent's signer/MCP identity.
2. **Process existence is only a precondition.** Health requires a positive, role-specific proof: queue movement, lock ownership, canary reply, or heartbeat.
3. **Missing signer/decrypt/relay/status is inconclusive, not idle.** A quiet result without capability proof is not an empty inbox.
4. **Supervision is `launchctl` registration, not PPID.** LaunchAgents are also parented to pid 1. The test is whether the label appears in `launchctl list` / `launchctl print`.
5. **Never key a liveness check to a recorded PID.** `KeepAlive` changes PIDs after respawn. Read the PID at check time.
6. **Do not grep for a token until you prove it exists as a field in the target format.** Rewrapped delivery may store the source event id inside content rather than as the row id.
7. **Owner and state need a shared ledger.** Relayed prose is lossy and slow enough to create duplicate work and false gaps.

## Pattern 1: Shared Codex Desktop daemon ingress

Use one managed Codex app-server as the sole task owner. Desktop, a remote TUI, and Nvoy all connect to that same owner over the local same-user Unix socket.

```text
Codex Desktop GUI  \
                    -> managed app-server daemon -> one writer lock -> one durable task
Nvoy ingress       /
optional TUI      /
```

Invariant:

```text
One task has one app-server owner. Every human or automated input producer routes through that owner.
```

### Proven local pieces

- daemon LaunchAgent: `pub.nave.codex.app-server-daemon`
- daemon command is pinned to a resolved release path, not `current`:
  `/Users/fairwja/.codex/packages/standalone/releases/0.147.0-aarch64-apple-darwin/bin/codex app-server --remote-control --listen unix://`
- Desktop selector installed via login environment agent:
  `CODEX_APP_SERVER_USE_LOCAL_DAEMON=1`
- ownership proof is PID equality, not process name:

```sh
DPID=$(launchctl print gui/$(id -u)/pub.nave.codex.app-server-daemon \
  | awk -F'= ' '/pid =/{gsub(/[ ;]/,"",$2); print $2}')

SOCKET_HOLDER=$(lsof -t ~/.codex/app-server-control/app-server-control.sock)
LOCK_HOLDER=$(lsof -t ~/.codex/thread-writer-locks/<thread-id>.lock)

test "$SOCKET_HOLDER" = "$DPID"
test "$LOCK_HOLDER" = "$DPID"
```

Correct signal:

```text
app-server-control.sock owner PID == target writer-lock owner PID == launchd daemon PID
```

Wrong signal:

```text
no embedded app-server process exists
```

An embedded app-server may exist and be harmless if it owns zero writer locks.

### Canary

Use:

```sh
node mcp/tools/codex-shared-daemon-canary.mjs --instance <id> [--root <instance-root>] [--no-drive]
```

Exit codes:

- `0`: owner match proven
- `1`: definite split/multiple holders
- `3`: inconclusive, not green

The canary must refuse empty-vs-empty comparisons. A stopped daemon and missing lock both produce empty strings; that is not success.

### Reboot/login caveat

`launchctl setenv` and ChatGPT Desktop are independent launchd jobs. There is no ordering guarantee at login. Therefore `launchctl getenv CODEX_APP_SERVER_USE_LOCAL_DAEMON` only proves the setter ran; it does not prove Desktop inherited the variable.

The reboot canary must drive or open the task and then verify ownership by PID equality.

### Version-skew caveat

Codex maintains a standalone updater process under `~/.codex/app-server-daemon/` and resolves through `~/.codex/packages/standalone/current`. Pinning the supervised daemon prevents silent symlink swaps, but creates possible skew: the updater can move `current` while the supervised daemon remains pinned to an older release.

Track in health:

- pinned daemon release path
- `current` symlink target
- `codex app-server daemon version`
- updater PID file and `processStartTime`

## Pattern 2: App-server delivery behavior

Nvoy's Codex adapter talks through `codex_app_server.mjs`.

Required behavior:

- active thread: `thread/read` -> find in-progress turn -> `turn/steer(expectedTurnId)`
- stale expectedTurnId: reconcile once from the server's actual active turn id
- idle thread: `thread/resume` -> `turn/start`
- daemon-owned idle thread may answer `thread/resume` with `already has an active writer`; that exact response falls through to `turn/start`
- unrelated `thread/resume` errors remain fatal

Test owner/status:

- retained test: `test/codex-app-server-active-writer.mjs`
- covers both directions:
  - exact active-writer text falls through to `turn/start`
  - unrelated resume error stays fatal

## Pattern 3: Waggle return-lane watcher supervision

Each local agent wake watcher should be a LaunchAgent with `KeepAlive=true` and a negative-control TERM proof.

Template shape:

```text
Label: pub.nave.nvoy.<instance>.agent-inbox
ProgramArguments:
  /opt/homebrew/bin/node
  /Users/fairwja/.buzz/REPOS/waggle-main/tools/agent-inbox.mjs
  --pubkey <agent-pubkey>
  --trust <bridge-pubkey>
  [--since <seconds>]
  --watch
  --jsonl
  --spool <agent-spool-dir>
  --on-message <hook-script>
EnvironmentVariables:
  HOME=/Users/fairwja
  PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin
  WAGGLE_BUNKER_URI_FILE=<existing local signer ref>
  WAGGLE_NIP46_CLIENT_NSEC_FILE=<existing local client ref>
RunAtLoad=true
KeepAlive=true
ThrottleInterval=10
StandardOutPath=<existing log dir>/agent-inbox-stdout.log
StandardErrorPath=<existing log dir>/agent-inbox-stderr.log
```

Do not copy or move key material. Reference the existing local credential files for that identity.

### Proven local watchers

- `pub.nave.nvoy.codex-jaf.agent-inbox` / DJ Codex watcher
- `pub.nave.nvoy.pi-dog.agent-inbox` / Pi Dog watcher
- `pub.nave.nvoy.mc-claude.agent-inbox` / MC Claude watcher

Each was proven by:

1. bootstrap plist
2. confirm wake-spool load in stderr
3. `TERM` current pid
4. confirm launchd respawn with a new pid

## Pattern 4: Nvoy bridge LaunchAgent

The Codex remote bridge is supervised separately:

```text
Label: pub.nave.nvoy.<id>.codex-bridge
ProgramArguments: node .../codex-remote-bridge.mjs --instance <id> --interval-ms 2000
NVOY_INSTANCE_ROOT=<local desktop instance root>
KeepAlive=true
ThrottleInterval=10
```

For renames, remember every site:

- plist filename
- `Label`
- `ProgramArguments --instance`
- `EnvironmentVariables/NVOY_INSTANCE_ROOT`
- `StandardOutPath`
- `StandardErrorPath`
- data root directory
- manifest filename under `instances/`
- manifest `id` field

Create the new `runtime/launchagent/` directory before `bootstrap`. If stdout/stderr paths point into a missing directory, launchd can fail without writing the diagnosis because the log destination is what broke.

Use:

```sh
launchctl bootout gui/$(id -u)/<old-label>
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/<new-file>.plist
```

Do not `kill` a `KeepAlive` bridge and expect it to stay down.

## Pattern 5: Rename / migration data handling

A rename is not just a file move. It is a change to every identity-bearing runtime boundary.

### Server-side hard rename

- old manifest must not remain as `*.json`; use `.json.disabled` for rollback
- manifest filename and `id` field must agree
- `assertNoCollisions()` scans every `*.json` and fails on duplicate pubkey
- old data volumes must be copied/preseeded before `up -d`
- locks are ephemeral: delete stale locks, do not rewrite them
- rewrite JSON field `instance` old->new across copied data volumes
- never blind `sed`; message bodies can contain old ids
- verify by exhaustion property:

```text
no old id remains in routing/boundary fields anywhere in copied volumes or instance root;
any remaining old-id literal must be pre-counted body text only
```

### Laptop-side DJ Codex rename sites

As of this runbook, Lane B includes at least:

- bridge plist: five in-file `codex-jaf` occurrences plus filename
- watcher plist: all `codex-jaf` occurrences plus filename
- local data root: `~/.nvoy/codex-desktop/codex-jaf`
- manifest file: `instances/codex-jaf.json`
- manifest field: `"id":"codex-jaf"`

The laptop remote manifest is keyless (`broker_mode: remote`, `delivery_mode: codex_app_server`). Do not seat or copy Bunker credentials into the laptop `codex-desktop` root.

## Pattern 6: Evidence boundaries for spools and delivery

Do not assume a source event id is the local spool row id. A carrier rewrap produces a new local record id; the source id may appear only inside content.

Before any presence/absence diff:

1. prove the proposed join key exists as a field in the target format with one positive control
2. avoid grepping for a token just published into the thing being grepped
3. distinguish field hits from body/content hits
4. label evidence source: relay-signed event, local spool record, send receipt, or community read-back

Truncated reads are not absence. If messages are long, record body length and the offset of the relevant claim before concluding it was not received.

## Operator commands

### Shared daemon status

```sh
launchctl list | grep pub.nave.codex.app-server-daemon
lsof -nP ~/.codex/app-server-control/app-server-control.sock
lsof -nP ~/.codex/thread-writer-locks/<thread-id>.lock
```

### Shared daemon canary

```sh
cd /Users/fairwja/Projects/connect/nvoy-macos-desktop-binder
node mcp/tools/codex-shared-daemon-canary.mjs --instance codex-jaf --no-drive
```

### Remote TUI attach to shared daemon

```sh
/Applications/ChatGPT.app/Contents/Resources/codex \
  --remote unix:// \
  resume <thread-id>
```

Bare `codex resume <thread-id>` tries to become another writer and can fail with active-writer.

### Watcher supervision check

```sh
launchctl list | grep 'pub.nave.nvoy.*agent-inbox'
pgrep -fl 'agent-inbox.mjs --pubkey <prefix>'
```

### Negative-control respawn

```sh
OLD=$(pgrep -f 'agent-inbox.mjs --pubkey <prefix>' | head -1)
kill -TERM "$OLD"
sleep 2
pgrep -fl 'agent-inbox.mjs --pubkey <prefix>'
launchctl list | grep <label>
```

## Open follow-ups

- Run a reboot/login canary that verifies actual shared-daemon ownership, not just environment presence.
- Decide how to represent Codex updater/version skew in health.
- Put owner/state ledger in a shared, queryable place instead of relying on relayed prose.
- Keep Lane B rename runbook updated with any newly created plist or data-root sites.
