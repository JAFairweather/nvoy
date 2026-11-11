#!/bin/sh
# The status page's host stage (status S1): the facts only the fleet host can see, gathered into a
# root-only directory for mcp/tools/nvoy-status.mjs, which judges them inside the runtime image with
# no Docker socket. Nothing here is published: the collector carries out counts, times and its own
# words, never a line of these logs. Run by nvoy-status.service.
#
#   sh deploy/nvoy-status-facts.sh /var/lib/nvoy-status/facts
set -eu
out=${1:?usage: nvoy-status-facts.sh <facts dir>}
umask 077
tmp=$(mktemp -d "$out.XXXXXX")
mkdir -p "$tmp/logs" "$tmp/deploy"

# Every nvoy container's state; the watchers' and brokers' last day of logs, bounded.
docker ps -a --format '{{.Names}}' | grep -E '^nvoy-' | sort | while read -r c; do
  docker inspect --format '{{.Name}}|{{.State.Running}}|{{.State.StartedAt}}|{{.RestartCount}}' "$c" || true
  case "$c" in
    *-watcher-1|*-broker-1) docker logs --timestamps --since 24h "$c" 2>&1 | tail -n 20000 > "$tmp/logs/$c.log" || true ;;
  esac
done > "$tmp/containers.txt"

# The harness side of each agent's channel: live channel processes per instance, names only.
ps -eo args= | grep -E '^(/usr/local/bin/)?node ' \
  | grep -oE '(claude-channel|codex-channel-mcp|codex-channel-feed)\.mjs --instance [a-z0-9-]+' \
  | sort | uniq -c > "$tmp/channels.txt" || true

{
  echo "uptime_sec=$(cut -d' ' -f1 /proc/uptime | cut -d. -f1)"
  echo "disk_pct=$(df -P / | awk 'NR==2 { sub("%", "", $5); print $5 }')"
  awk '/^MemTotal:/ { t = $2 } /^MemAvailable:/ { a = $2 } END { if (t) printf "mem_avail_pct=%d\n", a * 100 / t }' /proc/meminfo
} > "$tmp/host.txt"

# The deploy runner's own record of what runs and what main holds.
for f in DEPLOYED_SHA LAST_OUTCOME REMOTE_HEAD.json; do
  cp "/var/lib/nvoy-deploy/$f" "$tmp/deploy/" 2>/dev/null || true
done
systemctl is-active nvoy-runtime-deploy.timer > "$tmp/deploy/timer" 2>/dev/null || true

rm -rf "$out.old"
if [ -d "$out" ]; then mv "$out" "$out.old"; fi
mv "$tmp" "$out"
rm -rf "$out.old"
