#!/bin/sh
# nvoy-onboard.sh — run nvoy-onboard on the fleet host, in the deployed runtime image (#322).
#
#   sh /opt/nvoy-hub/deploy/nvoy-onboard.sh show|run <name> [nvoy-onboard flags]…
#   sh /opt/nvoy-hub/deploy/nvoy-onboard.sh watch|runner-pair      (phase B, docs/ONBOARD_PHASE_B.md)
#
# The host has no node; the deployed runtime image has the tools at the deployed commit. The steps
# write what an operator's run would, so the container sees exactly those host paths, at the same paths:
#   /etc/nvoy             manifests, credentials, identity-blocks.jsonl (allocate, pair, check, apply)
#   /root                 the staged dir ~/.nvoy/staged, the channel account's authorized_keys
#                         (root's, on this host) and the dated manifest backups
#   /var/lib/nvoy-onboard the request ledger and the receipts
#   /var/lib/nvoy-deploy  read-only: the runner's record that apply waits on
#   /run/nvoy             each agent's runtime dir, where the profile step queues its first kind 0
#   docker CLI + socket   apply baselines the channel with docker exec in the agent's adapter
#   the ssh host key      read-only, when the host has one: watch seals it into the owner's install line
# The docker socket is root on this host, so this is no sandbox: it is the operator's run, with the
# deployed code instead of a checkout.
set -eu
DOCKER=${NVOY_DOCKER:-docker}
DEPLOY=${NVOY_DEPLOY_STATE:-/var/lib/nvoy-deploy}
ONBOARD=${NVOY_ONBOARD_STATE:-/var/lib/nvoy-onboard}
HOST_KEY=${NVOY_HOST_KEY:-/etc/ssh/ssh_host_ed25519_key.pub}

image=$(cat "$DEPLOY/DEPLOYED_RUNTIME_IMAGE" 2>/dev/null || true)
if [ -z "$image" ]; then
  echo "nvoy-onboard: no deployed runtime image in $DEPLOY/DEPLOYED_RUNTIME_IMAGE" >&2
  exit 1
fi
# Made here, not by docker, so the ledger directory is root 0700 like the tool makes it.
install -d -m 0700 "$ONBOARD"
# One writer at a time: a watch tick and an operator's run never stage or pair the same name at once.
# The lock is held by the docker client this script becomes, so it lasts as long as the run.
if [ "${1:-}" != show ] && command -v flock >/dev/null 2>&1; then
  exec 9>"$ONBOARD/.lock"
  if ! flock -n 9; then
    echo "nvoy-onboard: another onboarding run holds $ONBOARD/.lock; try again when it ends" >&2
    exit 75
  fi
fi
# Only a key that is there is mounted: docker would make a missing source a directory.
host_key=
if [ -f "$HOST_KEY" ]; then host_key="-v $HOST_KEY:/etc/ssh/ssh_host_ed25519_key.pub:ro"; fi
tty=
if [ -t 0 ] && [ -t 1 ]; then tty=-t; fi

exec "$DOCKER" run --rm -i $tty -u 0:0 -e HOME=/root -e NVOY_GRANT_RELAYS \
  -v /etc/nvoy:/etc/nvoy \
  -v /root:/root \
  -v "$ONBOARD":/var/lib/nvoy-onboard \
  -v "$DEPLOY":/var/lib/nvoy-deploy:ro \
  -v /run/nvoy:/run/nvoy \
  -v /usr/bin/docker:/usr/bin/docker:ro \
  -v /var/run/docker.sock:/var/run/docker.sock \
  $host_key \
  --entrypoint node "$image" /srv/nvoy/mcp/tools/nvoy-onboard.mjs "$@"
