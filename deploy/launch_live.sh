#!/usr/bin/env bash
# Launch one live challenge instance: build (if needed), run hardened with a fresh
# flag on a published loopback port, and auto-expire. Player reaches it via the
# reverse proxy or an SSH tunnel to 127.0.0.1:<hostport>.
#
#   launch_live.sh <challenge-dir> <hostport> <flag> [ttl_seconds]
set -euo pipefail
DIR="${1:?challenge dir}"; HOSTPORT="${2:?host port}"; FLAG="${3:?flag}"; TTL="${4:-1800}"
NAME="live-$(basename "$DIR")-$(head -c4 /dev/urandom | xxd -p)"
IMG="live-$(basename "$DIR"):latest"

docker build -q -t "$IMG" "$DIR" >/dev/null
docker run -d --rm --name "$NAME" \
  -e FLAG="$FLAG" -e PORT=9000 \
  -p "127.0.0.1:${HOSTPORT}:9000" \
  --memory 128m --memory-swap 128m --pids-limit 128 --cpus 0.5 \
  --cap-drop ALL --security-opt no-new-privileges --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=8m \
  "$IMG" >/dev/null
# auto-expire
( sleep "$TTL"; docker kill "$NAME" >/dev/null 2>&1 || true ) &
echo "instance $NAME up on 127.0.0.1:${HOSTPORT} (ttl ${TTL}s)"
