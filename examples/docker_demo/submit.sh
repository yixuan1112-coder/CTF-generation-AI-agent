#!/usr/bin/env bash
# Build the demo image, prove it works, and submit it to an arena.
#
#   ./examples/docker_demo/submit.sh                       # build + check only
#   ARENA=... TEAM="My Team" ./examples/docker_demo/submit.sh
#                                                          # …upload tarball, play
#   PUSH=youruser/my-agent:v1 ARENA=... TEAM="My Team" ./examples/docker_demo/submit.sh
#                                                          # …push to a registry instead
#
# Env:
#   ARENA   arena base URL          (default http://127.0.0.1:8090)
#   TEAM    team name to register   (skip submission entirely if unset)
#   TOKEN   existing team token     (skip registration if set)
#   IMAGE   local image tag         (default autoctf-demo-agent)
#   PUSH    registry reference      (if set, push there and submit the address
#                                    instead of uploading a tarball)
#   TRACK   track to play           (default crypto)
set -euo pipefail

IMAGE="${IMAGE:-autoctf-demo-agent}"
ARENA="${ARENA:-http://127.0.0.1:8090}"
TRACK="${TRACK:-crypto}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARBALL="${TARBALL:-$ROOT/agent-image.tar.gz}"

command -v docker >/dev/null || { echo "docker is not installed" >&2; exit 1; }

# ── 1. build ───────────────────────────────────────────────────────────────
echo "▸ building $IMAGE"
docker build -t "$IMAGE" -f "$ROOT/examples/docker_demo/Dockerfile" "$ROOT"

# ── 2. check, before spending an upload on a broken image ──────────────────
echo
echo "▸ checking the image against the arena's acceptance criteria"
docker run --rm "$IMAGE" check

# ── 3. package: push to a registry, or save a tarball ──────────────────────
if [[ -n "${PUSH:-}" ]]; then
  echo
  echo "▸ pushing $PUSH"
  docker tag "$IMAGE" "$PUSH"
  docker push "$PUSH"
  echo "  the repository must be PUBLIC — the arena pulls anonymously"
else
  # gzip because the arena caps the upload; `docker save` output compresses hard.
  echo
  echo "▸ saving to $TARBALL"
  docker save "$IMAGE" | gzip > "$TARBALL"
  echo "  $(du -h "$TARBALL" | cut -f1)"
fi

if [[ -z "${TEAM:-}" && -z "${TOKEN:-}" ]]; then
  echo
  echo "Built and verified. Set TEAM (or TOKEN) and ARENA to submit it:"
  echo "  ARENA=$ARENA TEAM='My Team' $0"
  echo "  ARENA=$ARENA TEAM='My Team' PUSH=youruser/my-agent:v1 $0"
  exit 0
fi

# ── 4. register (only when no token was supplied) ──────────────────────────
api() { curl -sS -X POST "$@"; }

if [[ -z "${TOKEN:-}" ]]; then
  echo
  echo "▸ registering team '$TEAM'"
  RESPONSE="$(api "$ARENA/api/teams" -H 'Content-Type: application/json' \
                  -d "{\"name\":$(printf '%s' "$TEAM" | python3 -c \
                      'import json,sys; print(json.dumps(sys.stdin.read()))')}")"
  TOKEN="$(printf '%s' "$RESPONSE" | python3 -c \
           'import json,sys; print(json.load(sys.stdin)["token"])')"
  echo "  token: $TOKEN   ← save this, it cannot be recovered"
fi

# ── 5. submit the image ────────────────────────────────────────────────────
echo
if [[ -n "${PUSH:-}" ]]; then
  echo "▸ asking the arena to pull $PUSH"
  AGENT="$(api "$ARENA/api/agents" \
               -H "Authorization: Bearer $TOKEN" \
               -H 'Content-Type: application/json' \
               -d "{\"kind\":\"image\",\"name\":\"$IMAGE\",\"image_ref\":\"$PUSH\"}")"
else
  echo "▸ uploading the image (this is the slow part)"
  AGENT="$(api "$ARENA/api/agents?kind=image&name=$IMAGE" \
               -H "Authorization: Bearer $TOKEN" \
               -H 'Content-Type: application/octet-stream' \
               --data-binary "@$TARBALL")"
fi
AGENT_ID="$(printf '%s' "$AGENT" | python3 -c \
            'import json,sys; d=json.load(sys.stdin)
if "error" in d: sys.exit("arena refused it: " + d["error"])
print(d["id"])')"
echo "  accepted as $AGENT_ID"

# ── 6. play ────────────────────────────────────────────────────────────────
echo
echo "▸ starting a $TRACK match"
MATCH="$(api "$ARENA/api/matches" -H "Authorization: Bearer $TOKEN" \
             -H 'Content-Type: application/json' \
             -d "{\"agent_id\":\"$AGENT_ID\",\"track\":\"$TRACK\"}")"
printf '%s' "$MATCH" | python3 -c \
  'import json,sys; d=json.load(sys.stdin)
if "error" in d: sys.exit("could not start the match: " + d["error"])
print("  watch it at '"$ARENA"'/match/" + d["match_id"])'
