#!/usr/bin/env bash
# One-shot setup for a PUBLIC AutoCTF Arena on a fresh Ubuntu 22.04/24.04 server.
#
#   sudo bash deploy/bootstrap.sh arena.example.com you@example.com
#
# Installs Docker (so uploaded agents are properly confined), Python, the arena
# itself, a systemd service and Caddy with automatic HTTPS. Safe to re-run.
#
# An optional third argument also publishes the AutoCTF-GAN dashboard on its own
# subdomain, behind generated basic auth:
#
#   sudo bash deploy/bootstrap.sh arena.example.com you@example.com lab.example.com
#
# Both names need their own DNS A record pointing here before you run this.
set -euo pipefail

DOMAIN="${1:-}"
EMAIL="${2:-}"
DASH_DOMAIN="${3:-}"
REPO="${ARENA_REPO:-https://github.com/yixuan1112-coder/CTF-generation-AI-agent}"
# Deploy a branch instead of the default one:  ARENA_BRANCH=my-branch sudo -E bash ...
# Without this, a shallow clone silently takes the default branch, so work that
# has not been merged yet deploys as the version it replaced.
BRANCH="${ARENA_BRANCH:-}"
HOME_DIR=/opt/arena
DATA_DIR=/var/lib/arena

if [[ -z "$DOMAIN" ]]; then
  echo "usage: sudo bash deploy/bootstrap.sh <domain> [email] [dashboard-domain]" >&2
  echo "  each domain's DNS A record must already point at this server" >&2
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "run me with sudo" >&2
  exit 1
fi

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

say "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git python3 python3-venv python3-pip \
                       debian-keyring debian-archive-keyring apt-transport-https

say "Installing Docker (this is what confines uploaded agents)"
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io
fi
systemctl enable --now docker

say "Creating the arena user and directories"
id -u arena >/dev/null 2>&1 || useradd -r -m -d "$HOME_DIR" -s /usr/sbin/nologin arena
usermod -aG docker arena
mkdir -p "$DATA_DIR"
chown -R arena:arena "$DATA_DIR"

say "Fetching the arena"
if [[ -d "$HOME_DIR/.git" ]]; then
  if [[ -n "$BRANCH" ]]; then
    sudo -u arena git -C "$HOME_DIR" fetch --depth 1 origin "$BRANCH"
    sudo -u arena git -C "$HOME_DIR" checkout -B "$BRANCH" FETCH_HEAD
  else
    sudo -u arena git -C "$HOME_DIR" pull --ff-only
  fi
else
  rm -rf "${HOME_DIR:?}/"* 2>/dev/null || true
  sudo -u arena git clone --depth 1 ${BRANCH:+--branch "$BRANCH"} "$REPO" "$HOME_DIR"
fi
echo "  deployed $(sudo -u arena git -C "$HOME_DIR" rev-parse --short HEAD) on ${BRANCH:-default branch}"

say "Installing Python dependencies"
sudo -u arena python3 -m venv "$HOME_DIR/.venv"
sudo -u arena "$HOME_DIR/.venv/bin/pip" install -q --upgrade pip
sudo -u arena "$HOME_DIR/.venv/bin/pip" install -q -e "$HOME_DIR" pycryptodome sympy flask

say "Installing fpylll (optional: it is what enables the Boneh-Durfee rung)"
if apt-get install -y -qq libfplll-dev libgmp-dev libmpfr-dev libqd-dev 2>/dev/null \
   && sudo -u arena "$HOME_DIR/.venv/bin/pip" install -q cysignals fpylll 2>/dev/null; then
  echo "  fpylll installed — the crypto ladder gets all 7 rungs"
else
  echo "  fpylll unavailable — the ladder runs 6 rungs, ending at pollard"
fi

say "Building the agent sandbox image"
docker build -q -t autoctf-arena-agent:latest -f "$HOME_DIR/Dockerfile.agent" "$HOME_DIR"

say "Building the challenge-maker image"
# The maker builds challenges and runs verify_spec, which EXECUTES a generated
# solver. In this image that happens read-only, with capabilities dropped. The
# image also ships gcc, so the reverse ladder works even if the host has none.
docker build -q -t autoctf-maker:latest -f "$HOME_DIR/Dockerfile.maker" "$HOME_DIR"

say "Installing the service"
install -m 0644 "$HOME_DIR/deploy/arena.service" /etc/systemd/system/arena.service
systemctl daemon-reload
systemctl enable --now arena
sleep 4

if [[ -n "$DASH_DOMAIN" ]]; then
  say "Installing the AutoCTF-GAN dashboard"
  # Its own user on purpose: the dashboard generates and verifies challenges
  # in-process, so it executes generated code as itself. Running it as `arena`
  # would put the contest database and every uploaded agent in that blast
  # radius. ganlab owns only its scratch dir and is not in the docker group.
  id -u ganlab >/dev/null 2>&1 || useradd -r -m -d /var/lib/gan-lab -s /usr/sbin/nologin ganlab
  mkdir -p /var/lib/gan-lab
  chown -R ganlab:ganlab /var/lib/gan-lab
  # ...which only means anything if the contest state is actually unreadable.
  chmod 700 "$DATA_DIR"
  # ganlab still needs to read the code and the shared venv.
  chmod -R a+rX "$HOME_DIR"
  install -m 0644 "$HOME_DIR/deploy/gan-dashboard.service" /etc/systemd/system/gan-dashboard.service
  systemctl daemon-reload
  systemctl enable --now gan-dashboard
  sleep 3
fi

say "Installing Caddy for HTTPS"
if ! command -v caddy >/dev/null 2>&1; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq
  apt-get install -y -qq caddy
fi
sed -e "s/arena\.example\.com/$DOMAIN/" "$HOME_DIR/deploy/Caddyfile" > /etc/caddy/Caddyfile
[[ -n "$EMAIL" ]] && sed -i "1i {\n\temail $EMAIL\n}\n" /etc/caddy/Caddyfile

DASH_PASS=""
if [[ -n "$DASH_DOMAIN" ]]; then
  # Re-running must not silently rotate the password out from under whoever is
  # already using it, so reuse the existing hash if this block is already there.
  if grep -q "^$DASH_DOMAIN {" /etc/caddy/Caddyfile.dashboard.generated 2>/dev/null; then
    cat /etc/caddy/Caddyfile.dashboard.generated >> /etc/caddy/Caddyfile
    echo "  dashboard auth: unchanged (delete /etc/caddy/Caddyfile.dashboard.generated to rotate)"
  else
    DASH_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)"
    DASH_HASH="$(caddy hash-password --plaintext "$DASH_PASS")"
    sed -e "s/lab\.example\.com/$DASH_DOMAIN/" -e "s|BCRYPT_HASH_HERE|$DASH_HASH|" \
        "$HOME_DIR/deploy/Caddyfile.dashboard" > /etc/caddy/Caddyfile.dashboard.generated
    chmod 600 /etc/caddy/Caddyfile.dashboard.generated
    cat /etc/caddy/Caddyfile.dashboard.generated >> /etc/caddy/Caddyfile
  fi
fi

systemctl reload caddy || systemctl restart caddy

say "Verifying"
sleep 3
REPORT=$("$HOME_DIR/.venv/bin/python" - <<'PY' 2>/dev/null || echo "unavailable|unavailable"
import json, urllib.request
d = json.loads(urllib.request.urlopen("http://127.0.0.1:8090/api/config", timeout=10).read())
i, m = d["isolation"], d.get("maker", {})
print(f"{i['backend']} / {i['strength']}|{m.get('backend', '?')} / network: {m.get('network', '?')}")
PY
)
ISO="${REPORT%%|*}"
MAKER="${REPORT##*|}"
echo "  arena service : $(systemctl is-active arena)"
echo "  agent sandbox : $ISO"
echo "  maker         : $MAKER"
echo "  data dir      : $DATA_DIR"
if [[ -n "$DASH_DOMAIN" ]]; then
  echo "  dashboard     : $(systemctl is-active gan-dashboard)"
  curl -fsS --max-time 5 -o /dev/null http://127.0.0.1:8080/ 2>/dev/null \
    && echo "  dashboard http: responding on 127.0.0.1:8080" \
    || echo "  dashboard http: NOT responding — journalctl -u gan-dashboard -n 50"
fi

if [[ "$ISO" != docker* ]]; then
  cat <<'WARN'

  ⚠  The sandbox is NOT using Docker. Uploaded agents would run as the same OS
     user as the server, so the filesystem is not a boundary between them and
     your host. Do NOT accept public submissions in this state.
     Check: journalctl -u arena -n 50
WARN
fi

cat <<EOF

  Done. Your arena:  https://$DOMAIN

  Certificates are issued on the first request, so give it a few seconds.
  Logs:     journalctl -u arena -f
  Restart:  systemctl restart arena
  Back up:  $DATA_DIR   (this directory IS the whole contest)
EOF

if [[ -n "$DASH_DOMAIN" ]]; then
  cat <<EOF

  Dashboard:  https://$DASH_DOMAIN
  Logs:       journalctl -u gan-dashboard -f
EOF
  if [[ -n "$DASH_PASS" ]]; then
    cat <<EOF

  Sign in with   user: lab   password: $DASH_PASS
  This is printed ONCE — only the bcrypt hash is stored. Save it now.
EOF
  fi
fi
