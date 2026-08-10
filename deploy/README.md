# Publishing the arena on the internet

The arena is a normal Python HTTP server, so hosting it is ordinary work. The one
thing that is not ordinary: **it exists to run code that strangers upload.** That
single fact decides the whole deployment.

---

## The rule that decides everything

Run the agent sandbox under **Docker**. Not optional for a public arena.

Without Docker the platform falls back to a hardened subprocess: real rlimits, a
killable process group, a scrubbed environment, and a kernel network namespace.
Those all hold. But the agent runs as **the same OS user as the server**, so the
filesystem is not a boundary — an uploaded agent can read and write anything that
user can, including the arena's own SQLite database and every other team's
submitted code.

That is fine on your laptop. It is not fine when the submissions come from people
you have never met.

```bash
docker build -t autoctf-arena-agent:latest -f Dockerfile.agent .
```

Check what you actually got — the arena reports it honestly rather than assuming:

```bash
curl -s localhost:8090/api/config | python3 -m json.tool | grep -A6 isolation
```

`"strength": "strong"` means Docker. Anything else means do not open it to the
public yet.

---

## Where to host it

| Option | Verdict |
|---|---|
| **VPS with Docker** (Hetzner, DigitalOcean, EC2, a lab machine) | ✅ The right answer. Full control of the daemon and of kernel namespaces. |
| **Container PaaS** (Railway, Render, Fly.io, App Runner) | ⚠️ Usually cannot give you a usable Docker daemon or unprivileged user namespaces, so the sandbox silently degrades to its weakest mode. Check `/api/config` before trusting it. |
| **Static hosts** (GitHub Pages, Netlify, Vercel static) | ❌ Cannot run Python at all, let alone execute agents. |

A modest VPS is plenty: matches are short, and `--workers` is what bounds
concurrency. Two workers on two spare cores handles a small event comfortably.

---

## Topology

```
        internet
           │  HTTPS
    ┌──────▼───────┐
    │ Caddy/nginx  │   TLS, request-size cap, no buffering on the SSE stream
    └──────┬───────┘
           │  http://127.0.0.1:8090
    ┌──────▼───────────────┐
    │ arena (systemd, host)│   binds loopback only
    └──────┬───────────────┘
           │  docker run --network none --memory … --cap-drop ALL
    ┌──────▼───────┐
    │ agent sandbox│   one short-lived container per solve attempt
    └──────────────┘
```

**The arena runs on the host, not in a container.** It has to reach the Docker
daemon to sandbox agents, and doing that from inside a container means mounting
the Docker socket — which turns any container escape into root on the host. The
repo's own security notes rule that out. So the arena stays on the host and only
the untrusted part gets containerised.

---

## Steps

```bash
# 1. user, code, dependencies
sudo useradd -r -m -d /opt/arena arena
sudo usermod -aG docker arena          # only to launch agent sandboxes
sudo -u arena git clone https://github.com/yixuan1112-coder/CTF-generation-AI-agent /opt/arena
cd /opt/arena
sudo -u arena python3 -m venv .venv
sudo -u arena .venv/bin/pip install -e . pycryptodome sympy flask
sudo -u arena .venv/bin/pip install cysignals fpylll   # optional: enables the Boneh-Durfee rung

# 2. the sandbox image
sudo -u arena docker build -t autoctf-arena-agent:latest -f Dockerfile.agent .

# 3. state directory
sudo mkdir -p /var/lib/arena && sudo chown arena:arena /var/lib/arena

# 4. service
sudo cp deploy/arena.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now arena
journalctl -u arena -f

# 5. TLS
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile   # edit the hostname first
sudo systemctl reload caddy
```

---

## Two settings the proxy must get right

Both configs here already do, but if you write your own:

- **Do not buffer responses.** `/api/matches/<id>/stream` is Server-Sent Events. A
  buffering proxy delivers the entire climb in one lump when the match ends, so
  the live view looks frozen throughout the thing it exists to show.
- **Allow a body over 8 MB.** That is the agent upload cap; a smaller proxy limit
  rejects large submissions with a confusing error.

---

## What the platform already handles

- Binding a non-loopback address auto-sets `ARENA_BLOCK_PRIVATE_REMOTE=1`, so a
  team cannot register a remote-agent URL aimed at your internal network or at
  cloud metadata (`169.254.169.254`).
- Bearer tokens per team; a team can only run its own agents.
- Coarse per-IP rate limits on registration and match creation.
- One active match per team, so nobody can flood the queue.
- Uploads are validated before they are stored: path traversal, zip bombs, wrong
  file types.
- Matches interrupted by a restart are requeued rather than lost.

## What you still have to decide

- **Backups.** `/var/lib/arena` is the entire contest — database and every
  uploaded agent.
- **Disk.** Agent uploads accumulate; nothing prunes them yet.
- **Abuse.** The rate limits are coarse. For a public event, put your own limits
  or an auth gate in front.
- **Scale.** SQLite and a stdlib HTTP server are fine for a class, a club, or a
  small CTF. For hundreds of concurrent teams you would move to Postgres and a
  real WSGI/ASGI server.
