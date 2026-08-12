# Publishing the arena on the internet

The arena is a normal Python HTTP server, so hosting it is ordinary work. The one
thing that is not ordinary: **it exists to run code that strangers upload.** That
single fact decides the whole deployment.

---

## Pick your path

**A · A real public arena (you have, or will rent, a server).** One command on a
fresh Ubuntu 22.04/24.04 box with a domain already pointed at it:

```bash
git clone https://github.com/yixuan1112-coder/CTF-generation-AI-agent
cd CTF-generation-AI-agent
sudo bash deploy/bootstrap.sh arena.example.com you@example.com
```

That installs Docker, Python, the arena, a systemd service and Caddy with
automatic HTTPS, builds the agent sandbox image, and tells you at the end whether
the sandbox actually came up in Docker mode. Roughly $5/month of VPS is plenty.
Re-running it upgrades in place.

**B · Show it to a few people today, no server.** Expose the arena already running
on your machine through a tunnel:

```bash
# in one terminal
python -m arena_platform.server --host 127.0.0.1 --port 8090
# in another
cloudflared tunnel --url http://127.0.0.1:8090      # prints a public https URL
```

⚠️ **Only do this with people you trust.** A tunnel does not improve the sandbox.
If your host reports anything other than `"strength": "strong"`, every uploaded
agent runs as your user, on your laptop, with access to your files. Install
Docker first, or keep it to your own team.

**C · Same room, same network.** No tunnel, no certificates:

```bash
python -m arena_platform.server --host 0.0.0.0 --port 8090
```

Others use `http://<your-ip>:8090`. Binding a non-loopback address automatically
blocks remote-agent URLs aimed at private addresses, so nobody can turn your
arena into a probe of your own network.

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

### The second image: the challenge-maker

```bash
docker build -t autoctf-maker:latest -f Dockerfile.maker .
python -m arena_platform.server --maker-backend docker …
```

The maker builds each challenge and runs `verify_spec`, which **executes a
generated solver**. In-process that is a subprocess with your server's filesystem
and network; in the image it is read-only, capabilities dropped,
`no-new-privileges`, tmpfs workdir, memory/PID/CPU capped.

`--maker-backend docker` refuses to fall back, so a server that is supposed to be
containerised fails at startup instead of quietly running the maker on the host.
`/api/config` reports which backend is live under `maker`, and the startup banner
prints it.

Two consequences worth knowing:

- **The image decides what tracks you can offer.** It ships `gcc`, so the arena
  asks the container what it can build and plans each route from that. A host
  with no compiler can still run the reverse ladder.
- **A design brain means egress.** With `AUTOCTF_DESIGN=catalog` (the shipped
  default) the maker's containers run `--network none`. Set an `OPENAI_API_KEY`
  and they must reach the model endpoint instead. `describe()` and `/api/config`
  say which case is live — decide it deliberately.

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
