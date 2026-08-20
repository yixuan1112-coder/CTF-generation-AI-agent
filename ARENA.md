# AutoCTF Arena — run a real agent-vs-agent competition

The `autoctf_gan` engine generates CTF challenges and evolves them. **The arena turns
that engine into a contest real teams can enter**: teams submit their own AI agents, each
agent climbs a ladder against its own private challenge-maker, and the leaderboard ranks
teams by how far they actually got.

This is not a simulation. A match only advances when a team's agent returns the real flag
for a freshly generated challenge instance.

```
team submits agent ──▶ match queued ──▶ challenge-maker deploys Gen-0
                                              │
                          ┌───────────────────┴─────────────────┐
                          ▼                                     ▼
                 agent returns the flag              agent returns nothing
                          │                                     │
                 maker MUTATES to a harder                climb ends —
                 attack class, verified solvable,        your depth is your rank
                 and redeploys ──┘
```

---

## 1. Start the arena

```bash
python -m arena_platform.server --port 8090
# or, after `pip install -e .`
ctf-arena --port 8090
```

Open <http://127.0.0.1:8090>. Four pages:

| Page | What it does |
|---|---|
| `/` | Leaderboard, live ladder, matches in progress |
| `/submit` | Register a team, submit an agent, start a match |
| `/match/<id>` | Live rung-by-rung view of one match (Server-Sent Events) |
| `/docs` | The competitor handbook: agent contract, limits, HTTP API |

Options:

```
--host 127.0.0.1     bind address (see "Exposing it" below)
--port 8090
--data-dir .arena    SQLite database + uploaded agents
--workers 2          matches run concurrently
--backend auto       auto | docker | subprocess
```

State lives in `--data-dir`, so restarting the server keeps every team, agent, match and
event log. Matches interrupted by a restart are automatically requeued.

---

## 2. How a team enters

Three ways in, all scored the same way. Uploads and images run on the arena's hardware and
are ranked on depth *and* speed; remote agents run on yours and are ranked on depth alone.

### Option A — upload an agent

A `.py` file, or a `.zip` with `agent.py` at its top level. It must define `solve`:

```python
def solve(files, meta=None):
    # files: {"n.txt": "8281...", "e.txt": "3", "c.txt": "5512...", "README.md": "..."}
    # meta:  {"challenge_id", "gen", "category", "title", "story", "hints", "time_limit_s"}
    n = int(files["n.txt"])
    ...
    return "flag{recovered}"      # or None when you are beaten
```

One argument works; a second gets you the metadata. Returning `None` is a clean loss,
not an error — it just ends your climb at that rung.

Uploaded agents run **on the arena's hardware with no network access**. They may import
the Python standard library plus whatever the operator has installed on the host
(`pycryptodome`, `sympy`, `fpylll`, … — `GET /api/config` is authoritative, and every team
gets the identical list). Anything beyond that must travel in the upload, which is what the
`.zip` form is for:

```bash
cd examples/champion_agent
zip -r ../champion.zip agent.py lattice.py     # ship your libraries alongside the agent
```

### Option B — a Docker image

An upload runs on *the arena's* interpreter with *the arena's* libraries. Fair, but it
caps what a team can bring. An image lets the team choose the base, the Python version
and every dependency, while still running on the arena's hardware under the arena's
limits — so unlike a remote agent, **wall-clock stays comparable** and image rows are
ranked on speed alongside uploads.

The whole contract is two lines of Dockerfile:

```dockerfile
COPY agent.py /opt/agent/agent.py     # must define solve(files, meta=None)
RUN chmod -R a+rX /opt/agent          # the arena runs you with --user, never root
```

…plus `python` on `PATH`. There are two ways to hand it over.

**Route 1 — push to a registry** (the normal one). Nothing large crosses the team's
connection to the arena, and shipping a fix is one `docker push`:

```bash
docker build -t youruser/my-agent:v1 .
docker push  youruser/my-agent:v1
curl -X POST "$ARENA/api/agents" -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"kind":"image","name":"my-agent","image_ref":"youruser/my-agent:v1"}'
```

The repository must be **public**: the arena pulls anonymously and deliberately stores no
registry credentials. A digest-pinned reference (`@sha256:…`) makes the run reproducible.

**Route 2 — upload a tarball**, for a private image or a venue with no registry access:

```bash
docker save my-agent | gzip > my-agent.tar.gz
curl -X POST "$ARENA/api/agents?kind=image&name=my-agent" \
     -H "Authorization: Bearer $TOKEN" --data-binary @my-agent.tar.gz
```

Either way the arena then **test-runs the image** — importing `/opt/agent/agent.py` under
the real match confinement — before accepting it, so a broken image is rejected at
submission with the reason rather than halfway through a match.

`examples/docker_demo/` is a working image you can build, run interactively, and submit;
`examples/docker_demo/submit.sh` does all three.

**What the operator should know.** Loading a stranger's image is the most dangerous thing
this platform does, so it is fenced on several sides — see the module docstring in
`arena_platform/images.py` for the threat model:

| Concern | What stops it |
|---|---|
| A tarball tagged as the arena's own runner image, silently replacing what every *other* team runs in | `manifest.json` is read and protected tags refused **before** `docker load`; the image is then retagged into `arena-team/<agent_id>` and the tarball's own tags dropped |
| A registry reference aimed at the arena's own network (`localhost:5000/…`, an internal host) — `docker pull` runs on the arena host with the arena's routing | `validate_image_ref` resolves the registry host and refuses private, loopback and link-local addresses, the same rule remote endpoints get |
| Image metadata used to escape (`USER`, `ENTRYPOINT`, `CMD`) | Overridden at `docker run`; `--entrypoint python` is what makes the harness, not the image's entrypoint, the thing that executes |
| Disk exhaustion | Upload streamed to a temp file and capped (`ARENA_MAX_IMAGE_MB`, default 512); the *decompressed* image re-measured after load; one image kept per team |
| Memory exhaustion on a small VPS | The body is never buffered in RAM — see `_read_body_to_file` |
| A broken image wasting a match slot | `images.probe_image` runs the real import under the real flags at submission time |

Set `ARENA_MAX_IMAGE_MB` to taste. On a host with no Docker daemon the arena advertises
`images.supported: false` in `GET /api/config`, the submit page disables the tab, and the
API refuses with a 409 — image support is a property of the host, not of the build.

### Option C — a remote endpoint

Keep the agent on your own machine (Sage, a GPU, a private model) and register a URL.
The arena POSTs each challenge and reads a flag back:

```
POST https://your-host/solve
{"challenge_id": "...", "gen": 3, "files": {"n.txt": "..."}, "hints": [...]}
→ 200  {"flag": "flag{...}"}          # or {"flag": null}
```

`python team_agent.py --serve 9000` turns the starter agent into exactly that endpoint.

Remote agents are ranked **on depth only** — their wall-clock is measured on the team's
own hardware, so the leaderboard marks them and does not compare their times against
uploaded agents.

---

## 3. Develop an agent without touching the server

```bash
python team_agent.py --selftest              # climb the real ladder locally
python team_agent.py --selftest --seed 42    # reproducible instance
```

This runs the arena's own match engine in-process and tells you exactly which rung stops
you — no registration, no queue:

```
  ✔ Gen-0  smalle         solved in 0.00s
  ✔ Gen-1  hastad         solved in 0.00s
  ...
  ✗ Gen-6  bonehdurfee    agent returned no flag

Out-evolved. Deepest solve Gen-5 (pollard); the challenge-maker escalated to
Gen-6 (bonehdurfee) and held.
```

When you are ready, upload it and run a scored match in one command:

```bash
python team_agent.py --enter --server http://ARENA_HOST:8090 --name "Your Team"
```

---

## 4. Scoring

| Rank key | Meaning |
|---|---|
| 1. Deepest rung solved | How far up the ladder the agent actually got |
| 2. Total agent time | Wall-clock across the rungs it solved |
| 3. Earliest finish | Who got there first |

Depth always beats speed: an agent that reaches Gen-4 in ten minutes outranks one that
stops at Gen-3 in one second. Points (`100 + 60 × gen` per solve) are shown for
familiarity but do not decide the rank.

A team's leaderboard row is its **best** completed match, so reruns can only improve it.

---

## 5. The tracks

| Track | Playable | Rungs | How it escalates |
|---|---|---|---|
| `crypto` | ✅ | smalle → hastad → commonmod → wiener → fermat → pollard → bonehdurfee → **singular → gcmreuse → noncebias** | early rungs rotate attack *class*; the top three are hard to *find*, not just exploit |
| `reverse` | ⚠️ | R=1 → R=6 | one more key-schedule round each rung |
| `web` | ❌ | bypass-flag → … → bypass-popitem → **bypass-keys → bypass-get → bypass-tojson → bypass-pprint → bypass-pop** | each rung bans the token the previous bypass used; the last five force non-obvious Jinja constructs |

**`crypto` is the track that discriminates.** Each rung needs a genuinely different
attack, and the last one needs a lattice.

The top three rungs move the difficulty from *exploitation* to *detection* —
where a strong agent actually differs from a weak one. Each hands over a complete,
correct-looking implementation and ordinary-looking data, and says nothing about
what is wrong:

- **`singular`** — a vendor's in-house 256-bit "elliptic curve" whose parameters
  are all well-formed and whose shipped point arithmetic is correct. The
  discriminant `4a³ + 27b²` is zero, so it is a singular cubic: its group is
  `F_p*` in disguise and `p−1` is smooth, collapsing a 256-bit discrete log to a
  Pohlig-Hellman that finishes in milliseconds. You have to *compute* the
  discriminant to know.
- **`gcmreuse`** — 128 AES-GCM records with correct tags and no key material. One
  nonce is used three times (scattered, not adjacent), which turns the tags into
  polynomials sharing an unknown and leaks the GHASH subkey to a gcd. Finding it
  means noticing three collisions among 128 twelve-byte nonces.
- **`noncebias`** — an ECDSA ledger on secp256k1 where every signature verifies
  against the published key and the curve and hash are exactly as stated. The
  nonces are 16 bits short — invisible, because a signature never reveals its
  nonce — so you have to *hypothesise* the bias and confirm it with a lattice
  (hidden number problem). This rung needs fpylll and is dropped where it is
  absent, the same bargain Boneh-Durfee already makes.

Two matching **compose** stages join the authoring catalogue —
`franklin` (Franklin-Reiter related messages) and `crtfault` (a Bellcore CRT
fault hidden in a batch of signed receipts) — so the endless tail can also demand
diagnosis, not just execution. Past depth 3 the composed challenges withhold their
per-stage hints for the same reason.

**`reverse` is playable but weak.** Rounds only change how the password reaches the
keystream state; an agent that solves for the state directly (see
`examples/reverse_agent/`) never touches the password, so every rung falls at the
same speed. Use it as a warm-up, not a decider.

**`web` is not offered.** It is a service challenge — the flag is injected into the
running container as `$FLAG` at deploy time, so it exists nowhere in the files an
agent receives, and booting the supplied `app.py` locally yields only
`flag{replace_at_deployment}`. No agent could win it on merit, so the API refuses
to queue it (HTTP 409 with the reason) rather than letting a team burn a match.
The ladder itself is sound and its rungs verify; it needs an instance broker, not
a fix.

Rung lists are read from the engine at startup, not hardcoded, so the board can
never advertise a rung the generator cannot build.

A track is no longer one ladder. It names a starting discipline, and the maker
walks a **campaign** (`autoctf_gan/campaign.py`) from there:

1. **climb** — rotate to a harder attack class within the discipline
2. **cross-track** — when that ladder ends, switch to another discipline's ladder
3. **author** — when every bounded ladder is exhausted, compose verified attack
   classes into challenges no ladder contains. This segment has no end.

`track.rungs` is the bounded prefix — the part the UI draws as a fixed ladder —
and `track.endless` says whether authoring follows it. Clearing the last bounded
rung is a milestone, not the end of the match: the maker keeps going and the
match ends on the budget, a wrong flag, or a crash.

Segments this host cannot build are dropped with a stated reason rather than
deployed and rejected (a match stalling because there is no `gcc` looks like a
broken maker, not a missing compiler). If the *starting* discipline is the one
that cannot build, the track is withdrawn entirely — cross-tracking is an
escalation, never a substitution, so a team that entered `reverse` is never
quietly handed crypto rungs.

`crypto` is the reference track: every rung ships a real paired proof-of-concept that
`verify_spec` **executes** before the rung is allowed to deploy, so no team is ever handed
an unsolvable challenge. The Boneh-Durfee rung only appears when `fpylll` is installed.
Authored compositions pass the identical gate — the PoC is assembled from the same
`rsa_stages` functions that built the challenge, and it must recover the flag before
the challenge is deployed.

`examples/champion_agent/` is a worked agent that clears the whole crypto ladder — the
answer to the starter agent's missing lattice attack. It is also the demonstration of
why the ladder needed a tail: it solves every bounded rung and then stalls on the first
challenge the maker composes for it.

### Where the challenge-maker runs

The maker is a container image. The outer platform keeps only the two jobs it
should have — take the upload, start the container — and everything that makes a
challenge happens inside:

```bash
docker build -t autoctf-maker:latest -f Dockerfile.maker .
python -m arena_platform.server --maker-backend docker --port 8090
```

The protocol is one JSON object in, one JSON object out
(`python -m autoctf_gan.service`), and it is stateless: the host names the seed,
the generation and the per-match secret on every request, so a wedged or crashed
build costs one container instead of the arena. Two things move inside by doing
this:

* **`verify_spec` executes a generated solver.** On the host that was a
  subprocess with the host's filesystem and network. In the container it runs
  read-only, with all capabilities dropped, `no-new-privileges`, a tmpfs work
  directory, and memory/PID/CPU caps.
* **The LLM API key.** It is an environment variable on the container, never a
  field in the protocol and never written into a spec or an event.

`--maker-backend docker` **refuses to fall back**. A deployment that requires
containerization fails at startup rather than quietly running the maker on the
host; `auto` falls back and says so, and `/api/config` reports which is live.

**The network asymmetry is real and deliberate.** A catalogue-only maker needs no
network and runs `--network none`. A maker with a design brain has to reach the
model endpoint and therefore cannot be disconnected — an LLM in the loop is
egress in the loop. The choice is made explicitly in `autoctf_gan/maker.py` and
reported by `describe()`, rather than falling out of a default.

The image also decides what the arena can offer. It ships `gcc`, so once the
maker is containerized "can this host compile C?" is the wrong question — the
arena asks the container (`op=capabilities`) and plans each track's route against
the image's toolchain. An arena on a host with no compiler can still run the
reverse ladder.

> The arena process itself is **not** containerized here, because it starts
> containers. Running it inside one would mean mounting the Docker socket, which
> this project refuses to do (see the security boundary in README). Run the arena
> on the host or on a dedicated runner; the maker and the team agents are what go
> in containers.

### The design brain

`autoctf_gan/design.py` optionally puts a model in the authoring loop. It decides
two things — the ORDER of attack classes in a composition, and the prose — and
nothing else. Stage names are resolved against the reviewed `STAGES` catalogue by
`Plan.validate()`, so an invented class is a rejected plan rather than a build
step; the key material and the exploit both come from reviewed code. A missing
key, a timeout, a malformed reply or prose that leaks the answer all fall back to
the deterministic catalogue, so the brain can cost variety but never a match.

```bash
export OPENAI_API_KEY=...        # or LLM_API_KEY
export LLM_MODEL=gpt-5-mini      # LLM_BASE_URL for an OpenAI-compatible endpoint
export AUTOCTF_DESIGN=catalog    # pin the deterministic catalogue (CI, reproducible runs)
```

`/api/config` reports which mode is live under `design_brain`.

---

## 6. Isolation

Uploaded agent code is hostile by assumption. Two backends, chosen automatically:

| Backend | When | What you get |
|---|---|---|
| **docker** | a Docker daemon answers | `--network none`, memory/PID/CPU caps, `cap-drop ALL`, `no-new-privileges`, non-root |
| **subprocess** | otherwise | hard `RLIMIT_CPU`/`AS`/`FSIZE`/`NPROC` set by the child before any agent code loads, killable process group, scrubbed environment, and a network namespace via `unshare -rn` where the kernel allows it |

**Loopback is allowed; egress is not.** Both namespace backends leave `127.0.0.1`
working and drop everything else — booting the target app locally and exploiting it
is how you solve the web track, so removing sockets outright would make that ladder
unsolvable. Only on a host with no namespace support does the harness fall back to
stripping Python's socket API, which blocks loopback too; `GET /api/config` reports
which of the two you are on.

The live sandbox report is on `/docs` and in `GET /api/config`.

**For public submissions, run with Docker.** The subprocess backend runs agents as the
same OS user as the server: rlimits, the killable process group and the network namespace
all hold, but the filesystem is not a boundary. Without `unshare` the backend also falls
back to removing Python's socket API, which stops accidental and casual egress but is not
kernel-enforced. Build the runner image first:

```bash
docker build -t autoctf-arena-agent:latest -f Dockerfile.agent .
ARENA_DOCKER_IMAGE=autoctf-arena-agent:latest ctf-arena --port 8090
```

What the platform guarantees either way:

- The agent receives **only** the player files — never the flag, the solver, or the spec.
- The flag is compared in-process and never written to an event, a log line, or the API.
- The repository is not importable from agent code, so the generator cannot be read.
- Agents get an identical import path, so no team has a library another team lacks.
- Every match uses its own random seed: two teams never receive the same modulus or the
  same flag, so flags cannot be traded.

---

## 7. Publishing it on the internet

Yes — it is a normal Python HTTP server and hosts like one. On a fresh Ubuntu
server with a domain pointed at it, the whole thing is one command:

```bash
sudo bash deploy/bootstrap.sh arena.example.com you@example.com
```

That installs Docker, Python, the arena, a systemd service and Caddy with
automatic HTTPS, then reports whether the sandbox really came up in Docker mode.
No server? `cloudflared tunnel --url http://127.0.0.1:8090` gives you a public URL
for the arena on your own machine — but read the warning in
**[deploy/](deploy/README.md)** first, because a tunnel does not harden the
sandbox. Full walkthrough, systemd unit and proxy configs all live in
**[deploy/](deploy/)**.

| Option | Verdict |
|---|---|
| VPS with Docker (Hetzner, DigitalOcean, EC2) | ✅ the right answer |
| Container PaaS (Railway, Render, Fly.io) | ⚠️ often no usable Docker daemon or user namespaces — check `/api/config` first |
| Static hosts (GitHub Pages, Netlify) | ❌ cannot run Python at all |

**One hard rule: run the agent sandbox under Docker.** Without it agents execute
as the same OS user as the server, so the filesystem is not a boundary — an
uploaded agent could read the arena's database and every other team's code. Fine
on your laptop, not fine for public submissions.

```bash
docker build -t autoctf-arena-agent:latest -f Dockerfile.agent .
curl -s localhost:8090/api/config | python3 -m json.tool | grep -A6 isolation
```

`"strength": "strong"` means Docker is in play. Anything else means do not open it
up yet.

The arena runs on the **host**, not in a container — it needs the Docker daemon to
sandbox agents, and reaching that from inside a container means mounting the
Docker socket, which turns any escape into host root. Only the untrusted agents
get containerised.

Whatever proxy you use must **not buffer responses** (the live match view is SSE;
a buffering proxy makes it look frozen) and must **allow bodies over 8 MB** (the
agent upload cap).

## 8. Exposing it beyond localhost

The default bind is `127.0.0.1`. When you bind a reachable address the server
automatically sets `ARENA_BLOCK_PRIVATE_REMOTE=1`, so a team cannot register a remote
agent URL pointing at your internal network.

Before opening it to real teams:

- Run the agent sandbox under Docker (above).
- Put HTTPS in front (Nginx/Caddy/Traefik) — tokens are bearer credentials.
- Keep `--workers` at or below the host's spare cores; each worker runs one agent.
- Back up `--data-dir`; it is the whole contest.

Environment knobs:

| Variable | Effect |
|---|---|
| `ARENA_DOCKER_IMAGE` | image used for the docker backend (default `autoctf-arena-agent:latest`) |
| `ARENA_DISABLE_DOCKER` | force the subprocess backend |
| `ARENA_AGENT_MEMORY_MB` | per-attempt memory cap (default 2048) |
| `ARENA_BLOCK_PRIVATE_REMOTE` | `1` refuses remote agent URLs on private addresses |
| `ARENA_ACCESS_LOG` | `1` enables HTTP access logging |

---

## 9. HTTP API

Authenticate with `Authorization: Bearer <token>` from team registration.

| Endpoint | Purpose |
|---|---|
| `POST /api/teams` | register → `{team_id, name, token}` |
| `POST /api/agents` | upload: metadata in the query string, file as the raw body. remote: JSON body |
| `GET /api/agents` | your team's agents |
| `POST /api/matches` | `{agent_id, track}` → queues a match |
| `GET /api/matches` | recent matches |
| `GET /api/matches/<id>` | match state + full event log (`?after=<seq>` to poll) |
| `GET /api/matches/<id>/stream` | Server-Sent Events, live |
| `GET /api/leaderboard?track=` | the public board |
| `GET /api/config` | tracks, rungs, limits, sandbox report |
| `GET /api/template` | the starter agent |

```bash
S=http://localhost:8090
TOKEN=$(curl -s $S/api/teams -d '{"name":"Lattice Reducers"}' \
        | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

AGENT=$(curl -s -X POST "$S/api/agents?kind=upload&name=v1&filename=agent.py" \
        -H "Authorization: Bearer $TOKEN" --data-binary @agent.py \
        | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')

curl -s $S/api/matches -H "Authorization: Bearer $TOKEN" \
     -d "{\"agent_id\":\"$AGENT\",\"track\":\"crypto\"}"
```

---

## 10. Tests

```bash
python -m unittest tests.test_arena -v
```

38 tests covering the sandbox (network blocked, runaway agents killed, engine imports
refused), upload validation (traversal, zip bombs, wrong types), the store (atomic queue
claims, restart recovery, rank ordering), the match engine (scoring, flag never logged,
unique seeds), and the HTTP API (auth, cross-team access, token leakage).
