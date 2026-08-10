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

### Option B — a remote endpoint

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
| `crypto` | ✅ | smalle → hastad → commonmod → wiener → fermat → pollard → bonehdurfee | rotates to a harder attack *class* each rung |
| `reverse` | ⚠️ | R=1 → R=6 | one more key-schedule round each rung |
| `web` | ❌ | bypass-flag → … → bypass-popitem | each rung bans the token the previous bypass used |

**`crypto` is the track that discriminates.** Each rung needs a genuinely different
attack, and the last one needs a lattice.

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
never advertise a rung the generator cannot build. `crypto` and `web` both clamp at
their last entry and the tracks stop exactly there; `reverse` has no natural
ceiling, so the arena caps it at six rounds.

`crypto` is the reference track: every rung ships a real paired proof-of-concept that
`verify_spec` **executes** before the rung is allowed to deploy, so no team is ever handed
an unsolvable challenge. The Boneh-Durfee rung only appears when `fpylll` is installed.

`examples/champion_agent/` is a worked agent that clears the whole crypto ladder — the
answer to the starter agent's missing lattice attack.

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

## 7. Exposing it beyond localhost

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

## 8. HTTP API

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

## 9. Tests

```bash
python -m unittest tests.test_arena -v
```

38 tests covering the sandbox (network blocked, runaway agents killed, engine imports
refused), upload validation (traversal, zip bombs, wrong types), the store (atomic queue
claims, restart recovery, rank ordering), the match engine (scoring, flag never logged,
unique seeds), and the HTTP API (auth, cross-team access, token leakage).
