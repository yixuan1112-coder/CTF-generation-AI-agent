# The demo image — package an agent, submit it, watch it think

This folder builds one Docker image that is two things at once:

* **a demo you can open** — `docker run -it` gives you a menu, and you choose to run the AI;
* **a valid competition submission** — the same image, uploaded to the arena unchanged,
  climbs the crypto ladder.

It is deliberately both, because that is the lesson: the arena overrides your image's
`ENTRYPOINT`, `CMD` and `USER` at match time, so the human-facing half and the competing
half cannot interfere with each other.

There is **no language model in here.** No prompts, no API keys, no network. The agent is
the *circle-memory* pattern — an explicit loop over an explicit memory — which is the
shape we want competitors to start from.

---

## Quick start

```bash
# from the repository root
docker build -t autoctf-demo-agent -f examples/docker_demo/Dockerfile .
docker run --rm -it autoctf-demo-agent
```

```
  AutoCTF Arena — circle-memory demo agent
  ────────────────────────────────────────────────────────────────
  A packaged agent with no language model in it. Pick something:

    1) Run the AI agent on five sample rungs
    2) Run it verbosely — watch PERCEIVE → DECIDE → ACT → RECORD
    3) Check this image is submission-ready
    4) Show the agent contract and the circle
    5) Print the agent source
    s) Shell
    q) Quit

  choose ▸
```

Or drive it directly, no menu: `docker run --rm autoctf-demo-agent solve` (also `verbose`,
`check`, `contract`, `source`).

---

## The five steps, end to end

This is the whole workflow, and `submit.sh` automates steps 3–5.

### 1. Confirm the contract

Before writing anything, know what the platform will call and what it wants back. For this
arena, `GET /api/config` is authoritative and `/docs` is the human version. The answer is:

| Question | This arena's answer |
|---|---|
| How does the agent receive the challenge? | A Python call: `solve(files, meta=None)`. `files` is `{filename: contents}` — no `TARGET_HOST`/`TARGET_PORT` env vars, because challenges arrive as artifacts, not live targets. |
| How is the flag returned? | The **return value** of `solve()`. Not stdout, not a file. Returning `None` is a clean loss. |
| Where must the code live? | `/opt/agent/agent.py` inside the image. |
| Is there network access? | No. `--network none`. Loopback works, so you may boot a local target and exploit it. |

Other platforms answer these differently — env vars in, flag on stdout, is a common
alternative shape. The point of step 1 is that you *ask*, rather than assume.

### 2. Write the agent

`agent.py` defines `solve()`. That is the only name the platform looks for; structure the
rest however you like. This demo uses the circle-memory pattern, below.

### 3. Write the Dockerfile

See `Dockerfile` in this folder. Two required lines, plus whatever your attack needs:

```dockerfile
FROM python:3.11-slim

# your toolchain — this is the reason to submit an image at all
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py /opt/agent/agent.py     # required: defines solve()
RUN chmod -R a+rX /opt/agent          # required: the arena runs you with --user
```

### 4. Build and test locally

Never spend a submission on an untested image:

```bash
docker build -t autoctf-demo-agent -f examples/docker_demo/Dockerfile .
docker run --rm -it autoctf-demo-agent          # the menu
docker run --rm    autoctf-demo-agent check     # the arena's own acceptance checks
```

### 5. Submit it

**Push to a registry** (normal), and give the arena the address:

```bash
docker tag  autoctf-demo-agent youruser/my-ctf-agent:v1
docker push youruser/my-ctf-agent:v1

curl -X POST "$ARENA/api/agents" -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"kind":"image","name":"my-agent","image_ref":"youruser/my-ctf-agent:v1"}'
```

The repository must be **public** — the arena pulls anonymously and stores no credentials.

**Or upload a tarball**, for a private image or an offline venue:

```bash
docker save autoctf-demo-agent | gzip > my-agent.tar.gz
curl -X POST "$ARENA/api/agents?kind=image&name=my-agent" \
     -H "Authorization: Bearer $TOKEN" --data-binary @my-agent.tar.gz
```

Either way the arena loads the image and **test-runs it** before accepting, so you learn
about a mistake in seconds rather than losing a match to it.

`submit.sh` does 3–5 for you:

```bash
# build + verify only
./examples/docker_demo/submit.sh

# build, verify, upload the tarball, start a match
ARENA=https://arena.yixcyber.com TEAM="My Team" ./examples/docker_demo/submit.sh

# build, verify, push to a registry, submit the address, start a match
PUSH=youruser/my-ctf-agent:v1 ARENA=... TEAM="My Team" ./examples/docker_demo/submit.sh
```

---

## The circle, and why it is not a prompt

```
    ┌──────────────────────────────────────────────┐
    │                                              │
    ▼                                              │
PERCEIVE ──▶ RECALL ──▶ DECIDE ──▶ ACT ──▶ RECORD ─┘
read the     what do    pick the   run     write the
challenge    I already  best un-   the      result back
into facts   know?      tried move skill    into memory
```

Every skill declares **when it applies** (a precondition over the perceived facts) and
**how it runs**. The loop picks among the skills that apply and have not been tried, runs
one, writes the outcome to memory, and goes round again — until something returns a flag,
or nothing untried applies and the agent stops honestly instead of guessing.

Option 2 in the menu makes that visible. Watch `wiener` get promoted after it earns a win:

```
      perceived files: ['c.txt', 'e.txt', 'n.txt']
      trying 'small-exponent' (memory score 0.50)
      trying 'wiener' (memory score 0.50)
      'wiener' produced flag{circle_memory_agent_demo}
      perceived files: ['c.txt', 'e.txt', 'n.txt']
      trying 'wiener' (memory score 1.00)      ← memory reordered DECIDE
      trying 'small-exponent' (memory score 0.50)
      trying 'fermat' (memory score 0.50)
      'fermat' produced flag{circle_memory_agent_demo}
```

Nothing was retrained and nothing was prompted. `RECORD` wrote five outcomes down and
`DECIDE` read them back. That is the whole mechanism, and it is about forty lines of
Python in `demo_agent.py`.

**To make it your agent, replace the `SKILLS` list.** The loop never mentions RSA; swap
the repertoire and the same loop drives a pwn agent, a web agent, a forensics agent.

---

## What is in the image

| Path | What it is | Does the arena care? |
|---|---|---|
| `/opt/agent/agent.py` | The agent. Defines `solve(files, meta=None)`. | **Yes — this is the submission.** |
| `/opt/demo/menu.py` | The interactive menu, the image's `ENTRYPOINT`. | No. Overridden at match time. |
| `/opt/demo/samples.py` | Offline challenge generator, so the demo needs no arena. | No. |

`/opt/agent/agent.py` is the repository's `demo_agent.py`, copied in by the Dockerfile
rather than duplicated here — one canonical circle-memory agent, no drift.

---

## The contract, in full

Two requirements. That is genuinely all:

1. **`/opt/agent/agent.py` defines `solve(files, meta=None)`**, readable by any uid.
2. **`python` is on `PATH`.**

```python
def solve(files, meta=None):
    # files : {filename: contents} — exactly what a human player downloads
    # meta  : {"challenge_id", "gen", "category", "title", "story", "hints"}
    return "flag{...}"          # or None when you are honestly stuck
```

Everything else is yours: base image, interpreter, libraries, compiled binaries, extra
data files.

### Things that get images rejected

The arena test-runs your image at upload time and tells you which of these it was, so you
find out in seconds rather than losing a match:

| Mistake | Symptom | Fix |
|---|---|---|
| `/opt/agent` readable only by root | `not readable by the arena's run user` | `RUN chmod -R a+rX /opt/agent` — the arena runs you with `--user`, not as root |
| Base image with no `python` on `PATH` | `python is not on PATH inside your image` | Symlink it, or use a base that has it |
| Slow work at import time | probe times out after 120s | Do it inside `solve()`, not at module top level |
| `docker export` instead of `docker save` | `no manifest.json in the archive` | `docker save` — export flattens the filesystem and drops the metadata |
| Several images in one archive | `the archive holds N images` | Save exactly one |
| Tagged as an arena image | `reserved by the arena` | `docker tag` it to something else and save again |
| Image too large | `the image unpacks to N MB` | `-slim` base, multi-stage build. Deleting files in a *later* layer does not shrink an image |

### Limits your image runs under

Same as everyone's — your image supplies the filesystem, the arena supplies the rules, and
none of them can be opted out of from inside the image:

* `--network none`, all capabilities dropped, `no-new-privileges`
* memory / PID / CPU caps, and a per-rung wall-clock timeout
* a fresh container per rung, so nothing you write to disk survives to the next generation
* one image kept per team — submitting a new one reclaims the old

---

## Where to go next

* `../champion_agent/` — the `.zip` route, for when you only need one extra library
* `../../demo_agent.py` — the circle-memory template itself, with `--selftest` and `--serve`
* `../../ARENA.md` — the three submission routes and the operator's view of image intake
* `/docs` on a running arena — the live contract, current limits and library list
