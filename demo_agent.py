#!/usr/bin/env python3
"""AutoCTF Arena — DEMO agent: the "loop + memory" (circle-memory) pattern.

This file is a TEACHING TEMPLATE for competitors. It shows how to structure and
package an agent WITHOUT calling any language model — no prompts, no API keys,
no network. The intelligence here is an explicit agent loop over a memory and a
set of skills. Copy this file, replace the SKILLS, keep the loop.

────────────────────────────────────────────────────────────────────────────
The circle (the loop the agent runs every challenge)

        ┌──────────────────────────────────────────────┐
        │                                              │
        ▼                                              │
    PERCEIVE ──▶ RECALL ──▶ DECIDE ──▶ ACT ──▶ RECORD ─┘
    read the     what do    pick the   run     write the
    challenge    I already  best un-   the      result back
    into facts   know?      tried move skill    into memory

    The loop repeats until a skill returns a flag, or no untried skill applies
    (the agent is honestly stuck — it returns None instead of guessing).

Memory has two scopes, dictated by how the arena runs agents:

  • WITHIN one challenge — every run of the loop remembers which skills it has
    already tried, so it never repeats a move and it stops when out of moves.

  • ACROSS challenges — the arena runs an UPLOADED agent in a fresh, network-less
    container that is destroyed after each attempt, so module state does NOT
    survive between generations. But a REMOTE agent (`--serve`, below) is one
    long-lived process the arena calls repeatedly, so its memory DOES persist —
    and this demo uses that to rank skills by how often they have worked before.
    That ranking is the memory visibly changing the agent's behaviour, with no
    model involved.

────────────────────────────────────────────────────────────────────────────
The contract the arena calls

    solve(files: dict[str, str], meta: dict | None) -> str | None
        files : {filename: contents} — exactly what a human player downloads
        meta  : {"challenge_id","gen","category","title","story","hints",...}
        return: the flag string, or None if you cannot solve this one

Everything below is self-contained on purpose: uploaded agents run isolated,
with no access to this repository and no network. Whatever you need must be in
your file (or the zip you upload).

Package + run:
    python demo_agent.py --selftest          # climb the ladder locally, no server
    python demo_agent.py --serve 9000        # run as a persistent remote agent
    python demo_agent.py --enter --server URL --name "YourTeam"   # real match

Or ship it as a Docker image, which is what `examples/docker_demo/` builds from
this exact file — the arena looks for `solve` at `/opt/agent/agent.py`, so the
whole Dockerfile contract is:

    COPY demo_agent.py /opt/agent/agent.py
    RUN chmod -R a+rX /opt/agent

That route lets an agent bring its own libraries instead of borrowing the
arena's. See `examples/docker_demo/README.md`.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections import Counter
from functools import reduce


# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — MEMORY
#  A plain object. No database, no model. Just the facts the agent has gathered
#  and the outcomes of what it has tried. This is what makes it an *agent* and
#  not a one-shot function.
# ═══════════════════════════════════════════════════════════════════════════
class Memory:
    def __init__(self) -> None:
        # Within-challenge: reset at the start of every solve().
        self.facts: dict = {}            # what PERCEIVE learned about this challenge
        self.tried: set[str] = set()     # skills already attempted this challenge
        self.log: list[tuple[str, bool, str]] = []   # (skill, worked, note)

        # Across-challenge: survives between challenges in --serve mode only.
        # Counts how often each skill has produced a flag, so DECIDE can try the
        # historically-useful skills first. This is memory steering behaviour.
        self.skill_wins: Counter = Counter()
        self.skill_uses: Counter = Counter()

    def start_challenge(self, facts: dict) -> None:
        self.facts = facts
        self.tried = set()
        self.log = []

    def has_tried(self, skill_name: str) -> bool:
        return skill_name in self.tried

    def record(self, skill_name: str, worked: bool, note: str = "") -> None:
        self.tried.add(skill_name)
        self.log.append((skill_name, worked, note))
        self.skill_uses[skill_name] += 1
        if worked:
            self.skill_wins[skill_name] += 1

    def score(self, skill_name: str) -> float:
        """Historical success rate, used only to ORDER which skill to try next.

        Unknown skills get a small optimism bonus so they are still explored —
        the classic explore/exploit balance, done with arithmetic, not a model.
        """
        uses = self.skill_uses[skill_name]
        if uses == 0:
            return 0.5
        return self.skill_wins[skill_name] / uses


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — SKILLS (the action repertoire)
#  Each skill declares WHEN it applies (a precondition over the perceived facts)
#  and HOW it runs. The agent loop reasons over these declaratively. To teach
#  competitors your own domain, this is the ONE part you replace.
# ═══════════════════════════════════════════════════════════════════════════
class Skill:
    def __init__(self, name, applies, run):
        self.name = name
        self.applies = applies       # (facts) -> bool
        self.run = run               # (facts) -> flag str | None


# ---- small RSA helpers (the "tools" the skills use) -----------------------
def _iroot(x: int, k: int) -> int:
    """Integer k-th root by binary search."""
    if x < 0:
        return 0
    lo, hi = 0, 1 << ((x.bit_length() // k) + 2)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _to_flag(m: int) -> str | None:
    """Turn a recovered integer back into bytes and keep it only if it reads
    like a flag. A wrong attack yields garbage bytes, which this rejects."""
    try:
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
    except (OverflowError, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if text.startswith("flag{") and text.endswith("}") else None


def _egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def _wiener(e: int, n: int):
    """Wiener's attack: small private exponent via continued-fraction convergents."""
    cf, a, b = [], e, n
    while b:
        cf.append(a // b)
        a, b = b, a % b
    for i in range(len(cf)):
        num, den = 1, 0
        for x in reversed(cf[: i + 1]):
            num, den = x * num + den, num
        k, d = num, den
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        bb = n - phi + 1
        disc = bb * bb - 4 * n
        if disc >= 0 and math.isqrt(disc) ** 2 == disc:
            return d
    return None


def _fermat(n: int, cap: int = 1 << 20):
    """Fermat factoring: works when the two primes are close together."""
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(cap):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b
        a += 1
    return None


def _pollard(n: int, bound: int = 4000):
    """Pollard p-1: works when p-1 is composed of small factors."""
    a = 2
    for j in range(2, bound):
        a = pow(a, j, n)
        d = math.gcd(a - 1, n)
        if 1 < d < n:
            return d
    return None


def _from_factor(p: int, n: int, e: int, c: int):
    q = n // p
    d = pow(e, -1, (p - 1) * (q - 1))
    return _to_flag(pow(c, d, n))


# ---- the skill implementations --------------------------------------------
def _num(facts, name):
    return int(facts["files"][name].strip())


def _skill_hastad(facts):
    ns = [_num(facts, f"n{i}.txt") for i in range(3)]
    cs = [_num(facts, f"c{i}.txt") for i in range(3)]
    mod = reduce(lambda x, y: x * y, ns)
    x = sum(r * (mod // m) * pow(mod // m, -1, m) for r, m in zip(cs, ns)) % mod
    return _to_flag(_iroot(x, 3))


def _skill_common_modulus(facts):
    n, e1, e2 = _num(facts, "n.txt"), _num(facts, "e1.txt"), _num(facts, "e2.txt")
    c1, c2 = _num(facts, "c1.txt"), _num(facts, "c2.txt")
    _, a, b = _egcd(e1, e2)
    if a < 0:
        c1, a = pow(c1, -1, n), -a
    if b < 0:
        c2, b = pow(c2, -1, n), -b
    return _to_flag(pow(c1, a, n) * pow(c2, b, n) % n)


def _skill_small_e(facts):
    n, e, c = _num(facts, "n.txt"), _num(facts, "e.txt"), _num(facts, "c.txt")
    if e > 5:
        return None
    m = _iroot(c, e)
    return _to_flag(m) if m ** e == c else None


def _skill_wiener(facts):
    n, e, c = _num(facts, "n.txt"), _num(facts, "e.txt"), _num(facts, "c.txt")
    d = _wiener(e, n)
    return _to_flag(pow(c, d, n)) if d else None


def _skill_fermat(facts):
    n, e, c = _num(facts, "n.txt"), _num(facts, "e.txt"), _num(facts, "c.txt")
    p = _fermat(n)
    return _from_factor(p, n, e, c) if p and n % p == 0 else None


def _skill_pollard(facts):
    n, e, c = _num(facts, "n.txt"), _num(facts, "e.txt"), _num(facts, "c.txt")
    p = _pollard(n)
    return _from_factor(p, n, e, c) if p and n % p == 0 else None


def _has(*names):
    """Build a precondition: 'these files are all present'."""
    want = set(names)
    return lambda facts: want <= set(facts["files"])


# The repertoire. Order here does NOT decide execution order — the loop does,
# using memory. This is just the catalogue of what the agent CAN do.
SKILLS = [
    Skill("hastad-broadcast", _has("n0.txt", "n1.txt", "n2.txt",
                                   "c0.txt", "c1.txt", "c2.txt"), _skill_hastad),
    Skill("common-modulus", _has("n.txt", "e1.txt", "e2.txt",
                                 "c1.txt", "c2.txt"), _skill_common_modulus),
    Skill("small-exponent", _has("n.txt", "e.txt", "c.txt"), _skill_small_e),
    Skill("wiener", _has("n.txt", "e.txt", "c.txt"), _skill_wiener),
    Skill("fermat", _has("n.txt", "e.txt", "c.txt"), _skill_fermat),
    Skill("pollard-p-1", _has("n.txt", "e.txt", "c.txt"), _skill_pollard),
]


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — PERCEIVE
#  Turn the raw challenge into structured facts the loop can reason over. Keep
#  the raw files too, since the skills need them.
# ═══════════════════════════════════════════════════════════════════════════
def perceive(files: dict, meta: dict | None) -> dict:
    return {
        "files": files or {},
        "filenames": sorted((files or {}).keys()),
        "category": (meta or {}).get("category"),
        "gen": (meta or {}).get("gen"),
    }


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — THE AGENT (the loop itself)
#  This is the reusable heart. It never mentions RSA. Swap the SKILLS and the
#  same loop drives a pwn agent, a web agent, a forensics agent.
# ═══════════════════════════════════════════════════════════════════════════
class Agent:
    def __init__(self, memory: Memory | None = None, verbose: bool = False):
        self.memory = memory or Memory()
        self.verbose = verbose

    def _say(self, msg: str) -> None:
        if self.verbose:
            print(f"      {msg}", file=sys.stderr)

    def decide(self, facts: dict) -> Skill | None:
        """RECALL + DECIDE: among skills that apply and have not been tried this
        challenge, pick the one memory rates highest. Returns None when the
        agent is out of moves — the honest 'I am stuck' signal."""
        candidates = [s for s in SKILLS
                      if s.applies(facts) and not self.memory.has_tried(s.name)]
        if not candidates:
            return None
        candidates.sort(key=lambda s: self.memory.score(s.name), reverse=True)
        return candidates[0]

    def solve_once(self, files: dict, meta: dict | None = None) -> str | None:
        # PERCEIVE
        facts = perceive(files, meta)
        self.memory.start_challenge(facts)
        self._say(f"perceived files: {facts['filenames']}")

        # the circle
        while True:
            skill = self.decide(facts)               # RECALL + DECIDE
            if skill is None:
                self._say("no untried skill applies — stuck")
                return None
            self._say(f"trying '{skill.name}' (memory score "
                      f"{self.memory.score(skill.name):.2f})")
            try:
                flag = skill.run(facts)              # ACT
            except Exception as exc:
                flag = None
                self._say(f"'{skill.name}' raised {type(exc).__name__}: {exc}")
            self.memory.record(skill.name, worked=bool(flag))   # RECORD
            if flag:
                self._say(f"'{skill.name}' produced {flag}")
                return flag
            # otherwise: loop — memory now knows this skill failed, DECIDE again


# One module-level agent so that in --serve mode its cross-challenge memory
# (skill_wins/skill_uses) accumulates across every match the arena runs.
_AGENT = Agent()


# ═══════════════════════════════════════════════════════════════════════════
#  PART 5 — THE ARENA CONTRACT
#  The single function the arena requires. Everything above is your business;
#  this is the one name the platform looks for.
# ═══════════════════════════════════════════════════════════════════════════
def solve(files: dict, meta: dict | None = None) -> str | None:
    return _AGENT.solve_once(files, meta)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 6 — PACKAGING MODES (selftest / serve / enter)
#  Copied in shape from the reference agent so the demo is a drop-in example of
#  how to run and submit. You rarely need to touch these.
# ═══════════════════════════════════════════════════════════════════════════
def selftest(track: str = "crypto", seed: int | None = None) -> int:
    """Run the arena's own match engine in-process, against this file."""
    import random
    import tempfile
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from arena_platform.store import Store
    from arena_platform.runner import MatchEngine
    from arena_platform.tracks import get_track

    seed = seed if seed is not None else random.SystemRandom().randrange(1, 2 ** 31)
    tmp = Path(tempfile.mkdtemp(prefix="demo-selftest-"))
    (tmp / "agent").mkdir()
    (tmp / "agent" / "agent.py").write_bytes(Path(__file__).read_bytes())

    store = Store(tmp / "selftest.sqlite3")
    engine = MatchEngine(store, tmp / "uploads", workers=1)
    tr = get_track(track)
    team = store.create_team("demo-selftest")
    agent = store.create_agent(team_id=team["id"], name="demo", kind="upload",
                               entry="agent.py", source_dir=str(tmp / "agent"))
    store.create_match(team["id"], agent["id"], track, seed, tr.max_gen)

    print(f"self-test · track={track} · seed={seed} · {len(tr.rungs)} rungs\n")
    result = engine.run_match(store.claim_next_queued())

    for event in store.events(store.recent_matches(1)[0]["id"]):
        p, evt = event["payload"], event["evt"]
        if evt == "solve":
            print(f"  ✔ Gen-{p['gen']:<2} {p['rung']:<14} solved in {p['seconds']:.2f}s")
        elif evt == "agent.stuck":
            print(f"  ✗ Gen-{p['gen']:<2} {p['rung']:<14} {p['reason']}")
        elif evt == "match.finished":
            print(f"\n{p['summary']}")
    return 0 if result["reached_gen"] >= 0 else 1


def serve(port: int, host: str = "0.0.0.0", token: str = "") -> None:
    """Expose solve() at POST /solve. Because this process stays alive, the
    agent's cross-challenge memory persists between the arena's calls."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            if token and self.headers.get("Authorization", "") != f"Bearer {token}":
                return self._reply(401, {"error": "bad token"})
            try:
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                challenge = json.loads(body)
            except Exception as exc:
                return self._reply(400, {"error": f"bad request: {exc}"})
            meta = {k: v for k, v in challenge.items() if k != "files"}
            try:
                flag = solve(challenge.get("files") or {}, meta)
            except Exception as exc:
                print(f"[gen {challenge.get('gen')}] solve() raised "
                      f"{type(exc).__name__}: {exc}")
                return self._reply(200, {"flag": None})
            # Show the memory that just steered this decision.
            print(f"[gen {challenge.get('gen')}] "
                  f"{'solved' if flag else 'no flag'} · "
                  f"skill wins so far: {dict(_AGENT.memory.skill_wins)}")
            self._reply(200, {"flag": flag})

        def _reply(self, code, data):
            payload = json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    print(f"remote demo agent on http://{host}:{port}/solve")
    print("register that URL on the arena's 'Enter your agent' page (Remote tab)")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


def enter(server: str, name: str, track: str, token: str = "") -> int:
    import urllib.error
    import urllib.request
    from pathlib import Path

    server = server.rstrip("/")

    def call(path, data=None, raw=None, ctype="application/json"):
        req = urllib.request.Request(server + path, method="POST" if (data or raw) else "GET")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        payload = raw if raw is not None else (json.dumps(data).encode() if data else None)
        if payload is not None:
            req.add_header("Content-Type", ctype)
        try:
            with urllib.request.urlopen(req, payload, timeout=60) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            raise SystemExit(f"{path} failed (HTTP {exc.code}): "
                             f"{exc.read().decode('utf-8', 'replace')}") from exc

    if not token:
        team = call("/api/teams", {"name": name})
        token = team["token"]
        print(f"registered team {team['name']}\n  token: {token}   (save this)")

    source = Path(__file__).read_bytes()
    agent = call(f"/api/agents?token={token}&kind=upload&name={name}-agent&filename=agent.py",
                 raw=source, ctype="application/octet-stream")
    print(f"uploaded agent {agent['id']}")
    match = call(f"/api/matches?token={token}",
                 {"agent_id": agent["id"], "track": track})
    print(f"match {match['match_id']} queued — watch it at {server}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true",
                    help="climb the ladder locally without a server")
    ap.add_argument("--serve", type=int, metavar="PORT",
                    help="run as a persistent remote agent endpoint on PORT")
    ap.add_argument("--enter", action="store_true",
                    help="upload this file to an arena and run a match")
    ap.add_argument("--server", default="http://127.0.0.1:8090")
    ap.add_argument("--name", default="DemoTeam")
    ap.add_argument("--track", default="crypto")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--token", default="")
    ap.add_argument("--verbose", action="store_true",
                    help="print the loop's PERCEIVE/DECIDE/ACT/RECORD steps")
    args = ap.parse_args()

    _AGENT.verbose = args.verbose
    if args.serve:
        serve(args.serve, token=args.token)
        return 0
    if args.enter:
        return enter(args.server, args.name, args.track, args.token)
    return selftest(args.track, args.seed)


if __name__ == "__main__":
    raise SystemExit(main())
