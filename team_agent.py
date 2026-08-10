#!/usr/bin/env python3
"""AutoCTF Arena — starter agent.

This is YOUR agent. Edit `solve()`, then choose how it enters the arena:

    python team_agent.py --selftest              # climb the ladder locally, no server
    python team_agent.py --serve 9000            # expose it as a remote agent endpoint
    python team_agent.py --enter --server URL --name "YourTeam"
                                                 # upload this file and run a real match

`--selftest` is the fast loop: it builds the same verified ladder the arena uses and
tells you which rung stops you, without registering anything.

The default body below is the reference RSA toolkit — small-e, Håstad, common
modulus, Wiener, Fermat, Pollard p-1. It climbs six rungs and then dies at
Boneh-Durfee, because it has no lattice attack. Beating that is the exercise.
"""
from __future__ import annotations

import argparse
import json
import sys
import time


# ===========================================================================
#  YOUR AGENT — replace the body of solve() below.
#
#  files : {filename: contents}   exactly what a human player downloads
#  meta  : {"challenge_id", "gen", "category", "title", "story", "hints",
#           "time_limit_s"}       optional context; ignore it if you like
#  return: the flag string, or None if you cannot solve this one
#
#  Everything below is self-contained on purpose: uploaded agents run isolated,
#  with no access to this repository and no network. Whatever you need must be
#  in your file (or in the zip you upload).
# ===========================================================================
import math
from functools import reduce


def _iroot(x: int, k: int) -> int:
    """Integer k-th root by binary search."""
    if x < 0:
        return 0
    hi = 1
    while hi ** k <= x:
        hi <<= 1
    lo = hi >> 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _to_flag(m: int) -> str | None:
    try:
        text = m.to_bytes((m.bit_length() + 7) // 8, "big").decode()
    except Exception:
        return None
    return text if text.startswith("flag{") else None


def _egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def _wiener(e: int, n: int):
    """Continued-fraction attack: recovers a small private exponent d."""
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
        if disc >= 0:
            root = math.isqrt(disc)
            if root * root == disc:
                return d
    return None


def _fermat(n: int, cap: int = 1 << 20):
    """Factor n when its primes sit close together."""
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


def _pollard_p_minus_1(n: int, bound: int = 4000):
    """Factor n when p-1 is smooth."""
    a = 2
    for j in range(2, bound):
        a = pow(a, j, n)
        d = math.gcd(a - 1, n)
        if 1 < d < n:
            return d
    return None


def _from_factor(p: int, n: int, e: int, c: int):
    q = n // p
    try:
        d = pow(e, -1, (p - 1) * (q - 1))
    except Exception:
        return None
    return _to_flag(pow(c, d, n))


def solve(files: dict, meta: dict | None = None) -> str | None:
    """Reference RSA toolkit. It climbs six rungs and then dies at Boneh-Durfee,
    because it has no lattice attack. Beating that rung is the exercise."""
    def num(name: str) -> int:
        return int(files[name].strip())

    names = set(files)

    # Håstad broadcast: one message, e=3, three moduli -> CRT then cube root.
    if {"n0.txt", "n1.txt", "n2.txt", "c0.txt", "c1.txt", "c2.txt"} <= names:
        ns = [num(f"n{i}.txt") for i in range(3)]
        cs = [num(f"c{i}.txt") for i in range(3)]
        modulus = reduce(lambda x, y: x * y, ns)
        x = sum(r * (modulus // m) * pow(modulus // m, -1, m)
                for r, m in zip(cs, ns)) % modulus
        return _to_flag(_iroot(x, 3))

    # Common modulus: same n, coprime exponents -> Bézout combination.
    if {"n.txt", "e1.txt", "e2.txt", "c1.txt", "c2.txt"} <= names:
        n, e1, e2 = num("n.txt"), num("e1.txt"), num("e2.txt")
        c1, c2 = num("c1.txt"), num("c2.txt")
        _, a, b = _egcd(e1, e2)
        if a < 0:
            c1, a = pow(c1, -1, n), -a
        if b < 0:
            c2, b = pow(c2, -1, n), -b
        return _to_flag(pow(c1, a, n) * pow(c2, b, n) % n)

    # Single (n, e, c): try each attack in the kit.
    if {"n.txt", "e.txt", "c.txt"} <= names:
        n, e, c = num("n.txt"), num("e.txt"), num("c.txt")

        if e <= 5:                                   # unpadded, m^e < n
            m = _iroot(c, e)
            if m ** e == c and (flag := _to_flag(m)):
                return flag

        if (d := _wiener(e, n)) and (flag := _to_flag(pow(c, d, n))):
            return flag

        if (p := _fermat(n)) and n % p == 0 and (flag := _from_factor(p, n, e, c)):
            return flag

        if (p := _pollard_p_minus_1(n)) and n % p == 0 and (flag := _from_factor(p, n, e, c)):
            return flag

    return None      # no tool in the kit cracks this one
# ===========================================================================


# ---------------------------------------------------------------------------
# mode 1 — local self-test against the real ladder
# ---------------------------------------------------------------------------
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
    tmp = Path(tempfile.mkdtemp(prefix="arena-selftest-"))
    (tmp / "agent").mkdir()
    (tmp / "agent" / "agent.py").write_bytes(Path(__file__).read_bytes())

    store = Store(tmp / "selftest.sqlite3")
    engine = MatchEngine(store, tmp / "uploads", workers=1)
    tr = get_track(track)
    team = store.create_team("selftest")
    agent = store.create_agent(team_id=team["id"], name="local", kind="upload",
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


# ---------------------------------------------------------------------------
# mode 2 — serve as a remote agent the arena can call
# ---------------------------------------------------------------------------
def serve(port: int, host: str = "0.0.0.0", token: str = "") -> None:
    """Expose solve() at POST /solve, in the shape the arena expects."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            if token:
                sent = self.headers.get("Authorization", "")
                if sent != f"Bearer {token}":
                    return self._reply(401, {"error": "bad token"})
            try:
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                challenge = json.loads(body)
            except Exception as exc:
                return self._reply(400, {"error": f"bad request: {exc}"})

            gen = challenge.get("gen")
            started = time.monotonic()
            try:
                meta = {k: v for k, v in challenge.items() if k != "files"}
                flag = solve(challenge.get("files") or {}, meta)
            except Exception as exc:
                print(f"[gen {gen}] solve() raised {type(exc).__name__}: {exc}")
                return self._reply(200, {"flag": None})
            print(f"[gen {gen}] {'solved' if flag else 'no flag'} "
                  f"in {time.monotonic() - started:.2f}s")
            self._reply(200, {"flag": flag})

        def _reply(self, code, data):
            payload = json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    print(f"remote agent listening on http://{host}:{port}/solve")
    print("register that URL on the arena's 'Enter your agent' page (Remote endpoint tab)")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


# ---------------------------------------------------------------------------
# mode 3 — upload this file to an arena and run a real match
# ---------------------------------------------------------------------------
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
            detail = exc.read().decode("utf-8", "replace")
            raise SystemExit(f"{path} failed (HTTP {exc.code}): {detail}") from exc

    if not token:
        team = call("/api/teams", {"name": name})
        token = team["token"]
        print(f"registered team {team['name']}\n  token: {token}   (save this)")

    source = Path(__file__).read_bytes()
    agent = call(f"/api/agents?kind=upload&name={name}-agent&filename=agent.py",
                 raw=source, ctype="application/octet-stream")
    print(f"uploaded agent {agent['id']} ({agent['size_bytes']} bytes)")

    match = call("/api/matches", {"agent_id": agent["id"], "track": track})
    match_id = match["match_id"]
    print(f"match queued: {server}/match/{match_id}\n")

    seen = -1
    while True:
        state = call(f"/api/matches/{match_id}?after={seen}")
        for event in state["events"]:
            seen = event["seq"]
            p, evt = event["payload"], event["evt"]
            if evt == "challenge.deployed":
                print(f"  → Gen-{p['gen']} deployed ({p['rung']})")
            elif evt == "solve":
                print(f"  ✔ solved Gen-{p['gen']} in {p['seconds']:.2f}s (+{p['points']})")
            elif evt == "agent.stuck":
                print(f"  ✗ stuck at Gen-{p['gen']}: {p['reason']}")
            elif evt == "match.finished":
                print(f"\n{p['summary']}")
                return 0
        if state["match"]["status"] in ("done", "error"):
            return 0
        time.sleep(2)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true",
                    help="climb the ladder locally without a server")
    ap.add_argument("--serve", type=int, metavar="PORT",
                    help="run as a remote agent endpoint on PORT")
    ap.add_argument("--enter", action="store_true",
                    help="upload this file to an arena and run a match")
    ap.add_argument("--server", default="http://127.0.0.1:8090")
    ap.add_argument("--name", default="YourTeam")
    ap.add_argument("--track", default="crypto")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--token", default="", help="existing team token (skips registration)")
    ap.add_argument("--serve-token", default="", help="require this bearer token in --serve mode")
    args = ap.parse_args()

    if args.serve:
        serve(args.serve, token=args.serve_token)
        return 0
    if args.enter:
        return enter(args.server, args.name, args.track, args.token)
    return selftest(args.track, args.seed)          # the default: fastest feedback


if __name__ == "__main__":
    raise SystemExit(main())
