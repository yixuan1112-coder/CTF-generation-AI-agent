#!/usr/bin/env python3
"""AutoCTF-GAN — Team Agent Template.

This is YOUR agent. Run it on your own machine; it connects to a running
AutoCTF-GAN server and tries to beat the challenge-maker agent. Each team gets
its OWN evolving challenge-maker, so your run is independent.

    python team_agent.py --name "YourTeam" --server http://SERVER_IP:8080

How it works: register -> pull the current challenge -> solve it -> submit the
flag -> the challenge-maker evolves to a harder attack -> repeat, until your
agent can no longer keep up. The generation you reach is your score.

>>> To test YOUR agent: replace the body of solve() below. <<<
"""
from __future__ import annotations

import argparse
import json
import urllib.parse
import urllib.request


# ===========================================================================
#  YOUR AGENT — edit this function.
#  Input : files = {filename: contents}  (exactly what a player receives)
#  Output: the flag string "flag{...}", or None if you can't solve it.
# ===========================================================================
def solve(files: dict) -> str | None:
    # Default: use the reference RSA toolkit so this works out of the box.
    # Replace everything below with your own attack logic to test your agent.
    try:
        from autoctf_gan import competitor
        return competitor.solve(files)
    except Exception:
        return None
# ===========================================================================


def _get(server: str, path: str, **q):
    url = server.rstrip("/") + path + ("?" + urllib.parse.urlencode(q) if q else "")
    with urllib.request.urlopen(url, timeout=120) as r:
        return json.load(r)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="YourTeam")
    ap.add_argument("--server", default="http://127.0.0.1:8080")
    ap.add_argument("--rounds", type=int, default=30)
    args = ap.parse_args()

    reg = _get(args.server, "/comp/register", name=args.name)
    tid = reg["team_id"]
    print(f"[{args.name}] registered against {args.server}  (team {tid})")

    best = -1
    for _ in range(args.rounds):
        ch = _get(args.server, "/comp/challenge", team=tid)
        flag = solve(ch["files"])
        if not flag:
            print(f"[{args.name}] stuck at Gen-{ch['gen']} — the challenge-maker is ahead of you.")
            break
        res = _get(args.server, "/comp/submit", team=tid,
                   challenge=ch["challenge_id"], flag=flag)
        if res.get("correct"):
            best = max(best, ch["gen"])
            evolved = " → it evolves!" if res.get("evolved") else ""
            print(f"[{args.name}] ✔ solved Gen-{ch['gen']} (+{res.get('points')}){evolved}")
        elif res.get("msg", "").startswith("stale"):
            continue
        else:
            print(f"[{args.name}] ✗ wrong flag at Gen-{ch['gen']}")
            break

    st = _get(args.server, "/comp/status", team=tid)
    if best >= 0 and not st.get("solvers_of_current"):
        print(f"\n[{args.name}] RESULT: reached Gen-{best}. "
              f"The agent is now at Gen-{st['gen']} ({st['attack']}) — "
              f"{'you were out-evolved.' if st['gen'] > best else 'you kept pace!'}")
    print("scoreboard:", _get(args.server, "/comp/scoreboard"))


if __name__ == "__main__":
    main()
