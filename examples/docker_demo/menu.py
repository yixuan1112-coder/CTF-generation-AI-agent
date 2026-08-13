#!/usr/bin/env python3
"""The demo image's front door: open the container, choose to run the AI.

This is the image's ENTRYPOINT, and it exists purely for humans. The arena never
sees it — a match starts the container with `--entrypoint python`, which
discards ENTRYPOINT and CMD entirely and runs the harness instead. So the same
image is both a thing you can explore interactively and a valid competition
submission, and neither half can interfere with the other.

    docker run --rm -it autoctf-demo-agent          # this menu
    docker run --rm    autoctf-demo-agent solve     # non-interactive, one shot
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import time

AGENT_PATH = os.environ.get("ARENA_AGENT_DIR", "/opt/agent") + "/agent.py"
DEMO_DIR = os.path.dirname(os.path.abspath(__file__))

BOLD, DIM, GREEN, RED, CYAN, OFF = (
    "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[36m", "\033[0m")
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    BOLD = DIM = GREEN = RED = CYAN = OFF = ""


def load_agent():
    """Import the agent exactly the way the arena's harness does."""
    spec = importlib.util.spec_from_file_location("team_agent_module", AGENT_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {AGENT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _samples():
    sys.path.insert(0, DEMO_DIR)
    import samples
    return samples


# ---------------------------------------------------------------------------
# 1 / 2 — run the agent
# ---------------------------------------------------------------------------
def run_agent(verbose: bool = False) -> int:
    samples = _samples()
    agent = load_agent()
    if verbose and hasattr(agent, "_AGENT"):
        agent._AGENT.verbose = True

    print(f"\n{BOLD}Running the agent against {len(samples.RUNGS)} sample rungs{OFF}")
    print(f"{DIM}No model, no prompts, no network — a loop over a memory and a "
          f"set of skills.{OFF}\n", flush=True)

    solved = 0
    for challenge in samples.build():
        meta = {k: v for k, v in challenge.items() if k != "files"}
        started = time.time()
        flag = agent.solve(challenge["files"], meta)
        elapsed = time.time() - started
        ok = flag == samples.FLAG
        solved += ok
        mark = f"{GREEN}✔{OFF}" if ok else f"{RED}✗{OFF}"
        # flush: the agent's verbose trace goes to stderr, and an unflushed
        # stdout would let the whole summary land after it when piped.
        print(f"  {mark} Gen-{meta['gen']} {challenge['rung']:<11} "
              f"{(flag or 'no flag'):<34} {elapsed:5.2f}s", flush=True)

    print(f"\n{BOLD}{solved}/{len(samples.RUNGS)} rungs solved.{OFF}")
    memory = getattr(getattr(agent, "_AGENT", None), "memory", None)
    if memory is not None and getattr(memory, "skill_wins", None):
        print(f"\n{CYAN}What the memory kept across those five challenges:{OFF}")
        for skill, uses in sorted(memory.skill_uses.items(), key=lambda kv: -kv[1]):
            wins = memory.skill_wins[skill]
            print(f"    {skill:<20} {wins}/{uses} attempts produced a flag "
                  f"→ score {memory.score(skill):.2f}")
        print(f"{DIM}    That score is the ordering DECIDE uses next time. The agent "
              f"got better\n    at choosing without anyone retraining anything.{OFF}")
    return 0 if solved == len(samples.RUNGS) else 1


# ---------------------------------------------------------------------------
# 3 — the same check the arena runs at submission time
# ---------------------------------------------------------------------------
def check() -> int:
    print(f"\n{BOLD}Submission readiness{OFF}")
    print(f"{DIM}These are the arena's actual acceptance criteria for an image "
          f"agent.{OFF}\n")
    ok = True

    def report(label: str, passed: bool, detail: str = "") -> None:
        nonlocal ok
        ok = ok and passed
        mark = f"{GREEN}✔{OFF}" if passed else f"{RED}✗{OFF}"
        print(f"  {mark} {label}" + (f"  {DIM}{detail}{OFF}" if detail else ""))

    report(f"{AGENT_PATH} exists", os.path.isfile(AGENT_PATH))
    report(f"{AGENT_PATH} is world-readable",
           os.path.isfile(AGENT_PATH) and os.access(AGENT_PATH, os.R_OK),
           "the arena runs your image with --user, never as root")
    python = subprocess.run(["sh", "-c", "command -v python"],
                            capture_output=True, text=True)
    report("`python` is on PATH", python.returncode == 0,
           (python.stdout or "").strip() or "the arena uses --entrypoint python")
    try:
        module = load_agent()
        report("agent.py imports cleanly", True)
        report("agent.py defines a callable solve()",
               callable(getattr(module, "solve", None)))
    except Exception as exc:
        report("agent.py imports cleanly", False, f"{type(exc).__name__}: {exc}")
        report("agent.py defines a callable solve()", False)

    print()
    if ok:
        print(f"{GREEN}{BOLD}This image is submission-ready.{OFF}")
        print(f"{DIM}  docker save autoctf-demo-agent | gzip > agent.tar.gz\n"
              f"  curl -X POST \"$ARENA/api/agents?kind=image&name=my-agent\" \\\n"
              f"       -H \"Authorization: Bearer $TOKEN\" "
              f"--data-binary @agent.tar.gz{OFF}")
    else:
        print(f"{RED}{BOLD}The arena would reject this image.{OFF} "
              "Fix the ✗ lines above and rebuild.")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# 4 — the contract, on screen, for people who arrived without the README
# ---------------------------------------------------------------------------
CONTRACT = f"""
{BOLD}The one function the arena calls{OFF}

    def solve(files, meta=None) -> str | None:
        files : {{filename: contents}} — exactly what a human player downloads
        meta  : {{"challenge_id", "gen", "category", "title", "story", "hints"}}
        return: the flag, or None when you are honestly stuck

{BOLD}The circle this agent runs{OFF}

        ┌──────────────────────────────────────────────┐
        │                                              │
        ▼                                              │
    PERCEIVE ──▶ RECALL ──▶ DECIDE ──▶ ACT ──▶ RECORD ─┘
    read the     what do    pick the   run     write the
    challenge    I already  best un-   the      result back
    into facts   know?      tried move skill    into memory

    No prompts and no model anywhere in it. "Intelligence" here is an explicit
    loop over a memory: RECORD writes every outcome down, and DECIDE reads that
    memory back to order what it tries next. Replace the SKILLS and the same
    loop drives a pwn agent, a web agent, a forensics agent.

{BOLD}What the image owes the arena{OFF}

    /opt/agent/agent.py     defines solve(), readable by any uid
    python                  on PATH

    Everything else is yours. The arena overrides ENTRYPOINT, CMD and USER at
    run time, so this menu never executes during a match — and no image can opt
    out of --network none, the memory cap or the dropped capabilities.
"""


def show_contract() -> int:
    print(CONTRACT)
    return 0


def show_source() -> int:
    print(f"\n{DIM}--- {AGENT_PATH} ---{OFF}")
    with open(AGENT_PATH, encoding="utf-8") as fh:
        sys.stdout.write(fh.read())
    return 0


# ---------------------------------------------------------------------------
# the menu
# ---------------------------------------------------------------------------
ACTIONS = {
    "1": ("Run the AI agent on five sample rungs", lambda: run_agent(False)),
    "2": ("Run it verbosely — watch PERCEIVE → DECIDE → ACT → RECORD",
          lambda: run_agent(True)),
    "3": ("Check this image is submission-ready", check),
    "4": ("Show the agent contract and the circle", show_contract),
    "5": ("Print the agent source", show_source),
}
ALIASES = {"solve": "1", "run": "1", "verbose": "2", "check": "3",
           "contract": "4", "source": "5"}

BANNER = f"""
{BOLD}  AutoCTF Arena — circle-memory demo agent{OFF}
{DIM}  ────────────────────────────────────────────────────────────────{OFF}
  A packaged agent with no language model in it. Pick something:
"""


def main(argv: list[str]) -> int:
    if argv:
        choice = ALIASES.get(argv[0].lower(), argv[0])
        if choice in ACTIONS:
            return ACTIONS[choice][1]()
        if argv[0] in ("sh", "bash", "shell"):
            return subprocess.call(["sh"])
        print(f"unknown command {argv[0]!r}; try: "
              f"{', '.join(sorted(ALIASES))}, shell", file=sys.stderr)
        return 2

    if not sys.stdin.isatty():
        # Started without -it. Do the useful thing rather than hang on input.
        print(f"{DIM}(no tty — running the agent; use `docker run -it` for the "
              f"menu){OFF}")
        return run_agent(False)

    while True:
        print(BANNER)
        for key, (label, _) in ACTIONS.items():
            print(f"    {BOLD}{key}{OFF}) {label}")
        print(f"    {BOLD}s{OFF}) Shell")
        print(f"    {BOLD}q{OFF}) Quit\n")
        try:
            choice = input("  choose ▸ ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice in ("q", "quit", "exit"):
            return 0
        if choice in ("s", "sh", "shell"):
            subprocess.call(["sh"])
            continue
        action = ACTIONS.get(ALIASES.get(choice, choice))
        if action is None:
            print(f"  {RED}no such option{OFF}")
            continue
        action[1]()
        try:
            input(f"\n{DIM}  press enter for the menu{OFF} ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
