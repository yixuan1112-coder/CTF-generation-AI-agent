"""Live competition server — real teams vs. an evolving Generator.

This is the piece that turns the engine into a real contest:

  * teams register and pull the CURRENT challenge variant (never the flag/solver)
  * teams submit a flag; the server checks it and scores the solve
  * the moment the current variant is solved (real signal, not a simulation),
    the Generator MUTATES -> verify_spec -> deploys the next, harder variant

So the target keeps moving: every time a team beats the agent, the agent levels
up. A team only "wins" if it can keep solving faster than the agent escalates —
and the final generation (e.g. Boneh-Durfee) may be beyond every team, leaving
the agent undefeated.

Thread-safe; a single process holds one Competition. api.py exposes it over HTTP.
"""
from __future__ import annotations

import secrets
import threading
import time

from .verify import verify_spec


def _build(category: str, seed: int, gen: int):
    if category == "crypto":
        from .crypto_ladder import gen_crypto_ladder
        return gen_crypto_ladder(seed=seed, generation=gen)
    if category == "reverse":
        from .native import gen_compiled_crackme
        return gen_compiled_crackme(seed=seed, rounds=gen + 1)
    if category == "web":
        from .web import gen_web_ssti
        return gen_web_ssti(seed=seed, generation=gen)
    from .generator import offline_brain
    return offline_brain(category="misc", challenge_type="layered",
                         difficulty="medium", seed=seed, archetype_id="misc.layered")


def _mutate(category: str, spec):
    if category == "crypto":
        from .crypto_ladder import mutate_crypto
        return mutate_crypto(spec)
    if category == "reverse":
        from .native import mutate_native
        return mutate_native(spec)
    if category == "web":
        from .web import mutate_web
        return mutate_web(spec)
    import random
    from .evolve import mutate
    return mutate(spec, [], random.Random(f"{spec.seed}:{spec.lineage.generation}"))


class Competition:
    def __init__(self, category: str = "crypto", seed: int = 1234,
                 evolve_on: int = 1, max_gen: int = 6, verify_deploy: bool = True):
        self.category = category
        self.seed = seed
        self.evolve_on = evolve_on          # solves of current variant that trigger evolution
        self.max_gen = max_gen
        self.verify_deploy = verify_deploy
        self.lock = threading.RLock()
        self.teams: dict[str, dict] = {}
        self.events: list[dict] = []
        self._t0 = time.monotonic()
        self.spec = _build(category, seed, 0)
        self.gen = 0
        self.solvers_of_current: set[str] = set()
        self.first_blood_taken = False
        self._log("challenge.deployed", gen=0, challenge_id=self.spec.spec_id,
                  attack=self._attack())

    # ---- helpers -----------------------------------------------------------
    def _attack(self) -> str:
        return self.spec.mechanics.get("attack_class") or self.spec.challenge_type

    def _log(self, evt: str, **kw) -> None:
        self.events.append({"evt": evt, "t": round(time.monotonic() - self._t0, 2), **kw})

    # ---- public API --------------------------------------------------------
    def register(self, name: str) -> dict:
        with self.lock:
            tid = secrets.token_hex(4)
            self.teams[tid] = {"name": name, "score": 0, "solves": 0}
            self._log("team.registered", team=name, team_id=tid)
            return {"team_id": tid, "name": name}

    def current(self, team_id: str | None = None) -> dict:
        """The player-facing challenge — no flag, no solver, no attack name."""
        with self.lock:
            s = self.spec
            return {"challenge_id": s.spec_id, "gen": self.gen, "category": s.category,
                    "title": s.title, "story": s.story, "hints": s.hints,
                    "files": dict(s.artifacts)}

    def submit(self, team_id: str, challenge_id: str, flag: str) -> dict:
        with self.lock:
            if team_id not in self.teams:
                return {"ok": False, "msg": "unknown team — register first"}
            if challenge_id != self.spec.spec_id:
                return {"ok": True, "correct": False,
                        "msg": "stale challenge — the agent has evolved; pull /challenge again",
                        "current_gen": self.gen}
            if (flag or "").strip() != self.spec.flag:
                self._log("submit.wrong", team=self.teams[team_id]["name"], gen=self.gen)
                return {"ok": True, "correct": False, "points": 0}
            if team_id in self.solvers_of_current:
                return {"ok": True, "correct": True, "points": 0,
                        "msg": "already solved this variant"}

            first = not self.first_blood_taken
            pts = 100 + 60 * self.gen + (50 if first else 0)   # deeper gen worth more
            self.first_blood_taken = True
            self.solvers_of_current.add(team_id)
            self.teams[team_id]["score"] += pts
            self.teams[team_id]["solves"] += 1
            self._log("solve", team=self.teams[team_id]["name"], gen=self.gen,
                      points=pts, first_blood=first)

            evolved = False
            if len(self.solvers_of_current) >= self.evolve_on and self.gen < self.max_gen:
                evolved = self._evolve()
            return {"ok": True, "correct": True, "points": pts, "first_blood": first,
                    "evolved": evolved, "gen": self.gen}

    def _evolve(self) -> bool:
        child = _mutate(self.category, self.spec)
        if self.verify_deploy:
            v = verify_spec(child)                      # never deploy an unsolvable variant
            if not v.valid:
                self._log("evolve.rejected", reason=v.reason)
                return False
        self.spec = child
        self.gen = child.lineage.generation
        self.solvers_of_current = set()
        self.first_blood_taken = False
        self._log("challenge.deployed", gen=self.gen, challenge_id=child.spec_id,
                  attack=self._attack())
        return True

    def scoreboard(self) -> list[dict]:
        with self.lock:
            rows = sorted(self.teams.values(), key=lambda t: -t["score"])
            return [{"name": t["name"], "score": t["score"], "solves": t["solves"]}
                    for t in rows]

    def status(self) -> dict:
        with self.lock:
            return {"category": self.category, "gen": self.gen, "max_gen": self.max_gen,
                    "challenge_id": self.spec.spec_id, "attack": self._attack(),
                    "solvers_of_current": len(self.solvers_of_current),
                    "teams": len(self.teams)}


def run_competition_demo(category: str = "crypto", seed: int = 1234,
                         team_names=("alice", "bob", "carol"), max_gen: int = 6) -> dict:
    """Round-robin sample competitors against an evolving agent (offline demo)."""
    from . import competitor
    comp = Competition(category=category, seed=seed, evolve_on=1, max_gen=max_gen)
    teams = [comp.register(n)["team_id"] for n in team_names]
    for _ in range(30):
        progressed = False
        for t in teams:
            ch = comp.current(t)
            flag = competitor.solve(ch["files"])
            if flag and comp.submit(t, ch["challenge_id"], flag).get("correct"):
                progressed = True
        if not progressed:
            break
    return {"final_gen": comp.gen, "final_attack": comp.status()["attack"],
            "scoreboard": comp.scoreboard(), "events": comp.events}
