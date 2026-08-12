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

from .campaign import Campaign
from .maker import MakerError
from .verify import verify_spec


class Competition:
    def __init__(self, category: str = "crypto", seed: int = 1234,
                 evolve_on: int = 1, max_gen: int | None = 6, verify_deploy: bool = True,
                 flag_secret: str | None = None, campaign: Campaign | None = None,
                 cross_track: bool = True, authoring: bool = True,
                 maker=None):
        self.seed = seed
        self.evolve_on = evolve_on          # solves of current variant that trigger evolution
        self.max_gen = max_gen              # None -> only the match budget stops the climb
        self.verify_deploy = verify_deploy
        # Per-match secret. Flags derive from it, so they cannot be recomputed
        # from the challenge metadata the agent receives — and it never leaves
        # this object: not into a spec field, an event, or an API response.
        self.flag_secret = secrets.token_hex(16) if flag_secret is None else flag_secret
        # Where the maker RUNS — this process or a container. The default keeps
        # the original in-process behaviour; the arena injects a DockerMaker.
        if maker is None:
            from .maker import InProcessMaker
            maker = InProcessMaker(campaign) if campaign else InProcessMaker(
                start=category, cross_track=cross_track, authoring=authoring)
        self.maker = maker
        # The route, not a single category: the maker climbs a ladder, switches
        # discipline, then starts authoring. `category` picks where it starts.
        self.campaign = maker.campaign
        self.lock = threading.RLock()
        self.teams: dict[str, dict] = {}
        self.events: list[dict] = []
        self._t0 = time.monotonic()
        self.gen = 0
        # Gen-0 is not verified: it is the maker's own opening move, and every
        # ladder's first rung is a fixed, tested construction.
        self.spec = self.maker.build(seed=seed, generation=0,
                                     flag_secret=self.flag_secret, verify=False).spec
        self.solvers_of_current: set[str] = set()
        self.first_blood_taken = False
        self._log_deploy()

    @property
    def category(self) -> str:
        """The discipline the maker is CURRENTLY on — it changes mid-match now."""
        return self.campaign.locate(self.gen)[0].category

    @property
    def segment(self):
        return self.campaign.locate(self.gen)[0]

    # ---- helpers -----------------------------------------------------------
    def _attack(self) -> str:
        return self.spec.mechanics.get("attack_class") or self.spec.challenge_type

    def _log(self, evt: str, **kw) -> None:
        self.events.append({"evt": evt, "t": round(time.monotonic() - self._t0, 2), **kw})

    def _recent_classes(self) -> list[str]:
        """What the maker has already deployed — steers the design brain off repeats."""
        return [e["attack"] for e in self.events if e["evt"] == "challenge.deployed"]

    def _log_deploy(self) -> None:
        s = self.spec
        self._log("challenge.deployed", gen=self.gen, challenge_id=s.spec_id,
                  attack=self._attack(), title=s.title, story=s.story,
                  hints=s.hints, files=list(s.artifacts))

    # ---- public API --------------------------------------------------------
    def register(self, name: str) -> dict:
        with self.lock:
            tid = secrets.token_hex(4)
            self.teams[tid] = {"name": name, "score": 0, "solves": 0, "best_gen": -1}
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
            self.teams[team_id]["best_gen"] = self.gen
            self._log("solve", team=self.teams[team_id]["name"], gen=self.gen,
                      points=pts, first_blood=first)

            evolved = False
            capped = self.max_gen is not None and self.gen >= self.max_gen
            if len(self.solvers_of_current) >= self.evolve_on and not capped:
                evolved = self._evolve()
            return {"ok": True, "correct": True, "points": pts, "first_blood": first,
                    "evolved": evolved, "gen": self.gen}

    def _evolve(self) -> bool:
        target = self.gen + 1
        previous = self.campaign.locate(self.gen)[0]
        try:
            result = self.maker.build(
                seed=self.seed, generation=target, flag_secret=self.flag_secret,
                parent_spec_id=self.spec.spec_id,
                target_solve_rate=self.spec.target_solve_rate,
                recent=self._recent_classes(), verify=self.verify_deploy)
        except ValueError:                              # bounded campaign exhausted
            self._log("campaign.exhausted", gen=self.gen)
            return False
        except MakerError as exc:                       # container died, timed out, absent
            self._log("maker.failed", gen=self.gen, reason=str(exc))
            return False
        child = result.spec
        if self.verify_deploy:
            # The maker verifies where it builds; only re-run the gate if it did not.
            v = result.verdict or verify_spec(child)    # never deploy an unsolvable variant
            if not v.valid:
                self._log("evolve.rejected", reason=v.reason)
                return False
        self.spec = child
        self.gen = target
        current = self.campaign.locate(target)[0]
        if current.key != previous.key:
            # A discipline change is a bigger event than a rung: the team's agent
            # is about to be handed a different KIND of problem.
            self._log("segment.changed", gen=target, frm=previous.label,
                      to=current.label, category=current.category,
                      authoring=current.unbounded)
        self.solvers_of_current = set()
        self.first_blood_taken = False
        self._log_deploy()
        return True

    def scoreboard(self) -> list[dict]:
        with self.lock:
            rows = sorted(self.teams.values(), key=lambda t: -t["score"])
            return [{"name": t["name"], "score": t["score"], "solves": t["solves"]}
                    for t in rows]

    def status(self) -> dict:
        with self.lock:
            segment = self.segment
            return {"category": self.category, "gen": self.gen, "max_gen": self.max_gen,
                    "challenge_id": self.spec.spec_id, "attack": self._attack(),
                    "solvers_of_current": len(self.solvers_of_current),
                    "teams": len(self.teams),
                    "segment": segment.key, "segment_label": segment.label,
                    "authoring": segment.unbounded,
                    "bounded_rungs": self.campaign.bounded_rungs,
                    "skipped_segments": self.campaign.describe_skipped()}


class CompetitionHost:
    """Gives each registered team its OWN evolving challenge-maker instance.

    This is the model for "upload your agent and see how far it gets": your solves
    evolve *your* agent only, so your test is independent and reproducible. The
    highest generation you *solve* is your result; whoever's agent out-evolves
    their team the least (i.e. the team that climbs highest) leads the board.
    """

    def __init__(self, category: str = "crypto", seed: int = 1234, max_gen: int = 6):
        self.category, self.seed, self.max_gen = category, seed, max_gen
        self.lock = threading.RLock()
        self._teams: dict[str, dict] = {}

    def register(self, name: str) -> dict:
        with self.lock:
            comp = Competition(self.category, self.seed, evolve_on=1, max_gen=self.max_gen)
            inner = comp.register(name)["team_id"]
            tid = secrets.token_hex(4)
            self._teams[tid] = {"name": name, "comp": comp, "inner": inner}
            return {"team_id": tid, "name": name, "server": "connect your agent to /comp/*"}

    def challenge(self, tid: str) -> dict:
        t = self._teams.get(tid)
        return t["comp"].current() if t else {"error": "unknown team — register first"}

    def submit(self, tid: str, cid: str, flag: str) -> dict:
        t = self._teams.get(tid)
        if not t:
            return {"ok": False, "msg": "unknown team — register first"}
        return t["comp"].submit(t["inner"], cid, flag)

    def status(self, tid: str | None = None) -> dict:
        if tid and tid in self._teams:
            return self._teams[tid]["comp"].status()
        return {"teams": len(self._teams), "category": self.category, "max_gen": self.max_gen}

    def scoreboard(self) -> list[dict]:
        with self.lock:
            rows = []
            for t in self._teams.values():
                sc = t["comp"].teams[t["inner"]]
                rows.append({"name": t["name"], "score": sc["score"], "solves": sc["solves"],
                             "reached_gen": sc["best_gen"],
                             "agent_now": t["comp"].status()["attack"]})
            return sorted(rows, key=lambda r: (-r["reached_gen"], -r["score"]))


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
