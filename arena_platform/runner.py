"""The match engine: one team's agent versus its own evolving challenge-maker.

A match is a ladder climb. The challenge-maker deploys Gen-0. The team's agent
gets the same files a human player would get, and one chance per generation. If
it returns the real flag, the challenge-maker MUTATES — verify_spec proves the
new rung is still solvable — and redeploys one rung harder. The climb ends when
the agent stops producing flags, runs out of time, or clears the whole ladder.

Two design choices make this a contest rather than a demo:

  * every match gets its own random seed, so two teams never receive the same
    modulus or the same flag — flags cannot be traded between teams
  * the flag never leaves this process: it is compared here and never written to
    an event, a log line, or the API

Matches run on a small pool of worker threads pulling from the SQLite queue, so
the queue survives a server restart.
"""
from __future__ import annotations

import os
import queue
import random
import threading
import time
from pathlib import Path

from .agents import build_client
from .sandbox import Limits, backend_report
from .store import Store
from .tracks import Track, get_track, warmup

# Points mirror autoctf_gan.competition: depth is what pays.
POINTS_BASE = 100
POINTS_PER_GEN = 60


class EventBus:
    """Fan-out of live match events to SSE subscribers (in-memory, best effort)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subs: dict[str, list[queue.Queue]] = {}

    def subscribe(self, match_id: str) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=512)
        with self._lock:
            self._subs.setdefault(match_id, []).append(q)
        return q

    def unsubscribe(self, match_id: str, q: queue.Queue) -> None:
        with self._lock:
            subs = self._subs.get(match_id, [])
            if q in subs:
                subs.remove(q)
            if not subs:
                self._subs.pop(match_id, None)

    def publish(self, match_id: str, event: dict) -> None:
        with self._lock:
            subs = list(self._subs.get(match_id, []))
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass                       # a stalled browser must not stall a match


class MatchEngine:
    """Owns the worker pool and knows how to run a single match end to end."""

    def __init__(self, store: Store, upload_root: Path | str,
                 workers: int = 2, backend: str = "auto",
                 maker_backend: str = "auto"):
        self.store = store
        self.upload_root = Path(upload_root)
        self.bus = EventBus()
        self.backend = backend
        self.maker_backend = maker_backend
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._worker_count = max(1, workers)

    # ---- queue -------------------------------------------------------------
    def start(self) -> None:
        warmup()                       # before any worker thread exists
        requeued = self.store.requeue_stale_running()
        if requeued:
            print(f"[arena] requeued {requeued} match(es) interrupted by a restart")
        for i in range(self._worker_count):
            t = threading.Thread(target=self._loop, name=f"arena-worker-{i}", daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                match = self.store.claim_next_queued()
            except Exception as exc:            # a broken DB must not kill the worker
                print(f"[arena] queue error: {exc}")
                time.sleep(2)
                continue
            if match is None:
                time.sleep(0.4)
                continue
            try:
                self.run_match(match)
            except Exception as exc:
                import traceback
                traceback.print_exc()
                self.store.update_match(match["id"], status="error",
                                        error=f"{type(exc).__name__}: {exc}"[:500],
                                        finished_at=time.time())

    def queue_position(self, match_id: str) -> int:
        pending = [m for m in self.store.recent_matches(limit=200)
                   if m["status"] == "queued"]
        pending.sort(key=lambda m: m["created_at"])
        for i, m in enumerate(pending, 1):
            if m["id"] == match_id:
                return i
        return 0

    # ---- one match ---------------------------------------------------------
    def run_match(self, match: dict) -> dict:
        warmup()                       # no-op after the first call; see tracks.warmup
        track = get_track(match["track"])
        agent_row = self.store.agent(match["agent_id"])
        if not agent_row:
            raise RuntimeError("agent record vanished")

        seq = _Counter()
        emit = self._emitter(match["id"], seq)

        limits = Limits(wall_seconds=track.per_gen_timeout_s,
                        cpu_seconds=track.per_gen_timeout_s,
                        memory_mb=int(os.environ.get("ARENA_AGENT_MEMORY_MB", "2048")))
        client = build_client(agent_row, limits, backend=self.backend)

        emit("match.started", {
            "match_id": match["id"], "team": match["team_name"],
            "agent": match["agent_name"], "agent_kind": agent_row["kind"],
            "track": track.key, "track_label": track.label, "rungs": track.rungs,
            "max_gen": track.max_gen, "seed": match["seed"],
            "route": track.route, "endless": track.endless,
            "skipped_segments": track.skipped_segments,
            "isolation": _isolation_report(agent_row),
            "per_gen_timeout_s": track.per_gen_timeout_s,
            "match_budget_s": track.match_budget_s,
        })

        from autoctf_gan.competition import Competition
        from autoctf_gan.maker import for_arena
        # One maker per match. A container maker builds each challenge in a fresh
        # container, so a wedged build costs this match and nothing else.
        maker = for_arena(backend=self.maker_backend, start=track.category,
                          cross_track=track.cross_track, authoring=track.authoring)
        emit("maker.ready", maker.describe())
        # max_gen=None on an endless track: the bounded rungs are a milestone, not
        # a ceiling, and only the match budget stops the climb.
        comp = Competition(seed=match["seed"], evolve_on=1,
                           max_gen=None if track.endless else track.max_gen,
                           verify_deploy=True, maker=maker)
        team_key = comp.register(match["team_name"])["team_id"]

        reached_gen, score, solve_seconds = -1, 0, 0.0
        outcome, error = "", ""
        authoring_announced = False
        archived_by_gen: dict[int, str] = {}
        deadline = time.monotonic() + track.match_budget_s

        while True:
            if time.monotonic() > deadline:
                outcome = "timeout"
                emit("match.timeout", {"budget_s": track.match_budget_s})
                break

            challenge = comp.current(team_key)
            gen = challenge["gen"]
            segment = track.campaign.locate(gen)[0]
            emit("challenge.deployed", {
                "gen": gen, "rung": track.rung_name(gen),
                "segment": segment.key, "segment_label": segment.label,
                "discipline": segment.category, "authored": segment.unbounded,
                "challenge_id": challenge["challenge_id"],
                "title": challenge["title"], "story": challenge["story"],
                "hints": challenge["hints"],
                "files": [{"name": n, "bytes": len(c)}
                          for n, c in (challenge["files"] or {}).items()],
            })

            if segment.unbounded:
                # An authored challenge exists only because this team pushed the
                # maker past every bounded rung. Keep it before the match ends.
                archived = self.store.archive_challenge(
                    spec=comp.spec, match_id=match["id"], team_name=match["team_name"],
                    track=track.key, solved=False)
                if archived:
                    archived_by_gen[gen] = archived["id"]
                    emit("library.archived", {
                        "gen": gen, "entry_id": archived["id"],
                        "title": comp.spec.title,
                        "plan_source": comp.spec.mechanics.get("plan_source", "catalog")})

            # A service-style challenge (web) is not files to read — it is a
            # running target. Stand one up on a per-match --internal network,
            # hand the agent its URL, and let the agent join that network so it
            # can attack the target and nothing off-box. Torn down straight
            # after the attempt, win or lose.
            if comp.spec.delivery == "web":
                from .instance import InstanceError, WebInstance
                emit("instance.starting", {"gen": gen, "rung": track.rung_name(gen)})
                try:
                    with WebInstance(comp.spec) as inst:
                        challenge["target_url"] = inst.url
                        emit("instance.ready", {"gen": gen, "target_url": inst.url})
                        run = client.attempt(challenge, network=inst.network)
                except InstanceError as exc:
                    from .sandbox import AgentRun
                    run = AgentRun(ok=False, backend="docker",
                                   error=f"the arena could not stand up this "
                                         f"challenge instance: {exc}")
            else:
                run = client.attempt(challenge)
            emit("agent.attempt", {
                "gen": gen, "rung": track.rung_name(gen),
                "seconds": run.seconds, "backend": run.backend,
                "produced_flag": bool(run.flag), "error": run.error,
                "limits_hit": run.limits_hit,
                "stdout": run.stdout[-1200:], "stderr": run.stderr[-1200:],
            })

            if not run.flag:
                outcome = "out_evolved" if run.ok else "agent_error"
                error = run.error
                emit("agent.stuck", {"gen": gen, "rung": track.rung_name(gen),
                                     "reason": run.error or "agent returned no flag"})
                break

            verdict = comp.submit(team_key, challenge["challenge_id"], run.flag)
            if not verdict.get("correct"):
                if str(verdict.get("msg", "")).startswith("stale"):
                    continue                       # challenge moved on; re-pull
                outcome = "wrong_flag"
                emit("submit.wrong", {"gen": gen, "rung": track.rung_name(gen)})
                break

            if gen in archived_by_gen:
                self.store.mark_library_solved(archived_by_gen[gen])
            reached_gen = max(reached_gen, gen)
            solve_seconds += run.seconds
            score += POINTS_BASE + POINTS_PER_GEN * gen
            emit("solve", {"gen": gen, "rung": track.rung_name(gen),
                           "seconds": run.seconds, "points": verdict.get("points", 0),
                           "score": score, "evolved": bool(verdict.get("evolved"))})

            self.store.update_match(match["id"], reached_gen=reached_gen, score=score,
                                    solve_seconds=round(solve_seconds, 3),
                                    agent_gen=comp.gen)

            if gen >= track.max_gen and not track.endless:
                outcome = "cleared"
                emit("ladder.cleared", {"gen": gen, "rung": track.rung_name(gen)})
                break
            if not verdict.get("evolved"):
                outcome = "evolution_stalled"
                error = "the challenge-maker could not verify a harder rung"
                emit("evolve.rejected", {"gen": gen})
                break
            if track.endless and not authoring_announced and \
                    track.campaign.locate(comp.gen)[0].unbounded:
                authoring_announced = True
                emit("maker.authoring", {
                    "gen": comp.gen, "rung": track.rung_name(comp.gen),
                    "note": ("every bounded rung has fallen — from here the maker "
                             "composes challenges no ladder contains, and each one "
                             "is verified solvable before it is deployed")})

        summary = _summarize(outcome, reached_gen, comp.gen, track)
        # Every finished climb is a result, including a crash — the team's agent
        # failing IS the outcome. Only infrastructure faults mark the row 'error'.
        self.store.update_match(
            match["id"], status="done", reached_gen=reached_gen, agent_gen=comp.gen, score=score,
            solve_seconds=round(solve_seconds, 3), outcome=outcome,
            error=error[:500], finished_at=time.time())
        emit("match.finished", {
            "outcome": outcome, "summary": summary, "reached_gen": reached_gen,
            "agent_gen": comp.gen, "score": score,
            "solve_seconds": round(solve_seconds, 3),
            "rung_reached": track.rung_name(reached_gen) if reached_gen >= 0 else None,
            "rung_agent": track.rung_name(comp.gen),
        })
        return {"outcome": outcome, "reached_gen": reached_gen, "score": score}

    def _emitter(self, match_id: str, seq: "_Counter"):
        def emit(evt: str, payload: dict) -> None:
            n = seq.next()
            row = self.store.add_event(match_id, n, evt, payload)
            self.bus.publish(match_id, {"seq": n, "ts": row["ts"], "evt": evt,
                                        "payload": payload})
        return emit


class _Counter:
    def __init__(self) -> None:
        self._n = -1
        self._lock = threading.Lock()

    def next(self) -> int:
        with self._lock:
            self._n += 1
            return self._n


def _isolation_report(agent_row: dict) -> dict:
    """What the live match view tells spectators about where this agent ran.

    Image agents get their own line: the confinement is the same container
    machinery an uploaded agent gets, but the *contents* are the team's, which
    is worth saying out loud on a public scoreboard.
    """
    kind = agent_row.get("kind")
    if kind == "remote":
        return {"backend": "remote", "strength": "n/a",
                "note": "agent runs on the team's own host"}
    if kind == "image":
        return {**backend_report(), "backend": "docker",
                "note": "the team's own image, run with --network none, dropped "
                        "capabilities and the arena's memory/PID/CPU caps"}
    return backend_report()


def _summarize(outcome: str, reached: int, agent_gen: int, track: Track) -> str:
    reached_name = track.rung_name(reached) if reached >= 0 else "nothing"
    agent_name = track.rung_name(agent_gen)
    past_ladders = reached >= track.max_gen and track.endless
    if outcome == "cleared":
        return (f"Ladder cleared. The agent solved every rung up to Gen-{reached} "
                f"({reached_name}) — the challenge-maker ran out of moves.")
    if outcome == "timeout":
        if past_ladders:
            return (f"Match budget exhausted at Gen-{agent_gen} ({agent_name}). "
                    f"The agent cleared every bounded rung and was still solving "
                    f"challenges the maker composed on the spot — deepest solve "
                    f"Gen-{reached} ({reached_name}).")
        return (f"Match budget exhausted at Gen-{agent_gen} ({agent_name}). "
                f"Deepest solve: Gen-{reached} ({reached_name}).")
    if outcome == "wrong_flag":
        return (f"Submitted an incorrect flag at Gen-{agent_gen} ({agent_name}). "
                f"Deepest solve: Gen-{reached} ({reached_name}).")
    if outcome == "agent_error":
        return (f"The agent crashed or hit a limit at Gen-{agent_gen} ({agent_name}). "
                f"Deepest solve: Gen-{reached} ({reached_name}).")
    if outcome == "evolution_stalled":
        return f"The challenge-maker could not verify a rung past Gen-{agent_gen}."
    if reached < 0:
        return f"No solve. The challenge-maker held at Gen-0 ({track.rung_name(0)})."
    if past_ladders:
        return (f"Out-authored. The agent cleared every bounded rung, then stalled on "
                f"a challenge the maker composed for it: deepest solve Gen-{reached} "
                f"({reached_name}), maker now at Gen-{agent_gen} ({agent_name}).")
    return (f"Out-evolved. Deepest solve Gen-{reached} ({reached_name}); the "
            f"challenge-maker escalated to Gen-{agent_gen} ({agent_name}) and held.")


def fresh_seed() -> int:
    """A private seed per match — two teams never see the same instance."""
    return random.SystemRandom().randrange(1, 2 ** 31 - 1)
