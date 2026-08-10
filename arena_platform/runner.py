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
                 workers: int = 2, backend: str = "auto"):
        self.store = store
        self.upload_root = Path(upload_root)
        self.bus = EventBus()
        self.backend = backend
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
            "isolation": backend_report() if agent_row["kind"] == "upload" else
                         {"backend": "remote", "note": "agent runs on the team's own host"},
            "per_gen_timeout_s": track.per_gen_timeout_s,
            "match_budget_s": track.match_budget_s,
        })

        from autoctf_gan.competition import Competition
        comp = Competition(category=track.category, seed=match["seed"],
                           evolve_on=1, max_gen=track.max_gen, verify_deploy=True)
        team_key = comp.register(match["team_name"])["team_id"]

        reached_gen, score, solve_seconds = -1, 0, 0.0
        outcome, error = "", ""
        deadline = time.monotonic() + track.match_budget_s

        while True:
            if time.monotonic() > deadline:
                outcome = "timeout"
                emit("match.timeout", {"budget_s": track.match_budget_s})
                break

            challenge = comp.current(team_key)
            gen = challenge["gen"]
            emit("challenge.deployed", {
                "gen": gen, "rung": track.rung_name(gen),
                "challenge_id": challenge["challenge_id"],
                "title": challenge["title"], "story": challenge["story"],
                "hints": challenge["hints"],
                "files": [{"name": n, "bytes": len(c)}
                          for n, c in (challenge["files"] or {}).items()],
            })

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

            reached_gen = max(reached_gen, gen)
            solve_seconds += run.seconds
            score += POINTS_BASE + POINTS_PER_GEN * gen
            emit("solve", {"gen": gen, "rung": track.rung_name(gen),
                           "seconds": run.seconds, "points": verdict.get("points", 0),
                           "score": score, "evolved": bool(verdict.get("evolved"))})

            self.store.update_match(match["id"], reached_gen=reached_gen, score=score,
                                    solve_seconds=round(solve_seconds, 3),
                                    agent_gen=comp.gen)

            if gen >= track.max_gen:
                outcome = "cleared"
                emit("ladder.cleared", {"gen": gen, "rung": track.rung_name(gen)})
                break
            if not verdict.get("evolved"):
                outcome = "evolution_stalled"
                error = "the challenge-maker could not verify a harder rung"
                emit("evolve.rejected", {"gen": gen})
                break

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


def _summarize(outcome: str, reached: int, agent_gen: int, track: Track) -> str:
    reached_name = track.rung_name(reached) if reached >= 0 else "nothing"
    agent_name = track.rung_name(agent_gen)
    if outcome == "cleared":
        return (f"Ladder cleared. The agent solved every rung up to Gen-{reached} "
                f"({reached_name}) — the challenge-maker ran out of moves.")
    if outcome == "timeout":
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
    return (f"Out-evolved. Deepest solve Gen-{reached} ({reached_name}); the "
            f"challenge-maker escalated to Gen-{agent_gen} ({agent_name}) and held.")


def fresh_seed() -> int:
    """A private seed per match — two teams never see the same instance."""
    return random.SystemRandom().randrange(1, 2 ** 31 - 1)
