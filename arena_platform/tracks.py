"""Track definitions — which ladder a match climbs.

A *track* wraps one of the `autoctf_gan` co-evolution ladders and describes it in
the terms the leaderboard needs: how many rungs exist, what each rung is called,
and how deep the challenge-maker can escalate before it runs out of moves.

Crypto is the reference track: seven rungs, each shipping a real paired PoC that
`verify_spec` executes before the rung is ever deployed, ending at Boneh-Durfee —
a rung most attack toolkits cannot reach.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Track:
    key: str
    label: str
    category: str                 # what autoctf_gan.competition._build expects
    blurb: str
    rungs: list[str] = field(default_factory=list)
    per_gen_timeout_s: int = 120
    match_budget_s: int = 900

    @property
    def max_gen(self) -> int:
        return max(0, len(self.rungs) - 1)

    def rung_name(self, gen: int) -> str:
        if not self.rungs:
            return f"gen-{gen}"
        return self.rungs[min(gen, len(self.rungs) - 1)]


_LADDER_CACHE: dict[str, list[str]] = {}

FALLBACK_CRYPTO = ["smalle", "hastad", "commonmod", "wiener", "fermat", "pollard"]


def warmup() -> None:
    """Import the engine's heavy modules on the MAIN thread, before threads start.

    fpylll installs a signal handler when it is imported, and Python only permits
    that from the main thread. If a match worker or an HTTP handler triggers the
    first import instead, it raises, crypto_ladder quietly drops the Boneh-Durfee
    rung, and the arena would serve a six-rung ladder while advertising seven —
    the boss fight the whole contest is built around would simply vanish. Calling
    this at startup puts fpylll in sys.modules so every later thread import is a
    no-op.
    """
    _crypto_rungs()


def _crypto_rungs() -> list[str]:
    """Read the live ladder so the UI never drifts from the engine.

    The Boneh-Durfee rung is appended by crypto_ladder only when fpylll imports,
    so this is resolved at runtime rather than hardcoded — and cached, so worker
    threads reuse whatever the main thread resolved.
    """
    if "crypto" in _LADDER_CACHE:
        return list(_LADDER_CACHE["crypto"])
    try:
        from autoctf_gan.crypto_ladder import LADDER_NAMES
        rungs = list(LADDER_NAMES)
    except Exception as exc:                      # surface it: a silently short
        import sys                                # ladder looks like a rule change
        print(f"[arena] crypto ladder unavailable ({type(exc).__name__}: {exc}); "
              "falling back to the six-rung ladder", file=sys.stderr)
        rungs = list(FALLBACK_CRYPTO)
    import threading
    if threading.current_thread() is threading.main_thread():
        _LADDER_CACHE["crypto"] = list(rungs)     # only trust a main-thread result
    return rungs


def all_tracks() -> dict[str, Track]:
    return {
        "crypto": Track(
            key="crypto",
            label="Crypto — RSA attack ladder",
            category="crypto",
            blurb=("Each rung rotates to a harder attack CLASS, not a bigger modulus. "
                   "Every rung ships a verified proof-of-concept, so every rung is "
                   "provably solvable — by someone."),
            rungs=_crypto_rungs(),
            per_gen_timeout_s=120,
            match_budget_s=900,
        ),
        "reverse": Track(
            key="reverse",
            label="Reverse — compiled crackme",
            category="reverse",
            blurb="A generated C crackme that gains a transformation round every generation.",
            rungs=[f"rounds-{i + 1}" for i in range(6)],
            per_gen_timeout_s=180,
            match_budget_s=1200,
        ),
        "web": Track(
            key="web",
            label="Web — template injection",
            category="web",
            blurb="A Flask SSTI archetype whose filters and sinks harden each generation.",
            rungs=[f"filter-{i}" for i in range(6)],
            per_gen_timeout_s=120,
            match_budget_s=900,
        ),
    }


def get_track(key: str) -> Track:
    tracks = all_tracks()
    if key not in tracks:
        raise KeyError(f"unknown track {key!r}; choose one of {sorted(tracks)}")
    return tracks[key]
