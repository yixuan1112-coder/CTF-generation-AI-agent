"""The maker's escalation plan for a whole match.

A `Competition` used to hold ONE category for its lifetime, so the maker's entire
repertoire was a single ladder and the match ended when that ladder ran out. A
campaign replaces that with an ordered route the maker walks:

    crypto ladder (7 rungs)  ->  reverse ladder (6 rungs)  ->  composed crypto (no end)

Escalation is a global generation counter; the campaign maps it onto a segment
and a local rung. So "evolve" now means three different moves depending on where
the maker is: climb this ladder, switch to a different discipline, or author
something new.

Segments whose toolchain is missing are dropped at construction rather than
deployed and rejected — a match that stalls at "the challenge-maker could not
verify a harder rung" because the host has no gcc looks like a broken maker, not
a missing compiler. `describe_skipped` reports what was dropped and why, so the
arena can say it out loud instead of silently serving a shorter route.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import ChallengeSpec


@dataclass(frozen=True)
class Segment:
    key: str
    category: str
    label: str
    blurb: str = ""
    rungs: tuple[str, ...] = ()
    unbounded: bool = False

    @property
    def length(self) -> int | None:
        return None if self.unbounded else len(self.rungs)


@dataclass
class Campaign:
    segments: list[Segment] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)   # (label, reason)
    # "auto" uses the design brain when one is configured, "catalog" pins the
    # deterministic enumeration — which is what tests and reproducible demos want.
    design: str = "auto"
    # False when the STARTING discipline itself cannot be built here. A campaign
    # must never quietly substitute another discipline for the one it is named
    # after — a "reverse" track that silently serves crypto rungs is a lie to
    # every team that picked it.
    start_available: bool = True

    # ---- layout ------------------------------------------------------------
    def locate(self, generation: int) -> tuple[Segment, int]:
        """Map a global generation onto (segment, rung within that segment)."""
        if generation < 0:
            raise ValueError("generation must be >= 0")
        remaining = generation
        for segment in self.segments:
            if segment.unbounded:
                return segment, remaining
            if remaining < len(segment.rungs):
                return segment, remaining
            remaining -= len(segment.rungs)
        raise ValueError(f"generation {generation} is past the end of a bounded campaign")

    @property
    def bounded_rungs(self) -> int:
        """How many rungs exist before the maker starts authoring."""
        total = 0
        for segment in self.segments:
            if segment.unbounded:
                break
            total += len(segment.rungs)
        return total

    @property
    def has_authoring_tail(self) -> bool:
        return any(s.unbounded for s in self.segments)

    def rung_name(self, generation: int) -> str:
        segment, local = self.locate(generation)
        if not segment.unbounded:
            return segment.rungs[local]
        from .compose import plan_at
        return "compose:" + "+".join(plan_at(local).stages)

    def rung_names(self, limit: int) -> list[str]:
        """Names for the first `limit` generations — what the UI draws as a ladder."""
        return [self.rung_name(g) for g in range(limit)]

    def describe_skipped(self) -> list[str]:
        return [f"{label} ({reason})" for label, reason in self.skipped]

    # ---- building ----------------------------------------------------------
    def build(self, *, seed: int, generation: int, flag_secret: str = "",
              parent_spec_id: str | None = None,
              mutation_ops: list[str] | None = None,
              target_solve_rate: float = 0.05,
              recent: list[str] | None = None) -> ChallengeSpec:
        """Build the challenge for a global generation.

        The spec's `lineage.generation` is the GLOBAL index, not the rung within
        its segment, so ids stay unique and monotone across a segment switch.
        """
        segment, local = self.locate(generation)
        common = dict(parent_spec_id=parent_spec_id,
                      target_solve_rate=target_solve_rate,
                      flag_secret=flag_secret)

        if segment.key == "crypto-ladder":
            from .crypto_ladder import gen_crypto_ladder
            return gen_crypto_ladder(seed=seed, generation=local,
                                     mutation_ops=mutation_ops or ["rotate_attack_class"],
                                     **common)
        if segment.key == "reverse-ladder":
            from .native import gen_compiled_crackme
            return gen_compiled_crackme(seed=seed, generation=local, rounds=local + 1,
                                        mutation_ops=mutation_ops or ["deepen_key_schedule"],
                                        **common)
        if segment.key == "web-ladder":
            from .web import gen_web_ssti
            return gen_web_ssti(seed=seed, generation=local,
                                mutation_ops=mutation_ops or ["escalate_denylist"],
                                **common)
        if segment.key == "crypto-compose":
            from .compose import gen_composed, plan_at
            if self.design == "catalog":
                plan = plan_at(local)
            else:
                from .design import propose_plan
                plan = propose_plan(index=local, recent=recent)
            return gen_composed(seed=seed, generation=generation, plan=plan,
                                mutation_ops=mutation_ops or ["compose_attack_classes"],
                                **common)
        raise KeyError(f"campaign segment {segment.key!r} has no builder")


# ---------------------------------------------------------------------------
# the stock route
# ---------------------------------------------------------------------------
def crypto_ladder_segment() -> Segment:
    from .crypto_ladder import LADDER_NAMES
    return Segment(key="crypto-ladder", category="crypto",
                   label="Crypto — RSA attack ladder",
                   blurb="Each rung rotates to a harder attack class, not a bigger modulus.",
                   rungs=tuple(LADDER_NAMES))


def reverse_ladder_segment(depth: int = 6) -> Segment:
    return Segment(key="reverse-ladder", category="reverse",
                   label="Reverse — compiled crackme",
                   blurb="A generated C crackme gaining a key-schedule round per rung.",
                   rungs=tuple(f"R={i + 1}" for i in range(depth)))


def web_ladder_segment() -> Segment:
    """The SSTI denylist ladder. Clamps at its last entry, so the rung list is the ceiling."""
    try:
        from .web import PAYLOAD_LADDER
        rungs = tuple(f"bypass-{name}" for name, _ in PAYLOAD_LADDER)
    except Exception as exc:                      # surface it: a silently short
        import sys                                # ladder looks like a rule change
        print(f"[campaign] web ladder unavailable ({type(exc).__name__}: {exc})",
              file=sys.stderr)
        rungs = ("bypass-flag", "bypass-values", "bypass-items",
                 "bypass-dictsort", "bypass-popitem")
    return Segment(key="web-ladder", category="web",
                   label="Web — template injection",
                   blurb="Every rung bans the token the previous bypass used.",
                   rungs=rungs)


def compose_segment() -> Segment:
    return Segment(key="crypto-compose", category="crypto",
                   label="Composed — authored on the spot",
                   blurb=("Past every ladder the maker chains verified attack classes "
                          "into challenges no rung covers. There is no last one."),
                   unbounded=True)


def default_campaign(*, start: str = "crypto", cross_track: bool = True,
                     authoring: bool = True, probe: bool = True,
                     design: str | None = None,
                     capabilities: dict | None = None) -> Campaign:
    """The route a match walks: climb, switch discipline, then author.

    `probe` drops segments this host cannot build, which is the difference
    between an honest short route and a match that dies on a missing compiler.

    `capabilities` answers that question for a DIFFERENT machine. Once the maker
    runs in a container, "can this host compile C?" is the wrong question — the
    image ships gcc, so an arena on a host without a compiler can still offer the
    reverse track. Pass the container's reported capabilities and the route is
    planned against the toolchain that will actually build it.

    `design` defaults to $AUTOCTF_DESIGN so an operator can pin the deterministic
    catalogue without touching code.
    """
    import os

    from .native import gcc_available

    design = design or os.getenv("AUTOCTF_DESIGN", "auto")

    ladders = {"crypto": crypto_ladder_segment(), "reverse": reverse_ladder_segment(),
               "web": web_ladder_segment()}
    if start not in ladders:
        raise KeyError(f"no ladder for {start!r}; choose one of {sorted(ladders)}")
    # Only crypto and reverse are handed over as files, so only those two are
    # worth crossing into. Web is startable but never a cross-track destination.
    order = [start] + [k for k in ("crypto", "reverse") if k != start]
    if not cross_track:
        order = [start]

    def buildable(key: str) -> str:
        """Empty string if the ladder can be built, else the reason it cannot."""
        if key != "reverse":
            return ""
        if capabilities is not None:
            return "" if capabilities.get("gcc") else "the maker image has no gcc toolchain"
        if probe and not gcc_available():
            return "no gcc toolchain on this host"
        return ""

    blocked = buildable(start)
    if blocked:
        # Describe the track truthfully and let the caller refuse to offer it,
        # rather than cross-tracking into a discipline nobody asked for.
        return Campaign(segments=[ladders[start]],
                        skipped=[(ladders[start].label, blocked)],
                        start_available=False, design=design)

    segments: list[Segment] = []
    skipped: list[tuple[str, str]] = []
    for key in order:
        segment = ladders[key]
        reason = buildable(key)
        if reason:
            skipped.append((segment.label, reason))
            continue
        segments.append(segment)
    if authoring:
        segments.append(compose_segment())
    return Campaign(segments=segments, skipped=skipped, design=design)
