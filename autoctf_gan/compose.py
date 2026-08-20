"""Authoring mode — challenges no ladder rung covers.

A ladder is a finite list, so a maker that only climbs one runs out of moves:
`gen_crypto_ladder` used to clamp at the last rung and redeploy it forever, and
the arena reported "cleared — the challenge-maker ran out of moves". That is the
ceiling this module removes.

Past the last rung the maker stops *selecting* a challenge and starts *building*
one, by chaining verified attack classes into a challenge that is not any of
them:

    stage 1 in the clear  --break-->  a key
    that key unseals stage 2         --break-->  another key
    that key unseals stage 3         --break-->  the flag

Each stage is a real RSA weakness from `rsa_stages`; the envelope between them
is a keystream the previous stage's plaintext derives. So the depth is genuine —
stage N+1's key material does not exist in readable form until stage N actually
falls — and it grows by STRUCTURE, never by entropy, which is the one way this
codebase permits difficulty to increase (design principle P3).

The composed solver is assembled from the same `solve_*` functions that built
the stages, and `verify_spec` runs it for real before anything is deployed. A
composition that cannot be solved is rejected exactly like a bad mutation.

The space is unbounded: with 8 attack classes there are 56 orderings at depth 2,
392 at depth 3, and it keeps going, so the maker always has a next move.

Past depth 3 the per-stage hints are withheld — see `describe`. Naming every
weakness turned the deepest challenges in the repertoire into pure execution: an
agent that is told "stage 3 is Pollard p-1" never has to diagnose anything, and
diagnosis is the part strong agents differ on.
"""
from __future__ import annotations

import hashlib
import inspect
import itertools
import random
from dataclasses import dataclass, field

from . import rsa_stages
from .identity import challenge_flag, challenge_secret, public_slug
from .models import ChainStep, ChallengeSpec, Lineage, OfficialSolver
from .rsa_stages import STAGE_NAMES, STAGES

KEY_HEX = 32          # inter-stage key length; 32 bytes fits every stage's message cap


@dataclass
class Plan:
    """What to build. Either enumerated from the catalogue or proposed by a model."""
    stages: list[str]
    title: str = ""
    story: str = ""
    hints: list[str] = field(default_factory=list)
    designer_note: str = ""
    source: str = "catalog"           # catalog | llm

    def validate(self) -> "Plan":
        """A plan is only buildable from reviewed primitives — including an LLM's.

        This is the safety boundary: a model may choose the ORDER and write the
        prose, but every stage name must resolve to an audited entry in STAGES,
        so no model-authored code ever reaches the build.
        """
        if len(self.stages) < 2:
            raise ValueError("a composition needs at least two stages")
        unknown = [s for s in self.stages if s not in STAGES]
        if unknown:
            raise ValueError(f"unknown attack class(es): {', '.join(unknown)}")
        return self

    @property
    def rank(self) -> int:
        """Difficulty proxy: the classes involved plus the depth they are chained to."""
        return sum(STAGES[s].rank for s in self.stages) + len(self.stages)


# ---------------------------------------------------------------------------
# the catalogue of compositions, ordered so escalation stays monotone
# ---------------------------------------------------------------------------
def compositions(depth: int) -> list[tuple[str, ...]]:
    """Every ordering of `depth` stages, easiest total first.

    Immediate repeats are dropped — chaining Wiener into Wiener is a longer
    challenge but not a different one, and the point of authoring is variety.
    Non-adjacent repeats are allowed, which is what keeps depth unbounded once
    it exceeds the number of attack classes.
    """
    combos = [c for c in itertools.product(STAGE_NAMES, repeat=depth)
              if all(a != b for a, b in zip(c, c[1:]))]
    return sorted(combos, key=lambda c: (sum(STAGES[s].rank for s in c), c))


def _rank_of(combo: tuple[str, ...]) -> int:
    return sum(STAGES[s].rank for s in combo) + len(combo)


_CATALOG: list[tuple[str, ...]] | None = None
CATALOG_MAX_DEPTH = 5          # 22400 compositions; past this we extend instead of enumerate


def ordered_catalog() -> list[tuple[str, ...]]:
    """Every composition up to CATALOG_MAX_DEPTH, in global difficulty order.

    Ordering across depths, not within them, is what keeps escalation monotone.
    Enumerating depth-by-depth would exhaust the 30 pairs and then drop the team
    back to the EASIEST triple — a maker that "escalates" into a easier challenge
    is a broken maker, and the leaderboard ranks on depth reached.
    """
    global _CATALOG
    if _CATALOG is None:
        merged: list[tuple[str, ...]] = []
        for depth in range(2, CATALOG_MAX_DEPTH + 1):
            merged.extend(compositions(depth))
        merged.sort(key=lambda c: (_rank_of(c), len(c), c))
        _CATALOG = merged
    return _CATALOG


def _draw(rng: random.Random, depth: int) -> list[str]:
    stages: list[str] = []
    while len(stages) < depth:
        pick = rng.choice(STAGE_NAMES)
        if not stages or stages[-1] != pick:
            stages.append(pick)
    return stages


def _extended(offset: int) -> list[str]:
    """Past the enumerated catalogue: keep authoring, deeper and deterministically.

    Enumerating depth 6+ would mean holding 18k+ tuples for generations no match
    will ever reach, so beyond the catalogue the maker composes directly. Draws
    that would land easier than the catalogue's hardest entry are rejected, so
    escalation stays monotone across the boundary too.
    """
    depth = CATALOG_MAX_DEPTH + 1 + offset // 64
    floor = _rank_of(ordered_catalog()[-1])
    rng = random.Random(f"compose-extend:{offset}")
    for _ in range(200):
        stages = _draw(rng, depth)
        if _rank_of(tuple(stages)) >= floor:
            return stages
    # Nothing drawn cleared the floor: alternate the two hardest classes, which
    # is the deepest-rank composition this depth admits.
    hardest = sorted(STAGES.values(), key=lambda s: -s.rank)[:2]
    return [hardest[i % 2].name for i in range(depth)]


def plan_at(index: int) -> Plan:
    """The `index`-th composition in difficulty order. Defined for every index."""
    if index < 0:
        raise ValueError("composition index must be >= 0")
    catalog = ordered_catalog()
    if index < len(catalog):
        return describe(list(catalog[index]))
    return describe(_extended(index - len(catalog)))


def plan_for(*, generation: int, ladder_len: int) -> Plan:
    """Deterministically pick the composition for a generation past the ladder."""
    if generation < ladder_len:
        raise ValueError(f"generation {generation} is still on the ladder")
    return plan_at(generation - ladder_len)


# Compositions at or past this depth ship no per-stage diagnosis. The structural
# hint stays either way: how many layers there are is a fact about the archive an
# agent could count for itself, not a free answer.
HINT_DEPTH_LIMIT = 4


def describe(stages: list[str]) -> Plan:
    """Give an enumerated composition its player-facing prose."""
    labels = [STAGES[s].label for s in stages]
    layers = [f"There are {len(stages)} sealed layers; each one hands you the next key."]
    guided = [f"Stage {i + 1}: {STAGES[s].hint}" for i, s in enumerate(stages)]
    return Plan(
        stages=stages,
        # The title names the classes for shallow chains and stops doing so for
        # deep ones, for the same reason the hints do: it is shown to the agent.
        title=(f"Chained RSA — {' then '.join(labels)}"
               if len(stages) < HINT_DEPTH_LIMIT
               else f"Chained RSA — {len(stages)} sealed layers"),
        story=("A key-escrow archive was rebuilt in layers: each layer's unlock key "
               "is the plaintext of the layer before it. Only the outermost key set "
               "is readable. Recover the innermost message."),
        hints=(guided + layers) if len(stages) < HINT_DEPTH_LIMIT else layers,
        designer_note=(f"Composition of {len(stages)} verified attack classes "
                       f"({' -> '.join(stages)}); depth is structural, key sizes are unchanged."),
        source="catalog",
    ).validate()


# ---------------------------------------------------------------------------
# building
# ---------------------------------------------------------------------------
def _solver_source(plan: Plan, expected_sha: str) -> str:
    """Assemble the PoC from the very functions that built the stages."""
    lines = [
        "import hashlib",
        "from rsa_stages import materialize, unwrap, " +
        ", ".join(sorted({STAGES[s].solver for s in plan.stages})),
        "",
    ]
    for i, name in enumerate(plan.stages, start=1):
        stage = STAGES[name]
        call = f'{stage.solver}("s{i}_"{stage.solver_args})'
        if i < len(plan.stages):
            lines += [
                f"key = {call}                     # stage {i}: {stage.label}",
                f'with open("stage{i + 1}.enc", encoding="utf-8") as fh:',
                "    materialize(unwrap(fh.read(), key))",
            ]
        else:
            lines += [f"message = {call}                 # stage {i}: {stage.label}"]
    lines += [
        "",
        'flag = message.decode()',
        'assert flag.startswith("flag{"), "recovered plaintext is not a flag"',
        f'assert hashlib.sha256(flag.encode()).hexdigest() == {expected_sha!r}, "flag mismatch"',
        "print(flag)",
    ]
    return "\n".join(lines) + "\n"


def gen_composed(*, seed: int, generation: int,
                 archetype_id: str = "crypto.compose",
                 parent_spec_id: str | None = None,
                 mutation_ops: list[str] | None = None,
                 target_solve_rate: float = 0.05,
                 flag_secret: str = "",
                 plan: Plan | None = None) -> ChallengeSpec:
    """Author one composed challenge. `plan=None` enumerates from the catalogue."""
    from .crypto_ladder import CRYPTO_LADDER

    plan = (plan or plan_for(generation=generation, ladder_len=len(CRYPTO_LADDER))).validate()
    attack_class = "compose:" + "+".join(plan.stages)
    flag = challenge_flag(kind=attack_class, seed=seed, generation=generation,
                          secret=flag_secret)

    # Build inward-out: the last stage holds the flag, each earlier stage holds
    # the key that unseals the stage after it.
    artifacts: dict[str, str] = {}
    message = flag.encode()
    for i in range(len(plan.stages), 0, -1):
        stage = STAGES[plan.stages[i - 1]]
        rng = _stage_rng(seed, generation, i, flag_secret)
        files = stage.build(rng, message, f"s{i}_")
        if i == 1:
            artifacts.update(files)              # stage 1 is handed over in the clear
        else:
            key = challenge_secret(kind=attack_class, seed=seed, generation=generation,
                                   variant=f"envelope{i}", secret=flag_secret,
                                   length=KEY_HEX).encode()
            artifacts[f"stage{i}.enc"] = rsa_stages.wrap(files, key)
            message = key                        # the stage before must yield this key

    artifacts["README.md"] = (
        f"# {plan.title}\n\n{plan.story}\n\n"
        f"You are given the stage-1 key material in the clear and "
        f"{len(plan.stages) - 1} sealed layer(s). Each layer opens with the plaintext "
        f"recovered from the layer before it.\n")

    expected_sha = hashlib.sha256(flag.encode()).hexdigest()
    slug = public_slug(base=f"crypto-compose{len(plan.stages)}", seed=seed,
                       generation=generation, secret=flag_secret)
    return ChallengeSpec(
        slug=slug, title=f"{plan.title} (Gen-{generation})",
        category="crypto", challenge_type=f"rsa-compose-{len(plan.stages)}",
        difficulty="hard", story=plan.story,
        vulnerability="; then ".join(STAGES[s].vulnerability for s in plan.stages),
        intended_solution=[f"stage {i + 1}: break {STAGES[s].label}, unseal the next layer"
                           for i, s in enumerate(plan.stages)],
        hints=plan.hints, delivery="crypto", seed=seed,
        mechanics={"attack_class": attack_class, "rank": plan.rank,
                   "stages": list(plan.stages), "depth": len(plan.stages),
                   "plan_source": plan.source, "designer_note": plan.designer_note},
        flag=flag, spec_id=slug,
        lineage=Lineage(archetype_id=archetype_id, generation=generation,
                        parent_spec_id=parent_spec_id,
                        mutation_ops=mutation_ops or ["compose_attack_classes"],
                        seed=seed),
        # One step per attack plus one per seal: the seals are load-bearing, not
        # decoration, so they count toward the modeled depth.
        vuln_chain=_chain(plan),
        artifacts=artifacts,
        official_solver=OfficialSolver(
            entry="solver.py",
            files={"solver.py": _solver_source(plan, expected_sha),
                   "rsa_stages.py": inspect.getsource(rsa_stages)},
            expected_flag_sha256=expected_sha, max_runtime_s=180),
        target_solve_rate=target_solve_rate,
    )


def _stage_rng(seed: int, generation: int, index: int, flag_secret: str) -> random.Random:
    return random.Random(f"compose:{flag_secret}:{seed}:{generation}:{index}")


def _chain(plan: Plan) -> list[ChainStep]:
    steps: list[ChainStep] = []
    for i, name in enumerate(plan.stages, start=1):
        steps.append(ChainStep(step=len(steps) + 1, primitive=f"{name}_stage",
                               params={"stage": i}, guard="crypto"))
        if i < len(plan.stages):
            steps.append(ChainStep(step=len(steps) + 1, primitive="sealed_envelope",
                                   params={"opens": f"stage{i + 1}.enc"},
                                   guard="keystream-from-previous-plaintext"))
    return steps


def mutate_composed(parent: ChallengeSpec, flag_secret: str = "") -> ChallengeSpec:
    """Escalate to the next composition in the catalogue."""
    return gen_composed(seed=parent.seed, generation=parent.lineage.generation + 1,
                        archetype_id=parent.lineage.archetype_id,
                        parent_spec_id=parent.spec_id,
                        mutation_ops=["compose_attack_classes"],
                        target_solve_rate=parent.target_solve_rate,
                        flag_secret=flag_secret)
