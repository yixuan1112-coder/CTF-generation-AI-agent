"""CTF-GAN co-evolution engine — Step 3.

Implements the design-doc §4 core:
  * MUTATION_OPS   — formal, ENTROPY-FREE structural transforms (no keyspace growth).
  * mutate()        — apply ops to a parent spec, biased by live strategy signatures,
                      and RE-PAIR the official solver (P1) so verify_spec can pass.
  * AttackerPool    — simulates competitor agents with a skill distribution so
                      observed solve-rate is a real function of structural depth.
  * fitness()       — peaks in the elite band, penalizes both degeneration modes
                      (unsolvable AND trivial) and brute-forceable designs.
  * coevolve()      — the loop: generate -> mutate -> VERIFY (hard gate) -> evaluate
                      -> score -> archive elites. Runs fully offline.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any

from .generator import offline_brain
from .models import ChainStep, ChallengeSpec
from .verify import verify_spec

TARGET_SOLVE_RATE = 0.05
ELITE_BAND = (0.02, 0.12)

# op -> (applicable categories, structural?). NOTE: there is deliberately NO
# "increase_key_length" / "grow_password" op. Difficulty can only grow by
# structure — this is the anti-brute-force lever enforced at the op-set level.
MUTATION_OPS: dict[str, tuple[set[str], bool]] = {
    "deepen_chain":         ({"web", "pwn", "crypto", "forensics", "misc"}, True),
    "swap_guard_regex":     ({"web"}, True),
    "control_flow_flatten": ({"reverse", "pwn"}, True),
    "opaque_predicates":    ({"reverse"}, True),
    "raise_callstack":      ({"pwn", "reverse"}, True),
    "rotate_crypto_weak":   ({"crypto"}, True),
    "reweight_allocator":   ({"pwn"}, True),
    "covert_channel_shift": ({"forensics"}, True),
}

_PRIMS = ["positional_shift", "xor", "b64", "reverse", "rot13"]


def applicable_ops(category: str) -> list[str]:
    return [op for op, (cats, structural) in MUTATION_OPS.items()
            if category in cats and structural]


def signature_guided_selection(candidate_ops: list[str],
                               signatures: list[str], rng: random.Random) -> list[str]:
    """Bias op choice toward countering observed team strategies (design §3).

    e.g. a 'waf_bypass' signature -> prefer swap_guard_regex; a 'fast_solve'
    signature -> prefer deepen_chain to add a stage.
    """
    ops = list(candidate_ops)
    prioritized: list[str] = []
    for sig in signatures:
        if "waf" in sig or "guard" in sig:
            prioritized += [o for o in ops if "guard" in o]
        if "fast" in sig or "shortcut" in sig:
            prioritized += [o for o in ops if o == "deepen_chain"]
    chosen = prioritized[:1] or [rng.choice(ops)]
    if "deepen_chain" in ops and "deepen_chain" not in chosen and rng.random() < 0.7:
        chosen.append("deepen_chain")   # depth is the reliable structural lever
    return list(dict.fromkeys(chosen))  # dedup, preserve order


def mutate(parent: ChallengeSpec, signatures: list[str], rng: random.Random) -> ChallengeSpec:
    """Produce a child spec via structural ops, re-pairing its solver (P1)."""
    ops = signature_guided_selection(applicable_ops(parent.category), signatures, rng)

    # Structural effect on the runnable substrate: deepen_chain adds a transform
    # stage; swap_guard_regex re-parameterizes the outer stage. Non-codec ops
    # (cff, opaque predicates, ...) are recorded as build directives that a real
    # pwn/reverse pipeline would honour; here they raise the modeled depth.
    new_chain: list[ChainStep] = [ChainStep(step=s.step, primitive=s.primitive,
                                            params=dict(s.params), guard=s.guard)
                                  for s in parent.vuln_chain]
    for op in ops:
        if op in ("deepen_chain", "control_flow_flatten", "raise_callstack",
                  "opaque_predicates", "reweight_allocator", "covert_channel_shift"):
            prim = rng.choice(_PRIMS)
            params: dict[str, Any] = {}
            if prim == "positional_shift":
                params = {"offset": rng.randint(1, 25)}
            elif prim == "xor":
                params = {"key": f"{rng.randrange(16**6):06x}"}
            step = ChainStep(step=len(new_chain) + 1, primitive=prim, params=params,
                             guard=f"denylist:{op}-stage-{len(new_chain)+1}")
            new_chain.append(step)
        elif op in ("swap_guard_regex", "rotate_crypto_weak") and new_chain:
            outer = new_chain[-1]
            if outer.primitive == "positional_shift":
                outer.params["offset"] = rng.randint(1, 25)
            elif outer.primitive == "xor":
                outer.params["key"] = f"{rng.randrange(16**6):06x}"
            outer.guard = f"denylist:{op}-morphed"

    depth = len(new_chain)
    difficulty = "hard" if depth >= 3 else ("medium" if depth == 2 else "easy")
    child = offline_brain(
        category=parent.category, challenge_type=parent.challenge_type,
        difficulty=difficulty, seed=parent.seed, archetype_id=parent.lineage.archetype_id,
        generation=parent.lineage.generation + 1, parent_spec_id=parent.spec_id,
        mutation_ops=ops, chain_override=new_chain,
        target_solve_rate=parent.target_solve_rate,
    )
    return child


# ---------------------------------------------------------------------------
# Simulated competitor agents (stand-in for external team nodes in offline runs).
# ---------------------------------------------------------------------------
@dataclass
class SolveResult:
    agent_id: str
    skill: float
    solved: bool
    time_s: float
    payload_volume: int          # proxy for token/brute-force spend


@dataclass
class AttackerPool:
    n: int = 200
    k: float = 12.0              # logistic steepness
    seed: int = 7
    skills: list[float] = field(default_factory=list)

    def __post_init__(self) -> None:
        rng = random.Random(self.seed)
        # skill ~ Beta-ish via mean of uniforms -> concentrates mid-range, few elite
        self.skills = [sum(rng.random() for _ in range(3)) / 3 for _ in range(self.n)]

    @staticmethod
    def _threshold(depth: int) -> float:
        return 0.18 * depth        # deeper chain -> higher skill needed

    def evaluate(self, spec: ChallengeSpec) -> list[SolveResult]:
        rng = random.Random(f"eval:{spec.spec_id}")
        depth = spec.intended_depth
        thr = self._threshold(depth)
        results = []
        for i, skill in enumerate(self.skills):
            p = 1.0 / (1.0 + math.exp(-self.k * (skill - thr)))
            solved = rng.random() < p
            # weaker agents spam more payloads before solving/giving up (brute proxy)
            payloads = int(1 + (1.0 - skill) * 20 * depth)
            time_s = (1.0 - skill) * 60 * depth + rng.random() * 5
            results.append(SolveResult(f"agent-{i:03d}", skill, solved, time_s, payloads))
        return results


# ---------------------------------------------------------------------------
# Fitness (design §4.2)
# ---------------------------------------------------------------------------
def _discrimination(results: list[SolveResult]) -> float:
    """Point-biserial-ish: did strong agents solve and weak agents fail? (0..1)"""
    solved = [r.skill for r in results if r.solved]
    failed = [r.skill for r in results if not r.solved]
    if not solved or not failed:
        return 0.0
    gap = (sum(solved) / len(solved)) - (sum(failed) / len(failed))
    return max(0.0, min(1.0, gap * 2))   # scale into 0..1


def solve_rate(results: list[SolveResult]) -> float:
    return sum(1 for r in results if r.solved) / max(len(results), 1)


def fitness(spec: ChallengeSpec, results: list[SolveResult], token_cost: float = 0.0) -> float:
    rate = solve_rate(results)
    if rate == 0.0:
        return -1.0                       # unsolvable / broken
    if rate >= 0.90:
        return -0.7                       # trivial
    band = math.exp(-((rate - TARGET_SOLVE_RATE) ** 2) / (2 * 0.03 ** 2))
    disc = _discrimination(results)
    struct = 0.12 * spec.intended_depth + 0.05 * len(spec.lineage.mutation_ops)
    # brute proxy: mean payload volume normalized; challenges that force spam are worse
    mean_payload = sum(r.payload_volume for r in results) / max(len(results), 1)
    brute_penalty = 0.02 * (mean_payload / max(spec.intended_depth, 1))
    return band + 0.4 * disc + struct - 0.3 * token_cost - 0.1 * brute_penalty


# ---------------------------------------------------------------------------
# Archive + the co-evolution loop
# ---------------------------------------------------------------------------
@dataclass
class EliteArchive:
    specs: list[ChallengeSpec] = field(default_factory=list)

    def promote(self, spec: ChallengeSpec) -> None:
        self.specs.append(spec)

    def best(self) -> ChallengeSpec | None:
        return self.specs[-1] if self.specs else None


@dataclass
class GenerationRecord:
    generation: int
    spec_id: str
    depth: int
    mutation_ops: list[str]
    valid: bool
    reject_reason: str | None
    solve_rate: float
    fitness: float
    elite: bool


def coevolve(*, category: str, challenge_type: str, seed: int, archetype_id: str,
             pool: AttackerPool | None = None, max_generations: int = 8,
             signatures: list[str] | None = None) -> tuple[EliteArchive, list[GenerationRecord]]:
    """Drive a challenge from trivial toward the elite band. Fully offline."""
    pool = pool or AttackerPool()
    rng = random.Random(f"coevolve:{archetype_id}:{seed}")
    archive = EliteArchive()
    history: list[GenerationRecord] = []

    # Gen-0 baseline (deliberately easy -> will be 'too trivial' -> pressure to deepen)
    spec, _ = _gen0(category, challenge_type, seed, archetype_id)
    for gen in range(max_generations):
        verdict = verify_spec(spec)            # HARD GATE — invalid never deploys
        if not verdict.valid:
            history.append(GenerationRecord(gen, spec.spec_id, spec.intended_depth,
                                            spec.lineage.mutation_ops, False,
                                            verdict.reason, 0.0, -0.8, False))
            spec = mutate(spec, signatures or [], rng)   # try again structurally
            continue

        results = pool.evaluate(spec)
        rate = solve_rate(results)
        fit = fitness(spec, results)
        elite = ELITE_BAND[0] <= rate <= ELITE_BAND[1]
        history.append(GenerationRecord(gen, spec.spec_id, spec.intended_depth,
                                        spec.lineage.mutation_ops, True, None,
                                        rate, round(fit, 3), elite))
        if elite:
            archive.promote(spec)

        # strategy signature: if solved too fast/too often, next mutation deepens
        sigs = list(signatures or [])
        if rate > ELITE_BAND[1]:
            sigs.append("fast_solve")
        spec = mutate(spec, sigs, rng)

    return archive, history


def _gen0(category, challenge_type, seed, archetype_id):
    from .generator import generate_spec
    return generate_spec(category=category, challenge_type=challenge_type,
                         difficulty="easy", seed=seed, archetype_id=archetype_id)
