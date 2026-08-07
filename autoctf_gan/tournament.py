"""Framework-agnostic tournament engine — Step 4 core.

Runs the co-evolution loop and yields UI events (design §6.2 shapes). Both the
FastAPI app and the stdlib SSE fallback consume this identical event stream, so
the dashboard behaves the same regardless of what web stack is installed.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Iterator

from .evolve import (ELITE_BAND, AttackerPool, EliteArchive, fitness, mutate,
                     solve_rate)
from .generator import generate_spec
from .verify import verify_spec


@dataclass
class TournamentConfig:
    category: str = "crypto"
    challenge_type: str = "layered"
    seed: int = 42
    archetype_id: str = "crypto.layered"
    max_generations: int = 8
    pool_size: int = 300


def event(evt: str, **payload: Any) -> dict[str, Any]:
    return {"evt": evt, **payload}


def run_tournament_events(cfg: TournamentConfig) -> Iterator[dict[str, Any]]:
    """Yield the live event stream for one archetype's evolution."""
    import random
    pool = AttackerPool(n=cfg.pool_size)
    rng = random.Random(f"tourney:{cfg.archetype_id}:{cfg.seed}")
    archive = EliteArchive()

    yield event("tournament.start", archetype=cfg.archetype_id,
                category=cfg.category, max_generations=cfg.max_generations)

    # Category dispatch:
    #   reverse -> REAL gcc-compiled crackme (native.py), difficulty = key rounds
    #   crypto  -> REAL attack-class ladder (crypto_ladder.py), difficulty = rung
    #   else    -> codec substrate
    native = cfg.category == "reverse"
    crypto = cfg.category == "crypto"
    web = cfg.category == "web" and cfg.challenge_type == "ssti"
    if native:
        from .native import gcc_available, gen_compiled_crackme, mutate_native
        if not gcc_available():
            yield event("tournament.end", archetype=cfg.archetype_id,
                        elites=0, best_gen=None, note="gcc unavailable")
            return
        spec = gen_compiled_crackme(seed=cfg.seed, archetype_id=cfg.archetype_id, rounds=1)
        source = "native-gcc"
    elif crypto:
        from .crypto_ladder import gen_crypto_ladder, mutate_crypto
        spec = gen_crypto_ladder(seed=cfg.seed, generation=0, archetype_id=cfg.archetype_id)
        source = "crypto-ladder"
    elif web:
        from .web import gen_web_ssti, mutate_web
        spec = gen_web_ssti(seed=cfg.seed, generation=0, archetype_id=cfg.archetype_id)
        source = "web-ssti"
    else:
        spec, source = generate_spec(category=cfg.category, challenge_type=cfg.challenge_type,
                                     difficulty="easy", seed=cfg.seed, archetype_id=cfg.archetype_id)
    yield event("challenge.generated", spec_id=spec.spec_id, source=source,
                gen=0, depth=spec.intended_depth)

    for gen in range(cfg.max_generations):
        yield event("container.spawn", spec_id=spec.spec_id, gen=spec.lineage.generation,
                    image=f"autoctf/{spec.slug}")
        verdict = verify_spec(spec)
        yield event("verify.verdict", spec_id=spec.spec_id, valid=verdict.valid,
                    reason=verdict.reason, poc_time_s=verdict.poc_time_s,
                    checks=verdict.checks, failures=verdict.failures)

        if not verdict.valid:
            yield event("gen.rejected", spec_id=spec.spec_id, reason=verdict.reason)
            yield event("container.destroy", spec_id=spec.spec_id, ttl_expired=False)
            spec = mutate(spec, [], rng)
            continue

        results = pool.evaluate(spec)
        rate = solve_rate(results)
        fit = fitness(spec, results)
        elite = ELITE_BAND[0] <= rate <= ELITE_BAND[1]

        yield event("solverate.tick", spec_id=spec.spec_id, gen=spec.lineage.generation,
                    rate=round(rate, 4), band="elite" if elite else "off",
                    depth=spec.intended_depth)
        # a couple of representative agent solves for the Battle Arena feed
        solved_sorted = sorted((r for r in results if r.solved), key=lambda r: r.time_s)[:3]
        for r in solved_sorted:
            yield event("exploit.result", team=r.agent_id, spec_id=spec.spec_id,
                        solved=True, time_s=round(r.time_s, 1), gen=spec.lineage.generation)
        yield event("gen.scored", spec_id=spec.spec_id, gen=spec.lineage.generation,
                    depth=spec.intended_depth, solve_rate=round(rate, 4),
                    fitness=round(fit, 3), elite=elite,
                    heatmap={"category": cfg.category,
                             "complexity": round(min(1.0, spec.intended_depth / 6), 3)})

        if elite:
            archive.promote(spec)
            yield event("archetype.promoted", spec_id=spec.spec_id,
                        gen=spec.lineage.generation, solve_rate=round(rate, 4))

        yield event("container.destroy", spec_id=spec.spec_id, ttl_expired=True)

        sigs = ["fast_solve"] if rate > ELITE_BAND[1] else []
        prev_gen = spec.lineage.generation
        if native:
            spec = mutate_native(spec)
        elif crypto:
            from .crypto_ladder import mutate_crypto
            spec = mutate_crypto(spec)
        elif web:
            from .web import mutate_web
            spec = mutate_web(spec)
        else:
            spec = mutate(spec, sigs, rng)
        yield event("gen.advanced", archetype=cfg.archetype_id,
                    gen=spec.lineage.generation, reason=("sig:fast_solve" if sigs else "explore"),
                    prev_gen=prev_gen)

    yield event("tournament.end", archetype=cfg.archetype_id,
                elites=len(archive.specs),
                best_gen=archive.best().lineage.generation if archive.best() else None)


def events_as_ndjson(cfg: TournamentConfig) -> str:
    return "\n".join(json.dumps(e) for e in run_tournament_events(cfg))
