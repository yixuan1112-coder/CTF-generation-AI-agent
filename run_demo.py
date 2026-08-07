#!/usr/bin/env python3
"""End-to-end offline demo of all four AutoCTF-GAN build steps.

Run:  python run_demo.py
Serve the live dashboard:  python -m autoctf_gan.api  (then open http://127.0.0.1:8080)
"""
from autoctf_gan.evolve import ELITE_BAND, AttackerPool, coevolve
from autoctf_gan.generator import generate_spec
from autoctf_gan.schema import validate_spec_dict
from autoctf_gan.verify import verify_spec


def main() -> None:
    print("STEP 1+2  generate -> schema-validate -> verify PoC")
    spec, src = generate_spec(category="crypto", challenge_type="layered",
                              difficulty="hard", seed=2025, archetype_id="crypto.layered")
    print(f"  source={src}  schema_errors={len(validate_spec_dict(spec.to_dict()))}")
    v = verify_spec(spec)
    print(f"  verdict valid={v.valid}  checks={len(v.checks)}  poc={v.poc_time_s:.3f}s")

    print("\nSTEP 3  co-evolution toward the elite band (~top 5%)")
    pool = AttackerPool(n=300)
    archive, history = coevolve(category="crypto", challenge_type="layered", seed=42,
                                archetype_id="crypto.layered", pool=pool, max_generations=8)
    print(f"  {'gen':>3} {'depth':>5} {'solve%':>7} {'fitness':>8}  elite")
    for h in history:
        flag = " <-- ELITE (archived)" if h.elite else ""
        print(f"  {h.generation:>3} {h.depth:>5} {h.solve_rate*100:>6.1f}% {h.fitness:>8}{flag}")
    best = archive.best()
    if best:
        print(f"  elite band = {ELITE_BAND}; best = Gen-{best.lineage.generation}, "
              f"depth {best.intended_depth}, chain "
              f"{'->'.join(s.primitive for s in best.vuln_chain)}")

    print("\nSTEP 5  REAL gcc-compiled 'reverse' category co-evolving (actual binaries)")
    from autoctf_gan.native import gcc_available
    from autoctf_gan.tournament import TournamentConfig, run_tournament_events
    if not gcc_available():
        print("  (gcc unavailable — skipped)")
    else:
        cfg = TournamentConfig(category="reverse", challenge_type="crackme",
                               archetype_id="reverse.crackme", seed=2025, max_generations=8)
        print(f"  {'gen':>3} {'rounds':>6} {'solve%':>7} {'fitness':>8}  elite")
        for e in run_tournament_events(cfg):
            if e["evt"] == "gen.scored":
                flag = " <-- ELITE (compiled+PoC verified)" if e["elite"] else ""
                print(f"  {e['gen']:>3} {e['depth']:>6} {e['solve_rate']*100:>6.1f}% "
                      f"{e['fitness']:>8}{flag}")

    print("\nSTEP 6  REAL Crypto category — the PoC IS a Wiener attack")
    from autoctf_gan.crypto import gen_rsa_wiener
    vspec = gen_rsa_wiener(seed=1337, vulnerable=True)
    vv = verify_spec(vspec)
    print(f"  vulnerable (small d): valid={vv.valid}  attack_time={vv.poc_time_s:.3f}s")
    sv = verify_spec(gen_rsa_wiener(seed=1337, vulnerable=False))
    print(f"  safe key (weakness removed): valid={sv.valid}  <- rejected: attack can't run (P1)")

    print("\nSTEP 7  Attack/Defense arena — live local Flask SSTI (no Docker)")
    from autoctf_gan.arena_bridge import run_ssti_arena
    from autoctf_gan.web import gen_web_ssti
    rep = run_ssti_arena(gen_web_ssti(seed=7))
    for rnd in rep["rounds"]:
        print(f"  {rnd['agent']:9} {rnd['action']}")
    print(f"  => passed={rep['passed']} score={rep['score']}")

    print("\nSTEP 4  run `python -m autoctf_gan.api` and open http://127.0.0.1:8080")


if __name__ == "__main__":
    main()
