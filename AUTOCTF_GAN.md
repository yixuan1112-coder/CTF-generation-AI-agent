# AutoCTF-GAN — co-evolution extension for `ctf_factory`

This adds a GAN-style Generator ⇄ Attacker co-evolution engine, a mandatory
solvability gate, and a live tournament dashboard on top of the existing
`ctf_factory` challenge factory. It reuses the base repo's core idea — *a
challenge is only valid if the paired organizer solver recovers the exact flag*
(`ctf_factory.gates.audit_bundle`) — and turns it into an adversarial evolution
loop.

New package: **`autoctf_gan/`** (sibling of `ctf_factory/`). Runs offline; only
dependency is `jsonschema` (already used).

## Run it

```bash
python run_demo.py                          # steps 1-5 end to end
python -m unittest tests.test_autoctf -v    # 17 tests (gcc tests run; docker tests skip)
python -m autoctf_gan.api                   # dashboard -> http://127.0.0.1:8080
python -m autoctf_gan.api --fastapi         # production app (pip install fastapi uvicorn)
```

## Modules

| Module | Role |
|--------|------|
| `models.py` | `ChallengeSpec` (base fields + lineage/Gen-N, `vuln_chain`, `artifacts`, paired `official_solver`, `verification`), `Verdict`. |
| `schema.py` | JSON Schema + `validate_spec_dict()`. |
| `verify.py` | `verify_spec()` — routes by `delivery` to the right backend; every backend runs the PoC and rejects unsolvable/trivial/leaky/non-deterministic specs. |
| `generator.py` | `GENERATOR_SYSTEM_PROMPT`, `generate_spec()` (LLM + schema-validate/retry), `offline_brain()` deterministic fallback. |
| `codec.py` | Reversible-transform substrate (the fast, dependency-free reference build). |
| `native.py` | **Real gcc-compiled** crackme category + `build_and_verify_native()` (compiles, runs, `strings` leak-gate). |
| `web.py` | **Real Docker** Flask-SSTI category + `build_and_verify_web()` (builds image, runs container, PoC against live service; graceful-skips without Docker). |
| `evolve.py` | `MUTATION_OPS` (entropy-free), `mutate()`, `AttackerPool`, `fitness()`, `coevolve()`. |
| `tournament.py` | Event stream; category dispatch (`reverse` -> real gcc, else codec). |
| `api.py`, `dashboard.html` | FastAPI + `/ws/arena` WebSocket, stdlib SSE fallback, 3-panel dashboard. |

## Three delivery backends, one gate contract

`verify_spec(spec)` dispatches on `spec.delivery`:

| delivery | backend | proven here |
|----------|---------|-------------|
| `attachment` | subprocess codec | ✅ steps 1-4 |
| `binary` | **gcc** compile + run + `strings` leak-gate | ✅ real binaries, obfuscation verified |
| `web` | **Docker** build + run container + PoC | code complete; skips cleanly (no Docker in this env) |

All three enforce the same invariant: **PoC must recover the exact flag, wrong
inputs must not leak it, the flag must not appear in player artifacts.**

## How the design guarantees map to enforced, tested behavior

- **Guaranteed solvability (P1/P2)** — `verify_spec` runs the paired PoC.
  `test_removing_bug_is_rejected`, `test_native_degenerate_binary_is_rejected`.
- **Real obfuscation, not hardcoded secrets** — native leak-gate greps the
  compiled binary. `test_native_obfuscation_hides_flag_from_strings`.
- **Anti-brute-force / token cost (P3)** — `MUTATION_OPS` has no keyspace-growth
  op; native difficulty = key-schedule rounds, web difficulty = denylist size.
  `test_no_entropy_growth_op_exists`.
- **Elite-band selection** — `coevolve()` / tournament archive challenges solved
  only by the top ~5%. `test_coevolution_reaches_elite_band`, and the demo shows
  the real gcc `reverse` archetype hitting the band at Gen-4 (R=5, 5% solve).
- **Reproducibility (P4)** — seed-derived. `test_reproducible_seed`.

## Integrating deeper with `ctf_factory`

`ChallengeSpec.to_ctf_factory_dict()` projects onto the base dataclass fields.
The native/web backends are the production replacements for the codec substrate;
`ctf_factory.arena.run_arena` (Docker attack/defense) can be driven by the same
`verify_spec` verdicts.
