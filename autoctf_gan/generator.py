"""Generator Agent — Step 2.

Three parts:
  1. GENERATOR_SYSTEM_PROMPT   — production system prompt forcing valid ChallengeSpec JSON.
  2. generate_spec()           — LLM path with schema-validate + bounded retry.
  3. offline_brain()           — deterministic fallback (mirrors the base repo's
                                 "offline brain"); always emits a spec whose paired
                                 solver actually recovers the flag, so verify_spec passes.

The offline brain guarantees the tournament never stalls on a hallucinated/absent
LLM. It also serves as the reference implementation the LLM output is validated
against.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import random
from typing import Any, Callable

from . import codec
from .codec import encode_chain
from .models import ChainStep, ChallengeSpec, Lineage, OfficialSolver
from .schema import validate_spec_dict

# ---------------------------------------------------------------------------
# 1. Production system prompt (see design doc §3). Deploy as the system message
#    together with JSON-mode / structured output + the host-side validator below.
# ---------------------------------------------------------------------------
GENERATOR_SYSTEM_PROMPT = """\
You are GENERATOR-AGENT, the challenge-authoring core of AutoCTF-GAN, an
authorized, sandboxed CTF platform for security education and competition.
You produce vulnerable-by-design challenges together with the exact exploit
that solves them. All output is consumed by an automated build-and-verify
pipeline inside an isolated sandbox, never by an end user directly.

# NON-NEGOTIABLE CONTRACT
1. OUTPUT EXACTLY ONE JSON OBJECT conforming to ChallengeSpec v1. No prose,
   no markdown fences, no commentary before or after.
2. EVERY challenge MUST include a complete, runnable official_solver that
   deterministically recovers the flag. A spec without a working solver is
   INVALID and will be rejected. You are scored on solver pass-rate.
3. NEVER remove the vulnerability to make a challenge harder. Difficulty MUST
   come from STRUCTURE (chain length, obfuscation passes, call-stack depth,
   guard sophistication), NOT from raw entropy (longer passwords, bigger
   unstructured keyspaces). Entropy inflation is penalized.
4. The intended vulnerability MUST be reachable by exactly the chain declared
   in vuln_chain, and MUST NOT be reachable by a trivial one-step shortcut.
   If a shortcut exists, add a guard, do not add entropy.
5. NEVER inline the true flag in artifacts, logs, comments, or error strings.
   Provide official_solver.expected_flag_sha256 so the verifier can check
   recovery without the flag being stored in public material.
6. For Crypto/Pwn/Reverse: choose parameters that admit a KNOWN, BOUNDED-TIME
   attack that official_solver implements. "Unguessable" is a rejection, not a
   difficulty setting.
7. Stay within the sandbox contract: declared toolchain only, no host mounts,
   no outbound network in the challenge runtime, no real credentials.

# SELF-CHECK BEFORE EMITTING (reason internally, do not print)
- Does official_solver, run against my own artifacts, yield a flag whose
  sha256 == expected_flag_sha256?
- Is the trivial one-step payload BLOCKED by a guard?
- Is added difficulty structural (chain/obfuscation/depth), not entropy?
- Are all artifact and solver files fully specified (no TODO, no placeholder)?

# OUTPUT
A single ChallengeSpec v1 JSON object. artifacts and official_solver.files MUST
contain complete literal file contents. Leave verification fields null.
"""

DEPTH_BY_DIFFICULTY = {"easy": 1, "medium": 2, "hard": 3}
_PRIMITIVE_POOL = ["positional_shift", "xor", "b64", "reverse", "rot13"]


def _flag_for(seed: int) -> str:
    h = hashlib.sha256(f"autoctf-gan::{seed}".encode()).hexdigest()[:12]
    return f"flag{{{h}}}"


def _build_chain(rng: random.Random, depth: int) -> list[ChainStep]:
    """Structural chain; params derive from the RNG (seed), never inflated for entropy."""
    steps: list[ChainStep] = []
    # innermost transform applied first -> outermost last
    picks = [rng.choice(_PRIMITIVE_POOL) for _ in range(depth)]
    for i, prim in enumerate(picks, start=1):
        params: dict[str, Any] = {}
        if prim == "positional_shift":
            params = {"offset": rng.randint(1, 25)}
        elif prim == "xor":
            params = {"key": hashlib.sha256(f"k{rng.random()}".encode()).hexdigest()[:6]}
        guard = None if depth == 1 else f"denylist:stage-{i}-naive-decode"
        steps.append(ChainStep(step=i, primitive=prim, params=params, guard=guard))
    return steps


def _solver_files(chain: list[ChainStep], expected_sha: str) -> dict[str, str]:
    """Ship the codec source + a self-contained solver that inverts the chain."""
    codec_src = inspect.getsource(codec)
    chain_json = json.dumps([{"primitive": s.primitive, "params": s.params} for s in chain])
    solver_src = (
        "import hashlib, json\n"
        "from codec import decode_chain\n"
        f"CHAIN = json.loads(r'''{chain_json}''')\n"
        "art = open('cipher.txt', encoding='utf-8').read().strip()\n"
        "flag = decode_chain(art, CHAIN)\n"
        f"assert hashlib.sha256(flag.encode()).hexdigest() == '{expected_sha}', 'flag mismatch'\n"
        "print(flag)\n"
    )
    return {"codec.py": codec_src, "solver.py": solver_src}


def offline_brain(
    *, category: str, challenge_type: str, difficulty: str, seed: int,
    archetype_id: str, generation: int = 0, parent_spec_id: str | None = None,
    mutation_ops: list[str] | None = None, chain_override: list[ChainStep] | None = None,
    target_solve_rate: float = 0.05,
) -> ChallengeSpec:
    """Deterministic, always-valid generator. Same seed -> same spec (P4)."""
    rng = random.Random(f"{archetype_id}:{seed}:{generation}")
    flag = _flag_for(seed)
    depth = DEPTH_BY_DIFFICULTY.get(difficulty, 2)
    chain = chain_override or _build_chain(rng, depth)
    chain_dicts = [{"primitive": s.primitive, "params": s.params} for s in chain]
    artifact = encode_chain(flag, chain_dicts)
    expected_sha = hashlib.sha256(flag.encode()).hexdigest()

    slug = f"{category}-{challenge_type}-{seed:06d}-g{generation}".lower().replace("_", "-")[:80]
    spec = ChallengeSpec(
        slug=slug,
        title=f"{challenge_type.title()} Layers (Gen-{generation})",
        category=category,
        challenge_type=challenge_type,
        difficulty=difficulty,
        story=("A telemetry capture leaks an encoded token. Peel every stage in the "
               "right order; a single naive decode only reveals the next guard."),
        vulnerability=f"{depth}-stage reversible-transform chain ({'->'.join(s.primitive for s in chain)})",
        intended_solution=[f"invert {s.primitive} (stage {s.step})" for s in chain],
        hints=["The number of stages equals the declared depth.",
               "Each stage guards the one beneath it."][:max(1, depth - 1) or 1],
        delivery="attachment",
        seed=seed,
        mechanics={"depth": depth, "primitives": [s.primitive for s in chain]},
        flag=flag,
        spec_id=f"{slug}-{expected_sha[:8]}",
        lineage=Lineage(archetype_id=archetype_id, generation=generation,
                        parent_spec_id=parent_spec_id, mutation_ops=mutation_ops or [],
                        seed=seed),
        vuln_chain=chain,
        artifacts={"cipher.txt": artifact,
                   "README.md": f"# {challenge_type.title()}\n\nRecover the flag from `cipher.txt`."},
        official_solver=OfficialSolver(
            entry="solver.py",
            files=_solver_files(chain, expected_sha),
            expected_flag_sha256=expected_sha,
            max_runtime_s=30,
        ),
        target_solve_rate=target_solve_rate,
    )
    return spec


# ---------------------------------------------------------------------------
# 3. LLM path with schema-validate + bounded retry, offline-brain fallback.
# ---------------------------------------------------------------------------
def _llm_available() -> bool:
    return bool(os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY"))


def generate_spec(
    *, category: str, challenge_type: str, difficulty: str, seed: int,
    archetype_id: str, generation: int = 0, parent_spec_id: str | None = None,
    mutation_ops: list[str] | None = None, chain_override: list[ChainStep] | None = None,
    target_solve_rate: float = 0.05,
    llm_call: Callable[[str, str], str] | None = None, retry_budget: int = 3,
) -> tuple[ChallengeSpec, str]:
    """Return (spec, source) where source in {"llm", "offline"}.

    Tries the LLM (if configured / injected), validating each attempt against the
    JSON Schema; on exhaustion falls back to the deterministic offline brain so
    the pipeline never stalls (mirrors the base repo's behaviour).
    """
    kwargs = dict(category=category, challenge_type=challenge_type, difficulty=difficulty,
                  seed=seed, archetype_id=archetype_id, generation=generation,
                  parent_spec_id=parent_spec_id, mutation_ops=mutation_ops,
                  chain_override=chain_override, target_solve_rate=target_solve_rate)

    if llm_call is not None or _llm_available():
        call = llm_call or _default_llm_call
        user = json.dumps({"category": category, "challenge_type": challenge_type,
                           "difficulty": difficulty, "target_solve_rate": target_solve_rate,
                           "seed": seed})
        for _ in range(max(1, retry_budget)):
            try:
                raw = call(GENERATOR_SYSTEM_PROMPT, user)
                data = json.loads(raw)
            except Exception:
                continue
            errors = validate_spec_dict(data)
            if not errors:
                return ChallengeSpec.from_dict(data), "llm"
            # else: feed errors back on next attempt (real impl appends to `user`)
    # deterministic fallback
    return offline_brain(**kwargs), "offline"


def _default_llm_call(system: str, user: str) -> str:
    """OpenAI-compatible completion, using the repo's existing env convention.

    This used to raise "wire your provider SDK here", which meant `_llm_available`
    could report a key was present and then the call would fail on every attempt —
    the retry budget burned and the offline brain answered anyway. It is now the
    same client the maker's design brain uses.
    """
    from .design import DesignBrain
    return DesignBrain().complete(system, user)
