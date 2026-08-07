"""AutoCTF-GAN — adaptive attack/defense CTF co-evolution engine.

Extends yixuan1112-coder/CTF-generation-AI-agent (ctf_factory) with a real
GAN-style Generator<->Attacker loop, a mandatory solvability gate, and a live
tournament dashboard. See README.md for the 4-step build.
"""
from .models import ChallengeSpec, Verdict
from .verify import verify_spec
from .generator import GENERATOR_SYSTEM_PROMPT, generate_spec, offline_brain
from .evolve import coevolve, fitness, mutate, AttackerPool, MUTATION_OPS

__version__ = "1.0.0"
__all__ = [
    "ChallengeSpec", "Verdict", "verify_spec", "GENERATOR_SYSTEM_PROMPT",
    "generate_spec", "offline_brain", "coevolve", "fitness", "mutate",
    "AttackerPool", "MUTATION_OPS",
]
