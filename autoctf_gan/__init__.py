"""AutoCTF-GAN — adaptive attack/defense CTF co-evolution engine.

Extends yixuan1112-coder/CTF-generation-AI-agent (ctf_factory) with a real
GAN-style Generator<->Attacker loop, a mandatory solvability gate, and a live
tournament dashboard. See README.md for the 4-step build.
"""
from .models import ChallengeSpec, Verdict
from .verify import verify_spec
from .generator import GENERATOR_SYSTEM_PROMPT, generate_spec, offline_brain
from .evolve import coevolve, fitness, mutate, AttackerPool, MUTATION_OPS
from .native import gen_compiled_crackme
from .crypto import gen_rsa_wiener
from .crypto_ladder import gen_crypto_ladder, mutate_crypto, LADDER_NAMES
from .web import gen_web_ssti, mutate_web
from .arena_bridge import run_ssti_arena
from .lattice import lll

__version__ = "1.3.0"
__all__ = [
    "ChallengeSpec", "Verdict", "verify_spec", "GENERATOR_SYSTEM_PROMPT",
    "generate_spec", "offline_brain", "coevolve", "fitness", "mutate",
    "AttackerPool", "MUTATION_OPS", "gen_compiled_crackme", "gen_rsa_wiener",
    "gen_crypto_ladder", "mutate_crypto", "LADDER_NAMES",
    "gen_web_ssti", "mutate_web", "run_ssti_arena", "lll",
]
