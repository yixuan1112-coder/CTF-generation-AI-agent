"""AutoCTF-GAN test suite (stdlib unittest, matching the base repo's tests/)."""
from __future__ import annotations

import copy
import unittest

from autoctf_gan.evolve import (ELITE_BAND, MUTATION_OPS, AttackerPool, coevolve,
                                fitness, mutate, solve_rate)
from autoctf_gan.generator import generate_spec, offline_brain
from autoctf_gan.models import ChallengeSpec
from autoctf_gan.schema import validate_spec_dict
from autoctf_gan.verify import sha256_flag, verify_spec


class Step1SchemaAndGate(unittest.TestCase):
    def test_generated_spec_matches_schema(self):
        for diff in ("easy", "medium", "hard"):
            spec, _ = generate_spec(category="crypto", challenge_type="layered",
                                    difficulty=diff, seed=1, archetype_id="crypto.layered")
            self.assertEqual(validate_spec_dict(spec.to_dict()), [])

    def test_valid_spec_passes_gate(self):
        spec = offline_brain(category="crypto", challenge_type="layered",
                             difficulty="hard", seed=2, archetype_id="crypto.layered")
        v = verify_spec(spec)
        self.assertTrue(v.valid, v.reason)
        self.assertEqual(spec.verification.status, "valid")

    def test_removing_bug_is_rejected(self):
        """P1: if the solver can no longer recover the flag, spec is rejected."""
        spec = offline_brain(category="crypto", challenge_type="layered",
                             difficulty="medium", seed=3, archetype_id="crypto.layered")
        # degenerate the challenge: replace artifact with garbage (bug removed)
        spec.artifacts["cipher.txt"] = "no-longer-solvable"
        v = verify_spec(spec)
        self.assertFalse(v.valid)                       # rejected: PoC can't recover flag
        self.assertFalse(spec.verification.poc_passed)  # the degeneration is caught

    def test_flag_leak_is_rejected(self):
        spec = offline_brain(category="misc", challenge_type="layered",
                             difficulty="medium", seed=4, archetype_id="misc.layered")
        spec.artifacts["README.md"] += f"\n(psst the answer is {spec.flag})"
        v = verify_spec(spec)
        self.assertFalse(v.valid)

    def test_flag_never_in_public_view(self):
        spec = offline_brain(category="crypto", challenge_type="layered",
                             difficulty="hard", seed=5, archetype_id="crypto.layered")
        public = str(spec.to_dict(include_flag=False))
        self.assertNotIn(spec.flag, public)
        self.assertEqual(sha256_flag(spec.flag), spec.official_solver.expected_flag_sha256)


class Step2Generator(unittest.TestCase):
    def test_offline_fallback_when_no_llm(self):
        spec, source = generate_spec(category="pwn", challenge_type="layered",
                                     difficulty="medium", seed=6, archetype_id="pwn.layered")
        self.assertEqual(source, "offline")

    def test_llm_invalid_json_falls_back(self):
        spec, source = generate_spec(category="web", challenge_type="layered",
                                     difficulty="easy", seed=7, archetype_id="web.layered",
                                     llm_call=lambda s, u: "not json at all")
        self.assertEqual(source, "offline")   # invalid LLM output -> deterministic fallback
        self.assertTrue(verify_spec(spec).valid)

    def test_reproducible_seed(self):
        a = offline_brain(category="crypto", challenge_type="layered",
                          difficulty="hard", seed=99, archetype_id="crypto.layered")
        b = offline_brain(category="crypto", challenge_type="layered",
                          difficulty="hard", seed=99, archetype_id="crypto.layered")
        self.assertEqual(a.artifacts["cipher.txt"], b.artifacts["cipher.txt"])
        self.assertEqual(a.flag, b.flag)


class Step3Evolution(unittest.TestCase):
    def test_no_entropy_growth_op_exists(self):
        """Anti-brute-force: mutator must have no keyspace-inflation op."""
        for name in MUTATION_OPS:
            self.assertNotIn("length", name)
            self.assertNotIn("password", name)
            self.assertNotIn("keysize", name)

    def test_mutation_deepens_and_stays_solvable(self):
        import random
        parent = offline_brain(category="crypto", challenge_type="layered",
                               difficulty="easy", seed=8, archetype_id="crypto.layered")
        child = mutate(parent, ["fast_solve"], random.Random(1))
        self.assertGreaterEqual(child.intended_depth, parent.intended_depth)
        self.assertEqual(child.lineage.generation, parent.lineage.generation + 1)
        self.assertTrue(verify_spec(child).valid)   # re-paired solver still works

    def test_fitness_penalizes_extremes(self):
        spec = offline_brain(category="crypto", challenge_type="layered",
                             difficulty="hard", seed=9, archetype_id="crypto.layered")
        Res = __import__("autoctf_gan.evolve", fromlist=["SolveResult"]).SolveResult
        none_solved = [Res(f"a{i}", 0.1, False, 5, 3) for i in range(100)]
        all_solved = [Res(f"a{i}", 0.9, True, 5, 3) for i in range(100)]
        self.assertEqual(fitness(spec, none_solved), -1.0)
        self.assertLess(fitness(spec, all_solved), 0)   # trivial penalty

    def test_coevolution_reaches_elite_band(self):
        pool = AttackerPool(n=300)
        archive, history = coevolve(category="crypto", challenge_type="layered",
                                    seed=42, archetype_id="crypto.layered",
                                    pool=pool, max_generations=8)
        self.assertTrue(all(h.valid for h in history))          # every deploy verified
        self.assertGreaterEqual(len(archive.specs), 1)          # found an elite
        elite = archive.best()
        rate_ok = any(ELITE_BAND[0] <= h.solve_rate <= ELITE_BAND[1] for h in history if h.elite)
        self.assertTrue(rate_ok)


class Step4Tournament(unittest.TestCase):
    def test_event_stream_shape(self):
        from autoctf_gan.tournament import TournamentConfig, run_tournament_events
        events = list(run_tournament_events(TournamentConfig(max_generations=4, pool_size=150)))
        kinds = {e["evt"] for e in events}
        for required in ("tournament.start", "verify.verdict", "gen.scored",
                         "container.spawn", "container.destroy", "tournament.end"):
            self.assertIn(required, kinds)
        # every verify.verdict for a deployed gen must be valid=True
        self.assertTrue(all(e["valid"] for e in events if e["evt"] == "verify.verdict"))


class Step5RealBuildPipeline(unittest.TestCase):
    """The production swap-in: real gcc binary + Docker web, same verify contract."""

    def test_native_crackme_compiles_and_verifies(self):
        from autoctf_gan.native import gcc_available, gen_compiled_crackme
        if not gcc_available():
            self.skipTest("gcc not available")
        for rounds in (1, 3, 5):
            spec = gen_compiled_crackme(seed=2025, rounds=rounds)
            v = verify_spec(spec)          # routes to the real gcc pipeline
            self.assertTrue(v.valid, v.reason)
            self.assertTrue(spec.verification.poc_passed)

    def test_native_obfuscation_hides_flag_from_strings(self):
        import subprocess
        import tempfile
        from pathlib import Path
        from autoctf_gan.native import gcc_available, gen_compiled_crackme
        if not gcc_available():
            self.skipTest("gcc not available")
        spec = gen_compiled_crackme(seed=2025, rounds=4)
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "crackme.c").write_text(spec.artifacts["crackme.c"])
            subprocess.run(["gcc", "-O2", "-s", "crackme.c", "-o", "crackme"],
                           cwd=tmp, check=True)
            out = subprocess.run(["strings", "crackme"], cwd=tmp,
                                 capture_output=True, text=True).stdout
            self.assertNotIn(spec.flag, out)   # obfuscation actually holds

    def test_native_degenerate_binary_is_rejected(self):
        """P1 in the native path: break the ciphertext -> solver can't recover -> reject."""
        from autoctf_gan.native import gcc_available, gen_compiled_crackme
        if not gcc_available():
            self.skipTest("gcc not available")
        spec = gen_compiled_crackme(seed=2025, rounds=3)
        # corrupt the embedded ENC blob so no key can decode a valid flag
        spec.artifacts["crackme.c"] = spec.artifacts["crackme.c"].replace(
            "static const int ENCLEN", "static const int JUNK=1;\nstatic const int ENCLEN")
        spec.artifacts["crackme.c"] = spec.artifacts["crackme.c"].replace("ENC[i]", "(ENC[i]^0x5a)")
        v = verify_spec(spec)
        self.assertFalse(v.valid)

    def test_web_ssti_spec_valid_or_docker_skipped(self):
        from autoctf_gan.web import docker_available, gen_web_ssti
        spec = gen_web_ssti(seed=7)
        self.assertEqual(spec.delivery, "web")
        v = verify_spec(spec)
        if not docker_available():
            self.assertFalse(v.valid)
            self.assertIn("docker", v.reason.lower())   # graceful skip, no crash
        else:
            self.assertTrue(v.valid, v.reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
