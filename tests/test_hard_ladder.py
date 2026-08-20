"""The hard rungs — where diagnosis, not execution, is the difficulty.

These rungs (singular, gcmreuse, noncebias) and the two hard compose stages
(franklin, crtfault) exist to be hard for a strong agent to SOLVE, which for the
first time in this repo means hard to *diagnose*. So the tests assert two things
the rest of the suite does not:

  * the paired PoC still recovers the exact flag (P1), across several seeds, so a
    generator cannot quietly ship an unsolvable boss rung; and
  * the player artifacts never name the weakness — no "singular", no "nonce
    reuse", no attack name in a README or a hint — because a challenge whose
    files announce the bug is not a detection challenge at all.
"""
from __future__ import annotations

import json
import unittest

from autoctf_gan.crypto_ladder import (CRYPTO_LADDER, LADDER_NAMES,
                                       gen_crypto_ladder)
from autoctf_gan.hard_ladder import HARD_LADDER_NAMES, LATTICE_RUNGS
from autoctf_gan.verify import verify_spec


def _fpylll() -> bool:
    try:
        import fpylll  # noqa: F401
        return True
    except Exception:
        return False


# Words that would hand the diagnosis to the agent. Each rung's whole difficulty
# is that none of these appears in anything the player receives.
# The vulnerability, never the recovery target: `gcmreuse` legitimately says the
# flag is sealed under the GHASH subkey (you cannot unseal it otherwise), so
# "ghash" is not a giveaway — "nonce reuse" is. These are the words that would
# name the BUG.
_GIVEAWAYS = ("singular", "discriminant", " node", "nonce reuse", "reused nonce",
              "reuses a nonce", "forbidden attack", "biased", "hidden number",
              "pohlig", "wiener", "franklin", "bellcore", "csidh")


class HardRungsAreSolvable(unittest.TestCase):
    def test_every_hard_rung_verifies_across_seeds(self):
        for name in HARD_LADDER_NAMES:
            if name in LATTICE_RUNGS and not _fpylll():
                self.skipTest(f"{name} needs fpylll, which is not installed")
            gen = LADDER_NAMES.index(name)
            for seed in (101, 202, 303):
                spec = gen_crypto_ladder(seed=seed, generation=gen,
                                         flag_secret=f"secret-{seed}")
                self.assertEqual(spec.mechanics["attack_class"], name)
                verdict = verify_spec(spec)
                self.assertTrue(verdict.valid, f"{name}@{seed}: {verdict.reason}")

    def test_lattice_rungs_are_dropped_without_fpylll(self):
        """A PoC that cannot run is never advertised (P1)."""
        if not _fpylll():
            for name in LATTICE_RUNGS:
                self.assertNotIn(name, LADDER_NAMES)


class HardRungsHideTheirWeakness(unittest.TestCase):
    def test_no_artifact_names_the_attack(self):
        for name in HARD_LADDER_NAMES:
            if name not in LADDER_NAMES:
                continue
            gen = LADDER_NAMES.index(name)
            spec = gen_crypto_ladder(seed=4242, generation=gen, flag_secret="s")
            haystack = "\n".join(spec.artifacts.values()).lower()
            haystack += "\n" + "\n".join(spec.hints).lower() + "\n" + spec.story.lower()
            for giveaway in _GIVEAWAYS:
                self.assertNotIn(giveaway, haystack,
                                 f"{name} leaks the diagnosis via {giveaway!r}")

    def test_flag_is_never_in_a_player_file(self):
        for name in HARD_LADDER_NAMES:
            if name not in LADDER_NAMES:
                continue
            gen = LADDER_NAMES.index(name)
            spec = gen_crypto_ladder(seed=9, generation=gen, flag_secret="s")
            for content in spec.artifacts.values():
                self.assertNotIn(spec.flag, content)


class HardRungsSitAboveTheEasyOnes(unittest.TestCase):
    def test_they_are_the_top_of_the_ladder(self):
        present = [n for n in HARD_LADDER_NAMES if n in LADDER_NAMES]
        if not present:
            self.skipTest("no hard rungs available on this host")
        # Every hard rung ranks above every RSA-diagnosis rung.
        first_hard = min(LADDER_NAMES.index(n) for n in present)
        self.assertGreaterEqual(first_hard, 6)
        self.assertEqual(len(CRYPTO_LADDER), len(LADDER_NAMES))


class HardComposeStages(unittest.TestCase):
    def test_franklin_and_crtfault_round_trip_and_verify(self):
        import os
        import random
        import tempfile

        from autoctf_gan import rsa_stages as R

        payload = b"c0ffee00c0ffee00c0ffee00c0ffee00"
        for name in ("franklin", "crtfault"):
            self.assertIn(name, R.STAGES)
            stage = R.STAGES[name]
            files = stage.build(random.Random(f"hc:{name}"), payload, "s1_")
            with tempfile.TemporaryDirectory() as tmp:
                cwd = os.getcwd()
                os.chdir(tmp)
                try:
                    for rel, content in files.items():
                        with open(rel, "w", encoding="utf-8") as fh:
                            fh.write(content)
                    recovered = getattr(R, stage.solver)("s1_")
                finally:
                    os.chdir(cwd)
            self.assertEqual(int.from_bytes(recovered, "big"),
                             int.from_bytes(payload, "big"))

    def test_deep_compositions_withhold_per_stage_hints(self):
        from autoctf_gan.compose import HINT_DEPTH_LIMIT, describe
        shallow = describe(["franklin", "smalle"])
        self.assertTrue(any("Stage 1" in h for h in shallow.hints))
        deep = describe(["franklin", "smalle", "wiener", "crtfault"])
        self.assertFalse(any("Stage" in h for h in deep.hints))
        self.assertTrue(any("sealed layers" in h for h in deep.hints))
        self.assertGreaterEqual(len(deep.stages), HINT_DEPTH_LIMIT)


if __name__ == "__main__":
    unittest.main()
