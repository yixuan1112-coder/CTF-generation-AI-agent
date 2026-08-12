"""The maker authors, escalates across disciplines, and never reuses a flag.

Three properties are covered here, in the order they matter:

  1. FLAG ISOLATION — the regression that made the arena scoreable at all. Flags
     used to derive from the match seed alone and the seed was printed into the
     public challenge id, so an agent could compute the flag from its metadata
     and replay one flag up the whole ladder.
  2. AUTHORING — past the bounded route the maker builds challenges no rung
     contains, and each one is genuinely solvable.
  3. CAMPAIGN — escalation crosses disciplines in a declared order and never
     silently substitutes one for another.
"""
from __future__ import annotations

import hashlib
import json
import unittest

from autoctf_gan.campaign import Campaign, default_campaign
from autoctf_gan.compose import (Plan, compositions, gen_composed, ordered_catalog,
                                 plan_at)
from autoctf_gan.competition import Competition
from autoctf_gan.crypto_ladder import CRYPTO_LADDER, gen_crypto_ladder
from autoctf_gan.design import propose_plan
from autoctf_gan.rsa_stages import STAGE_NAMES, STAGES
from autoctf_gan.verify import verify_spec

SECRET = "unit-test-match-secret"


class FlagIsolationTests(unittest.TestCase):
    def test_every_generation_has_its_own_flag(self):
        """A flag solved at one rung must not unlock any other rung."""
        flags = [gen_crypto_ladder(seed=4242, generation=g, flag_secret=SECRET).flag
                 for g in range(len(CRYPTO_LADDER))]
        self.assertEqual(len(set(flags)), len(flags))

    def test_the_seed_is_not_printed_into_the_public_id(self):
        """challenge_id reaches the competing agent; the seed must not ride along."""
        seed = 987654
        for generation in (0, 3, len(CRYPTO_LADDER) + 2):
            spec = gen_crypto_ladder(seed=seed, generation=generation, flag_secret=SECRET)
            self.assertNotIn(str(seed), spec.spec_id)
            self.assertNotIn(f"{seed:06d}", spec.spec_id)

    def test_the_public_id_does_not_leak_the_flag_hash(self):
        """It used to end in sha256(flag)[:8] — half the hash, handed over free."""
        spec = gen_crypto_ladder(seed=13, generation=1, flag_secret=SECRET)
        self.assertNotIn(hashlib.sha256(spec.flag.encode()).hexdigest()[:8], spec.spec_id)

    def test_the_secret_changes_the_flag(self):
        """Two matches on the same seed must not share a flag."""
        a = gen_crypto_ladder(seed=7, generation=0, flag_secret="match-a")
        b = gen_crypto_ladder(seed=7, generation=0, flag_secret="match-b")
        self.assertNotEqual(a.flag, b.flag)

    def test_the_match_secret_never_reaches_the_player(self):
        comp = Competition(category="crypto", seed=55, verify_deploy=False)
        published = comp.current()
        blob = repr(published) + repr(comp.status()) + repr(comp.events)
        self.assertNotIn(comp.flag_secret, blob)
        self.assertNotIn(comp.spec.flag, blob)

    def test_replaying_a_solved_flag_does_not_climb(self):
        comp = Competition(category="crypto", seed=2024, evolve_on=1,
                           max_gen=3, verify_deploy=False)
        team = comp.register("replayer")["team_id"]
        first = comp.spec.flag
        self.assertTrue(comp.submit(team, comp.spec.spec_id, first)["correct"])
        # the maker has evolved; the old flag must not satisfy the new rung
        self.assertFalse(comp.submit(team, comp.spec.spec_id, first)["correct"])


class AuthoringTests(unittest.TestCase):
    def test_past_the_ladder_the_maker_composes(self):
        spec = gen_crypto_ladder(seed=31337, generation=len(CRYPTO_LADDER),
                                 flag_secret=SECRET)
        self.assertTrue(spec.mechanics["attack_class"].startswith("compose:"))
        self.assertGreaterEqual(spec.mechanics["depth"], 2)

    def test_the_ladder_no_longer_clamps(self):
        """Two generations past the end used to be the same challenge twice."""
        end = len(CRYPTO_LADDER)
        a = gen_crypto_ladder(seed=8, generation=end, flag_secret=SECRET)
        b = gen_crypto_ladder(seed=8, generation=end + 1, flag_secret=SECRET)
        self.assertNotEqual(a.mechanics["attack_class"], b.mechanics["attack_class"])
        self.assertNotEqual(a.artifacts, b.artifacts)

    def test_a_composed_challenge_is_really_solvable(self):
        """The paired PoC runs for real — the same gate every rung passes."""
        for offset in (0, 1, 30):
            spec = gen_composed(seed=606, generation=len(CRYPTO_LADDER) + offset,
                                flag_secret=SECRET)
            verdict = verify_spec(spec)
            self.assertTrue(verdict.valid, f"{spec.mechanics['attack_class']}: {verdict.reason}")

    def test_a_composed_challenge_hides_the_later_stages(self):
        """Depth is real: stage 2's key material must not be readable up front."""
        spec = gen_composed(seed=99, generation=len(CRYPTO_LADDER), flag_secret=SECRET)
        published = "\n".join(spec.artifacts.values())
        self.assertNotIn(spec.flag, published)
        self.assertIn("stage2.enc", spec.artifacts)
        # the sealed layer must not be readable text
        self.assertNotIn("n.txt", spec.artifacts["stage2.enc"])

    def test_escalation_is_monotone(self):
        """A maker that 'escalates' into an easier challenge is a broken maker."""
        ranks = [plan_at(i).rank for i in range(len(ordered_catalog()))]
        self.assertEqual(ranks, sorted(ranks))

    def test_authored_challenges_do_not_repeat(self):
        seen = {plan_at(i).stages and "+".join(plan_at(i).stages) for i in range(200)}
        self.assertEqual(len(seen), 200)

    def test_compositions_never_chain_a_class_into_itself(self):
        for depth in (2, 3):
            for combo in compositions(depth):
                self.assertTrue(all(a != b for a, b in zip(combo, combo[1:])), combo)

    def test_a_plan_only_accepts_reviewed_primitives(self):
        """The safety boundary: an LLM may order stages, never invent one."""
        with self.assertRaises(ValueError):
            Plan(stages=["smalle", "exec_arbitrary_python"]).validate()
        with self.assertRaises(ValueError):
            Plan(stages=["smalle"]).validate()          # depth 1 is not a composition
        self.assertTrue(Plan(stages=["smalle", "wiener"]).validate())

    def test_every_stage_roundtrips(self):
        """build_* and solve_* are one contract; drift here breaks every composition."""
        import os
        import random
        import tempfile
        payload = b"9f3c1a7e55b04d2288ae6c10f7d3b491"
        for name in STAGE_NAMES:
            stage = STAGES[name]
            files = stage.build(random.Random(f"rt:{name}"), payload, "s1_")
            with tempfile.TemporaryDirectory() as tmp:
                cwd = os.getcwd()
                os.chdir(tmp)
                try:
                    for rel, content in files.items():
                        with open(rel, "w", encoding="utf-8") as fh:
                            fh.write(content)
                    recovered = getattr(__import__("autoctf_gan.rsa_stages",
                                                   fromlist=["x"]), stage.solver)("s1_")
                finally:
                    os.chdir(cwd)
            self.assertEqual(recovered, payload, name)


class CampaignTests(unittest.TestCase):
    def test_the_route_starts_on_the_requested_discipline(self):
        for start in ("crypto", "reverse"):
            campaign = default_campaign(start=start, probe=False)
            self.assertEqual(campaign.segments[0].category, start)

    def test_cross_track_visits_the_other_ladder_then_authors(self):
        campaign = default_campaign(start="crypto", probe=False)
        keys = [s.key for s in campaign.segments]
        self.assertEqual(keys, ["crypto-ladder", "reverse-ladder", "crypto-compose"])
        self.assertTrue(campaign.has_authoring_tail)

    def test_generations_map_onto_segments_in_order(self):
        campaign = default_campaign(start="crypto", probe=False)
        crypto_len = len(campaign.segments[0].rungs)
        reverse_len = len(campaign.segments[1].rungs)
        self.assertEqual(campaign.locate(0)[0].key, "crypto-ladder")
        self.assertEqual(campaign.locate(crypto_len)[0].key, "reverse-ladder")
        self.assertEqual(campaign.locate(crypto_len + reverse_len)[0].key, "crypto-compose")
        self.assertEqual(campaign.bounded_rungs, crypto_len + reverse_len)

    def test_an_unbuildable_start_withdraws_the_track(self):
        """It must not cross-track into a discipline the team did not choose."""
        campaign = default_campaign(start="reverse", probe=True)
        from autoctf_gan.native import gcc_available
        if gcc_available():
            self.skipTest("this host can build the reverse ladder")
        self.assertFalse(campaign.start_available)
        self.assertEqual([s.category for s in campaign.segments], ["reverse"])

    def test_no_cross_track_keeps_a_single_ladder(self):
        campaign = default_campaign(start="crypto", cross_track=False,
                                    authoring=False, probe=False)
        self.assertEqual([s.key for s in campaign.segments], ["crypto-ladder"])
        self.assertFalse(campaign.has_authoring_tail)

    def test_a_bounded_campaign_reports_exhaustion(self):
        campaign = default_campaign(start="crypto", cross_track=False,
                                    authoring=False, probe=False)
        with self.assertRaises(ValueError):
            campaign.locate(campaign.bounded_rungs)

    def test_the_competition_switches_discipline_mid_match(self):
        campaign = Campaign(segments=[
            default_campaign(start="crypto", probe=False).segments[0],
            default_campaign(start="crypto", probe=False).segments[2],
        ])
        comp = Competition(seed=4, evolve_on=1, max_gen=None,
                           verify_deploy=False, campaign=campaign)
        team = comp.register("probe")["team_id"]
        ladder_len = len(campaign.segments[0].rungs)
        for _ in range(ladder_len + 2):
            comp.submit(team, comp.spec.spec_id, comp.spec.flag)
        self.assertTrue(comp.status()["authoring"])
        self.assertTrue(any(e["evt"] == "segment.changed" for e in comp.events))


class DesignBrainTests(unittest.TestCase):
    """The model plans and writes prose. It never supplies code, and never blocks."""

    def _reply(self, payload) -> object:
        return lambda system, user: json.dumps(payload)

    def test_a_valid_plan_is_accepted_and_marked_llm(self):
        plan = propose_plan(index=0, complete=self._reply({
            "stages": ["fermat", "wiener", "pollard"], "title": "Escrow Cascade",
            "story": "An archive rebuilt in layers.",
            "hints": ["The primes were not chosen independently."],
            "designer_note": "chains three factorization weaknesses"}))
        self.assertEqual(plan.source, "llm")
        self.assertEqual(plan.stages, ["fermat", "wiener", "pollard"])
        self.assertEqual(plan.title, "Escrow Cascade")

    def test_an_llm_designed_challenge_still_passes_the_solvability_gate(self):
        plan = propose_plan(index=0, complete=self._reply({
            "stages": ["fermat", "wiener"], "title": "Escrow Cascade",
            "story": "An archive rebuilt in layers.", "hints": ["Two layers."]}))
        spec = gen_composed(seed=42, generation=len(CRYPTO_LADDER),
                            flag_secret=SECRET, plan=plan)
        self.assertEqual(spec.mechanics["plan_source"], "llm")
        self.assertTrue(verify_spec(spec).valid)

    def test_an_invented_attack_class_is_refused(self):
        """The safety boundary: a model cannot introduce a primitive."""
        plan = propose_plan(index=0, complete=self._reply({
            "stages": ["smalle", "run_shell_command"], "title": "x",
            "story": "y", "hints": ["z"]}))
        self.assertEqual(plan.source, "catalog")
        self.assertTrue(all(s in STAGES for s in plan.stages))

    def test_prose_that_leaks_the_answer_is_refused(self):
        plan = propose_plan(index=0, complete=self._reply({
            "stages": ["smalle", "wiener"], "title": "t", "story": "s",
            "hints": ["the answer is flag{abc}"]}))
        self.assertEqual(plan.source, "catalog")

    def test_malformed_and_failing_calls_fall_back_silently(self):
        """A design brain is a nice-to-have; it must never cost a match."""
        for broken in (lambda s, u: "not json at all",
                       lambda s, u: json.dumps(["not", "an", "object"]),
                       lambda s, u: (_ for _ in ()).throw(OSError("network down")),
                       lambda s, u: (_ for _ in ()).throw(RuntimeError("rate limited"))):
            plan = propose_plan(index=0, complete=broken)
            self.assertEqual(plan.source, "catalog")
            self.assertTrue(plan.validate())

    def test_the_model_is_never_shown_a_flag_or_solver_code(self):
        """The brain plans from a catalogue of names and weaknesses — nothing else."""
        captured = {}

        def spy(system, user):
            captured["system"], captured["user"] = system, user
            return json.dumps({"stages": ["smalle", "wiener"], "title": "t",
                               "story": "s", "hints": ["h"]})

        propose_plan(index=3, complete=spy)
        self.assertNotIn("flag{", captured["system"] + captured["user"])
        payload = json.loads(captured["user"])
        # the catalogue carries descriptions, never an implementation
        self.assertEqual({"catalogue", "target_rank", "target_depth", "avoid_repeating"},
                         set(payload))
        for entry in payload["catalogue"]:
            self.assertEqual({"name", "label", "rank", "weakness"}, set(entry))
        for banned in ("def solve_", "def build_", "import ", "pow("):
            self.assertNotIn(banned, captured["user"])

    def test_catalog_mode_pins_the_deterministic_plan(self):
        campaign = default_campaign(start="crypto", probe=False, design="catalog")
        self.assertEqual(campaign.design, "catalog")
        spec = campaign.build(seed=5, generation=campaign.bounded_rungs,
                              flag_secret=SECRET)
        self.assertEqual(spec.mechanics["plan_source"], "catalog")


if __name__ == "__main__":
    unittest.main()
