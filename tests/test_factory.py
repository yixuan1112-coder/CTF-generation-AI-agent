import json
import tempfile
import unittest
from pathlib import Path

from ctf_factory.catalog import CATEGORY_INFO, TEMPLATES, make_spec
from ctf_factory.gates import audit_spec
from ctf_factory.models import DIFFICULTIES
from ctf_factory.orchestrator import ChallengeFactory
from ctf_factory.arena import run_arena
from ctf_factory.operations import batch_generate, export_player_bundle
from ctf_factory.studio import create_plan


class OfflineLLM:
    def rewrite_story(self, **kwargs):
        return None


class FactoryTests(unittest.TestCase):
    def test_catalog_covers_ten_domains_and_30_types(self):
        self.assertEqual(len(CATEGORY_INFO), 10)
        self.assertEqual(len(TEMPLATES), 30)
        self.assertTrue(all(sum(1 for category, _ in TEMPLATES if category == key) >= 3 for key in CATEGORY_INFO))

    def test_studio_offline_plan_stays_on_allow_list(self):
        class OfflineDesigner:
            def design_challenge(self, **kwargs): return None
        plan = create_plan({"brief": "空间站里的 RAG 污染", "difficulty": "hard"}, OfflineDesigner())
        self.assertEqual((plan["category"], plan["challenge_type"]), ("ai-ml", "rag-poisoning"))
        self.assertEqual(plan["difficulty"], "hard")

    def test_factory_accepts_safe_studio_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            design = {"title": "Neon Archive", "story": "A fictional local training archive.", "hints": ["Inspect the token."]}
            bundle, reports = ChallengeFactory(OfflineLLM()).generate(
                category="web", challenge_type="weak-session", difficulty="easy",
                theme="studio", output=Path(directory), variant="ui", design=design)
            public = json.loads((bundle / "challenge.json").read_text())
            self.assertEqual(public["title"], "Neon Archive")
            self.assertTrue(all(report.passed for report in reports))

    def test_all_template_difficulty_combinations_generate_and_solve(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for category, challenge_type in TEMPLATES:
                for difficulty in DIFFICULTIES:
                    with self.subTest(category=category, challenge_type=challenge_type, difficulty=difficulty):
                        bundle, reports = ChallengeFactory(OfflineLLM()).generate(
                            category=category, challenge_type=challenge_type,
                            difficulty=difficulty, theme="test range", output=root,
                        )
                        self.assertTrue(all(report.passed for report in reports))
                        public = json.loads((bundle / "challenge.json").read_text())
                        self.assertNotIn("flag", public)

    def test_web_attack_defend_arena(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for challenge_type in ("path-normalization", "weak-session", "query-injection"):
                bundle, _ = ChallengeFactory(OfflineLLM()).generate(category="web", challenge_type=challenge_type, difficulty="easy", theme="arena", output=root)
                report = run_arena(bundle)
                self.assertTrue(report["passed"])
                self.assertEqual(report["score"], 100)

    def test_seed_is_reproducible_and_quality_is_written(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            kwargs = dict(category="crypto", challenge_type="repeating-xor", difficulty="medium", theme="English challenge", variant="repeatable", seed="seed-42")
            one, _ = ChallengeFactory(OfflineLLM()).generate(output=Path(first), **kwargs)
            two, _ = ChallengeFactory(OfflineLLM()).generate(output=Path(second), **kwargs)
            self.assertEqual(json.loads((one / "organizer/spec.json").read_text())["flag"], json.loads((two / "organizer/spec.json").read_text())["flag"])
            self.assertEqual(json.loads((one / "quality.json").read_text())["score"], 100)

    def test_batch_and_player_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = batch_generate(count=3, categories=["crypto"], difficulties=["easy"], theme="English batch", output=root / "generated", seed="batch-seed")
            self.assertEqual(len(results), 3)
            bundle = Path(results[0]["bundle"])
            archive = export_player_bundle(bundle, root / "exports")
            self.assertTrue(archive.is_file())
            import zipfile
            with zipfile.ZipFile(archive) as z:
                names = z.namelist()
            self.assertFalse(any(name.startswith("organizer/") for name in names))

    def test_web_player_export_redacts_live_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, _ = ChallengeFactory(OfflineLLM()).generate(
                category="web", challenge_type="query-injection", difficulty="hard",
                theme="redaction", output=root / "generated")
            live_flag = json.loads((bundle / "organizer/spec.json").read_text())["flag"]
            archive = export_player_bundle(bundle, root / "exports")
            import zipfile
            with zipfile.ZipFile(archive) as zipped:
                joined = b"\n".join(zipped.read(name) for name in zipped.namelist())
            self.assertNotIn(live_flag.encode(), joined)
            self.assertIn(b"flag{replace_at_deployment}", joined)

    def test_rejects_unknown_template(self):
        with self.assertRaises(ValueError):
            make_spec("web", "unknown-rce", "easy", "x")

    def test_difficulty_changes_steps_and_hints(self):
        easy = make_spec("crypto", "repeating-xor", "easy", "x")
        hard = make_spec("crypto", "repeating-xor", "hard", "x")
        self.assertLess(len(easy.intended_solution), len(hard.intended_solution))
        self.assertGreater(len(easy.hints), len(hard.hints))
        self.assertTrue(audit_spec(hard).passed)


if __name__ == "__main__":
    unittest.main()
