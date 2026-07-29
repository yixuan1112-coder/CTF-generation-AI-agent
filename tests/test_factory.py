import json
import tempfile
import unittest
from pathlib import Path

from ctf_factory.catalog import TEMPLATES, make_spec
from ctf_factory.gates import audit_spec
from ctf_factory.models import DIFFICULTIES
from ctf_factory.orchestrator import ChallengeFactory


class OfflineLLM:
    def rewrite_story(self, **kwargs):
        return None


class FactoryTests(unittest.TestCase):
    def test_all_27_combinations_generate_and_solve(self):
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
