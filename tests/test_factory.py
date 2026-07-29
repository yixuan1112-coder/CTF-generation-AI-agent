import tempfile
import unittest
from pathlib import Path

from ctf_factory.gates import audit_spec
from ctf_factory.llm import offline_spec
from ctf_factory.models import ChallengeSpec
from ctf_factory.orchestrator import ChallengeFactory


class FakeLLM:
    def generate(self, brief):
        return offline_spec(brief)


class FactoryTests(unittest.TestCase):
    def test_factory_generates_audited_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, reports = ChallengeFactory(FakeLLM()).generate("museum archive", Path(directory))
            self.assertTrue(all(report.passed for report in reports))
            self.assertTrue((bundle / "Dockerfile").is_file())
            self.assertTrue((bundle / "tests/test_solve.py").is_file())

    def test_rejects_unreviewed_vulnerability(self):
        spec = ChallengeSpec.from_dict(offline_spec("x"))
        spec.vulnerability = "unknown-rce"
        self.assertFalse(audit_spec(spec).passed)


if __name__ == "__main__":
    unittest.main()
