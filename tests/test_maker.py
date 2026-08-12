"""The maker runs somewhere: this process, or a container.

Docker is not available in every environment this suite runs in, so the tests
split three ways:

  * the SERVICE protocol — exercised directly, since `autoctf_gan.service` is
    plain stdin/stdout and needs no container to drive
  * the CONTAINER INVOCATION — the argv, the environment and the network decision
    are asserted without running Docker, because those are exactly the details
    that are wrong in a deployment nobody tested
  * the LIVE container — skipped unless Docker and the image are both present

The third group is the only one that proves the image works. The first two prove
the arena would ask it for the right thing.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from unittest import mock

from autoctf_gan import maker as maker_mod
from autoctf_gan.campaign import default_campaign
from autoctf_gan.competition import Competition
from autoctf_gan.crypto_ladder import CRYPTO_LADDER
from autoctf_gan.maker import (BuildResult, DockerMaker, InProcessMaker, MakerError,
                               for_arena)
from autoctf_gan.models import ChallengeSpec
from autoctf_gan.service import build, capabilities, handle

SECRET = "maker-test-secret"


def _run_service(request: dict) -> dict:
    """Drive the service the way a container does: one JSON object each way."""
    proc = subprocess.run([sys.executable, "-m", "autoctf_gan.service"],
                          input=json.dumps(request).encode(),
                          capture_output=True, timeout=900)
    return json.loads(proc.stdout.decode().splitlines()[-1])


class ServiceProtocolTests(unittest.TestCase):
    def test_capabilities_reports_what_can_be_built(self):
        caps = capabilities()
        self.assertEqual(caps["protocol"], 1)
        for key in ("gcc", "fpylll", "llm"):
            self.assertIsInstance(caps[key], bool)

    def test_a_build_round_trips_through_json(self):
        response = build({"seed": 7, "generation": 0, "flag_secret": SECRET,
                          "campaign": {"start": "crypto", "design": "catalog"},
                          "verify": False})
        self.assertTrue(response["ok"])
        spec = ChallengeSpec.from_dict(response["spec"])
        self.assertEqual(spec.mechanics["attack_class"], "smalle")
        self.assertTrue(spec.flag.startswith("flag{"))
        self.assertTrue(spec.artifacts)

    def test_verification_happens_where_the_build_happens(self):
        """The solver executes in the container, not in the arena process."""
        response = build({"seed": 7, "generation": len(CRYPTO_LADDER),
                          "flag_secret": SECRET,
                          "campaign": {"start": "crypto", "design": "catalog"},
                          "verify": True})
        self.assertTrue(response["verdict"]["valid"], response["verdict"]["reason"])
        self.assertIsNotNone(response["verdict"]["poc_time_s"])

    def test_the_response_describes_the_route_it_planned(self):
        response = build({"seed": 1, "generation": 0, "flag_secret": SECRET,
                          "campaign": {"start": "crypto", "design": "catalog"}})
        keys = [s["key"] for s in response["campaign"]["segments"]]
        self.assertEqual(keys[0], "crypto-ladder")
        self.assertTrue(response["campaign"]["segments"][-1]["authoring"])

    def test_a_bad_request_is_data_not_a_crash(self):
        self.assertFalse(handle({"op": "no_such_op"})["ok"])
        self.assertIn("unknown op", handle({"op": "no_such_op"})["error"])
        broken = handle({"op": "build", "seed": "not-a-number", "generation": 0})
        self.assertFalse(broken["ok"])
        self.assertIn("error", broken)

    def test_the_entrypoint_speaks_the_protocol_as_a_subprocess(self):
        response = _run_service({"op": "capabilities"})
        self.assertTrue(response["ok"])
        self.assertEqual(response["capabilities"]["protocol"], 1)

    def test_malformed_stdin_is_reported_not_traced(self):
        proc = subprocess.run([sys.executable, "-m", "autoctf_gan.service"],
                              input=b"{not json", capture_output=True, timeout=120)
        payload = json.loads(proc.stdout.decode())
        self.assertFalse(payload["ok"])
        self.assertIn("not valid JSON", payload["error"])


class InProcessMakerTests(unittest.TestCase):
    def test_it_builds_and_verifies(self):
        maker = InProcessMaker(start="crypto", cross_track=False, design="catalog")
        result = maker.build(seed=3, generation=0, flag_secret=SECRET, verify=True)
        self.assertIsInstance(result, BuildResult)
        self.assertEqual(result.backend, "inprocess")
        self.assertTrue(result.verdict.valid)

    def test_it_admits_it_is_not_isolated(self):
        """The report must not let 'in-process' read as 'contained'."""
        report = InProcessMaker(start="crypto").describe()
        self.assertEqual(report["backend"], "inprocess")
        self.assertIn("not isolated", report["network"])
        self.assertIn("none", report["isolation"])


class ContainerInvocationTests(unittest.TestCase):
    """Assert the docker argv without needing a docker daemon."""

    def _command(self, **kw) -> list[str]:
        return DockerMaker(campaign_kw=kw, image="test-image:1")._command()

    def test_the_container_is_locked_down(self):
        cmd = " ".join(self._command(design="catalog"))
        for flag in ("--rm", "--read-only", "--cap-drop ALL",
                     "--security-opt no-new-privileges", "--pids-limit",
                     "--memory", "--tmpfs /work:rw,size=256m,mode=1777"):
            self.assertIn(flag, cmd)
        self.assertTrue(cmd.endswith("test-image:1"))

    def test_a_catalogue_only_maker_gets_no_network(self):
        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"}, clear=False):
            cmd = self._command(design="catalog")
        self.assertIn("--network", cmd)
        self.assertEqual(cmd[cmd.index("--network") + 1], "none")
        self.assertNotIn("OPENAI_API_KEY=sk-test", " ".join(cmd))

    def test_a_design_brain_maker_is_given_egress_and_the_key(self):
        """An LLM in the loop is egress in the loop — stated, not accidental."""
        with mock.patch.dict("os.environ",
                             {"OPENAI_API_KEY": "sk-test", "LLM_MODEL": "gpt-5-mini"},
                             clear=False):
            cmd = self._command(design="auto")
        self.assertNotIn("--network", cmd)
        joined = " ".join(cmd)
        self.assertIn("OPENAI_API_KEY=sk-test", joined)
        self.assertIn("LLM_MODEL=gpt-5-mini", joined)

    def test_without_a_key_even_auto_stays_disconnected(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            cmd = self._command(design="auto")
        self.assertEqual(cmd[cmd.index("--network") + 1], "none")

    def test_the_api_key_is_never_put_in_the_request_body(self):
        """The key is container environment, never protocol payload."""
        captured = {}

        def fake_call(request, timeout_s=None):
            captured.update(request)
            return {"ok": True, "capabilities": {"gcc": True, "fpylll": False,
                                                 "llm": True, "protocol": 1}}

        maker = DockerMaker(campaign_kw={"design": "auto"}, image="test-image:1")
        with mock.patch.object(maker, "_call", fake_call), \
                mock.patch.dict("os.environ", {"OPENAI_API_KEY": "sk-secret"}):
            maker.capabilities()
        self.assertNotIn("sk-secret", json.dumps(captured))

    def test_a_container_failure_becomes_a_maker_error(self):
        maker = DockerMaker(image="test-image:1")
        with mock.patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 1, b"", b"boom")
            with self.assertRaises(MakerError):
                maker.build(seed=1, generation=0, flag_secret=SECRET)

    def test_a_timeout_becomes_a_maker_error(self):
        maker = DockerMaker(image="test-image:1", timeout_s=1)
        with mock.patch("subprocess.run",
                        side_effect=subprocess.TimeoutExpired([], 1)):
            with self.assertRaises(MakerError):
                maker.build(seed=1, generation=0, flag_secret=SECRET)

    def test_the_route_is_planned_against_the_image_toolchain(self):
        """The image ships gcc; the host may not. The route must follow the image."""
        maker = DockerMaker(campaign_kw={"start": "crypto", "design": "catalog"},
                            image="test-image:1")
        with mock.patch.object(maker, "capabilities",
                               return_value={"gcc": True, "fpylll": False, "llm": False}):
            keys = [s.key for s in maker.campaign.segments]
        self.assertIn("reverse-ladder", keys)

    def test_requesting_docker_never_silently_falls_back(self):
        with mock.patch.object(maker_mod, "docker_available", return_value=False):
            with self.assertRaises(MakerError) as ctx:
                for_arena(backend="docker")
        self.assertIn("no Docker daemon", str(ctx.exception))

    def test_a_missing_image_names_the_build_command(self):
        with mock.patch.object(maker_mod, "docker_available", return_value=True), \
                mock.patch.object(maker_mod, "image_available", return_value=False):
            with self.assertRaises(MakerError) as ctx:
                for_arena(backend="docker", image="autoctf-maker:latest")
        self.assertIn("Dockerfile.maker", str(ctx.exception))

    def test_auto_falls_back_when_there_is_no_image(self):
        with mock.patch.object(maker_mod, "docker_available", return_value=True), \
                mock.patch.object(maker_mod, "image_available", return_value=False):
            self.assertEqual(for_arena(backend="auto").backend, "inprocess")


class CompetitionUsesTheMakerTests(unittest.TestCase):
    def test_a_competition_drives_whatever_maker_it_is_given(self):
        calls = []

        class RecordingMaker:
            backend = "recording"
            campaign = default_campaign(start="crypto", probe=False, design="catalog")

            def build(self, *, verify=True, **kw):
                calls.append(kw["generation"])
                spec = self.campaign.build(**kw)
                return BuildResult(spec=spec, verdict=None, backend=self.backend)

        comp = Competition(seed=11, evolve_on=1, max_gen=2, verify_deploy=False,
                           maker=RecordingMaker())
        team = comp.register("t")["team_id"]
        comp.submit(team, comp.spec.spec_id, comp.spec.flag)
        self.assertEqual(calls, [0, 1])

    def test_a_maker_failure_stalls_evolution_without_killing_the_match(self):
        class BrokenMaker:
            backend = "broken"
            campaign = default_campaign(start="crypto", probe=False, design="catalog")

            def build(self, *, verify=True, **kw):
                if kw["generation"] == 0:
                    return BuildResult(spec=self.campaign.build(**kw), backend="broken")
                raise MakerError("container vanished")

        comp = Competition(seed=12, evolve_on=1, max_gen=5, verify_deploy=False,
                           maker=BrokenMaker())
        team = comp.register("t")["team_id"]
        verdict = comp.submit(team, comp.spec.spec_id, comp.spec.flag)
        self.assertTrue(verdict["correct"])          # the solve still counts
        self.assertFalse(verdict["evolved"])         # but the maker could not escalate
        self.assertTrue(any(e["evt"] == "maker.failed" for e in comp.events))

    def test_the_maker_verdict_is_not_recomputed_on_the_host(self):
        """If the container verified it, the host must not run the solver again."""
        campaign = default_campaign(start="crypto", probe=False, design="catalog")

        class PreVerifiedMaker:
            backend = "prever"

            def __init__(self):
                self.campaign = campaign

            def build(self, *, verify=True, **kw):
                from autoctf_gan.models import Verdict
                return BuildResult(spec=campaign.build(**kw),
                                   verdict=Verdict(True, "verified in container"),
                                   backend=self.backend)

        with mock.patch("autoctf_gan.competition.verify_spec") as host_verify:
            comp = Competition(seed=13, evolve_on=1, max_gen=2, verify_deploy=True,
                               maker=PreVerifiedMaker())
            team = comp.register("t")["team_id"]
            comp.submit(team, comp.spec.spec_id, comp.spec.flag)
        host_verify.assert_not_called()


@unittest.skipUnless(maker_mod.docker_available()
                     and maker_mod.image_available(maker_mod.DEFAULT_IMAGE),
                     f"needs Docker and the {maker_mod.DEFAULT_IMAGE} image "
                     f"(docker build -t {maker_mod.DEFAULT_IMAGE} -f Dockerfile.maker .)")
class LiveContainerTests(unittest.TestCase):
    """The only tests that prove the image itself works."""

    def test_the_container_reports_its_toolchain(self):
        caps = DockerMaker().capabilities()
        self.assertEqual(caps["protocol"], 1)
        self.assertTrue(caps["gcc"], "the maker image is supposed to ship gcc")

    def test_the_container_builds_and_verifies_a_composed_challenge(self):
        maker = DockerMaker(campaign_kw={"start": "crypto", "design": "catalog"})
        result = maker.build(seed=21, generation=len(CRYPTO_LADDER),
                             flag_secret=SECRET, verify=True)
        self.assertEqual(result.backend, "docker")
        self.assertTrue(result.verdict.valid, result.verdict.reason)
        self.assertTrue(result.spec.mechanics["attack_class"].startswith("compose:"))

    def test_a_containerized_match_runs_end_to_end(self):
        comp = Competition(seed=22, evolve_on=1, max_gen=3, verify_deploy=True,
                           maker=DockerMaker(campaign_kw={"start": "crypto",
                                                          "design": "catalog"}))
        team = comp.register("t")["team_id"]
        for _ in range(3):
            self.assertTrue(comp.submit(team, comp.spec.spec_id, comp.spec.flag)["correct"])
        self.assertEqual(comp.gen, 3)


if __name__ == "__main__":
    unittest.main()
