import json
import tempfile
import unittest
from pathlib import Path

from ctf_factory.catalog import CATEGORY_INFO, TEMPLATES, make_spec
from ctf_factory.gates import audit_spec
from ctf_factory.models import DIFFICULTIES
from ctf_factory.evolution import EvolutionEngine
from ctf_factory.memory import ExperienceMemory
from ctf_factory.orchestrator import ChallengeFactory
from ctf_factory.arena import run_arena
from ctf_factory.operations import batch_generate, export_player_bundle
from ctf_factory.studio import DockerInstanceManager, create_plan, record_experience


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
        self.assertEqual(plan["evolution"]["agents"], ["Generator", "Solver", "Breaker", "Judge"])
        self.assertGreaterEqual(plan["evolution"]["candidate_count"], 4)
        self.assertEqual(plan["evolution"]["score_basis"].split(",")[0], "built bundles")
        self.assertGreaterEqual(plan["evolution"]["winner_generation"], 0)

    def test_experience_memory_redacts_secrets_and_guides_novelty(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "memory.sqlite3"
            memory = ExperienceMemory(database)
            plan = {"category": "web", "challenge_type": "weak-session",
                    "difficulty": "easy", "title": "Session Drift"}
            memory.remember(
                plan, score=88, passed=True,
                lessons=["Never store flag{real-secret}", "Never store sk-project-secret-value"],
            )
            self.assertEqual(memory.stats(), {"experiences": 1, "passed": 1, "patterns": 1})
            self.assertLess(memory.novelty_score(plan), 100)
            memory.close()
            raw = database.read_bytes()
            self.assertNotIn(b"flag{real-secret}", raw)
            self.assertNotIn(b"sk-project-secret-value", raw)

    def test_adversarial_evolution_rejects_public_flag_leaks(self):
        memory = ExperienceMemory(":memory:")
        engine = EvolutionEngine(memory)
        def candidate(index, lessons):
            return {
                "category": "web", "challenge_type": "weak-session",
                "difficulty": "easy", "title": f"Candidate {index}",
                "story": "Recover the local training evidence.",
                "hints": ["Inspect the session."] if index else ["flag{leaked-answer}"],
            }
        def executed(plan, index, generation):
            return {
                "score": 100, "passed": True,
                "dimensions": {
                    "execution": 100, "adversarial_resistance": 100,
                    "determinism": 100, "runtime_integrity": 100,
                },
                "evidence": ["test executable probe passed"], "risks": [],
                "metrics": {"generation": generation},
            }
        winner = engine.evolve(
            candidate, allowed={("web", "weak-session")}, count=2,
            executable_evaluator=executed,
        )
        self.assertEqual(winner["title"], "Candidate 1")
        self.assertFalse(winner["evolution"]["self_modification"])
        self.assertEqual(winner["evolution"]["executed_candidates"], 4)
        self.assertEqual(memory.stats()["experiences"], 4)
        memory.close()

    def test_successful_bundle_records_evolution_without_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            memory = ExperienceMemory(root / "memory.sqlite3")
            class OfflineDesigner:
                def design_challenge(self, **kwargs): return None
            plan = create_plan({
                "brief": "A local identity service",
                "category": "web",
                "challenge_type": "weak-session",
                "difficulty": "easy",
            }, OfflineDesigner(), memory)
            bundle, reports = ChallengeFactory(OfflineLLM()).generate(
                category=plan["category"], challenge_type=plan["challenge_type"],
                difficulty=plan["difficulty"], theme="identity",
                output=root / "generated", variant="memory", design=plan)
            evolution, stats = record_experience(bundle, plan, reports, memory)
            self.assertTrue(evolution["winner_review"]["passed"])
            self.assertGreaterEqual(stats["experiences"], 7)
            quality = json.loads((bundle / "quality.json").read_text())
            self.assertEqual(quality["experience_memory"]["experiences"], stats["experiences"])
            live_flag = json.loads((bundle / "organizer/spec.json").read_text())["flag"]
            memory.close()
            self.assertNotIn(live_flag.encode(), (root / "memory.sqlite3").read_bytes())

    def test_second_evolution_retrieves_history_and_changes_mechanics(self):
        with tempfile.TemporaryDirectory() as directory:
            memory = ExperienceMemory(Path(directory) / "memory.sqlite3")

            class OfflineDesigner:
                def design_challenge(self, **kwargs): return None

            payload = {
                "brief": "A local telemetry investigation",
                "category": "forensics",
                "challenge_type": "log-fragments",
                "difficulty": "medium",
                "evolution_candidates": 2,
                "evolution_generations": 2,
            }
            first = create_plan(payload, OfflineDesigner(), memory)
            second = create_plan(payload, OfflineDesigner(), memory)
            self.assertEqual(first["evolution"]["historical_retrieval"]["episodes"], 0)
            self.assertGreater(second["evolution"]["historical_retrieval"]["episodes"], 0)
            self.assertGreaterEqual(second["mechanics"]["decoy_density"], 1)
            retrieved = memory.retrieve("forensics", "log-fragments", "medium")
            self.assertTrue(any(item["metrics"].get("solver_seconds") is not None for item in retrieved))
            memory.close()

    def test_factory_accepts_safe_studio_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            design = {"title": "Neon Archive", "story": "A fictional local training archive.", "hints": ["Inspect the token."]}
            bundle, reports = ChallengeFactory(OfflineLLM()).generate(
                category="web", challenge_type="weak-session", difficulty="easy",
                theme="studio", output=Path(directory), variant="ui", design=design)
            public = json.loads((bundle / "challenge.json").read_text())
            self.assertEqual(public["title"], "Neon Archive")
            self.assertTrue(all(report.passed for report in reports))

    def test_docker_manager_restricts_bundles_to_generated_web_challenges(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, _ = ChallengeFactory(OfflineLLM()).generate(
                category="web", challenge_type="weak-session", difficulty="easy",
                theme="studio", output=root, variant="instance")
            manager = DockerInstanceManager(root)
            self.assertEqual(manager._bundle(bundle.name), bundle.resolve())
            self.assertIn('ports: ["127.0.0.1::8000"]', (bundle / "docker-compose.yml").read_text())
            with self.assertRaises(ValueError):
                manager._bundle("../outside")

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
                names = zipped.namelist()
                joined = b"\n".join(zipped.read(name) for name in names)
            self.assertNotIn(live_flag.encode(), joined)
            self.assertNotIn("player/flag.txt", names)

    def test_runtime_contracts_cover_service_and_attachment_deliveries(self):
        cases = {
            ("web", "weak-session"): ("docker", "http"),
            ("pwn", "stack-overflow-sim"): ("docker", "tcp"),
            ("ai-ml", "prompt-injection"): ("docker", "http"),
            ("blockchain", "storage-slots"): ("docker", "json-rpc"),
            ("iot", "mqtt-retain"): ("docker", "mqtt"),
            ("mobile", "android-manifest"): ("docker", "adb"),
            ("reverse", "xor-strings"): ("docker", "download"),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for (category, challenge_type), expected in cases.items():
                with self.subTest(category=category):
                    bundle, _ = ChallengeFactory(OfflineLLM()).generate(
                        category=category, challenge_type=challenge_type, difficulty="easy",
                        theme="runtime contract", output=root)
                    runtime = json.loads((bundle / "runtime.json").read_text())
                    self.assertEqual((runtime["kind"], runtime["protocol"]), expected)
                    if category not in {"web", "ai-ml"}:
                        self.assertTrue((bundle / "player/portal.html").is_file())

    def test_ai_runtime_and_studio_open_the_real_challenge_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, _ = ChallengeFactory(OfflineLLM()).generate(
                category="ai-ml", challenge_type="prompt-injection", difficulty="medium",
                theme="launch contract", output=root)
            service_source = (bundle / "player/service.py").read_text(encoding="utf-8")
            challenge_page = (bundle / "player/challenge.html").read_text(encoding="utf-8")
            self.assertIn('self.path in ("/","/challenge")', service_source)
            self.assertIn('self.path=="/api/chat"', service_source)
            self.assertIn('self.path=="/api/submit"', service_source)
            self.assertIn("MODEL OPERATIONS", challenge_page)
            self.assertNotIn("protected_value=", challenge_page)

            manager = DockerInstanceManager(root)

            def fake_run(_bundle, *args, **_kwargs):
                class Result:
                    stdout = "challenge\n" if args[0] == "ps" else "0.0.0.0:33960\n"
                return Result()

            manager._run = fake_run
            state = manager.status(bundle.name)
            self.assertEqual(state["url"], "http://127.0.0.1:33960")
            self.assertEqual(state["launch_url"], "http://127.0.0.1:33960/")

    def test_native_runtime_keeps_protocol_port_and_adds_browser_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, _ = ChallengeFactory(OfflineLLM()).generate(
                category="pwn", challenge_type="stack-overflow-sim", difficulty="easy",
                theme="dual runtime", output=root)
            manager = DockerInstanceManager(root)

            def fake_run(_bundle, *args, **_kwargs):
                class Result:
                    stdout = ""
                result = Result()
                if args[0] == "ps":
                    result.stdout = "challenge\n"
                elif args[-1] == "31337":
                    result.stdout = "0.0.0.0:31338\n"
                else:
                    result.stdout = "0.0.0.0:18000\n"
                return result

            manager._run = fake_run
            state = manager.status(bundle.name)
            self.assertEqual(state["command"], "nc 127.0.0.1 31338")
            self.assertEqual(state["launch_url"], "http://127.0.0.1:18000")

    def test_studio_contains_visible_adversarial_evaluation(self):
        static = Path(__file__).parents[1] / "ctf_factory" / "studio_static"
        page = (static / "index.html").read_text(encoding="utf-8")
        script = (static / "app.js").read_text(encoding="utf-8")
        self.assertIn('id="cEvalScore"', page)
        self.assertIn('id="cEvalDimensions"', page)
        self.assertIn("state.launch_url||state.url", script)

    def test_pwn_service_export_does_not_disclose_live_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, _ = ChallengeFactory(OfflineLLM()).generate(
                category="pwn", challenge_type="stack-overflow-sim", difficulty="easy",
                theme="service export", output=root / "generated")
            live_flag = json.loads((bundle / "organizer/spec.json").read_text())["flag"]
            archive = export_player_bundle(bundle, root / "exports")
            import zipfile
            with zipfile.ZipFile(archive) as zipped:
                names = zipped.namelist()
                joined = b"\n".join(zipped.read(name) for name in names)
            self.assertNotIn(live_flag.encode(), joined)
            self.assertNotIn("player/flag.txt", names)

    def test_static_portal_export_keeps_evidence_but_omits_plaintext_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, _ = ChallengeFactory(OfflineLLM()).generate(
                category="crypto", challenge_type="repeating-xor", difficulty="medium",
                theme="portal export", output=root / "generated")
            live_flag = json.loads((bundle / "organizer/spec.json").read_text())["flag"]
            archive = export_player_bundle(bundle, root / "exports")
            import zipfile
            with zipfile.ZipFile(archive) as zipped:
                names = zipped.namelist()
                joined = b"\n".join(zipped.read(name) for name in names)
            self.assertIn("player/cipher.hex", names)
            self.assertIn("player/portal.html", names)
            self.assertNotIn("player/flag.txt", names)
            self.assertNotIn(live_flag.encode(), joined)

    def test_rejects_unknown_template(self):
        with self.assertRaises(ValueError):
            make_spec("web", "unknown-rce", "easy", "x")

    def test_difficulty_changes_steps_and_hints(self):
        easy = make_spec("crypto", "repeating-xor", "easy", "x")
        hard = make_spec("crypto", "repeating-xor", "hard", "x")
        self.assertLess(len(easy.intended_solution), len(hard.intended_solution))
        self.assertGreater(len(easy.hints), len(hard.hints))
        self.assertTrue(audit_spec(hard).passed)

    def test_web_session_page_reports_the_actual_encoding_layers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for difficulty, layers in (("easy", 1), ("medium", 2), ("hard", 3)):
                bundle, _ = ChallengeFactory(OfflineLLM()).generate(
                    category="web", challenge_type="weak-session",
                    difficulty=difficulty, theme="layer check", output=root)
                app = (bundle / "player/app.py").read_text(encoding="utf-8")
                self.assertIn(f"Encoding layers: {layers}", app)


if __name__ == "__main__":
    unittest.main()
