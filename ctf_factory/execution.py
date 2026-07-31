from __future__ import annotations

import base64
import json
import py_compile
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

from .llm import CompatibleLLM
from .operations import export_player_bundle
from .orchestrator import ChallengeFactory


class ExecutableChallengeEvaluator:
    """Build and execute a candidate in an isolated temporary bundle."""

    def __init__(self, llm: CompatibleLLM | None = None) -> None:
        self.llm = llm

    @staticmethod
    def _solver(bundle: Path, expected_flag: str) -> tuple[bool, bool, float, str]:
        outputs: list[str] = []
        started = time.perf_counter()
        for _ in range(2):
            result = subprocess.run(
                [sys.executable, "organizer/solver.py"],
                cwd=bundle,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if result.returncode:
                return False, False, time.perf_counter() - started, (
                    result.stderr or result.stdout or "solver failed"
                ).strip()[-500:]
            outputs.append(result.stdout.strip())
        return (
            all(value == expected_flag for value in outputs),
            len(set(outputs)) == 1,
            time.perf_counter() - started,
            "",
        )

    @staticmethod
    def _minimum_generic_decode_depth(data: bytes, expected: bytes) -> int | None:
        if expected in data:
            return 0
        tokens = [data.strip()]
        try:
            text = data.decode("utf-8", errors="ignore")
            tokens.extend(token.encode() for token in re.findall(r"[A-Za-z0-9+/=]{12,}|[0-9a-fA-F]{16,}", text))
        except UnicodeError:
            pass
        seen = set(tokens)
        frontier = tokens
        for depth in range(1, 4):
            next_frontier: list[bytes] = []
            for value in frontier:
                transforms: list[bytes] = []
                try:
                    transforms.append(base64.b64decode(value, validate=True))
                except (ValueError, TypeError):
                    pass
                try:
                    transforms.append(bytes.fromhex(value.decode().strip()))
                except (ValueError, UnicodeError):
                    pass
                for transformed in transforms:
                    if expected in transformed:
                        return depth
                    if transformed not in seen and len(transformed) <= 256 * 1024:
                        seen.add(transformed)
                        next_frontier.append(transformed)
            frontier = next_frontier
        return None

    @classmethod
    def _archive_probe(
        cls, archive: Path, expected_flag: str, difficulty: str,
    ) -> tuple[int, list[str], list[str], dict[str, Any]]:
        score = 100
        evidence: list[str] = []
        risks: list[str] = []
        expected = expected_flag.encode()
        minimum_depth: int | None = None
        with zipfile.ZipFile(archive) as zipped:
            names = zipped.namelist()
            if "player/flag.txt" in names or any(name.startswith("organizer/") for name in names):
                risks.append("export contains a private flag or organizer file")
                score = 0
            else:
                evidence.append("export excludes private flag and organizer files")
            for name in names:
                if name.endswith("/"):
                    continue
                data = zipped.read(name)
                if expected in data:
                    risks.append(f"plaintext flag leaked through exported file: {name}")
                    score = 0
                    break
                depth = cls._minimum_generic_decode_depth(data, expected)
                if depth is not None:
                    minimum_depth = depth if minimum_depth is None else min(minimum_depth, depth)
        required_depth = {"easy": 0, "medium": 1, "hard": 2}.get(difficulty, 1)
        if minimum_depth is not None and minimum_depth < required_depth:
            risks.append(
                f"generic shortcut recovered the flag at depth {minimum_depth}; "
                f"difficulty expects at least {required_depth}"
            )
            score = min(score, 45)
        else:
            evidence.append("generic shortcut probe found no under-calibrated decode path")
        return score, evidence, risks, {
            "generic_shortcut_depth": minimum_depth,
            "exported_files": len(names),
        }

    @staticmethod
    def _runtime_probe(bundle: Path) -> tuple[int, list[str], list[str]]:
        source = bundle / "player/service.py"
        if not source.is_file():
            source = bundle / "player/app.py"
        if not source.is_file():
            return 55, [], ["generated runtime has no executable entrypoint"]
        try:
            py_compile.compile(str(source), doraise=True)
        except py_compile.PyCompileError as exc:
            return 0, [], [f"runtime entrypoint does not compile: {exc.msg}"]
        evidence = ["generated runtime entrypoint compiles"]
        if source.name == "service.py":
            probe = (
                "import importlib.util,pathlib;"
                "p=pathlib.Path('player/service.py');"
                "s=importlib.util.spec_from_file_location('runtime_probe',p);"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                "assert callable(getattr(m,'public_challenge',None));"
                "m.public_challenge()"
            )
            result = subprocess.run(
                [sys.executable, "-c", probe],
                cwd=bundle,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode:
                return 35, evidence, [
                    "runtime import probe failed: " +
                    (result.stderr or result.stdout or "unknown error").strip()[-300:]
                ]
            evidence.append("runtime challenge metadata executed successfully")
        return 100, evidence, []

    def evaluate(
        self,
        plan: dict[str, Any],
        *,
        candidate_index: int,
        generation: int,
    ) -> dict[str, Any]:
        started = time.perf_counter()
        evidence: list[str] = []
        risks: list[str] = []
        with tempfile.TemporaryDirectory(prefix="ctf-evolution-") as directory:
            root = Path(directory)
            try:
                bundle, reports = ChallengeFactory(self.llm).generate(
                    category=str(plan["category"]),
                    challenge_type=str(plan["challenge_type"]),
                    difficulty=str(plan["difficulty"]),
                    theme=str(plan.get("story", "Evolution candidate")),
                    output=root / "generated",
                    variant=f"evo-g{generation}-c{candidate_index}",
                    seed=f"evolution-{generation}-{candidate_index}",
                    design=plan,
                )
            except Exception as exc:
                return {
                    "score": 0,
                    "passed": False,
                    "dimensions": {
                        "execution": 0, "adversarial_resistance": 0,
                        "determinism": 0, "runtime_integrity": 0,
                    },
                    "evidence": [],
                    "risks": [f"candidate build failed: {type(exc).__name__}: {exc}"],
                    "metrics": {"build_seconds": round(time.perf_counter() - started, 4)},
                }
            private = json.loads((bundle / "organizer/spec.json").read_text(encoding="utf-8"))
            expected_flag = str(private["flag"])
            solver_ok, deterministic, solver_seconds, solver_error = self._solver(
                bundle, expected_flag
            )
            execution_score = 100 if solver_ok else 0
            if solver_ok:
                evidence.append("official solver executed twice and recovered the exact flag")
            else:
                risks.append("official solver execution failed: " + solver_error)
            determinism_score = 100 if deterministic else 20
            if deterministic:
                evidence.append("repeated solver executions were deterministic")
            else:
                risks.append("solver output changed between executions")
            archive = export_player_bundle(bundle, root / "exports")
            resistance_score, archive_evidence, archive_risks, archive_metrics = (
                self._archive_probe(archive, expected_flag, str(plan["difficulty"]))
            )
            evidence.extend(archive_evidence)
            risks.extend(archive_risks)
            runtime_score, runtime_evidence, runtime_risks = self._runtime_probe(bundle)
            evidence.extend(runtime_evidence)
            risks.extend(runtime_risks)
            gate_passed = all(report.passed for report in reports)
            if gate_passed:
                evidence.append("specification and bundle release gates passed")
            else:
                risks.append("one or more release gates failed")
            score = round(
                execution_score * 0.40
                + resistance_score * 0.30
                + determinism_score * 0.15
                + runtime_score * 0.15
            )
            passed = (
                gate_passed and solver_ok and deterministic
                and resistance_score >= 60 and runtime_score >= 60
            )
            metrics = {
                "build_seconds": round(time.perf_counter() - started, 4),
                "solver_seconds": round(solver_seconds, 4),
                "gate_count": sum(len(report.checks) for report in reports),
                "mechanics_encoding_delta": int(
                    plan.get("mechanics", {}).get("encoding_delta", 0)
                ),
                "mechanics_decoy_density": int(
                    plan.get("mechanics", {}).get("decoy_density", 0)
                ),
                **archive_metrics,
            }
            return {
                "score": score,
                "passed": passed,
                "dimensions": {
                    "execution": execution_score,
                    "adversarial_resistance": resistance_score,
                    "determinism": determinism_score,
                    "runtime_integrity": runtime_score,
                },
                "evidence": evidence,
                "risks": risks,
                "metrics": metrics,
            }
