from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import sys
import zipfile
import tempfile
from pathlib import Path

from .catalog import TEMPLATES
from .orchestrator import ChallengeFactory
from .models import ChallengeSpec
from .render import render_bundle


def doctor() -> dict:
    def command_ok(command: list[str]) -> tuple[bool, str]:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=15)
            text = (result.stdout or result.stderr).strip().splitlines()
            return result.returncode == 0, text[0] if text else ""
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)
    py = (sys.version_info >= (3, 11), sys.version.split()[0])
    docker_cli = command_ok(["docker", "--version"])
    docker_engine = command_ok(["docker", "info", "--format", "{{.ServerVersion}}"])
    model = (bool(os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")), "configured" if os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") else "offline fallback")
    checks = {"python": {"ok": py[0], "detail": py[1]}, "docker_cli": {"ok": docker_cli[0], "detail": docker_cli[1]}, "docker_engine": {"ok": docker_engine[0], "detail": docker_engine[1]}, "llm": {"ok": True, "detail": model[1]}}
    return {"ready": all(x["ok"] for x in checks.values()), "checks": checks}


def batch_generate(*, count: int, categories: list[str], difficulties: list[str], theme: str, output: Path, seed: str) -> list[dict]:
    if not 1 <= count <= 100:
        raise ValueError("count must be between 1 and 100")
    choices = [(c, t) for c, t in TEMPLATES if c in categories]
    if not choices:
        raise ValueError("no templates match the selected categories")
    rng = random.Random(seed)
    results = []
    factory = ChallengeFactory()
    for index in range(1, count + 1):
        category, challenge_type = rng.choice(choices)
        difficulty = rng.choice(difficulties)
        variant = f"batch-{index:03d}"
        bundle, reports = factory.generate(category=category, challenge_type=challenge_type, difficulty=difficulty, theme=theme, output=output, variant=variant, seed=seed)
        results.append({"bundle": str(bundle), "category": category, "type": challenge_type, "difficulty": difficulty, "score": 100, "passed": all(r.passed for r in reports)})
    (output / "batch-report.json").write_text(json.dumps({"seed": seed, "count": count, "results": results}, indent=2), encoding="utf-8")
    return results


def export_player_bundle(bundle: Path, output: Path) -> Path:
    bundle = bundle.resolve()
    spec = json.loads((bundle / "challenge.json").read_text(encoding="utf-8"))
    output.mkdir(parents=True, exist_ok=True)
    target = output / f"{spec['slug']}-player.zip"
    allowed = ["README.md", "challenge.json", "quality.json", "runtime.json", "deployment.json",
               "Dockerfile", "docker-compose.yml", "launch-android.ps1"]
    source = bundle
    temporary = None
    # Web source bundles contain the live local validation flag so the organizer
    # solver and arena can test them. Never distribute that value: rebuild the
    # player-facing service with a conspicuous deployment placeholder instead.
    if spec.get("delivery") in {"web", "tcp", "api", "blockchain", "mqtt"}:
        temporary = tempfile.TemporaryDirectory()
        private = json.loads((bundle / "organizer/spec.json").read_text(encoding="utf-8"))
        redacted = ChallengeSpec.from_dict(private)
        redacted.flag = "flag{replace_at_deployment}"
        source = render_bundle(redacted, Path(temporary.name))
    try:
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
            for name in allowed:
                path = source / name if (source / name).is_file() else bundle / name
                if path.is_file(): archive.write(path, name)
            for path in (source / "player").rglob("*"):
                if not path.is_file() or path.name == "flag.txt":
                    continue
                archive.write(path, path.relative_to(source))
    finally:
        if temporary is not None:
            temporary.cleanup()
    return target
