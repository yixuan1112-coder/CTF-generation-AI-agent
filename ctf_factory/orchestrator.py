from __future__ import annotations

import secrets
import shutil
import hashlib
import json
from pathlib import Path

from .catalog import make_spec
from .gates import audit_bundle, audit_spec
from .llm import CompatibleLLM
from .models import GateReport
from .render import render_bundle


class FactoryError(RuntimeError):
    pass


class ChallengeFactory:
    def __init__(self, llm: CompatibleLLM | None = None) -> None:
        self.llm = llm or CompatibleLLM()

    def generate(self, *, category: str, challenge_type: str, difficulty: str, theme: str, output: Path, variant: str = "default", seed: str | None = None, design: dict | None = None) -> tuple[Path, list[GateReport]]:
        if not __import__("re").fullmatch(r"[a-z0-9-]{1,32}", variant):
            raise FactoryError("variant must contain only lowercase letters, numbers, and hyphens")
        spec = make_spec(category, challenge_type, difficulty, theme, variant, seed)
        if design:
            if design.get("title"):
                spec.title = str(design["title"])[:120]
            if design.get("story"):
                spec.story = str(design["story"])[:600]
            if isinstance(design.get("hints"), list):
                spec.hints = [str(item)[:160] for item in design["hints"][:3]]
        else:
            try:
                story = self.llm.rewrite_story(theme=theme, title=spec.title, category=category, difficulty=difficulty)
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                story = None
            if story:
                spec.story = story
        token = hashlib.sha256(f"{seed}:{spec.slug}".encode()).hexdigest()[:32] if seed else secrets.token_hex(16)
        spec.flag = f"flag{{{token}}}"
        first = audit_spec(spec)
        if not first.passed:
            raise FactoryError("spec rejected: " + "; ".join(first.failures))
        output.mkdir(parents=True, exist_ok=True)
        target = output / spec.slug
        if target.exists():
            raise FactoryError(f"output already exists: {target}")
        try:
            bundle = render_bundle(spec, output)
            second = audit_bundle(bundle, spec.flag)
            if not second.passed:
                raise FactoryError("bundle rejected: " + "; ".join(second.failures))
            quality = {
                "version": "0.4",
                "score": 100,
                "dimensions": {"solvability": 40, "safety": 30, "difficulty_calibration": 15, "bundle_completeness": 15},
                "passed": True,
                "evidence": first.checks + second.checks,
            }
            (bundle / "quality.json").write_text(json.dumps(quality, indent=2), encoding="utf-8")
        except Exception:
            if target.exists():
                shutil.rmtree(target)
            raise
        return bundle, [first, second]

