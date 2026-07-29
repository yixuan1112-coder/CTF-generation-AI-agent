from __future__ import annotations

import secrets
import shutil
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

    def generate(self, *, category: str, challenge_type: str, difficulty: str, theme: str, output: Path) -> tuple[Path, list[GateReport]]:
        spec = make_spec(category, challenge_type, difficulty, theme)
        story = self.llm.rewrite_story(theme=theme, title=spec.title, category=category, difficulty=difficulty)
        if story:
            spec.story = story
        spec.flag = f"flag{{{secrets.token_hex(16)}}}"
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
        except Exception:
            if target.exists():
                shutil.rmtree(target)
            raise
        return bundle, [first, second]

