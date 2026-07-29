from __future__ import annotations

import secrets
from pathlib import Path

from .gates import audit_bundle, audit_spec
from .llm import CompatibleLLM
from .models import ChallengeSpec, GateReport
from .render import render_bundle


class FactoryError(RuntimeError):
    pass


class ChallengeFactory:
    def __init__(self, llm: CompatibleLLM | None = None) -> None:
        self.llm = llm or CompatibleLLM()

    def generate(self, brief: str, output: Path) -> tuple[Path, list[GateReport]]:
        spec = ChallengeSpec.from_dict(self.llm.generate(brief))
        spec.flag = f"flag{{{secrets.token_hex(16)}}}"
        first = audit_spec(spec)
        if not first.passed:
            raise FactoryError("spec rejected: " + "; ".join(first.failures))
        output.mkdir(parents=True, exist_ok=True)
        bundle = render_bundle(spec, output)
        second = audit_bundle(bundle)
        if not second.passed:
            raise FactoryError("bundle rejected: " + "; ".join(second.failures))
        return bundle, [first, second]

