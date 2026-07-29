from __future__ import annotations

import re
from pathlib import Path

from .models import ChallengeSpec, GateReport


ALLOWED = {("web", "path-normalization")}
FORBIDDEN = re.compile(r"(?:https?://(?!localhost|127\.0\.0\.1)|ssh-rsa|BEGIN .*PRIVATE KEY|AKIA[0-9A-Z]{16})")


def audit_spec(spec: ChallengeSpec) -> GateReport:
    checks, failures = [], []
    if (spec.category, spec.vulnerability) in ALLOWED:
        checks.append("template is allow-listed")
    else:
        failures.append("category/vulnerability has no reviewed template")
    text = str(spec.to_dict())
    if FORBIDDEN.search(text):
        failures.append("external target or credential-like material detected")
    else:
        checks.append("no external target or credential-like material")
    if re.fullmatch(r"[a-z0-9-]{3,50}", spec.slug):
        checks.append("safe slug")
    else:
        failures.append("slug is unsafe")
    if len(spec.intended_solution) >= 2:
        checks.append("solution outline present")
    else:
        failures.append("solution outline is incomplete")
    return GateReport(not failures, checks, failures)


def audit_bundle(path: Path) -> GateReport:
    checks, failures = [], []
    required = ["Dockerfile", "docker-compose.yml", "challenge.json", "README.md", "src/app.py", "tests/test_solve.py"]
    for name in required:
        if (path / name).is_file():
            checks.append(f"present: {name}")
        else:
            failures.append(f"missing: {name}")
    return GateReport(not failures, checks, failures)

