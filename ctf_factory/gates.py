from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from .catalog import TEMPLATES
from .models import DIFFICULTIES, ChallengeSpec, GateReport


FORBIDDEN = re.compile(r"(?:https?://(?!localhost|127\.0\.0\.1)|BEGIN .*PRIVATE KEY|AKIA[0-9A-Z]{16})")


def audit_spec(spec: ChallengeSpec) -> GateReport:
    checks, failures = [], []
    if (spec.category, spec.challenge_type) in TEMPLATES:
        checks.append("template is allow-listed")
    else:
        failures.append("category/type has no reviewed template")
    if spec.difficulty in DIFFICULTIES:
        checks.append("difficulty is calibrated")
    else:
        failures.append("unsupported difficulty")
    public_text = str(spec.to_dict(include_flag=False))
    if FORBIDDEN.search(public_text):
        failures.append("external target or credential-like material detected")
    else:
        checks.append("no external target or credential-like material")
    if re.fullmatch(r"[a-z0-9-]{3,80}", spec.slug):
        checks.append("safe slug")
    else:
        failures.append("slug is unsafe")
    return GateReport(not failures, checks, failures)


def audit_bundle(path: Path, expected_flag: str) -> GateReport:
    checks, failures = [], []
    required = ["challenge.json", "README.md", "organizer/spec.json", "organizer/solver.py", "player"]
    for name in required:
        if (path / name).exists():
            checks.append(f"present: {name}")
        else:
            failures.append(f"missing: {name}")
    public_files = [path / "challenge.json", path / "README.md"]
    if any(expected_flag in p.read_text(encoding="utf-8") for p in public_files):
        failures.append("flag leaked in public metadata")
    else:
        checks.append("flag absent from public metadata")
    if not failures:
        result = subprocess.run(
            [sys.executable, "organizer/solver.py"], cwd=path,
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip() == expected_flag:
            checks.append("organizer solver recovered exact flag")
        else:
            failures.append(f"solver failed: {result.stderr.strip() or result.stdout.strip()}")
    return GateReport(not failures, checks, failures)

