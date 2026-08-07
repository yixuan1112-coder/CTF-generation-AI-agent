"""Attack/Defense arena for AutoCTF-GAN specs — wires into the ctf_factory arena.

`ctf_factory.arena.run_arena` runs a Docker black-box attack/defend/judge loop on
generated Web bundles. This bridge runs the SAME three-round protocol for an
AutoCTF-GAN `web`/`ssti` spec, but against a LIVE LOCAL FLASK server instead of a
Docker container — so it verifies the exploit and the defense end-to-end even in
environments without Docker (e.g. WSL without Docker Desktop integration).

Report shape matches ctf_factory.arena.run_arena (mode/challenge/rounds/score/
passed/scope) so downstream consumers are interchangeable.

Rounds:
  attacker : run the official SSTI PoC against the vulnerable app  -> flag stolen
  defender : patch the sink (escape user input, no template eval)  -> exploit blocked
  judge    : normal greeting (?name=guest) still works on both     -> no regression
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import urllib.request

from .models import ChallengeSpec

# Canonical SSTI fix: stop evaluating user input as a template. The greeting
# still renders; the injection no longer does.
_VULN_SINK = 'return Template("Hello " + name + "!").render(flag=FLAG)'
_SAFE_SINK = ('from markupsafe import escape\n'
              '    return "Hello " + str(escape(name)) + "!"  # SSTI_SINK_NEUTRALIZED')


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http(url: str, timeout: float = 5.0) -> str:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.read().decode(errors="replace")


def _serve(app_path: Path, flag: str, port: int) -> subprocess.Popen:
    env = {**os.environ, "FLAG": flag, "PORT": str(port)}
    proc = subprocess.Popen([sys.executable, str(app_path)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(40):
        try:
            _http(base + "/?name=ready")
            return proc
        except OSError:
            time.sleep(0.15)
    proc.terminate()
    raise RuntimeError("flask app did not become ready")


def _attack(base: str, solver: str, root: Path, expected_flag: str) -> bool:
    (root / "solver.py").write_text(solver, encoding="utf-8")
    out = subprocess.run([sys.executable, "solver.py", base], cwd=root,
                         capture_output=True, text=True, timeout=30).stdout
    m = re.search(r"flag\{[0-9a-f]+\}", out)
    return bool(m and m.group(0) == expected_flag)


def _normal_ok(base: str) -> bool:
    return "Hello guest!" in _http(base + "/?name=guest")


def run_ssti_arena(spec: ChallengeSpec) -> dict:
    if spec.category != "web" or spec.challenge_type != "ssti":
        raise ValueError("run_ssti_arena supports web/ssti specs only")
    import tempfile

    solver = spec.official_solver.files["solver.py"]
    vuln_app = spec.artifacts["app.py"]
    if _VULN_SINK not in vuln_app:
        raise ValueError("reviewed SSTI sink no longer matches generated source")
    safe_app = vuln_app.replace(_VULN_SINK, _SAFE_SINK)

    with tempfile.TemporaryDirectory(prefix="autoctf-arena-") as tmp:
        root = Path(tmp)

        # ---- Round 1: attacker vs vulnerable service ------------------------
        (root / "app.py").write_text(vuln_app, encoding="utf-8")
        port = _free_port()
        proc = _serve(root / "app.py", spec.flag, port)
        base = f"http://127.0.0.1:{port}"
        try:
            attack_before = _attack(base, solver, root, spec.flag)
            normal_before = _normal_ok(base)
        finally:
            proc.terminate(); proc.wait(timeout=10)

        # ---- Round 2+3: defender patches, re-evaluate -----------------------
        (root / "app.py").write_text(safe_app, encoding="utf-8")
        port = _free_port()
        proc = _serve(root / "app.py", spec.flag, port)
        base = f"http://127.0.0.1:{port}"
        try:
            attack_after = _attack(base, solver, root, spec.flag)
            normal_after = _normal_ok(base)
        finally:
            proc.terminate(); proc.wait(timeout=10)

    passed = attack_before and normal_before and not attack_after and normal_after
    return {
        "mode": "local-flask-attack-defense-arena",
        "challenge": spec.slug,
        "rounds": [
            {"agent": "attacker", "action": "jinja2 SSTI context read",
             "vulnerable_service_compromised": attack_before},
            {"agent": "defender", "action": "SSTI_SINK_NEUTRALIZED (escape user input)",
             "exploit_blocked": not attack_after},
            {"agent": "judge", "action": "normal greeting regression",
             "vulnerable_ok": normal_before, "defended_ok": normal_after},
        ],
        "score": 100 if passed else 0,
        "passed": passed,
        "scope": "Ephemeral local Flask processes on 127.0.0.1 only. No external target contacted.",
    }
