from __future__ import annotations

import base64
import json
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path


PATCHES = {
    "path-normalization": {
        "marker": "SAFE_PATH_BOUNDARY",
        "old": '  value=once\n  for _ in range(DECODE_PASSES-1): value=unquote(value)\n  try: body=(ROOT/value).read_bytes()',
        "new": '  value=once\n  target=(ROOT/value).resolve()\n  if not target.is_relative_to(ROOT.resolve()): self.send_error(403); return # SAFE_PATH_BOUNDARY\n  try: body=target.read_bytes()',
        "attack": "multi-encoded path traversal",
    },
    "weak-session": {
        "marker": "SIGNED_SESSION_REQUIRED",
        "old": '   admin=json.loads(raw).get("role")=="admin"',
        "new": '   admin=False # SIGNED_SESSION_REQUIRED: unsigned claims are never privileged',
        "attack": "unsigned administrator role cookie",
    },
    "query-injection": {
        "marker": "PARAMETERIZED_QUERY",
        "old": 'rows=db.execute("select name from items where name=\'"+q+"\'").fetchall()',
        "new": 'rows=db.execute("select name from items where name=?",(q,)).fetchall();PARAMETERIZED_QUERY=True',
        "attack": "boolean SQL injection",
    },
}


def _run(command: list[str], *, cwd: Path | None = None, timeout: int = 120) -> str:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip())
    return result.stdout.strip()


def _http(url: str, cookie: str | None = None) -> str:
    request = urllib.request.Request(url, headers={"Cookie": cookie} if cookie else {})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.read().decode(errors="replace")


def _start(tag: str) -> tuple[str, str]:
    container = _run(["docker", "run", "--rm", "-d", "-p", "127.0.0.1::8000", tag])
    port_line = _run(["docker", "port", container, "8000/tcp"])
    port = port_line.rsplit(":", 1)[-1]
    base = f"http://127.0.0.1:{port}"
    for _ in range(30):
        try:
            _http(base + "/")
            return container, base
        except OSError:
            time.sleep(0.2)
    _run(["docker", "stop", container]); raise RuntimeError("container did not become ready")


def _exploit(base: str, spec: dict) -> str:
    level = ("easy", "medium", "hard").index(spec["difficulty"]) + 1
    kind = spec["challenge_type"]
    if kind == "weak-session":
        token = json.dumps({"role": "admin"}).encode()
        for _ in range(level): token = base64.b64encode(token)
        return _http(base + "/admin", "role=" + token.decode())
    if kind == "query-injection":
        body = _http(base + "/search?name=" + urllib.parse.quote("' OR kind='flag' -- "))
        data = body.strip().encode()
        for _ in range(level - 1): data = base64.b64decode(data)
        return data.decode(errors="replace")
    depth = level + 1
    last = ""
    # HTTP clients and servers may each normalize one layer. The attacker probes
    # a bounded set around the template's documented decode depth.
    for passes in range(depth, depth + 3):
        payload = "../flag.txt"
        for _ in range(passes):
            # quote() deliberately leaves dots unescaped, while this challenge
            # needs every traversal character hidden during the first check.
            payload = "".join(f"%{byte:02X}" for byte in payload.encode())
        last = _http(base + "/file?name=" + payload)
        if "flag{" in last: return last
    return last


def _normal(base: str, kind: str) -> bool:
    if kind == "weak-session": return _http(base + "/status").strip() == "guest"
    if kind == "query-injection": return "manual" in _http(base + "/search?name=manual")
    return "public archive" in _http(base + "/file?name=welcome.txt")


def _evaluate_image(tag: str, spec: dict, expected_flag: str) -> tuple[bool, bool]:
    container = ""
    try:
        container, base = _start(tag)
        return _exploit(base, spec).strip() == expected_flag, _normal(base, spec["challenge_type"])
    finally:
        if container:
            subprocess.run(["docker", "stop", container], capture_output=True, timeout=30)


def run_arena(bundle: Path) -> dict:
    bundle = bundle.resolve()
    spec = json.loads((bundle / "organizer/spec.json").read_text(encoding="utf-8"))
    if spec["category"] != "web": raise ValueError("arena supports generated Web bundles only")
    rule = PATCHES[spec["challenge_type"]]
    original = (bundle / "player/app.py").read_text(encoding="utf-8")
    if rule["old"] not in original: raise ValueError("reviewed patch no longer matches generated source")
    vulnerable_tag = "ctf-arena-vuln-" + spec["slug"].replace("_", "-")
    _run(["docker", "build", "-q", "-t", vulnerable_tag, "."], cwd=bundle)
    attack_before, normal_before = _evaluate_image(vulnerable_tag, spec, spec["flag"])
    with tempfile.TemporaryDirectory() as directory:
        defended_root = Path(directory)
        shutil.copy2(bundle / "Dockerfile", defended_root / "Dockerfile")
        shutil.copytree(bundle / "player", defended_root / "player")
        patched = original.replace(rule["old"], rule["new"])
        (defended_root / "player/app.py").write_text(patched, encoding="utf-8")
        defended_tag = "ctf-arena-defended-" + spec["slug"].replace("_", "-")
        _run(["docker", "build", "-q", "-t", defended_tag, "."], cwd=defended_root)
        attack_after, normal_after = _evaluate_image(defended_tag, spec, spec["flag"])
    passed = attack_before and normal_before and not attack_after and normal_after
    report = {
        "mode": "docker-black-box-arena", "challenge": spec["slug"],
        "rounds": [
            {"agent": "attacker", "action": rule["attack"], "vulnerable_service_compromised": attack_before},
            {"agent": "defender", "action": f"apply {rule['marker']}", "exploit_blocked": not attack_after},
            {"agent": "judge", "action": "normal feature regression", "vulnerable_ok": normal_before, "defended_ok": normal_after},
        ],
        "score": 100 if passed else 0, "passed": passed,
        "scope": "Ephemeral local Docker containers only. No external target is contacted.",
    }
    (bundle / "arena-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
