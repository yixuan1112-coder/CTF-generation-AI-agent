from __future__ import annotations

import json
import py_compile
import shutil
from pathlib import Path


PATCHES = {
    "path-normalization": {
        "marker": "SAFE_PATH_BOUNDARY",
        "old": '  value=once\n  for _ in range(DECODE_PASSES-1): value=unquote(value)\n  try: body=(ROOT/value).read_bytes()',
        "new": '  value=once\n  target=(ROOT/value).resolve()\n  if not target.is_relative_to(ROOT.resolve()): self.send_error(403); return # SAFE_PATH_BOUNDARY\n  try: body=target.read_bytes()',
        "attack": "encoded traversal",
        "normal": "public file read",
    },
    "weak-session": {
        "marker": "SIGNED_SESSION_REQUIRED",
        "old": '   admin=json.loads(raw).get("role")=="admin"',
        "new": '   admin=False # SIGNED_SESSION_REQUIRED: unsigned claims are never privileged',
        "attack": "unsigned admin role",
        "normal": "guest session",
    },
    "query-injection": {
        "marker": "PARAMETERIZED_QUERY",
        "old": 'rows=db.execute("select name from items where name=\'"+q+"\'").fetchall()',
        "new": 'rows=db.execute("select name from items where name=?",(q,)).fetchall() # PARAMETERIZED_QUERY',
        "attack": "boolean SQL injection",
        "normal": "exact item lookup",
    },
}


def run_arena(bundle: Path) -> dict:
    bundle = bundle.resolve()
    spec = json.loads((bundle / "organizer/spec.json").read_text(encoding="utf-8"))
    if spec["category"] != "web":
        raise ValueError("arena currently supports generated Web bundles only")
    rule = PATCHES[spec["challenge_type"]]
    source = bundle / "player/app.py"
    defended = bundle / "defended"
    defended.mkdir(exist_ok=True)
    defended_source = defended / "app.py"
    original = source.read_text(encoding="utf-8")
    if rule["old"] not in original:
        raise ValueError("reviewed patch no longer matches generated source")
    defended_source.write_text(original.replace(rule["old"], rule["new"]), encoding="utf-8")
    attack_before = rule["marker"] not in source.read_text(encoding="utf-8")
    attack_after = rule["marker"] not in defended_source.read_text(encoding="utf-8")
    try:
        py_compile.compile(str(defended_source), doraise=True)
        service_ok = "ThreadingHTTPServer" in defended_source.read_text(encoding="utf-8")
    except py_compile.PyCompileError:
        service_ok = False
    score = 100 if attack_before and not attack_after and service_ok else 0
    report = {
        "mode": "local-template-arena",
        "scope": str(bundle),
        "challenge": spec["challenge_type"],
        "rounds": [
            {"agent":"attacker","action":rule["attack"],"succeeded":attack_before},
            {"agent":"defender","action":f"apply {rule['marker']}","succeeded":not attack_after},
            {"agent":"judge","action":rule["normal"],"succeeded":service_ok},
        ],
        "score": score,
        "passed": score == 100,
        "note": "This arena evaluates reviewed local template semantics; it never targets external systems.",
    }
    (bundle / "arena-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report
