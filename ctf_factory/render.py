from __future__ import annotations

import json
from pathlib import Path

from .models import ChallengeSpec


APP = r'''from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

PUBLIC = Path("/srv/public").resolve()

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b"Archive service: GET /file?name=welcome.txt"
            self.send_response(200); self.end_headers(); self.wfile.write(body); return
        raw = urlparse(self.path).query.removeprefix("name=")
        once = unquote(raw)
        if ".." in once or once.startswith("/"):
            self.send_error(403); return
        # Deliberate CTF bug: decoding again after validation.
        target = (PUBLIC / unquote(once)).resolve()
        try:
            body = target.read_bytes()
        except (OSError, ValueError):
            self.send_error(404); return
        self.send_response(200); self.end_headers(); self.wfile.write(body)

ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
'''

SOLVER_TEST = r'''from pathlib import Path
from urllib.parse import unquote

def test_intended_double_decode_reaches_flag():
    public = Path("/srv/public")
    payload = "%252e%252e%252fsecret%252fflag.txt"
    once = unquote(payload)
    assert ".." not in once and not once.startswith("/")
    twice = unquote(once)
    assert twice == "../secret/flag.txt"
    assert (public / twice).as_posix().endswith("/srv/public/../secret/flag.txt")
'''


def render_bundle(spec: ChallengeSpec, root: Path) -> Path:
    out = root / spec.slug
    (out / "src").mkdir(parents=True, exist_ok=False)
    (out / "tests").mkdir()
    (out / "public").mkdir()
    (out / "secret").mkdir()
    (out / "src/app.py").write_text(APP, encoding="utf-8")
    (out / "tests/test_solve.py").write_text(SOLVER_TEST, encoding="utf-8")
    (out / "public/welcome.txt").write_text("Nothing sensitive is in the public archive.\n", encoding="utf-8")
    (out / "secret/flag.txt").write_text(spec.flag + "\n", encoding="utf-8")
    (out / "challenge.json").write_text(json.dumps(spec.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "Dockerfile").write_text(
        "FROM python:3.12-alpine\nWORKDIR /app\nCOPY src/app.py /app/app.py\nCOPY public /srv/public\nCOPY secret /srv/secret\nUSER 65534\nEXPOSE 8000\nCMD [\"python\", \"app.py\"]\n",
        encoding="utf-8",
    )
    (out / "docker-compose.yml").write_text(
        f"services:\n  challenge:\n    build: .\n    ports:\n      - \"{spec.port}:8000\"\n    read_only: true\n    tmpfs:\n      - /tmp\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n",
        encoding="utf-8",
    )
    (out / "README.md").write_text(
        f"# {spec.title}\n\n{spec.story}\n\n## Run\n\n```sh\ndocker compose up --build\n```\n\nOnly attack this local challenge container.\n",
        encoding="utf-8",
    )
    return out

