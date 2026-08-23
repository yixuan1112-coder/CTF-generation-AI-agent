"""Command Injection — a live HTTP service with a filtered shell injection.

`GET /stat?path=<p>` reports the size of a file under `/tmp` by shelling out:

    stat -c %s /tmp/<p>

with `shell=True`, and returns the command's combined output. It is injectable,
but a filter rejects the usual metacharacters — `; | & \` newline` and every
space — so the obvious `; cat /tmp/flag.txt` is blocked. The bypass is the
red-team staple: shell command substitution plus `${IFS}` for whitespace. Inject
`$(cat${IFS}/tmp/flag.txt)` and `stat` will complain about a file whose name is
the flag, reflecting it straight back to you.

Stdlib only. The flag is written to `/tmp/flag.txt` at startup (the only writable
mount under the container's read-only rootfs).
"""
import json
import os
import re
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")

# A "WAF": block the obvious command separators/redirects and all whitespace.
# It does NOT block `$`, `(`, `)`, `{`, `}` — leaving command substitution and
# ${IFS} open, which is the intended bypass.
_BLOCK = re.compile(r"[;|&`\n\r\t ]|\.\.")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, obj):
        body = json.dumps(obj).encode() + b"\n"
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, {
                "service": "cmdinject",
                "hint": "GET /stat?path=<p> runs: stat -c %s /tmp/<p>",
                "note": "filter blocks ; | & backtick, whitespace and ..  — the flag is /tmp/flag.txt",
            })
            return
        if u.path == "/stat":
            path = parse_qs(u.query).get("path", [""])[0]
            if _BLOCK.search(path):
                self._send(403, {"error": "blocked by filter"})
                return
            cmd = "stat -c %s /tmp/" + path             # injectable, shell=True
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True,
                                     text=True, timeout=5)
                self._send(200, {"output": (out.stdout + out.stderr).strip()})
            except subprocess.TimeoutExpired:
                self._send(200, {"output": "timeout"})
            return
        self._send(404, {"error": "no such path"})


def main():
    # the target file whose contents are the flag (/tmp is the writable mount)
    try:
        with open("/tmp/flag.txt", "w") as fh:
            fh.write(FLAG)
        with open("/tmp/readme", "w") as fh:
            fh.write("diagnostics\n")
    except OSError:
        pass
    port = int(os.environ.get("PORT", "9000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"cmdinject listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
