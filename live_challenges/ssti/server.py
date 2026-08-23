"""SSTI — a live server-side template injection (Jinja2) with a filter to bypass.

`GET /greet?name=<x>` builds a template by concatenating your input and rendering
it, so `{{7*7}}` comes back as `49` — classic SSTI. From there the usual path is
to walk Python's object graph to a module that can run commands and read the flag
from the environment. A filter makes the obvious payloads fail: it rejects any
`.` and a blacklist of words (`os`, `popen`, `globals`, `class`, `mro`, `flag`,
`import`, ...). The intended solution is the standard filter bypass — reach
attributes with the `|attr()` filter instead of `.`, and build the blocked words
by string concatenation.

Stdlib + jinja2. The flag is in the environment.
"""
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from jinja2 import Environment

ENV = Environment()   # NOT a sandbox — rendering attacker input is the vuln

# The filter: no dots, and a blacklist of the words the naive payloads need.
_BLOCK = re.compile(
    r"\.|__class__|__mro__|__subclasses__|__globals__|__builtins__|"
    r"\bos\b|os|popen|system|subprocess|import|eval|exec|flag|config|request|"
    r"mro|subclasses|globals|class|popen|getattr",
    re.IGNORECASE)


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
                "service": "ssti",
                "hint": "GET /greet?name=<x> renders your input as a template (try {{7*7}})",
                "note": "filter blocks '.' and words like os/popen/globals/class/mro/flag",
            })
            return
        if u.path == "/greet":
            name = parse_qs(u.query).get("name", [""])[0]
            if _BLOCK.search(name):
                self._send(403, {"error": "blocked by filter"})
                return
            try:
                rendered = ENV.from_string("Hello, " + name + "!").render()
            except Exception as e:
                self._send(200, {"result": f"template error: {type(e).__name__}: {e}"})
                return
            self._send(200, {"result": rendered})
            return
        self._send(404, {"error": "no such path"})


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"ssti listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
