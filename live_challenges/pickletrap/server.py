"""Pickle Trap — a live HTTP service with an insecure-deserialization RCE.

On `GET /` the service issues a `session` cookie: base64 of a pickled dict
describing your (guest) session. `GET /whoami` reads that cookie back by
un-pickling it and returns a description of the object. Python's `pickle` is not a
safe format for untrusted input: a crafted pickle can execute arbitrary code
during load via `__reduce__`. There is no signature on the cookie, so you can
replace it with a malicious pickle whose reduction runs a command and returns its
output — read the flag from the environment and echo it back through /whoami.

Stdlib only. The flag is in the environment (`FLAG`), never on disk.
"""
import base64
import json
import os
import pickle
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie

FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")


class Session:
    def __init__(self, user="guest", role="user"):
        self.user = user
        self.role = role

    def __repr__(self):
        return f"Session(user={self.user!r}, role={self.role!r})"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, obj, cookie=None):
        body = json.dumps(obj).encode() + b"\n"
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", f"session={cookie}; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

    def _cookie(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return c["session"].value if "session" in c else ""

    def do_GET(self):
        if self.path == "/":
            token = base64.b64encode(pickle.dumps(Session())).decode()
            self._send(200, {
                "service": "pickletrap",
                "hint": "GET /whoami reads your `session` cookie by unpickling it.",
                "note": "the cookie is an unsigned base64 pickle; the flag is in the env",
            }, cookie=token)
            return
        if self.path == "/whoami":
            raw = self._cookie()
            if not raw:
                self._send(400, {"error": "no session cookie; GET / first"})
                return
            try:
                obj = pickle.loads(base64.b64decode(raw))     # <-- unsafe load
            except Exception as e:
                self._send(400, {"error": f"bad session: {e}"})
                return
            self._send(200, {"session": str(obj)})
            return
        self._send(404, {"error": "no such path"})


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"pickletrap listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
