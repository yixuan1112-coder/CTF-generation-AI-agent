"""Chain Logic — a multi-step business-logic chain, no public CVE.

The flag needs three moves that only work together, and each is a bug in ordinary-
looking logic rather than a known exploit:

  1. SSRF. `GET /fetch?url=...` fetches a URL server-side and echoes the body. It
     does not restrict the host, so it can reach services the outside cannot.
  2. A localhost-gated internal API. `/internal/*` answers only when the request
     comes from 127.0.0.1 — which is exactly what a fetch from step 1 looks like.
  3. Mass assignment. `/internal/token?user=..` mints a signed session token and
     defaults role=user, but it also reads a `role` parameter, so role=admin mints
     an admin token. `/internal/flag?token=..` returns the flag for an admin token.

Chain: fetch the internal token endpoint with role=admin, then fetch the internal
flag endpoint with that token.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SECRET = secrets.token_bytes(16)
FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")
PORT = int(os.environ.get("PORT", "9000"))
HELP = (
    "chainlogic gateway\n"
    "  GET /fetch?url=<url>   -- fetch a URL and echo its body\n"
    "  internal services bind 127.0.0.1:%d and are not exposed directly\n" % PORT
)


def sign(payload: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    mac = hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{body}.{mac}"


def verify(token: str):
    try:
        body, mac = token.split(".", 1)
        if hmac.compare_digest(mac, hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()[:16]):
            return json.loads(base64.urlsafe_b64decode(body))
    except Exception:
        pass
    return None


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/plain"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        local = self.client_address[0] in ("127.0.0.1", "::1")

        if u.path == "/":
            return self._send(200, HELP)

        if u.path == "/fetch":
            url = (q.get("url") or [""])[0]
            if not url.startswith("http://") and not url.startswith("https://"):
                return self._send(400, "url must be http(s)")
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    return self._send(200, r.read()[:8192])
            except Exception as exc:
                return self._send(502, f"fetch error: {exc}")

        if u.path.startswith("/internal/"):
            if not local:
                return self._send(403, "internal API is restricted to localhost")
            if u.path == "/internal/token":
                user = (q.get("user") or ["guest"])[0]
                role = (q.get("role") or ["user"])[0]        # mass-assignment bug
                return self._send(200, sign({"user": user, "role": role}))
            if u.path == "/internal/flag":
                claims = verify((q.get("token") or [""])[0])
                if claims and claims.get("role") == "admin":
                    return self._send(200, FLAG)
                return self._send(403, "admin token required")
            return self._send(404, "no such internal route")

        return self._send(404, "not found")


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    print(f"chainlogic listening on 0.0.0.0:{PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
