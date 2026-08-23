"""JWT Lab — a live HTTP service with a JWT algorithm-confusion flaw.

On `GET /` the service hands you a *guest* session token: a normal HS256 JWT
signed with a per-instance server secret, carrying `{"user":"guest","role":"user"}`.
`GET /flag` returns the flag only to a token whose `role` is `admin`.

You cannot forge an HS256 admin token — the secret is random and never leaves the
box. But the verifier has the classic algorithm-confusion bug: it honours the
token's own `alg` header, and it accepts `alg:none` (an unsigned token) as valid.
So mint your own header `{"alg":"none"}` with `{"role":"admin"}` and an empty
signature, and `/flag` will trust it.

Everything is line-oriented JSON over HTTP; no external libraries.
"""
import base64
import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.urandom(32)                       # per-instance, never leaves the box
FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")


def b64u_dec(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_token(payload: dict) -> str:
    header = b64u_enc(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64u_enc(json.dumps(payload).encode())
    sig = b64u_enc(hmac.new(SECRET, f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def verify(token: str):
    """Return the payload if the token 'verifies', else None.

    The bug: the verifier trusts the token's own `alg`. For `HS256` it checks the
    HMAC; for `none` it accepts the token with no signature at all.
    """
    try:
        h_b64, p_b64, sig = token.split(".")
        header = json.loads(b64u_dec(h_b64))
        payload = json.loads(b64u_dec(p_b64))
    except Exception:
        return None
    alg = header.get("alg", "")
    if alg == "none":
        return payload                        # <-- accepts unsigned tokens
    if alg == "HS256":
        expect = b64u_enc(hmac.new(SECRET, f"{h_b64}.{p_b64}".encode(),
                                   hashlib.sha256).digest())
        if hmac.compare_digest(expect, sig):
            return payload
    return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, obj):
        body = json.dumps(obj).encode() + b"\n"
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):                # keep the container quiet
        pass

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            token = make_token({"user": "guest", "role": "user"})
            self._send(200, {
                "service": "jwtlab",
                "hint": "GET /flag with header  Authorization: Bearer <token>",
                "your_token": token,
                "note": "guests are not admins; the flag wants role=admin",
            })
            return
        if self.path == "/flag":
            auth = self.headers.get("Authorization", "")
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            payload = verify(token)
            if payload and payload.get("role") == "admin":
                self._send(200, {"flag": FLAG})
            else:
                self._send(403, {"error": "admin only", "you_are": payload})
            return
        self._send(404, {"error": "no such path"})


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"jwtlab listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
