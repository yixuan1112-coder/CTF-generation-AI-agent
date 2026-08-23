"""vault — internal-only service holding the flag. Not published; reachable only
from web01. Releases the flag to a request carrying the internal token."""
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

TOKEN = "svc-7c1f9e2a4b6d8e0f-internal"
FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _send(self, code, obj):
        b = json.dumps(obj).encode() + b"\n"
        self.send_response(code); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, {"service": "vault", "note": "GET /flag?token=<internal token>"}); return
        if u.path == "/flag":
            tok = parse_qs(u.query).get("token", [""])[0]
            if tok == TOKEN:
                self._send(200, {"flag": FLAG})
            else:
                self._send(403, {"error": "invalid internal token"})
            return
        self._send(404, {"error": "no such path"})

def main():
    port = int(os.environ.get("PORT","9000"))
    print(f"vault listening on 0.0.0.0:{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()

if __name__ == "__main__":
    main()
