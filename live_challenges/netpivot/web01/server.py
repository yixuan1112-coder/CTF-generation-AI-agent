"""web01 — the only exposed host. Its /fetch endpoint is an SSRF: it makes an
HTTP GET from web01 to an internal host and returns the body, so it is the
player's pivot onto the private network."""
import json, os, socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import urllib.request

ALLOWED = {"metadata", "vault"}      # internal service DNS names on the private net


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _send(self, code, obj):
        b = json.dumps(obj).encode() + b"\n"
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, {"service": "web01",
                             "hint": "GET /fetch?url=http://<host>:9000/... (I can reach internal hosts)",
                             "note": "the flag is not on web01; pivot to the internal network"})
            return
        if u.path == "/fetch":
            target = parse_qs(u.query).get("url", [""])[0]
            t = urlparse(target)
            if t.scheme != "http" or t.hostname not in ALLOWED:
                self._send(400, {"error": "I can only reach internal hosts: " + ", ".join(sorted(ALLOWED))})
                return
            try:
                with urllib.request.urlopen(target, timeout=8) as r:
                    body = r.read(65536).decode(errors="replace")
                    self._send(200, {"upstream": target, "status": r.status, "body": body})
            except Exception as e:
                self._send(502, {"upstream": target, "error": f"{type(e).__name__}: {e}"})
            return
        self._send(404, {"error": "no such path"})


def main():
    port = int(os.environ.get("PORT", "9000"))
    print(f"web01 listening on 0.0.0.0:{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()

if __name__ == "__main__":
    main()
