"""metadata — an internal-only cloud-metadata-style service. Not published; only
reachable from web01 over the private network. It hands out the internal token."""
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

TOKEN = "svc-7c1f9e2a4b6d8e0f-internal"

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _send(self, code, obj):
        b = json.dumps(obj).encode() + b"\n"
        self.send_response(code); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
    def do_GET(self):
        p = urlparse(self.path).path
        if p in ("/", "/latest", "/latest/meta-data", "/latest/meta-data/"):
            self._send(200, {"service": "metadata",
                             "paths": ["/latest/meta-data/instance-id",
                                       "/latest/meta-data/internal-token"]})
            return
        if p == "/latest/meta-data/instance-id":
            self._send(200, {"instance-id": "i-0internalweb01"}); return
        if p == "/latest/meta-data/internal-token":
            self._send(200, {"token": TOKEN, "use": "present to vault as ?token="}); return
        self._send(404, {"error": "no such path"})

def main():
    port = int(os.environ.get("PORT","9000"))
    print(f"metadata listening on 0.0.0.0:{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()

if __name__ == "__main__":
    main()
