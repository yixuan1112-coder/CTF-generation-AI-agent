"""XXE — a live XML service vulnerable to XML External Entity injection.

`POST /profile` accepts a small XML document describing a user and echoes the
name back: `<user><name>Alice</name></user>` -> `{"greeting": "Hello, Alice"}`.
The parser resolves external entities and DTDs, so a document that declares an
external entity pointing at a local file and references it in `<name>` will echo
that file's contents. The flag is at `/tmp/flag.txt`.

    <?xml version="1.0"?>
    <!DOCTYPE user [ <!ENTITY xxe SYSTEM "file:///tmp/flag.txt"> ]>
    <user><name>&xxe;</name></user>

Uses lxml. The flag is written to /tmp/flag.txt at startup (the writable mount
under the container's read-only rootfs).
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from lxml import etree

FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")


def parse_profile(xml_bytes: bytes) -> str:
    # A deliberately unsafe parser: external entities and DTDs are resolved, and
    # local file access is permitted (no_network keeps it to local files).
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True,
                             no_network=True, dtd_validation=False, recover=False)
    root = etree.fromstring(xml_bytes, parser)
    name = root.findtext("name")
    return name if name is not None else ""


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
        if self.path == "/":
            self._send(200, {
                "service": "xxe",
                "hint": "POST /profile  with an XML body: <user><name>Alice</name></user>",
                "note": "the parser resolves external entities; the flag is /tmp/flag.txt",
            })
            return
        self._send(404, {"error": "no such path"})

    def do_POST(self):
        if self.path != "/profile":
            self._send(404, {"error": "no such path"})
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            name = parse_profile(body)
        except etree.XMLSyntaxError as e:
            self._send(400, {"error": f"invalid XML: {e}"})
            return
        except Exception as e:
            self._send(400, {"error": f"parse error: {type(e).__name__}: {e}"})
            return
        self._send(200, {"greeting": f"Hello, {name}"})


def main():
    try:
        with open("/tmp/flag.txt", "w") as fh:
            fh.write(FLAG)
    except OSError:
        pass
    port = int(os.environ.get("PORT", "9000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"xxe listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
