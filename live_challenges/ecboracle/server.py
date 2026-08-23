"""ECB Oracle — byte-at-a-time AES-ECB decryption of a hidden secret.

The service encrypts, under a fixed per-instance AES-128-ECB key:

    AES-ECB( key, prefix || your_bytes || SECRET )

and returns the ciphertext. ECB encrypts identical plaintext blocks to identical
ciphertext blocks, and you control `your_bytes`, so you can line the unknown up
against a block boundary and recover it one byte at a time — the classic ECB
byte-at-a-time attack. `SECRET` is the flag. The catch that makes this the hard
variant: a fixed random `prefix` of unknown length sits in front of your input,
so you must first recover the prefix length before the extraction works.

Line-oriented: `GET /encrypt?data=<hex>` -> `{"ct": "<hex>"}`. Stdlib + pycryptodome.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from Crypto.Cipher import AES

BS = 16
KEY = os.urandom(16)
PREFIX = os.urandom(5 + (os.urandom(1)[0] % 26))     # fixed, unknown length 5..30
FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}").encode()


def pkcs7(b):
    p = BS - (len(b) % BS)
    return b + bytes([p]) * p


def encrypt(user: bytes) -> bytes:
    pt = PREFIX + user + FLAG
    return AES.new(KEY, AES.MODE_ECB).encrypt(pkcs7(pt))


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
                "service": "ecboracle",
                "hint": "GET /encrypt?data=<hex> returns AES-ECB(key, prefix||data||FLAG)",
                "note": "same key every time; identical plaintext blocks -> identical ciphertext blocks",
            })
            return
        if u.path == "/encrypt":
            data = parse_qs(u.query).get("data", [""])[0]
            try:
                user = bytes.fromhex(data) if data else b""
            except ValueError:
                self._send(400, {"error": "data must be hex"})
                return
            if len(user) > 4096:
                self._send(400, {"error": "too long"})
                return
            self._send(200, {"ct": encrypt(user).hex()})
            return
        self._send(404, {"error": "no such path"})


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"ecboracle listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
