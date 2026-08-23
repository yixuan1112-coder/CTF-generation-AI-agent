"""Golden Ticket — a live Kerberos-style Pass-the-Ticket / ticket-forgery lab.

The domain controller (`dc01`) trusts any ticket that decrypts cleanly under the
`krbtgt` account's key — that is how Kerberos works, and it is why the krbtgt
hash is the domain's master key. From an earlier compromise you dumped that hash
(a DCSync-style leak, exposed here at `/loot/krbtgt_hash`). With it you can FORGE
a ticket for any principal you like — including a Domain Admin who was never
issued one — and present it to `dc01` for the flag. That is a Golden Ticket.

The legitimate path shows why forgery is needed: `dc01` will issue a real ticket
to a real user (auth by NT hash), but no real user is a Domain Admin, so a
legitimate ticket never satisfies the flag endpoint. Only a forged one does.

Stdlib only. The flag lives in the env, behind Domain Admin on dc01.
"""
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")

# Per-instance secrets. The krbtgt key is the domain master key; it is "leaked"
# (dumped from an earlier compromise) so the intended attack is ticket forgery.
KRBTGT_KEY = os.urandom(16).hex()
# A real, non-privileged user (auth by NT-style hash), to show the legit path.
JDOE_HASH = os.urandom(16).hex()

TICKET_MAGIC = "KRB5-TGT-v1"


def keystream(key: bytes, n: int) -> bytes:
    out = bytearray()
    c = 0
    while len(out) < n:
        out += hashlib.sha256(key + b"|" + str(c).encode()).digest()
        c += 1
    return bytes(out[:n])


def seal(body: dict, key_hex: str) -> str:
    raw = json.dumps(body, sort_keys=True).encode()
    ks = keystream(bytes.fromhex(key_hex), len(raw))
    return bytes(a ^ b for a, b in zip(raw, ks)).hex()


def unseal(ticket_hex: str, key_hex: str):
    raw = bytes.fromhex(ticket_hex)
    ks = keystream(bytes.fromhex(key_hex), len(raw))
    try:
        return json.loads(bytes(a ^ b for a, b in zip(raw, ks)))
    except Exception:
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

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == "/":
            self._send(200, {
                "service": "goldenticket",
                "domain": "CORP.LOCAL",
                "loot": "GET /loot/krbtgt_hash  (dumped krbtgt key from an earlier compromise)",
                "legit": "GET /tgt?user=jdoe&nthash=<hash>  (real users only; none are admin)",
                "target": "GET /resource?ticket=<hex>  (flag if the ticket is a Domain Admin)",
                "ticket_format": {"magic": TICKET_MAGIC, "user": "<name>",
                                  "groups": ["<group>", "..."],
                                  "sealed_under": "the krbtgt key (XOR sha256 keystream)"},
                "hint": "no real user is a Domain Admin — forge one with the krbtgt key",
            })
            return
        if u.path == "/loot/krbtgt_hash":
            self._send(200, {"account": "krbtgt", "nthash": KRBTGT_KEY,
                             "warning": "the krbtgt key signs every ticket in the domain"})
            return
        if u.path == "/tgt":
            # legit issuance: a real user, authenticated by hash, gets a real TGT
            if qs.get("user", [""])[0] != "jdoe" or qs.get("nthash", [""])[0].lower() != JDOE_HASH:
                self._send(401, {"error": "unknown user or bad nthash"})
                return
            ticket = seal({"magic": TICKET_MAGIC, "user": "jdoe",
                           "groups": ["Domain Users"]}, KRBTGT_KEY)
            self._send(200, {"user": "jdoe", "groups": ["Domain Users"], "ticket": ticket,
                             "note": "a valid TGT — but jdoe is not a Domain Admin"})
            return
        if u.path == "/resource":
            ticket = qs.get("ticket", [""])[0]
            body = unseal(ticket, KRBTGT_KEY)
            if not body or body.get("magic") != TICKET_MAGIC:
                self._send(401, {"error": "ticket does not decrypt under the krbtgt key"})
                return
            if "Domain Admins" not in body.get("groups", []):
                self._send(403, {"error": f"{body.get('user')!r} is not a Domain Admin",
                                 "groups": body.get("groups")})
                return
            self._send(200, {"user": body.get("user"), "flag": FLAG})
            return
        self._send(404, {"error": "no such path (start at /)"})


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"goldenticket listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
