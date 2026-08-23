"""AD Lab — a live internal-network lateral-movement chain in one container.

You already have a foothold on `web01` (10.0.0.5) in the `CORP` domain. The only
service published to the internet is web01's SSRF-able fetch endpoint; the rest of
the network — `fileserver` (10.0.0.10) and the domain controller `dc01`
(10.0.0.100) — is reachable ONLY by pivoting requests through it. The kill chain:

  1. Pivot with  GET /fetch?url=http://10.0.0.5/...  to loot web01.
  2. web01's config backup leaks user CORP\\jdoe's NT hash.
  3. Pass-the-Hash: authenticate to fileserver with that hash (no password).
  4. A share note names service account `svc_sql` (SPN MSSQLSvc/dc01).
  5. Kerberoast: ask dc01 for that SPN's service ticket — a blob encrypted with
     svc_sql's password key. Crack it offline against the wordlist.
  6. svc_sql is (misconfigured) Domain Admin: authenticate to dc01 with its hash
     and read the flag.

Authentic primitives: NT hash = MD4(pw as UTF-16LE); the roastable ticket is
encrypted under the service account's NT-derived key and only a correct password
guess decrypts it. Stdlib only; the flag lives in the env.
"""
import hashlib
import json
import os
import struct
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")


# --------------------------------------------------------------------------
# NTLM: NT hash = MD4(password encoded as UTF-16LE). hashlib has no md4 on
# OpenSSL 3, so here is a compact, correct MD4 (RFC 1320).
# --------------------------------------------------------------------------
def md4(data: bytes) -> bytes:
    def lrot(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    msg = bytearray(data)
    ml = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", ml)
    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d
        for i in (0, 4, 8, 12):
            a = lrot(a + (b & c | ~b & d) + X[i], 3)
            d = lrot(d + (a & b | ~a & c) + X[i + 1], 7)
            c = lrot(c + (d & a | ~d & b) + X[i + 2], 11)
            b = lrot(b + (c & d | ~c & a) + X[i + 3], 19)
        for i in (0, 1, 2, 3):
            a = lrot(a + (b & c | b & d | c & d) + X[i] + 0x5A827999, 3)
            d = lrot(d + (a & b | a & c | b & c) + X[i + 4] + 0x5A827999, 5)
            c = lrot(c + (d & a | d & b | a & b) + X[i + 8] + 0x5A827999, 9)
            b = lrot(b + (c & d | c & a | d & a) + X[i + 12] + 0x5A827999, 13)
        for i in (0, 2, 1, 3):
            a = lrot(a + (b ^ c ^ d) + X[i] + 0x6ED9EBA1, 3)
            d = lrot(d + (a ^ b ^ c) + X[i + 8] + 0x6ED9EBA1, 9)
            c = lrot(c + (d ^ a ^ b) + X[i + 4] + 0x6ED9EBA1, 11)
            b = lrot(b + (c ^ d ^ a) + X[i + 12] + 0x6ED9EBA1, 15)
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d)


def nt_hash(password: str) -> str:
    return md4(password.encode("utf-16-le")).hex()


def keystream(key: bytes, n: int) -> bytes:
    out = bytearray()
    c = 0
    while len(out) < n:
        out += hashlib.sha256(key + b"|" + str(c).encode()).digest()
        c += 1
    return bytes(out[:n])


# --------------------------------------------------------------------------
# The "domain": credentials and the roastable service ticket, built at startup.
# --------------------------------------------------------------------------
WORDLIST = [
    "Password1", "Summer2023!", "Welcome1", "Company123", "Passw0rd!",
    "Autumn2024", "Server2019", "Sqlservice1", "Database!23", "Winter2022!",
    "Corp@2023", "Admin@123", "Letmein1!", "Spring2024!", "Backup2023",
    "Falcon9!", "Orange!23", "Marketing1", "Finance2023", "Helpdesk1!",
    "Pa55word!", "Qwerty123!", "Zaq12wsx!", "Monday2024", "Sunshine1!",
    "Dragon2023", "Cluster01!", "Exchange1!", "Kerberos1", "TicketMaster1",
    "Sql2019Svc!", "Redteam123", "Blueteam!23", "Domain@dmin1", "October2024!",
]


def build_domain(rng):
    jdoe_pw = "J" + os.urandom(8).hex() + "!"        # strong: you loot the HASH
    svc_sql_pw = WORDLIST[rng.randrange(len(WORDLIST))]   # weak: roastable
    users = {
        "jdoe":    {"pw": jdoe_pw,   "nthash": nt_hash(jdoe_pw),   "da": False},
        "svc_sql": {"pw": svc_sql_pw, "nthash": nt_hash(svc_sql_pw), "da": True},
    }
    # the roastable TGS for MSSQLSvc/dc01, encrypted under svc_sql's key.
    spn = "MSSQLSvc/dc01.corp.local"
    marker = b"KRB5-TGS\x00" + spn.encode() + b"\x00"
    session = os.urandom(16)
    body = marker + session
    key = bytes.fromhex(users["svc_sql"]["nthash"])
    ticket = bytes(a ^ b for a, b in zip(body, keystream(key, len(body)))).hex()
    return users, spn, ticket, marker


import random as _random
_RNG = _random.Random(os.urandom(16))
USERS, SPN, TICKET, TICKET_MARKER = build_domain(_RNG)


# --------------------------------------------------------------------------
# The internal "hosts". Reachable only through web01's /fetch pivot.
# --------------------------------------------------------------------------
def internal(host, path, qs):
    if host in ("10.0.0.5", "web01", "web01.corp.local"):
        if path == "/backup/web.config":
            return 200, {
                "file": "web.config.bak",
                "content": (
                    "<configuration><appSettings>\n"
                    "  <add key=\"domain\" value=\"CORP\" />\n"
                    "  <add key=\"svcUser\" value=\"CORP\\jdoe\" />\n"
                    f"  <add key=\"svcNtHash\" value=\"{USERS['jdoe']['nthash']}\" />\n"
                    "</appSettings></configuration>"),
                "note": "cached service credentials — NT hash, not the password",
            }
        if path == "/":
            return 200, {"host": "web01", "hint": "GET /backup/web.config"}
        return 404, {"error": "not found on web01"}

    if host in ("10.0.0.10", "fileserver", "fileserver.corp.local"):
        # Pass-the-Hash: authenticate with the NT hash, no password.
        user = qs.get("user", [""])[0]
        nh = qs.get("nthash", [""])[0].lower()
        if user not in USERS or nh != USERS[user]["nthash"]:
            return 401, {"error": "authentication failed (present user + nthash)"}
        if path == "/shares":
            return 200, {"user": user, "shares": ["HR", "IT", "SYSVOL"]}
        if path == "/share/HR/note.txt":
            return 200, {"content": (
                "IT handover: the reporting DB runs as service account "
                "'svc_sql' with SPN MSSQLSvc/dc01.corp.local. Ask dc01 for its "
                "service ticket and crack it offline if you need the password.")}
        if path == "/":
            return 200, {"host": "fileserver", "hint": "GET /shares then /share/HR/note.txt"}
        return 404, {"error": "not found on fileserver"}

    if host in ("10.0.0.100", "dc01", "dc01.corp.local"):
        user = qs.get("user", [""])[0]
        nh = qs.get("nthash", [""])[0].lower()
        if path == "/tgs":
            # Kerberoast: any authenticated user can request an SPN's TGS.
            if user not in USERS or nh != USERS[user]["nthash"]:
                return 401, {"error": "need a valid TGT (user + nthash)"}
            spn = qs.get("spn", [""])[0]
            if spn != SPN:
                return 404, {"error": f"no such SPN; try {SPN}"}
            return 200, {"spn": SPN, "enctype": "svc_sql key (NT)",
                         "ticket": TICKET,
                         "note": "encrypted under the service account's password key"}
        if path == "/admin":
            # Domain Admin only. svc_sql is DA by misconfiguration.
            if user not in USERS or nh != USERS[user]["nthash"]:
                return 401, {"error": "authentication failed"}
            if not USERS[user]["da"]:
                return 403, {"error": f"{user} is not a Domain Admin"}
            return 200, {"user": user, "flag": FLAG}
        if path == "/":
            return 200, {"host": "dc01", "hint": "GET /tgs?spn=... then /admin"}
        return 404, {"error": "not found on dc01"}

    return 502, {"error": f"host {host} is unreachable from web01"}


ALLOWED_HOSTS = {"10.0.0.5", "10.0.0.10", "10.0.0.100",
                 "web01", "fileserver", "dc01",
                 "web01.corp.local", "fileserver.corp.local", "dc01.corp.local"}


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
                "service": "adlab",
                "you_are": "a foothold on web01 (10.0.0.5), domain CORP",
                "network": ["10.0.0.5 web01", "10.0.0.10 fileserver", "10.0.0.100 dc01"],
                "pivot": "GET /fetch?url=http://10.0.0.X/path  (internal hosts only)",
                "wordlist": "GET /wordlist.txt  (for offline cracking)",
                "goal": "reach Domain Admin on dc01 and read the flag",
            })
            return
        if u.path == "/wordlist.txt":
            body = ("\n".join(WORDLIST) + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if u.path == "/fetch":
            target = parse_qs(u.query).get("url", [""])[0]
            if not target:
                self._send(400, {"error": "url= required"})
                return
            t = urlparse(target)
            if t.scheme not in ("http", "") or t.hostname not in ALLOWED_HOSTS:
                self._send(400, {"error": "pivot reaches internal 10.0.0.0/24 hosts only"})
                return
            code, obj = internal(t.hostname, t.path or "/", parse_qs(t.query))
            self._send(code, {"upstream": target, "status": code, "body": obj})
            return
        self._send(404, {"error": "no such path (start at /)"})


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"adlab listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
