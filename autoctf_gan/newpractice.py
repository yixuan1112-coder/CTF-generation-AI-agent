"""A second wave of static practice challenges — reverse, forensics, network, web.

Same contract as `variety.py`: every builder returns a `delivery="crypto"` spec
whose paired `solver.py` (pure standard library) recovers the flag when
`verify_spec` runs it in the sandbox, and the literal flag never appears in any
player artifact. These deliberately reach for techniques the first variety wave
skipped — GF(2) linear algebra, USB-HID scancode decode, pcap stream reassembly,
and a hash length-extension forgery — so the static catalogue spans real CTF
disciplines rather than repeating one shape.

They ride on `variety._spec`, so nothing about the archive/verify/download path
changes: `practice.py` just appends `NEWPRACTICE_BUILDERS` to the list it seeds.
"""
from __future__ import annotations

import base64
import hashlib
import struct

from .identity import challenge_flag
from .variety import _rng, _spec


# ===========================================================================
# reverse — a checker built out of GF(2) parity constraints
# ===========================================================================
# The checker computes M·x + c over GF(2), where x is the bit-expansion of the
# serial, and accepts iff the result equals a fixed target t. Recognising it as a
# linear system and solving M x = t - c with Gauss-Jordan over GF(2) recovers the
# serial, which is the flag. No per-byte shortcut: every output bit mixes many
# input bits, so it is one coupled system, not 8-bit-at-a-time inversion.
_GF2_SOLVER = '''\
"""checker.py accepts one serial and prints CORRECT. It verifies a system of GF(2)
parity equations: for each row i, XOR of the selected serial bits equals t_i. That
is a linear system  M x = t  over GF(2); solve it with Gaussian elimination and
read the serial (LSB-first per byte) back out. The serial is the flag."""

def load():
    rows, rhs = [], []
    with open("system.txt", encoding="utf-8") as fh:
        n = int(fh.readline().split()[1])          # "bits N"
        for line in fh:
            line = line.strip()
            if not line:
                continue
            mask_hex, bit = line.split()
            rows.append(int(mask_hex, 16))
            rhs.append(int(bit))
    return n, rows, rhs

n, rows, rhs = load()
# Gauss-Jordan over GF(2): each equation is an int bitmask (the selected x-bits)
# plus a right-hand-side bit. Reduce to solve for every x-bit.
eqs = [(rows[i] | (rhs[i] << n)) for i in range(len(rows))]   # pack rhs as bit n
pivot_for = {}
for col in range(n):
    # find a row whose lowest set data-bit is `col`
    piv = None
    for e in eqs:
        if (e & ((1 << col) - 1)) == 0 and (e >> col) & 1:
            piv = e
            break
    if piv is None:
        continue
    pivot_for[col] = piv
    eqs = [e ^ piv if (e is not piv and (e >> col) & 1) else e for e in eqs]

x = 0
for col, piv in pivot_for.items():
    # after full reduction each pivot row is (1<<col) | (bit<<n)
    x |= ((piv >> n) & 1) << col

serial = bytes((x >> (8 * i)) & 0xFF for i in range(n // 8))
flag = serial.decode()
assert flag.startswith("flag{"), "linear solve did not land on a flag"
print(flag)
'''

_GF2_CHECKER = '''\
"""checker.py — vendor serial validator.

    python3 checker.py <serial>

Accepts exactly one serial. The accepted serial is the flag. Each line of
system.txt is one parity check over the bits of the serial (bit 0 = LSB of the
first byte): the XOR of the serial bits named by the hex mask must equal the
trailing bit. Recover the serial that satisfies every check."""
import sys


def bits_of(data):
    v = 0
    for i, b in enumerate(data):
        v |= b << (8 * i)
    return v


def check(serial):
    x = bits_of(serial)
    with open("system.txt", encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            line = line.strip()
            if not line:
                continue
            mask_hex, want = line.split()
            got = bin(int(mask_hex, 16) & x).count("1") & 1
            if got != int(want):
                return False
    return True


if __name__ == "__main__":
    print("CORRECT" if check(sys.argv[1].encode()) else "WRONG")
'''


def gen_gf2keygen(seed, generation, **kw):
    secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="gf2keygen", seed=seed, generation=generation, secret=secret)
    rng = _rng("gf2keygen", seed, generation, secret)
    data = flag.encode()
    n = 8 * len(data)
    x = 0
    for i, b in enumerate(data):
        x |= b << (8 * i)
    # A unit lower-triangular matrix over GF(2) is always invertible, so the system
    # has exactly one solution — the serial. Row i owns pivot bit i plus a random
    # spread of lower bits, so every equation genuinely couples many unknowns.
    lines = [f"bits {n}"]
    for i in range(n):
        mask = 1 << i
        for j in range(i):
            if rng.random() < 0.5:
                mask |= 1 << j
        bit = bin(mask & x).count("1") & 1
        lines.append(f"{mask:x} {bit}")
    artifacts = {
        "checker.py": _GF2_CHECKER,
        "system.txt": "\n".join(lines) + "\n",
        "README.md": ("# Serial validator\n\n"
                      "`checker.py` accepts exactly one serial and prints CORRECT; that "
                      "serial is the flag. `system.txt` is the set of parity checks it "
                      "enforces over the serial's bits. Solve the system.\n"),
    }
    return _spec(
        slug=f"np-gf2-g{generation}-" +
             hashlib.sha256(f"gf2keygen:{secret}:{seed}:{generation}".encode()).hexdigest()[:8],
        title="Serial Validator", category="reverse", challenge_type="gf2-linear-system",
        story="A serial validator enforces a web of parity checks; recover the one serial that passes.",
        vulnerability="the check is a linear system over GF(2) — solvable by Gaussian elimination",
        solution=["read checker.py: each row is a parity (XOR) constraint on the serial bits",
                  "assemble M x = t over GF(2) and Gauss-eliminate to recover the serial"],
        artifacts=artifacts, solver=_GF2_SOLVER, flag=flag, seed=seed,
        generation=generation, attack_class="gf2-linear-system", rank=7, difficulty="hard")


# ===========================================================================
# forensics — a USB HID keyboard capture
# ===========================================================================
# A stream of 8-byte USB HID keyboard reports (modifier, reserved, up to six
# keycodes). Decode the scancodes — honouring the shift modifier for the braces —
# to read back what was typed. What was typed is the flag.
_HID_SOLVER = '''\
"""keys.txt is a USB HID keyboard capture: one 8-byte report per line (hex). Byte 0
is the modifier bitmap (bit 1 or 5 = shift), byte 2 is the active keycode. Map the
keycodes back to characters, apply shift for the shifted symbols, and read the
typed string — it is the flag."""

BASE = {0x27: "0"}
for i in range(1, 10):
    BASE[0x1e + (i - 1)] = str(i)              # 0x1e..0x26 -> '1'..'9'
for i in range(26):
    BASE[0x04 + i] = chr(ord("a") + i)         # 0x04..0x1d -> 'a'..'z'
BASE[0x2d] = "-"; BASE[0x2f] = "["; BASE[0x30] = "]"
BASE[0x2c] = " "; BASE[0x37] = "."; BASE[0x33] = ";"
SHIFT = {"[": "{", "]": "}", "-": "_", ";": ":", "9": "(", "0": ")"}

out = []
for line in open("keys.txt", encoding="utf-8"):
    line = line.strip().replace(" ", "")
    if not line:
        continue
    rep = bytes.fromhex(line)
    mod, key = rep[0], rep[2]
    if key == 0:
        continue
    ch = BASE.get(key)
    if ch is None:
        continue
    if mod & 0x22:                              # left or right shift
        ch = SHIFT.get(ch, ch.upper())
    out.append(ch)
flag = "".join(out)
assert flag.startswith("flag{"), "decoded keystrokes are not a flag"
print(flag)
'''

_HID_BASE = {"0": 0x27}
for _i in range(1, 10):
    _HID_BASE[str(_i)] = 0x1e + (_i - 1)
for _i in range(26):
    _HID_BASE[chr(ord("a") + _i)] = 0x04 + _i
_HID_SHIFTED = {"{": 0x2f, "}": 0x30, "_": 0x2d}   # keycode + shift


def _hid_reports(text, rng):
    reports = []
    for ch in text:
        mod, key = 0x00, 0x00
        if ch in _HID_BASE:
            key = _HID_BASE[ch]
        elif ch in _HID_SHIFTED:
            key, mod = _HID_SHIFTED[ch], 0x02
        else:
            continue
        reports.append(bytes([mod, 0x00, key, 0, 0, 0, 0, 0]))
        # a key-up report between presses, as a real capture shows
        reports.append(bytes(8))
    return reports


def gen_usbhid(seed, generation, **kw):
    secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="usbhid", seed=seed, generation=generation, secret=secret)
    rng = _rng("usbhid", seed, generation, secret)
    reports = _hid_reports(flag, rng)
    body = "\n".join(r.hex() for r in reports) + "\n"
    artifacts = {
        "keys.txt": body,
        "README.md": ("# Captured keystrokes\n\n"
                      "A USB sniffer logged this keyboard's traffic: one 8-byte HID "
                      "report per line. Someone typed a passphrase — decode the "
                      "scancodes to read what they typed.\n"),
    }
    return _spec(
        slug=f"np-usbhid-g{generation}-" +
             hashlib.sha256(f"usbhid:{secret}:{seed}:{generation}".encode()).hexdigest()[:8],
        title="Captured Keystrokes", category="forensics", challenge_type="usb-hid-decode",
        story="A USB capture logged a keyboard; decode the HID reports to read what was typed.",
        vulnerability="raw USB HID keyboard reports — scancodes map straight back to characters",
        solution=["parse each 8-byte report: byte 0 is the modifier, byte 2 the keycode",
                  "map keycodes to characters, applying shift for the braces"],
        artifacts=artifacts, solver=_HID_SOLVER, flag=flag, seed=seed,
        generation=generation, attack_class="usb-hid-decode", rank=4, difficulty="medium")


# ===========================================================================
# network — reassemble an exfil stream out of a pcap
# ===========================================================================
# A real (little-endian) libpcap file with a handful of Ethernet/IPv4/TCP frames.
# The frames arrive out of order and the payload is base64 of the flag, split
# across segments. Reassemble by TCP sequence number, concatenate, base64-decode.
_PCAP_SOLVER = '''\
"""capture.pcap.b64 is a base64-wrapped libpcap file. Parse it, pull the TCP
payloads, order the segments by sequence number, concatenate, and base64-decode
the reassembled stream — it is the flag."""
import base64
import struct

raw = base64.b64decode(open("capture.pcap.b64", encoding="utf-8").read())

magic = raw[:4]
le = magic in (b"\\xd4\\xc3\\xb2\\xa1", b"\\x4d\\x3c\\xb2\\xa1")
end = "<" if le else ">"
off = 24                                    # skip the global header
segs = []
while off + 16 <= len(raw):
    _ts, _us, caplen, _orig = struct.unpack(end + "IIII", raw[off:off + 16])
    off += 16
    frame = raw[off:off + caplen]
    off += caplen
    if len(frame) < 14 + 20:
        continue
    ihl = (frame[14] & 0x0F) * 4
    ip = frame[14:14 + ihl]
    if ip[9] != 6:                          # protocol 6 = TCP
        continue
    tcp_off = 14 + ihl
    tcp = frame[tcp_off:]
    seq = struct.unpack(">I", tcp[4:8])[0]
    data_off = (tcp[12] >> 4) * 4
    payload = tcp[data_off:]
    if payload:
        segs.append((seq, payload))

segs.sort()
stream = b"".join(p for _s, p in segs)
flag = base64.b64decode(stream).decode()
assert flag.startswith("flag{"), "reassembled stream is not a flag"
print(flag)
'''


def _ipv4_tcp_frame(seq, payload, sport, dport):
    """Build one Ethernet/IPv4/TCP frame carrying `payload` at TCP seq `seq`."""
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0,
                      (5 << 4), 0x18, 8192, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0,
                     bytes([10, 0, 0, 2]), bytes([10, 0, 0, 1]))
    return eth + ip + tcp


def gen_pcapstream(seed, generation, **kw):
    secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="pcapstream", seed=seed, generation=generation, secret=secret)
    rng = _rng("pcapstream", seed, generation, secret)
    encoded = base64.b64encode(flag.encode())
    # split the base64 stream into 3-5 TCP segments and emit them out of order
    n_seg = rng.randint(3, 5)
    cuts = sorted(rng.sample(range(1, len(encoded)), n_seg - 1))
    bounds = [0, *cuts, len(encoded)]
    segments = [encoded[bounds[i]:bounds[i + 1]] for i in range(n_seg)]
    base_seq = rng.randint(1000, 5_000_000)
    records = []
    seq = base_seq
    order = list(range(n_seg))
    for idx in order:
        records.append((seq, segments[idx]))
        seq += len(segments[idx])
    rng.shuffle(records)                        # arrive out of order
    sport, dport = rng.randint(1025, 65000), 4444
    pcap = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)  # LE global header
    ts = 1_600_000_000
    for i, (sq, payload) in enumerate(records):
        frame = _ipv4_tcp_frame(sq, payload, sport, dport)
        pcap += struct.pack("<IIII", ts + i, i * 137, len(frame), len(frame)) + frame
    artifacts = {
        "capture.pcap.b64": base64.b64encode(pcap).decode() + "\n",
        "README.md": ("# Exfil capture\n\n"
                      "`capture.pcap.b64` is a base64-wrapped packet capture (decode it "
                      "to a real `.pcap` you can open in Wireshark). A short TCP stream "
                      "carried data off the host — the segments are out of order. "
                      "Reassemble the stream and recover what left.\n"),
    }
    return _spec(
        slug=f"np-pcap-g{generation}-" +
             hashlib.sha256(f"pcapstream:{secret}:{seed}:{generation}".encode()).hexdigest()[:8],
        title="Exfil Capture", category="forensics", challenge_type="pcap-tcp-reassembly",
        story="A packet capture holds a short, out-of-order TCP stream that carried data off a host.",
        vulnerability="TCP payload reassembly by sequence number, then base64 decode",
        solution=["parse the libpcap records and pull the TCP payloads",
                  "order the segments by sequence number, concatenate, and base64-decode"],
        artifacts=artifacts, solver=_PCAP_SOLVER, flag=flag, seed=seed,
        generation=generation, attack_class="pcap-tcp-reassembly", rank=6, difficulty="hard")


# ===========================================================================
# web — a session cookie forged by SHA-256 length extension
# ===========================================================================
# The cookie is `data | mac`, mac = sha256(secret || data). The server grants the
# flag when the data says role=admin. Not knowing `secret` is no defence: SHA-256
# is a Merkle-Damgård hash, so from (data, mac, len(secret)) you can compute a
# valid mac for `data || glue || &role=admin` without the key. The flag is sealed
# under that forged mac, so only a correct forgery unseals it.
_SHA256_PY = '''
# A from-scratch SHA-256 that also supports *resuming* from a known digest — the
# core primitive of a length-extension forgery.
import struct

_K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]

def _rotr(x, n): return ((x >> n) | (x << (32 - n))) & 0xffffffff

def _pad(msg_len):
    pad = b"\\x80" + b"\\x00" * ((56 - (msg_len + 1) % 64) % 64)
    return pad + struct.pack(">Q", msg_len * 8)

def _compress(state, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i-15],7) ^ _rotr(w[i-15],18) ^ (w[i-15] >> 3)
        s1 = _rotr(w[i-2],17) ^ _rotr(w[i-2],19) ^ (w[i-2] >> 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) & 0xffffffff)
    a,b,c,d,e,f,g,h = state
    for i in range(64):
        S1 = _rotr(e,6) ^ _rotr(e,11) ^ _rotr(e,25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + _K[i] + w[i]) & 0xffffffff
        S0 = _rotr(a,2) ^ _rotr(a,13) ^ _rotr(a,22)
        mj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + mj) & 0xffffffff
        h,g,f,e,d,c,b,a = g,f,e,(d+t1)&0xffffffff,c,b,a,(t1+t2)&0xffffffff
    return [(x + y) & 0xffffffff for x, y in zip(state, [a,b,c,d,e,f,g,h])]

_INIT = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]

def sha256(msg, state=None, prefix_len=0):
    """Hash `msg`. With state+prefix_len set, resume from that digest as if
    prefix_len bytes were already consumed (length extension)."""
    st = list(state) if state else list(_INIT)
    if state:
        data = msg + _pad(prefix_len + len(msg))
        # the already-processed prefix + its glue padding is accounted for by
        # prefix_len; we only feed the new suffix + final padding here
        data = msg + _pad(prefix_len + len(msg))
    else:
        data = msg + _pad(len(msg))
    for i in range(0, len(data), 64):
        st = _compress(st, data[i:i+64])
    return b"".join(struct.pack(">I", x) for x in st)

def state_from_digest(digest):
    return list(struct.unpack(">8I", digest))

def glue_padding(msg_len):
    return _pad(msg_len)
'''

_LENEXT_SOLVER = '''\
"""Forge an admin cookie by SHA-256 length extension.

cookie.txt holds `data|mac` with mac = sha256(secret || data) and the secret
length is given in README (SECRET_LEN). Extend the message with `&role=admin`:
compute the glue padding sha256 used after (secret||data), then continue the hash
state from `mac` over the suffix — no secret needed. The forged mac is the seal
key for flag.enc.
"""
''' + _SHA256_PY + '''

SECRET_LEN = __SECRET_LEN__
SUFFIX = b"&role=admin"

raw = open("cookie.txt", encoding="utf-8").read().strip()
data_hex, mac_hex = raw.split("|")
data = bytes.fromhex(data_hex)
mac = bytes.fromhex(mac_hex)

glue = glue_padding(SECRET_LEN + len(data))
prefix_len = SECRET_LEN + len(data) + len(glue)
forged_mac = sha256(SUFFIX, state=state_from_digest(mac), prefix_len=prefix_len).hex()

def keystream(seed_hex, n):
    out = bytearray(); c = 0
    while len(out) < n:
        out += __import__("hashlib").sha256(seed_hex.encode() + b"|" + str(c).encode()).digest(); c += 1
    return bytes(out[:n])

sealed = bytes.fromhex(open("flag.enc", encoding="utf-8").read().strip())
magic = b"AUTOCTF-LE\\x00"
plain = bytes(a ^ b for a, b in zip(sealed, keystream(forged_mac, len(sealed))))
assert plain.startswith(magic), "forged mac did not unseal — check the padding"
flag = plain[len(magic):].decode()
assert flag.startswith("flag{"), "unsealed data is not a flag"
print(flag)
'''


def _sha256_lenext_forged_mac(secret_len, data, mac):
    """Mirror the solver's forge, in-process, to derive the seal key."""
    import struct as _s

    def rotr(x, n): return ((x >> n) | (x << (32 - n))) & 0xffffffff
    K = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]

    def pad(mlen):
        return b"\x80" + b"\x00" * ((56 - (mlen + 1) % 64) % 64) + _s.pack(">Q", mlen * 8)

    def compress(state, block):
        w = list(_s.unpack(">16I", block))
        for i in range(16, 64):
            s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3)
            s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xffffffff)
        a,b,c,d,e,f,g,h = state
        for i in range(64):
            S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25)
            ch = (e & f) ^ (~e & g)
            t1 = (h + S1 + ch + K[i] + w[i]) & 0xffffffff
            S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22)
            mj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + mj) & 0xffffffff
            h,g,f,e,d,c,b,a = g,f,e,(d+t1)&0xffffffff,c,b,a,(t1+t2)&0xffffffff
        return [(x + y) & 0xffffffff for x, y in zip(state, [a,b,c,d,e,f,g,h])]

    suffix = b"&role=admin"
    glue = pad(secret_len + len(data))
    prefix_len = secret_len + len(data) + len(glue)
    st = list(_s.unpack(">8I", mac))
    block = suffix + pad(prefix_len + len(suffix))
    for i in range(0, len(block), 64):
        st = compress(st, block[i:i + 64])
    return b"".join(_s.pack(">I", x) for x in st).hex()


def gen_lenext_cookie(seed, generation, **kw):
    secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="lenextcookie", seed=seed, generation=generation, secret=secret)
    rng = _rng("lenextcookie", seed, generation, secret)
    secret_len = rng.randint(8, 20)
    mac_secret = bytes(rng.getrandbits(8) for _ in range(secret_len))
    data = b"user=guest&role=user"
    mac = hashlib.sha256(mac_secret + data).hexdigest()
    forged_mac = _sha256_lenext_forged_mac(secret_len, data, bytes.fromhex(mac))

    def keystream(seed_hex, n):
        out = bytearray(); c = 0
        while len(out) < n:
            out += hashlib.sha256(seed_hex.encode() + b"|" + str(c).encode()).digest(); c += 1
        return bytes(out[:n])

    magic = b"AUTOCTF-LE\x00"
    body = magic + flag.encode()
    sealed = bytes(a ^ b for a, b in zip(body, keystream(forged_mac, len(body)))).hex()
    solver = _LENEXT_SOLVER.replace("__SECRET_LEN__", str(secret_len))
    artifacts = {
        "cookie.txt": f"{data.hex()}|{mac}\n",
        "flag.enc": sealed + "\n",
        "README.md": ("# Session cookie\n\n"
                      "The app hands out a cookie `data|mac` where "
                      "`mac = sha256(SECRET || data)` and grants the flag when the data "
                      f"contains `role=admin`. The server-side `SECRET` is {secret_len} "
                      "bytes long. `flag.enc` is the operator blob, sealed under the mac "
                      "the server would accept for an admin cookie. Forge it.\n"),
    }
    return _spec(
        slug=f"np-lenext-g{generation}-" +
             hashlib.sha256(f"lenextcookie:{secret}:{seed}:{generation}".encode()).hexdigest()[:8],
        title="Session Cookie", category="web", challenge_type="hash-length-extension",
        story="A web session cookie is authenticated with sha256(secret || data) — forge an admin cookie.",
        vulnerability="secret-prefix MAC over a Merkle-Damgard hash (SHA-256 length extension)",
        solution=["recognise mac = sha256(secret || data) with a known secret length",
                  "length-extend to append &role=admin and compute the mac without the secret",
                  "the forged mac unseals flag.enc"],
        artifacts=artifacts, solver=solver, flag=flag, seed=seed,
        generation=generation, attack_class="hash-length-extension", rank=8, difficulty="hard")


NEWPRACTICE_BUILDERS = [gen_gf2keygen, gen_usbhid, gen_pcapstream, gen_lenext_cookie]
