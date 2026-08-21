"""Harder rungs: real cryptanalysis, an interlocked real-vuln pair, and a decode
that crosses categories.

  filtergen    A keystream that is the output of a linear-feedback shift register.
               There is no key to search and no cipher to recognise — the stream
               just has to be cryptanalysed. A known header gives enough keystream
               bits to run Berlekamp-Massey, recover the register, and run it
               forward to decrypt the rest.

  hmacpollute  Two real flaws that only escalate together. The token MAC is
               hash(secret ‖ token) over an in-house hash, so it length-extends —
               but a bare extension buys nothing until you read the token parser
               and notice it is last-value-wins, so an appended role=admin
               overrides the original role. You have to find BOTH: the extendable
               MAC and the parser rule that makes the extension matter.

  crosskey     A signal decode feeding a cipher. An OOK/Manchester beacon carries
               a key, not a flag; demodulate it, then use the key as the seed of
               the keystream that sealed the payload. The forensics half produces
               exactly what the crypto half needs.

Two of these recover the flag from a signal or a forge with no secret; none writes
the flag into a player artifact.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import random
import struct
import wave

from .hardcore import _SEAL_TOOL, _seal
from .identity import challenge_flag
from .realvuln import _HASH_SRC, _lenext_glue, _lenext_hash
from .signals import BEACON_CHIP, BEACON_FS, BEACON_PREAMBLE, _beacon_manchester


def _spec(*, slug, title, category, challenge_type, story, vulnerability, solution,
          artifacts, solver_files, flag, seed, generation, attack_class, rank,
          max_runtime_s, flag_secret, difficulty="hard"):
    from .models import ChainStep, ChallengeSpec, Lineage, OfficialSolver
    expected = hashlib.sha256(flag.encode()).hexdigest()
    return ChallengeSpec(
        slug=slug, title=f"{title} (Gen-{generation})", category=category,
        challenge_type=challenge_type, difficulty=difficulty, story=story,
        vulnerability=vulnerability, intended_solution=solution, hints=[],
        delivery="crypto", seed=seed,
        mechanics={"attack_class": attack_class, "rank": rank},
        flag=flag, spec_id=slug,
        lineage=Lineage(archetype_id=f"harder.{attack_class}", generation=generation,
                        parent_spec_id=None, mutation_ops=[], seed=seed),
        vuln_chain=[ChainStep(step=1, primitive=f"{attack_class}_stage",
                              params={}, guard=category)],
        artifacts=artifacts,
        official_solver=OfficialSolver(entry="solver.py", files=solver_files,
                                       expected_flag_sha256=expected,
                                       max_runtime_s=max_runtime_s),
        target_solve_rate=0.02)


def _slug(kind, flag_secret, seed, generation):
    tag = hashlib.sha256(f"{kind}:{flag_secret}:{seed}:{generation}".encode()).hexdigest()[:8]
    return f"hd-{kind}-g{generation}-{tag}"


# ---------------------------------------------------------------------------
# filtergen — LFSR keystream recovered by Berlekamp-Massey
# ---------------------------------------------------------------------------
FILTER_DEG = 40
FILTER_HEADER = b"TELEMETRY/1.1;o="       # 16-byte known plaintext prefix

_FILTERGEN_SOLVER = '''\
"""Recover an LFSR keystream by Berlekamp-Massey, then decrypt the rest.

The record is XORed with the output bits of a linear-feedback shift register.
There is no key to guess. The known header (`header` in `record.json`) gives the
first bytes of plaintext, so XOR it against the ciphertext to expose that many
keystream bits. Berlekamp-Massey turns a run of LFSR output into the shortest
register that produces it — feed it the exposed bits and it returns the connection
polynomial. Run that register forward to generate the whole keystream, then XOR it
across the ciphertext; the plaintext after the header is the flag.
"""
import json

doc = json.load(open("record.json", encoding="utf-8"))
ct = bytes.fromhex(doc["ciphertext"])
header = doc["header"].encode()

bits_ct = [(ct[i] >> (7 - k)) & 1 for i in range(len(ct)) for k in range(8)]
bits_hdr = [(header[i] >> (7 - k)) & 1 for i in range(len(header)) for k in range(8)]
known = [bits_ct[i] ^ bits_hdr[i] for i in range(len(bits_hdr))]


def berlekamp_massey(bits):
    n = len(bits)
    c = [1] + [0] * n
    b = [1] + [0] * n
    L, m = 0, 1
    for i in range(n):
        d = bits[i]
        for j in range(1, L + 1):
            d ^= c[j] & bits[i - j]
        if d == 0:
            m += 1
        elif 2 * L <= i:
            t = c[:]
            for j in range(n - m + 1):
                c[j + m] ^= b[j]
            L = i + 1 - L
            b, m = t, 1
        else:
            for j in range(n - m + 1):
                c[j + m] ^= b[j]
            m += 1
    return c[1:L + 1]


conn = berlekamp_massey(known)
L = len(conn)
stream = known[:]
while len(stream) < len(bits_ct):
    nb = 0
    for j in range(L):
        nb ^= conn[j] & stream[-1 - j]
    stream.append(nb)

ks = bytes(int("".join(str(stream[i + k]) for k in range(8)), 2)
           for i in range(0, len(bits_ct), 8))
plain = bytes(a ^ b for a, b in zip(ct, ks))
flag = plain[len(header):]
print(flag[:flag.find(b"}") + 1].decode())
'''


def gen_filtergen(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="filtergen", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"filtergen:{flag_secret}:{seed}:{generation}")

    taps = sorted(rng.sample(range(FILTER_DEG), 6))
    state = [rng.randrange(2) for _ in range(FILTER_DEG)]
    plain = FILTER_HEADER + flag.encode()
    nbits = len(plain) * 8
    stream, s = [], state[:]
    for _ in range(nbits):
        stream.append(s[-1])
        fb = 0
        for t in taps:
            fb ^= s[t]
        s = [fb] + s[:-1]
    ks = bytes(int("".join(str(stream[i + k]) for k in range(8)), 2)
               for i in range(0, nbits, 8))
    ct = bytes(a ^ b for a, b in zip(plain, ks))

    artifacts = {
        "record.json": json.dumps({
            "note": "record = plaintext XOR keystream; plaintext begins with header",
            "header": FILTER_HEADER.decode(),
            "ciphertext": ct.hex(),
        }, indent=1) + "\n",
        "README.md": (
            "# Telemetry record\n\n"
            "`record.json` is one telemetry record encrypted with a bit-stream cipher "
            "— the plaintext XORed with a pseudo-random keystream. Every record on "
            "this link begins with the fixed header given in the file; the flag "
            "follows it.\n\n"
            "There is no key in the file. Recover the flag (`flag{...}`).\n"),
    }
    return _spec(
        slug=_slug("filtergen", flag_secret, seed, generation),
        title="Telemetry Record", category="crypto",
        challenge_type="lfsr-keystream-recovery",
        story=("A telemetry record is XORed with a pseudo-random keystream. No key "
               "ships with it, but every record opens with the same fixed header."),
        vulnerability=("the keystream is a linear-feedback shift register, so a known-plaintext "
                       "run recovers the register by Berlekamp-Massey and the rest follows"),
        solution=["xor the known header against the ciphertext to expose keystream bits",
                  "run Berlekamp-Massey on those bits to get the connection polynomial",
                  "run the recovered register forward over the whole record length",
                  "xor the full keystream out; the flag follows the header"],
        artifacts=artifacts,
        solver_files={"solver.py": _FILTERGEN_SOLVER},
        flag=flag, seed=seed, generation=generation, attack_class="filtergen",
        rank=16, max_runtime_s=60, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# hmacpollute — length extension + last-value-wins parser
# ---------------------------------------------------------------------------
_PARSER_SRC = '''\
"""Token parser + access check (reference build).

A token is `k=v` pairs joined by `&`. Access is granted when the parsed role is
`admin`.
"""


def parse(token_bytes):
    fields = {}
    for pair in token_bytes.split(b"&"):
        if b"=" in pair:
            k, v = pair.split(b"=", 1)
            fields[k] = v
    return fields


def is_admin(token_bytes):
    return parse(token_bytes).get(b"role") == b"admin"
'''

_HMACPOLLUTE_SOLVER = '''\
"""Escalate to admin: length-extend the MAC AND know what to append.

The MAC is `authhash.mac(secret, token)` over the Merkle-Damgard hash in
`authhash.py`, so it length-extends: the published MAC is the hash state, and
appending bytes continues it without the secret. But an extension only helps
because of `parser.py`: the parser is last-value-wins, so appending `&role=admin`
overrides the token's original `role=guest`. Read the parser to know that; a
first-wins parser would make the whole thing useless.

So append `&role=admin`, compute the extended MAC, and seal opens on that forged
MAC (which authenticates the admin-granting token).
"""
import json

import authhash

doc = json.load(open("token.json", encoding="utf-8"))
message = doc["message"].encode()
mac = int(doc["mac"], 16)
secret_len = doc["secret_len"]

extension = b"&role=admin"
glue = authhash.pad(secret_len + len(message))
total = secret_len + len(message) + len(glue) + len(extension)
data = extension + authhash.pad(total)
state = mac
for i in range(0, len(data), authhash.B):
    state = authhash.compress(state, data[i:i + authhash.B])

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), f"{state:016x}"))
'''


def gen_hmacpollute(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="hmacpollute", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"hmacpollute:{flag_secret}:{seed}:{generation}")
    secret = bytes(rng.randrange(256) for _ in range(16))
    message = (f"user=guest&role=guest&sid={rng.randrange(10**8):08d}").encode()
    extension = b"&role=admin"

    mac, _ = _lenext_hash(secret, message)
    forged_mac, _ = _lenext_hash(secret, message + _lenext_glue(secret, message) + extension)

    artifacts = {
        "authhash.py": _HASH_SRC,
        "parser.py": _PARSER_SRC,
        "token.json": json.dumps({
            "note": "server grants access when parser.is_admin(token) and the MAC checks",
            "message": message.decode(),
            "mac": f"{mac:016x}",
            "secret_len": 16,
        }, indent=1) + "\n",
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(f"{forged_mac:016x}", flag),
        "README.md": (
            "# Admin token\n\n"
            "The server authenticates a token as `authhash.mac(secret, token)` "
            "(`authhash.py`) and grants access when `parser.is_admin(token)` "
            "(`parser.py`). `token.json` is a captured guest token with its MAC and "
            "the secret's length; the secret is not disclosed.\n\n"
            "Produce a token the server accepts as admin. The recovery blob is sealed "
            "under the MAC of that token, as 16 lowercase hex digits. `sealed.py` "
            "opens it.\n"),
    }
    return _spec(
        slug=_slug("hmacpollute", flag_secret, seed, generation),
        title="Admin Token", category="crypto",
        challenge_type="length-extension-plus-parser-pollution",
        story=("A server authenticates tokens with hash(secret ‖ token) and grants "
               "admin by parsing the token. A guest token was captured. Two things "
               "about the design have to line up for an escalation."),
        vulnerability=("the MAC length-extends and the parser is last-value-wins, so an "
                       "appended role=admin both authenticates and overrides — neither alone"),
        solution=["see the MAC as an extendable secret-prefix construction",
                  "read the parser and note later fields overwrite earlier ones",
                  "append &role=admin so it both extends the MAC and wins the parse",
                  "compute the extended MAC over the appended token"],
        artifacts=artifacts,
        solver_files={"solver.py": _HMACPOLLUTE_SOLVER, "authhash.py": _HASH_SRC,
                      "parser.py": _PARSER_SRC, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="hmacpollute",
        rank=15, max_runtime_s=60, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# crosskey — beacon decode feeds a keystream cipher
# ---------------------------------------------------------------------------
CROSS_WHITEN_LEN = 4

_CROSSKEY_SOLVER = '''\
"""A forensics decode that produces the crypto key.

The WAV is an OOK/Manchester beacon, but it carries a key, not a flag. Demodulate
it as a beacon: threshold the envelope to chips, Manchester-decode ((on,off)=1,
(off,on)=0, silence ends a burst), find the 0xAAAA sync, and drop it. The payload
is whitened by a short repeating pad and begins with the marker `KEY:`, so XOR the
first four payload bytes with `KEY:` to recover the pad, XOR it across the payload,
and drop the marker — what remains is 32 hex characters, the key.

The sealed payload is then XORed with a sha256 counter-stream keyed by that key.
"""
import base64
import hashlib
import io
import struct
import wave

raw = base64.b64decode("".join(open("capture.wav.b64", encoding="utf-8").read().split()))
w = wave.open(io.BytesIO(raw), "rb")
n = w.getnframes()
samples = list(struct.unpack("<%d" % n + "h", w.readframes(n)))

CHIP = 10
env = [abs(s) for s in samples]
thr = max(env) // 2
chip_bits = []
for i in range(0, len(env) - CHIP + 1, CHIP):
    window = env[i:i + CHIP]
    chip_bits.append(1 if sum(1 for e in window if e > thr) > CHIP // 2 else 0)


def manch(databits):
    out = []
    for b in databits:
        out += [1, 0] if b else [0, 1]
    return out


pre = manch([(b >> k) & 1 for b in b"\\xAA\\xAA" for k in range(7, -1, -1)])
off = next(o for o in range(len(chip_bits) - len(pre))
           if chip_bits[o:o + len(pre)] == pre)
databits, j = [], off
while j + 2 <= len(chip_bits):
    a, b = chip_bits[j], chip_bits[j + 1]
    if (a, b) == (1, 0):
        databits.append(1)
    elif (a, b) == (0, 1):
        databits.append(0)
    else:
        break
    j += 2
frame = bytes(int("".join(str(x) for x in databits[k:k + 8]), 2)
              for k in range(0, len(databits) - 7, 8))
payload = frame[2:]

marker = b"KEY:"
pad = bytes(payload[i] ^ marker[i] for i in range(len(marker)))
dewhite = bytes(payload[i] ^ pad[i % len(pad)] for i in range(len(payload)))
key = dewhite[len(marker):len(marker) + 32]

blob = bytes.fromhex(open("payload.enc", encoding="utf-8").read().strip())
ks = bytearray()
counter = 0
while len(ks) < len(blob):
    ks += hashlib.sha256(key + b"|" + str(counter).encode()).digest()
    counter += 1
secret = bytes(a ^ b for a, b in zip(blob, ks)).decode()

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), secret))
'''


def gen_crosskey(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="crosskey", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"crosskey:{flag_secret}:{seed}:{generation}")

    key_hex = hashlib.sha256(f"crosskey-key:{flag_secret}:{seed}:{generation}"
                             .encode()).hexdigest()[:32].encode()   # 32 hex chars
    payload_plain = b"KEY:" + key_hex                              # known marker prefix
    pad = bytes(rng.randrange(256) for _ in range(CROSS_WHITEN_LEN))
    whitened = bytes(payload_plain[i] ^ pad[i % CROSS_WHITEN_LEN]
                     for i in range(len(payload_plain)))
    frame = BEACON_PREAMBLE + whitened
    databits = [(byte >> k) & 1 for byte in frame for k in range(7, -1, -1)]
    chips = _beacon_manchester(databits)

    samples = []
    for _ in range(3):
        for c in chips:
            amp = 12000 if c else 0
            for _ in range(BEACON_CHIP):
                samples.append(amp + rng.randint(-180, 180))
        samples += [rng.randint(-180, 180) for _ in range(BEACON_CHIP * 8)]
    buf = io.BytesIO()
    w = wave.open(buf, "wb")
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(BEACON_FS)
    w.writeframes(b"".join(struct.pack("<h", max(-32000, min(32000, s))) for s in samples))
    w.close()
    encoded = base64.b64encode(buf.getvalue()).decode()

    secret = hashlib.sha256(f"crosskey-secret:{flag_secret}:{seed}:{generation}"
                            .encode()).hexdigest()[:32]
    ks = bytearray()
    counter = 0
    while len(ks) < len(secret):
        ks += hashlib.sha256(key_hex + b"|" + str(counter).encode()).digest()
        counter += 1
    payload = bytes(a ^ b for a, b in zip(secret.encode(), ks))

    artifacts = {
        "capture.wav.b64": "\n".join(encoded[i:i + 76]
                                     for i in range(0, len(encoded), 76)) + "\n",
        "payload.enc": payload.hex() + "\n",
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(secret, flag),
        "README.md": (
            "# Keyed beacon\n\n"
            "`capture.wav.b64` is a base64-wrapped WAV of a short-range beacon that "
            "keys a carrier on and off and repeats its burst. It does not transmit "
            "the flag — it transmits a key. `payload.enc` is a record sealed under a "
            "keystream derived from that key.\n\n"
            "The recovery blob is sealed under the decrypted payload string. "
            "`sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("crosskey", flag_secret, seed, generation),
        title="Keyed Beacon", category="forensics",
        challenge_type="signal-decode-into-keystream",
        story=("A beacon was recorded off the air, and separately a record encrypted "
               "under a key the beacon carries. Neither half is the flag; together they "
               "are."),
        vulnerability=("the beacon's demodulated payload is the keystream seed for the sealed "
                       "record, so a forensics decode produces the crypto key"),
        solution=["demodulate the OOK/Manchester beacon to its payload bytes",
                  "the payload is a hex key under a repeating whitening pad; de-whiten it",
                  "derive the sha256 counter-keystream from the recovered key",
                  "xor it against the record and unseal"],
        artifacts=artifacts,
        solver_files={"solver.py": _CROSSKEY_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="crosskey",
        rank=17, max_runtime_s=120, flag_secret=flag_secret)


HARDER_BUILDERS = [gen_filtergen, gen_hmacpollute, gen_crosskey]
