"""A spread of challenge categories beyond crypto — misc, web, forensics, reverse.

The practice model is a static download plus a server-side flag check, which fits
any challenge whose answer can be recovered from files alone. That rules out
*interactive* categories — real pwn and live web want a running service to attack,
which is the arena's agent/service track, not a download. It leaves plenty that
works well as files: reverse an encoding, exploit reused keystream, crack a weak
JWT secret, carve a hidden payload out of a blob, or invert an obfuscated keygen.

Every generator here returns a `delivery="crypto"` spec, which is not a claim
about the category — it just means `verify_spec` recovers the flag by running the
shipped `solver.py` in a subalt sandbox and checking the hash. The solvers are
pure standard library so they run anywhere, and none of them writes the literal
flag into a player artifact (the leak gate would reject that): the flag is always
encoded, XORed, sealed, or transformed, and recovering it is the challenge.
"""
from __future__ import annotations

import base64
import hashlib
import json
import zlib

from .identity import challenge_flag


def _spec(*, slug, title, category, challenge_type, story, vulnerability, solution,
          artifacts, solver, flag, seed, generation, attack_class, rank,
          difficulty="medium", extra_files=None):
    from .models import ChainStep, ChallengeSpec, Lineage, OfficialSolver
    expected = hashlib.sha256(flag.encode()).hexdigest()
    files = {"solver.py": solver, **(extra_files or {})}
    return ChallengeSpec(
        slug=slug, title=f"{title} (Gen-{generation})", category=category,
        challenge_type=challenge_type, difficulty=difficulty, story=story,
        vulnerability=vulnerability, intended_solution=solution, hints=[],
        delivery="crypto", seed=seed,
        mechanics={"attack_class": attack_class, "rank": rank},
        flag=flag, spec_id=slug,
        lineage=Lineage(archetype_id=f"variety.{attack_class}", generation=generation,
                        parent_spec_id=None, mutation_ops=[], seed=seed),
        vuln_chain=[ChainStep(step=1, primitive=attack_class, params={}, guard=category)],
        artifacts=artifacts,
        official_solver=OfficialSolver(entry="solver.py", files=files,
                                       expected_flag_sha256=expected, max_runtime_s=60),
        target_solve_rate=0.1)


def _rng(kind, seed, generation, flag_secret):
    import random
    return random.Random(f"variety:{kind}:{flag_secret}:{seed}:{generation}")


# ---------------------------------------------------------------------------
# misc — a stack of reversible encodings, no key
# ---------------------------------------------------------------------------
_LAYERED_SOLVER = '''\
"""Peel the encoding stack. It was, from the flag outward:
   zlib compress -> base85 -> reverse the bytes -> hex. Undo it in reverse."""
import base64, binascii, zlib

with open("payload.txt", encoding="utf-8") as fh:
    blob = fh.read().strip()
step = binascii.unhexlify(blob)      # undo hex
step = step[::-1]                    # undo the byte reversal
step = base64.b85decode(step)        # undo base85
flag = zlib.decompress(step).decode()
assert flag.startswith("flag{"), "did not land on a flag"
print(flag)
'''


def gen_layered(seed, generation, **kw):
    secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="layered", seed=seed, generation=generation, secret=secret)
    packed = zlib.compress(flag.encode())
    blob = base64.b85encode(packed)[::-1].hex()
    artifacts = {
        "payload.txt": blob + "\n",
        "README.md": ("# Recovered payload\n\n"
                      "This blob came off the wire wrapped in several reversible "
                      "encodings — no key, just layers. Peel them.\n"),
    }
    return _spec(
        slug=f"var-layered-g{generation}-" +
             hashlib.sha256(f"layered:{secret}:{seed}:{generation}".encode()).hexdigest()[:8],
        title="Recovered Payload", category="misc", challenge_type="encoding-stack",
        story="A blob came off the wire wrapped in several reversible encodings.",
        vulnerability="a stack of reversible encodings (hex/base85/zlib) — no key",
        solution=["identify each layer from its alphabet/structure",
                  "undo hex, reverse the bytes, base85-decode, zlib-decompress"],
        artifacts=artifacts, solver=_LAYERED_SOLVER, flag=flag, seed=seed,
        generation=generation, attack_class="encoding-stack", rank=2, difficulty="easy")


# ---------------------------------------------------------------------------
# crypto — keystream reuse (two-time pad with one known sample)
# ---------------------------------------------------------------------------
_KEYSTREAM_SOLVER = '''\
"""Two messages were XORed with the SAME keystream. One is given in the clear, so
the keystream is sample_pt XOR sample_ct, and that decrypts the other."""

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

sample_pt = open("sample.txt", "rb").read()
sample_ct = bytes.fromhex(open("sample.enc", encoding="utf-8").read().strip())
flag_ct = bytes.fromhex(open("flag.enc", encoding="utf-8").read().strip())
keystream = xor(sample_pt, sample_ct)
flag = xor(flag_ct, keystream).decode()
assert flag.startswith("flag{"), "recovered plaintext is not a flag"
print(flag)
'''


def gen_keystream(seed, generation, **kw):
    secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="keystream", seed=seed, generation=generation, secret=secret)
    rng = _rng("keystream", seed, generation, secret)
    sample_pt = (f"MISSION LOG {seed:04d}: telemetry nominal, all subsystems green, "
                 f"cycle {generation}.").encode()
    length = max(len(sample_pt), len(flag))
    keystream = bytes(rng.getrandbits(8) for _ in range(length))
    xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
    artifacts = {
        "sample.txt": sample_pt.decode(),               # known plaintext, in the clear
        "sample.enc": xor(sample_pt, keystream).hex() + "\n",
        "flag.enc": xor(flag.encode(), keystream).hex() + "\n",
        "README.md": ("# Intercept\n\n"
                      "Two records were encrypted with the same device in the same "
                      "session. One is an operations log we already have in the clear "
                      "(`sample.txt`); the other hides the recovery flag. Only the "
                      "ciphertexts (`*.enc`) left the device.\n"),
    }
    return _spec(
        slug=f"var-keystream-g{generation}-" +
             hashlib.sha256(f"keystream:{secret}:{seed}:{generation}".encode()).hexdigest()[:8],
        title="Session Intercept", category="crypto", challenge_type="keystream-reuse",
        story="Two records were encrypted under the same keystream; one plaintext is known.",
        vulnerability="keystream/two-time-pad reuse (known-plaintext recovers the keystream)",
        solution=["XOR the known sample plaintext with its ciphertext to get the keystream",
                  "XOR the flag ciphertext with that keystream"],
        artifacts=artifacts, solver=_KEYSTREAM_SOLVER, flag=flag, seed=seed,
        generation=generation, attack_class="keystream-reuse", rank=4)


# ---------------------------------------------------------------------------
# web — forge past a JWT signed with a weak HS256 secret
# ---------------------------------------------------------------------------
_JWT_WORDS = [
    "letmein", "password", "secret", "changeme", "admin123", "qwerty123",
    "s3cr3t", "hunter2", "iloveyou", "trustno1", "welcome1", "dragon",
    "sunshine", "monkey123", "shadow", "superman", "batman", "flagship",
    "master", "access", "ninja", "football", "baseball", "jwt-signing-key",
]
_JWT_SOLVER = '''\
"""The service accepts an HS256 JWT and trusts `admin:true`. The signing secret is
weak — it is one of the entries in wordlist.txt. Find it (verify the signature of
the given token), then the flag is sealed under that secret."""
import base64, hashlib, hmac

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

token = open("token.txt", encoding="utf-8").read().strip()
header_b64, payload_b64, sig_b64 = token.split(".")
signing_input = f"{header_b64}.{payload_b64}".encode()
secret = None
for word in open("wordlist.txt", encoding="utf-8").read().split():
    mac = b64u(hmac.new(word.encode(), signing_input, hashlib.sha256).digest())
    if hmac.compare_digest(mac, sig_b64):
        secret = word
        break
assert secret, "no candidate secret verified the token"

MAGIC = b"AUTOCTF-JWT\\x00"
def keystream(s, n):
    out = bytearray(); c = 0
    while len(out) < n:
        out += hashlib.sha256(s.encode() + b"|" + str(c).encode()).digest(); c += 1
    return bytes(out[:n])
raw = bytes.fromhex(open("flag.enc", encoding="utf-8").read().strip())
plain = bytes(a ^ b for a, b in zip(raw, keystream(secret, len(raw))))
assert plain.startswith(MAGIC), "wrong secret"
print(plain[len(MAGIC):].decode())
'''


def gen_jwt(seed, generation, **kw):
    import hmac
    secret_key = kw.get("flag_secret", "")
    flag = challenge_flag(kind="jwt", seed=seed, generation=generation, secret=secret_key)
    rng = _rng("jwt", seed, generation, secret_key)
    weak = _JWT_WORDS[rng.randrange(len(_JWT_WORDS))]

    def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    header = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64u(json.dumps({"user": "guest", "admin": False, "sid": seed}).encode())
    sig = b64u(hmac.new(weak.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    token = f"{header}.{payload}.{sig}"

    # seal the flag under the weak secret so the literal flag is not in any file
    magic = b"AUTOCTF-JWT\x00"

    def keystream(s, n):
        out = bytearray(); c = 0
        while len(out) < n:
            out += hashlib.sha256(s.encode() + b"|" + str(c).encode()).digest(); c += 1
        return bytes(out[:n])
    sealed = bytes(a ^ b for a, b in
                   zip(magic + flag.encode(), keystream(weak, len(magic) + len(flag)))).hex()

    words = list(_JWT_WORDS)
    rng.shuffle(words)
    artifacts = {
        "token.txt": token + "\n",
        "wordlist.txt": "\n".join(words) + "\n",
        "flag.enc": sealed + "\n",
        "README.md": ("# Session token\n\n"
                      "A web app issues this HS256 JWT and trusts the `admin` claim. "
                      "The signing secret was picked from a small list of common "
                      "passwords (`wordlist.txt`). The operator's recovery blob is "
                      "sealed under that secret.\n"),
    }
    return _spec(
        slug=f"var-jwt-g{generation}-" +
             hashlib.sha256(f"jwt:{secret_key}:{seed}:{generation}".encode()).hexdigest()[:8],
        title="Session Token", category="web", challenge_type="jwt-weak-secret",
        story="A web app signs its session JWTs with a weak HS256 secret.",
        vulnerability="HS256 JWT signed with a guessable secret (offline dictionary attack)",
        solution=["brute the wordlist against the token's signature",
                  "the verifying secret unseals the recovery blob"],
        artifacts=artifacts, solver=_JWT_SOLVER, flag=flag, seed=seed,
        generation=generation, attack_class="jwt-weak-secret", rank=5)


# ---------------------------------------------------------------------------
# forensics — a payload carved out of a binary blob
# ---------------------------------------------------------------------------
_CARVE_SOLVER = '''\
"""dump.b64 is a base64-wrapped raw dump. Decode it, find the odd magic marker,
read the 4-byte big-endian length that follows, and un-zlib that many bytes."""
import base64, struct, zlib

data = base64.b64decode(open("dump.b64", encoding="utf-8").read())
MARKER = b"\\x89PWN\\r\\n\\x1a\\n"          # a deliberately odd magic to grep for
i = data.rindex(MARKER) + len(MARKER)
(length,) = struct.unpack(">I", data[i:i + 4])
chunk = data[i + 4:i + 4 + length]
flag = zlib.decompress(chunk).decode()
assert flag.startswith("flag{"), "carved data is not a flag"
print(flag)
'''


def gen_carve(seed, generation, **kw):
    import struct
    secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="carve", seed=seed, generation=generation, secret=secret)
    rng = _rng("carve", seed, generation, secret)
    # a plausible-looking binary dump: random pages, then a marked, length-prefixed
    # zlib record buried inside, then more noise.
    noise1 = bytes(rng.getrandbits(8) for _ in range(rng.randint(600, 1200)))
    noise2 = bytes(rng.getrandbits(8) for _ in range(rng.randint(600, 1200)))
    packed = zlib.compress(flag.encode())
    marker = b"\x89PWN\r\n\x1a\n"
    record = marker + struct.pack(">I", len(packed)) + packed
    dump = noise1 + record + noise2
    artifacts = {
        "dump.b64": base64.b64encode(dump).decode() + "\n",
        "README.md": ("# Memory dump\n\n"
                      "A crash handler wrote this raw dump (base64-wrapped as "
                      "`dump.b64`). Somewhere in the noise a structured record was "
                      "flushed — find it and recover what it held.\n"),
    }
    return _spec(
        slug=f"var-carve-g{generation}-" +
             hashlib.sha256(f"carve:{secret}:{seed}:{generation}".encode()).hexdigest()[:8],
        title="Memory Dump", category="forensics", challenge_type="carve-hidden-record",
        story="A crash dump hides a structured, compressed record inside random noise.",
        vulnerability="a length-prefixed zlib record hidden behind a magic marker",
        solution=["scan the dump for the unusual magic marker",
                  "read the 4-byte big-endian length, then zlib-decompress that many bytes"],
        artifacts=artifacts, solver=_CARVE_SOLVER, flag=flag, seed=seed,
        generation=generation, attack_class="carve-hidden-record", rank=3, difficulty="easy")


# ---------------------------------------------------------------------------
# reverse — invert an obfuscated keygen
# ---------------------------------------------------------------------------
_KEYGEN_CHECKER = '''\
"""validate.py — the vendor's serial checker (obfuscated).

    python3 validate.py <serial>

It rejects everything but the one correct serial. Recovering that serial IS the
flag. The transform is a fixed, invertible per-byte pipeline; work out the inverse.
"""
import sys

ROT = 0x5A
MUL = 0x1D            # odd, so invertible mod 256


def transform(data):
    out = bytearray()
    prev = 0x7F
    for i, b in enumerate(data):
        x = ((b * MUL) & 0xFF) ^ (ROT + i & 0xFF) ^ prev
        out.append(x & 0xFF)
        prev = b
    return bytes(out)


TARGET = __TARGET__

if __name__ == "__main__":
    serial = sys.argv[1].encode()
    print("CORRECT" if transform(serial) == TARGET else "WRONG")
'''

_KEYGEN_SOLVER = '''\
"""Invert validate.py's per-byte pipeline. Each output byte is
   x_i = ((b_i * MUL) & 0xFF) ^ ((ROT + i) & 0xFF) ^ b_{i-1},
with b_{-1} = 0x7F. MUL is odd so it has an inverse mod 256; and b_{i-1} is known
by the time we decode byte i, so decode left to right."""

ROT = 0x5A
MUL = 0x1D
MUL_INV = pow(MUL, -1, 256)

target = bytes.fromhex(open("target.txt", encoding="utf-8").read().strip())
out = bytearray()
prev = 0x7F
for i, x in enumerate(target):
    b = ((x ^ ((ROT + i) & 0xFF) ^ prev) * MUL_INV) & 0xFF
    out.append(b)
    prev = b
flag = out.decode()
assert flag.startswith("flag{"), "inversion did not land on a flag"
print(flag)
'''


def gen_keygen(seed, generation, **kw):
    secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="keygen", seed=seed, generation=generation, secret=secret)
    ROT, MUL = 0x5A, 0x1D

    def transform(data):
        out = bytearray()
        prev = 0x7F
        for i, b in enumerate(data):
            out.append((((b * MUL) & 0xFF) ^ ((ROT + i) & 0xFF) ^ prev) & 0xFF)
            prev = b
        return bytes(out)

    target = transform(flag.encode())
    checker = _KEYGEN_CHECKER.replace("__TARGET__", repr(target))
    artifacts = {
        "validate.py": checker,
        "target.txt": target.hex() + "\n",
        "README.md": ("# Serial check\n\n"
                      "`validate.py` accepts exactly one serial and prints CORRECT. "
                      "The accepted serial is the flag. `target.txt` is the value the "
                      "checker compares against. Invert the transform.\n"),
    }
    return _spec(
        slug=f"var-keygen-g{generation}-" +
             hashlib.sha256(f"keygen:{secret}:{seed}:{generation}".encode()).hexdigest()[:8],
        title="Serial Check", category="reverse", challenge_type="invertible-keygen",
        story="A vendor serial checker accepts exactly one serial; recover it.",
        vulnerability="a fixed, invertible per-byte transform (multiply/xor/chain) in the checker",
        solution=["read validate.py's per-byte transform",
                  "invert it: multiply by the inverse of MUL mod 256, undo the position and chain xors"],
        artifacts=artifacts, solver=_KEYGEN_SOLVER, flag=flag, seed=seed,
        generation=generation, attack_class="invertible-keygen", rank=6, difficulty="hard")


ALL_VARIETY = [gen_layered, gen_keystream, gen_jwt, gen_carve, gen_keygen]
