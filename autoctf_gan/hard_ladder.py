"""The crypto ladder's upper rungs — where FINDING the bug is the hard part.

Rungs 0-6 in `crypto_ladder` are hard to *exploit* and easy to *diagnose*: the
artifact is three integers, the README all but names the attack, and an agent
that recognises "e = 3, no padding" has already won. That is a fine difficulty
curve for the first half of a match and a useless one for the top of a
leaderboard, because every strong agent recognises those instantly.

These three rungs move the difficulty into detection. Each one hands over a
complete, correct-looking implementation and a pile of ordinary-looking data:

  rank 7  singular    a vendor's in-house curve. Every published parameter is
                      well-formed and the shipped point arithmetic is right. The
                      discriminant is zero, so the "curve" is a singular cubic
                      whose smooth points are F_p^* wearing a costume, and its
                      p-1 is smooth. Nothing says so; you compute 4a^3 + 27b^2.

  rank 8  gcmreuse    a vault's AES-GCM archive. 128 records, correct tags,
                      no key material. One nonce appears three times, which
                      turns the tags into polynomial evaluations sharing an
                      unknown, and the GHASH subkey falls out of a gcd. Finding
                      it means noticing three collisions in 128 twelve-byte
                      nonces.

  rank 9  noncebias   an ECDSA ledger on secp256k1. Every signature verifies
                      against the published key, the curve is standard, the
                      hashes are honest. The nonces are 16 bits short — which is
                      invisible, because nonces are the one thing a signature
                      does not reveal. You have to hypothesise the bias and
                      confirm it with a lattice.

The rungs stay honest by the same rule as every other one: `verify_spec` runs the
paired PoC and rejects the spec unless it recovers the exact flag, so a
generator that "fixes" the weakness breaks its own challenge (P1).

Difficulty here still grows by STRUCTURE, never entropy (P3): every modulus,
field and curve is a standard size, and what changes is what you must notice.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import random

from Crypto.Cipher import AES
from Crypto.Util.number import isPrime

from . import curves, gf128
from .identity import challenge_flag

# Only these three rungs need it, and they need it identically: a recovered
# secret is stretched into a keystream and XORed over a magic-prefixed record.
# The magic is what lets a solver tell a right key from a wrong one when an
# attack returns several candidates, which both the GCM and the lattice rung do.
SEAL_MAGIC = b"AUTOCTF-VAULT\x00"

_SEAL_TOOL = '''\
"""Offline unsealer for a sealed record.

    python3 sealed.py <secret>

The vault seals a record by stretching the operator secret into a keystream and
XORing it over the plaintext, which is prefixed with a magic marker so a wrong
secret is obvious rather than silently producing garbage. The secret itself is
never stored here; it lives only in the device that produced the archive.
"""
import hashlib
import sys

MAGIC = b"AUTOCTF-VAULT\\x00"


def keystream(secret, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(secret.encode() + b"|" + str(counter).encode()).digest()
        counter += 1
    return bytes(out[:length])


def unseal(blob_hex, secret):
    raw = bytes.fromhex(blob_hex.strip())
    plain = bytes(a ^ b for a, b in zip(raw, keystream(secret, len(raw))))
    if not plain.startswith(MAGIC):
        raise ValueError("wrong secret")
    return plain[len(MAGIC):].decode()


if __name__ == "__main__":
    with open("flag.enc", encoding="utf-8") as fh:
        print(unseal(fh.read(), sys.argv[1]))
'''


def _keystream(secret: str, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(secret.encode() + b"|" + str(counter).encode()).digest()
        counter += 1
    return bytes(out[:length])


def _seal(secret: str, flag: str) -> str:
    plain = SEAL_MAGIC + flag.encode()
    return bytes(a ^ b for a, b in zip(plain, _keystream(secret, len(plain)))).hex()


def _shipped(*modules) -> dict[str, str]:
    """Ship a repo module into the solver bundle under its own name."""
    return {f"{m.__name__.rsplit('.', 1)[-1]}.py": inspect.getsource(m) for m in modules}


# ---------------------------------------------------------------------------
# rank 7 — a singular "elliptic" curve (the discriminant is zero)
# ---------------------------------------------------------------------------
_CURVE_TOOL = '''\
"""Reference arithmetic for the CX-7 parameter set, as shipped by the vendor.

These are the standard short-Weierstrass affine formulas for y^2 = x^3 + ax + b
over F_p. They are not the interesting part of this archive — they are correct,
and they are here so you do not have to guess how the device multiplies.
"""
import json


def load():
    with open("params.json", encoding="utf-8") as fh:
        return json.load(fh)


def add(p1, p2, a, p):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if p1 == p2:
        slope = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (slope * slope - x1 - x2) % p
    return (x3, (slope * (x1 - x3) - y1) % p)


def mul(k, point, a, p):
    result, addend = None, point
    while k:
        if k & 1:
            result = add(result, addend, a, p)
        addend = add(addend, addend, a, p)
        k >>= 1
    return result
'''

_SINGULAR_SOLVER = '''\
"""Recover the CX-7 signing scalar.

The published parameters describe a curve that is not one: 4a^3 + 27b^2 vanishes
mod p, so the cubic has a double root and the "curve" is singular. Its smooth
points are not an elliptic curve group at all — for a split node they are F_p^*,
and the vendor's own scalar multiplication is exponentiation in disguise. p-1 is
smooth, so the discrete log that was supposed to be 128-bit hard is Pohlig-
Hellman on factors below 2^17.
"""
import json

from curves import discriminant, is_on_curve, pohlig_hellman, to_multiplicative
from sealed import unseal

with open("params.json", encoding="utf-8") as fh:
    params = json.load(fh)
p, a, b = params["p"], params["a"], params["b"]
G, Q = tuple(params["G"]), tuple(params["Q"])

assert is_on_curve(G, a, b, p) and is_on_curve(Q, a, b, p), "points are off the curve"
assert discriminant(a, b, p) == 0, "the curve is non-singular; this attack does not apply"

g = to_multiplicative(G, a, b, p)
h = to_multiplicative(Q, a, b, p)
d = pohlig_hellman(g, h, p)

with open("flag.enc", encoding="utf-8") as fh:
    flag = unseal(fh.read(), str(d))
assert flag.startswith("flag{"), "recovered plaintext is not a flag"
print(flag)
'''


def _smooth_prime_3mod4(rng: random.Random, bits: int, bound: int) -> int:
    """A prime p = 3 (mod 4) whose p-1 factors entirely below `bound`.

    Starting the product at 2 and multiplying only odd primes keeps p-1 exactly
    twice an odd number, so p = 3 (mod 4) for free — which is what makes the
    square root in `curves.node_slope` a single exponentiation.
    """
    small = [i for i in range(3, bound) if isPrime(i)]
    while True:
        product = 2
        while product.bit_length() < bits - 1:
            product *= rng.choice(small)
        candidate = product + 1
        if candidate.bit_length() == bits and isPrime(candidate):
            return candidate


def gen_singular(seed, generation, **kw):
    rng = random.Random(f"singular:{seed}:{generation}")
    flag = challenge_flag(kind="singular", seed=seed, generation=generation,
                          secret=kw.get("flag_secret", ""))
    p = _smooth_prime_3mod4(rng, 256, 1 << 17)

    # A cubic with a double root at alpha and no x^2 term forces the third root
    # to -2·alpha, which fixes a = -3·alpha^2 and b = 2·alpha^3 and makes
    # 4a^3 + 27b^2 vanish identically. Requiring 3·alpha to be a square keeps the
    # node split, so the smooth points are F_p^* and not a quadratic twist of it.
    while True:
        alpha = rng.randrange(1, p)
        if pow(3 * alpha % p, (p - 1) // 2, p) == 1:
            break
    a = (-3 * alpha * alpha) % p
    b = 2 * pow(alpha, 3, p) % p

    def random_point():
        while True:
            x = rng.randrange(1, p)
            if x == alpha:
                continue
            rhs = (x * x % p * x + a * x + b) % p
            if rhs == 0 or pow(rhs, (p - 1) // 2, p) != 1:
                continue
            return (x, pow(rhs, (p + 1) // 4, p))

    # Pick a base point that generates all of F_p^*: then the recovered scalar is
    # unique rather than defined only modulo a smaller order, and the sealed flag
    # has exactly one key.
    factors = curves.factorize(p - 1)
    while True:
        G = random_point()
        g = curves.to_multiplicative(G, a, b, p)
        if curves.element_order(g, p, p - 1, factors) == p - 1:
            break
    d = rng.randrange(1 << 200, p - 1)
    Q = curves.mul(d, G, a, p)

    art = {
        "params.json": json.dumps({"name": "CX-7", "p": p, "a": a, "b": b,
                                   "G": list(G), "Q": list(Q)}, indent=2) + "\n",
        "curve.py": _CURVE_TOOL,
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(str(d), flag),
        "README.md": (
            "# CX-7 key archive\n\n"
            "A signing module ships with its own domain parameters rather than a "
            "named curve. The private scalar never leaves the module; `Q = d·G` and "
            "the parameter set are public, and the recovery blob is sealed under the "
            "scalar in decimal.\n\n"
            "`curve.py` is the vendor's own arithmetic. `sealed.py` opens the blob "
            "once you have the scalar.\n"),
    }
    return _rung_spec(
        rank=7, challenge_type="ecc-singular", attack_class="singular",
        family="ECC", title_override="CX-7 Domain Parameters",
        story=("A hardware vendor generated its own 256-bit curve instead of using a "
               "named one. The parameters, the base point and the public point are all "
               "published; the scalar is not."),
        vuln="singular cubic (zero discriminant): the group is F_p^* and p-1 is smooth",
        solution=["compute 4a^3 + 27b^2 mod p and find it zero",
                  "locate the node and map the smooth points onto F_p^*",
                  "Pohlig-Hellman the resulting discrete log"],
        hints=["Every published parameter is well-formed and `curve.py` is correct.",
               "Nothing here is a named curve, and nobody checked what was generated."],
        artifacts=art, solver_src=_SINGULAR_SOLVER, flag=flag,
        seed=seed, generation=generation, max_runtime_s=120,
        extra_solver_files={**_shipped(curves), "sealed.py": _SEAL_TOOL}, **kw)


# ---------------------------------------------------------------------------
# rank 8 — AES-GCM nonce reuse (the forbidden attack)
# ---------------------------------------------------------------------------
_GCM_TOOL = '''\
"""How the archive was written, reconstructed from the vault's own source.

    record = AES-GCM(key, nonce) over the payload, no associated data
    flag.enc = seal(GHASH subkey H, flag)

The GHASH subkey is E_K(0^128) — the vault derives its recovery secret from it so
that a leaked archive key does not also unseal the recovery blob. H is written as
the lowercase hex of its 16-byte block.
"""
'''

_GCM_SOLVER = '''\
"""Recover the vault's GHASH subkey from a repeated GCM nonce.

A GCM tag is GHASH_H(A, C) + E_K(J0), and J0 depends only on the nonce. Two
records written under the SAME nonce therefore share E_K(J0) exactly, so adding
their tags cancels the one term nobody can compute and leaves a polynomial in H
whose coefficients are all known ciphertext differences. Its roots are the
candidate subkeys; two independent pairs pin down a single one by gcd.

Finding the reuse is the work: 128 records, twelve-byte nonces, no other signal.
"""
import json
from collections import defaultdict

from gf128 import block_to_element, element_to_block, padd, pgcd, roots
from sealed import unseal

with open("records.json", encoding="utf-8") as fh:
    records = json.load(fh)

groups = defaultdict(list)
for record in records:
    groups[record["nonce"]].append(record)
reused = [rs for rs in groups.values() if len(rs) >= 2]
assert reused, "no nonce is used twice; the forbidden attack does not apply"
family = max(reused, key=len)


def error_poly(left, right):
    """Coefficients of GHASH(left) + GHASH(right) as a polynomial in H."""
    ct_l, ct_r = bytes.fromhex(left["ct"]), bytes.fromhex(right["ct"])
    assert len(ct_l) == len(ct_r), "equal lengths keep the length block from surviving"
    blocks = [bytes(a ^ b for a, b in zip(ct_l[i:i + 16], ct_r[i:i + 16]))
              for i in range(0, len(ct_l), 16)]
    tag_delta = bytes(a ^ b for a, b in
                      zip(bytes.fromhex(left["tag"]), bytes.fromhex(right["tag"])))
    # GHASH = C_1·H^(m+1) + ... + C_m·H^2 + L·H, and L cancels for equal lengths.
    poly = [0] * (len(blocks) + 2)
    poly[0] = block_to_element(tag_delta)
    for i, block in enumerate(blocks):
        poly[len(blocks) + 1 - i] = block_to_element(block)
    return poly


base = error_poly(family[0], family[1])
candidate_poly = base
if len(family) >= 3:
    shared = pgcd(base, error_poly(family[0], family[2]))
    if len(shared) >= 2:
        candidate_poly = shared

with open("flag.enc", encoding="utf-8") as fh:
    blob = fh.read()

flag = None
for h in roots(candidate_poly):
    if h == 0:
        continue
    try:
        flag = unseal(blob, element_to_block(h).hex())
        break
    except ValueError:
        continue
assert flag and flag.startswith("flag{"), "no candidate subkey unsealed the blob"
print(flag)
'''


def gen_gcmreuse(seed, generation, **kw):
    rng = random.Random(f"gcmreuse:{seed}:{generation}")
    flag = challenge_flag(kind="gcmreuse", seed=seed, generation=generation,
                          secret=kw.get("flag_secret", ""))

    def rand_bytes(count):
        return bytes(rng.getrandbits(8) for _ in range(count))

    key = rand_bytes(16)
    subkey = AES.new(key, AES.MODE_ECB).encrypt(b"\x00" * 16)

    total = 128
    # Three records share a nonce, and they are scattered rather than adjacent:
    # spotting the reuse should mean counting nonces, not reading the file top to
    # bottom. Their payloads are equal-length random blobs, so the keystream
    # reuse those three share leaks nothing on its own — recovering the subkey is
    # the only way through.
    collide_at = sorted(rng.sample(range(total), 3))
    shared_nonce = rand_bytes(12)
    used = {shared_nonce}
    records = []
    for index in range(total):
        if index in collide_at:
            nonce, payload = shared_nonce, rand_bytes(48)
        else:
            while True:
                nonce = rand_bytes(12)
                if nonce not in used:
                    used.add(nonce)
                    break
            payload = rand_bytes(16 * rng.randint(1, 5))
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        records.append({"id": f"rec-{index:04d}", "nonce": nonce.hex(),
                        "ct": ciphertext.hex(), "tag": tag.hex()})

    art = {
        "records.json": json.dumps(records, indent=1) + "\n",
        "vault.md": _GCM_TOOL.strip('"\n'),
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(subkey.hex(), flag),
        "README.md": (
            "# Vault archive export\n\n"
            "Every record is AES-256-GCM with no associated data, exported straight "
            "from the vault. The archive key is not in here and is not recoverable.\n\n"
            "`flag.enc` is the vault's recovery blob. `vault.md` says what it is "
            "sealed under; `sealed.py` opens it once you have that.\n"),
    }
    return _rung_spec(
        rank=8, challenge_type="aes-gcm-nonce-reuse", attack_class="gcmreuse",
        family="AES-GCM", title_override="Vault Archive Export",
        story=("An encrypted vault exported 128 AES-GCM records. The tags are all "
               "correct and the archive key never left the device."),
        vuln="one GCM nonce reused across three records (forbidden attack recovers H)",
        solution=["group the records by nonce and find the repeat",
                  "subtract the tags to cancel E_K(J0), leaving a polynomial in H",
                  "gcd two error polynomials and read off the GHASH subkey"],
        hints=["The tags are genuine: nothing in this archive is forged.",
               "128 records were exported and the vault kept no key material."],
        artifacts=art, solver_src=_GCM_SOLVER, flag=flag,
        seed=seed, generation=generation, max_runtime_s=120,
        extra_solver_files={**_shipped(gf128), "sealed.py": _SEAL_TOOL}, **kw)


# ---------------------------------------------------------------------------
# rank 9 — biased ECDSA nonces (the hidden number problem)
# ---------------------------------------------------------------------------
NONCE_BIAS_BITS = 16          # how many high bits of every nonce are zero
NONCE_SIGNATURES = 24         # 24 x 16 = 384 leaked bits against a 256-bit key

_HNP_SOLVER = '''\
"""Recover an ECDSA private key from nonces that are a few bits short.

Every signature gives s·k = h + r·d (mod n). Write t = r/s and u = h/s and the
nonce is k = t·d + u (mod n) — a hidden-number instance. Nothing about (r, s)
reveals k, so the bias cannot be measured directly; the only way to confirm it is
to assume a bound, build the lattice, reduce, and check the recovered key against
the published point. Sweeping the bound costs one LLL each and settles it.
"""
import json

from curves import (SECP256K1_A, SECP256K1_G, SECP256K1_N, SECP256K1_P,
                    hnp_basis, hnp_candidates, mul)
from lattice import lll
from sealed import unseal

with open("signatures.json", encoding="utf-8") as fh:
    ledger = json.load(fh)
pub = tuple(ledger["pubkey"])
sigs = [(int(s["h"], 16), int(s["r"], 16), int(s["s"], 16)) for s in ledger["signatures"]]
n = SECP256K1_N

secret = None
for short_bits in range(4, 65):
    bound = 1 << (256 - short_bits)
    reduced = lll(hnp_basis(sigs, n, bound))
    for candidate in hnp_candidates(reduced, len(sigs), n, bound):
        if mul(candidate, SECP256K1_G, SECP256K1_A, SECP256K1_P) == pub:
            secret = candidate
            break
    if secret is not None:
        break

assert secret is not None, "no nonce bound produced the published key"
with open("flag.enc", encoding="utf-8") as fh:
    flag = unseal(fh.read(), str(secret))
assert flag.startswith("flag{"), "recovered plaintext is not a flag"
print(flag)
'''


def gen_noncebias(seed, generation, **kw):
    from . import lattice

    rng = random.Random(f"noncebias:{seed}:{generation}")
    flag = challenge_flag(kind="noncebias", seed=seed, generation=generation,
                          secret=kw.get("flag_secret", ""))
    n, p, a = curves.SECP256K1_N, curves.SECP256K1_P, curves.SECP256K1_A
    G = curves.SECP256K1_G
    bound = 1 << (256 - NONCE_BIAS_BITS)

    d = rng.randrange(1 << 250, n)
    pub = curves.mul(d, G, a, p)
    signatures = []
    for index in range(NONCE_SIGNATURES):
        digest = hashlib.sha256(f"ledger-entry-{seed}-{generation}-{index}".encode()).digest()
        h = int.from_bytes(digest, "big") % n
        while True:
            k = rng.randrange(1, bound)          # the bug: k is 16 bits short
            point = curves.mul(k, G, a, p)
            r = point[0] % n
            if r == 0:
                continue
            s = pow(k, -1, n) * (h + r * d) % n
            if s:
                break
        signatures.append({"entry": f"ledger-entry-{seed}-{generation}-{index}",
                           "h": f"{h:064x}", "r": f"{r:064x}", "s": f"{s:064x}"})

    art = {
        "signatures.json": json.dumps(
            {"curve": "secp256k1", "hash": "sha256", "pubkey": list(pub),
             "signatures": signatures}, indent=1) + "\n",
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(str(d), flag),
        "README.md": (
            "# Settlement ledger\n\n"
            "Twenty-four signed ledger entries on secp256k1, with the signer's public "
            "key so you can check them. Every signature verifies.\n\n"
            "The operator's recovery blob is sealed under the signing key in decimal; "
            "`sealed.py` opens it.\n"),
    }
    return _rung_spec(
        rank=9, challenge_type="ecdsa-nonce-bias", attack_class="noncebias",
        family="ECDSA", title_override="Settlement Ledger",
        story=("A settlement service published its signed ledger and its public key. "
               "The curve is standard, the hashing is standard, and every signature "
               "checks out."),
        vuln=f"ECDSA nonces {NONCE_BIAS_BITS} bits short (hidden number problem via LLL)",
        solution=["rewrite each signature as k = t·d + u (mod n)",
                  "assume the nonces are short and build the HNP lattice",
                  "LLL, then confirm the recovered key against the published point"],
        hints=["Every signature verifies against the published key; none is forged.",
               "The curve and the hash are both exactly what the file says they are."],
        artifacts=art, solver_src=_HNP_SOLVER, flag=flag,
        seed=seed, generation=generation, max_runtime_s=180,
        extra_solver_files={**_shipped(curves, lattice), "sealed.py": _SEAL_TOOL}, **kw)


def _rung_spec(**kwargs):
    """Defer to `crypto_ladder._spec`, which owns the ChallengeSpec shape.

    Imported at call time, not module scope: `crypto_ladder` appends these rungs
    to its own ladder at the bottom of its module body, so a top-level import
    here would close the cycle before either module finished loading.
    """
    from .crypto_ladder import _spec
    return _spec(**kwargs)


HARD_LADDER = [gen_singular, gen_gcmreuse, gen_noncebias]
HARD_LADDER_NAMES = ["singular", "gcmreuse", "noncebias"]

# `noncebias` is the only rung here that needs a lattice reduction library. The
# pure-Python LLL in lattice.py is exact but takes minutes past dimension eight,
# and this basis is dimension 26, so without fpylll the PoC would time out and
# verify_spec would reject the rung on every build. Dropping it up front is the
# same bargain crypto_ladder already makes for Boneh-Durfee: advertise only what
# this host can actually build.
LATTICE_RUNGS = {"noncebias"}
