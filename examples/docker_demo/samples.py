#!/usr/bin/env python3
"""Sample challenges, generated offline so the demo image needs no arena.

These are the same shapes the crypto ladder deploys — same filenames, same
artifacts — so an agent that solves these is solving the real rungs. Everything
here is stdlib: the demo image must run on a laptop with no network.

Nothing in this file is part of the agent. It is the *challenge* side, kept
separate on purpose so a competitor reading the image can see exactly which half
is theirs to write.
"""
from __future__ import annotations

import math
import random

FLAG = "flag{circle_memory_agent_demo}"


# ---------------------------------------------------------------------------
# small primality / prime generation, stdlib only
# ---------------------------------------------------------------------------
_SMALL = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in _SMALL:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in _SMALL:                       # deterministic enough for a demo
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int, rng: random.Random) -> int:
    while True:
        n = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(n):
            return n


def _next_prime(n: int) -> int:
    n |= 1
    while not _is_prime(n):
        n += 2
    return n


def _to_int(text: str) -> int:
    return int.from_bytes(text.encode(), "big")


# ---------------------------------------------------------------------------
# the rungs
# ---------------------------------------------------------------------------
def _small_exponent(rng: random.Random) -> dict:
    """e=3 and no padding, so the ciphertext is just m³ — take the cube root.

    n is 2048-bit so that m³ never wraps: the flag is ~30 bytes (240 bits) and
    240×3 = 720 bits has to stay below the modulus for the root to be exact.
    """
    p, q = _prime(1024, rng), _prime(1024, rng)
    n, e, m = p * q, 3, _to_int(FLAG)
    return {"n.txt": str(n), "e.txt": str(e), "c.txt": str(pow(m, e, n))}


def _hastad(rng: random.Random) -> dict:
    """The same message sent to three recipients under e=3 — CRT, then cube root."""
    files, m = {}, _to_int(FLAG)
    for i in range(3):
        n = _prime(512, rng) * _prime(512, rng)
        files[f"n{i}.txt"] = str(n)
        files[f"c{i}.txt"] = str(pow(m, 3, n))
    return files


def _common_modulus(rng: random.Random) -> dict:
    """One modulus, two coprime exponents — Bézout recovers m without factoring."""
    p, q = _prime(512, rng), _prime(512, rng)
    n, m = p * q, _to_int(FLAG)
    e1, e2 = 65537, 65539                  # gcd(e1, e2) == 1
    return {"n.txt": str(n), "e1.txt": str(e1), "e2.txt": str(e2),
            "c1.txt": str(pow(m, e1, n)), "c2.txt": str(pow(m, e2, n))}


def _wiener(rng: random.Random) -> dict:
    """d chosen small enough that a continued-fraction convergent of e/n finds it."""
    while True:
        p, q = _prime(512, rng), _prime(512, rng)
        if p == q:
            continue
        n, phi = p * q, (p - 1) * (q - 1)
        bound = math.isqrt(math.isqrt(n)) // 3      # d < n^0.25 / 3
        d = rng.randrange(bound // 2, bound) | 1
        while math.gcd(d, phi) != 1:
            d += 2
        if d >= bound:
            continue
        e = pow(d, -1, phi)
        return {"n.txt": str(n), "e.txt": str(e),
                "c.txt": str(pow(_to_int(FLAG), e, n))}


def _fermat(rng: random.Random) -> dict:
    """p and q generated too close together, so n factors from √n outwards."""
    p = _prime(512, rng)
    q = _next_prime(p + rng.randrange(2, 1 << 16))
    n, phi, e = p * q, (p - 1) * (q - 1), 65537
    return {"n.txt": str(n), "e.txt": str(e),
            "c.txt": str(pow(_to_int(FLAG), e, n))}


def _boneh_durfee(rng: random.Random) -> dict:
    """d too large for Wiener, small enough for a lattice.

    Wiener's continued-fraction attack needs d < n^0.25/3; Boneh-Durfee reaches
    about n^0.292. Sizing d at roughly n^0.27 lands it squarely between the two,
    so this rung separates an agent that ships a lattice library from one that
    does not — which is the whole argument for submitting an image.
    """
    while True:
        p, q = _prime(256, rng), _prime(256, rng)
        if p == q:
            continue
        n, phi = p * q, (p - 1) * (q - 1)

        # d must land in the gap between the two attacks, and the gap is narrow:
        #   Wiener  needs d < n^0.25 / 3   (≈ 126 bits here) — must NOT reach
        #   lattice.py is verified to n^0.255 (≈ 130 bits)   — must reach
        # 0.255 is that verified point, measured over 8 random instances at
        # 8/8 for the lattice agent and 0/8 for the stdlib one. Do not raise it:
        # Boneh-Durfee's theoretical 0.292 is not what this implementation
        # reaches at mm=4, and instances above ~0.26 start failing. Lower is
        # also wrong — Wiener's bound is sufficient, not necessary, so at 0.253
        # the stdlib agent occasionally got lucky and the contrast broke.
        #
        # Sizing d by *bit length* rather than n**0.25 also avoids the float
        # overflow that raising a 512-bit int to a fractional power causes.
        d_bits = int(n.bit_length() * 0.255)
        d = rng.getrandbits(d_bits) | (1 << (d_bits - 1)) | 1
        while math.gcd(d, phi) != 1:
            d += 2
        try:
            e = pow(d, -1, phi)
        except ValueError:
            continue
        if e.bit_length() < 0.9 * n.bit_length():
            continue                        # want e large, the small-d fingerprint
        return {"n.txt": str(n), "e.txt": str(e),
                "c.txt": str(pow(_to_int(FLAG), e, n))}


RUNGS = [
    ("smalle", "Gen-0", "Small public exponent", _small_exponent),
    ("hastad", "Gen-1", "Håstad broadcast", _hastad),
    ("commonmod", "Gen-2", "Common modulus", _common_modulus),
    ("wiener", "Gen-3", "Wiener (small d)", _wiener),
    ("fermat", "Gen-4", "Fermat (close primes)", _fermat),
    ("bonehdurfee", "Gen-5", "Boneh-Durfee (lattice)", _boneh_durfee),
]


def build(seed: int | None = None) -> list[dict]:
    """One challenge per rung, in the order the maker escalates them."""
    rng = random.Random(seed) if seed is not None else random.SystemRandom()
    out = []
    for key, gen, label, make in RUNGS:
        out.append({"challenge_id": f"demo-{key}", "gen": int(gen.split("-")[1]),
                    "category": "crypto", "title": label, "rung": key,
                    "story": f"A demo instance of the {label} rung.",
                    "hints": [], "files": make(rng)})
    return out


if __name__ == "__main__":
    for challenge in build(seed=1):
        print(f"{challenge['rung']:12} {sorted(challenge['files'])}")
