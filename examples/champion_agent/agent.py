#!/usr/bin/env python3
"""Champion agent — clears the RSA ladder through Boneh-Durfee (Gen-0..6).

This is the worked answer to the starter agent's limitation. The starter has no
lattice attack, so the challenge-maker out-evolves it at Gen-6. This one ships
`lattice.py` alongside it in the zip and adds a Boneh-Durfee stage, which takes
it to the last RSA rung.

It deliberately STOPS there. Gen-7 and up (singular, gcmreuse, noncebias) are the
detection rungs: each hands over a correct-looking implementation and ordinary
data, and the whole challenge is noticing what is wrong — a zero discriminant, a
thrice-used GCM nonce, a 16-bit nonce bias. An agent like this one, which
dispatches on the *shape* of the artifacts (`n.txt`+`e.txt` -> try Wiener,
`e == 3` -> try cube root), has nothing to match on there: the files look like a
well-formed curve, a clean archive, a valid ledger. Beating those rungs needs an
agent that computes an invariant and reacts to it, not one with a bigger table of
named attacks. That gap is the point of the upper ladder — leaving this agent
unable to climb it is the demonstration, not a bug to fix.

Package it the way the arena expects:

    cd examples/champion_agent && zip -r ../champion.zip agent.py lattice.py

then upload champion.zip on the "Enter your agent" page. The point is the shape,
not the specific attacks: an agent is just code plus whatever it brings with it.
"""
from __future__ import annotations

import math
from functools import reduce


def _iroot(x: int, k: int) -> int:
    """Integer k-th root by binary search."""
    if x < 0:
        return 0
    hi = 1
    while hi ** k <= x:
        hi <<= 1
    lo = hi >> 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _to_flag(m: int) -> str | None:
    try:
        text = m.to_bytes((m.bit_length() + 7) // 8, "big").decode()
    except Exception:
        return None
    return text if text.startswith("flag{") else None


def _egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def _wiener(e: int, n: int):
    """Continued-fraction attack: recovers a small private exponent d."""
    cf, a, b = [], e, n
    while b:
        cf.append(a // b)
        a, b = b, a % b
    for i in range(len(cf)):
        num, den = 1, 0
        for x in reversed(cf[: i + 1]):
            num, den = x * num + den, num
        k, d = num, den
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        bb = n - phi + 1
        disc = bb * bb - 4 * n
        if disc >= 0:
            root = math.isqrt(disc)
            if root * root == disc:
                return d
    return None


def _fermat(n: int, cap: int = 1 << 20):
    """Factor n when its primes sit close together."""
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(cap):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b
        a += 1
    return None


def _pollard_p_minus_1(n: int, bound: int = 4000):
    """Factor n when p-1 is smooth."""
    a = 2
    for j in range(2, bound):
        a = pow(a, j, n)
        d = math.gcd(a - 1, n)
        if 1 < d < n:
            return d
    return None


def _from_factor(p: int, n: int, e: int, c: int):
    q = n // p
    try:
        d = pow(e, -1, (p - 1) * (q - 1))
    except Exception:
        return None
    return _to_flag(pow(c, d, n))


def _classic(files: dict) -> str | None:
    """The six classical rungs: small-e, Håstad, common modulus, Wiener,
    Fermat, Pollard p-1."""
    def num(name: str) -> int:
        return int(files[name].strip())

    names = set(files)

    # Håstad broadcast: one message, e=3, three moduli -> CRT then cube root.
    if {"n0.txt", "n1.txt", "n2.txt", "c0.txt", "c1.txt", "c2.txt"} <= names:
        ns = [num(f"n{i}.txt") for i in range(3)]
        cs = [num(f"c{i}.txt") for i in range(3)]
        modulus = reduce(lambda x, y: x * y, ns)
        x = sum(r * (modulus // m) * pow(modulus // m, -1, m)
                for r, m in zip(cs, ns)) % modulus
        return _to_flag(_iroot(x, 3))

    # Common modulus: same n, coprime exponents -> Bézout combination.
    if {"n.txt", "e1.txt", "e2.txt", "c1.txt", "c2.txt"} <= names:
        n, e1, e2 = num("n.txt"), num("e1.txt"), num("e2.txt")
        c1, c2 = num("c1.txt"), num("c2.txt")
        _, a, b = _egcd(e1, e2)
        if a < 0:
            c1, a = pow(c1, -1, n), -a
        if b < 0:
            c2, b = pow(c2, -1, n), -b
        return _to_flag(pow(c1, a, n) * pow(c2, b, n) % n)

    # Single (n, e, c): try each attack in the kit.
    if {"n.txt", "e.txt", "c.txt"} <= names:
        n, e, c = num("n.txt"), num("e.txt"), num("c.txt")

        if e <= 5:                                   # unpadded, m^e < n
            m = _iroot(c, e)
            if m ** e == c and (flag := _to_flag(m)):
                return flag

        if (d := _wiener(e, n)) and (flag := _to_flag(pow(c, d, n))):
            return flag

        if (p := _fermat(n)) and n % p == 0 and (flag := _from_factor(p, n, e, c)):
            return flag

        if (p := _pollard_p_minus_1(n)) and n % p == 0 and (flag := _from_factor(p, n, e, c)):
            return flag

    return None


def _boneh_durfee(files: dict) -> str | None:
    """The rung the starter agent cannot reach: d small, but past Wiener's bound.

    lattice.py rides along in the zip — uploaded agents get no network and cannot
    import this repository, so everything an agent needs travels with it.
    """
    if not {"n.txt", "e.txt", "c.txt"} <= set(files):
        return None
    try:
        from lattice import boneh_durfee
    except ImportError:
        return None                      # zip lattice.py next to agent.py

    n = int(files["n.txt"].strip())
    e = int(files["e.txt"].strip())
    c = int(files["c.txt"].strip())
    try:
        factors = boneh_durfee(n, e, delta=0.28, mm=5)
    except NotImplementedError:
        return None                      # no fpylll on this host
    if not factors:
        return None
    p, q = factors
    try:
        d = pow(e, -1, (p - 1) * (q - 1))
    except ValueError:
        return None
    return _to_flag(pow(c, d, n))


def solve(files: dict, meta: dict | None = None) -> str | None:
    print(f"champion: {len(files)} files at gen {(meta or {}).get('gen', '?')}")
    if flag := _classic(files):
        return flag
    print("classic toolkit exhausted — building the Boneh-Durfee lattice")
    return _boneh_durfee(files)
