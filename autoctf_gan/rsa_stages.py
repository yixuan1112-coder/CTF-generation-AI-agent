"""Composable RSA attack stages — the primitive library the maker AUTHORS from.

`crypto_ladder` hardcodes one challenge per attack class: the flag goes in, one
attack comes out, and the ladder ends. To *compose* attacks the maker needs each
class reduced to a reusable pair — "encrypt an arbitrary message under a key with
weakness X" and "recover that message" — which is what this module is.

Both halves live in one file on purpose. `build_*` runs on the server to
manufacture a stage; `solve_*` is shipped verbatim into the official solver and
runs the real attack under `verify_spec`. If they were separate modules the
generator could drift from the attack that is supposed to verify it, and the
first sign would be a challenge deployed to a team that nobody can solve. Here
the code that made the key IS the code that breaks it.

Nothing here imports a third-party package, so a shipped solver runs on a bare
Python. That is also why primality is a local Miller-Rabin rather than
`Crypto.Util.number.isPrime` — the ladder can depend on pycryptodome because it
only ever runs server-side, but this module has to survive being copied into an
agent's sandbox.

Every stage encrypts a message of at most MAX_MESSAGE_BYTES. The binding
constraint is `smalle`: an unpadded cube must not wrap the modulus, so
m^3 < n with a 1024-bit n caps the message at 341 bits.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import dataclass
from typing import Callable

MAX_MESSAGE_BYTES = 42


# ---------------------------------------------------------------------------
# number theory (dependency-free; shipped into the solver)
# ---------------------------------------------------------------------------
_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
                 59, 61, 67, 71, 73, 79, 83, 89, 97]


def is_prime(n: int) -> bool:
    """Miller-Rabin over the first 25 primes as bases.

    Deterministic below 3.3e24 and an overwhelming probable-prime test above it
    — the same practical guarantee `isPrime` gives, without the dependency.
    """
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in _SMALL_PRIMES:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(rng: random.Random, bits: int) -> int:
    while True:
        cand = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(cand):
            return cand


def next_prime(x: int) -> int:
    x |= 1
    while not is_prime(x):
        x += 2
    return x


def smooth_prime(rng: random.Random, bits: int, bound: int) -> int:
    """A prime p where p-1 has only factors below `bound` — Pollard p-1 bait."""
    small = [i for i in range(2, bound) if is_prime(i)]
    while True:
        m = 1
        while m.bit_length() < bits - 1:
            m *= rng.choice(small)
        p = m + 1
        if p.bit_length() == bits and is_prime(p):
            return p


def iroot(x: int, k: int) -> int:
    """Integer k-th root by binary search (no float precision loss)."""
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


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def crt(residues: list[int], moduli: list[int]) -> int:
    total, product = 0, 1
    for m in moduli:
        product *= m
    for r, m in zip(residues, moduli):
        partial = product // m
        total += r * partial * pow(partial, -1, m)
    return total % product


def b2i(data: bytes) -> int:
    return int.from_bytes(data, "big")


def i2b(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


# ---------------------------------------------------------------------------
# the inter-stage envelope
# ---------------------------------------------------------------------------
def _keystream(key: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + b"|" + str(counter).encode()).digest()
        counter += 1
    return bytes(out[:length])


def wrap(files: dict[str, str], key: bytes) -> str:
    """Seal the next stage's files under a key only the previous attack yields.

    This is what makes a composition a single challenge rather than two
    challenges in one zip: stage N+1's key material does not exist in readable
    form until stage N is actually broken.
    """
    raw = json.dumps(files, sort_keys=True).encode()
    stream = _keystream(key, len(raw))
    return bytes(a ^ b for a, b in zip(raw, stream)).hex()


def unwrap(blob: str, key: bytes) -> dict[str, str]:
    raw = bytes.fromhex(blob.strip())
    stream = _keystream(key, len(raw))
    return json.loads(bytes(a ^ b for a, b in zip(raw, stream)).decode())


def materialize(files: dict[str, str]) -> None:
    """Write an unwrapped stage to the working directory so solve_* can read it."""
    for name, content in files.items():
        with open(name, "w", encoding="utf-8") as fh:
            fh.write(content)


def _read_int(name: str) -> int:
    with open(name, encoding="utf-8") as fh:
        return int(fh.read().strip())


# ---------------------------------------------------------------------------
# rank 0 — small public exponent, unpadded (direct e-th root)
# ---------------------------------------------------------------------------
def build_smalle(rng: random.Random, message: bytes, prefix: str) -> dict[str, str]:
    m, e = b2i(message), 3
    while True:
        p, q = gen_prime(rng, 512), gen_prime(rng, 512)
        if p == q or (p - 1) * (q - 1) % e == 0:
            continue
        n = p * q
        if m ** e < n:            # no reduction -> the cube root IS the message
            return {f"{prefix}n.txt": str(n), f"{prefix}e.txt": str(e),
                    f"{prefix}c.txt": str(pow(m, e, n))}


def solve_smalle(prefix: str = "") -> bytes:
    n = _read_int(f"{prefix}n.txt")
    e = _read_int(f"{prefix}e.txt")
    c = _read_int(f"{prefix}c.txt")
    m = iroot(c, e)
    if m ** e != c:
        raise ValueError("smalle: c is not a perfect power (message wrapped the modulus)")
    return i2b(m)


# ---------------------------------------------------------------------------
# rank 1 — Hastad broadcast (same message, e=3, three moduli)
# ---------------------------------------------------------------------------
def build_hastad(rng: random.Random, message: bytes, prefix: str) -> dict[str, str]:
    m, e = b2i(message), 3
    ns: list[int] = []
    cs: list[int] = []
    while len(ns) < e:
        p, q = gen_prime(rng, 512), gen_prime(rng, 512)
        if p == q or (p - 1) * (q - 1) % e == 0:
            continue
        n = p * q
        if m >= n or any(math.gcd(n, prev) != 1 for prev in ns):
            continue
        ns.append(n)
        cs.append(pow(m, e, n))
    files: dict[str, str] = {}
    for i in range(e):
        files[f"{prefix}n{i}.txt"] = str(ns[i])
        files[f"{prefix}c{i}.txt"] = str(cs[i])
    return files


def solve_hastad(prefix: str = "", count: int = 3) -> bytes:
    ns = [_read_int(f"{prefix}n{i}.txt") for i in range(count)]
    cs = [_read_int(f"{prefix}c{i}.txt") for i in range(count)]
    combined = crt(cs, ns)
    m = iroot(combined, count)
    if m ** count != combined:
        raise ValueError("hastad: CRT result is not a perfect cube")
    return i2b(m)


# ---------------------------------------------------------------------------
# rank 2 — common modulus, coprime exponents (Bezout combination)
# ---------------------------------------------------------------------------
def build_commonmod(rng: random.Random, message: bytes, prefix: str) -> dict[str, str]:
    m, e1, e2 = b2i(message), 3, 5
    while True:
        p, q = gen_prime(rng, 512), gen_prime(rng, 512)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e1 == 0 or phi % e2 == 0:
            continue
        n = p * q
        if m >= n:
            continue
        return {f"{prefix}n.txt": str(n), f"{prefix}e1.txt": str(e1),
                f"{prefix}e2.txt": str(e2), f"{prefix}c1.txt": str(pow(m, e1, n)),
                f"{prefix}c2.txt": str(pow(m, e2, n))}


def solve_commonmod(prefix: str = "") -> bytes:
    n = _read_int(f"{prefix}n.txt")
    e1 = _read_int(f"{prefix}e1.txt")
    e2 = _read_int(f"{prefix}e2.txt")
    c1 = _read_int(f"{prefix}c1.txt")
    c2 = _read_int(f"{prefix}c2.txt")
    g, a, b = egcd(e1, e2)
    if g != 1:
        raise ValueError("commonmod: exponents are not coprime")
    if a < 0:
        c1, a = pow(c1, -1, n), -a
    if b < 0:
        c2, b = pow(c2, -1, n), -b
    return i2b(pow(c1, a, n) * pow(c2, b, n) % n)


# ---------------------------------------------------------------------------
# rank 3 — small private exponent (Wiener continued fractions)
# ---------------------------------------------------------------------------
def build_wiener(rng: random.Random, message: bytes, prefix: str) -> dict[str, str]:
    m = b2i(message)
    while True:
        p, q = gen_prime(rng, 256), gen_prime(rng, 256)
        if p == q:
            continue
        n, phi = p * q, (p - 1) * (q - 1)
        if m >= n:
            continue
        d = gen_prime(rng, 120)          # d < N^0.25 / 3 -> Wiener applies
        if phi % d == 0:
            continue
        try:
            e = pow(d, -1, phi)
        except ValueError:
            continue
        return {f"{prefix}n.txt": str(n), f"{prefix}e.txt": str(e),
                f"{prefix}c.txt": str(pow(m, e, n))}


def _convergents(a: int, b: int):
    cf = []
    while b:
        cf.append(a // b)
        a, b = b, a % b
    for i in range(len(cf)):
        num, den = 1, 0
        for x in reversed(cf[: i + 1]):
            num, den = x * num + den, num
        yield num, den                   # num/den approximates e/n -> (k, d)


def solve_wiener(prefix: str = "") -> bytes:
    n = _read_int(f"{prefix}n.txt")
    e = _read_int(f"{prefix}e.txt")
    c = _read_int(f"{prefix}c.txt")
    for k, d in _convergents(e, n):
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        b = n - phi + 1                  # x^2 - bx + n = 0 has roots p, q
        disc = b * b - 4 * n
        if disc < 0:
            continue
        root = math.isqrt(disc)
        if root * root == disc and (b + root) % 2 == 0:
            return i2b(pow(c, d, n))
    raise ValueError("wiener: no convergent yielded a valid d (key is not weak)")


# ---------------------------------------------------------------------------
# rank 4 — primes too close (Fermat difference of squares)
# ---------------------------------------------------------------------------
def build_fermat(rng: random.Random, message: bytes, prefix: str) -> dict[str, str]:
    m, e = b2i(message), 65537
    while True:
        p = gen_prime(rng, 512)
        q = next_prime(p + rng.randint(2, 1 << 20))
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        n = p * q
        if m >= n:
            continue
        return {f"{prefix}n.txt": str(n), f"{prefix}e.txt": str(e),
                f"{prefix}c.txt": str(pow(m, e, n))}


def solve_fermat(prefix: str = "", max_steps: int = 1 << 22) -> bytes:
    n = _read_int(f"{prefix}n.txt")
    e = _read_int(f"{prefix}e.txt")
    c = _read_int(f"{prefix}c.txt")
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_steps):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a + b, a - b
            d = pow(e, -1, (p - 1) * (q - 1))
            return i2b(pow(c, d, n))
        a += 1
    raise ValueError("fermat: primes are not close enough")


# ---------------------------------------------------------------------------
# rank 5 — smooth p-1 (Pollard p-1 factorization)
# ---------------------------------------------------------------------------
def build_pollard(rng: random.Random, message: bytes, prefix: str) -> dict[str, str]:
    m, e = b2i(message), 65537
    while True:
        p = smooth_prime(rng, 256, 150)
        q = gen_prime(rng, 256)
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        n = p * q
        if m >= n:
            continue
        return {f"{prefix}n.txt": str(n), f"{prefix}e.txt": str(e),
                f"{prefix}c.txt": str(pow(m, e, n))}


def solve_pollard(prefix: str = "", bound: int = 4000) -> bytes:
    n = _read_int(f"{prefix}n.txt")
    e = _read_int(f"{prefix}e.txt")
    c = _read_int(f"{prefix}c.txt")
    a = 2
    for j in range(2, bound):
        a = pow(a, j, n)
        g = math.gcd(a - 1, n)
        if 1 < g < n:
            p, q = g, n // g
            d = pow(e, -1, (p - 1) * (q - 1))
            return i2b(pow(c, d, n))
    raise ValueError("pollard: p-1 is not smooth enough")


# ---------------------------------------------------------------------------
# the catalogue the maker composes from
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Stage:
    name: str
    rank: int                            # relative difficulty, mirrors the ladder
    label: str
    vulnerability: str
    hint: str
    build: Callable[[random.Random, bytes, str], dict[str, str]]
    solver: str                          # the solve_* symbol shipped into solver.py
    solver_args: str = ""                # extra literal args, e.g. a stage count


STAGES: dict[str, Stage] = {
    "smalle": Stage(
        "smalle", 0, "small public exponent",
        "unpadded RSA with e=3 and m^e < n (direct e-th root)",
        "One exponent is tiny and nothing is padded.",
        build_smalle, "solve_smalle"),
    "hastad": Stage(
        "hastad", 1, "Hastad broadcast",
        "same message under e=3 to three moduli (CRT then cube root)",
        "The same plaintext went to three recipients.",
        build_hastad, "solve_hastad", solver_args=", 3"),
    "commonmod": Stage(
        "commonmod", 2, "common modulus",
        "one modulus, two coprime exponents (Bezout combination)",
        "One modulus is reused with two different exponents.",
        build_commonmod, "solve_commonmod"),
    "wiener": Stage(
        "wiener", 3, "Wiener small-d",
        "small private exponent d (continued-fraction attack)",
        "A public exponent that large means a private one that small.",
        build_wiener, "solve_wiener"),
    "fermat": Stage(
        "fermat", 4, "Fermat close primes",
        "primes generated too close together (difference of squares)",
        "The two primes were not chosen independently.",
        build_fermat, "solve_fermat"),
    "pollard": Stage(
        "pollard", 5, "Pollard p-1",
        "a prime whose p-1 is smooth (Pollard's p-1 factorization)",
        "One prime is only a product of small factors, plus one.",
        build_pollard, "solve_pollard"),
}

STAGE_NAMES: list[str] = sorted(STAGES, key=lambda k: STAGES[k].rank)
