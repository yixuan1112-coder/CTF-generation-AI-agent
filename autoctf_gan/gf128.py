"""GF(2^128) exactly as GCM defines it, plus root-finding over that field.

This is the toolkit the `gcmreuse` rung's attack needs, and nothing else in the
repo uses it. It lives in its own module for the same reason `lattice.py` does:
the official solver ships it verbatim into the challenge bundle, so it must
import nothing outside the standard library and must not reach back into
`autoctf_gan`.

Two details are where implementations usually go wrong, and both are load-bearing
for the attack:

  * **Bit order.** GCM numbers the bits of a block from the *most* significant
    bit of byte 0 upward, which is the reverse of the natural integer reading.
    `block_to_element` therefore reverses all 128 bits before doing polynomial
    arithmetic mod x^128 + x^7 + x^2 + x + 1. Skip that and every product is
    wrong in a way that still looks like a plausible field element.

  * **GHASH is a polynomial in H.** `ghash(H, aad, ct)` evaluates
    X_1·H^m + X_2·H^(m-1) + ... + X_m·H, where the X_i are the padded AAD
    blocks, then the padded ciphertext blocks, then the length block. That the
    tag is a *polynomial evaluation* is the whole reason nonce reuse is fatal:
    two tags under one nonce subtract the unknown E_K(J0) away and leave a
    polynomial whose only unknown is H.

`roots()` is a full univariate root-finder over GF(2^128) — distinct-degree
extraction by gcd with X^(2^128) - X, then Cantor-Zassenhaus equal-degree
splitting via the trace map. The `gcmreuse` rung ships three records under the
repeated nonce so that the gcd of two error polynomials is almost always linear,
but "almost always" is not a contract, so the general finder is here to make the
solver total. Its randomness is seeded from a constant: `verify_spec` reruns the
solver and compares output, and a non-deterministic PoC is a rejected spec.
"""
from __future__ import annotations

import random

# x^128 + x^7 + x^2 + x + 1 — the GCM reduction polynomial.
REDUCTION = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1
ORDER = 1 << 128


# ---------------------------------------------------------------------------
# field arithmetic
# ---------------------------------------------------------------------------
def block_to_element(block: bytes) -> int:
    """A 16-byte GCM block as a field element (GCM's bit order, reversed)."""
    if len(block) != 16:
        raise ValueError(f"a GCM block is 16 bytes, got {len(block)}")
    return int(format(int.from_bytes(block, "big"), "0128b")[::-1], 2)


def element_to_block(value: int) -> bytes:
    """Inverse of `block_to_element`."""
    return int(format(value & (ORDER - 1), "0128b")[::-1], 2).to_bytes(16, "big")


def gmul(a: int, b: int) -> int:
    """Carry-less multiply, reduced mod x^128 + x^7 + x^2 + x + 1."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a >> 128:
            a ^= REDUCTION
    return result


def gpow(base: int, exponent: int) -> int:
    result, factor = 1, base
    while exponent:
        if exponent & 1:
            result = gmul(result, factor)
        factor = gmul(factor, factor)
        exponent >>= 1
    return result


def ginv(value: int) -> int:
    if value == 0:
        raise ZeroDivisionError("0 has no inverse in GF(2^128)")
    return gpow(value, ORDER - 2)          # Fermat: a^(2^128 - 2) = a^-1


def _pad_blocks(data: bytes) -> list[bytes]:
    return [data[i:i + 16].ljust(16, b"\x00") for i in range(0, len(data), 16)]


def ghash(h: int, aad: bytes, ciphertext: bytes) -> int:
    """GHASH_H(A, C) as a field element — the tag before E_K(J0) is added."""
    acc = 0
    for block in _pad_blocks(aad) + _pad_blocks(ciphertext):
        acc = gmul(acc ^ block_to_element(block), h)
    length_block = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    return gmul(acc ^ block_to_element(length_block), h)


# ---------------------------------------------------------------------------
# polynomials over GF(2^128) — coefficient i is the X^i term
# ---------------------------------------------------------------------------
def _trim(poly: list[int]) -> list[int]:
    while poly and poly[-1] == 0:
        poly.pop()
    return poly


def padd(a: list[int], b: list[int]) -> list[int]:
    out = [0] * max(len(a), len(b))
    for i, v in enumerate(a):
        out[i] ^= v
    for i, v in enumerate(b):
        out[i] ^= v
    return _trim(out)


def pmul(a: list[int], b: list[int]) -> list[int]:
    if not a or not b:
        return []
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if not x:
            continue
        for j, y in enumerate(b):
            if y:
                out[i + j] ^= gmul(x, y)
    return _trim(out)


def pmod(a: list[int], m: list[int]) -> list[int]:
    """Remainder of a mod m. `m` must be non-zero."""
    if not m:
        raise ZeroDivisionError("polynomial division by zero")
    a = list(a)
    degree_m = len(m) - 1
    lead_inv = ginv(m[-1])
    while a and len(a) - 1 >= degree_m:
        shift = len(a) - 1 - degree_m
        factor = gmul(a[-1], lead_inv)
        for i, coeff in enumerate(m):
            a[i + shift] ^= gmul(coeff, factor)
        _trim(a)
    return _trim(a)


def pgcd(a: list[int], b: list[int]) -> list[int]:
    """Monic gcd; [] when both are zero."""
    a, b = _trim(list(a)), _trim(list(b))
    while b:
        a, b = b, pmod(a, b)
    if a:
        scale = ginv(a[-1])
        a = [gmul(c, scale) for c in a]
    return a


def pmulmod(a: list[int], b: list[int], m: list[int]) -> list[int]:
    return pmod(pmul(a, b), m)


def roots(poly: list[int], *, rng_seed: str = "autoctf-gf128") -> list[int]:
    """Every root of `poly` in GF(2^128), as field elements.

    Deterministic given `rng_seed`: the equal-degree split is the only random
    step and it draws from a seeded Random, so two runs of the same solver
    return the same list in the same order.
    """
    poly = _trim(list(poly))
    if len(poly) < 2:
        return []                                   # constant (or zero): no roots
    scale = ginv(poly[-1])
    poly = [gmul(c, scale) for c in poly]

    # Every element of GF(2^128) satisfies X^(2^128) = X, so gcd(f, X^(2^128) - X)
    # strips everything except the distinct linear factors. Squaring X 128 times
    # modulo f keeps the intermediate degree below deg(f) throughout.
    x_pow = [0, 1]
    for _ in range(128):
        x_pow = pmulmod(x_pow, x_pow, poly)
    linear_part = pgcd(padd(x_pow, [0, 1]), poly)

    found: list[int] = []
    pending = [linear_part]
    rng = random.Random(rng_seed)
    while pending:
        factor = pending.pop()
        if len(factor) < 2:
            continue
        if len(factor) == 2:                        # c1·X + c0  ->  root c0/c1
            found.append(gmul(factor[0], ginv(factor[1])))
            continue
        # Cantor-Zassenhaus for degree-1 factors in characteristic 2: the trace
        # map Tr(cX) = sum_{i<128} (cX)^(2^i) sends each root to 0 or 1, so its
        # gcd with the factor splits it whenever the roots disagree — about half
        # the draws.
        for _ in range(128):
            c = rng.getrandbits(128)
            if c == 0:
                continue
            trace, term = [0], [0, c]
            for _ in range(128):
                trace = padd(trace, term)
                term = pmulmod(term, term, factor)
            part = pgcd(trace, factor)
            if 0 < len(part) - 1 < len(factor) - 1:
                pending += [part, pmod(factor, part)]
                break
        else:                                       # 128 failures is not bad luck
            raise RuntimeError("equal-degree splitting did not terminate")
    return sorted(found)
