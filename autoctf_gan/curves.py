"""Elliptic-curve arithmetic and the two structural attacks the hard rungs use.

Like `lattice.py` and `gf128.py`, this module is shipped verbatim into a
challenge bundle, so it imports nothing but the standard library and never
reaches back into `autoctf_gan`.

It carries three things:

  * plain short-Weierstrass arithmetic over F_p (`add` / `mul`). These formulas
    are the ones every ECC library uses, and they keep working on a *singular*
    curve as long as you stay off the singular point — which is exactly what the
    `singular` rung relies on to look completely ordinary.

  * the singular-curve reduction. y^2 = x^3 + ax + b is singular iff its
    discriminant 4a^3 + 27b^2 vanishes, and then the smooth points form a group
    isomorphic to F_p^* (split node) rather than an elliptic curve group. ECDLP
    collapses into an ordinary finite-field discrete log, and if p-1 is smooth
    Pohlig-Hellman finishes it in milliseconds. Nothing about the published
    parameters announces this: you have to compute the discriminant.

  * the hidden-number-problem lattice for biased ECDSA nonces (`hnp_basis`).
    Given signatures whose nonces are short, k_i = t_i·d + u_i (mod n) with
    small k_i, and the private key falls out of one LLL reduction. Building the
    basis is the whole trick; the reduction itself is `lattice.lll`.

`pohlig_hellman` here solves in F_p^*, not in a curve group — that is deliberate,
because after the singular reduction that is the only group left.
"""
from __future__ import annotations

import math

# secp256k1 — a completely ordinary curve. The `noncebias` rung's weakness is in
# how the signer picks k, never in the curve.
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
               0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

Point = tuple[int, int] | None          # None is the point at infinity


# ---------------------------------------------------------------------------
# group law
# ---------------------------------------------------------------------------
def add(p1: Point, p2: Point, a: int, p: int) -> Point:
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


def mul(k: int, point: Point, a: int, p: int) -> Point:
    if k < 0:
        k, point = -k, (point[0], (-point[1]) % p) if point else None
    result, addend = None, point
    while k:
        if k & 1:
            result = add(result, addend, a, p)
        addend = add(addend, addend, a, p)
        k >>= 1
    return result


def is_on_curve(point: Point, a: int, b: int, p: int) -> bool:
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x % p * x + a * x + b)) % p == 0


def discriminant(a: int, b: int, p: int) -> int:
    """4a^3 + 27b^2 mod p. Zero means the curve is singular — and broken."""
    return (4 * pow(a, 3, p) + 27 * b * b) % p


# ---------------------------------------------------------------------------
# singular curves: the smooth points are F_p^* in disguise
# ---------------------------------------------------------------------------
def node_x(a: int, b: int, p: int) -> int:
    """The x of the singular point, i.e. the double root of x^3 + ax + b.

    Differentiating gives 3x^2 + a = 0 and the cubic itself gives x^3 + ax + b = 0;
    eliminating x^2 between them leaves x = -3b/(2a). Valid whenever a != 0, which
    holds for every node (a == 0 with a vanishing discriminant is a cusp).
    """
    if a % p == 0:
        raise ValueError("a == 0: the singularity is a cusp, not a node")
    return (-3 * b) % p * pow(2 * a, -1, p) % p


def _sqrt_mod(value: int, p: int) -> int | None:
    """Square root mod p for p = 3 (mod 4); None when `value` is not a residue."""
    if p % 4 != 3:
        raise ValueError("this square root needs p = 3 (mod 4)")
    value %= p
    if value == 0:
        return 0
    root = pow(value, (p + 1) // 4, p)
    return root if root * root % p == value else None


def node_slope(a: int, b: int, p: int) -> int:
    """The tangent slope t at the node, where t^2 = 3·alpha.

    A node has two tangent lines y = ±t·(x - alpha). They are defined over F_p
    exactly when 3·alpha is a quadratic residue — the *split* case, which is what
    makes the smooth points isomorphic to F_p^* rather than to the norm-one
    subgroup of F_p^2^*.
    """
    alpha = node_x(a, b, p)
    slope = _sqrt_mod(3 * alpha % p, p)
    if slope is None:
        raise ValueError("non-split node: 3·alpha is not a square mod p")
    return slope


def to_multiplicative(point: tuple[int, int], a: int, b: int, p: int) -> int:
    """Map a smooth point of a split-node singular curve into F_p^*.

    Shifting x by the node moves the curve to y^2 = u^2·(u + 3·alpha), whose
    smooth points map isomorphically by (u, y) -> (y + t·u)/(y - t·u). Group law
    in, multiplication out — so a scalar multiple becomes a power.
    """
    alpha = node_x(a, b, p)
    slope = node_slope(a, b, p)
    x, y = point
    u = (x - alpha) % p
    if u == 0:
        raise ValueError("that is the singular point itself; it is not in the group")
    return (y + slope * u) % p * pow((y - slope * u) % p, -1, p) % p


# ---------------------------------------------------------------------------
# discrete logs in F_p^* when p-1 is smooth
# ---------------------------------------------------------------------------
def factorize(n: int, bound: int = 1 << 24) -> dict[int, int]:
    """Trial division. Anything left above `bound` is reported as one factor."""
    factors: dict[int, int] = {}
    for divisor in (2, 3):
        while n % divisor == 0:
            factors[divisor] = factors.get(divisor, 0) + 1
            n //= divisor
    divisor = 5
    step = 2
    while divisor * divisor <= n and divisor < bound:
        while n % divisor == 0:
            factors[divisor] = factors.get(divisor, 0) + 1
            n //= divisor
        divisor += step
        step = 6 - step                    # 5, 7, 11, 13, 17, 19, ...
    if n > 1:
        factors[n] = factors.get(n, 0) + 1
    return factors


def element_order(g: int, p: int, group_order: int, factors: dict[int, int]) -> int:
    """The multiplicative order of g, given the factored group order."""
    order = group_order
    for prime, power in factors.items():
        for _ in range(power):
            if order % prime or pow(g, order // prime, p) != 1:
                break
            order //= prime
    return order


def _bsgs(g: int, h: int, order: int, p: int) -> int:
    """Baby-step giant-step for a subgroup of prime order `order`."""
    step = math.isqrt(order) + 1
    table: dict[int, int] = {}
    value = 1
    for j in range(step):
        table.setdefault(value, j)
        value = value * g % p
    stride = pow(pow(g, step, p), -1, p)
    y = h
    for i in range(step + 1):
        if y in table:
            return i * step + table[y]
        y = y * stride % p
    raise ValueError("baby-step giant-step found no logarithm in this subgroup")


def _crt(residues: list[int], moduli: list[int]) -> int:
    total, product = 0, 1
    for m in moduli:
        product *= m
    for r, m in zip(residues, moduli):
        partial = product // m
        total += r * partial * pow(partial, -1, m)
    return total % product


def pohlig_hellman(g: int, h: int, p: int, bound: int = 1 << 24) -> int:
    """Solve g^x = h in F_p^*. Fast exactly when the order of g is smooth.

    The order of g, not p-1: the image of a curve point under
    `to_multiplicative` is very often a square, so it generates only half the
    group and projecting into the 2-part of p-1 would silently return a wrong
    digit. Working in <g> makes the answer unique instead.
    """
    factors = factorize(p - 1, bound)
    order = element_order(g, p, p - 1, factors)
    order_factors = {q: e for q, e in factorize(order, bound).items()}
    residues, moduli = [], []
    for prime, power in order_factors.items():
        modulus = prime ** power
        base = pow(g, order // modulus, p)
        target = pow(h, order // modulus, p)
        generator = pow(base, modulus // prime, p)
        digit_sum = 0
        for k in range(power):
            projected = pow(pow(base, -digit_sum, p) * target % p,
                            modulus // prime ** (k + 1), p)
            digit_sum += _bsgs(generator, projected, prime, p) * prime ** k
        residues.append(digit_sum % modulus)
        moduli.append(modulus)
    result = _crt(residues, moduli) if moduli else 0
    if pow(g, result, p) != h:
        raise ValueError("Pohlig-Hellman failed: h is not in <g>, or p-1 is not smooth")
    return result


# ---------------------------------------------------------------------------
# biased ECDSA nonces: the hidden number problem
# ---------------------------------------------------------------------------
def hnp_basis(signatures: list[tuple[int, int, int]], n: int, bound: int) -> list[list[int]]:
    """Lattice whose short vectors expose the private key of a biased signer.

    Each ECDSA signature gives s·k = h + r·d (mod n), so with t = r/s and
    u = h/s the nonce is k = t·d + u (mod n). When every k is below `bound` the
    vector (n·k_1, ..., n·k_m, bound·d, n·bound) lies in the lattice below and is
    far shorter than the Gaussian heuristic predicts, so LLL finds it. Everything
    is scaled by n to stay in the integers — the textbook basis wants bound/n in
    one cell.

    Recovery needs m·log2(n/bound) to comfortably exceed log2(n): each signature
    contributes only as many bits as the nonce is short.
    """
    m = len(signatures)
    if m < 2:
        raise ValueError("the hidden number problem needs several signatures")
    size = m + 2
    basis = [[0] * size for _ in range(size)]
    for i in range(m):
        basis[i][i] = n * n
    for i, (h, r, s) in enumerate(signatures):
        s_inv = pow(s, -1, n)
        basis[m][i] = n * (r * s_inv % n)
        basis[m + 1][i] = n * (h * s_inv % n)
    basis[m][m] = bound
    basis[m + 1][m + 1] = n * bound
    return basis


def hnp_candidates(reduced: list[list[int]], m: int, n: int, bound: int) -> list[int]:
    """Private-key candidates read out of an LLL-reduced `hnp_basis`.

    The target vector's last coordinate is ±n·bound and its second-to-last is
    ±bound·d, so a row with the right last coordinate hands over d directly. Both
    signs are returned: LLL is free to negate the vector it finds.
    """
    out: list[int] = []
    for row in reduced:
        if abs(row[m + 1]) != n * bound or row[m] % bound:
            continue
        candidate = row[m] // bound % n
        for value in (candidate, (-candidate) % n):
            if value and value not in out:
                out.append(value)
    return out
