"""LLL + a real Boneh-Durfee attack (recover small RSA d, d < N^~0.27).

`lll()` uses fpylll's optimized reduction when available and falls back to a
correct pure-Python reduction otherwise. `boneh_durfee()` is a full attack that
actually recovers the factors (Herrmann-May triangular lattice with the
u = xy + 1 substitution), verified in the test suite to recover d at N^0.255 on
512-bit moduli. It requires fpylll (LLL) + sympy (resultant); when fpylll is
absent it raises NotImplementedError rather than pretending — no PoC that cannot
run is ever shipped (principle P1).

This module is self-contained (no autoctf_gan imports) so it can be shipped
verbatim inside a challenge's solver bundle.
"""
from __future__ import annotations

import math
from fractions import Fraction as Fr


def _fpylll():
    try:
        import fpylll
        return fpylll
    except Exception:
        return None


def lll(basis: list[list[int]], delta: Fr = Fr(99, 100)) -> list[list[int]]:
    """LLL-reduce integer lattice rows. Uses fpylll if present, else pure Python."""
    fp = _fpylll()
    if fp is not None:
        M = fp.IntegerMatrix(len(basis), len(basis[0]))
        for i, row in enumerate(basis):
            for j, v in enumerate(row):
                M[i, j] = int(v)
        fp.LLL.reduction(M)
        return [[M[i, j] for j in range(M.ncols)] for i in range(M.nrows)]
    return _lll_python(basis, delta)


def _lll_python(basis, delta=Fr(99, 100)):
    B = [[int(x) for x in row] for row in basis]
    n = len(B)

    def dot(u, v):
        return sum(a * b for a, b in zip(u, v))

    def gso():
        Bs, mu = [], [[Fr(0)] * n for _ in range(n)]
        for i in range(n):
            bi = [Fr(x) for x in B[i]]
            for j in range(i):
                dj = dot(Bs[j], Bs[j])
                mu[i][j] = (dot([Fr(x) for x in B[i]], Bs[j]) / dj) if dj else Fr(0)
                bi = [bi[k] - mu[i][j] * Bs[j][k] for k in range(len(bi))]
            Bs.append(bi)
        return Bs, mu

    Bs, mu = gso()
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fr(1, 2):
                frac = mu[k][j] - int(mu[k][j])
                q = int(mu[k][j]) + (1 if frac > Fr(1, 2) else (-1 if frac < Fr(-1, 2) else 0))
                B[k] = [B[k][t] - q * B[j][t] for t in range(len(B[k]))]
                Bs, mu = gso()
        if dot(Bs[k], Bs[k]) >= (delta - mu[k][k - 1] ** 2) * dot(Bs[k - 1], Bs[k - 1]):
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            Bs, mu = gso()
            k = max(k - 1, 1)
    return B


def boneh_durfee(N: int, e: int, delta: float = 0.28, mm: int = 5, tt: int | None = None):
    """Recover (p, q) from an RSA key with small d (d < N^delta). Returns None on failure.

    Requires fpylll for a fast enough LLL. Raises NotImplementedError without it.
    """
    fp = _fpylll()
    if fp is None:
        raise NotImplementedError(
            "Boneh-Durfee needs fpylll for LLL at cryptographic sizes. "
            "Install fpylll; the pure-Python LLL here is correct but too slow.")
    from sympy import Poly, expand, resultant, symbols

    u, x, y = symbols("u x y")
    if tt is None:
        tt = max(1, int((1 - 2 * delta) * mm))

    def reduce_uxy(P):
        res = 0
        for (i, j), c in zip(P.monoms(), P.coeffs()):
            mn = min(i, j)
            res += c * (u - 1) ** mn * x ** (i - mn) * y ** (j - mn)
        return Poly(expand(res), u, x, y)

    XX = 2 * int(N ** delta)
    YY = 3 * int(math.isqrt(N))
    A = N + 1
    pol = Poly(1 + x * (A + y), x, y)
    UU = XX * YY + 1

    gg = []
    for kk in range(mm + 1):
        for ii in range(mm - kk + 1):
            gg.append(reduce_uxy(Poly(x ** ii * e ** (mm - kk), x, y) * pol ** kk))
    for jj in range(1, tt + 1):
        for kk in range(mm // tt * jj, mm + 1):
            gg.append(reduce_uxy(Poly(y ** jj * e ** (mm - kk), x, y) * pol ** kk))

    monos = []
    for g in gg:
        for m in g.monoms():
            if m not in monos:
                monos.append(m)
    monos.sort()
    idx = {m: i for i, m in enumerate(monos)}

    def ev(m):
        return (UU ** m[0]) * (XX ** m[1]) * (YY ** m[2])

    M = fp.IntegerMatrix(len(gg), len(monos))
    for r, g in enumerate(gg):
        for m, c in zip(g.monoms(), g.coeffs()):
            M[r, idx[m]] = int(c) * ev(m)
    fp.LLL.reduction(M)

    def row_poly(r):
        ex = 0
        for m, col in idx.items():
            v = M[r, col]
            if v:
                ex += (v // ev(m)) * (u ** m[0]) * (x ** m[1]) * (y ** m[2])
        return Poly(expand(ex.subs(u, x * y + 1)), x, y)

    def recover(y0):
        s = -int(y0)
        disc = s * s - 4 * N
        if disc >= 0:
            sq = math.isqrt(disc)
            if sq * sq == disc and (s + sq) % 2 == 0:
                p = (s + sq) // 2
                if p > 1 and N % p == 0:
                    return p, N // p
        return None

    polys = [row_poly(r) for r in range(min(5, M.nrows))]
    for a in range(len(polys)):
        for b in range(a + 1, len(polys)):
            try:
                R = resultant(polys[a], polys[b], x)
                if R == 0:
                    continue
                for root in Poly(R, y).ground_roots():
                    got = recover(root)
                    if got:
                        return got
            except Exception:
                continue
    return None
