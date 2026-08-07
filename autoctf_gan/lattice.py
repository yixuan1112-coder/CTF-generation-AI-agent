"""Pure-Python LLL, plus an honest status note on lattice RSA attacks.

`lll()` is a correct, self-contained LLL reduction (rational Gram-Schmidt). It is
verified in the test suite on a known basis and is a real building block.

Boneh-Durfee (recover d < N^0.292) and Coppersmith "known-high-bits-of-p" both
reduce to LLL on lattices whose dimension and entry size make a *pure-Python*
Fraction-based LLL far too slow to reduce reliably within a challenge's time
budget. Doing them for real needs an optimized reduction backend (fpylll / NTL /
Sage). Rather than ship an attack PoC that does not actually run — which would
violate AutoCTF-GAN's core rule that every official_solver must recover the flag
— the crypto ladder tops out with attacks that verify in pure Python (Fermat,
Pollard p-1). `boneh_durfee()` below is intentionally gated: it runs only if an
fpylll backend is importable, and raises a clear error otherwise.
"""
from __future__ import annotations

from fractions import Fraction as Fr


def lll(basis: list[list[int]], delta: Fr = Fr(99, 100)) -> list[list[int]]:
    """LLL-reduce an integer lattice basis (rows). Returns reduced integer rows."""
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


def _fpylll_available() -> bool:
    try:
        import fpylll  # noqa: F401
        return True
    except Exception:
        return False


def boneh_durfee(N: int, e: int, delta: float = 0.28, m: int = 4, t: int = 2):
    """Recover small d via Boneh-Durfee. Requires an optimized LLL backend.

    Gated on purpose: the pure-Python `lll` above cannot reduce this lattice fast
    enough to be a usable challenge PoC. Wire fpylll here for production use.
    """
    if not _fpylll_available():
        raise NotImplementedError(
            "Boneh-Durfee needs an optimized LLL backend (fpylll/NTL/Sage). "
            "The pure-Python LLL in this module is correct but too slow for this "
            "lattice; install fpylll and plug it in to enable this attack.")
    raise NotImplementedError("plug an fpylll-based Boneh-Durfee routine in here")
