"""Sample competitor agent — a reference attacker teams can model theirs on.

`solve(files)` is a real RSA attack toolkit: small-e cube root, Håstad broadcast,
common modulus, Wiener, Fermat, Pollard p-1. It is strong enough to climb the
crypto ladder — but it has NO lattice attack, so it cannot crack the Boneh-Durfee
final form. That's the point: a team keeps beating the agent until the agent
evolves past the team's capability.

`run_agent(comp, name)` drives one agent against a live Competition: register,
pull the current challenge, solve it, submit, repeat until it can no longer keep up.
"""
from __future__ import annotations

import math
from functools import reduce


def _iroot(x: int, k: int) -> int:
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


def _to_flag(m: int):
    try:
        s = m.to_bytes((m.bit_length() + 7) // 8, "big").decode()
        return s if s.startswith("flag{") else None
    except Exception:
        return None


def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def _wiener(e, n):
    cf, a, b = [], e, n
    while b:
        cf.append(a // b); a, b = b, a % b
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
            s = math.isqrt(disc)
            if s * s == disc:
                return d
    return None


def _fermat(n, cap=1 << 20):
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


def _pollard(n, B=4000):
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
        d = math.gcd(a - 1, n)
        if 1 < d < n:
            return d
    return None


def _from_factor(p, n, e, c):
    q = n // p
    phi = (p - 1) * (q - 1)
    try:
        d = pow(e, -1, phi)
    except Exception:
        return None
    return _to_flag(pow(c, d, n))


def solve(files: dict) -> str | None:
    """Try the toolkit against whatever challenge files were provided."""
    def I(name):
        return int(files[name].strip())
    names = set(files)

    # Håstad broadcast: same message, e=3, three moduli
    if {"n0.txt", "n1.txt", "n2.txt", "c0.txt", "c1.txt", "c2.txt"} <= names:
        ns = [I(f"n{i}.txt") for i in range(3)]
        cs = [I(f"c{i}.txt") for i in range(3)]
        M = reduce(lambda x, y: x * y, ns)
        x = sum(r * (M // m) * pow(M // m, -1, m) for r, m in zip(cs, ns)) % M
        return _to_flag(_iroot(x, 3))

    # common modulus
    if {"n.txt", "e1.txt", "e2.txt", "c1.txt", "c2.txt"} <= names:
        n, e1, e2 = I("n.txt"), I("e1.txt"), I("e2.txt")
        c1, c2 = I("c1.txt"), I("c2.txt")
        _, a, b = _egcd(e1, e2)
        if a < 0:
            c1 = pow(c1, -1, n); a = -a
        if b < 0:
            c2 = pow(c2, -1, n); b = -b
        return _to_flag(pow(c1, a, n) * pow(c2, b, n) % n)

    # single n, e, c
    if {"n.txt", "e.txt", "c.txt"} <= names:
        n, e, c = I("n.txt"), I("e.txt"), I("c.txt")
        if e <= 5:                                   # small-e cube/e-th root
            m = _iroot(c, e)
            if m ** e == c and (f := _to_flag(m)):
                return f
        if (d := _wiener(e, n)):                     # small private exponent
            if (f := _to_flag(pow(c, d, n))):
                return f
        if (p := _fermat(n)) and n % p == 0:         # close primes
            if (f := _from_factor(p, n, e, c)):
                return f
        if (p := _pollard(n)) and n % p == 0:        # smooth p-1
            if (f := _from_factor(p, n, e, c)):
                return f
    return None   # no tool in the kit cracks this (e.g. Boneh-Durfee)


def run_agent(comp, name: str, max_rounds: int = 20) -> dict:
    """One competitor agent vs. a live Competition until it can't keep up."""
    team = comp.register(name)["team_id"]
    solved = []
    for _ in range(max_rounds):
        ch = comp.current(team)
        flag = solve(ch["files"])
        if flag is None:
            break                                    # stuck — the agent has out-evolved us
        r = comp.submit(team, ch["challenge_id"], flag)
        if r.get("correct"):
            solved.append({"gen": ch["gen"], "points": r.get("points", 0),
                           "first_blood": r.get("first_blood", False)})
        elif not r.get("correct") and r.get("msg", "").startswith("stale"):
            continue                                 # someone evolved it; re-pull
        else:
            break
    return {"team": name, "solved": solved}
