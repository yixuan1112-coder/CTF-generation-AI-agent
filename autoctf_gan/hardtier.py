"""The hardest rungs: real cryptographic techniques, each with a wall in front.

Everything here has the same shape — the obvious attack is infeasible, and the
feasible attack is a named technique a solver has to actually know or derive and
then implement correctly. There is no recognition shortcut and no toolkit call
that finishes the job. A tireless-but-unwise agent burns its budget on the
infeasible path; a strong solver reaches for the right theorem.

  rswelch   A secret polynomial sampled at many points, a dozen of them corrupted.
            Interpolating the points gives garbage; guessing which points are
            clean is a search over hundreds of millions of subsets. The clean
            route is Berlekamp-Welch error-locator decoding — one linear system —
            which nothing but knowing Reed-Solomon decoding hands you.

  phsmooth  A discrete log in a ~200-bit prime field. Brute force and baby-step
            giant-step over the whole group are both hopeless, but this p was
            chosen so p-1 is smooth, which Pohlig-Hellman turns into a handful of
            tiny logs plus CRT. The catch is that the smoothness is not advertised
            — you have to factor p-1 to discover the attack even exists. (Its
            sibling `dlogwall` is the same field size with p-1 deliberately NOT
            smooth, so this shortcut is absent; telling them apart is the point.)

  mqlin     A key defined by a thousand quadratic equations over GF(2). It reads
            as an NP-hard multivariate-quadratic system, and brute force over the
            48-bit key is a wall. But the instance ships enough equations to
            LINEARISE: treat every quadratic monomial as its own unknown and it
            collapses to one big linear system over GF(2).

None writes the flag into a player artifact.
"""
from __future__ import annotations

import hashlib
import json
import random

from .hardcore import _SEAL_TOOL, _seal
from .identity import challenge_flag


def _spec(*, slug, title, category, challenge_type, story, vulnerability, solution,
          artifacts, solver_files, flag, seed, generation, attack_class, rank,
          max_runtime_s, flag_secret):
    from .models import ChainStep, ChallengeSpec, Lineage, OfficialSolver
    expected = hashlib.sha256(flag.encode()).hexdigest()
    return ChallengeSpec(
        slug=slug, title=f"{title} (Gen-{generation})", category=category,
        challenge_type=challenge_type, difficulty="hard", story=story,
        vulnerability=vulnerability, intended_solution=solution, hints=[],
        delivery="crypto", seed=seed,
        mechanics={"attack_class": attack_class, "rank": rank},
        flag=flag, spec_id=slug,
        lineage=Lineage(archetype_id=f"hardtier.{attack_class}", generation=generation,
                        parent_spec_id=None, mutation_ops=[], seed=seed),
        vuln_chain=[ChainStep(step=1, primitive=f"{attack_class}_stage",
                              params={}, guard="crypto")],
        artifacts=artifacts,
        official_solver=OfficialSolver(entry="solver.py", files=solver_files,
                                       expected_flag_sha256=expected,
                                       max_runtime_s=max_runtime_s),
        target_solve_rate=0.01)


def _slug(kind, flag_secret, seed, generation):
    tag = hashlib.sha256(f"{kind}:{flag_secret}:{seed}:{generation}".encode()).hexdigest()[:8]
    return f"ht-{kind}-g{generation}-{tag}"


# ---------------------------------------------------------------------------
# rswelch — Reed-Solomon / Berlekamp-Welch decoding through planted errors
# ---------------------------------------------------------------------------
RS_P = (1 << 61) - 1
RS_DEG = 10               # secret polynomial degree (11 coefficients)
RS_ERRORS = 12
RS_POINTS = (RS_DEG + 1) + 2 * RS_ERRORS      # 35 points

_RSWELCH_SOLVER = '''\
"""Recover a secret polynomial from evaluations, a dozen of them corrupted.

Interpolating all the points is worthless: the errors drag the fit off the true
polynomial. Guessing the clean subset is a search over hundreds of millions of
choices. Berlekamp-Welch sidesteps both. Posit an error-locator E(x), monic of
degree e (the error count), zero exactly at the corrupted points, and Q(x) = f(x)
E(x) of degree deg+e. At every point, corrupted or not,

    Q(x_i) = y_i * E(x_i),

which is linear in the unknown coefficients of Q and E. Solve that one system over
GF(p), divide Q by E, and the quotient is f. The recovery key is the coefficient
list, each written as 16 hex digits, low degree first.
"""
import json

doc = json.load(open("samples.json", encoding="utf-8"))
p, deg, e = doc["prime"], doc["degree"], doc["errors"]
pts = [(int(s["x"]), int(s["y"])) for s in doc["samples"]]
n = len(pts)


def solve_mod(rows, ncols):
    R = [r[:] for r in rows]
    where = [-1] * ncols
    r = 0
    for col in range(ncols):
        sel = next((i for i in range(r, len(R)) if R[i][col] % p), None)
        if sel is None:
            continue
        R[r], R[sel] = R[sel], R[r]
        inv = pow(R[r][col], -1, p)
        R[r] = [(v * inv) % p for v in R[r]]
        for i in range(len(R)):
            if i != r and R[i][col] % p:
                f = R[i][col]
                R[i] = [(a - f * b) % p for a, b in zip(R[i], R[r])]
        where[col] = r
        r += 1
    sol = [0] * ncols
    for col in range(ncols):
        if where[col] != -1:
            sol[col] = R[where[col]][ncols]
    return sol


# Unknowns: Q has deg+e+1 coeffs, E has e coeffs (E is monic, top coeff fixed to 1).
nq = deg + e + 1
ncols = nq + e
rows = []
for x, y in pts:
    row = [0] * (ncols + 1)
    xp = 1
    for j in range(nq):
        row[j] = xp
        xp = xp * x % p
    xp = 1
    for i in range(e):
        row[nq + i] = (-y * xp) % p
        xp = xp * x % p
    row[ncols] = (y * pow(x, e, p)) % p      # y * x^e  (E's monic top term)
    rows.append(row)

sol = solve_mod(rows, ncols)
Q = sol[:nq]
E = sol[nq:] + [1]                            # append the monic leading coefficient


def poly_divmod(num, den):
    num = num[:]
    dd = len(den) - 1
    dinv = pow(den[-1], -1, p)
    quot = [0] * max(1, len(num) - dd)
    for i in range(len(num) - 1, dd - 1, -1):
        c = (num[i] * dinv) % p
        quot[i - dd] = c
        for j in range(dd + 1):
            num[i - dd + j] = (num[i - dd + j] - c * den[j]) % p
    return quot


f = poly_divmod(Q, E)
f = (f + [0] * (deg + 1))[:deg + 1]
key = "".join(f"{c:016x}" for c in f)

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), key))
'''


def gen_rswelch(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="rswelch", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"rswelch:{flag_secret}:{seed}:{generation}")

    coeffs = [rng.randrange(RS_P) for _ in range(RS_DEG + 1)]
    xs = rng.sample(range(1, RS_P), RS_POINTS)
    samples = []
    for x in xs:
        y = 0
        for c in reversed(coeffs):
            y = (y * x + c) % RS_P
        samples.append([x, y])
    for i in rng.sample(range(RS_POINTS), RS_ERRORS):
        samples[i][1] = (samples[i][1] + rng.randrange(1, RS_P)) % RS_P

    key = "".join(f"{c:016x}" for c in coeffs)
    artifacts = {
        "samples.json": json.dumps({
            "prime": RS_P, "degree": RS_DEG, "errors": RS_ERRORS,
            "note": ("evaluations of a secret polynomial mod prime; exactly `errors` "
                     "of them are corrupted"),
            "samples": [{"x": str(x), "y": str(y)} for x, y in samples],
        }, indent=1) + "\n",
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key, flag),
        "README.md": (
            "# Corrupted telemetry fit\n\n"
            f"`samples.json` holds {RS_POINTS} evaluations of a secret degree-{RS_DEG} "
            f"polynomial modulo a prime, of which exactly {RS_ERRORS} are corrupted. "
            "The prime, the degree and the corruption count are given.\n\n"
            "The operator's recovery blob is sealed under the polynomial's "
            f"{RS_DEG + 1} coefficients, each written as 16 hex digits from the "
            "constant term upward and concatenated. `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("rswelch", flag_secret, seed, generation),
        title="Corrupted Telemetry Fit", category="crypto",
        challenge_type="reed-solomon-decoding",
        story=("Telemetry sampled a secret polynomial at many points, but a dozen "
               "readings were corrupted in transit. A plain fit through the points "
               "lands nowhere near the truth."),
        vulnerability=("errors make interpolation fail and subset search infeasible; only "
                       "Berlekamp-Welch error-locator decoding recovers the polynomial"),
        solution=["reject plain interpolation: the errors drag the fit off",
                  "posit a monic error locator E and Q = f*E, both unknown",
                  "Q(x_i) = y_i E(x_i) at every point is one linear system over GF(p)",
                  "divide Q by E to get f and format its coefficients"],
        artifacts=artifacts,
        solver_files={"solver.py": _RSWELCH_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="rswelch",
        rank=17, max_runtime_s=120, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# phsmooth — a discrete log the size hides but the smoothness gives away
# ---------------------------------------------------------------------------
PHS_FACTOR_BITS = 30
PHS_FACTORS = 7

_PHSMOOTH_SOLVER = '''\
"""A discrete log in a ~200-bit field, feasible only once you factor p-1.

Baby-step giant-step over the whole group is 2**100 work; do not attempt it. This
p was built so p-1 is smooth, so factor p-1 first (its factors are small enough for
Pollard's rho), then Pohlig-Hellman: for each prime power q**a dividing p-1, push
g and h into the order-q**a subgroup and solve that small log with baby-step
giant-step, then recombine the residues with the CRT. The exponent x is the key,
in lowercase hex.
"""
import json
from math import gcd, isqrt

doc = json.load(open("exchange.json", encoding="utf-8"))
p, g, h = int(doc["p"]), int(doc["g"]), int(doc["h"])


def is_prime(n):
    if n < 2:
        return False
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % q == 0:
            return n == q
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def rho(n):
    if n % 2 == 0:
        return 2
    c = 1
    while True:
        x = y = 2
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = gcd(abs(x - y), n)
        if d != n:
            return d
        c += 1


def factor(n):
    fac = {}
    stack = [n]
    while stack:
        m = stack.pop()
        if m == 1:
            continue
        if is_prime(m):
            fac[m] = fac.get(m, 0) + 1
            continue
        d = rho(m)
        stack.append(d)
        stack.append(m // d)
    return fac


def bsgs(base, target, mod, order):
    m = isqrt(order) + 1
    table = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = e * base % mod
    step = pow(pow(base, m, mod), -1, mod)
    cur = target
    for i in range(m + 1):
        if cur in table:
            return i * m + table[cur]
        cur = cur * step % mod
    raise AssertionError("no log in subgroup")


order = p - 1
residues, moduli = [], []
for q, a in factor(order).items():
    pe = q ** a
    gi = pow(g, order // pe, p)
    hi = pow(h, order // pe, p)
    residues.append(bsgs(gi, hi, p, pe) % pe)
    moduli.append(pe)

M = 1
for mod in moduli:
    M *= mod
x = 0
for r, mod in zip(residues, moduli):
    Mi = M // mod
    x = (x + r * Mi * pow(Mi, -1, mod)) % M
assert pow(g, x, p) == h, "recovered exponent does not check"

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), f"{x:x}"))
'''


def gen_phsmooth(seed, generation, **kw):
    from Crypto.Util.number import isPrime

    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="phsmooth", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"phsmooth:{flag_secret}:{seed}:{generation}")

    def rand_prime(bits):
        while True:
            c = rng.getrandbits(bits) | 1 | (1 << (bits - 1))
            if isPrime(c):
                return c

    while True:
        factors = [rand_prime(PHS_FACTOR_BITS) for _ in range(PHS_FACTORS)]
        pm1 = 2
        for q in factors:
            pm1 *= q
        p = pm1 + 1
        if isPrime(p):
            break

    prime_set = set(factors) | {2}
    # A primitive root: g^((p-1)/q) != 1 for every prime q dividing p-1, so the
    # discrete log is unique mod p-1 and the sealed exponent is unambiguous.
    g = 2
    while any(pow(g, (p - 1) // q, p) == 1 for q in prime_set):
        g += 1
    x = rng.randrange(2, p - 1)
    h = pow(g, x, p)

    artifacts = {
        "exchange.json": json.dumps({"p": str(p), "g": str(g), "h": str(h)},
                                    indent=1) + "\n",
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(f"{x:x}", flag),
        "README.md": (
            "# Key exchange transcript\n\n"
            "`exchange.json` is a Diffie-Hellman transcript over a prime field: the "
            "prime `p`, the base `g`, and one party's public value `h = g^x mod p`. "
            "The prime is about 210 bits.\n\n"
            "The operator's recovery blob is sealed under the private exponent `x` as "
            "lowercase hex with no leading zeros. `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("phsmooth", flag_secret, seed, generation),
        title="Key Exchange Transcript", category="crypto",
        challenge_type="smooth-order-discrete-log",
        story=("A Diffie-Hellman transcript over a roughly 210-bit prime field. The "
               "field size alone puts a direct discrete log out of reach; the prime's "
               "structure is another matter."),
        vulnerability=("p-1 is smooth, so Pohlig-Hellman reduces the log to tiny subgroup "
                       "logs, but the smoothness only shows once p-1 is factored"),
        solution=["do not attempt a direct log over a 200-bit group",
                  "factor p-1; discover it is smooth (small prime factors)",
                  "solve the log in each prime-power subgroup with baby-step giant-step",
                  "recombine the residues with the CRT to get x"],
        artifacts=artifacts,
        solver_files={"solver.py": _PHSMOOTH_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="phsmooth",
        rank=16, max_runtime_s=120, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# mqlin — a multivariate quadratic system that ships enough rows to linearise
# ---------------------------------------------------------------------------
MQ_BITS = 48
MQ_EXTRA = 90             # equations beyond the monomial count, for full rank

_MQLIN_SOLVER = '''\
"""Solve a multivariate-quadratic system that looks NP-hard and is not, here.

Brute force over the 48-bit key is a wall, and a quadratic system over GF(2) is
NP-hard in general. But this instance ships far more equations than it has
distinct monomials, which is the opening: LINEARISE. Treat every quadratic monomial
x_i*x_j as its own independent unknown alongside the linear x_i, and every equation
becomes linear over that enlarged variable set. One Gaussian elimination over GF(2)
solves it, and the values of the linear unknowns are the key bits.
"""
import json

doc = json.load(open("system.json", encoding="utf-8"))
n = doc["vars"]
equations = doc["equations"]

# Assign a column to every monomial that appears, plus a constant column.
col = {}


def column(mono):
    if mono not in col:
        col[mono] = len(col)
    return col[mono]


parsed = []
for eq in equations:
    bits = set()
    for mono in eq["m"]:
        bits ^= {column(mono)}
    parsed.append((bits, eq["r"]))

ncols = len(col)

rows = []
for bits, rhs in parsed:
    word = 0
    for c in bits:
        word |= 1 << c
    rows.append(word | (rhs << ncols))

# Gaussian elimination over GF(2); pivot on unknown columns 0..ncols-1.
where = [-1] * ncols
r = 0
for c in range(ncols):
    sel = next((i for i in range(r, len(rows)) if (rows[i] >> c) & 1), None)
    if sel is None:
        continue
    rows[r], rows[sel] = rows[sel], rows[r]
    for i in range(len(rows)):
        if i != r and (rows[i] >> c) & 1:
            rows[i] ^= rows[r]
    where[c] = r
    r += 1

sol = [0] * ncols
for c in range(ncols):
    if where[c] != -1:
        sol[c] = (rows[where[c]] >> ncols) & 1

key_bits = [sol[col[str(i)]] for i in range(n)]
key = bytes(int("".join(str(b) for b in key_bits[i:i + 8]), 2)
            for i in range(0, n, 8))

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), key.hex()))
'''


def gen_mqlin(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="mqlin", seed=seed, generation=generation,
                          secret=flag_secret)
    n = MQ_BITS
    quad = [(i, j) for i in range(n) for j in range(i + 1, n)]
    monomials = [str(i) for i in range(n)] + [f"{i}*{j}" for i, j in quad]
    n_mono = len(monomials)

    for attempt in range(4):
        rng = random.Random(f"mqlin:{flag_secret}:{seed}:{generation}:{attempt}")
        key_bits = [rng.randrange(2) for _ in range(n)]

        def value(mono):
            if "*" in mono:
                i, j = (int(t) for t in mono.split("*"))
                return key_bits[i] & key_bits[j]
            return key_bits[int(mono)]

        equations = []
        for _ in range(n_mono + MQ_EXTRA):
            support = rng.sample(monomials, rng.randrange(3, 12))
            rhs = 0
            for mono in support:
                rhs ^= value(mono)
            # The right-hand side already carries the affine part (it is the XOR of
            # the monomials' values at the true key), so no separate constant term
            # is needed and the all-zero assignment is not a solution.
            equations.append({"m": support, "r": rhs})

        # Rehearse the exact solve the player runs; ship only a determined system.
        if _mqlin_recovers(n, equations, key_bits):
            break
    else:                                                  # pragma: no cover
        raise RuntimeError("mqlin: system did not determine the key")

    key = bytes(int("".join(str(b) for b in key_bits[i:i + 8]), 2)
                for i in range(0, n, 8))
    rng2 = random.Random(f"mqlin-shuf:{flag_secret}:{seed}:{generation}")
    rng2.shuffle(equations)

    artifacts = {
        "system.json": json.dumps({
            "vars": n,
            "field": "GF(2)",
            "note": ("each equation is the XOR of the listed terms equal to r; a "
                     "term is 'i' for x_i or 'i*j' for the product x_i times x_j"),
            "equations": equations,
        }) + "\n",
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key.hex(), flag),
        "README.md": (
            "# Constraint system\n\n"
            f"`system.json` is a system of quadratic equations over GF(2) in {n} "
            "unknown bits x_0..x_{n-1}. Each equation is the XOR of the listed "
            "terms, equal to its right-hand side.\n\n"
            "The operator's recovery blob is sealed under the solution bits packed "
            "big-endian into bytes, as lowercase hex. `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("mqlin", flag_secret, seed, generation),
        title="Constraint System", category="crypto",
        challenge_type="mq-linearization",
        story=("A key is pinned by a large system of quadratic equations over GF(2). "
               "The system is all you are given; the key is what satisfies it."),
        vulnerability=("the system ships more equations than distinct monomials, so treating "
                       "each quadratic monomial as a free variable linearises it"),
        solution=["reject brute force over the 48-bit key",
                  "assign every quadratic monomial its own unknown",
                  "each equation is then linear over the enlarged variable set",
                  "Gaussian-eliminate over GF(2); the linear unknowns are the key"],
        artifacts=artifacts,
        solver_files={"solver.py": _MQLIN_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="mqlin",
        rank=18, max_runtime_s=120, flag_secret=flag_secret)


def _mqlin_recovers(n, equations, key_bits):
    """Run the shipped linearisation and confirm it reproduces the key bits."""
    col = {}

    def column(mono):
        if mono not in col:
            col[mono] = len(col)
        return col[mono]

    parsed = []
    for eq in equations:
        bits = set()
        for mono in eq["m"]:
            bits ^= {column(mono)}
        parsed.append((bits, eq["r"]))
    ncols = len(col)
    rows = []
    for bits, rhs in parsed:
        word = 0
        for c in bits:
            word |= 1 << c
        rows.append(word | (rhs << ncols))
    where = [-1] * ncols
    r = 0
    for c in range(ncols):
        sel = next((i for i in range(r, len(rows)) if (rows[i] >> c) & 1), None)
        if sel is None:
            continue                        # a quadratic monomial may stay free
        rows[r], rows[sel] = rows[sel], rows[r]
        for i in range(len(rows)):
            if i != r and (rows[i] >> c) & 1:
                rows[i] ^= rows[r]
        where[c] = r
        r += 1
    # Only the linear (key) columns must be pinned; free quadratic monomials are
    # fine because the key does not depend on them.
    if any(where[col[str(i)]] == -1 for i in range(n)):
        return False
    sol = [((rows[where[c]] >> ncols) & 1) if where[c] != -1 else 0
           for c in range(ncols)]
    return [sol[col[str(i)]] for i in range(n)] == key_bits


HARDTIER_BUILDERS = [gen_rswelch, gen_phsmooth, gen_mqlin]
