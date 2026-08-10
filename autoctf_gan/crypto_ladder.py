"""Crypto co-evolution ladder — attack-CLASS rotation across generations.

Difficulty for a crypto archetype cannot come from bigger moduli (that is entropy
growth, forbidden by P3). It comes from rotating to a harder ATTACK CLASS. Each
rung ships a real, self-contained PoC that verify_spec runs and checks:

  rank 0  small-e cube root         (unpadded RSA, m^e < n)
  rank 1  Håstad broadcast          (same m, e=3, three moduli, CRT + cube root)
  rank 2  common modulus            (same n, coprime e1,e2 -> Bézout)
  rank 3  Wiener                    (small private exponent d)
  rank 4  Fermat                    (primes too close -> factor by difference)

The simulated attacker pool models escalating field difficulty via the rung
index (spec.intended_depth = rank+1), exactly like the `reverse` rounds ladder;
every rung remains genuinely solvable because its paired attack is verified.
Removing the weakness at any rung makes that rung's PoC fail -> spec rejected (P1).
"""
from __future__ import annotations

import hashlib
import math
import random

from Crypto.Util.number import bytes_to_long, inverse, isPrime

from .crypto import _flag_for, _gen_prime
from .models import ChainStep, ChallengeSpec, Lineage, OfficialSolver

# integer k-th root, shared by the cube-root PoCs
_IROOT = '''
def iroot(x, k):
    if x < 0: return 0
    hi = 1
    while hi ** k <= x: hi <<= 1
    lo = hi >> 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x: lo = mid
        else: hi = mid - 1
    return lo
'''

_TAIL = '''
flag = m.to_bytes((m.bit_length() + 7) // 8, "big").decode(errors="replace")
assert flag.startswith("flag{"), "recovered plaintext is not a flag"
print(flag)
'''


def _keypair(rng, bits, e):
    """RSA key with gcd(e, phi) == 1."""
    while True:
        p = _gen_prime(rng, bits // 2)
        q = _gen_prime(rng, bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e:
            return p, q, p * q, phi


def _spec(*, seed, generation, rank, challenge_type, story, vuln, solution,
          hints, artifacts, solver_src, flag, archetype_id, parent_spec_id,
          mutation_ops, attack_class, target_solve_rate, extra_solver_files=None):
    expected = hashlib.sha256(flag.encode()).hexdigest()
    slug = f"crypto-{attack_class}-{seed:06d}-g{generation}"
    solver_files = {"solver.py": solver_src, **(extra_solver_files or {})}
    return ChallengeSpec(
        slug=slug, title=f"RSA {attack_class.title()} (Gen-{generation})",
        category="crypto", challenge_type=challenge_type, difficulty="hard",
        story=story, vulnerability=vuln, intended_solution=solution, hints=hints,
        delivery="crypto", seed=seed,
        mechanics={"attack_class": attack_class, "rank": rank},
        flag=flag, spec_id=f"{slug}-{expected[:8]}",
        lineage=Lineage(archetype_id=archetype_id, generation=generation,
                        parent_spec_id=parent_spec_id, mutation_ops=mutation_ops or [],
                        seed=seed),
        # intended_depth = rank+1 drives the attacker-pool difficulty curve
        vuln_chain=[ChainStep(step=i + 1, primitive=f"{attack_class}_stage",
                              params={}, guard="crypto") for i in range(rank + 1)],
        artifacts=artifacts,
        official_solver=OfficialSolver(entry="solver.py", files=solver_files,
                                       expected_flag_sha256=expected, max_runtime_s=90),
        target_solve_rate=target_solve_rate,
    )


def _common(seed, generation, archetype_id, parent_spec_id, mutation_ops, tsr):
    # seed/generation are passed positionally to the builder; keep them out here
    return dict(archetype_id=archetype_id, parent_spec_id=parent_spec_id,
                mutation_ops=mutation_ops, target_solve_rate=tsr)


# --- rank 0: small-e cube root ---------------------------------------------
def gen_smalle(seed, generation, **kw):
    rng = random.Random(f"smalle:{seed}:{generation}")
    flag = _flag_for(seed)
    m = bytes_to_long(flag.encode())
    e = 3
    p, q, n, phi = _keypair(rng, 1024, e)   # big n so m^3 < n (no reduction)
    c = pow(m, e, n)
    solver = ("n=int(open('n.txt').read());e=int(open('e.txt').read());"
              "c=int(open('c.txt').read())\n" + _IROOT +
              "m=iroot(c,e)\nassert m**e==c, 'not an unpadded cube'\n" + _TAIL)
    art = {"n.txt": str(n), "e.txt": str(e), "c.txt": str(c),
           "README.md": "# RSA\n\nn, e, c. The exponent is tiny."}
    return _spec(rank=0, challenge_type="rsa-smalle", attack_class="smalle",
                 story="RSA with a tiny public exponent and no padding.",
                 vuln="unpadded RSA, m^e < n (direct e-th root)",
                 solution=["take the integer e-th root of c"],
                 hints=["e is very small.", "No padding means m^e might be < n."],
                 artifacts=art, solver_src=solver, flag=flag, seed=seed, generation=generation, **kw)


# --- rank 1: Håstad broadcast (e=3, three moduli) --------------------------
def gen_hastad(seed, generation, **kw):
    rng = random.Random(f"hastad:{seed}:{generation}")
    flag = _flag_for(seed)
    m = bytes_to_long(flag.encode())
    e = 3
    ns, cs = [], []
    for _ in range(3):
        _, _, n, _ = _keypair(rng, 1024, e)
        ns.append(n); cs.append(pow(m, e, n))
    solver = (
        "from functools import reduce\n"
        "ns=[int(open(f'n{i}.txt').read()) for i in range(3)]\n"
        "cs=[int(open(f'c{i}.txt').read()) for i in range(3)]\n"
        "def crt(r,mod):\n"
        "    M=reduce(lambda a,b:a*b,mod);x=0\n"
        "    for ri,mi in zip(r,mod):\n"
        "        Mi=M//mi;x+=ri*Mi*pow(Mi,-1,mi)\n"
        "    return x%M\n"
        "M=crt(cs,ns)\n" + _IROOT + "m=iroot(M,3)\nassert m**3==M\n" + _TAIL)
    art = {"README.md": "# RSA broadcast\n\nSame message, e=3, three public keys."}
    for i in range(3):
        art[f"n{i}.txt"] = str(ns[i]); art[f"c{i}.txt"] = str(cs[i])
    return _spec(rank=1, challenge_type="rsa-hastad", attack_class="hastad",
                 story="The same message was broadcast to three recipients with e=3.",
                 vuln="Håstad broadcast: CRT over three cubes then a cube root",
                 solution=["CRT-combine the three ciphertexts", "take the cube root"],
                 hints=["Same plaintext, three moduli.", "e = 3."],
                 artifacts=art, solver_src=solver, flag=flag, seed=seed, generation=generation, **kw)


# --- rank 2: common modulus -------------------------------------------------
def gen_commonmod(seed, generation, **kw):
    rng = random.Random(f"commonmod:{seed}:{generation}")
    flag = _flag_for(seed)
    m = bytes_to_long(flag.encode())
    e1, e2 = 3, 5
    while True:
        p = _gen_prime(rng, 512); q = _gen_prime(rng, 512)
        phi = (p - 1) * (q - 1)
        if phi % e1 and phi % e2:
            break
    n = p * q
    c1, c2 = pow(m, e1, n), pow(m, e2, n)
    solver = (
        "n=int(open('n.txt').read());e1=int(open('e1.txt').read());"
        "e2=int(open('e2.txt').read())\n"
        "c1=int(open('c1.txt').read());c2=int(open('c2.txt').read())\n"
        "def egcd(a,b):\n"
        "    if b==0:return a,1,0\n"
        "    g,x,y=egcd(b,a%b);return g,y,x-(a//b)*y\n"
        "g,a,b=egcd(e1,e2)\n"
        "if a<0:c1=pow(c1,-1,n);a=-a\n"
        "if b<0:c2=pow(c2,-1,n);b=-b\n"
        "m=pow(c1,a,n)*pow(c2,b,n)%n\n" + _TAIL)
    art = {"n.txt": str(n), "e1.txt": str(e1), "e2.txt": str(e2),
           "c1.txt": str(c1), "c2.txt": str(c2),
           "README.md": "# RSA\n\nOne modulus, two exponents, two ciphertexts."}
    return _spec(rank=2, challenge_type="rsa-commonmod", attack_class="commonmod",
                 story="One message, one modulus, encrypted twice with different exponents.",
                 vuln="common modulus with coprime exponents (Bézout combination)",
                 solution=["egcd(e1,e2)=1", "combine c1^a * c2^b mod n"],
                 hints=["Same n, two exponents.", "gcd(e1,e2)=1."],
                 artifacts=art, solver_src=solver, flag=flag, seed=seed, generation=generation, **kw)


# --- rank 3: Wiener (small d) ----------------------------------------------
def gen_wiener_rung(seed, generation, **kw):
    from .crypto import _WIENER_SOLVER
    rng = random.Random(f"wiener-rung:{seed}:{generation}")
    flag = _flag_for(seed)
    m = bytes_to_long(flag.encode())
    p = _gen_prime(rng, 256); q = _gen_prime(rng, 256)
    n = p * q; phi = (p - 1) * (q - 1)
    while True:
        d = _gen_prime(rng, 256 // 2 - 8)
        if phi % d:
            try:
                e = inverse(d, phi); break
            except ValueError:
                pass
    c = pow(m, e, n)
    art = {"n.txt": str(n), "e.txt": str(e), "c.txt": str(c),
           "README.md": "# RSA\n\nThe public exponent looks enormous."}
    return _spec(rank=3, challenge_type="rsa-wiener", attack_class="wiener",
                 story="An RSA key was chosen for fast decryption, not safety.",
                 vuln="small private exponent d (Wiener continued-fraction attack)",
                 solution=["expand e/N as a continued fraction", "test convergents"],
                 hints=["e is suspiciously large.", "Continued fractions relate e/N to k/d."],
                 artifacts=art, solver_src=_WIENER_SOLVER, flag=flag, seed=seed, generation=generation, **kw)


# --- rank 4: Fermat (primes too close) -------------------------------------
def _next_prime(x):
    x |= 1
    while not isPrime(x):
        x += 2
    return x


def gen_fermat(seed, generation, **kw):
    rng = random.Random(f"fermat:{seed}:{generation}")
    flag = _flag_for(seed)
    m = bytes_to_long(flag.encode())
    e = 65537
    while True:
        p = _gen_prime(rng, 512)
        q = _next_prime(p + rng.randint(2, 1 << 20))   # q close to p -> Fermat
        phi = (p - 1) * (q - 1)
        if phi % e:
            break
    n = p * q
    c = pow(m, e, n)
    solver = (
        "import math\n"
        "n=int(open('n.txt').read());e=int(open('e.txt').read());"
        "c=int(open('c.txt').read())\n"
        "a=math.isqrt(n)\n"
        "if a*a<n: a+=1\n"
        "for _ in range(1<<22):\n"
        "    b2=a*a-n;b=math.isqrt(b2)\n"
        "    if b*b==b2: break\n"
        "    a+=1\n"
        "else:\n"
        "    raise SystemExit('fermat: primes not close enough')\n"
        "p=a+b;q=a-b;phi=(p-1)*(q-1);d=pow(e,-1,phi);m=pow(c,d,n)\n" + _TAIL)
    art = {"n.txt": str(n), "e.txt": str(e), "c.txt": str(c),
           "README.md": "# RSA\n\nStandard RSA. Or is the modulus?"}
    return _spec(rank=4, challenge_type="rsa-fermat", attack_class="fermat",
                 story="A normal-looking RSA key — but the primes were generated carelessly.",
                 vuln="close primes (Fermat factorization by difference of squares)",
                 solution=["a = ceil(sqrt(n))", "increment until a^2 - n is a square"],
                 hints=["The primes may be close together.", "Difference of squares."],
                 artifacts=art, solver_src=solver, flag=flag, seed=seed, generation=generation, **kw)


# --- rank 5: Pollard p-1 (smooth p-1) --------------------------------------
def _smooth_prime(rng, bits, B):
    small = [i for i in range(2, B) if isPrime(i)]
    while True:
        m = 1
        while m.bit_length() < bits - 1:
            m *= rng.choice(small)
        p = m + 1
        if p.bit_length() == bits and isPrime(p):
            return p


def gen_pollard(seed, generation, **kw):
    rng = random.Random(f"pollard:{seed}:{generation}")
    flag = _flag_for(seed)
    m = bytes_to_long(flag.encode())
    e = 65537
    B = 150
    while True:
        p = _smooth_prime(rng, 256, B)   # p-1 is B-smooth -> Pollard p-1 works
        q = _gen_prime(rng, 256)
        phi = (p - 1) * (q - 1)
        if phi % e:
            break
    n = p * q
    c = pow(m, e, n)
    solver = (
        "import math\n"
        "n=int(open('n.txt').read());e=int(open('e.txt').read());"
        "c=int(open('c.txt').read())\n"
        "def pollard(N,B=4000):\n"
        "    a=2\n"
        "    for j in range(2,B):\n"
        "        a=pow(a,j,N);d=math.gcd(a-1,N)\n"
        "        if 1<d<N: return d\n"
        "    return None\n"
        "p=pollard(n)\nassert p and n%p==0, 'pollard p-1 failed (p-1 not smooth)'\n"
        "q=n//p;phi=(p-1)*(q-1);d=pow(e,-1,phi);m=pow(c,d,n)\n" + _TAIL)
    art = {"n.txt": str(n), "e.txt": str(e), "c.txt": str(c),
           "README.md": "# RSA\n\nStandard-looking key. One prime was chosen unwisely."}
    return _spec(rank=5, challenge_type="rsa-pollard", attack_class="pollard",
                 story="An RSA prime was generated so that p-1 has only small factors.",
                 vuln="smooth p-1 (Pollard's p-1 factorization)",
                 solution=["a = 2^(k!) mod n", "gcd(a-1, n) reveals a factor"],
                 hints=["One prime is 'smooth minus one'.", "Pollard's p-1."],
                 artifacts=art, solver_src=solver, flag=flag,
                 seed=seed, generation=generation, **kw)


# --- rank 6: Boneh-Durfee (small d beyond Wiener, lattice attack) -----------
def _fpylll_available() -> bool:
    try:
        import fpylll  # noqa: F401
        return True
    except Exception:
        return False


def _wiener_recovers(e: int, n: int, d: int) -> bool:
    """Does the Gen-3 attack already crack this key?

    d sits at N^0.255, only just past Wiener's N^0.25 bound, and Wiener's
    continued-fraction search succeeds a little beyond it depending on how the
    expansion falls — empirically on roughly 5% of instances. Raising d is not an
    option: measured across a seed sweep, the shipped Boneh-Durfee attack
    (delta=0.28, mm=5) recovers d reliably at 0.255 and not at all by 0.265, so a
    larger d would leave the rung unsolvable and verify_spec would reject it.

    So instead the generator re-rolls the key. Without this, ~1 team in 20 gets a
    boss rung its Wiener stage alone can beat, and since the arena ranks on depth
    first, that luck decides the top of the leaderboard.
    """
    cf, a, b = [], e, n
    while b:
        cf.append(a // b)
        a, b = b, a % b
    for i in range(len(cf)):
        num, den = 1, 0
        for x in reversed(cf[: i + 1]):
            num, den = x * num + den, num
        k, cand = num, den
        if k == 0 or (e * cand - 1) % k:
            continue
        phi = (e * cand - 1) // k
        bb = n - phi + 1
        disc = bb * bb - 4 * n
        if disc >= 0:
            root = math.isqrt(disc)
            if root * root == disc:
                return cand == d
    return False


def gen_boneh_durfee(seed, generation, **kw):
    import inspect

    from . import lattice
    rng = random.Random(f"bonehdurfee:{seed}:{generation}")
    flag = _flag_for(seed)
    m = bytes_to_long(flag.encode())
    nbits = 512
    while True:
        p = _gen_prime(rng, nbits // 2)
        q = _gen_prime(rng, nbits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        d = _gen_prime(rng, int(nbits * 0.255))   # d ~ N^0.255, past Wiener's N^0.25
        if phi % d == 0:
            continue
        try:
            e = inverse(d, phi)
        except ValueError:
            continue
        if _wiener_recovers(e, n, d):             # the previous rung must not suffice
            continue
        break
    c = pow(m, e, n)
    lattice_src = inspect.getsource(lattice)
    solver = (
        "from lattice import boneh_durfee\n"
        "n=int(open('n.txt').read());e=int(open('e.txt').read());"
        "c=int(open('c.txt').read())\n"
        "res=boneh_durfee(n,e,delta=0.28,mm=5)\n"
        "assert res, 'Boneh-Durfee failed (d not small enough)'\n"
        "p,q=res;phi=(p-1)*(q-1);d=pow(e,-1,phi);m=pow(c,d,n)\n" + _TAIL)
    art = {"n.txt": str(n), "e.txt": str(e), "c.txt": str(c),
           "README.md": "# RSA\n\nDecryption is suspiciously fast. Recover the flag."}
    return _spec(rank=6, challenge_type="rsa-boneh-durfee", attack_class="bonehdurfee",
                 story="An RSA key uses a small private exponent — smaller than Wiener can reach.",
                 vuln="small private exponent d < N^0.29 (Boneh-Durfee lattice attack)",
                 solution=["build the Boneh-Durfee lattice", "LLL-reduce", "resultant -> factor N"],
                 hints=["d is small but beyond Wiener's bound.", "Lattices (Coppersmith/Boneh-Durfee)."],
                 artifacts=art, solver_src=solver, flag=flag,
                 seed=seed, generation=generation,
                 extra_solver_files={"lattice.py": lattice_src}, **kw)


CRYPTO_LADDER = [gen_smalle, gen_hastad, gen_commonmod, gen_wiener_rung,
                 gen_fermat, gen_pollard]
LADDER_NAMES = ["smalle", "hastad", "commonmod", "wiener", "fermat", "pollard"]
if _fpylll_available():
    CRYPTO_LADDER.append(gen_boneh_durfee)
    LADDER_NAMES.append("bonehdurfee")


def gen_crypto_ladder(*, seed: int, generation: int = 0,
                      archetype_id: str = "crypto.ladder",
                      parent_spec_id: str | None = None,
                      mutation_ops: list[str] | None = None,
                      target_solve_rate: float = 0.05) -> ChallengeSpec:
    rung = min(generation, len(CRYPTO_LADDER) - 1)
    builder = CRYPTO_LADDER[rung]
    return builder(seed, generation, **_common(seed, generation, archetype_id,
                                               parent_spec_id, mutation_ops,
                                               target_solve_rate))


def mutate_crypto(parent: ChallengeSpec) -> ChallengeSpec:
    """Rotate to the next (harder) attack class; re-pairs the PoC (P1)."""
    return gen_crypto_ladder(seed=parent.seed, generation=parent.lineage.generation + 1,
                             archetype_id=parent.lineage.archetype_id,
                             parent_spec_id=parent.spec_id,
                             mutation_ops=["rotate_attack_class"],
                             target_solve_rate=parent.target_solve_rate)
