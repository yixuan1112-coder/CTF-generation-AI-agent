"""Compute walls — the terminal point of "harder until the AI cannot solve it".

Every other rung in this catalogue ships a deterministic solver, because the
platform proves solvability by running one. That is exactly why none of them is
literally unsolvable by a machine: an agent that reproduces the algorithm clears
it. These are different in kind. Their intended solution is an unbroken hard
problem — factoring, elliptic-curve discrete log — at a size where no known method
finishes in any feasible time, for a person or a machine alike.

They are still marked solvable to the platform, because the official checker uses
an organizer TRAPDOOR (the known factorization, the known scalar) that never ships
to a player. The player gets only the wall. There is no hidden weakness to find
and no trick to spot; the honesty of the rung is that the cost is real. Solving one
would be a cryptographic result, not a CTF solve.

This is where "make it harder" ends. Past here, harder means breaking RSA or the
elliptic-curve discrete log, and no prompt makes that cheaper.

  rsawall    Factor a 2048-bit RSA modulus. The flag is sealed under its smaller
             prime factor. RSA-2048 is unfactored.
  ecdlpwall  Recover a secp256k1 private scalar from its public point. The best
             known attack is ~2**128 group operations.

Its sibling `dlogwall` (a 320-bit safe-prime discrete log) rounds out the three
classical hard problems. None writes the flag into a player artifact.
"""
from __future__ import annotations

import hashlib

from .curves import SECP256K1_A, SECP256K1_G, SECP256K1_N, SECP256K1_P, mul
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
        lineage=Lineage(archetype_id=f"walls.{attack_class}", generation=generation,
                        parent_spec_id=None, mutation_ops=[], seed=seed),
        vuln_chain=[ChainStep(step=1, primitive=f"{attack_class}_stage",
                              params={}, guard="crypto")],
        artifacts=artifacts,
        official_solver=OfficialSolver(entry="solver.py", files=solver_files,
                                       expected_flag_sha256=expected,
                                       max_runtime_s=max_runtime_s),
        target_solve_rate=0.0)


def _slug(kind, flag_secret, seed, generation):
    tag = hashlib.sha256(f"{kind}:{flag_secret}:{seed}:{generation}".encode()).hexdigest()[:8]
    return f"wall-{kind}-g{generation}-{tag}"


# ---------------------------------------------------------------------------
# rsawall — factor a 2048-bit modulus
# ---------------------------------------------------------------------------
RSA_BITS = 2048


def _rsa_primes_cached(flag_secret, seed, generation, cache_dir):
    """Two ~1024-bit primes for this challenge, generated once and cached.

    Same bargain as the dlog safe prime: the prime search is the only slow step
    and it would otherwise recur on every catalogue rebuild. The primes are a
    function of the seed, so a stale or missing cache is only slower, never wrong.
    """
    import json
    import random
    from pathlib import Path

    from Crypto.Util.number import isPrime

    tag = hashlib.sha256(
        f"rsa-primes:{flag_secret}:{seed}:{generation}:{RSA_BITS}".encode()).hexdigest()[:16]
    path = Path(cache_dir) / f"rsawall-{tag}.json" if cache_dir else None
    if path is not None:
        try:
            data = json.loads(path.read_text())
            if data.get("bits") == RSA_BITS:
                return int(data["p"]), int(data["q"])
        except (FileNotFoundError, ValueError, KeyError):
            pass

    rng = random.Random(f"rsawall:{flag_secret}:{seed}:{generation}")

    def det_prime(bits):
        while True:
            cand = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
            if isPrime(cand):
                return cand

    half = RSA_BITS // 2
    p = det_prime(half)
    q = det_prime(half)
    while q == p:                                   # astronomically unlikely, but exact
        q = det_prime(half)
    if path is not None:
        try:
            path.write_text(json.dumps({"bits": RSA_BITS, "p": str(p), "q": str(q)}))
        except OSError:
            pass
    return p, q


def gen_rsawall(seed, generation, cache_dir=None, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="rsawall", seed=seed, generation=generation,
                          secret=flag_secret)
    p, q = _rsa_primes_cached(flag_secret, seed, generation, cache_dir)
    n = p * q
    e = 65537
    smaller = min(p, q)

    # Trapdoor checker: the organizer knows the factorization, so the flag can be
    # unsealed for verification. Players never see this file — they get only n.
    solver = (
        "from sealed import unseal\n"
        f"p = {smaller}\n"
        "with open('flag.enc', encoding='utf-8') as fh:\n"
        "    flag = unseal(fh.read(), str(p))\n"
        "assert flag.startswith('flag{'), 'recovered plaintext is not a flag'\n"
        "print(flag)\n")

    artifacts = {
        "key.txt": (f"# RSA public modulus\n"
                    f"n = {n}\n"
                    f"e = {e}\n"
                    f"# n = p*q with p, q prime and about {RSA_BITS // 2} bits each.\n"),
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(str(smaller), flag),
        "README.md": (
            "# Recovered public key\n\n"
            f"`key.txt` is a {RSA_BITS}-bit RSA public modulus `n = p*q` and its "
            "public exponent. Nothing else about the key was recovered.\n\n"
            "The recovery blob is sealed under the smaller prime factor of `n`, in "
            "decimal; `sealed.py` opens it. The modulus has no deliberate weakness — "
            "the factors are balanced, random, and far apart — so recovering the "
            "factor means factoring `n`.\n"),
    }
    return _spec(
        slug=_slug("rsawall", flag_secret, seed, generation),
        title="Recovered Public Key", category="crypto", challenge_type="rsa-factoring",
        story=("A 2048-bit RSA public modulus was recovered with no private material. "
               "The key has no deliberate weakness; the factors are balanced and random."),
        vulnerability="integer factorization of a 2048-bit balanced RSA modulus (no weakness)",
        solution=["factor the 2048-bit modulus n = p*q",
                  "the flag is sealed under the smaller prime factor"],
        artifacts=artifacts,
        solver_files={"solver.py": solver, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="rsawall",
        rank=45, max_runtime_s=60, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# ecdlpwall — recover a secp256k1 scalar from its public point
# ---------------------------------------------------------------------------
def gen_ecdlpwall(seed, generation, **kw):
    import random

    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="ecdlpwall", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"ecdlpwall:{flag_secret}:{seed}:{generation}")
    d = rng.randrange(1 << 250, SECP256K1_N - 1)      # full-size scalar, no bias
    Px, Py = mul(d, SECP256K1_G, SECP256K1_A, SECP256K1_P)

    solver = (
        "from sealed import unseal\n"
        f"d = {d}\n"
        "with open('flag.enc', encoding='utf-8') as fh:\n"
        "    flag = unseal(fh.read(), str(d))\n"
        "assert flag.startswith('flag{'), 'recovered plaintext is not a flag'\n"
        "print(flag)\n")

    artifacts = {
        "point.txt": (
            "# secp256k1 public key\n"
            "curve = secp256k1\n"
            f"Gx = {SECP256K1_G[0]}\n"
            f"Gy = {SECP256K1_G[1]}\n"
            f"Px = {Px}\n"
            f"Py = {Py}\n"
            "# P = d*G; recover the scalar d. The flag is sealed under d (decimal).\n"),
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(str(d), flag),
        "README.md": (
            "# secp256k1 public key\n\n"
            "`point.txt` gives the standard secp256k1 base point `G` and a public "
            "point `P = d*G` on the curve. Recover the private scalar `d`.\n\n"
            "The recovery blob is sealed under `d` in decimal; `sealed.py` opens it. "
            "The scalar is full-length and unbiased — the only route is the "
            "elliptic-curve discrete log itself.\n"),
    }
    return _spec(
        slug=_slug("ecdlpwall", flag_secret, seed, generation),
        title="secp256k1 Public Key", category="crypto", challenge_type="ecdlp",
        story=("A secp256k1 public point P = d*G was published. The scalar is full "
               "length and carries no bias or structure; only the elliptic-curve "
               "discrete log recovers it."),
        vulnerability="elliptic-curve discrete log on secp256k1 (~2**128 best known attack)",
        solution=["solve the elliptic-curve discrete log P = d*G on secp256k1",
                  "the flag is sealed under the scalar d"],
        artifacts=artifacts,
        solver_files={"solver.py": solver, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="ecdlpwall",
        rank=48, max_runtime_s=60, flag_secret=flag_secret)


WALLS_BUILDERS = [gen_rsawall, gen_ecdlpwall]
