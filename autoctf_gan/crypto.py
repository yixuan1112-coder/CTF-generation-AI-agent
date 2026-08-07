"""Real Crypto category — RSA small-d (Wiener) — the third verified backend.

This is the sharpest demonstration of principle P1 ("the solver IS the attack"):
the official PoC is a full Wiener continued-fraction attack. If the Generator
degenerates the challenge by choosing a SAFE key (large d / normal e=65537), the
attack no longer recovers d, the PoC fails, and verify_spec REJECTS the spec.
So the Generator cannot profit from removing the weakness.

No build step: the PoC is pure Python arithmetic. Difficulty for a crypto
archetype is rotated by ATTACK CLASS (Wiener -> Boneh-Durfee -> partial-key),
not by modulus size (which would be entropy growth). Only Wiener is implemented
here as the reference; the co-evolution knob is documented in evolve/tournament.
"""
from __future__ import annotations

import hashlib
import random

from Crypto.Util.number import bytes_to_long, inverse, isPrime

from .models import ChainStep, ChallengeSpec, Lineage, OfficialSolver, Verdict


def _gen_prime(rng: random.Random, bits: int) -> int:
    while True:
        cand = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if isPrime(cand):
            return cand


def _flag_for(seed: int) -> str:
    return f"flag{{{hashlib.sha256(f'wiener::{seed}'.encode()).hexdigest()[:12]}}}"


# The PoC shipped as the official solver: a self-contained Wiener attack.
_WIENER_SOLVER = r'''
import hashlib, math

def read_int(name):
    return int(open(name).read().strip())

n = read_int("n.txt"); e = read_int("e.txt"); c = read_int("c.txt")

def convergents(a, b):
    cf = []
    while b:
        cf.append(a // b); a, b = b, a % b
    out = []
    for i in range(len(cf)):
        num, den = 1, 0
        for x in reversed(cf[: i + 1]):
            num, den = x * num + den, num
        out.append((num, den))   # num/den ~ e/n  ->  (k, d)
    return out

def wiener(e, n):
    for k, d in convergents(e, n):
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        b = n - phi + 1                 # x^2 - b x + n = 0  (x = p, q)
        disc = b * b - 4 * n
        if disc < 0:
            continue
        s = math.isqrt(disc)
        if s * s == disc and (b + s) % 2 == 0:
            return d
    return None

d = wiener(e, n)
assert d is not None, "Wiener attack failed (key not weak)"
m = pow(c, d, n)
length = (m.bit_length() + 7) // 8
flag = m.to_bytes(length, "big").decode(errors="replace")
assert flag.startswith("flag{"), "recovered plaintext is not a flag"
print(flag)
'''


def gen_rsa_wiener(*, seed: int, archetype_id: str = "crypto.rsa.wiener",
                   generation: int = 0, vulnerable: bool = True,
                   n_bits: int = 512, parent_spec_id: str | None = None,
                   mutation_ops: list[str] | None = None,
                   target_solve_rate: float = 0.05) -> ChallengeSpec:
    """Deterministic RSA challenge. vulnerable=True -> small d (Wiener applies)."""
    rng = random.Random(f"wiener:{seed}:{generation}")
    p = _gen_prime(rng, n_bits // 2)
    q = _gen_prime(rng, n_bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    flag = _flag_for(seed)
    m = bytes_to_long(flag.encode())

    if vulnerable:
        # small private exponent d < N^0.25 / 3  -> Wiener-vulnerable
        while True:
            d = _gen_prime(rng, n_bits // 4 - 8)
            if d < 1 or phi % d == 0:
                continue
            try:
                e = inverse(d, phi)
                break
            except ValueError:
                continue
    else:
        e = 65537
        d = inverse(e, phi)   # normal, safe key: Wiener will NOT recover d
    c = pow(m, e, n)

    expected_sha = hashlib.sha256(flag.encode()).hexdigest()
    slug = f"crypto-wiener-{seed:06d}-g{generation}"
    return ChallengeSpec(
        slug=slug, title=f"RSA Whisper (Gen-{generation})", category="crypto",
        challenge_type="rsa-wiener", difficulty="hard",
        story=("An RSA public key was chosen for speed, not safety. The public "
               "exponent looks enormous. Recover the message."),
        vulnerability="RSA with small private exponent d (Wiener's attack)",
        intended_solution=["expand e/N as a continued fraction",
                           "test convergents k/d", "recover d and decrypt"],
        hints=["The public exponent e is suspiciously large.",
               "Continued fractions relate e/N to k/d."],
        delivery="crypto", seed=seed,
        mechanics={"attack_class": "wiener", "n_bits": n_bits, "vulnerable": vulnerable},
        flag=flag, spec_id=f"{slug}-{expected_sha[:8]}",
        lineage=Lineage(archetype_id=archetype_id, generation=generation,
                        parent_spec_id=parent_spec_id, mutation_ops=mutation_ops or [],
                        seed=seed),
        vuln_chain=[ChainStep(step=1, primitive="wiener_continued_fraction",
                              params={"n_bits": n_bits}, guard="large-public-exponent")],
        artifacts={"n.txt": str(n), "e.txt": str(e), "c.txt": str(c),
                   "README.md": "# RSA\n\nGiven n, e, c recover the flag."},
        official_solver=OfficialSolver(entry="solver.py",
                                       files={"solver.py": _WIENER_SOLVER},
                                       expected_flag_sha256=expected_sha, max_runtime_s=30),
        target_solve_rate=target_solve_rate,
    )


def build_and_verify_crypto(spec: ChallengeSpec) -> Verdict:
    """Run the attack PoC (no build). Same contract as the other backends."""
    import subprocess
    import sys
    import tempfile
    import time
    from pathlib import Path

    expected = spec.official_solver.expected_flag_sha256
    checks: list[str] = []
    failures: list[str] = []
    secs = None
    with tempfile.TemporaryDirectory(prefix="autoctf-crypto-") as tmp:
        root = Path(tmp)
        for rel, content in {**spec.artifacts, **spec.official_solver.files}.items():
            (root / rel).write_text(content, encoding="utf-8")
        # leak gate: the flag must not sit in any published artifact
        leak_ok = not any(spec.flag in v for v in spec.artifacts.values())
        checks.append("flag absent from published key material") if leak_ok else \
            failures.append("flag leaked into artifacts")
        # the PoC (the attack itself) must recover the flag
        t0 = time.monotonic()
        run = subprocess.run([sys.executable, spec.official_solver.entry], cwd=root,
                             capture_output=True, text=True,
                             timeout=spec.official_solver.max_runtime_s)
        secs = time.monotonic() - t0
        recovered = run.stdout.strip()
        poc_ok = run.returncode == 0 and \
            hashlib.sha256(recovered.encode()).hexdigest() == expected
        checks.append(f"Wiener attack recovered the flag in {secs:.3f}s") if poc_ok else \
            failures.append(f"attack failed (key not weak / unsolvable): "
                            f"{(run.stderr or run.stdout).strip()[:120]}")
        det_ok = poc_ok  # deterministic pure arithmetic

    valid = poc_ok and leak_ok
    reason = "valid" if valid else "; ".join(failures) or "rejected"
    spec.verification.status = "valid" if valid else "rejected"
    spec.verification.poc_passed = poc_ok
    spec.verification.leak_gates_passed = leak_ok
    spec.verification.determinism_runs = 1 if poc_ok else 0
    spec.verification.measured_solve_time_s = secs if poc_ok else None
    spec.verification.rejection_reason = None if valid else reason
    return Verdict(valid, reason, poc_time_s=secs if poc_ok else None,
                   checks=checks, failures=failures)
