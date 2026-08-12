"""Real gcc-compiled challenge category (Pwn/Reverse) — the production build swap-in.

This replaces the reversible-transform reference substrate with an actual native
binary, exercising the §8.2 compilation pipeline end-to-end:

    Generator emits C source + build flags
        -> gcc compiles a stripped, optimized binary
        -> official PoC runs the binary and recovers the flag
        -> verify gate: strings(binary) must NOT contain the flag (obfuscation
           actually works), wrong keys must NOT leak it, solver must recover it.

The flag is XOR-obfuscated in the binary with a keystream derived from the
correct key via R rounds (R = structural difficulty; growing R is entropy-free —
the key length is fixed). The Python generator and the C runtime implement the
SAME keystream so the stored `enc[]` decodes correctly at runtime.
"""
from __future__ import annotations

import hashlib
import random
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .identity import challenge_flag, challenge_secret, public_slug
from .models import (ChainStep, ChallengeSpec, Lineage, OfficialSolver, Verdict)

_MASK = 0xFFFFFFFF


# ---- shared keystream (must match the C code below byte-for-byte) ----------
def _mix_state(password: bytes, rounds: int) -> int:
    state = 0x811C9DC5
    for _ in range(rounds):
        for b in password:
            state = ((state ^ b) * 16777619) & _MASK
    return state


def _keystream(state: int, n: int) -> bytes:
    s, out = state, bytearray()
    for _ in range(n):
        s ^= (s << 13) & _MASK
        s ^= (s >> 17)
        s ^= (s << 5) & _MASK
        s &= _MASK
        out.append(s & 0xFF)
    return bytes(out)


# Placeholder replacement (not str.format) because C source is full of braces.
_C_TEMPLATE = r"""
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static const unsigned char ENC[] = { __ENC__ };
static const int ENCLEN = __ENCLEN__;
static const int ROUNDS = __ROUNDS__;

static uint32_t mix_state(const char *pw) {
    uint32_t state = 0x811c9dc5u;
    int L = (int)strlen(pw);
    for (int r = 0; r < ROUNDS; r++)
        for (int i = 0; i < L; i++)
            state = (state ^ (unsigned char)pw[i]) * 16777619u;
    return state;
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: %s <key>\n", argv[0]); return 1; }
    uint32_t s = mix_state(argv[1]);
    char dec[128];
    for (int i = 0; i < ENCLEN; i++) {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;
        dec[i] = ENC[i] ^ (unsigned char)(s & 0xff);
    }
    dec[ENCLEN] = 0;
    if (ENCLEN >= 5 && dec[0]=='f' && dec[1]=='l' && dec[2]=='a' && dec[3]=='g' && dec[4]=='{') {
        printf("%s\n", dec);
        return 0;
    }
    printf("Access denied\n");
    return 2;
}
"""


def gen_compiled_crackme(*, seed: int, archetype_id: str = "reverse.crackme",
                         generation: int = 0, rounds: int | None = None,
                         parent_spec_id: str | None = None,
                         mutation_ops: list[str] | None = None,
                         target_solve_rate: float = 0.05,
                         flag_secret: str = "") -> ChallengeSpec:
    """Deterministic native crackme. `rounds` = structural difficulty knob."""
    # Both the flag and the intended password are bound to the generation and to
    # the per-match secret. They used to be sha256 of the seed alone, so every
    # round of a climb shipped the same flag and the same password.
    flag = challenge_flag(kind="crackme", seed=seed, generation=generation,
                          secret=flag_secret)
    password = challenge_secret(kind="crackme-key", seed=seed, generation=generation,
                                secret=flag_secret)
    rounds = rounds if rounds is not None else 2 + generation
    ks = _keystream(_mix_state(password.encode(), rounds), len(flag))
    enc = bytes(f ^ k for f, k in zip(flag.encode(), ks))
    enc_c = ", ".join(str(b) for b in enc)
    c_source = (_C_TEMPLATE
                .replace("__ENC__", enc_c)
                .replace("__ENCLEN__", str(len(flag)))
                .replace("__ROUNDS__", str(rounds)))
    expected_sha = hashlib.sha256(flag.encode()).hexdigest()

    solver_src = (
        "import hashlib, subprocess, sys\n"
        f"PW = {password!r}   # organizer-known intended key (kept out of public view)\n"
        "out = subprocess.run(['./crackme', PW], capture_output=True, text=True).stdout.strip()\n"
        f"assert hashlib.sha256(out.encode()).hexdigest() == {expected_sha!r}, 'flag mismatch'\n"
        "print(out)\n"
    )

    difficulty = "hard" if rounds >= 4 else ("medium" if rounds >= 2 else "easy")
    slug = public_slug(base="reverse-crackme", seed=seed, generation=generation,
                       secret=flag_secret)
    depth = rounds  # modeled intended depth = key-schedule rounds
    return ChallengeSpec(
        slug=slug,
        title=f"Crackme (R={rounds}, Gen-{generation})",
        category="reverse",
        challenge_type="crackme",
        difficulty=difficulty,
        story=("A stripped binary guards a flag behind a key schedule. The flag is "
               "not stored in the clear; recover the key to let the binary decode it."),
        vulnerability=f"{rounds}-round FNV/xorshift key schedule; flag XOR-obfuscated in .rodata",
        intended_solution=[f"recover the {rounds}-round key schedule",
                           "supply the key so the binary decodes the flag"],
        hints=["The flag never appears in `strings` output.",
               "Difficulty is the number of schedule rounds, not the key length."],
        delivery="binary",
        seed=seed,
        mechanics={"build": {"compiler": "gcc", "source": "crackme.c",
                             "output": "crackme", "flags": ["-O2", "-s"],
                             "rounds": rounds},
                   "password_len": len(password)},
        flag=flag,
        spec_id=slug,
        lineage=Lineage(archetype_id=archetype_id, generation=generation,
                        parent_spec_id=parent_spec_id, mutation_ops=mutation_ops or [],
                        seed=seed),
        vuln_chain=[ChainStep(step=i + 1, primitive="key_schedule_round",
                              params={"round": i + 1}, guard="stripped-symbols")
                    for i in range(rounds)],
        artifacts={"crackme.c": c_source,
                   "README.md": "# Crackme\n\nRecover the flag from the provided binary."},
        official_solver=OfficialSolver(entry="solver.py",
                                       files={"solver.py": solver_src},
                                       expected_flag_sha256=expected_sha,
                                       max_runtime_s=30),
        target_solve_rate=target_solve_rate,
    )


def mutate_native(parent: ChallengeSpec, flag_secret: str = "") -> ChallengeSpec:
    """Structural mutation for the native category: +1 key-schedule round.

    Entropy-free (the key length is fixed); difficulty grows only by deepening
    the schedule. Re-pairs the solver (P1) via full regeneration.
    """
    rounds = int(parent.mechanics.get("build", {}).get("rounds", parent.intended_depth)) + 1
    return gen_compiled_crackme(seed=parent.seed, archetype_id=parent.lineage.archetype_id,
                                generation=parent.lineage.generation + 1, rounds=rounds,
                                parent_spec_id=parent.spec_id,
                                mutation_ops=["deepen_key_schedule"],
                                target_solve_rate=parent.target_solve_rate,
                                flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# Native build + verify gate (real gcc pipeline)
# ---------------------------------------------------------------------------
def gcc_available() -> bool:
    return shutil.which("gcc") is not None


def build_and_verify_native(spec: ChallengeSpec) -> Verdict:
    checks: list[str] = []
    failures: list[str] = []
    if not gcc_available():
        return Verdict(False, "gcc toolchain unavailable", failures=["gcc not found"])

    build = spec.mechanics.get("build", {})
    out_name = build.get("output", "crackme")
    src_name = build.get("source", "crackme.c")
    flags = build.get("flags", ["-O2", "-s"])
    expected = spec.official_solver.expected_flag_sha256 or \
        hashlib.sha256(spec.flag.encode()).hexdigest()

    with tempfile.TemporaryDirectory(prefix="autoctf-native-") as tmp:
        root = Path(tmp)
        for rel, content in {**spec.artifacts, **spec.official_solver.files}.items():
            (root / rel).write_text(content, encoding="utf-8")

        # --- compile ---------------------------------------------------------
        comp = subprocess.run(["gcc", *flags, src_name, "-o", out_name],
                              cwd=root, capture_output=True, text=True, timeout=60)
        if comp.returncode != 0:
            return Verdict(False, "build_failed",
                           failures=[comp.stderr.strip()[:200] or "compile error"])
        checks.append(f"compiled with gcc {' '.join(flags)}")

        binary = root / out_name

        # --- obfuscation/leak gate: flag must NOT be in the binary or source -
        blob = binary.read_bytes()
        leak_ok = (spec.flag.encode() not in blob and
                   spec.flag not in (root / src_name).read_text(encoding="utf-8"))
        if leak_ok:
            checks.append("flag absent from binary strings and source (obfuscation holds)")
        else:
            failures.append("flag recoverable from binary/source without solving")

        # --- wrong key must NOT leak the flag (no trivial shortcut) ----------
        wrong = subprocess.run([f"./{out_name}", "wrongkey"], cwd=root,
                               capture_output=True, text=True, timeout=15)
        shortcut = spec.flag in (wrong.stdout + wrong.stderr)
        if shortcut:
            failures.append("wrong key leaks the flag (trivial shortcut)")
        else:
            checks.append("wrong key is rejected without leaking the flag")

        # --- official PoC must recover the exact flag ------------------------
        t0 = time.monotonic()
        run = subprocess.run([sys.executable, spec.official_solver.entry], cwd=root,
                             capture_output=True, text=True,
                             timeout=spec.official_solver.max_runtime_s)
        secs = time.monotonic() - t0
        recovered = run.stdout.strip()
        poc_ok = run.returncode == 0 and \
            hashlib.sha256(recovered.encode()).hexdigest() == expected
        if poc_ok:
            checks.append(f"official solver recovered exact flag in {secs:.3f}s")
        else:
            failures.append(f"solver failed: {(run.stderr or run.stdout).strip()[:160]}")

        # --- determinism -----------------------------------------------------
        det_ok = False
        if poc_ok:
            outs = set()
            for _ in range(3):
                r = subprocess.run([sys.executable, spec.official_solver.entry], cwd=root,
                                   capture_output=True, text=True, timeout=30)
                outs.add(r.stdout.strip())
            det_ok = len(outs) == 1
            checks.append("deterministic across 3 runs") if det_ok else \
                failures.append("non-deterministic output")

    valid = poc_ok and leak_ok and (not shortcut) and det_ok
    reason = "valid" if valid else "; ".join(failures) or "rejected"
    spec.verification.status = "valid" if valid else "rejected"
    spec.verification.poc_passed = poc_ok
    spec.verification.leak_gates_passed = leak_ok
    spec.verification.trivial_shortcut = shortcut
    spec.verification.determinism_runs = 3 if poc_ok else 0
    spec.verification.measured_solve_time_s = secs if poc_ok else None
    spec.verification.rejection_reason = None if valid else reason
    return Verdict(valid, reason, poc_time_s=secs if poc_ok else None,
                   checks=checks, failures=failures)
