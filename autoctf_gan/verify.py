"""verify_spec — the solvability gate (Steps 1 & the "guaranteed solvability" pain point).

This is the single most important invariant in AutoCTF-GAN. A mutated spec is a
"valid evolution" ONLY if:

  (a) its paired official_solver runs and recovers a flag whose sha256 matches
      expected_flag_sha256                         -> not unsolvable / not degenerate
  (b) no trivial one-step shortcut recovers the flag while depth > 1
                                                    -> not too-easy / not leaked path
  (c) the true flag does not leak into player artifacts
  (d) the challenge is deterministic across N runs

Removing the bug or hardcoding an unguessable secret makes (a) fail, so the
Generator can never profit from degenerating the challenge.

The reference build runs the solver in a subprocess sandbox (cwd-isolated, no
args, hard timeout). The same contract scales to Docker/K8s in production
(§8.2) — swap `_run_solver` for a container exec without touching callers.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

from .codec import decode_chain
from .models import ChallengeSpec, Verdict

DETERMINISM_RUNS = 3


def sha256_flag(flag: str) -> str:
    return hashlib.sha256(flag.encode()).hexdigest()


def _materialize(spec: ChallengeSpec, root: Path) -> None:
    """Write player artifacts + organizer solver files into an isolated dir."""
    for rel, content in spec.artifacts.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    for rel, content in spec.official_solver.files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def _run_solver(spec: ChallengeSpec, root: Path) -> tuple[bool, str, float]:
    """Run the official solver in a subprocess sandbox; return (ok, stdout, secs)."""
    import time  # local: Date.now-style calls are fine in normal runtime
    start = time.monotonic()
    try:
        proc = subprocess.run(
            [sys.executable, spec.official_solver.entry],
            cwd=root, capture_output=True, text=True,
            timeout=spec.official_solver.max_runtime_s,
        )
    except subprocess.TimeoutExpired:
        return False, "<timeout>", float(spec.official_solver.max_runtime_s)
    elapsed = time.monotonic() - start
    ok = proc.returncode == 0
    return ok, (proc.stdout or proc.stderr).strip(), elapsed


def _trivial_shortcut(spec: ChallengeSpec) -> bool:
    """True if any single inverse step recovers the flag while depth > 1.

    A genuine multi-stage chain must require every layer; if peeling one layer
    already yields flag{...}, the challenge is effectively single-step and the
    declared depth is a lie. Guards make this False for real chains.
    """
    chain = [s.__dict__ if hasattr(s, "__dict__") else s for s in spec.vuln_chain]
    if len(chain) <= 1:
        return False  # single-step by design; difficulty is calibrated elsewhere
    primary = spec.artifacts.get("cipher.txt") or next(iter(spec.artifacts.values()), "")
    for step in chain:
        try:
            peeled = decode_chain(primary, [step])
        except Exception:
            continue
        if "flag{" in peeled:
            return True
    return False


def _leak_gates(spec: ChallengeSpec) -> bool:
    """True (pass) if the true flag does not appear in any player artifact."""
    return not any(spec.flag in content for content in spec.artifacts.values())


def _determinism_holds(spec: ChallengeSpec, root: Path) -> bool:
    outputs = set()
    for _ in range(DETERMINISM_RUNS):
        ok, out, _ = _run_solver(spec, root)
        outputs.add((ok, out))
    return len(outputs) == 1


def verify_spec(spec: ChallengeSpec) -> Verdict:
    """Route to the build/verify backend for this challenge's delivery type.

    Every backend honours the identical contract: run the paired PoC in an
    isolated build, reject unsolvable / trivial / leaky / non-deterministic
    specs. Only the sandbox differs (subprocess codec / gcc binary / Docker).
    """
    if spec.delivery == "binary":
        from .native import build_and_verify_native
        return build_and_verify_native(spec)
    if spec.delivery == "web":
        from .web import build_and_verify_web
        return build_and_verify_web(spec)
    return _verify_codec(spec)


def _verify_codec(spec: ChallengeSpec) -> Verdict:
    checks: list[str] = []
    failures: list[str] = []
    expected = spec.official_solver.expected_flag_sha256 or sha256_flag(spec.flag)

    with tempfile.TemporaryDirectory(prefix="autoctf-verify-") as tmp:
        root = Path(tmp)
        _materialize(spec, root)

        # (a) PoC must recover the exact flag ---------------------------------
        ok, out, secs = _run_solver(spec, root)
        recovered_hash = sha256_flag(out) if ok else ""
        if not ok:
            failures.append(f"solver did not run cleanly: {out[:120]}")
        elif recovered_hash != expected:
            failures.append("solver output does not match expected flag hash (unsolvable/degenerate)")
        else:
            checks.append(f"official solver recovered exact flag in {secs:.3f}s")

        poc_passed = ok and recovered_hash == expected

        # (b) no trivial shortcut --------------------------------------------
        shortcut = _trivial_shortcut(spec)
        if shortcut:
            failures.append("trivial one-step shortcut recovers the flag (too easy)")
        else:
            checks.append("no trivial single-step shortcut")

        # (c) no flag leak ----------------------------------------------------
        leak_ok = _leak_gates(spec)
        if leak_ok:
            checks.append("flag absent from player artifacts")
        else:
            failures.append("true flag leaked into player artifacts")

        # (d) determinism (only worth checking if the solver works at all) ----
        det_ok = _determinism_holds(spec, root) if poc_passed else False
        if poc_passed:
            checks.append("deterministic across %d runs" % DETERMINISM_RUNS) if det_ok \
                else failures.append("non-deterministic solver output")

    valid = poc_passed and (not shortcut) and leak_ok and det_ok
    reason = "valid" if valid else "; ".join(failures) or "rejected"

    # write results back onto the spec
    spec.verification.status = "valid" if valid else "rejected"
    spec.verification.poc_passed = poc_passed
    spec.verification.leak_gates_passed = leak_ok
    spec.verification.trivial_shortcut = shortcut
    spec.verification.determinism_runs = DETERMINISM_RUNS if poc_passed else 0
    spec.verification.measured_solve_time_s = secs if poc_passed else None
    spec.verification.rejection_reason = None if valid else reason

    return Verdict(valid=valid, reason=reason, poc_time_s=secs if poc_passed else None,
                   checks=checks, failures=failures)
