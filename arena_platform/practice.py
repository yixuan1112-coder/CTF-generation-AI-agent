"""The practice catalogue — a fixed set of challenges a player solves by hand.

The arena is agent-first: challenges are generated live inside a match, exist for
the seconds an agent has to solve them, and are gone. That is the wrong shape for
a human who just wants to *pick a challenge and try it*, the way picoCTF works.

This module builds a stable, curated set — every crypto ladder rung plus a few
composed challenges — at a FIXED seed, so the catalogue is the same on every boot
and a downloaded challenge always checks against the same flag. `seed_practice`
archives them into the same `library` table the match-authored challenges land
in, so the existing download + flag-submit endpoints work unchanged; the only new
thing is an `origin='practice'` marker so the two sets can be told apart.

Two properties are load-bearing:

  * **The flags must not be computable from the repo.** A ladder flag is
    `sha256(kind, secret, seed, generation, ...)`, and this file is public, so a
    fixed seed with a fixed in-repo secret would let anyone read the answer
    without solving anything. The secret therefore comes from the SERVER
    (`Store.practice_secret()`, a random value persisted next to the database and
    never committed), so the seed can be a public constant and the flag still
    cannot be derived off-box.

  * **Seeding is idempotent.** `archive_challenge` de-dupes on the flag hash
    (unique per secret+seed+generation), so re-running `seed_practice` on every
    boot inserts each challenge once and silently no-ops thereafter.
"""
from __future__ import annotations

# A public constant on purpose: the seed carries no secrecy once the per-server
# `practice_secret` is mixed into every flag (see the module docstring). Keeping
# it fixed is what makes the catalogue reproducible across restarts.
PRACTICE_SEED = 20260820

# Composed challenges to include past the plain ladder, as explicit stage plans
# so the catalogue is deterministic rather than dependent on catalogue indexing.
# Each is given its own generation so its flag is distinct.
_COMPOSED = [
    (1001, ["wiener", "smalle"]),
    (1002, ["fermat", "hastad", "commonmod"]),
    (1003, ["franklin", "pollard", "wiener"]),   # showcases a detection-flavoured stage
]


def practice_specs(secret: str):
    """Build the curated catalogue as a list of ChallengeSpec.

    A rung whose toolchain is missing on this host (e.g. the fpylll-backed
    `noncebias` where fpylll is absent) is skipped rather than shipped broken —
    the same bargain the live ladder makes. Nothing here is verified: these
    generators are the ones the test suite already exercises, and verifying a
    dozen specs on every boot would add minutes to startup for no new signal.
    """
    from autoctf_gan.compose import describe, gen_composed
    from autoctf_gan.crypto_ladder import (CRYPTO_LADDER, LADDER_NAMES,
                                           gen_crypto_ladder)

    specs = []
    for generation in range(len(CRYPTO_LADDER)):
        try:
            specs.append(gen_crypto_ladder(seed=PRACTICE_SEED, generation=generation,
                                           flag_secret=secret))
        except Exception as exc:                          # a missing toolchain, etc.
            print(f"[practice] skipped crypto rung {LADDER_NAMES[generation]!r}: "
                  f"{type(exc).__name__}: {exc}")
    for generation, stages in _COMPOSED:
        try:
            specs.append(gen_composed(seed=PRACTICE_SEED, generation=generation,
                                      plan=describe(stages), flag_secret=secret))
        except Exception as exc:
            print(f"[practice] skipped composed {'+'.join(stages)!r}: "
                  f"{type(exc).__name__}: {exc}")
    return specs


def seed_practice(store) -> int:
    """Ensure the practice catalogue exists in the library. Returns how many were
    newly inserted (0 on every boot after the first)."""
    secret = store.practice_secret()
    inserted = 0
    for spec in practice_specs(secret):
        if store.archive_challenge(spec=spec, track=spec.category,
                                   team_name="", origin="practice"):
            inserted += 1
    return inserted
