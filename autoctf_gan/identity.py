"""Per-challenge flag and public-identifier derivation.

Every track used to derive its flag from the match seed alone —
`sha256(f"crackme::{seed}")`, `sha256(f"wiener::{seed}")`, `sha256(f"ssti::{seed}")`
— which had two consequences the arena could not survive:

  * a ladder's rungs all carried the SAME flag, because the seed is constant for
    a match and the generation was not part of the derivation. Solving the
    easiest rung and replaying its flag climbed the entire ladder.
  * the seed was printed into the public slug and therefore into `challenge_id`,
    and the derivation lives in a public repository, so the flag could be
    computed straight from the metadata the platform hands the agent — without
    opening a single artifact.

So a flag now depends on the generation AND on a per-match `secret` that never
appears in a player-visible field, and the public identifier is no longer a
function of the flag (it used to end in `sha256(flag)[:8]`, handing out half the
flag's hash for free).

`secret=""` keeps derivation fully deterministic for tests and offline demos.
That is only safe because the seed no longer reaches the player: with the seed
out of the public id, "deterministic given the seed" stops being "derivable by
the player". Live matches pass a real secret on top — see `Competition`.
"""
from __future__ import annotations

import hashlib

# 64 bits of flag entropy. It was 48, which is fine while sha256(flag) stays
# organizer-only — but the challenge library publishes that hash so a submission
# can be checked without storing the answer, and 2^48 sha256 is a tractable
# offline grind. 2^64 is not.
FLAG_HEX = 16


def _digest(*parts: object) -> str:
    return hashlib.sha256("::".join(str(p) for p in parts).encode()).hexdigest()


def challenge_flag(*, kind: str, seed: int, generation: int,
                   variant: str = "", secret: str = "") -> str:
    """The flag for ONE rung. Distinct per generation, so no rung can be replayed."""
    return f"flag{{{_digest('autoctf-flag', kind, secret, seed, generation, variant)[:FLAG_HEX]}}}"


def challenge_secret(*, kind: str, seed: int, generation: int,
                     variant: str = "", secret: str = "", length: int = 8) -> str:
    """An organizer-only secret bound to one rung — e.g. a crackme's password.

    Same rules as the flag: never derivable from anything the player receives.
    """
    return _digest("autoctf-secret", kind, secret, seed, generation, variant)[:length]


def public_slug(*, base: str, seed: int, generation: int, secret: str = "") -> str:
    """A unique, non-revealing identifier.

    Carries a discriminator so two matches never collide on a docker image tag or
    an export directory, but the discriminator is a one-way digest — unlike the
    old `f"{base}-{seed:06d}-g{generation}"`, it does not print the seed.
    """
    return f"{base}-g{generation}-{_digest('autoctf-id', base, secret, seed, generation)[:8]}"
