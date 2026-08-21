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
# Each is given its own generation so its flag is distinct. The deep ones are
# pure time sinks: every sealed layer must be broken in order before the next
# one's key material even becomes readable, so a six-layer chain is six different
# attacks with no shortcut and no parallelism.
_COMPOSED = [
    (1001, ["wiener", "smalle"]),
    (1002, ["fermat", "hastad", "commonmod"]),
    (1003, ["franklin", "pollard", "wiener"]),   # showcases a detection-flavoured stage
    (1004, ["crtfault", "franklin", "fermat", "commonmod"]),
    (1005, ["pollard", "wiener", "hastad", "fermat", "commonmod", "smalle"]),
    (1006, ["franklin", "crtfault", "pollard", "wiener", "fermat",
            "hastad", "commonmod", "smalle"]),   # eight sealed layers
    (1007, ["crtfault", "franklin", "pollard", "wiener", "fermat", "hastad",
            "commonmod", "smalle", "wiener", "fermat", "hastad", "commonmod"]),  # twelve
]


def _strip_hints(spec):
    """Practice challenges ship WITHOUT hints on purpose.

    Hints exist in a live match to keep the co-evolution fair to an uploaded
    agent under a clock. The practice catalogue is where difficulty is the point,
    so naming the weakness or the technique in a hint just hands the answer to the
    solver we are trying to challenge. The story stays — that is the scenario, not
    a hint — but the hint list is emptied.
    """
    spec.hints = []
    return spec


def practice_specs(secret: str, cache_dir=None):
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
    from autoctf_gan.prng import gen_mt19937_predict

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
    try:
        specs.append(gen_mt19937_predict(seed=PRACTICE_SEED, generation=0,
                                         flag_secret=secret))
    except Exception as exc:
        print(f"[practice] skipped mt19937: {type(exc).__name__}: {exc}")
    # The hardcore tier: a bespoke ECDSA variant that must be DERIVED, and a
    # discrete-log COMPUTE wall with no shortcut — the two that a toolkit-equipped
    # agent cannot clear by recognition alone.
    from autoctf_gan.hardcore import gen_dlog_wall, gen_lcg_nonce_ecdsa
    try:
        specs.append(gen_lcg_nonce_ecdsa(seed=PRACTICE_SEED, generation=0, flag_secret=secret))
    except Exception as exc:
        print(f"[practice] skipped lcgnonce: {type(exc).__name__}: {exc}")
    try:
        specs.append(gen_dlog_wall(seed=PRACTICE_SEED, generation=0, flag_secret=secret,
                                   cache_dir=cache_dir))
    except Exception as exc:
        print(f"[practice] skipped dlogwall: {type(exc).__name__}: {exc}")
    # A spread of non-crypto categories — misc, web, forensics, reverse — so the
    # catalogue is a real CTF, not one discipline. (Interactive pwn/web live on the
    # agent/service track, not in a static download.)
    from autoctf_gan.variety import ALL_VARIETY
    for builder in ALL_VARIETY:
        try:
            specs.append(builder(seed=PRACTICE_SEED, generation=0, flag_secret=secret))
        except Exception as exc:
            print(f"[practice] skipped {builder.__name__}: {type(exc).__name__}: {exc}")
    # Two tiers aimed at a solver that arrives with a toolkit and a library of
    # writeups. `adversarial` makes a classifier the target, so the attack is on a
    # model rather than on a cipher; `airesistant` is shaped so that recognition,
    # library reuse, and the first plausible lead each point the wrong way.
    # `gradgate` rehearses its own descent at build time, which is most of the
    # extra ~10s a catalogue rebuild now costs.
    # `bespoke` is a third of the same kind: the device's own source ships, so the
    # algorithm is knowable and the key still is not, and neither construction has
    # a published attack script to bind to.
    # `agentbench` is built against failure modes that agent benchmarks measured
    # rather than ones we reasoned about — see that module's docstring for which
    # finding each rung targets.
    # `picostyle` fills the two picoCTF/CyLab-flagship shapes the rest of the
    # catalogue skips — a general-skills encoding puzzle and a keygen-reversing
    # challenge — hardened so recognition does not clear them.
    from autoctf_gan.adversarial import ADVERSARIAL_BUILDERS
    from autoctf_gan.agentbench import AGENTBENCH_BUILDERS
    from autoctf_gan.airesistant import AIRESISTANT_BUILDERS
    # `humanhard` targets a solver that grinds but does not leap, and that
    # reverse-engineers by reading code — so it grinds where grinding cannot
    # finish, matches where nothing matches, and gets only behaviour, never source.
    # `hardtier` is the top of the difficulty range: real cryptographic techniques
    # (Reed-Solomon decoding, smooth-order Pohlig-Hellman, MQ linearisation) each
    # behind a wall that makes the obvious attack infeasible.
    from autoctf_gan.bespoke import BESPOKE_BUILDERS
    from autoctf_gan.composite import COMPOSITE_BUILDERS
    from autoctf_gan.harder import HARDER_BUILDERS
    from autoctf_gan.hardtier import HARDTIER_BUILDERS
    from autoctf_gan.humanhard import HUMANHARD_BUILDERS
    from autoctf_gan.morepico import MOREPICO_BUILDERS
    from autoctf_gan.picostyle import PICOSTYLE_BUILDERS
    # `realvuln` is genuine software-security bugs (length extension, CBC
    # malleability) made hard by bespoke primitives that defeat the standard tool.
    from autoctf_gan.realvuln import REALVULN_BUILDERS
    # `signals` decodes physical-layer captures (an OOK/Manchester beacon, BLE
    # whitening) — modelled on the signal-decode cases an agent eval found hard.
    from autoctf_gan.signals import SIGNALS_BUILDERS
    # `walls` is the terminal tier: genuine unbroken hard problems (factoring,
    # ECDLP) verified by an organizer trapdoor. Nobody solves these — that is the
    # honest end of "make it harder". They join `dlogwall` above.
    from autoctf_gan.walls import WALLS_BUILDERS
    for builder in (ADVERSARIAL_BUILDERS + AIRESISTANT_BUILDERS + BESPOKE_BUILDERS
                    + AGENTBENCH_BUILDERS + PICOSTYLE_BUILDERS + MOREPICO_BUILDERS
                    + HUMANHARD_BUILDERS + HARDTIER_BUILDERS + COMPOSITE_BUILDERS
                    + REALVULN_BUILDERS + SIGNALS_BUILDERS + HARDER_BUILDERS
                    + WALLS_BUILDERS):
        try:
            specs.append(builder(seed=PRACTICE_SEED, generation=0, flag_secret=secret))
        except Exception as exc:
            print(f"[practice] skipped {builder.__name__}: {type(exc).__name__}: {exc}")
    return [_strip_hints(s) for s in specs]


# Bump this whenever the catalogue changes (a challenge added, removed, or its
# generator altered). A boot whose stored version already matches skips the whole
# rebuild — otherwise every restart pays ~15s to re-derive 20 specs (safe primes,
# deep RSA chains) only to dedup them away. A version bump forces one rebuild.
CATALOGUE_VERSION = 17


def seed_practice(store) -> int:
    """Ensure the practice catalogue exists in the library. Returns how many were
    newly inserted (0 on a boot whose catalogue is already current)."""
    version_file = store.path.with_name("practice_version")
    try:
        current = version_file.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        current = ""
    # Fast path: catalogue unchanged and already seeded — do not rebuild anything.
    if current == str(CATALOGUE_VERSION) and store.library_count(origin="practice") > 0:
        store.clear_practice_hints()
        return 0

    secret = store.practice_secret()
    cache_dir = store.path.parent
    inserted = 0
    for spec in practice_specs(secret, cache_dir=cache_dir):
        if store.archive_challenge(spec=spec, track=spec.category,
                                   team_name="", origin="practice"):
            inserted += 1
    # Enforce the no-hints policy even on rows an older build already seeded with
    # hints — archive_challenge de-dupes on the flag hash and never rewrites them.
    store.clear_practice_hints()
    try:
        version_file.write_text(str(CATALOGUE_VERSION), encoding="utf-8")
    except OSError:
        pass
    return inserted
