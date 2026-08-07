"""Organizer Console backend — generate a challenge from a simple menu choice.

Powers the browser console (console.html): pick a category + level, get a fully
built, optionally-verified challenge with player files, the organizer solver, and
a downloadable player ZIP. Same generators the tournament uses.
"""
from __future__ import annotations

import io
import zipfile

from .verify import verify_spec

# menu options exposed in the UI: id -> (label, builder(seed, level))
def _catalog():
    from .crypto_ladder import LADDER_NAMES, gen_crypto_ladder
    from .native import gen_compiled_crackme
    from .web import MAX_WEB_GEN, gen_web_ssti
    from .generator import offline_brain

    cat = {}
    for i, name in enumerate(LADDER_NAMES):
        cat[f"crypto:{i}"] = (f"Crypto · {name} (rung {i})",
                              lambda seed, lv=i: gen_crypto_ladder(seed=seed, generation=lv))
    for r in (1, 2, 3, 4, 5):
        cat[f"reverse:{r}"] = (f"Reverse · gcc crackme (R={r})",
                               lambda seed, rr=r: gen_compiled_crackme(seed=seed, rounds=rr))
    for lv in range(MAX_WEB_GEN + 1):
        cat[f"web:{lv}"] = (f"Web · SSTI guard level {lv}",
                            lambda seed, l=lv: gen_web_ssti(seed=seed, generation=l))
    for diff in ("easy", "medium", "hard"):
        cat[f"misc:{diff}"] = (f"Misc · encoding chain ({diff})",
                               lambda seed, d=diff: offline_brain(
                                   category="misc", challenge_type="layered",
                                   difficulty=d, seed=seed, archetype_id="misc.layered"))
    return cat


def menu() -> list[dict]:
    return [{"id": k, "label": v[0]} for k, v in _catalog().items()]


def build(option_id: str, seed: int = 1234):
    cat = _catalog()
    if option_id not in cat:
        raise KeyError(option_id)
    return cat[option_id][1](seed)


def generate_challenge(option_id: str, seed: int = 1234, do_verify: bool = False) -> dict:
    spec = build(option_id, seed)
    result = {
        "slug": spec.slug,
        "title": spec.title,
        "category": spec.category,
        "attack": spec.mechanics.get("attack_class") or spec.challenge_type,
        "difficulty": spec.difficulty,
        "story": spec.story,
        "hints": spec.hints,
        "player_files": dict(spec.artifacts),          # what players receive
        "solver_files": dict(spec.official_solver.files),
        "flag": spec.flag,                             # organizer-only
        "verified": None,
        "verify_reason": None,
        "verify_time_s": None,
    }
    if do_verify:
        v = verify_spec(spec)
        result["verified"] = v.valid
        result["verify_reason"] = v.reason
        result["verify_time_s"] = v.poc_time_s
    return result


def challenge_zip(option_id: str, seed: int = 1234) -> tuple[str, bytes]:
    """Player-facing ZIP only (no flag, no solver)."""
    spec = build(option_id, seed)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in spec.artifacts.items():
            z.writestr(name, content)
    return f"{spec.slug}-player.zip", buf.getvalue()
