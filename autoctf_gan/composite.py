"""Composite rungs — several bespoke weaknesses that only work when combined.

Every other crypto rung turns on one idea. These turn on the interaction of two or
three, none of them a named textbook attack, none of them enough alone. Remove any
one weakness and the challenge is unsolvable, not merely harder; that interlock is
the whole design, and it is what a recognise-one-attack solver cannot shortcut.

  triad     Three flaws that only bite together. A key-derivation seed is 48 bits
            but 30 of them leaked, leaving 2**18 to search — hopeless at 48, an
            afternoon at 18. The session key is the raw stream of a weak counter
            PRNG, so a candidate seed gives a candidate key for free. And the
            record MAC is GF(2)-LINEAR, so it is an exact, cheap filter that says
            which candidate seed is the real one. The partial leak makes the search
            finite, the weak PRNG turns a seed into a key, and the linear MAC
            decides the search — miss any one and there is no way through.

  cascade   Two flaws in series where the first feeds the second. A blinded tag
            scheme reuses its blind across two tags, so subtracting them cancels
            the blind and hands you the long-term multiplier k. That k is then the
            seed of the keystream that sealed the payload — so the leak from the
            first flaw is exactly the key the second flaw needs.

Neither writes the flag into a player artifact.
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
        lineage=Lineage(archetype_id=f"composite.{attack_class}", generation=generation,
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
    return f"cmp-{kind}-g{generation}-{tag}"


# ---------------------------------------------------------------------------
# triad — partial seed + weak PRNG + linear MAC, all three required
# ---------------------------------------------------------------------------
TRIAD_SEED_BITS = 48
TRIAD_KNOWN_BITS = 30          # leaked high bits -> 2**18 to search
TRIAD_MAC_BITS = 80
TRIAD_LCG_A = 0x5DEECE66D
TRIAD_LCG_C = 0xB


def _triad_prng_key(seed):
    """16 key bytes from a weak 48-bit counter PRNG (top byte of each state)."""
    mask = (1 << TRIAD_SEED_BITS) - 1
    state = seed & mask
    out = bytearray()
    for _ in range(16):
        state = (TRIAD_LCG_A * state + TRIAD_LCG_C) & mask
        out.append((state >> (TRIAD_SEED_BITS - 8)) & 0xFF)
    return bytes(out)


def _triad_linmac(key_bytes, msg_bytes, masks):
    """A GF(2)-linear MAC: each output bit is the parity of a fixed subset of the
    key||msg bits. Linear on purpose — that is what makes it a cheap exact filter."""
    bits = int.from_bytes(key_bytes + msg_bytes, "big")
    val = 0
    for i, m in enumerate(masks):
        val |= ((bits & m).bit_count() & 1) << i
    return val


_TRIAD_SOLVER = '''\
"""Open the vault by combining three weaknesses; none is enough alone.

The key-derivation seed is 48 bits, which is far out of reach — except `seed.txt`
leaks its top 30 bits, leaving only 2**18 to search. That is the first weakness and
it makes the rest finite.

For each candidate seed, the session key is just the raw stream of the counter PRNG
in `prng.py` (top byte of each state) — a weak generator whose output IS the key,
so a candidate seed is a candidate key with no extra work. That is the second.

To know which candidate is right, use the record MAC. It is GF(2)-linear: every
output bit is the parity of a fixed subset of the key and message bits, listed in
`mac_masks.json`. So it is an exact, cheap check — recompute it per candidate and
keep the seed whose MAC matches the captured one. That is the third. The matching
seed's session key unseals the flag.
"""
import json

import prng

low_bits = 48 - 30
base = int(open("seed_high.txt", encoding="utf-8").read().split("=")[1].strip(), 16) << low_bits
mac_doc = json.load(open("mac_masks.json", encoding="utf-8"))
masks = [int(m, 16) for m in mac_doc["masks"]]
msg = bytes.fromhex(mac_doc["message"])
target_mac = int(mac_doc["mac"], 16)


def linmac(key_bytes):
    bits = int.from_bytes(key_bytes + msg, "big")
    val = 0
    for i, m in enumerate(masks):
        val |= ((bits & m).bit_count() & 1) << i
    return val


session_key = None
for low in range(1 << low_bits):
    key = prng.stream_key(base | low)
    if linmac(key) == target_mac:
        session_key = key
        break

assert session_key is not None, "no seed in the leaked range matches the MAC"

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), session_key.hex()))
'''

_TRIAD_PRNG_SRC = '''\
"""The device's key-derivation PRNG (reference build). Weak by construction: the
session key is simply the high byte of each successive 48-bit LCG state."""
A = 0x5DEECE66D
C = 0xB
MASK = (1 << 48) - 1


def stream_key(seed):
    state = seed & MASK
    out = bytearray()
    for _ in range(16):
        state = (A * state + C) & MASK
        out.append((state >> 40) & 0xFF)
    return bytes(out)
'''


def gen_triad(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="triad", seed=seed, generation=generation,
                          secret=flag_secret)
    low_bits = TRIAD_SEED_BITS - TRIAD_KNOWN_BITS
    for attempt in range(8):
        rng = random.Random(f"triad:{flag_secret}:{seed}:{generation}:{attempt}")
        full_seed = rng.getrandbits(TRIAD_SEED_BITS)
        session_key = _triad_prng_key(full_seed)

        msg = ("PROV " + hashlib.sha256(str(full_seed).encode()).hexdigest()[:24]).encode()
        keybits = 8 * (len(session_key) + len(msg))
        masks = [rng.getrandbits(keybits) for _ in range(TRIAD_MAC_BITS)]
        target_mac = _triad_linmac(session_key, msg, masks)

        # A composite must have a UNIQUE answer: exactly one seed in the leaked
        # range may reproduce the MAC, or the sealed key is ambiguous. Rehearse the
        # search and rebuild if the MAC collides within the range.
        base = (full_seed >> low_bits) << low_bits
        hits = 0
        for low in range(1 << low_bits):
            if _triad_linmac(_triad_prng_key(base | low), msg, masks) == target_mac:
                hits += 1
                if hits > 1:
                    break
        if hits == 1:
            break
    else:                                                  # pragma: no cover
        raise RuntimeError("triad: MAC did not single out the seed")

    artifacts = {
        "seed_high.txt": (f"# key-derivation seed: only the top {TRIAD_KNOWN_BITS} of "
                          f"{TRIAD_SEED_BITS} bits survived\nhigh = {full_seed >> low_bits:x}\n"),
        "prng.py": _TRIAD_PRNG_SRC,
        "mac_masks.json": json.dumps({
            "note": ("record MAC: bit i is the parity of (key||message) AND masks[i]; "
                     "key is 16 bytes, message follows"),
            "message": msg.hex(),
            "mac": f"{target_mac:x}",
            "masks": [f"{m:x}" for m in masks],
        }) + "\n",
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(session_key.hex(), flag),
        "README.md": (
            "# Vault key recovery\n\n"
            "Three fragments were pulled off a provisioning vault. `seed_high.txt` is "
            f"what survived of the 48-bit key-derivation seed — only its top "
            f"{TRIAD_KNOWN_BITS} bits. `prng.py` is the device's key-derivation "
            "routine. `mac_masks.json` is a captured record with its MAC and the MAC's "
            "definition.\n\n"
            "The recovery blob is sealed under the 16-byte session key as lowercase "
            "hex. `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("triad", flag_secret, seed, generation),
        title="Vault Key Recovery", category="crypto",
        challenge_type="partial-seed-weak-prng-linear-mac",
        story=("A provisioning vault leaked three fragments: most of a key-derivation "
               "seed, the derivation routine, and one MAC'd record. Apart, each is "
               "useless; together they give up the session key."),
        vulnerability=("a partially-leaked seed, a weak PRNG whose stream is the key, and a "
                       "linear MAC that filters the seed search — solvable only in combination"),
        solution=["the leaked high seed bits cut the search from 2**48 to 2**18",
                  "the weak PRNG turns each candidate seed into a candidate key",
                  "the linear MAC is an exact filter that picks the real seed",
                  "the matching session key unseals the flag"],
        artifacts=artifacts,
        solver_files={"solver.py": _TRIAD_SOLVER, "prng.py": _TRIAD_PRNG_SRC,
                      "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="triad",
        rank=16, max_runtime_s=180, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# cascade — reused blind leaks k, which is the keystream seed for the payload
# ---------------------------------------------------------------------------
CASCADE_M = (1 << 89) - 1          # a Mersenne prime modulus for the tag scheme


def _cascade_keystream(k, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"cascade-ks:{k}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:length])


_CASCADE_SOLVER = '''\
"""Two flaws in series: the first leaks the key the second needs.

The tag scheme blinds each tag: t = (k*h + r) mod M, with k the long-term
multiplier and r a per-batch blind. `tags.json` has two tags from the same batch,
so they share r. Subtract them and the blind cancels:

    t1 - t2 = k*(h1 - h2) mod M   ->   k = (t1 - t2) * inv(h1 - h2) mod M.

That recovers k outright. The second flaw is that this same k is the seed of the
keystream that sealed the payload: `payload.enc` is the seal secret XORed with a
sha256 counter-stream keyed by k. Rebuild that keystream from the recovered k,
XOR it back, and the result is the secret that opens the flag.
"""
import hashlib
import json

doc = json.load(open("tags.json", encoding="utf-8"))
M = int(doc["M"])
(h1, t1), (h2, t2) = [(int(x["h"]), int(x["t"])) for x in doc["tags"]]
k = (t1 - t2) * pow(h1 - h2, -1, M) % M


def keystream(length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"cascade-ks:{k}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:length])


blob = bytes.fromhex(open("payload.enc", encoding="utf-8").read().strip())
secret = bytes(a ^ b for a, b in zip(blob, keystream(len(blob)))).decode()

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), secret))
'''


def gen_cascade(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="cascade", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"cascade:{flag_secret}:{seed}:{generation}")

    k = rng.randrange(2, CASCADE_M)
    r = rng.randrange(2, CASCADE_M)                     # the reused blind
    h1 = rng.randrange(2, CASCADE_M)
    h2 = rng.randrange(2, CASCADE_M)
    while h1 == h2:
        h2 = rng.randrange(2, CASCADE_M)
    t1 = (k * h1 + r) % CASCADE_M
    t2 = (k * h2 + r) % CASCADE_M

    secret = hashlib.sha256(f"cascade-secret:{flag_secret}:{seed}:{generation}"
                            .encode()).hexdigest()[:32]
    ks = _cascade_keystream(k, len(secret))
    payload = bytes(a ^ b for a, b in zip(secret.encode(), ks))

    artifacts = {
        "tags.json": json.dumps({
            "scheme": "blinded tag: t = (k*h + r) mod M, r per batch",
            "M": str(CASCADE_M),
            "tags": [{"h": str(h1), "t": str(t1)}, {"h": str(h2), "t": str(t2)}],
        }, indent=1) + "\n",
        "payload.enc": payload.hex() + "\n",
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(secret, flag),
        "README.md": (
            "# Blinded tag capture\n\n"
            "`tags.json` holds two tags from one batch of a blinded tagging scheme, "
            "each `t = (k*h + r) mod M` for a fixed long-term multiplier `k` and a "
            "per-batch blind `r` that is constant within a batch. `payload.enc` is a "
            "record sealed under a keystream keyed by `k`.\n\n"
            "The recovery blob is sealed under the decrypted payload string. "
            "`sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("cascade", flag_secret, seed, generation),
        title="Blinded Tag Capture", category="crypto",
        challenge_type="reused-blind-into-keystream",
        story=("A blinded tagging scheme emitted two tags in one batch, and a record "
               "sealed under the scheme's own long-term key. The two captures are more "
               "connected than they look."),
        vulnerability=("a reused per-batch blind cancels under subtraction and leaks the "
                       "long-term multiplier, which is the keystream seed for the payload"),
        solution=["subtract the two same-batch tags to cancel the shared blind",
                  "recover k = (t1-t2) / (h1-h2) mod M",
                  "rebuild the payload keystream from k and XOR it back",
                  "unseal the flag with the recovered payload"],
        artifacts=artifacts,
        solver_files={"solver.py": _CASCADE_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="cascade",
        rank=13, max_runtime_s=60, flag_secret=flag_secret)


COMPOSITE_BUILDERS = [gen_triad, gen_cascade]
