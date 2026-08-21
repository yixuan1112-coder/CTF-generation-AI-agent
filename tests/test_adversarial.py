"""The two tiers aimed at a strong solver rather than at a hard theorem.

`autoctf_gan.adversarial` attacks a model instead of a cipher; `autoctf_gan.
airesistant` attacks the habits of a solver that arrives with a toolkit. Both
make a claim the rest of the suite does not have to make, so both are tested for
it here:

  * the paired PoC recovers the exact flag across several seeds (P1). These rungs
    do real numerical work — a knapsack DP, a non-convex descent, a seed search —
    and "usually converges" is not solvable. A seed that only works sometimes is a
    rung that vanishes from the catalogue with no explanation.
  * nothing a player receives names the weakness. `story` and `artifacts` are the
    only spec fields that reach a player (`vulnerability` and `intended_solution`
    are organizer-side, so they may say exactly what the bug is), and for these
    rungs the whole difficulty is that the artifacts do not say.
"""
from __future__ import annotations

import unittest

from autoctf_gan.adversarial import ADVERSARIAL_BUILDERS, gen_bandflip, gen_gradgate
from autoctf_gan.airesistant import (AIRESISTANT_BUILDERS, gen_honeytrap,
                                     gen_lsbseed, gen_oddproto, gen_permstego,
                                     gen_skewlog, gen_vmkeygen)
from autoctf_gan.bespoke import BESPOKE_BUILDERS, gen_codebook, gen_cpatrace
from autoctf_gan.verify import verify_spec

ALL_BUILDERS = ADVERSARIAL_BUILDERS + AIRESISTANT_BUILDERS + BESPOKE_BUILDERS

# Words that would hand over the technique. Each rung's difficulty is that a
# player has to arrive at one of these on their own.
_GIVEAWAYS = ("knapsack", "gradient", "descent", "off-by-one", "off by one",
              "bit-revers", "bit revers", "brute force", "brute-force",
              "adversarial", "dead end", "red herring", "decoy", "honeypot",
              "out of bounds", "out-of-bounds", "correlation", "correlate",
              "hamming", "side channel", "side-channel", "shamir", "lagrange",
              "factorial", "permutation", "lehmer", "interpolat", "tampered")


class RungsAreSolvable(unittest.TestCase):
    def test_every_rung_verifies_across_seeds(self):
        for builder in ALL_BUILDERS:
            for seed in (101, 202):
                with self.subTest(builder=builder.__name__, seed=seed):
                    spec = builder(seed=seed, generation=0, flag_secret=f"secret-{seed}")
                    verdict = verify_spec(spec)
                    self.assertTrue(verdict.valid, f"{builder.__name__}@{seed}: {verdict.reason}")

    def test_flag_is_distinct_per_generation(self):
        """A rung solved at one generation must not unlock the next."""
        for builder in ALL_BUILDERS:
            flags = {builder(seed=7, generation=g, flag_secret="s").flag for g in range(3)}
            self.assertEqual(len(flags), 3, builder.__name__)


class ArtifactsDoNotNameTheWeakness(unittest.TestCase):
    def test_no_giveaway_in_player_visible_text(self):
        for builder in ALL_BUILDERS:
            spec = builder(seed=303, generation=0, flag_secret="secret-303")
            blob = (spec.story + " " + " ".join(spec.artifacts.values())).lower()
            for word in _GIVEAWAYS:
                self.assertNotIn(word, blob, f"{builder.__name__} artifacts say {word!r}")

    def test_rungs_ship_without_hints(self):
        for builder in ALL_BUILDERS:
            self.assertEqual(builder(seed=1, generation=0, flag_secret="s").hints, [])


class TheAnswerIsNotInTheArtifacts(unittest.TestCase):
    """Each rung seals its flag under a value only a finished solve produces.

    The generic leak gate in `verify_spec` checks the flag itself is absent. These
    rungs need the stronger property: the SEAL KEY must not be sitting in a player
    file either, or the seal is decoration.
    """

    def test_seal_key_never_ships(self):
        cases = [
            # (builder, how to pull the seal key back out of the built spec)
            (gen_bandflip, _bandflip_key),
            (gen_gradgate, _gradgate_key),
            (gen_oddproto, _oddproto_key),
            (gen_vmkeygen, _vmkeygen_key),
            (gen_lsbseed, _lsbseed_key),
            (gen_honeytrap, _honeytrap_key),
            (gen_skewlog, _skewlog_key),
            (gen_permstego, _permstego_key),
            (gen_cpatrace, _cpatrace_key),
            (gen_codebook, _codebook_key),
        ]
        for builder, extract in cases:
            spec = builder(seed=404, generation=0, flag_secret="secret-404")
            key = extract(spec)
            for name, content in spec.artifacts.items():
                self.assertNotIn(key, content,
                                 f"{builder.__name__}: seal key appears in {name}")


# --- pulling the seal key back out of a built spec, the organizer's way --------
# Each of these performs the intended attack and stops one step short of
# unsealing, so it doubles as an independent check that the attack the rung
# advertises is the one the generator actually sealed under.

def _bandflip_key(spec):
    import json

    from autoctf_gan.adversarial import _bandflip_optimum
    gate = json.loads(spec.artifacts["gate.json"])
    probe = json.loads(spec.artifacts["probe.json"])["probe"]
    chosen, _ = _bandflip_optimum(probe, gate["template_authorized"],
                                  gate["template_rejected"], gate["band_cost"])
    forged = list(probe)
    for i in chosen:
        forged[i] = gate["template_authorized"][i]
    return ",".join(str(v) for v in forged)


def _gradgate_key(spec):
    """Replay the generator's own RNG stream to recover the sealed detent point.

    Deriving it by descent instead would double the suite's runtime to re-prove
    what `verify_spec` already proved. What this checks is the other half: that
    the point the seal was built from is nowhere in the files.
    """
    import json
    import math
    import random

    from autoctf_gan import adversarial as adv

    published = json.loads(spec.artifacts["model.json"])["b2"]
    for attempt in range(16):
        rng = random.Random(f"gradgate:secret-404:404:0:{attempt}")
        s1, s2 = 1.0 / math.sqrt(adv.GRAD_IN), 1.0 / math.sqrt(adv.GRAD_H1)
        [[round(rng.gauss(0, s1), 9) for _ in range(adv.GRAD_IN)]
         for _ in range(adv.GRAD_H1)]
        [round(rng.gauss(0, 0.25), 9) for _ in range(adv.GRAD_H1)]
        [[round(rng.gauss(0, s2), 9) for _ in range(adv.GRAD_H1)]
         for _ in range(adv.GRAD_H2)]
        b2 = [round(rng.gauss(0, 0.25), 9) for _ in range(adv.GRAD_H2)]
        point = [rng.randrange(2, adv.GRAD_GRID - 1) for _ in range(adv.GRAD_IN)]
        if b2 == published:
            return "-".join(str(k) for k in point)
    raise AssertionError("could not reproduce the gradgate model")


def _oddproto_key(spec):
    from autoctf_gan.airesistant import SHARD_TAG, _bitrev16, ESC, ESC_XOR
    blob = bytes.fromhex("".join(spec.artifacts["capture.hex"].split()))
    shards, pos = [], 0
    while pos < len(blob):
        tag = blob[pos]
        body_len = _bitrev16((blob[pos + 1] << 8) | blob[pos + 2])
        body = blob[pos + 3:pos + 3 + body_len]
        out, i = bytearray(), 0
        while i < len(body):
            if body[i] == ESC:
                out.append(body[i + 1] ^ ESC_XOR)
                i += 2
            else:
                out.append(body[i])
                i += 1
        if tag == SHARD_TAG:
            shards.append(bytes(out))
        pos += 3 + body_len + 2
    return b"".join(shards).hex()


def _vmkeygen_key(spec):
    prog = bytes.fromhex("".join(spec.artifacts["program.hex"].split()))
    table = bytes.fromhex("".join(spec.artifacts["sbox.hex"].split()))
    inv = [0] * 256
    for value, mapped in enumerate(table):
        inv[mapped] = value
    pos, seed_cell = 0, None
    while prog[pos] != 0x11:
        if prog[pos] == 0x12 and prog[pos + 2] == 0x18 and (prog[pos + 3] & 3) == 0:
            seed_cell = prog[pos + 1]
        pos += 2
    state, key, pc = seed_cell, bytearray(24), 0
    while pc < len(prog):
        if prog[pc] == 0x11 and prog[pc + 2] == 0x19:
            idx, rot, const, expect = prog[pc + 1], prog[pc + 7] & 7, prog[pc + 9], prog[pc + 13]
            t = (expect - const) & 0xFF
            t = ((t >> rot) | (t << (8 - rot))) & 0xFF
            key[idx] = inv[t] ^ state
            state = (expect + key[idx]) & 0xFF
            pc += 19
        else:
            pc += 2
    return bytes(key).hex()


def _lsbseed_key(spec):
    from autoctf_gan.airesistant import (STEGO_KEY_BYTES, STEGO_MAGIC,
                                         STEGO_SEED_BITS, _stego_schedule)
    tokens = spec.artifacts["frame.pgm"].split()
    w, h = int(tokens[1]), int(tokens[2])
    pixels = [int(t) for t in tokens[4:4 + w * h]]
    npix = w * h
    magic_bits = [(b >> s) & 1 for b in STEGO_MAGIC for s in (7, 6, 5, 4, 3, 2, 1, 0)]
    mask, mult, incr = (1 << 64) - 1, 6364136223846793005, 1442695040888963407

    def matches(candidate):
        state = (candidate * mult + incr) & mask
        seen, got = set(), 0
        while got < len(magic_bits):
            state = (state * mult + incr) & mask
            pos = (state >> 29) % npix
            if pos in seen:
                continue
            seen.add(pos)
            if pixels[pos] & 1 != magic_bits[got]:
                return False
            got += 1
        return True

    found = next(c for c in range(1 << STEGO_SEED_BITS) if matches(c))
    total = (len(STEGO_MAGIC) + STEGO_KEY_BYTES) * 8
    bits = [pixels[p] & 1 for p in _stego_schedule(found, total, npix)]
    blob = bytes(int("".join(str(x) for x in bits[i:i + 8]), 2)
                 for i in range(0, len(bits), 8))
    return blob[len(STEGO_MAGIC):].hex()


def _honeytrap_key(spec):
    import hashlib
    from autoctf_gan.airesistant import RECORD_COUNT, RECORD_LEN, TABLE_BASE
    image = bytes.fromhex("".join(spec.artifacts["nvram.hex"].split()))
    off = TABLE_BASE + RECORD_COUNT * RECORD_LEN
    out, counter = bytearray(), 0
    while len(out) < RECORD_LEN:
        out += hashlib.sha256(b"SLC-NVRAM" + bytes([RECORD_COUNT, counter])).digest()
        counter += 1
    return bytes(a ^ b for a, b in zip(image[off:off + RECORD_LEN], out)).hex()



def _skewlog_key(spec):
    import hashlib
    import json
    doc = json.loads(spec.artifacts["logs.json"])
    prime, threshold = int(doc["prime"]), doc["threshold"]
    good = []
    for node in doc["nodes"]:
        digest = hashlib.sha256(node["node_id"].encode()).hexdigest()
        for entry in node["entries"]:
            digest = hashlib.sha256((digest + entry["event"]).encode()).hexdigest()
            if digest != entry["digest"]:
                break
        else:
            good.append((int(node["share_x"]), int(node["share_y"])))
    assert len(good) == threshold, f"{len(good)} intact vs threshold {threshold}"
    secret = 0
    for i, (xi, yi) in enumerate(good):
        num = den = 1
        for j, (xj, _) in enumerate(good):
            if i != j:
                num = num * (-xj) % prime
                den = den * (xi - xj) % prime
        secret = (secret + yi * num * pow(den, -1, prime)) % prime
    return secret.to_bytes(32, "big").hex()


def _permstego_key(spec):
    import json
    import math
    from autoctf_gan.airesistant import PERM_MAGIC
    entries = json.loads(spec.artifacts["manifest.json"])["entries"]
    n = len(entries)
    order = {path: i for i, path in enumerate(sorted(e["path"] for e in entries))}
    seq = [order[e["path"]] for e in entries]
    value = sum(sum(1 for j in range(i + 1, n) if seq[j] < seq[i])
                * math.factorial(n - 1 - i) for i in range(n))
    blob = value.to_bytes((value.bit_length() + 7) // 8, "big")
    assert blob[:len(PERM_MAGIC)] == PERM_MAGIC
    return blob[len(PERM_MAGIC):].hex()


def _cpatrace_key(spec):
    import json
    from autoctf_gan.bespoke import _cpa_attack
    cap = json.loads(spec.artifacts["captures.json"])
    table = bytes.fromhex(spec.artifacts["sbox.hex"].strip())
    key, _ = _cpa_attack(table, cap["iv"],
                         [bytes.fromhex(t["challenge"]) for t in cap["captures"]],
                         [t["samples"] for t in cap["captures"]])
    return key.hex()


def _codebook_key(spec):
    import json
    from autoctf_gan.bespoke import _codebook_survivors, _feistel_encrypt
    table = bytes.fromhex(spec.artifacts["sbox.hex"].strip())
    pairs = [(int(p["pt"], 16), int(p["ct"], 16))
             for p in json.loads(spec.artifacts["pairs.json"])["pairs"]]
    keys = _codebook_survivors(list(table), pairs, limit=1)[0]
    lookup = {_feistel_encrypt(table, keys, b): b for b in range(65536)}
    blob = bytes.fromhex(spec.artifacts["archive.enc"].strip())
    plain = bytearray()
    for i in range(0, len(blob), 2):
        word = lookup[(blob[i] << 8) | blob[i + 1]]
        plain += bytes([word >> 8, word & 0xFF])
    return bytes(plain).hex()
if __name__ == "__main__":
    unittest.main()
