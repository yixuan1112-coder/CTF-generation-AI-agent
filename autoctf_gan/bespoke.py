"""Attacks on primitives nothing has ever published a script for.

Both rungs hand the player the device's own source. That is not generosity — it
is Kerckhoffs, and it is what makes the challenge honest: the algorithm is known,
the key is not, and no amount of reading the implementation recovers it. What
neither rung hands over is an attack, and neither construction appears in any
toolkit, so the canned scripts that clear a textbook rung have nothing to bind to.

  cpatrace   A provisioning HSM leaks one scalar per byte-step. The obvious move
             — recover each key byte independently from its own column, the way
             every published side-channel script does — cannot work here, because
             the leaking value is an accumulator that has already absorbed every
             earlier key byte. Once that is noticed the attack is ordinary and the
             bytes fall in sequence, each conditioned on the prefix already found.
             Get byte 3 wrong and bytes 4..15 are noise; there is no partial credit
             and no way to check a byte except by the statistics.

  codebook   A four-round Feistel over 16-bit blocks with four one-byte round keys.
             Thirty-two bits of key is small enough to look brute-forceable and
             large enough that it is not, in Python, against a 512-pair codebook.
             The intended route costs 2**16: guess the outer two keys, and the
             inner two are then *determined* rather than searched — one table
             inversion each, from a single pair, checked against four more.

Both seal the flag under a value only a completed attack produces.
"""
from __future__ import annotations

import hashlib
import json
import math
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
        lineage=Lineage(archetype_id=f"bespoke.{attack_class}", generation=generation,
                        parent_spec_id=None, mutation_ops=[], seed=seed),
        vuln_chain=[ChainStep(step=1, primitive=f"{attack_class}_stage",
                              params={}, guard=category)],
        artifacts=artifacts,
        official_solver=OfficialSolver(entry="solver.py", files=solver_files,
                                       expected_flag_sha256=expected,
                                       max_runtime_s=max_runtime_s),
        target_solve_rate=0.02)


def _slug(kind, flag_secret, seed, generation):
    tag = hashlib.sha256(f"{kind}:{flag_secret}:{seed}:{generation}".encode()).hexdigest()[:8]
    return f"bsp-{kind}-g{generation}-{tag}"


def _hw(value: int) -> int:
    return bin(value).count("1")


def _rol(value: int, n: int) -> int:
    return ((value << n) | (value >> (8 - n))) & 0xFF


def _pearson(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxy = sum((a - mx) * (b - my) for a, b in zip(xs, ys))
    sxx = sum((a - mx) ** 2 for a in xs)
    syy = sum((b - my) ** 2 for b in ys)
    return sxy / math.sqrt(sxx * syy) if sxx > 0 and syy > 0 else 0.0


# ---------------------------------------------------------------------------
# cpatrace — a leak that has already absorbed every earlier key byte
# ---------------------------------------------------------------------------
CPA_TRACES = 240
CPA_SIGMA = 2.0
CPA_KEY_BYTES = 16

_DEVICE_SOURCE = '''\
"""HSM-7 provisioning tag routine (reference build).

Folds a 16-byte challenge into a one-byte authentication tag under the device
key. One byte-step per challenge byte; the accumulator carries forward.
"""


def load_table(path="sbox.hex"):
    with open(path, encoding="utf-8") as fh:
        return bytes.fromhex("".join(fh.read().split()))


def rol(value, n):
    return ((value << n) | (value >> (8 - n))) & 0xFF


def tag(table, iv, key, challenge):
    """The value the accumulator holds after each byte-step, and the final tag."""
    acc = iv
    trail = []
    for i in range(16):
        acc = rol(acc ^ table[challenge[i] ^ key[i]], 3)
        trail.append(acc)
    return acc, trail


DEVICE_KEY = None          # fused at manufacture; not present in a service build
'''

_CPA_SOLVER = '''\
"""Recover an HSM-7 device key from its provisioning captures.

Every published attack of this shape recovers key bytes independently: one column
of the capture per key byte, 256 candidates each, done. That does not work here,
and `device.py` says why in one line —

    acc = rol(acc ^ table[challenge[i] ^ key[i]], 3)

`acc` is carried. The value alive at byte-step i is a function of key bytes
0..i, not of key byte i, so column i on its own is a mixture over 2**(8i)
hypotheses and correlates with nothing. Nothing about that is subtle once seen,
and it is the whole challenge.

The fix is to go in order. With bytes 0..i-1 already known, the accumulator
entering step i is known per trace, so the step-i hypothesis depends on exactly
one unknown byte again, and one ordinary correlation over the capture picks it:
model each candidate's post-step accumulator, score it against the recorded
sample column, take the strongest. Then carry the accumulator forward and repeat.

The samples are the accumulator's set bit count plus measurement noise, which is
what a bit count buried in noise looks like: a column centred near 4 with a
spread of about one and a half. No candidate but the right one survives 240
traces, but a wrong byte poisons every byte after it, so there is no partial
credit here — the sequence is right or it is noise from that point on.
"""
import json
import math

import device

HW = [bin(v).count("1") for v in range(256)]

table = device.load_table()
cap = json.load(open("captures.json", encoding="utf-8"))
iv = cap["iv"]
challenges = [bytes.fromhex(t["challenge"]) for t in cap["captures"]]
samples = [t["samples"] for t in cap["captures"]]
ntraces = len(challenges)


def pearson(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxy = sum((a - mx) * (b - my) for a, b in zip(xs, ys))
    sxx = sum((a - mx) ** 2 for a in xs)
    syy = sum((b - my) ** 2 for b in ys)
    return sxy / math.sqrt(sxx * syy) if sxx > 0 and syy > 0 else 0.0


key = bytearray(16)
acc = [iv] * ntraces                     # the accumulator entering the current step
for i in range(16):
    observed = [samples[t][i] for t in range(ntraces)]
    best = (-1.0, 0)
    for cand in range(256):
        model = [HW[device.rol(acc[t] ^ table[challenges[t][i] ^ cand], 3)]
                 for t in range(ntraces)]
        score = abs(pearson(model, observed))
        if score > best[0]:
            best = (score, cand)
    key[i] = best[1]
    acc = [device.rol(acc[t] ^ table[challenges[t][i] ^ key[i]], 3)
           for t in range(ntraces)]

# The device publishes the tag for one challenge; it is the only check available
# that the whole sequence is right rather than the first few bytes.
probe = bytes.fromhex(cap["probe"]["challenge"])
assert device.tag(table, iv, bytes(key), probe)[0] == cap["probe"]["tag"], \\
    "recovered key does not reproduce the published tag"

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), bytes(key).hex()))
'''


def _cpa_attack(table, iv, challenges, samples):
    """The solver's attack, run generator-side. Returns (key, weakest margin)."""
    hw = [_hw(v) for v in range(256)]
    ntraces = len(challenges)
    key = bytearray(CPA_KEY_BYTES)
    margins = []
    acc = [iv] * ntraces
    for i in range(CPA_KEY_BYTES):
        observed = [samples[t][i] for t in range(ntraces)]
        scored = []
        for cand in range(256):
            model = [hw[_rol(acc[t] ^ table[challenges[t][i] ^ cand], 3)]
                     for t in range(ntraces)]
            scored.append((abs(_pearson(model, observed)), cand))
        scored.sort(reverse=True)
        key[i] = scored[0][1]
        margins.append(scored[0][0] - scored[1][0])
        acc = [_rol(acc[t] ^ table[challenges[t][i] ^ key[i]], 3)
               for t in range(ntraces)]
    return bytes(key), min(margins)


def gen_cpatrace(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="cpatrace", seed=seed, generation=generation,
                          secret=flag_secret)
    for attempt in range(8):
        rng = random.Random(f"cpatrace:{flag_secret}:{seed}:{generation}:{attempt}")
        table = list(range(256))
        rng.shuffle(table)
        key = bytes(rng.randrange(256) for _ in range(CPA_KEY_BYTES))
        iv = rng.randrange(256)

        challenges, samples = [], []
        for _ in range(CPA_TRACES):
            challenge = bytes(rng.randrange(256) for _ in range(CPA_KEY_BYTES))
            acc, row = iv, []
            for i in range(CPA_KEY_BYTES):
                acc = _rol(acc ^ table[challenge[i] ^ key[i]], 3)
                row.append(round(_hw(acc) + rng.gauss(0, CPA_SIGMA), 3))
            challenges.append(challenge)
            samples.append(row)

        # A capture set that does not actually yield the key is an unsolvable rung,
        # and with noise in play that is a per-instance property, not a design one.
        recovered, margin = _cpa_attack(table, iv, challenges, samples)
        if recovered == key and margin > 0.04:
            break
    else:                                                  # pragma: no cover
        raise RuntimeError("cpatrace: no capture set separates the key")

    probe = bytes(rng.randrange(256) for _ in range(CPA_KEY_BYTES))
    probe_acc = iv
    for i in range(CPA_KEY_BYTES):
        probe_acc = _rol(probe_acc ^ table[probe[i] ^ key[i]], 3)

    artifacts = {
        "captures.json": json.dumps({
            "iv": iv,
            "probe": {"challenge": probe.hex(), "tag": probe_acc},
            "captures": [{"challenge": c.hex(), "samples": s}
                         for c, s in zip(challenges, samples)],
        }) + "\n",
        "sbox.hex": bytes(table).hex() + "\n",
        "device.py": _DEVICE_SOURCE,
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key.hex(), flag),
        "README.md": (
            "# HSM-7 provisioning captures\n\n"
            f"A current probe was left on an HSM-7 while it tagged {CPA_TRACES} "
            "provisioning challenges. The harness recorded one scalar per byte-step "
            "— sixteen per challenge, in step order — alongside the challenge that "
            "produced it. `device.py` is the tag routine as documented, with the "
            "fused key absent, and `sbox.hex` is the table it loads.\n\n"
            "One extra challenge is included with the tag the device actually "
            "returned for it, so a candidate key can be checked.\n\n"
            "The operator's recovery blob is sealed under the 16-byte device key as "
            "lowercase hex. `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("cpatrace", flag_secret, seed, generation),
        title="HSM-7 Provisioning Captures", category="crypto",
        challenge_type="chained-accumulator-side-channel",
        story=("A current probe sat on a provisioning HSM for 240 tag operations and "
               "recorded one scalar per byte-step. The tag routine is documented. The "
               "fused key is not."),
        vulnerability=("the leaking accumulator has absorbed every earlier key byte, so the "
                       "key falls only to a sequential attack conditioned on the prefix"),
        solution=["read the accumulator carry in the device routine",
                  "reject the per-byte-independent attack: column i mixes bytes 0..i",
                  "recover byte 0, carry the accumulator forward, repeat for each byte",
                  "confirm the whole sequence against the published probe tag"],
        artifacts=artifacts,
        solver_files={"solver.py": _CPA_SOLVER, "device.py": _DEVICE_SOURCE,
                      "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="cpatrace",
        rank=17, max_runtime_s=300, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# codebook — four rounds, four one-byte keys, and only 2**16 of real work
# ---------------------------------------------------------------------------
CODEBOOK_PAIRS = 512
CODEBOOK_SECRET_BYTES = 32

_CIPHER_SOURCE = '''\
"""PK-4 pairing cipher (reference build).

A four-round balanced Feistel on 16-bit blocks. Each round mixes the right half
through the shared table under one round key and folds it into the left half.
Round keys are one byte each and are fused at pairing time.
"""


def load_table(path="sbox.hex"):
    with open(path, encoding="utf-8") as fh:
        return bytes.fromhex("".join(fh.read().split()))


def encrypt(table, keys, block):
    left, right = block >> 8, block & 0xFF
    for key in keys:
        left, right = right, left ^ table[right ^ key]
    return (left << 8) | right


def decrypt(table, keys, block):
    left, right = block >> 8, block & 0xFF
    for key in reversed(keys):
        left, right = right ^ table[left ^ key], left
    return (left << 8) | right


PAIRING_KEYS = None        # fused at pairing; not present in a service build
'''

_CODEBOOK_SOLVER = '''\
"""Recover PK-4 pairing keys from a captured codebook.

Thirty-two bits of key invites a search over all of it. Four billion trial
encryptions is not a plan in this language, and it is also not necessary: only
the two OUTER round keys have to be guessed. The inner two are determined.

Write a pair as plaintext (L0, R0) and ciphertext (CL, CR). Rolling the rounds
out, with Ri the right half after round i:

    R1 = L0 ^ S[R0 ^ k1]                      (forward, needs k1)
    R2 = R0 ^ S[R1 ^ k2]
    R3 = R1 ^ S[R2 ^ k3]   and   R3 == CL     (the last round's left half)
    CR = R2 ^ S[CL ^ k4]                      (backward, needs k4)

Guess k1 and k4. R1 comes out of the first line and R2 out of the last, so both
middle equations now have a single unknown inside the table lookup, and the table
is a permutation — so each inverts directly, from ONE pair:

    k2 = Sinv[R2 ^ R0] ^ R1
    k3 = Sinv[CL ^ R1] ^ R2

That is 2**16 guesses at a couple of table lookups each, not 2**32 encryptions.
Confirm a surviving quadruple against a handful of further pairs — a wrong guess
reproduces one pair by construction and the next one only by luck — then check it
against the whole codebook before trusting it with the archive.
"""
import json

import cipher

table = cipher.load_table()
inv = [0] * 256
for value, mapped in enumerate(table):
    inv[mapped] = value

pairs = [(int(p["pt"], 16), int(p["ct"], 16))
         for p in json.load(open("pairs.json", encoding="utf-8"))["pairs"]]
probe = pairs[:6]

found = None
for k1 in range(256):
    for k4 in range(256):
        keys = None
        for idx, (pt, ct) in enumerate(probe):
            l0, r0 = pt >> 8, pt & 0xFF
            cl, cr = ct >> 8, ct & 0xFF
            r1 = l0 ^ table[r0 ^ k1]
            r2 = cr ^ table[cl ^ k4]
            if idx == 0:
                keys = [k1, inv[r2 ^ r0] ^ r1, inv[cl ^ r1] ^ r2, k4]
            elif cipher.encrypt(table, keys, pt) != ct:
                keys = None
                break
        if keys and all(cipher.encrypt(table, keys, pt) == ct for pt, ct in pairs):
            found = keys
            break
    if found:
        break

assert found, "no key quadruple reproduces the codebook"

blob = bytes.fromhex(open("archive.enc", encoding="utf-8").read().strip())
plain = bytearray()
for i in range(0, len(blob), 2):
    word = cipher.decrypt(table, found, (blob[i] << 8) | blob[i + 1])
    plain += bytes([word >> 8, word & 0xFF])

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), bytes(plain).hex()))
'''


def _feistel_encrypt(table, keys, block):
    left, right = block >> 8, block & 0xFF
    for key in keys:
        left, right = right, left ^ table[right ^ key]
    return (left << 8) | right


def _codebook_survivors(table, pairs, limit):
    """Every key quadruple consistent with the whole codebook, up to `limit`.

    The generator needs this to prove the answer is unique. A second quadruple
    reproducing all 512 pairs would make the sealed archive unopenable by a solver
    that found the other one first, which is an unsolvable rung, not a hard one.
    """
    inv = [0] * 256
    for value, mapped in enumerate(table):
        inv[mapped] = value
    probe = pairs[:6]
    out = []
    for k1 in range(256):
        for k4 in range(256):
            keys = None
            for idx, (pt, ct) in enumerate(probe):
                l0, r0 = pt >> 8, pt & 0xFF
                cl, cr = ct >> 8, ct & 0xFF
                r1 = l0 ^ table[r0 ^ k1]
                r2 = cr ^ table[cl ^ k4]
                if idx == 0:
                    keys = [k1, inv[r2 ^ r0] ^ r1, inv[cl ^ r1] ^ r2, k4]
                elif _feistel_encrypt(table, keys, pt) != ct:
                    keys = None
                    break
            if keys and all(_feistel_encrypt(table, keys, pt) == ct for pt, ct in pairs):
                out.append(tuple(keys))
                if len(out) >= limit:
                    return out
    return out


def gen_codebook(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="codebook", seed=seed, generation=generation,
                          secret=flag_secret)
    for attempt in range(8):
        rng = random.Random(f"codebook:{flag_secret}:{seed}:{generation}:{attempt}")
        table = list(range(256))
        rng.shuffle(table)
        keys = [rng.randrange(256) for _ in range(4)]
        blocks = rng.sample(range(65536), CODEBOOK_PAIRS)
        pairs = [(b, _feistel_encrypt(table, keys, b)) for b in blocks]
        survivors = _codebook_survivors(table, pairs, limit=2)
        if survivors == [tuple(keys)]:
            break
    else:                                                  # pragma: no cover
        raise RuntimeError("codebook: key quadruple is not uniquely determined")

    secret = bytes(rng.randrange(256) for _ in range(CODEBOOK_SECRET_BYTES))
    archive = bytearray()
    for i in range(0, len(secret), 2):
        word = _feistel_encrypt(table, keys, (secret[i] << 8) | secret[i + 1])
        archive += bytes([word >> 8, word & 0xFF])

    artifacts = {
        "pairs.json": json.dumps({
            "note": "challenge/response pairs recovered from the pairing log",
            "pairs": [{"pt": f"{p:04x}", "ct": f"{c:04x}"} for p, c in pairs],
        }) + "\n",
        "archive.enc": bytes(archive).hex() + "\n",
        "sbox.hex": bytes(table).hex() + "\n",
        "cipher.py": _CIPHER_SOURCE,
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(secret.hex(), flag),
        "README.md": (
            "# PK-4 pairing log\n\n"
            f"A pairing log yielded {CODEBOOK_PAIRS} challenge/response pairs from one "
            "paired device, all under the same fused round keys. `cipher.py` is the "
            "reference build of the pairing cipher and `sbox.hex` is the table it "
            "loads; the fused keys are absent from a service build.\n\n"
            "`archive.enc` is the device's maintenance record, encrypted block by "
            "block under those same keys. The operator's recovery blob is sealed "
            "under the decrypted record as lowercase hex. `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("codebook", flag_secret, seed, generation),
        title="PK-4 Pairing Log", category="crypto",
        challenge_type="feistel-outer-key-guess",
        story=("A pairing log captured 512 challenge/response pairs from one device, "
               "all under the same fused round keys, along with the encrypted "
               "maintenance record those keys protect."),
        vulnerability=("only the two outer round keys need guessing; the inner two are "
                       "determined by table inversion from a single pair"),
        solution=["roll out the four rounds and name the right half after each",
                  "guess the outer keys so the middle equations have one unknown each",
                  "invert the table for the two inner keys from a single pair",
                  "confirm the quadruple on the whole codebook, then decrypt the record"],
        artifacts=artifacts,
        solver_files={"solver.py": _CODEBOOK_SOLVER, "cipher.py": _CIPHER_SOURCE,
                      "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="codebook",
        rank=15, max_runtime_s=300, flag_secret=flag_secret)


BESPOKE_BUILDERS = [gen_cpatrace, gen_codebook]
