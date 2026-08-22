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
from autoctf_gan.agentbench import (AGENTBENCH_BUILDERS, gen_chainlink,
                                    gen_falsestart, gen_toolliar)
from autoctf_gan.bespoke import BESPOKE_BUILDERS, gen_codebook, gen_cpatrace
from autoctf_gan.composite import COMPOSITE_BUILDERS, gen_cascade, gen_triad
from autoctf_gan.estranged import (ESTRANGED_BUILDERS, gen_mirage, gen_sandtrap,
                                   gen_statewalk)
from autoctf_gan.evalhard import EVALHARD_BUILDERS, gen_cgmdecode, gen_fwscope
from autoctf_gan.harder import (HARDER_BUILDERS, gen_crosskey, gen_filtergen,
                                gen_hmacpollute)
from autoctf_gan.hardtier import (HARDTIER_BUILDERS, gen_mqlin, gen_phsmooth,
                                  gen_rswelch)
from autoctf_gan.humanhard import (HUMANHARD_BUILDERS, gen_blackbox,
                                   gen_gridpath, gen_wythoff)
from autoctf_gan.morepico import (MOREPICO_BUILDERS, gen_dnschain, gen_rotkey,
                                  gen_streamweave)
from autoctf_gan.picostyle import (PICOSTYLE_BUILDERS, gen_mbakeygen,
                                   gen_nestpeel)
from autoctf_gan.realvuln import REALVULN_BUILDERS, gen_cbcflip, gen_lenext
from autoctf_gan.signals import SIGNALS_BUILDERS
from autoctf_gan.verify import verify_spec
from autoctf_gan.walls import WALLS_BUILDERS, gen_ecdlpwall, gen_rsawall

ALL_BUILDERS = (ADVERSARIAL_BUILDERS + AIRESISTANT_BUILDERS + BESPOKE_BUILDERS
                + AGENTBENCH_BUILDERS + PICOSTYLE_BUILDERS + MOREPICO_BUILDERS
                + HUMANHARD_BUILDERS + HARDTIER_BUILDERS + COMPOSITE_BUILDERS
                + REALVULN_BUILDERS + SIGNALS_BUILDERS + HARDER_BUILDERS
                + EVALHARD_BUILDERS + ESTRANGED_BUILDERS + WALLS_BUILDERS)

# Words that would hand over the technique. Each rung's difficulty is that a
# player has to arrive at one of these on their own.
_GIVEAWAYS = ("knapsack", "gradient", "descent", "off-by-one", "off by one",
              "bit-revers", "bit revers", "brute force", "brute-force",
              "adversarial", "dead end", "red herring", "decoy", "honeypot",
              "out of bounds", "out-of-bounds", "correlation", "correlate",
              "hamming", "side channel", "side-channel", "shamir", "lagrange",
              "factorial", "permutation", "lehmer", "interpolat", "tampered",
              "polyglot", "planted", "wrong key", "meet in the middle",
              "baby step", "unproductive", "affine", "xor in disguise",
              "gaussian", "boolean-arithmetic", "linked list", "linked-list",
              "circular", "follow the chain", "wythoff", "golden ratio",
              "golden-ratio", "fibonacci", "beatty", "1.618", "sqrt(5)",
              "difference signature", "berlekamp", "welch", "reed-solomon",
              "error locator", "error-locator", "pohlig", "monomial",
              "linearise", "linearize", "reused", "cancel the blind", "subtract",
              "length extension", "length-extension", "malleable", "bit-flip",
              "hashpump", "berlekamp", "massey", "last write", "last-value",
              "signing scope", "signing-scope", "unauthenticated header")


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
            (gen_falsestart, _falsestart_key),
            (gen_toolliar, _toolliar_key),
            (gen_chainlink, _chainlink_key),
            (gen_nestpeel, _nestpeel_key),
            (gen_mbakeygen, _mbakeygen_key),
            (gen_streamweave, _streamweave_key),
            (gen_dnschain, _dnschain_key),
            (gen_rotkey, _rotkey_key),
            (gen_wythoff, _wythoff_key),
            (gen_blackbox, _blackbox_key),
            (gen_gridpath, _gridpath_key),
            (gen_rswelch, _rswelch_key),
            (gen_phsmooth, _phsmooth_key),
            (gen_mqlin, _mqlin_key),
            (gen_cascade, _cascade_key),
            (gen_lenext, _lenext_key),
            (gen_cbcflip, _cbcflip_key),
            (gen_hmacpollute, _hmacpollute_key),
            (gen_fwscope, _fwscope_key),
            (gen_cgmdecode, _cgmdecode_key),
            (gen_mirage, _mirage_key),
            (gen_sandtrap, _sandtrap_key),
            (gen_statewalk, _statewalk_key),
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

def _falsestart_key(spec):
    import hashlib
    import json
    doc = json.loads(spec.artifacts["archive.json"])
    pads = [bytes.fromhex(p) for p in json.loads(spec.artifacts["keyring.json"])["pads"]]
    out = []
    for record in doc["records"]:
        data = bytes.fromhex(record["data"])
        for pad in pads:
            plain = bytes(a ^ b for a, b in zip(data, pad))
            if hashlib.sha256(plain).hexdigest() == record["digest"]:
                out.append(plain)
                break
        else:
            raise AssertionError(f"record {record['seq']} has no matching pad")
    return b"".join(out).hex()


def _toolliar_key(spec):
    import base64
    import zlib
    blob = base64.b64decode("".join(spec.artifacts["container.b64"].split()))
    frags, pos = {}, 8
    while pos + 8 <= len(blob):
        length = int.from_bytes(blob[pos:pos + 4], "big")
        ctype = blob[pos + 4:pos + 8]
        data = blob[pos + 8:pos + 8 + length]
        stored = blob[pos + 8 + length:pos + 12 + length]
        if len(stored) < 4:
            break
        if ctype == b"prVt" and (zlib.crc32(ctype + data) & 0xFFFFFFFF
                                 == int.from_bytes(stored, "big")):
            frags[data[0]] = data[1:]
        pos += 12 + length
        if ctype == b"IEND":
            break
    return zlib.decompress(b"".join(frags[i] for i in sorted(frags))).hex()


def _chainlink_key(spec):
    """Walk all five stages. Slower than replaying the generator, and the point:
    it re-proves that each stage's answer is the only way into the next."""
    import base64
    import json
    import math
    import zlib

    def unseal(blob_hex, secret):
        import hashlib
        raw = bytes.fromhex(blob_hex.strip())
        out, counter = bytearray(), 0
        while len(out) < len(raw):
            out += hashlib.sha256(secret.encode() + b"|" + str(counter).encode()).digest()
            counter += 1
        plain = bytes(a ^ b for a, b in zip(raw, out))
        assert plain.startswith(b"AUTOCTF-HC\x00"), "wrong secret"
        return plain[len(b"AUTOCTF-HC\x00"):].decode()

    raw = base64.b64decode("".join(spec.artifacts["recovered.b64"].split()))
    engine = zlib.decompressobj()
    engine.decompress(raw)
    a1 = engine.unused_data.hex()

    stage2 = json.loads(unseal(spec.artifacts["stage2.sealed"], a1))
    inv7 = pow(7, -1, 256)
    state = json.loads(stage2["params.json"])["k"]
    plain = bytearray()
    for v in bytes.fromhex(stage2["target.hex"].strip()):
        u = ((v >> 5) | (v << 3)) & 0xFF
        plain.append((((u - 13) * inv7) & 0xFF) ^ state)
        state = (state + v) & 0xFF
    a2 = bytes(plain).hex()

    stage3 = json.loads(unseal(stage2["stage3.sealed"], a2))
    cipher = bytes.fromhex(stage3["memo.hex"].strip())
    crib = json.loads(stage3["params.json"])["opens_with"].encode()
    stream = bytes(a ^ b for a, b in zip(cipher, crib))
    period = next(n for n in range(1, len(crib))
                  if all(stream[i] == stream[i % n] for i in range(len(stream))))
    memo = bytes(c ^ stream[i % period] for i, c in enumerate(cipher)).decode()
    a3 = memo.rsplit("RELEASE TOKEN: ", 1)[1].split()[0]

    stage4 = json.loads(unseal(stage3["stage4.sealed"], a3))
    doc = json.loads(stage4["outputs.json"])
    p = int(doc["modulus"])
    xs = [int(v) for v in doc["outputs"]]
    mult = (xs[2] - xs[1]) * pow(xs[1] - xs[0], -1, p) % p
    incr = (xs[1] - mult * xs[0]) % p
    a4 = "%x" % ((xs[0] - incr) * pow(mult, -1, p) % p)

    stage5 = json.loads(unseal(stage4["stage5.sealed"], a4))
    dh = json.loads(stage5["exchange.json"])
    p, g, h = int(dh["p"]), int(dh["g"]), int(dh["h"])
    m = math.isqrt(p - 1) + 1
    table, cur = {}, 1
    for j in range(m):
        table.setdefault(cur, j)
        cur = cur * g % p
    factor, cur = pow(pow(g, m, p), -1, p), h
    for i in range(m + 1):
        if cur in table:
            return "%x" % (i * m + table[cur])
        cur = cur * factor % p
    raise AssertionError("no discrete log found")


def _nestpeel_key(spec):
    import base64
    import binascii
    import json
    import zlib
    from autoctf_gan.picostyle import NEST_MARKER as MARK
    manifest = json.loads(spec.artifacts["manifest.json"])
    blob = bytes.fromhex("".join(spec.artifacts["wrapped.hex"].split()))
    for layer in manifest["layers"]:
        codec = layer["codec"]
        if codec == "hex":
            blob = binascii.unhexlify(blob)
        elif codec == "base64":
            blob = base64.b64decode(blob)
        elif codec == "base85":
            blob = base64.b85decode(blob)
        elif codec == "zlib":
            blob = zlib.decompress(blob)
        elif codec == "reverse":
            blob = blob[::-1]
        elif codec == "rot":
            amt = (blob[0] - MARK[0]) % 256
            blob = bytes((b - amt) % 256 for b in blob)
        elif codec == "xorb":
            const = blob[0] ^ MARK[0]
            blob = bytes(b ^ const for b in blob)
        elif codec == "keystream":
            klen = layer["key_len"]
            key = bytes(blob[i] ^ MARK[i] for i in range(klen))
            blob = bytes(b ^ key[i % klen] for i, b in enumerate(blob))
        assert blob.startswith(MARK)
        blob = blob[len(MARK):]
    return blob.hex()


def _mbakeygen_key(spec):
    import json
    from autoctf_gan.picostyle import MBA_BITS, _mba_scramble
    doc = json.loads(spec.artifacts["rounds.json"])
    rounds = [tuple(r) for r in doc["rounds"]]
    target = int(doc["target"])
    c = _mba_scramble(0, rounds)
    cols = [_mba_scramble(1 << i, rounds) ^ c for i in range(MBA_BITS)]
    b = target ^ c
    rows = [[sum(((cols[i] >> j) & 1) << i for i in range(MBA_BITS)), (b >> j) & 1]
            for j in range(MBA_BITS)]
    pr, pc = 0, {}
    for col in range(MBA_BITS):
        sel = next((r for r in range(pr, MBA_BITS) if (rows[r][0] >> col) & 1), None)
        if sel is None:
            continue
        rows[pr], rows[sel] = rows[sel], rows[pr]
        for r in range(MBA_BITS):
            if r != pr and (rows[r][0] >> col) & 1:
                rows[r][0] ^= rows[pr][0]
                rows[r][1] ^= rows[pr][1]
        pc[col] = pr
        pr += 1
    key_int = sum((1 << col) for col, r in pc.items() if rows[r][1])
    return key_int.to_bytes(MBA_BITS // 8, "big").hex()


def _streamweave_key(spec):
    import json
    import zlib
    doc = json.loads(spec.artifacts["capture.json"])
    base, count = doc["base_seq"], doc["frag_count"]
    good = {}
    for frag in doc["fragments"]:
        data = bytes.fromhex(frag["data"])
        if zlib.crc32(data) & 0xFFFFFFFF == frag["crc"]:
            good.setdefault(frag["seq"], data)
    return b"".join(good[(base + k) & 0xFFFF] for k in range(count)).hex()


def _dnschain_key(spec):
    import json
    doc = json.loads(spec.artifacts["querylog.json"])
    alphabet = doc["b32_alphabet"]
    by_id = {q["txid"]: q for q in doc["queries"]}
    labels, cur = [], doc["head"]
    while cur != 0:
        labels.append(by_id[cur]["label"])
        cur = by_id[cur]["next"]
    val = {c: i for i, c in enumerate(alphabet)}
    bits = "".join(f"{val[c]:05b}" for c in "".join(labels))
    return bytes(int(bits[i:i + 8], 2)
                 for i in range(0, len(bits) - len(bits) % 8, 8)).hex()


def _rotkey_key(spec):
    import hashlib
    import json
    doc = json.loads(spec.artifacts["records.json"])
    crib = doc["record0_opens_with"].encode()
    L = len(crib)
    records = [bytes.fromhex(r["data"]) for r in doc["records"]]
    digests = [r["sha256"] for r in doc["records"]]
    key = bytes(records[0][i] ^ crib[i] for i in range(L))
    out = []
    for data, digest in zip(records, digests):
        for shift in range(L):
            rk = key[shift:] + key[:shift]
            plain = bytes(b ^ rk[i % L] for i, b in enumerate(data))
            if hashlib.sha256(plain).hexdigest() == digest:
                out.append(plain)
                break
        else:
            raise AssertionError("no rotation matched a record digest")
    return b"".join(out).hex()


def _wythoff_key(spec):
    import json
    import math
    positions = json.loads(spec.artifacts["positions.json"])["positions"]

    def losing(a, b):
        if a > b:
            a, b = b, a
        k = b - a
        return a == (k + math.isqrt(5 * k * k)) // 2

    bits = "".join("0" if losing(p[0], p[1]) else "1" for p in positions)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)).hex()


def _blackbox_key(spec):
    import json
    doc = json.loads(spec.artifacts["pairs.json"])
    W = doc["width"]
    pairs = [(bytes.fromhex(p["in"]), bytes.fromhex(p["out"])) for p in doc["pairs"]]
    target = bytes.fromhex(doc["target_out"])
    in0, out0 = pairs[0]
    in_sig = [bytes(pairs[p][0][c] ^ in0[c] for p in range(1, len(pairs))) for c in range(W)]
    out_sig = [bytes(pairs[p][1][c] ^ out0[c] for p in range(1, len(pairs))) for c in range(W)]
    perm = [next(c for c in range(W) if out_sig[i] == in_sig[c]) for i in range(W)]
    mask = [out0[i] ^ in0[perm[i]] for i in range(W)]
    key = bytearray(W)
    for i in range(W):
        key[perm[i]] = target[i] ^ mask[i]
    return bytes(key).hex()


def _gridpath_key(spec):
    import json
    doc = json.loads(spec.artifacts["grid.json"])
    H, W, flat = doc["height"], doc["width"], doc["readings"]
    cells = [flat[r * W:(r + 1) * W] for r in range(H)]

    def lit(r, c):
        return 0 <= r < H and 0 <= c < W and cells[r][c] >= 0xA0

    start = next((r, c) for r in range(H) for c in range(W) if cells[r][c] == 0xFF)
    nibbles, prev, cur = [], None, start
    while True:
        nxt = None
        for dr, dc in ((-1, 0), (1, 0), (0, -1), (0, 1)):
            nr, nc = cur[0] + dr, cur[1] + dc
            if lit(nr, nc) and (nr, nc) != prev:
                nxt = (nr, nc)
                break
        if nxt is None:
            break
        nibbles.append(cells[nxt[0]][nxt[1]] & 0x0F)
        prev, cur = cur, nxt
    return bytes((nibbles[i] << 4) | nibbles[i + 1]
                 for i in range(0, len(nibbles), 2)).hex()


def _rswelch_key(spec):
    import json
    doc = json.loads(spec.artifacts["samples.json"])
    p, deg, e = doc["prime"], doc["degree"], doc["errors"]
    pts = [(int(v["x"]), int(v["y"])) for v in doc["samples"]]
    nq = deg + e + 1
    ncols = nq + e
    rows = []
    for x, y in pts:
        row = [0] * (ncols + 1)
        xp = 1
        for j in range(nq):
            row[j] = xp
            xp = xp * x % p
        xp = 1
        for i in range(e):
            row[nq + i] = (-y * xp) % p
            xp = xp * x % p
        row[ncols] = (y * pow(x, e, p)) % p
        rows.append(row)
    R = [r[:] for r in rows]
    where = [-1] * ncols
    r = 0
    for col in range(ncols):
        sel = next((i for i in range(r, len(R)) if R[i][col] % p), None)
        if sel is None:
            continue
        R[r], R[sel] = R[sel], R[r]
        inv = pow(R[r][col], -1, p)
        R[r] = [(v * inv) % p for v in R[r]]
        for i in range(len(R)):
            if i != r and R[i][col] % p:
                f = R[i][col]
                R[i] = [(a - f * b) % p for a, b in zip(R[i], R[r])]
        where[col] = r
        r += 1
    sol = [R[where[c]][ncols] if where[c] != -1 else 0 for c in range(ncols)]
    Q, E = sol[:nq], sol[nq:] + [1]
    num = Q[:]
    dd = len(E) - 1
    dinv = pow(E[-1], -1, p)
    quot = [0] * max(1, len(num) - dd)
    for i in range(len(num) - 1, dd - 1, -1):
        c = (num[i] * dinv) % p
        quot[i - dd] = c
        for j in range(dd + 1):
            num[i - dd + j] = (num[i - dd + j] - c * E[j]) % p
    f = (quot + [0] * (deg + 1))[:deg + 1]
    return "".join(f"{c:016x}" for c in f)


def _phsmooth_key(spec):
    import json
    from math import gcd, isqrt
    doc = json.loads(spec.artifacts["exchange.json"])
    p, g, h = int(doc["p"]), int(doc["g"]), int(doc["h"])

    def is_prime(n):
        if n < 2:
            return False
        for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % q == 0:
                return n == q
        d, r = n - 1, 0
        while d % 2 == 0:
            d //= 2
            r += 1
        for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    def rho(n):
        if n % 2 == 0:
            return 2
        c = 1
        while True:
            x = y = 2
            d = 1
            while d == 1:
                x = (x * x + c) % n
                y = (y * y + c) % n
                y = (y * y + c) % n
                d = gcd(abs(x - y), n)
            if d != n:
                return d
            c += 1

    def factor(n):
        fac, stack = {}, [n]
        while stack:
            m = stack.pop()
            if m == 1:
                continue
            if is_prime(m):
                fac[m] = fac.get(m, 0) + 1
                continue
            d = rho(m)
            stack += [d, m // d]
        return fac

    def bsgs(base, target, mod, order):
        m = isqrt(order) + 1
        table, e = {}, 1
        for j in range(m):
            table.setdefault(e, j)
            e = e * base % mod
        step = pow(pow(base, m, mod), -1, mod)
        cur = target
        for i in range(m + 1):
            if cur in table:
                return i * m + table[cur]
            cur = cur * step % mod
        raise AssertionError("no log")

    order = p - 1
    res, mod = [], []
    for q, a in factor(order).items():
        pe = q ** a
        res.append(bsgs(pow(g, order // pe, p), pow(h, order // pe, p), p, pe) % pe)
        mod.append(pe)
    M = 1
    for m in mod:
        M *= m
    x = 0
    for r, m in zip(res, mod):
        Mi = M // m
        x = (x + r * Mi * pow(Mi, -1, m)) % M
    return f"{x:x}"


def _mqlin_key(spec):
    import json
    doc = json.loads(spec.artifacts["system.json"])
    n = doc["vars"]
    col = {}

    def column(mono):
        if mono not in col:
            col[mono] = len(col)
        return col[mono]

    parsed = []
    for eq in doc["equations"]:
        bits = set()
        for mono in eq["m"]:
            bits ^= {column(mono)}
        parsed.append((bits, eq["r"]))
    ncols = len(col)
    rows = []
    for bits, rhs in parsed:
        word = 0
        for c in bits:
            word |= 1 << c
        rows.append(word | (rhs << ncols))
    where = [-1] * ncols
    r = 0
    for c in range(ncols):
        sel = next((i for i in range(r, len(rows)) if (rows[i] >> c) & 1), None)
        if sel is None:
            continue
        rows[r], rows[sel] = rows[sel], rows[r]
        for i in range(len(rows)):
            if i != r and (rows[i] >> c) & 1:
                rows[i] ^= rows[r]
        where[c] = r
        r += 1
    sol = [((rows[where[c]] >> ncols) & 1) if where[c] != -1 else 0 for c in range(ncols)]
    key_bits = [sol[col[str(i)]] for i in range(n)]
    return bytes(int("".join(str(b) for b in key_bits[i:i + 8]), 2)
                 for i in range(0, n, 8)).hex()


class WallsAreRealAndTrapdoorStaysHidden(unittest.TestCase):
    """The compute walls verify only through the organizer trapdoor, which — like
    the flag — must never appear in a player artifact. There is no player-side
    extractor to test against, because not having one is the point."""

    def test_rsawall_trapdoor_absent_and_modulus_hard(self):
        import re
        from autoctf_gan.walls import _rsa_primes_cached
        spec = gen_rsawall(seed=909, generation=0, flag_secret="secret-909")
        p, q = _rsa_primes_cached("secret-909", 909, 0, None)
        n = int(re.search(r"n = (\d+)", spec.artifacts["key.txt"]).group(1))
        self.assertEqual(n, p * q)
        self.assertGreaterEqual(n.bit_length(), 2047)          # a real 2048-bit modulus
        self.assertGreater(abs(p - q).bit_length(), 500)        # far apart -> Fermat-immune
        for content in spec.artifacts.values():
            self.assertNotIn(str(min(p, q)), content)           # trapdoor factor never ships
            self.assertNotIn(spec.flag, content)

    def test_ecdlpwall_trapdoor_absent(self):
        import random
        from autoctf_gan.curves import SECP256K1_N
        spec = gen_ecdlpwall(seed=909, generation=0, flag_secret="secret-909")
        d = random.Random("ecdlpwall:secret-909:909:0").randrange(1 << 250, SECP256K1_N - 1)
        for content in spec.artifacts.values():
            self.assertNotIn(str(d), content)
            self.assertNotIn(spec.flag, content)


def _cascade_key(spec):
    import hashlib
    import json
    doc = json.loads(spec.artifacts["tags.json"])
    M = int(doc["M"])
    (h1, t1), (h2, t2) = [(int(x["h"]), int(x["t"])) for x in doc["tags"]]
    k = (t1 - t2) * pow(h1 - h2, -1, M) % M
    blob = bytes.fromhex(spec.artifacts["payload.enc"].strip())
    out, counter = bytearray(), 0
    while len(out) < len(blob):
        out += hashlib.sha256(f"cascade-ks:{k}:{counter}".encode()).digest()
        counter += 1
    return bytes(a ^ b for a, b in zip(blob, out)).decode()


def _lenext_key(spec):
    import json
    ns = {}
    exec(spec.artifacts["authhash.py"], ns)
    doc = json.loads(spec.artifacts["token.json"])
    msg = doc["message"].encode()
    mac = int(doc["mac"], 16)
    slen = doc["secret_len"]
    ext = doc["extension"].encode()
    glue = ns["pad"](slen + len(msg))
    data = ext + ns["pad"](slen + len(msg) + len(glue) + len(ext))
    st = mac
    for i in range(0, len(data), ns["B"]):
        st = ns["compress"](st, data[i:i + ns["B"]])
    return f"{st:016x}"


def _cbcflip_key(spec):
    import json
    doc = json.loads(spec.artifacts["token.json"])
    B = doc["block_size"]
    iv = bytes.fromhex(doc["iv"])
    ct = bytes.fromhex(doc["ciphertext"])
    blocks = [ct[i:i + B] for i in range(0, len(ct), B)]
    known = doc["plaintext_template"].encode("latin-1")
    target = doc["target_plaintext"].encode("latin-1")
    rb = doc["role_block_index"]
    delta = bytes(a ^ b for a, b in zip(known[rb * B:(rb + 1) * B],
                                        target[rb * B:(rb + 1) * B]))
    chain = [iv] + blocks
    prev = bytes(a ^ b for a, b in zip(chain[rb], delta))
    fb = blocks[:]
    fb[rb - 1] = prev
    return (iv + b"".join(fb)).hex()


def _hmacpollute_key(spec):
    import json
    ns = {}
    exec(spec.artifacts["authhash.py"], ns)
    doc = json.loads(spec.artifacts["token.json"])
    msg = doc["message"].encode()
    mac = int(doc["mac"], 16)
    slen = doc["secret_len"]
    ext = b"&role=admin"
    glue = ns["pad"](slen + len(msg))
    data = ext + ns["pad"](slen + len(msg) + len(glue) + len(ext))
    st = mac
    for i in range(0, len(data), ns["B"]):
        st = ns["compress"](st, data[i:i + ns["B"]])
    return f"{st:016x}"


def _fwscope_key(spec):
    import struct
    image = bytes.fromhex(spec.artifacts["firmware.hex"].strip())
    v, r, eo, bo, bl = struct.unpack("<HHIII", image[4:20])
    prefix = image[:bo + bl + 32]
    payload = b"PAYLOAD\x00" + b"\x00" * 8
    new_header = struct.pack("<HHIII", v, r, len(prefix), bo, bl)
    forged = image[:4] + new_header + image[20:bo + bl + 32] + payload
    return forged.hex()


def _cgmdecode_key(spec):
    import json

    def crc8(data):
        crc = 0
        for byte in data:
            crc ^= byte
            for _ in range(8):
                crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
        return crc

    records = [bytes.fromhex(r) for r in json.loads(spec.artifacts["capture.json"])["records"]]
    for seed in range(256):
        ks, s2 = [], seed & 0xFF
        for _ in range(len(records) * 2):
            s2 = (s2 * 0x6D + 0x3B) & 0xFF
            ks.append(s2)
        ok, msg = True, bytearray()
        for i, rec in enumerate(records):
            val = bytes([rec[1] ^ ks[2 * i], rec[2] ^ ks[2 * i + 1]])
            if crc8(bytes([rec[0]]) + val) != rec[3]:
                ok = False
                break
            msg.append(val[0])
        if ok:
            return bytes(msg).rstrip(b"\x00").hex()
    raise AssertionError("no whitening seed checks")

def _mirage_key(spec):
    import json
    d = json.loads(spec.artifacts["target.json"])
    T, A, B, C = d["token"], d["A"], d["B"], d["C"]
    Ai = pow(A, -1, 256)
    n = len(T)
    key = [0] * n
    key[n - 1] = (Ai * ((T[n - 1] - C[n - 1]) % 256)) % 256
    for i in range(n - 2, -1, -1):
        key[i] = (Ai * ((T[i] - B * key[i + 1] - C[i]) % 256)) % 256
    return bytes(key).hex()


def _sandtrap_key(spec):
    import json
    from autoctf_gan.estranged import _sand_gmul
    d = json.loads(spec.artifacts["target.json"])
    T, a, C = d["token"], d["a"], d["C"]
    ia = next(b for b in range(1, 256) if _sand_gmul(a, b) == 1)
    return bytes(_sand_gmul(T[i] ^ C[i], ia) for i in range(len(T))).hex()


def _statewalk_key(spec):
    import json
    from autoctf_gan.estranged import _state_run
    prog = [tuple(p) for p in json.loads(spec.artifacts["program.json"])["program"]]
    return _state_run(prog, modal=True).hex()


if __name__ == "__main__":
    unittest.main()
