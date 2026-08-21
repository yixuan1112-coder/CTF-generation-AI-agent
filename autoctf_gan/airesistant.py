"""Challenges built against the failure modes of a tooled-up solving agent.

Everything else in this repo is hard because the *mathematics* is hard. These are
hard for a different reason: each one is shaped so that recognition, library
reuse, and the first plausible lead all point the wrong way, and only reading the
actual artifact carefully gets you through.

  oddproto   A vendor binary protocol whose published specification is wrong. The
             field the spec calls a length is the bit-reversal of one, and the
             escape constant is not the HDLC value the spec claims. Feeding the
             capture to a standard framing parser produces confident garbage. The
             frame trailers are honest CRCs, so the true rules are recoverable —
             but only by disbelieving the document you were handed.

  vmkeygen   A maintenance key checked by a bytecode program for a made-up stack
             machine. The interpreter ships, the bytecode ships, the instruction
             semantics are therefore knowable — but no disassembler, decompiler or
             symbolic-execution frontend has ever seen this ISA, so the whole solve
             is hand work on an opcode stream.

  lsbseed    A payload hidden in image LSBs at positions drawn by a non-standard
             PRNG whose seed was lost. The embedding tool ships with the seed
             redacted, so the schedule is known exactly and the seed is not: the
             only route is to search the seed space, which is small enough to be
             fair and large enough that no amount of reasoning replaces the search.

  honeytrap  A device dump with a loud, obvious, deliberately dead vulnerability
             sitting in front of a quiet real one. The bait decodes cleanly, which
             is what makes it expensive — it looks like progress.

Every rung here seals the flag under a value only a completed solve produces, and
none of them writes the flag into a player artifact.
"""
from __future__ import annotations

import hashlib
import json
import random

from .hardcore import _SEAL_TOOL, _seal
from .identity import challenge_flag


def _spec(*, slug, title, category, challenge_type, story, vulnerability, solution,
          artifacts, solver_files, flag, seed, generation, attack_class, rank,
          max_runtime_s, flag_secret, difficulty="hard"):
    from .models import ChainStep, ChallengeSpec, Lineage, OfficialSolver
    expected = hashlib.sha256(flag.encode()).hexdigest()
    return ChallengeSpec(
        slug=slug, title=f"{title} (Gen-{generation})", category=category,
        challenge_type=challenge_type, difficulty=difficulty, story=story,
        vulnerability=vulnerability, intended_solution=solution, hints=[],
        delivery="crypto", seed=seed,
        mechanics={"attack_class": attack_class, "rank": rank},
        flag=flag, spec_id=slug,
        lineage=Lineage(archetype_id=f"airesistant.{attack_class}", generation=generation,
                        parent_spec_id=None, mutation_ops=[], seed=seed),
        vuln_chain=[ChainStep(step=1, primitive=f"{attack_class}_stage",
                              params={}, guard=category)],
        artifacts=artifacts,
        official_solver=OfficialSolver(entry="solver.py", files=solver_files,
                                       expected_flag_sha256=expected,
                                       max_runtime_s=max_runtime_s),
        target_solve_rate=0.03)


def _slug(kind, flag_secret, seed, generation):
    tag = hashlib.sha256(f"{kind}:{flag_secret}:{seed}:{generation}".encode()).hexdigest()[:8]
    return f"air-{kind}-g{generation}-{tag}"


# ---------------------------------------------------------------------------
# oddproto — a vendor protocol whose published spec is wrong in two places
# ---------------------------------------------------------------------------
ESC = 0x7D
ESC_XOR = 0x5A            # the real constant; the spec sheet claims 0x20
SHARD_TAG = 0x2A


def _crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _bitrev16(value: int) -> int:
    out = 0
    for _ in range(16):
        out = (out << 1) | (value & 1)
        value >>= 1
    return out


def _escape(payload: bytes) -> bytes:
    out = bytearray()
    for byte in payload:
        if byte in (ESC, 0x7E):
            out.append(ESC)
            out.append(byte ^ ESC_XOR)
        else:
            out.append(byte)
    return bytes(out)


_ODDPROTO_SOLVER = '''\
"""Parse an SLP-2 capture correctly, which means not believing SLP-2.txt.

Two fields in the vendor sheet are wrong, and both are wrong in ways that a
standard framing parser swallows without complaining:

  * `length` is not the payload length. It is the payload length with its 16 bits
    reversed. A parser that trusts it walks off the end of the buffer on frame one
    (a 41-byte body reads as 37888), which is the tell: the only reading under
    which consecutive frames tile the capture exactly is the bit-reversed one.
  * the escape constant is not 0x20. The sheet cites HDLC and HDLC uses 0x20, but
    this device XORs with 0x5A. Nothing about the frame layout reveals that — the
    trailer does. The trailer really is a CRC-16/CCITT-FALSE over the *unescaped*
    payload, so the right constant is the one that makes every frame's CRC check,
    and 256 candidates is a short search.

Once the frames parse, the key shards are the type-0x2A payloads in capture order.
"""
ESC = 0x7D


def crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def bitrev16(value):
    out = 0
    for _ in range(16):
        out = (out << 1) | (value & 1)
        value >>= 1
    return out


def unescape(body, xor_const):
    out = bytearray()
    i = 0
    while i < len(body):
        if body[i] == ESC:
            out.append(body[i + 1] ^ xor_const)
            i += 2
        else:
            out.append(body[i])
            i += 1
    return bytes(out)


def frames(blob, xor_const):
    """Walk the capture; return None unless every frame tiles and its CRC checks."""
    out = []
    pos = 0
    while pos < len(blob):
        if pos + 5 > len(blob):
            return None
        tag = blob[pos]
        body_len = bitrev16((blob[pos + 1] << 8) | blob[pos + 2])
        start = pos + 3
        end = start + body_len
        if end + 2 > len(blob):
            return None
        payload = unescape(blob[start:end], xor_const)
        trailer = (blob[end] << 8) | blob[end + 1]
        if crc16(payload) != trailer:
            return None
        out.append((tag, payload))
        pos = end + 2
    return out


blob = bytes.fromhex("".join(open("capture.hex", encoding="utf-8").read().split()))
parsed = next(f for f in (frames(blob, k) for k in range(256)) if f)
shards = b"".join(payload for tag, payload in parsed if tag == 0x2A)

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), shards.hex()))
'''

_ODDPROTO_SHEET = """\
SLP-2 SERIAL LINK PROTOCOL — FRAME FORMAT (vendor sheet, rev C)
================================================================

Every frame on the link has the layout:

    +--------+------------------+--------------+-------------+
    | type   | length           | payload      | trailer     |
    | 1 byte | 2 bytes          | `length`     | 2 bytes     |
    +--------+------------------+--------------+-------------+

  type      Record type. 0x10 and 0x11 are periodic telemetry. 0x2A is a
            provisioning shard.

  length    Payload length in bytes, transmitted big-endian, most significant
            byte first.

  payload   Byte-stuffed. As in HDLC, the escape octet 0x7D indicates that the
            following octet has been XORed with 0x20 and must be restored; the
            octets 0x7D and 0x7E are the ones stuffed.

  trailer   CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) over the payload after
            de-stuffing, transmitted big-endian.

Frames are transmitted back to back with no inter-frame gap; the receiver relies
on `length` to find the next frame boundary.
"""


def gen_oddproto(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="oddproto", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"oddproto:{flag_secret}:{seed}:{generation}")
    shards, blob = [], bytearray()
    plan = [0x10, SHARD_TAG, 0x11, 0x10, SHARD_TAG, 0x11, SHARD_TAG, 0x10,
            SHARD_TAG, 0x11]
    for idx, tag in enumerate(plan):
        if tag == SHARD_TAG:
            # Real key material, salted with the two stuffed octets so a wrong
            # escape constant corrupts the shard instead of silently working.
            payload = bytearray(rng.randrange(256) for _ in range(8))
            for _ in range(2):
                payload[rng.randrange(len(payload))] = rng.choice((0x7D, 0x7E))
            payload = bytes(payload)
            shards.append(payload)
        else:
            payload = (f"T{tag:02X} seq={idx:03d} bus={rng.randrange(100):02d} "
                       f"mv={rng.randrange(2800, 3400)} degc={rng.randrange(-5, 60)}"
                       ).encode()
        body = _escape(payload)
        blob.append(tag)
        stored = _bitrev16(len(body))
        blob.append(stored >> 8)
        blob.append(stored & 0xFF)
        blob += body
        crc = _crc16_ccitt(payload)
        blob.append(crc >> 8)
        blob.append(crc & 0xFF)

    key = b"".join(shards).hex()
    hex_text = bytes(blob).hex()
    wrapped = "\n".join(hex_text[i:i + 64] for i in range(0, len(hex_text), 64))
    artifacts = {
        "capture.hex": wrapped + "\n",
        "SLP-2.txt": _ODDPROTO_SHEET,
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key, flag),
        "README.md": (
            "# Provisioning link capture\n\n"
            "`capture.hex` is a raw byte capture off a provisioning harness, taken "
            "between two frames so it starts and ends on a frame boundary. "
            "`SLP-2.txt` is the vendor's frame-format sheet for the link.\n\n"
            "The provisioning key was split across the capture's shard records. The "
            "operator's recovery blob is sealed under those shard payloads, "
            "concatenated in capture order and written as lowercase hex. "
            "`sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("oddproto", flag_secret, seed, generation),
        title="Provisioning Link Capture", category="reverse",
        challenge_type="misdocumented-framing",
        story=("A provisioning harness was captured on the wire, and the vendor's "
               "frame-format sheet for the link came with it. The provisioning key was "
               "split across the capture's shard records."),
        vulnerability=("the published framing spec misstates the length encoding and the "
                       "byte-stuffing constant; only the CRC trailer is honest"),
        solution=["notice the documented length walks past the end of the capture",
                  "find the encoding under which frames tile the buffer exactly",
                  "recover the true stuffing constant by requiring every CRC to check",
                  "concatenate the shard-record payloads in capture order and unseal"],
        artifacts=artifacts,
        solver_files={"solver.py": _ODDPROTO_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="oddproto",
        rank=11, max_runtime_s=60, flag_secret=flag_secret)



# ---------------------------------------------------------------------------
# vmkeygen — a keygen for a stack machine no tool has ever seen
# ---------------------------------------------------------------------------
KEY_BYTES = 24

_VM_SOURCE = '''\
"""SLC-8 bytecode interpreter (service build).

Loads the maintenance-key checker from program.hex and runs it against a
candidate key. Byte-addressed stack machine, four scratch cells, one shared
substitution table. Everything is mod 256.
"""


def load_program(path="program.hex"):
    with open(path, encoding="utf-8") as fh:
        return bytes.fromhex("".join(fh.read().split()))


def load_table(path="sbox.hex"):
    with open(path, encoding="utf-8") as fh:
        return bytes.fromhex("".join(fh.read().split()))


def run(prog, table, key):
    stack = []
    cell = [0, 0, 0, 0]
    pc = 0
    while pc < len(prog):
        op = prog[pc]
        pc += 1
        if op == 0x11:                       # key byte -> stack
            stack.append(key[prog[pc]])
            pc += 1
        elif op == 0x12:                     # immediate -> stack
            stack.append(prog[pc])
            pc += 1
        elif op == 0x13:
            b = stack.pop()
            stack.append(stack.pop() ^ b)
        elif op == 0x14:
            b = stack.pop()
            stack.append((stack.pop() + b) & 0xFF)
        elif op == 0x15:
            stack.append(table[stack.pop()])
        elif op == 0x16:                     # rotate left by an immediate
            n = prog[pc] & 7
            pc += 1
            v = stack.pop()
            stack.append(((v << n) | (v >> (8 - n))) & 0xFF)
        elif op == 0x17:
            stack.append(stack[-1])
        elif op == 0x18:                     # stack -> scratch cell
            cell[prog[pc] & 3] = stack.pop()
            pc += 1
        elif op == 0x19:                     # scratch cell -> stack
            stack.append(cell[prog[pc] & 3])
            pc += 1
        elif op == 0x1A:                     # compare against an immediate
            want = prog[pc]
            pc += 1
            if stack.pop() != want:
                return False
        elif op == 0x1B:
            return True
        else:
            raise ValueError("bad opcode %02x at %d" % (op, pc - 1))
    return True


if __name__ == "__main__":
    with open("key.hex", encoding="utf-8") as fh:
        candidate = bytes.fromhex(fh.read().strip())
    print("ACCEPT" if run(load_program(), load_table(), candidate) else "REJECT")
'''

_VMKEYGEN_SOLVER = '''\
"""Invert an SLC-8 key checker by hand.

There is no disassembler for SLC-8, so the opcode stream is read directly out of
program.hex against the semantics in vm.py. Stripped of the scratch-cell writes
that are stored and never loaded, the program is a chain of 24 identical blocks:

    PUSHK i, PUSHM 0, XOR, SBOX, ROL 3, PUSHI c_i, ADD, DUP, CHECK e_i,
    PUSHK i, ADD, STORE 0

so byte i must satisfy `((rol3(S[key[i] ^ state]) + c_i) & 0xFF) == e_i`, and the
running state becomes `(e_i + key[i]) & 0xFF` for the next block. Every step is a
bijection on a byte, so the block inverts exactly:

    key[i] = Sinv[ror3((e_i - c_i) & 0xFF)] ^ state

The chain is strictly sequential — `state` for block i needs key[i-1] — so there
is nothing to parallelise and nothing to brute force; you just walk it forward
from the seed immediate the program stores into cell 0 before the first block.

Rather than hand-transcribe the 24 (c_i, e_i) pairs, this lifts them straight out
of the byte stream by matching the block pattern, which is also the honest way to
show the pattern is really there.
"""
import vm

prog = vm.load_program()
table = vm.load_table()
inv = [0] * 256
for value, mapped in enumerate(table):
    inv[mapped] = value


def blocks(prog):
    """Yield (index, rot, const, expect) for each key-checking block."""
    pc = 0
    while pc < len(prog):
        if prog[pc] == 0x11 and prog[pc + 2:pc + 3] == b"\\x19":
            idx = prog[pc + 1]
            assert prog[pc + 4] == 0x13 and prog[pc + 5] == 0x15
            assert prog[pc + 6] == 0x16
            rot = prog[pc + 7] & 7
            assert prog[pc + 8] == 0x12
            const = prog[pc + 9]
            assert prog[pc + 10] == 0x14 and prog[pc + 11] == 0x17
            assert prog[pc + 12] == 0x1A
            yield idx, rot, const, prog[pc + 13]
            pc += 19                         # ...PUSHK i, ADD, STORE 0
        else:
            pc += 2                          # every other opcode here is op+imm


seed_cell = None
pos = 0
while prog[pos] != 0x11:                     # the PUSHI/STORE that primes cell 0
    if prog[pos] == 0x12 and prog[pos + 2] == 0x18 and (prog[pos + 3] & 3) == 0:
        seed_cell = prog[pos + 1]
    pos += 2
assert seed_cell is not None, "no seed immediate before the first block"

state = seed_cell
key = bytearray(24)
for idx, rot, const, expect in blocks(prog):
    t = (expect - const) & 0xFF
    t = ((t >> rot) | (t << (8 - rot))) & 0xFF
    key[idx] = inv[t] ^ state
    state = (expect + key[idx]) & 0xFF

assert vm.run(prog, table, bytes(key)), "recovered key does not satisfy the checker"

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), bytes(key).hex()))
'''


def gen_vmkeygen(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="vmkeygen", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"vmkeygen:{flag_secret}:{seed}:{generation}")
    table = list(range(256))
    rng.shuffle(table)
    key = bytes(rng.randrange(256) for _ in range(KEY_BYTES))
    rot = 3
    seed_cell = rng.randrange(256)

    prog = bytearray([0x12, seed_cell, 0x18, 0x00])
    state = seed_cell
    for i in range(KEY_BYTES):
        const = rng.randrange(256)
        t = table[key[i] ^ state]
        t = ((t << rot) | (t >> (8 - rot))) & 0xFF
        expect = (t + const) & 0xFF
        prog += bytes([0x11, i, 0x19, 0x00, 0x13, 0x15, 0x16, rot,
                       0x12, const, 0x14, 0x17, 0x1A, expect,
                       0x11, i, 0x14, 0x18, 0x00])
        state = (expect + key[i]) & 0xFF
        # Scratch traffic: written, never read. Cheap noise in the byte stream,
        # and a reader who does not check which cells are loaded will chase it.
        if rng.random() < 0.5:
            prog += bytes([0x12, rng.randrange(256), 0x18, rng.choice((1, 2, 3))])
    prog.append(0x1B)

    prog_hex = bytes(prog).hex()
    artifacts = {
        "program.hex": "\n".join(prog_hex[i:i + 64]
                                 for i in range(0, len(prog_hex), 64)) + "\n",
        "sbox.hex": bytes(table).hex() + "\n",
        "vm.py": _VM_SOURCE,
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key.hex(), flag),
        "README.md": (
            "# Maintenance key checker\n\n"
            "The controller validates its 24-byte maintenance key by running "
            "`program.hex` on the SLC-8 core. `vm.py` is the service build of that "
            "core and `sbox.hex` is the substitution table it loads. Put a candidate "
            "key in `key.hex` as lowercase hex and run `python3 vm.py` to see whether "
            "the controller takes it.\n\n"
            "The operator's recovery blob is sealed under the accepted key as "
            "lowercase hex. `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("vmkeygen", flag_secret, seed, generation),
        title="Maintenance Key Checker", category="reverse",
        challenge_type="custom-isa-keygen",
        story=("A controller checks its maintenance key with a bytecode program for an "
               "in-house stack core. The core's source ships with the service image; "
               "the key does not."),
        vulnerability=("every step of the per-byte check is a bijection on a byte, so the "
                       "checker inverts exactly once its bespoke ISA is read"),
        solution=["read the opcode semantics out of the interpreter source",
                  "recover the repeating block and drop the scratch writes nothing loads",
                  "invert each block: subtract the constant, rotate back, undo the table",
                  "walk the state chain forward from the primed cell and unseal"],
        artifacts=artifacts,
        solver_files={"solver.py": _VMKEYGEN_SOLVER, "vm.py": _VM_SOURCE,
                      "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="vmkeygen",
        rank=13, max_runtime_s=60, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# lsbseed — LSB stego on a schedule whose seed was thrown away
# ---------------------------------------------------------------------------
STEGO_W, STEGO_H = 96, 96
STEGO_SEED_BITS = 20
STEGO_MAGIC = b"SLB1"
STEGO_KEY_BYTES = 32

_EMBED_SOURCE = '''\
"""Provisioning-rig LSB writer.

Writes a payload into the least significant bits of a P2 frame at positions drawn
from the rig's own counter-mode generator. The generator is not the platform PRNG
— it is the same 64-bit recurrence the rig uses for its wear-levelling schedule,
seeded with the run counter so a frame can be re-read from the logbook alone.
"""

MASK = (1 << 64) - 1
MULT = 6364136223846793005
INCR = 1442695040888963407

RUN_SEED = None            # redacted before release; see the run logbook
MAGIC = b"SLB1"


def schedule(seed, count, npix):
    """The first `count` distinct pixel indices this run writes to, in order."""
    state = (seed * MULT + INCR) & MASK
    seen = set()
    out = []
    while len(out) < count:
        state = (state * MULT + INCR) & MASK
        pos = (state >> 29) % npix
        if pos in seen:
            continue
        seen.add(pos)
        out.append(pos)
    return out


def bits_of(payload):
    for byte in payload:
        for shift in (7, 6, 5, 4, 3, 2, 1, 0):
            yield (byte >> shift) & 1


def embed(pixels, payload, seed):
    blob = MAGIC + payload
    bits = list(bits_of(blob))
    for pos, bit in zip(schedule(seed, len(bits), len(pixels)), bits):
        pixels[pos] = (pixels[pos] & 0xFE) | bit
    return pixels


def read_pgm(path):
    tokens = open(path, encoding="utf-8").read().split()
    assert tokens[0] == "P2"
    w, h = int(tokens[1]), int(tokens[2])
    return w, h, [int(t) for t in tokens[4:4 + w * h]]


if __name__ == "__main__":
    raise SystemExit("RUN_SEED is redacted in this build")
'''

_LSBSEED_SOLVER = '''\
"""Recover a payload written to image LSBs on a lost run seed.

The rig's writer ships, so nothing about the schedule is unknown: 64-bit LCG,
`pos = (state >> 29) %% npix`, duplicates skipped, MSB-first bits, four magic
bytes in front of the payload. The one missing input is the run counter, and the
logbook says it is under 2**%d.

Searching that space naively costs a full magic's worth of PRNG steps per seed,
which is far more work than it needs to be: the payload starts with a KNOWN four
bytes, so a candidate seed can be rejected on its very first mismatching bit.
Half the seeds die after one LCG step, three quarters after two. The expected cost
is about two steps per seed rather than thirty-two, which turns a coffee break
into a few seconds.
"""
import embed

MASK, MULT, INCR = embed.MASK, embed.MULT, embed.INCR
MAGIC_BITS = list(embed.bits_of(embed.MAGIC))

w, h, pixels = embed.read_pgm("frame.pgm")
npix = w * h


def matches(seed):
    """True if this seed's schedule reproduces the magic bits. Bails on bit one."""
    state = (seed * MULT + INCR) & MASK
    seen = set()
    got = 0
    while got < len(MAGIC_BITS):
        state = (state * MULT + INCR) & MASK
        pos = (state >> 29) %% npix
        if pos in seen:
            continue
        seen.add(pos)
        if pixels[pos] & 1 != MAGIC_BITS[got]:
            return False
        got += 1
    return True


seed = next(s for s in range(1 << %d) if matches(s))

total_bits = (len(embed.MAGIC) + %d) * 8
bits = [pixels[p] & 1 for p in embed.schedule(seed, total_bits, npix)]
blob = bytes(int("".join(str(b) for b in bits[i:i + 8]), 2)
             for i in range(0, len(bits), 8))
assert blob[:len(embed.MAGIC)] == embed.MAGIC, "magic did not survive extraction"
key = blob[len(embed.MAGIC):]

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), key.hex()))
''' % (STEGO_SEED_BITS, STEGO_SEED_BITS, STEGO_KEY_BYTES)


def _stego_schedule(seed, count, npix):
    mask = (1 << 64) - 1
    state = (seed * 6364136223846793005 + 1442695040888963407) & mask
    seen, out = set(), []
    while len(out) < count:
        state = (state * 6364136223846793005 + 1442695040888963407) & mask
        pos = (state >> 29) % npix
        if pos in seen:
            continue
        seen.add(pos)
        out.append(pos)
    return out


def gen_lsbseed(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="lsbseed", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"lsbseed:{flag_secret}:{seed}:{generation}")
    npix = STEGO_W * STEGO_H
    # A plausible sensor frame: a slow diagonal ramp under per-pixel grain, so the
    # LSB plane looks like noise whether or not anything is written into it.
    pixels = []
    for y in range(STEGO_H):
        for x in range(STEGO_W):
            base = 40 + (x + y) * 160 // (STEGO_W + STEGO_H)
            pixels.append(max(0, min(255, base + rng.randrange(-18, 19))))

    run_seed = rng.randrange(1 << STEGO_SEED_BITS)
    key = bytes(rng.randrange(256) for _ in range(STEGO_KEY_BYTES))
    blob = STEGO_MAGIC + key
    bits = [(byte >> shift) & 1 for byte in blob for shift in (7, 6, 5, 4, 3, 2, 1, 0)]
    for pos, bit in zip(_stego_schedule(run_seed, len(bits), npix), bits):
        pixels[pos] = (pixels[pos] & 0xFE) | bit

    rows = []
    for y in range(STEGO_H):
        row = pixels[y * STEGO_W:(y + 1) * STEGO_W]
        rows.append(" ".join(str(v) for v in row))
    pgm = f"P2\n{STEGO_W} {STEGO_H}\n255\n" + "\n".join(rows) + "\n"

    artifacts = {
        "frame.pgm": pgm,
        "embed.py": _EMBED_SOURCE,
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key.hex(), flag),
        "README.md": (
            "# Provisioning frame\n\n"
            "`frame.pgm` is the calibration frame the provisioning rig wrote at the "
            "end of a run, and `embed.py` is the rig's writer as shipped — with the "
            "run seed redacted, because the release build strips it and the logbook "
            "page that recorded it is gone. All anyone remembers is that the run "
            f"counter is below 2**{STEGO_SEED_BITS}.\n\n"
            "The operator's recovery blob is sealed under the embedded payload — the "
            "bytes after the magic — as lowercase hex. `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("lsbseed", flag_secret, seed, generation),
        title="Provisioning Frame", category="forensics",
        challenge_type="seeded-lsb-stego",
        story=("A provisioning rig hid its run payload in the LSBs of a calibration "
               "frame, at positions drawn from the rig's own counter-mode generator. "
               "The writer survived the release build. The seed did not."),
        vulnerability=("the position schedule is fully specified and the seed space is small, "
                       "and a known payload prefix rejects a wrong seed on its first bit"),
        solution=["read the schedule and bit order out of the shipped writer",
                  "search the run-counter space against the known magic prefix",
                  "abort each candidate on its first mismatching bit, not after the magic",
                  "replay the schedule at the found seed and unseal with the payload"],
        artifacts=artifacts,
        solver_files={"solver.py": _LSBSEED_SOLVER, "embed.py": _EMBED_SOURCE,
                      "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="lsbseed",
        rank=10, max_runtime_s=180, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# honeytrap — a loud dead end parked in front of a quiet real one
# ---------------------------------------------------------------------------
NVRAM_SIZE = 0x0600
TABLE_BASE = 0x0400
RECORD_LEN = 32
RECORD_COUNT = 12
DEBUG_OFF, DEBUG_LEN = 0x0100, 0x40

_FIRMWARE_SOURCE = '''\
"""SLC-8 controller — NVRAM config service (service build, symbols kept).

Reads the controller's configuration records out of the NVRAM image. Records are
stored obfuscated with a per-record keystream so a raw dump does not read as
plaintext; `read_record` is the only supported way in.
"""
import hashlib

TABLE_BASE = 0x0400
RECORD_LEN = 32
RECORD_COUNT = 12

DEBUG_OFF = 0x0100
DEBUG_LEN = 0x40
DEBUG_KEY = bytes.fromhex("5a3c91e07b46d2af")


def nvram(path="nvram.hex"):
    with open(path, encoding="utf-8") as fh:
        return bytes.fromhex("".join(fh.read().split()))


def _keystream(idx, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(b"SLC-NVRAM" + bytes([idx & 0xFF, counter])).digest()
        counter += 1
    return bytes(out[:length])


def _codec(idx, blob):
    return bytes(a ^ b for a, b in zip(blob, _keystream(idx, len(blob))))


def read_record(image, idx):
    """Read one config record. Records are 0 .. RECORD_COUNT - 1."""
    if idx < 0 or idx > RECORD_COUNT:
        raise IndexError("record out of range")
    off = TABLE_BASE + idx * RECORD_LEN
    return _codec(idx, image[off:off + RECORD_LEN])


def factory_debug(image):
    """Legacy factory hook. Left in the service build; returns the debug blob."""
    blob = image[DEBUG_OFF:DEBUG_OFF + DEBUG_LEN]
    key = DEBUG_KEY * (DEBUG_LEN // len(DEBUG_KEY) + 1)
    return bytes(a ^ b for a, b in zip(blob, key))


if __name__ == "__main__":
    image = nvram()
    for i in range(RECORD_COUNT):
        print("%02d %s" % (i, read_record(image, i).rstrip(b"\\x00").decode("latin-1")))
    print("debug:", factory_debug(image).rstrip(b"\\x00").decode("latin-1"))
'''

_HONEYTRAP_SOLVER = '''\
"""Read the record the controller's bounds check forgets to exclude.

The obvious lead is `factory_debug`: a legacy hook, a hardcoded XOR key, a blob
sitting right there in the dump. It decodes cleanly on the first try, which is
what makes it expensive — a clean decode reads as progress. It is a dead end; the
blob says so once you read it.

The real defect is in the line that looks like the safe one:

    if idx < 0 or idx > RECORD_COUNT:

`RECORD_COUNT` is a count, not a maximum index, so the valid range is 0..11 and
the guard admits 12. Record 12 is one stride past the end of the config table, in
a region the service never enumerates, and `read_record` will happily decode it —
with keystream index 12, which is why the bytes are not readable any other way.
"""
import firmware

image = firmware.nvram()
shadow = firmware.read_record(image, firmware.RECORD_COUNT)

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), shadow.hex()))
'''


def gen_honeytrap(seed, generation, **kw):
    import hashlib as _h
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="honeytrap", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"honeytrap:{flag_secret}:{seed}:{generation}")

    def keystream(idx, length):
        out = bytearray()
        counter = 0
        while len(out) < length:
            out += _h.sha256(b"SLC-NVRAM" + bytes([idx & 0xFF, counter])).digest()
            counter += 1
        return bytes(out[:length])

    image = bytearray(rng.randrange(256) for _ in range(NVRAM_SIZE))

    records = [
        b"unit=SLC8-%04d" % rng.randrange(10000),
        b"bus=%02d rate=115200" % rng.randrange(64),
        b"lamp_trim=%d,%d,%d" % (rng.randrange(999), rng.randrange(999), rng.randrange(999)),
        b"cal_epoch=17%08d" % rng.randrange(10 ** 8),
        b"mode=service",
        b"watchdog=8000ms",
        b"nvram_rev=C",
        b"escrow=disabled",
        b"log_ring=2048",
        b"link=SLP-2",
        b"boot_slot=b",
        b"provision=complete",
    ]
    for idx, text in enumerate(records):
        plain = text.ljust(RECORD_LEN, b"\x00")[:RECORD_LEN]
        off = TABLE_BASE + idx * RECORD_LEN
        image[off:off + RECORD_LEN] = bytes(a ^ b for a, b in
                                            zip(plain, keystream(idx, RECORD_LEN)))

    key = bytes(rng.randrange(256) for _ in range(RECORD_LEN))
    off = TABLE_BASE + RECORD_COUNT * RECORD_LEN
    image[off:off + RECORD_LEN] = bytes(a ^ b for a, b in
                                        zip(key, keystream(RECORD_COUNT, RECORD_LEN)))

    bait = b"FACTORY DEBUG BLOB v3 - contents cleared at provisioning".ljust(
        DEBUG_LEN, b"\x00")[:DEBUG_LEN]
    debug_key = bytes.fromhex("5a3c91e07b46d2af")
    debug_key = debug_key * (DEBUG_LEN // len(debug_key) + 1)
    image[DEBUG_OFF:DEBUG_OFF + DEBUG_LEN] = bytes(a ^ b for a, b in zip(bait, debug_key))

    hex_text = bytes(image).hex()
    artifacts = {
        "nvram.hex": "\n".join(hex_text[i:i + 64]
                               for i in range(0, len(hex_text), 64)) + "\n",
        "firmware.py": _FIRMWARE_SOURCE,
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key.hex(), flag),
        "README.md": (
            "# Controller NVRAM\n\n"
            "`nvram.hex` is a dump of a controller's NVRAM and `firmware.py` is the "
            "config service from the same image. Running the service prints the "
            "configuration the controller believes it has.\n\n"
            "The operator's recovery blob is sealed under a 32-byte record that the "
            "service never prints, as lowercase hex. `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("honeytrap", flag_secret, seed, generation),
        title="Controller NVRAM", category="reverse",
        challenge_type="off-by-one-behind-a-decoy",
        story=("A controller's NVRAM dump ships with the config service that reads it. "
               "The service prints twelve configuration records and a legacy factory "
               "debug blob. Something in that image is sealed under neither."),
        vulnerability=("`idx > RECORD_COUNT` admits index RECORD_COUNT, exposing one record "
                       "past the config table that the service never enumerates"),
        solution=["decode the factory debug blob, confirm it is empty, and drop the lead",
                  "notice RECORD_COUNT is a count being compared as a maximum index",
                  "read record 12 through the service's own per-record codec and unseal"],
        artifacts=artifacts,
        solver_files={"solver.py": _HONEYTRAP_SOLVER, "firmware.py": _FIRMWARE_SOURCE,
                      "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="honeytrap",
        rank=8, max_runtime_s=60, flag_secret=flag_secret, difficulty="medium")



# ---------------------------------------------------------------------------
# skewlog — the evidence that looks worst is the evidence that is sound
# ---------------------------------------------------------------------------
SKEW_NODES = 40
SKEW_BAD = 18
SKEW_ENTRIES = 10
SKEW_PRIME = (1 << 521) - 1        # a Mersenne prime, published in the artifact

_SKEWLOG_SOLVER = '''\
"""Reconstruct an escrow secret from the node logs that are actually intact.

The collector's own note points at the wrong evidence. It flags every node whose
wall-clock is non-monotonic as suspect, and those flags are real — the clocks did
step. But a stepped clock is a clock fault, not a tampered record, and the note
never claims otherwise; it is just the first signal anyone reaches for.

The signal that decides it is the digest chain, which each log carries and which
the format note specifies in full:

    d_0 = sha256(node_id)
    d_i = sha256(d_{i-1} + event_i)

An entry edited after the fact is not accompanied by a recomputed successor, so
the chain stops agreeing at exactly that entry. Recomputing it end to end sorts
the forty logs cleanly, and the split is the reverse of the flag list: the nodes
with the ugly clocks are the ones whose records were never touched.

That matters because the threshold equals the number of intact nodes exactly.
There is no margin, no majority to lean on, and no subset to try — every intact
share is required and no damaged one may be included. Lagrange at zero over the
published prime then gives the escrow secret directly.
"""
import hashlib
import json

doc = json.load(open("logs.json", encoding="utf-8"))
prime, threshold = int(doc["prime"]), doc["threshold"]

good = []
for node in doc["nodes"]:
    digest = hashlib.sha256(node["node_id"].encode()).hexdigest()
    intact = True
    for entry in node["entries"]:
        digest = hashlib.sha256((digest + entry["event"]).encode()).hexdigest()
        if digest != entry["digest"]:
            intact = False
            break
    if intact:
        good.append((int(node["share_x"]), int(node["share_y"])))

assert len(good) == threshold, f"{len(good)} intact logs, threshold is {threshold}"

secret = 0
for i, (xi, yi) in enumerate(good):
    num = den = 1
    for j, (xj, _) in enumerate(good):
        if i != j:
            num = num * (-xj) %% prime
            den = den * (xi - xj) %% prime
    secret = (secret + yi * num * pow(den, -1, prime)) %% prime

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(),
                    secret.to_bytes(%d, "big").hex()))
''' % (32,)

_SKEW_EVENTS = [
    "link up on bond0", "quorum join accepted", "escrow share loaded",
    "heartbeat ok", "config epoch advanced", "peer census complete",
    "ntp step applied", "checkpoint written", "lease renewed",
    "heartbeat ok", "audit cursor advanced", "link flap cleared",
]


def gen_skewlog(seed, generation, **kw):
    import hashlib as _h
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="skewlog", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"skewlog:{flag_secret}:{seed}:{generation}")
    good_count = SKEW_NODES - SKEW_BAD

    secret_bytes = bytes(rng.randrange(256) for _ in range(32))
    secret = int.from_bytes(secret_bytes, "big") % SKEW_PRIME
    # Threshold == the number of intact nodes, so the intact set must be identified
    # exactly: one damaged share included, or one sound share dropped, and the
    # interpolation lands on a different number with nothing to say it is wrong.
    coeffs = [secret] + [rng.randrange(SKEW_PRIME) for _ in range(good_count - 1)]

    def share(x):
        value = 0
        for c in reversed(coeffs):
            value = (value * x + c) % SKEW_PRIME
        return value

    tampered = set(rng.sample(range(SKEW_NODES), SKEW_BAD))
    nodes, flagged = [], []
    for idx in range(SKEW_NODES):
        node_id = f"node-{idx:02d}"
        entries, digest = [], _h.sha256(node_id.encode()).hexdigest()
        clock = 1755_000_000 + rng.randrange(600)
        skewed = idx not in tampered          # the intact nodes are the skewed ones
        for step in range(SKEW_ENTRIES):
            event = f"{_SKEW_EVENTS[step]} seq={step}"
            digest = _h.sha256((digest + event).encode()).hexdigest()
            if skewed and step == SKEW_ENTRIES // 2:
                clock -= rng.randrange(40, 90)        # a real NTP step backwards
            else:
                clock += rng.randrange(1, 14)
            entries.append({"seq": step, "ts": clock, "event": event, "digest": digest})
        if skewed:
            flagged.append(node_id)
        else:
            # Edited after the fact, with no successor digest recomputed.
            hit = rng.randrange(1, SKEW_ENTRIES)
            entries[hit]["event"] += " [reconciled]"
        nodes.append({"node_id": node_id, "share_x": idx + 1,
                      "share_y": str(share(idx + 1)), "entries": entries})

    artifacts = {
        "logs.json": json.dumps({
            "prime": str(SKEW_PRIME),
            "threshold": good_count,
            "digest_chain": "d0 = sha256(node_id); di = sha256(d(i-1) + event_i)",
            "collector_note": (
                "Clock audit: the following nodes reported non-monotonic wall-clock "
                "across the incident window and are flagged suspect: "
                + ", ".join(flagged) + "."),
            "nodes": nodes,
        }, indent=1) + "\n",
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(secret.to_bytes(32, "big").hex(), flag),
        "README.md": (
            f"# Escrow quorum logs\n\n"
            f"Forty nodes each hold one share of the escrow secret and each keep an "
            f"append-only event log. `logs.json` is the collector's dump of all forty, "
            f"with the digest-chain rule the logs are written under and the collector's "
            f"own clock-audit note.\n\n"
            f"The secret is split so that **{good_count}** shares reconstruct it. Shares "
            f"and the prime are decimal strings.\n\n"
            f"The operator's recovery blob is sealed under the reconstructed secret, "
            f"written as 32 bytes of lowercase hex. `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("skewlog", flag_secret, seed, generation),
        title="Escrow Quorum Logs", category="forensics",
        challenge_type="misleading-triage-signal",
        story=("Forty nodes each hold one share of an escrow secret and each keep an "
               "append-only log. The collector dumped all forty along with its own "
               "audit note about which ones look wrong."),
        vulnerability=("the audit signal the collector offers is exactly inverted against the "
                       "digest chain, and the threshold leaves no room to be wrong"),
        solution=["recompute each log's digest chain from its node id",
                  "treat a broken chain, not a stepped clock, as the tamper signal",
                  "note the flagged set is the intact set and the threshold admits no slack",
                  "Lagrange-interpolate the intact shares at zero and unseal"],
        artifacts=artifacts,
        solver_files={"solver.py": _SKEWLOG_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="skewlog",
        rank=12, max_runtime_s=120, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# permstego — a payload with no bytes to inspect
# ---------------------------------------------------------------------------
PERM_ENTRIES = 96
PERM_MAGIC = b"EMT1"
PERM_KEY_BYTES = 32

_PERMSTEGO_SOLVER = '''\
"""Read a payload that was never written into any byte of the manifest.

Every byte in `manifest.json` is accounted for: the paths are paths, the sizes
match, the digests are the digests of the recorded sizes. There is no low bit to
harvest, no trailing slack, no field with a spare nibble. What is not accounted
for is the ORDER, and the packer's note says so plainly — the loader sorts by
path and does not care what order it is given, and the run payload was recorded
in emission order.

An ordering of n distinct items carries log2(n!) bits, and for 96 entries that is
about 484 — comfortably more than a marker plus a 32-byte payload. The encoding
that gets them out is the only natural one: number the entries by their position
in path order, read off how far out of place each one is, and that sequence is
the digits of an integer in factorial base.

Concretely, for each position i take the count of later entries whose path-order
index is smaller than this one's; multiply by (n-1-i)! and sum. The result is the
payload as a big integer, big-endian, marker first.
"""
import json
import math

doc = json.load(open("manifest.json", encoding="utf-8"))
entries = doc["entries"]
n = len(entries)

order = {path: i for i, path in enumerate(sorted(e["path"] for e in entries))}
seq = [order[e["path"]] for e in entries]

value = 0
for i in range(n):
    smaller = sum(1 for j in range(i + 1, n) if seq[j] < seq[i])
    value += smaller * math.factorial(n - 1 - i)

width = (value.bit_length() + 7) // 8
blob = value.to_bytes(width, "big")
marker = %r
assert blob[:len(marker)] == marker, "emission order does not decode to a payload"

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(),
                    blob[len(marker):].hex()))
''' % (PERM_MAGIC,)

_PERM_DIRS = ["boot", "etc", "lib", "opt/agent", "usr/share/fw", "var/spool"]
_PERM_STEMS = ["loader", "table", "policy", "keymap", "profile", "index", "blob",
               "record", "shim", "trace", "vector", "digest"]


def _perm_from_rank(rank, n):
    """The rank-th permutation of range(n) in factorial base, most significant first."""
    import math as _m
    pool = list(range(n))
    out = []
    for i in range(n):
        block = _m.factorial(n - 1 - i)
        which = rank // block
        rank -= which * block
        out.append(pool.pop(which))
    return out


def gen_permstego(seed, generation, **kw):
    import hashlib as _h
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="permstego", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"permstego:{flag_secret}:{seed}:{generation}")

    paths = set()
    while len(paths) < PERM_ENTRIES:
        paths.add(f"/{rng.choice(_PERM_DIRS)}/{rng.choice(_PERM_STEMS)}"
                  f"-{rng.randrange(1000):03d}.bin")
    ordered = sorted(paths)

    key = bytes(rng.randrange(256) for _ in range(PERM_KEY_BYTES))
    value = int.from_bytes(PERM_MAGIC + key, "big")
    perm = _perm_from_rank(value, PERM_ENTRIES)

    entries = []
    for idx in perm:
        path = ordered[idx]
        size = 512 + (int(_h.sha256(path.encode()).hexdigest()[:6], 16) % 60000)
        entries.append({
            "path": path, "size": size,
            "sha256": _h.sha256(f"{path}:{size}".encode()).hexdigest(),
        })

    artifacts = {
        "manifest.json": json.dumps({
            "packer": "emt-pack 2.4",
            "note": ("entries are listed in emission order; the loader sorts by path "
                     "and does not depend on the order it is given. The run payload "
                     "for this image was recorded in that emission order."),
            "digest_rule": "sha256(path + ':' + size)",
            "entries": entries,
        }, indent=1) + "\n",
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key.hex(), flag),
        "README.md": (
            "# Firmware image manifest\n\n"
            f"`manifest.json` is the manifest `emt-pack` wrote for a firmware image: "
            f"{PERM_ENTRIES} entries, each with its path, its size, and a digest over "
            "both. Every field checks out against the packer's stated digest rule.\n\n"
            "The run payload begins with a four-byte marker. The operator's recovery "
            "blob is sealed under the bytes after that marker, as lowercase hex. "
            "`sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("permstego", flag_secret, seed, generation),
        title="Firmware Image Manifest", category="forensics",
        challenge_type="ordering-as-payload",
        story=("A packer wrote a manifest for a firmware image. Every field in it is "
               "consistent with the packer's own digest rule, and the packer notes that "
               "the loader ignores the order the entries arrive in."),
        vulnerability=("the payload is carried by the ordering of the records, not by any byte "
                       "in them, so every byte-level check passes and finds nothing"),
        solution=["confirm every field is consistent, so no byte carries slack",
                  "note an ordering of 96 distinct entries carries ~484 bits",
                  "index the entries by path order and read the displacement digits",
                  "read those digits as factorial base, big-endian, marker first"],
        artifacts=artifacts,
        solver_files={"solver.py": _PERMSTEGO_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="permstego",
        rank=13, max_runtime_s=120, flag_secret=flag_secret)


AIRESISTANT_BUILDERS = [gen_oddproto, gen_vmkeygen, gen_lsbseed, gen_honeytrap,
                        gen_skewlog, gen_permstego]
