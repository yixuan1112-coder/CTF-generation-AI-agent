"""Rungs built to be UNFAMILIAR, and to punish the reflex to pattern-match.

An agent is strong on shapes it has seen and weak the moment a shape is made
strange on purpose — and when it is unsure it does not stop, it commits to a
confident wrong answer. These rungs are designed around exactly that. Each keygen
LOOKS like a textbook cipher, so the familiar inversion is the obvious move; each
keygen is subtly not that cipher, so the familiar inversion yields the wrong key.
And each ships a second sealed file that the wrong key opens cleanly into a
plausible decoy flag — so an agent that takes the obvious path is handed a
confident, checkable, wrong flag and never learns it was wrong.

  mirage    Reads as a per-byte affine cipher T[i] = A*K[i] + C[i]. It is not:
            each output byte is also coupled to the NEXT key byte, T[i] = A*K[i] +
            B*K[i+1] + C[i], so inverting it byte-by-byte gives a wrong key that
            opens the decoy. The real key falls out of a back-substitution from the
            last (uncoupled) byte.

  sandtrap  Reads as a per-byte multiply cipher T[i] = mix(K[i]) XOR C[i], where
            `mix` looks like ordinary integer arithmetic on a byte. It is a
            multiplication in GF(2^8), so the integer inverse produces the decoy
            key and only the field inverse produces the real one.

  statewalk A bytecode VM whose every instruction changes meaning with a MODE the
            program toggles, again and again, across a long run. Reading the ops
            once and applying them uniformly — ignoring the toggles — produces a
            clean decoy. Only tracking the mode faithfully through the whole
            program yields the real result. It targets the twin failures of not
            covering the state space and not holding a long format.

None writes the real flag into a player artifact; the only flag sitting in the
open is the decoy, and it is wrong.
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
        lineage=Lineage(archetype_id=f"estranged.{attack_class}", generation=generation,
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
    return f"es-{kind}-g{generation}-{tag}"


def _decoy_flag(kind, seed, generation, flag_secret):
    """A plausible but WRONG flag, sealed under the key the familiar misreading
    produces. The arena checks the real flag's hash, so submitting this fails."""
    return challenge_flag(kind=kind, seed=seed, generation=generation,
                          variant="decoy", secret=flag_secret)


# ---------------------------------------------------------------------------
# mirage — affine on the surface, coupled underneath
# ---------------------------------------------------------------------------
MIRAGE_LEN = 16

_MIRAGE_CHECK = '''\
"""License transform (reference build). Folds a 16-byte key to a 16-byte token."""


def transform(key, A, B, C):
    n = len(key)
    out = []
    for i in range(n):
        nxt = key[i + 1] if i + 1 < n else 0
        out.append((A * key[i] + B * nxt + C[i]) % 256)
    return out
'''

_MIRAGE_SOLVER = '''\
"""Recover the license key. The obvious reading is a trap.

`check.py` looks like a per-byte affine map, T[i] = A*key[i] + C[i], which inverts
one byte at a time to key[i] = A^{-1} (T[i] - C[i]) mod 256. That key opens
`recovery.enc` into a clean flag — and it is the wrong flag. The transform is not
per-byte: each output also carries B*key[i+1], the NEXT key byte. The last byte has
no successor, so it is the only one the naive inverse gets right; from it, back-
substitute:

    key[n-1] = A^{-1} (T[n-1] - C[n-1])
    key[i]   = A^{-1} (T[i] - B*key[i+1] - C[i])

That real key opens `flag.enc`.
"""
import json

doc = json.load(open("target.json", encoding="utf-8"))
T = doc["token"]
A, B, C = doc["A"], doc["B"], doc["C"]
Ai = pow(A, -1, 256)

n = len(T)
key = [0] * n
key[n - 1] = (Ai * ((T[n - 1] - C[n - 1]) % 256)) % 256
for i in range(n - 2, -1, -1):
    key[i] = (Ai * ((T[i] - B * key[i + 1] - C[i]) % 256)) % 256

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), bytes(key).hex()))
'''


def gen_mirage(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="mirage", seed=seed, generation=generation,
                          secret=flag_secret)
    decoy = _decoy_flag("mirage", seed, generation, flag_secret)
    rng = random.Random(f"mirage:{flag_secret}:{seed}:{generation}")

    key = bytes(rng.randrange(256) for _ in range(MIRAGE_LEN))
    A = rng.randrange(1, 256) | 1
    B = rng.randrange(1, 256) | 1
    C = [rng.randrange(256) for _ in range(MIRAGE_LEN)]
    T = [(A * key[i] + (B * key[i + 1] if i + 1 < MIRAGE_LEN else 0) + C[i]) % 256
         for i in range(MIRAGE_LEN)]

    Ai = pow(A, -1, 256)
    naive_key = bytes((Ai * ((T[i] - C[i]) % 256)) % 256 for i in range(MIRAGE_LEN))

    artifacts = {
        "target.json": json.dumps({"token": T, "A": A, "B": B, "C": C}, indent=1) + "\n",
        "check.py": _MIRAGE_CHECK,
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key.hex(), flag),
        "recovery.enc": _seal(naive_key.hex(), decoy),
        "README.md": (
            "# License token\n\n"
            "`check.py` is the licensing routine: it folds a 16-byte key into the "
            "16-byte token in `target.json` under the constants there. Recover the key "
            "that produces this token.\n\n"
            "The operator kept two sealed blobs, `flag.enc` and `recovery.enc`; the "
            "recovery blob opens under the license key as lowercase hex. `sealed.py` "
            "opens a blob.\n"),
    }
    return _spec(
        slug=_slug("mirage", flag_secret, seed, generation),
        title="License Token", category="reverse",
        challenge_type="coupled-affine-decoy",
        story=("A licensing routine and a token were recovered, along with two sealed "
               "blobs. The routine looks like a simple per-byte transform; recovering "
               "the key it accepts is the task."),
        vulnerability=("the transform couples each byte to the next, so a per-byte inverse "
                       "yields a wrong key that opens a decoy while the real key needs "
                       "back-substitution"),
        solution=["do not invert byte-by-byte: each output carries the next key byte",
                  "the last byte is uncoupled; recover it first",
                  "back-substitute to recover the earlier bytes",
                  "the real key opens flag.enc; the naive key opens the decoy"],
        artifacts=artifacts,
        solver_files={"solver.py": _MIRAGE_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="mirage",
        rank=15, max_runtime_s=60, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# sandtrap — GF(2^8) multiply wearing integer-arithmetic clothes
# ---------------------------------------------------------------------------
SAND_LEN = 16

_SAND_CHECK = '''\
"""Token mixer (reference build). Per byte: token = mix(key_byte) XOR C[i]."""


def mix(x, a):
    r = 0
    for _ in range(8):
        if a & 1:
            r ^= x
        a >>= 1
        hi = x & 0x80
        x = (x << 1) & 0xFF
        if hi:
            x ^= 0x1B
    return r


def transform(key, a, C):
    return [mix(key[i], a) ^ C[i] for i in range(len(key))]
'''

_SAND_SOLVER = '''\
"""Recover the key. `mix` is not integer multiplication.

`check.py` reads like a per-byte multiply cipher: token[i] = mix(key[i], a) XOR
C[i]. The obvious inverse assumes `mix` is ordinary multiplication mod 256 and
divides by `a` — that produces a key that opens `recovery.enc` into a clean flag,
and it is wrong. `mix` is multiplication in GF(2^8) (the AES field, reduction
0x11b): a carryless product reduced by 0x1B. So invert it in the field —
key[i] = ginv(a) (x) mix (token[i] XOR C[i]) — using the field inverse of `a`.
"""
import json


def gmul(x, a):
    r = 0
    for _ in range(8):
        if a & 1:
            r ^= x
        a >>= 1
        hi = x & 0x80
        x = (x << 1) & 0xFF
        if hi:
            x ^= 0x1B
    return r


def ginv(a):
    for b in range(1, 256):
        if gmul(a, b) == 1:
            return b
    raise ValueError("no inverse")


doc = json.load(open("target.json", encoding="utf-8"))
T, a, C = doc["token"], doc["a"], doc["C"]
ia = ginv(a)
key = bytes(gmul(T[i] ^ C[i], ia) for i in range(len(T)))

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), key.hex()))
'''


def _sand_gmul(x, a):
    r = 0
    for _ in range(8):
        if a & 1:
            r ^= x
        a >>= 1
        hi = x & 0x80
        x = (x << 1) & 0xFF
        if hi:
            x ^= 0x1B
    return r


def gen_sandtrap(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="sandtrap", seed=seed, generation=generation,
                          secret=flag_secret)
    decoy = _decoy_flag("sandtrap", seed, generation, flag_secret)
    rng = random.Random(f"sandtrap:{flag_secret}:{seed}:{generation}")

    key = bytes(rng.randrange(256) for _ in range(SAND_LEN))
    a = rng.choice([v for v in range(2, 256) if v % 2 == 1])   # invertible in GF(2^8)
    C = [rng.randrange(256) for _ in range(SAND_LEN)]
    T = [_sand_gmul(key[i], a) ^ C[i] for i in range(SAND_LEN)]

    # The naive (integer) inverse a familiar reading would apply.
    ai_int = pow(a, -1, 256) if a % 2 else 1
    naive_key = bytes((((T[i] ^ C[i]) * ai_int) % 256) for i in range(SAND_LEN))

    artifacts = {
        "target.json": json.dumps({"token": T, "a": a, "C": C}, indent=1) + "\n",
        "check.py": _SAND_CHECK,
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key.hex(), flag),
        "recovery.enc": _seal(naive_key.hex(), decoy),
        "README.md": (
            "# Token mixer\n\n"
            "`check.py` mixes a 16-byte key into the token in `target.json` under the "
            "constant `a`. Recover the key that produces this token.\n\n"
            "The operator kept two sealed blobs, `flag.enc` and `recovery.enc`; the "
            "recovery blob opens under the key as lowercase hex. `sealed.py` opens a "
            "blob.\n"),
    }
    return _spec(
        slug=_slug("sandtrap", flag_secret, seed, generation),
        title="Token Mixer", category="reverse",
        challenge_type="gf256-multiply-decoy",
        story=("A token mixer and its output were recovered with two sealed blobs. The "
               "mixer's per-byte combine looks like ordinary arithmetic on a byte; "
               "recovering the key it accepts is the task."),
        vulnerability=("the mixer multiplies in GF(2^8), not the integers, so an integer "
                       "inverse yields a wrong key that opens a decoy"),
        solution=["read `mix`: it is a carryless product reduced by 0x1B, i.e. GF(2^8)",
                  "do not invert with an integer division by a",
                  "invert `a` in the field and field-multiply each token byte",
                  "the field-recovered key opens flag.enc; the integer key opens the decoy"],
        artifacts=artifacts,
        solver_files={"solver.py": _SAND_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="sandtrap",
        rank=16, max_runtime_s=60, flag_secret=flag_secret)


ESTRANGED_BUILDERS = [gen_mirage, gen_sandtrap]


# ---------------------------------------------------------------------------
# statewalk — a modal VM where the mode changes what every op means
# ---------------------------------------------------------------------------
STATE_REGS = 16
STATE_OPS = 160

_STATE_VM = '''\
"""SLM-1 core (reference build).

16 byte-registers and one status bit. A program is a list of (op, arg) pairs;
the machine state after the whole program is the 16 registers.
"""


def run(program):
    acc = [0] * 16
    mode = 0
    for op, arg in program:
        if op == 0:                      # TOGGLE: flip the mode
            mode ^= 1
        elif op == 1:                    # COMBINE reg[arg] with its neighbour
            i, j = arg % 16, (arg + 1) % 16
            if mode == 0:
                acc[i] = (acc[i] + acc[j] + arg) & 0xFF
            else:
                acc[i] = (acc[i] ^ acc[j] ^ arg) & 0xFF
        elif op == 2:                    # MIX an immediate into reg[arg]
            i = arg % 16
            if mode == 0:
                acc[i] = (acc[i] * 3 + arg) & 0xFF
            else:
                acc[i] = (((acc[i] << 1) | (acc[i] >> 7)) ^ arg) & 0xFF
        elif op == 3:                    # SET reg[arg]
            acc[arg % 16] = (arg * 7 + 13) & 0xFF
    return bytes(acc)
'''

_STATEWALK_SOLVER = '''\
"""Run the SLM-1 program — with the mode, not without it.

`vm.py` is a modal machine: the MODE bit decides whether COMBINE adds or xors and
whether MIX multiplies-and-adds or rotates-and-xors, and TOGGLE flips it. The
program in `program.json` flips the mode many times. Apply the ops uniformly, as if
the mode never changed, and you get a clean final state — it opens `recovery.enc`
into a flag, and it is the wrong one. Track the mode faithfully through the whole
program and the final registers are the real key.
"""
import json

import vm

program = [tuple(p) for p in json.load(open("program.json", encoding="utf-8"))["program"]]
final = vm.run(program)

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), final.hex()))
'''


def _state_run(program, modal=True):
    acc = [0] * STATE_REGS
    mode = 0
    for op, arg in program:
        if op == 0:
            mode ^= 1 if modal else 0
        elif op == 1:
            i, j = arg % 16, (arg + 1) % 16
            acc[i] = (acc[i] + acc[j] + arg) & 0xFF if mode == 0 else (acc[i] ^ acc[j] ^ arg) & 0xFF
        elif op == 2:
            i = arg % 16
            acc[i] = (acc[i] * 3 + arg) & 0xFF if mode == 0 else (((acc[i] << 1) | (acc[i] >> 7)) ^ arg) & 0xFF
        elif op == 3:
            acc[arg % 16] = (arg * 7 + 13) & 0xFF
    return bytes(acc)


def gen_statewalk(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="statewalk", seed=seed, generation=generation,
                          secret=flag_secret)
    decoy = _decoy_flag("statewalk", seed, generation, flag_secret)
    rng = random.Random(f"statewalk:{flag_secret}:{seed}:{generation}")

    # A program with plenty of TOGGLEs so the mode genuinely matters throughout.
    program = []
    for _ in range(STATE_OPS):
        op = rng.choices([0, 1, 2, 3], weights=[3, 4, 4, 2])[0]
        program.append([op, rng.randrange(256)])

    real_key = _state_run(program, modal=True)
    lazy_key = _state_run(program, modal=False)          # the mode-ignoring misread

    artifacts = {
        "program.json": json.dumps({"program": program}) + "\n",
        "vm.py": _STATE_VM,
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(real_key.hex(), flag),
        "recovery.enc": _seal(lazy_key.hex(), decoy),
        "README.md": (
            "# Machine dump\n\n"
            "`vm.py` is a small machine's core and `program.json` is a program it ran. "
            "The machine's final register state is the key. Run the program and "
            "recover that key.\n\n"
            "The operator kept two sealed blobs, `flag.enc` and `recovery.enc`; the "
            "recovery blob opens under the final register state as lowercase hex. "
            "`sealed.py` opens a blob.\n"),
    }
    return _spec(
        slug=_slug("statewalk", flag_secret, seed, generation),
        title="Machine Dump", category="reverse",
        challenge_type="modal-vm-decoy",
        story=("A small machine's core and a program it ran were recovered, with two "
               "sealed blobs. The machine's final state is the key; running the "
               "program to get it is the task."),
        vulnerability=("every op's meaning depends on a mode the program toggles, so applying "
                       "the ops uniformly yields a wrong final state that opens a decoy"),
        solution=["read vm.py: the MODE bit changes what COMBINE and MIX do",
                  "the program TOGGLEs the mode repeatedly — track it throughout",
                  "running with the mode fixed produces the decoy key",
                  "the mode-faithful final registers open flag.enc"],
        artifacts=artifacts,
        solver_files={"solver.py": _STATEWALK_SOLVER, "vm.py": _STATE_VM,
                      "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="statewalk",
        rank=14, max_runtime_s=60, flag_secret=flag_secret)




# ---------------------------------------------------------------------------
# endiantrap — a middle-endian packing that reads as ordinary little-endian
# ---------------------------------------------------------------------------
_ENDIAN_SPEC = '''\
SLK-3 KEY BLOB — byte order (vendor sheet)
==========================================

The key is four 32-bit words, W0..W3, stored back to back. Each word is NOT stored
as a plain 32-bit little- or big-endian integer. It is stored HALF-SWAPPED: the
word's two 16-bit halves are written high-half FIRST, then low-half, and within
each 16-bit half the two bytes are written low byte first.

So a word whose big-endian bytes are (b0, b1, b2, b3) — b0 most significant —
is written to the blob as (b1, b0, b3, b2).

Read the blob back into the four words to recover the key; the word bytes in
big-endian order, concatenated W0..W3, are the 16-byte key.
'''

_ENDIAN_SOLVER = '''\
"""Unpack a half-swapped (middle-endian) key blob. Plain endianness is the trap.

`spec.txt` says each 32-bit word is stored half-swapped: big-endian word bytes
(b0,b1,b2,b3) are written (b1,b0,b3,b2). Reading each 4-byte group as an ordinary
little-endian integer — the reflex — gives a key that opens `recovery.enc` into a
clean flag, and it is wrong. Undo the exact swap instead: for each group
(c0,c1,c2,c3) the true word bytes are (c1,c0,c3,c2).
"""
blob = bytes.fromhex(open("blob.hex", encoding="utf-8").read().strip())
key = bytearray()
for i in range(0, len(blob), 4):
    c0, c1, c2, c3 = blob[i], blob[i + 1], blob[i + 2], blob[i + 3]
    key += bytes([c1, c0, c3, c2])

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), bytes(key).hex()))
'''


def gen_endiantrap(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="endiantrap", seed=seed, generation=generation,
                          secret=flag_secret)
    decoy = _decoy_flag("endiantrap", seed, generation, flag_secret)
    rng = random.Random(f"endiantrap:{flag_secret}:{seed}:{generation}")

    key = bytes(rng.randrange(256) for _ in range(16))
    blob = bytearray()
    for i in range(0, 16, 4):
        b0, b1, b2, b3 = key[i], key[i + 1], key[i + 2], key[i + 3]
        blob += bytes([b1, b0, b3, b2])                 # half-swapped store
    # The reflexive misread: each group as a plain little-endian uint32.
    naive = bytearray()
    for i in range(0, 16, 4):
        naive += int.from_bytes(blob[i:i + 4], "little").to_bytes(4, "big")

    artifacts = {
        "blob.hex": bytes(blob).hex() + "\n",
        "spec.txt": _ENDIAN_SPEC,
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key.hex(), flag),
        "recovery.enc": _seal(bytes(naive).hex(), decoy),
        "README.md": (
            "# Key blob\n\n"
            "`blob.hex` is a 16-byte key blob and `spec.txt` is the vendor's byte-order "
            "sheet for it. Recover the key.\n\n"
            "The operator kept two sealed blobs, `flag.enc` and `recovery.enc`; the "
            "recovery blob opens under the key as lowercase hex. `sealed.py` opens a "
            "blob.\n"),
    }
    return _spec(
        slug=_slug("endiantrap", flag_secret, seed, generation),
        title="Key Blob", category="reverse",
        challenge_type="middle-endian-decoy",
        story=("A 16-byte key blob was recovered with the vendor's byte-order sheet and "
               "two sealed blobs. Reading the blob back into the key is the task."),
        vulnerability=("the words are stored half-swapped (middle-endian); a plain "
                       "little-endian read yields a wrong key that opens a decoy"),
        solution=["read spec.txt exactly: words are stored half-swapped, not plain LE",
                  "a reflexive little-endian read produces the decoy key",
                  "undo the swap: (c0,c1,c2,c3) -> word bytes (c1,c0,c3,c2)",
                  "concatenate the words big-endian and open flag.enc"],
        artifacts=artifacts,
        solver_files={"solver.py": _ENDIAN_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="endiantrap",
        rank=13, max_runtime_s=60, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# graytrap — reflected Gray code that reads as plain binary
# ---------------------------------------------------------------------------
_GRAY_SPEC = '''\
SLK-4 SENSOR WORD — encoding note
=================================

The 128-bit sensor word is transmitted as a REFLECTED binary code (each transmitted
bit is the XOR of two adjacent bits of the true value), the way an absolute encoder
reports position so that only one bit changes between adjacent readings.

To recover the true 128-bit value from the transmitted code g, take the running
prefix-XOR: bit i of the value is the XOR of bits i, i-1, ..., 0 of the value, i.e.
v = g XOR (g >> 1) XOR (g >> 2) XOR ... . The 16 big-endian bytes of v are the key.
'''

_GRAY_SOLVER = '''\
"""Decode a reflected-binary (Gray) sensor word. Reading it as plain binary is the trap.

`spec.txt` says the 128-bit word is a reflected binary code, not the value itself.
Taking the transmitted bytes as the key directly — the reflex — opens
`recovery.enc` into a clean flag, and it is wrong. Convert Gray to binary: fold the
value with successive right-shifted XORs until the shift covers all 128 bits.
"""
g = int.from_bytes(bytes.fromhex(open("word.hex", encoding="utf-8").read().strip()), "big")
v = g
shift = 1
while shift < 128:
    v ^= v >> shift
    shift <<= 1
v &= (1 << 128) - 1
key = v.to_bytes(16, "big")

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), key.hex()))
'''


def gen_graytrap(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="graytrap", seed=seed, generation=generation,
                          secret=flag_secret)
    decoy = _decoy_flag("graytrap", seed, generation, flag_secret)
    rng = random.Random(f"graytrap:{flag_secret}:{seed}:{generation}")

    key = bytes(rng.randrange(256) for _ in range(16))
    v = int.from_bytes(key, "big")
    g = v ^ (v >> 1)                                    # binary -> reflected Gray
    word = g.to_bytes(16, "big")
    naive = word                                        # the reflex: read code as value

    artifacts = {
        "word.hex": word.hex() + "\n",
        "spec.txt": _GRAY_SPEC,
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key.hex(), flag),
        "recovery.enc": _seal(naive.hex(), decoy),
        "README.md": (
            "# Sensor word\n\n"
            "`word.hex` is a 128-bit sensor word and `spec.txt` is its encoding note. "
            "Recover the true value; its 16 big-endian bytes are the key.\n\n"
            "The operator kept two sealed blobs, `flag.enc` and `recovery.enc`; the "
            "recovery blob opens under the key as lowercase hex. `sealed.py` opens a "
            "blob.\n"),
    }
    return _spec(
        slug=_slug("graytrap", flag_secret, seed, generation),
        title="Sensor Word", category="reverse",
        challenge_type="gray-code-decoy",
        story=("A 128-bit sensor word was captured with its encoding note and two sealed "
               "blobs. Recovering the true value it encodes is the task."),
        vulnerability=("the word is a reflected binary (Gray) code, so reading it as plain "
                       "binary yields a wrong value that opens a decoy"),
        solution=["read spec.txt: the word is a reflected binary code, not the value",
                  "reading the transmitted bytes as the value opens the decoy",
                  "convert Gray to binary with successive right-shifted XORs",
                  "the 16 big-endian bytes of the value open flag.enc"],
        artifacts=artifacts,
        solver_files={"solver.py": _GRAY_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="graytrap",
        rank=12, max_runtime_s=60, flag_secret=flag_secret)


ESTRANGED_BUILDERS = [gen_mirage, gen_sandtrap, gen_statewalk,
                      gen_endiantrap, gen_graytrap]
