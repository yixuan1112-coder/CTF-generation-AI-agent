"""Red-team-flavoured static practice challenges — the harder end of the ladder.

Same contract as `variety.py`/`newpractice.py`: a `delivery="crypto"` spec whose
stdlib `solver.py` recovers the flag under `verify_spec`, and the literal flag
never appears in a player artifact. This module holds challenges pitched at a
solver who arrives with a toolkit: the intended path is a real cryptanalytic
technique, not recognition.
"""
from __future__ import annotations

import hashlib
import struct

from .identity import challenge_flag
from .variety import _rng, _spec


# ===========================================================================
# crypto — meet-in-the-middle on a double-encrypted block cipher
# ===========================================================================
# A toy 32-bit Feistel block cipher `E_k` with a 16-bit key ships in the clear,
# so the algorithm is fully known. The flag is encrypted twice, C = E_k2(E_k1(m)),
# which looks like 32 bits of key strength. It is not: with one known
# plaintext/ciphertext pair, a meet-in-the-middle recovers (k1, k2) in ~2^17 work
# instead of 2^32 — build a table of E_k1(known_pt) over all k1, then match it
# against D_k2(known_ct) over all k2. Recover the keys, decrypt the flag blocks.
_MITM_CIPHER = '''\
"""cipher.py — a toy 32-bit Feistel block cipher with a 16-bit key.

Blocks and keys are integers. This is the reference implementation the challenge
was built with, shipped so the algorithm is fully known; the security was meant
to come from double-encrypting with two independent keys."""
MASK16 = 0xFFFF
ROUNDS = 6


def _f(half, rk):
    # a deliberately simple, non-linear round function on 16 bits
    x = (half + rk) & MASK16
    x = ((x << 7) | (x >> 9)) & MASK16          # rotate
    x ^= (x >> 5)
    x = (x * 0x2545 + 0x9E37) & MASK16           # odd multiply + const
    return x & MASK16


def _round_keys(key):
    rks, k = [], key & MASK16
    for r in range(ROUNDS):
        k = ((k << 3) | (k >> 13)) & MASK16
        k ^= (0xACE1 + r * 0x1111) & MASK16
        rks.append(k)
    return rks


def encrypt(block, key):
    l, r = (block >> 16) & MASK16, block & MASK16
    for rk in _round_keys(key):
        l, r = r, (l ^ _f(r, rk)) & MASK16
    return ((l << 16) | r) & 0xFFFFFFFF


def decrypt(block, key):
    l, r = (block >> 16) & MASK16, block & MASK16
    for rk in reversed(_round_keys(key)):
        r, l = l, (r ^ _f(l, rk)) & MASK16
    return ((l << 16) | r) & 0xFFFFFFFF
'''

_MITM_SOLVER = '''\
"""Meet-in-the-middle on the double encryption.

C = encrypt(encrypt(m, k1), k2). With the known (pt, ct) pair, tabulate
encrypt(pt, k1) for every 16-bit k1, then for every 16-bit k2 check whether
decrypt(ct, k2) is in the table — a hit gives (k1, k2). Then decrypt every flag
block: m = decrypt(decrypt(C_i, k2), k1)."""
import struct
from cipher import encrypt, decrypt

pt, ct = None, None
blocks = []
with open("data.txt", encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        tag, _, val = line.partition("=")
        if tag == "known_pt":
            pt = int(val, 16)
        elif tag == "known_ct":
            ct = int(val, 16)
        elif tag == "block":
            blocks.append(int(val, 16))

# forward table: encrypt(pt, k1) -> k1
mid = {}
for k1 in range(0x10000):
    mid[encrypt(pt, k1)] = k1

k1 = k2 = None
for cand in range(0x10000):
    inner = decrypt(ct, cand)
    if inner in mid:
        k1, k2, = mid[inner], cand
        break
assert k1 is not None, "meet-in-the-middle found no key pair"

out = bytearray()
for c in blocks:
    m = decrypt(decrypt(c, k2), k1)
    out += struct.pack(">I", m)
flag = out.rstrip(b"\\x00").decode()
assert flag.startswith("flag{"), "decryption did not land on a flag"
print(flag)
'''


def _mitm_funcs():
    """The cipher, in-process, to build the challenge (mirrors _MITM_CIPHER)."""
    MASK16 = 0xFFFF
    ROUNDS = 6

    def f(half, rk):
        x = (half + rk) & MASK16
        x = ((x << 7) | (x >> 9)) & MASK16
        x ^= (x >> 5)
        x = (x * 0x2545 + 0x9E37) & MASK16
        return x & MASK16

    def round_keys(key):
        rks, k = [], key & MASK16
        for r in range(ROUNDS):
            k = ((k << 3) | (k >> 13)) & MASK16
            k ^= (0xACE1 + r * 0x1111) & MASK16
            rks.append(k)
        return rks

    def encrypt(block, key):
        l, r = (block >> 16) & MASK16, block & MASK16
        for rk in round_keys(key):
            l, r = r, (l ^ f(r, rk)) & MASK16
        return ((l << 16) | r) & 0xFFFFFFFF

    return encrypt


def gen_mitm_cipher(seed, generation, **kw):
    secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="mitmcipher", seed=seed, generation=generation, secret=secret)
    rng = _rng("mitmcipher", seed, generation, secret)
    encrypt = _mitm_funcs()
    k1 = rng.randrange(0x10000)
    k2 = rng.randrange(0x10000)

    def enc2(block):
        return encrypt(encrypt(block, k1), k2)

    # a fixed known plaintext block and its double ciphertext
    known_pt = 0x54455354                          # "TEST"
    known_ct = enc2(known_pt)
    # encrypt the flag block by block (zero-padded to a multiple of 4 bytes)
    raw = flag.encode()
    raw += b"\x00" * ((-len(raw)) % 4)
    blocks = [struct.unpack(">I", raw[i:i + 4])[0] for i in range(0, len(raw), 4)]
    enc_blocks = [enc2(b) for b in blocks]
    lines = [f"known_pt={known_pt:08x}", f"known_ct={known_ct:08x}"]
    lines += [f"block={b:08x}" for b in enc_blocks]
    artifacts = {
        "cipher.py": _MITM_CIPHER,
        "data.txt": "\n".join(lines) + "\n",
        "README.md": ("# Double-encrypted flag\n\n"
                      "`cipher.py` is a 32-bit block cipher with a 16-bit key. The flag was "
                      "encrypted **twice** under two independent keys — "
                      "`C = encrypt(encrypt(m, k1), k2)` — for a claimed 32 bits of strength. "
                      "`data.txt` gives one known plaintext/ciphertext pair and the flag's "
                      "ciphertext blocks. Recover the keys and decrypt the flag.\n"),
    }
    return _spec(
        slug=f"rt-mitm-g{generation}-" +
             hashlib.sha256(f"mitmcipher:{secret}:{seed}:{generation}".encode()).hexdigest()[:8],
        title="Double-Encrypted Flag", category="crypto", challenge_type="meet-in-the-middle",
        story="A flag double-encrypted under two 16-bit keys — 32 bits of strength, supposedly.",
        vulnerability="double encryption is not 2x key strength — meet-in-the-middle halves it",
        solution=["recognise C = E_k2(E_k1(m)) and one known plaintext/ciphertext pair",
                  "tabulate E_k1(pt) over all k1, match against D_k2(ct) over all k2",
                  "recover (k1, k2) and decrypt the flag blocks"],
        artifacts=artifacts, solver=_MITM_SOLVER, flag=flag, seed=seed,
        generation=generation, attack_class="meet-in-the-middle", rank=8, difficulty="hard")


REDTEAM_BUILDERS = [gen_mitm_cipher]
