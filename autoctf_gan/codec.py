"""Reversible transform chain — the runnable substrate for challenges.

A challenge artifact is produced by applying an ordered chain of reversible
primitives to the flag. The official solver inverts the same chain. This lets the
whole GAN pipeline run and self-verify offline (no Docker/GCC needed for the
reference build) while preserving the real invariant: difficulty is the *length
and structure* of the chain, never raw keyspace (principle P3).

Each primitive is (encode, decode). Adding a layer = "deepen_chain" mutation.
The earlier `cirnovsky` puzzle in this session was exactly `positional_shift`.
"""
from __future__ import annotations

import base64
import binascii
from typing import Callable

Transform = tuple[Callable[[str, dict], str], Callable[[str, dict], str]]


def _positional_shift_enc(s: str, p: dict) -> str:
    off = int(p.get("offset", 0))
    out = []
    for i, ch in enumerate(s):
        if ch.isalpha():
            base = 97 if ch.islower() else 65
            out.append(chr((ord(ch) - base + (i + off) % 26) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def _positional_shift_dec(s: str, p: dict) -> str:
    off = int(p.get("offset", 0))
    out = []
    for i, ch in enumerate(s):
        if ch.isalpha():
            base = 97 if ch.islower() else 65
            out.append(chr((ord(ch) - base - (i + off) % 26) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def _xor_enc(s: str, p: dict) -> str:
    key = str(p.get("key", "k")).encode()
    raw = s.encode()
    x = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return binascii.hexlify(x).decode()


def _xor_dec(s: str, p: dict) -> str:
    key = str(p.get("key", "k")).encode()
    x = binascii.unhexlify(s.encode())
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(x)).decode()


def _b64_enc(s: str, p: dict) -> str:
    return base64.b64encode(s.encode()).decode()


def _b64_dec(s: str, p: dict) -> str:
    return base64.b64decode(s.encode()).decode()


def _reverse_enc(s: str, p: dict) -> str:
    return s[::-1]


def _rot13_enc(s: str, p: dict) -> str:
    import codecs
    return codecs.encode(s, "rot_13")


PRIMITIVES: dict[str, Transform] = {
    "positional_shift": (_positional_shift_enc, _positional_shift_dec),
    "xor":              (_xor_enc, _xor_dec),
    "b64":              (_b64_enc, _b64_dec),
    "reverse":          (_reverse_enc, _reverse_enc),   # self-inverse
    "rot13":            (_rot13_enc, _rot13_enc),        # self-inverse
}


def encode_chain(flag: str, chain: list[dict]) -> str:
    """Apply steps in order to produce the player-facing artifact."""
    data = flag
    for step in chain:
        enc, _ = PRIMITIVES[step["primitive"]]
        data = enc(data, step.get("params", {}))
    return data


def decode_chain(artifact: str, chain: list[dict]) -> str:
    """Invert the chain (reverse order) to recover the flag."""
    data = artifact
    for step in reversed(chain):
        _, dec = PRIMITIVES[step["primitive"]]
        data = dec(data, step.get("params", {}))
    return data
