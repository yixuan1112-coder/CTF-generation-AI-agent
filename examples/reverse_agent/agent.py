#!/usr/bin/env python3
"""Reference agent for the `reverse` track — recovers the flag from crackme.c.

The crackme XORs the flag with a keystream taken from a 32-bit xorshift, seeded
by whatever `mix_state(password)` produces. The password is never shipped, so
guessing it is hopeless — but you do not need it. You need the *state*, and the
flag's own "flag{" prefix leaks enough to solve for it outright.

The trick is that xorshift32 is **linear over GF(2)**: `s ^= s << 13`,
`s ^= s >> 17` and `s ^= s << 5` are all XOR-of-shifts, so every output bit is a
fixed XOR of input bits. That makes each keystream byte 8 linear equations in the
32 unknown bits of the state. Five known plaintext bytes give 40 equations for 32
unknowns — over-determined, so Gaussian elimination pins the state exactly. No
search, no password, microseconds.

It also means the ladder cannot escalate away from this agent: ROUNDS only
changes how the password reaches the state, and we never touch the password.

Upload as-is — it needs nothing but the standard library.
"""
from __future__ import annotations

import re

MASK = 0xFFFFFFFF
KNOWN_PREFIX = b"flag{"


def _step(s: int) -> int:
    """One xorshift32 round, exactly as the crackme does it."""
    s ^= (s << 13) & MASK
    s ^= s >> 17
    s ^= (s << 5) & MASK
    return s & MASK


def _parse(src: str) -> tuple[list[int], int] | None:
    """Pull the ciphertext and round count straight out of the source."""
    enc = re.search(r"ENC\[\]\s*=\s*\{([^}]*)\}", src)
    if not enc:
        return None
    data = [int(x) for x in re.findall(r"\d+", enc.group(1))]
    rounds = re.search(r"ROUNDS\s*=\s*(\d+)", src)
    if not data or not rounds:
        return None
    return data, int(rounds.group(1))


def _observed_bits(state: int, count: int) -> int:
    """Low byte of each of the first `count` keystream words, packed into an int."""
    bits, out = 0, state
    for i in range(count):
        bits |= (out & 0xFF) << (8 * i)
        out = _step(out)
    return bits


def _solve_state(enc: list[int]) -> int | None:
    """Recover the keystream state from known plaintext, over GF(2).

    Column j holds what basis bit j of the state contributes to the observed
    bits; solving `sum_j x_j * column_j == target` gives the state.
    """
    n = min(len(KNOWN_PREFIX), len(enc))
    if n < 4:
        return None

    target = 0
    for i in range(n):
        target |= (enc[i] ^ KNOWN_PREFIX[i]) << (8 * i)

    # Linearity means the map has no constant term: verify rather than assume.
    if _observed_bits(0, n) != 0:
        return None

    columns = [_observed_bits(1 << j, n) for j in range(32)]

    # Gaussian elimination. Each row tracks which state bits produced it.
    rows = [(columns[j], 1 << j) for j in range(32)]
    pivots: dict[int, tuple[int, int]] = {}
    for value, provenance in rows:
        while value:
            top = value.bit_length() - 1
            if top not in pivots:
                pivots[top] = (value, provenance)
                break
            pv, pp = pivots[top]
            value ^= pv
            provenance ^= pp
        # value == 0 means this column was dependent; harmless, just drop it.

    state, residual = 0, target
    while residual:
        top = residual.bit_length() - 1
        if top not in pivots:
            return None                    # target outside the column space
        pv, pp = pivots[top]
        residual ^= pv
        state ^= pp

    return state if _observed_bits(state, n) == target else None


def _decrypt(state: int, enc: list[int]) -> bytes:
    out = bytearray()
    for byte in enc:
        out.append(byte ^ (state & 0xFF))
        state = _step(state)
    return bytes(out)


def solve(files: dict, meta: dict | None = None) -> str | None:
    src = files.get("crackme.c")
    if not src:
        return None
    parsed = _parse(src)
    if not parsed:
        return None
    enc, rounds = parsed

    print(f"crackme: {len(enc)} encrypted bytes, {rounds} key-schedule rounds")
    state = _solve_state(enc)
    if state is None:
        print("could not pin the state from the known prefix")
        return None
    print(f"solved keystream state = 0x{state:08x} (linear algebra, no search)")

    plain = _decrypt(state, enc)
    try:
        flag = plain.decode("ascii")
    except UnicodeDecodeError:
        return None
    return flag if flag.startswith("flag{") and flag.endswith("}") else None
