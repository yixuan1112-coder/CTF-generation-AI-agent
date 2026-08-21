"""Rungs aimed at a solver that is tireless but not insightful, and blind without
source.

Two weaknesses the user named, taken literally. A grinding agent throws effort at
a problem — bigger search, more tool calls, every attack in its kit — but a search
that is exponential stays exponential, and a kit that matches nothing stays empty.
And an agent that reverse-engineers by reading code is stranded when there is no
code to read, only behaviour.

An honest caveat lives in this module's design: every rung still ships a
deterministic official solver, because the platform verifies solvability by
running it. So none of these is literally unsolvable by a machine — a solver that
makes the same leap a person makes would clear them. What they punish is the leap
NOT being made: grinding where grinding cannot finish, and pattern-matching where
there is no pattern on file.

  wythoff    A two-pile game with huge starting positions. Deciding a position by
             actually searching the game — the tireless move — is hopeless: the
             tree is astronomical. The positions were chosen so that only the
             closed-form theory of the game classifies them, and the classification
             bits are the payload. A person who recognises or derives the structure
             answers each in one line; a search does not finish one.

  blackbox   A function given ONLY as input/output pairs — no source, no name, no
             standard cipher it matches. A code-reading or toolkit-matching agent
             has nothing to bite on. A person notices what the pairs conserve,
             infers the shape, and inverts it.

  gridpath   A grid of numbers that is a picture. Rendered, a lit trail snakes
             across it and its cells spell the payload; read as a flat number
             stream, it is noise. The move a person makes without thinking — look
             at it — is the move a stream processor never makes.

None writes the flag into a player artifact.
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
        lineage=Lineage(archetype_id=f"humanhard.{attack_class}", generation=generation,
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
    return f"hh-{kind}-g{generation}-{tag}"


# ---------------------------------------------------------------------------
# wythoff — classify game positions the search cannot reach
# ---------------------------------------------------------------------------
WYTHOFF_KEYBYTES = 18
WYTHOFF_MAG = 10 ** 15

_WYTHOFF_SOLVER = '''\
"""Classify each position, then read the bits off the classifications.

The game is Wythoff's: two piles, a move removes any positive amount from one pile
or the SAME positive amount from both, and the player who cannot move loses. Whether
a position is a loss for the player to move is not something you can find by
searching from coordinates this large — the tree is astronomical. It is something
you compute.

The losing positions (a <= b) are exactly

    a == floor(k * phi),   b == a + k,   where k = b - a and phi = (1+sqrt 5)/2,

which in integers is `a == (k + isqrt(5*k*k)) // 2`. That is one line per position
and no search at all. Each position's bit is 0 if it is a losing (P) position and
1 otherwise; eight bits per byte, most significant first, give the payload.
"""
import json
import math

positions = json.load(open("positions.json", encoding="utf-8"))["positions"]


def is_losing(a, b):
    if a > b:
        a, b = b, a
    k = b - a
    return a == (k + math.isqrt(5 * k * k)) // 2


bits = "".join("0" if is_losing(p[0], p[1]) else "1" for p in positions)
payload = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), payload.hex()))
'''


def _wyth_losing(a, b):
    if a > b:
        a, b = b, a
    k = b - a
    return a == (k + math.isqrt(5 * k * k)) // 2


def _wyth_floor_kphi(k):
    return (k + math.isqrt(5 * k * k)) // 2


def gen_wythoff(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="wythoff", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"wythoff:{flag_secret}:{seed}:{generation}")

    payload = bytes(rng.randrange(256) for _ in range(WYTHOFF_KEYBYTES))
    bits = "".join(f"{b:08b}" for b in payload)

    positions = []
    for bit in bits:
        # Build the position from a large index, then present a losing position for
        # a 0-bit and a near-miss winning position for a 1-bit. Off-by-one on `a`
        # around a losing position is still winning, so the two classes look alike
        # and only the closed form tells them apart — eyeballing will not.
        k = rng.randrange(WYTHOFF_MAG, 4 * WYTHOFF_MAG)
        a = _wyth_floor_kphi(k)
        b = a + k
        if bit == "0":
            pa, pb = a, b
        else:
            # nudge to a guaranteed winning position near the losing one
            pa, pb = a + rng.randrange(1, 5), b
            while _wyth_losing(pa, pb):
                pa += 1
        if rng.random() < 0.5:
            pa, pb = pb, pa                       # order carries no information
        positions.append([pa, pb])

    # Never ship a rung whose own decoding does not reproduce the payload.
    check = "".join("0" if _wyth_losing(p[0], p[1]) else "1" for p in positions)
    assert bytes(int(check[i:i + 8], 2) for i in range(0, len(check), 8)) == payload

    artifacts = {
        "positions.json": json.dumps({
            "game": ("two piles; a move removes any positive count from one pile, or "
                     "an equal positive count from both; the player who cannot move "
                     "loses"),
            "task": ("for each position, bit 0 if it is a loss for the player to move, "
                     "else bit 1; 8 bits per byte, most significant first"),
            "positions": positions,
        }, indent=1) + "\n",
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(payload.hex(), flag),
        "README.md": (
            "# Position ledger\n\n"
            f"`positions.json` lists {len(positions)} starting positions of a two-pile "
            "game and states its rules. For each position, decide whether the player "
            "to move loses under perfect play.\n\n"
            "Read the outcomes as bits (a loss for the mover is 0, otherwise 1), most "
            "significant bit first, eight to a byte. The operator's recovery blob is "
            "sealed under those bytes as lowercase hex. `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("wythoff", flag_secret, seed, generation),
        title="Position Ledger", category="misc",
        challenge_type="game-theory-closed-form",
        story=("A ledger lists starting positions of a two-pile game at enormous sizes "
               "and asks, for each, whether the player to move is already lost."),
        vulnerability=("the positions are far too large to decide by searching the game; only "
                       "the game's closed-form losing-position theory classifies them"),
        solution=["recognise the game and its losing-position structure",
                  "a<=b is a loss iff a == floor((b-a)*phi), computed in integers",
                  "classify every position in O(1) rather than by search",
                  "pack the outcome bits MSB-first into bytes and unseal"],
        artifacts=artifacts,
        solver_files={"solver.py": _WYTHOFF_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="wythoff",
        rank=15, max_runtime_s=60, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# blackbox — a function given only as behaviour
# ---------------------------------------------------------------------------
BLACK_WIDTH = 8
BLACK_PAIRS = 20

_BLACKBOX_SOLVER = '''\
"""Invert a function handed over only as input/output pairs.

There is no source and it is no cipher anyone has named, so a disassembler and a
crypto toolkit both have nothing to work on. What the pairs show, if you difference
them, is the tell: xor any two outputs and xor the two matching inputs, and column
i of the output difference always equals some fixed column of the input
difference. That can only happen if the function permutes the eight byte positions
and then xors a fixed mask into each — any additive or table term would not cancel
under a difference.

So recover the permutation by matching each output column's difference signature to
an input column's, read the mask off a single pair, and invert the target:

    out[i] = in[perm[i]] ^ mask[i]   ->   in[perm[i]] = out[i] ^ mask[i]
"""
import json

doc = json.load(open("pairs.json", encoding="utf-8"))
W = doc["width"]
pairs = [(bytes.fromhex(p["in"]), bytes.fromhex(p["out"])) for p in doc["pairs"]]
target = bytes.fromhex(doc["target_out"])

# Difference signatures relative to pair 0.
in0, out0 = pairs[0]
in_sig = [bytes(pairs[p][0][c] ^ in0[c] for p in range(1, len(pairs))) for c in range(W)]
out_sig = [bytes(pairs[p][1][c] ^ out0[c] for p in range(1, len(pairs))) for c in range(W)]

perm = []
for i in range(W):
    perm.append(next(c for c in range(W) if out_sig[i] == in_sig[c]))
assert sorted(perm) == list(range(W)), "difference signatures did not resolve a permutation"

mask = [out0[i] ^ in0[perm[i]] for i in range(W)]

# Sanity: the recovered map must reproduce every pair.
for src, dst in pairs:
    assert all(dst[i] == src[perm[i]] ^ mask[i] for i in range(W)), "model rejects a pair"

key = bytearray(W)
for i in range(W):
    key[perm[i]] = target[i] ^ mask[i]

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), bytes(key).hex()))
'''


def gen_blackbox(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="blackbox", seed=seed, generation=generation,
                          secret=flag_secret)
    for attempt in range(16):
        rng = random.Random(f"blackbox:{flag_secret}:{seed}:{generation}:{attempt}")
        perm = list(range(BLACK_WIDTH))
        rng.shuffle(perm)
        mask = [rng.randrange(256) for _ in range(BLACK_WIDTH)]

        def f(block):
            return bytes(block[perm[i]] ^ mask[i] for i in range(BLACK_WIDTH))

        pairs = []
        for _ in range(BLACK_PAIRS):
            src = bytes(rng.randrange(256) for _ in range(BLACK_WIDTH))
            pairs.append((src, f(src)))
        # The pairs must pin the permutation: every output column's difference
        # signature has to be unique, or perm is ambiguous. A degenerate draw
        # (e.g. two input columns identical across all pairs) is rebuilt.
        in0 = pairs[0][0]
        sig = [bytes(pairs[p][0][c] ^ in0[c] for p in range(1, len(pairs)))
               for c in range(BLACK_WIDTH)]
        if len(set(sig)) == BLACK_WIDTH:
            break
    else:                                                  # pragma: no cover
        raise RuntimeError("blackbox: could not pin the permutation")

    key = bytes(rng.randrange(256) for _ in range(BLACK_WIDTH))
    target = f(key)

    artifacts = {
        "pairs.json": json.dumps({
            "width": BLACK_WIDTH,
            "note": "input/output pairs of a fixed unknown function on 8-byte blocks",
            "target_out": target.hex(),
            "pairs": [{"in": s.hex(), "out": d.hex()} for s, d in pairs],
        }, indent=1) + "\n",
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key.hex(), flag),
        "README.md": (
            "# Black-box transform\n\n"
            "`pairs.json` gives input/output pairs of one fixed transform on 8-byte "
            "blocks. There is no source and no name for it — only its behaviour on "
            "these inputs. It also gives one target output.\n\n"
            "The operator's recovery blob is sealed under the 8-byte input that "
            "produces that target output, as lowercase hex. `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("blackbox", flag_secret, seed, generation),
        title="Black-Box Transform", category="reverse",
        challenge_type="behaviour-only-inversion",
        story=("A fixed transform on 8-byte blocks is known only by its behaviour: a "
               "handful of input/output pairs and one target output. No source, no "
               "documentation, no name."),
        vulnerability=("with no source and no matching cipher, the transform's shape shows only "
                       "in what its output differences conserve"),
        solution=["difference the pairs; note each output column tracks one input column",
                  "conclude the transform permutes byte positions and xors a mask",
                  "recover the permutation by matching difference signatures, mask from a pair",
                  "invert the target output to the input block and unseal"],
        artifacts=artifacts,
        solver_files={"solver.py": _BLACKBOX_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="blackbox",
        rank=12, max_runtime_s=60, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# gridpath — a number grid that is a picture
# ---------------------------------------------------------------------------
GRID_H = 24
GRID_W = 24
GRID_KEYBYTES = 16
_LIT = 0xA0                # lit data cells are 0xA0 | nibble; start marker is 0xFF

_GRIDPATH_SOLVER = '''\
"""Read a payload off a trail drawn in a grid of numbers.

The readings are a flat row-major dump; reshape them to height x width and they are
a picture, not a stream. Cells at or above 0xA0 are "lit" and form a single
non-branching trail through the dark background, and the low four bits of each lit
cell are its data. Start at the one saturated cell (0xFF), walk the trail, read the
low nibble of each cell you step onto, and pair the nibbles into bytes.
"""
import json

grid = json.load(open("grid.json", encoding="utf-8"))
H, W, flat = grid["height"], grid["width"], grid["readings"]
# The readings are a flat row-major dump; reshaping them to H x W is the point.
cells = [flat[r * W:(r + 1) * W] for r in range(H)]


def lit(r, c):
    return 0 <= r < H and 0 <= c < W and cells[r][c] >= 0xA0


start = next((r, c) for r in range(H) for c in range(W) if cells[r][c] == 0xFF)

nibbles = []
prev, cur = None, start
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

payload = bytes((nibbles[i] << 4) | nibbles[i + 1] for i in range(0, len(nibbles), 2))

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(), payload.hex()))
'''


def _grid_walk(rng, need):
    """A self-avoiding, non-self-touching trail of `need` cells, or None."""
    for _ in range(200):
        r = rng.randrange(GRID_H)
        c = rng.randrange(GRID_W)
        path = [(r, c)]
        occ = {(r, c)}
        ok = True
        for _ in range(need - 1):
            opts = []
            for dr, dc in ((-1, 0), (1, 0), (0, -1), (0, 1)):
                nr, nc = path[-1][0] + dr, path[-1][1] + dc
                if not (0 <= nr < GRID_H and 0 <= nc < GRID_W) or (nr, nc) in occ:
                    continue
                # Reject a step that would touch the trail anywhere but the cell we
                # came from — an induced path keeps the greedy walk unambiguous.
                touches = sum(1 for ar, ac in ((nr - 1, nc), (nr + 1, nc),
                                               (nr, nc - 1), (nr, nc + 1))
                              if (ar, ac) in occ)
                if touches == 1:
                    opts.append((nr, nc))
            if not opts:
                ok = False
                break
            step = opts[rng.randrange(len(opts))]
            path.append(step)
            occ.add(step)
        if ok and len(path) == need:
            return path
    return None


def gen_gridpath(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="gridpath", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"gridpath:{flag_secret}:{seed}:{generation}")

    payload = bytes(rng.randrange(256) for _ in range(GRID_KEYBYTES))
    nibbles = []
    for byte in payload:
        nibbles.append((byte >> 4) & 0xF)
        nibbles.append(byte & 0xF)
    need = len(nibbles) + 1                         # +1 for the start marker cell

    path = _grid_walk(rng, need)
    if path is None:                                             # pragma: no cover
        raise RuntimeError("gridpath: no clean trail fit the grid")

    cells = [[rng.randrange(0x00, 0x90) for _ in range(GRID_W)] for _ in range(GRID_H)]
    (sr, sc) = path[0]
    cells[sr][sc] = 0xFF                            # start marker
    for (r, c), nib in zip(path[1:], nibbles):
        cells[r][c] = _LIT | nib

    artifacts = {
        "grid.json": json.dumps({
            "height": GRID_H, "width": GRID_W,
            "readings": [cells[r][c] for r in range(GRID_H) for c in range(GRID_W)],
        }) + "\n",
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(payload.hex(), flag),
        "README.md": (
            "# Sensor grid\n\n"
            f"`grid.json` is {GRID_H * GRID_W} byte readings from a sensor panel, dumped "
            f"in row-major order for a {GRID_H} by {GRID_W} panel. Most of the panel is "
            "background noise. A trail of raised readings runs across it from the single "
            "saturated cell (value 255), and that trail is the message.\n\n"
            "The operator's recovery blob is sealed under the payload the trail carries "
            "as lowercase hex. `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("gridpath", flag_secret, seed, generation),
        title="Sensor Grid", category="forensics",
        challenge_type="visual-trail",
        story=("A sensor panel dumped a grid of readings. A trail of raised readings "
               "runs through the background from a single saturated cell; the trail is "
               "the message."),
        vulnerability=("the payload is a trail through a 2-D grid, legible when the grid is "
                       "drawn and invisible when the numbers are read as a flat stream"),
        solution=["lay the numbers out as a grid rather than a sequence",
                  "threshold the lit trail and find the saturated start cell",
                  "walk the non-branching trail from the start",
                  "read each cell's low nibble, two to a byte, and unseal"],
        artifacts=artifacts,
        solver_files={"solver.py": _GRIDPATH_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="gridpath",
        rank=9, max_runtime_s=60, flag_secret=flag_secret, difficulty="medium")


HUMANHARD_BUILDERS = [gen_wythoff, gen_blackbox, gen_gridpath]
