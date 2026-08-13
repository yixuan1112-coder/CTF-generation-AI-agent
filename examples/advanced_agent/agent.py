#!/usr/bin/env python3
"""AutoCTF Arena — ADVANCED agent: the circle-memory pattern, grown up.

Same circle as `demo_agent.py`, still with **no language model, no prompts and
no network**. What changed is how much the agent knows about itself:

  demo_agent.py                     this file
  ─────────────────────────────     ──────────────────────────────────────────
  preconditions on FILENAMES        preconditions on measured FEATURES of the
                                    numbers (modulus size, exponent class,
                                    how many moduli, gcd structure)
  memory = one win-rate per skill   memory = win-rate per skill PER CHALLENGE
                                    SIGNATURE, so experience transfers only
                                    between challenges that actually resemble
                                    each other
  try skills in score order         expected-value scheduling: score ÷ cost,
                                    with a time budget it refuses to overrun
  6 stdlib attacks                  10 attacks, including a real lattice
                                    attack that needs fpylll + sympy

That last row is the reason this agent ships as an **image**. A `.zip` agent
may only import what the arena host happens to have; an image brings its own
libraries, and Boneh-Durfee is unreachable without them. The rung this agent
clears and `demo_agent.py` does not is exactly the rung its extra libraries buy.

────────────────────────────────────────────────────────────────────────────
The circle, unchanged

    PERCEIVE ──▶ RECALL ──▶ DECIDE ──▶ ACT ──▶ RECORD ──┐
        ▲                                               │
        └───────────────────────────────────────────────┘

  PERCEIVE  parse every artifact into numbers, then MEASURE them
  RECALL    what worked before on challenges with this signature?
  DECIDE    highest expected value per unit of time, within the budget left
  ACT       run one skill
  RECORD    write the outcome down, keyed by signature

Contract (identical — the arena only ever calls this):
    solve(files: dict[str, str], meta: dict | None) -> str | None
"""
from __future__ import annotations

import math
import sys
import time
from collections import Counter, defaultdict
from functools import reduce

try:                                   # shipped in the image alongside this file
    from lattice import boneh_durfee
except ImportError:                    # still importable without it; that skill
    boneh_durfee = None                # simply never applies


# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — PERCEIVE
#  Turn artifacts into *measured facts*. The demo agent asked "is there a file
#  called n.txt?"; this one asks "how big is the modulus, how many are there,
#  do any share a factor, is the exponent tiny or enormous?" Preconditions
#  written over measurements survive a challenge that renames its files.
# ═══════════════════════════════════════════════════════════════════════════
def _ints(files: dict) -> dict:
    """Every artifact that is a bare integer, by name without extension."""
    out = {}
    for name, body in (files or {}).items():
        text = (body or "").strip()
        if not text or len(text) > 20000:
            continue
        try:
            out[name.rsplit(".", 1)[0]] = int(text)
        except ValueError:
            continue
    return out


def _group(nums: dict, prefix: str) -> list[int]:
    """Indexed families: n0,n1,n2 → [n0,n1,n2]. Sorted numerically, not
    lexically, so n10 does not sort between n1 and n2."""
    found = []
    for key, value in nums.items():
        if key.startswith(prefix) and key[len(prefix):].isdigit():
            found.append((int(key[len(prefix):]), value))
    return [v for _, v in sorted(found)]


def perceive(files: dict, meta: dict | None) -> dict:
    nums = _ints(files)
    meta = meta or {}

    moduli = _group(nums, "n") or ([nums["n"]] if "n" in nums else [])
    cts = _group(nums, "c") or ([nums["c"]] if "c" in nums else [])
    exps = _group(nums, "e") or ([nums["e"]] if "e" in nums else [])
    if "e" in nums and nums["e"] not in exps:
        exps.append(nums["e"])

    n = moduli[0] if moduli else 0
    n_bits = n.bit_length()

    # Do any two moduli share a prime? If a challenge generates keys carelessly
    # this is instant, and it costs one gcd per pair to find out.
    shared = None
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = math.gcd(moduli[i], moduli[j])
            if 1 < g < moduli[i]:
                shared = (i, j, g)
                break
        if shared:
            break

    facts = {
        "files": files or {},
        "nums": nums,
        "moduli": moduli,
        "cts": cts,
        "exps": exps,
        "n": n,
        "n_bits": n_bits,
        "e": exps[0] if exps else 0,
        "e_bits": exps[0].bit_length() if exps else 0,
        "shared_factor": shared,
        # e comparable to n is the fingerprint of a SMALL d — it is what makes
        # Wiener and Boneh-Durfee worth attempting at all.
        "e_is_huge": bool(exps) and exps[0].bit_length() > 0.6 * max(n_bits, 1),
        "e_is_tiny": bool(exps) and exps[0] <= 5,
        "category": meta.get("category"),
        "gen": meta.get("gen"),
        "time_limit_s": float(meta.get("time_limit_s") or 120),
        "text": " ".join(str(v) for k, v in (files or {}).items()
                         if not k.endswith(".txt") or k.rsplit(".", 1)[0] not in nums
                         )[:4000].lower(),
    }
    facts["signature"] = signature(facts)
    return facts


def signature(facts: dict) -> str:
    """A coarse fingerprint of the challenge's SHAPE.

    Coarse on purpose. Too fine and every challenge is unique, so memory never
    transfers and the agent learns nothing. Too coarse and unrelated challenges
    pool their statistics and it learns the wrong thing. Bucketing the modulus
    by 256 bits and the exponent into three classes puts challenges that yield
    to the same attack in the same bucket.
    """
    e_class = ("tiny" if facts["e_is_tiny"]
               else "huge" if facts["e_is_huge"]
               else "normal")
    return (f"n{facts['n_bits'] // 256}"
            f"|e{e_class}"
            f"|m{min(len(facts['moduli']), 4)}"
            f"|c{min(len(facts['cts']), 4)}"
            f"|x{min(len(facts['exps']), 3)}")


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — MEMORY
#  Two tiers. Global stats answer "is this skill ever any good?"; per-signature
#  stats answer "is it good HERE?" DECIDE blends them, leaning on the specific
#  evidence only once there is enough of it to trust.
# ═══════════════════════════════════════════════════════════════════════════
class Memory:
    def __init__(self) -> None:
        # within one challenge
        self.tried: set[str] = set()
        self.log: list[tuple[str, bool, float, str]] = []

        # across challenges (persists in --serve mode and across the rungs of
        # one match, because the module-level agent below is reused)
        self.wins: Counter = Counter()
        self.uses: Counter = Counter()
        self.sig_wins: dict = defaultdict(Counter)
        self.sig_uses: dict = defaultdict(Counter)
        self.spent: dict = defaultdict(float)      # seconds per skill, ever
        self.timeouts: Counter = Counter()

    def start_challenge(self) -> None:
        self.tried = set()
        self.log = []

    def has_tried(self, name: str) -> bool:
        return name in self.tried

    def record(self, name: str, sig: str, worked: bool, seconds: float,
               note: str = "") -> None:
        self.tried.add(name)
        self.log.append((name, worked, seconds, note))
        self.uses[name] += 1
        self.sig_uses[sig][name] += 1
        self.spent[name] += seconds
        if worked:
            self.wins[name] += 1
            self.sig_wins[sig][name] += 1

    def score(self, name: str, sig: str) -> float:
        """P(this skill wins | this signature), smoothed toward the global rate.

        Laplace-smoothed rather than raw, so one lucky success on one challenge
        does not pin a skill at 1.00 forever, and one failure does not banish a
        skill that is usually right.
        """
        g_uses, g_wins = self.uses[name], self.wins[name]
        global_rate = (g_wins + 1) / (g_uses + 2)          # optimistic prior
        s_uses, s_wins = self.sig_uses[sig][name], self.sig_wins[sig][name]
        if s_uses == 0:
            return global_rate
        # Confidence in the specific evidence grows with how much there is.
        weight = s_uses / (s_uses + 2)
        specific = s_wins / s_uses
        return weight * specific + (1 - weight) * global_rate

    def expected_seconds(self, name: str, declared_cost: float) -> float:
        """Measured cost once we have measured it; the declared guess until then."""
        if self.uses[name] == 0:
            return declared_cost
        return max(0.001, self.spent[name] / self.uses[name])


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — NUMBER-THEORY TOOLING
#  The "hands" the skills use. Nothing here decides anything.
# ═══════════════════════════════════════════════════════════════════════════
def _iroot(x: int, k: int) -> int:
    if x < 0:
        return 0
    lo, hi = 0, 1 << ((x.bit_length() // k) + 2)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _to_flag(m: int) -> str | None:
    """Bytes that read like a flag, or nothing. A wrong attack yields garbage,
    and this is what stops the agent submitting garbage with confidence."""
    try:
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
    except (OverflowError, ValueError):
        return None
    for candidate in (raw, raw.lstrip(b"\x00")):
        try:
            text = candidate.decode("utf-8")
        except UnicodeDecodeError:
            continue
        start = text.find("flag{")
        if start >= 0 and text.rstrip().endswith("}"):
            return text[start:].rstrip()
    return None


def _egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def _decrypt(p: int, n: int, e: int, c: int) -> str | None:
    """Once a factor is known, every factoring attack finishes the same way."""
    q = n // p
    try:
        d = pow(e, -1, (p - 1) * (q - 1))
    except ValueError:
        return None
    return _to_flag(pow(c, d, n))


def _wiener_d(e: int, n: int):
    cf, a, b = [], e, n
    while b:
        cf.append(a // b)
        a, b = b, a % b
    for i in range(len(cf)):
        num, den = 1, 0
        for x in reversed(cf[: i + 1]):
            num, den = x * num + den, num
        k, d = num, den
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        bb = n - phi + 1
        disc = bb * bb - 4 * n
        if disc >= 0 and math.isqrt(disc) ** 2 == disc:
            return d
    return None


def _fermat(n: int, cap: int = 1 << 21):
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(cap):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b
        a += 1
    return None


def _pollard_p1(n: int, bound: int = 200_000):
    a = 2
    for j in range(2, bound):
        a = pow(a, j, n)
        if j % 256 == 0:                       # gcd is the expensive part
            d = math.gcd(a - 1, n)
            if 1 < d < n:
                return d
            if d == n:
                return None
    return None


def _pollard_rho(n: int, budget_s: float = 20.0):
    """Brent's variant. Good at pulling out a factor up to ~2^60; hopeless on a
    balanced 1024-bit modulus, which is precisely what its cost reflects."""
    if n % 2 == 0:
        return 2
    deadline = time.monotonic() + budget_s
    y, c, m = 2, 1, 128
    g = r = q = 1
    while g == 1:
        x = y
        for _ in range(r):
            y = (y * y + c) % n
        k = 0
        while k < r and g == 1:
            ys = y
            for _ in range(min(m, r - k)):
                y = (y * y + c) % n
                q = q * abs(x - y) % n
            g = math.gcd(q, n)
            k += m
            if time.monotonic() > deadline:
                return None
        r *= 2
    if g == n:
        g = 1
        while g == 1:
            ys = (ys * ys + c) % n
            g = math.gcd(abs(x - ys), n)
            if time.monotonic() > deadline:
                return None
    return g if 1 < g < n else None


_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]


def _trial(n: int, limit: int = 100_000):
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return p
    p = 49
    while p < limit:
        if n % p == 0:
            return p
        p += 2
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — SKILLS
#  Each declares WHEN it applies (over measured features), HOW it runs, and
#  ROUGHLY WHAT IT COSTS. Cost is what lets DECIDE prefer a one-millisecond
#  gamble over a twenty-second one when both look equally likely.
# ═══════════════════════════════════════════════════════════════════════════
class Skill:
    def __init__(self, name, applies, run, cost, needs=()):
        self.name = name
        self.applies = applies
        self.run = run
        self.cost = cost              # declared seconds, until measured
        # Importable module names this skill cannot run without — NOT prose.
        # The image's `check` imports each one, which is the only way to notice
        # a library that is installed but broken. A skill that degrades quietly
        # is the whole hazard: it reports success and never fires.
        self.needs = tuple(needs)


def _sk_small_e(f):
    n, e, c = f["n"], f["e"], f["cts"][0]
    m = _iroot(c, e)
    return _to_flag(m) if m ** e == c else None


def _sk_hastad(f):
    ns, cs = f["moduli"][:3], f["cts"][:3]
    mod = reduce(lambda x, y: x * y, ns)
    x = sum(r * (mod // m) * pow(mod // m, -1, m) for r, m in zip(cs, ns)) % mod
    return _to_flag(_iroot(x, 3))


def _sk_common_modulus(f):
    nums = f["nums"]
    n, e1, e2 = nums["n"], nums["e1"], nums["e2"]
    c1, c2 = nums["c1"], nums["c2"]
    g, a, b = _egcd(e1, e2)
    if g != 1:
        return None
    if a < 0:
        c1, a = pow(c1, -1, n), -a
    if b < 0:
        c2, b = pow(c2, -1, n), -b
    return _to_flag(pow(c1, a, n) * pow(c2, b, n) % n)


def _sk_shared_factor(f):
    """Two moduli sharing a prime: gcd hands you both keys at once."""
    i, _j, p = f["shared_factor"]
    n, c = f["moduli"][i], f["cts"][i] if i < len(f["cts"]) else f["cts"][0]
    return _decrypt(p, n, f["e"] or 65537, c)


def _factoring_skill(finder):
    def run(f):
        n, e, c = f["n"], f["e"] or 65537, f["cts"][0]
        p = finder(n)
        return _decrypt(p, n, e, c) if p and 1 < p < n and n % p == 0 else None
    return run


def _sk_wiener(f):
    n, e, c = f["n"], f["e"], f["cts"][0]
    d = _wiener_d(e, n)
    return _to_flag(pow(c, d, n)) if d else None


def _sk_boneh_durfee(f):
    """The lattice attack. Recovers d up to about N^0.292, well past Wiener's
    N^0.25 — and the single reason this agent needs to be an image."""
    n, e, c = f["n"], f["e"], f["cts"][0]
    for delta in (0.26, 0.28, 0.292):
        try:
            got = boneh_durfee(n, e, delta=delta, mm=4)
        except NotImplementedError:
            return None
        except Exception:
            continue
        if got:
            p, _q = got
            flag = _decrypt(p, n, e, c)
            if flag:
                return flag
    return None


def _has_nec(f):
    return bool(f["n"]) and bool(f["exps"]) and bool(f["cts"])


SKILLS = [
    Skill("trial-division", lambda f: _has_nec(f) and f["n_bits"] < 2048,
          _factoring_skill(_trial), cost=0.2),
    Skill("small-exponent", lambda f: _has_nec(f) and f["e_is_tiny"],
          _sk_small_e, cost=0.05),
    Skill("hastad-broadcast", lambda f: len(f["moduli"]) >= 3 and len(f["cts"]) >= 3,
          _sk_hastad, cost=0.1),
    Skill("common-modulus",
          lambda f: {"n", "e1", "e2", "c1", "c2"} <= set(f["nums"]),
          _sk_common_modulus, cost=0.1),
    Skill("shared-factor", lambda f: f["shared_factor"] is not None,
          _sk_shared_factor, cost=0.05),
    Skill("fermat", lambda f: _has_nec(f), _factoring_skill(_fermat), cost=3.0),
    Skill("pollard-p-1", lambda f: _has_nec(f), _factoring_skill(_pollard_p1),
          cost=6.0),
    Skill("pollard-rho", lambda f: _has_nec(f) and f["n_bits"] <= 256,
          _factoring_skill(_pollard_rho), cost=20.0),
    Skill("wiener", lambda f: _has_nec(f) and f["e_is_huge"], _sk_wiener, cost=0.3),
    Skill("boneh-durfee",
          lambda f: _has_nec(f) and f["e_is_huge"] and boneh_durfee is not None,
          _sk_boneh_durfee, cost=45.0, needs=("fpylll", "sympy")),
]


# ═══════════════════════════════════════════════════════════════════════════
#  PART 5 — THE AGENT
#  The loop. Still knows nothing about RSA — it reasons only over names,
#  scores, costs and a clock.
# ═══════════════════════════════════════════════════════════════════════════
class Agent:
    def __init__(self, memory: Memory | None = None, verbose: bool = False):
        self.memory = memory or Memory()
        self.verbose = verbose

    def _say(self, msg: str) -> None:
        if self.verbose:
            print(f"      {msg}", file=sys.stderr, flush=True)

    def decide(self, facts: dict, seconds_left: float):
        """RECALL + DECIDE: expected value per second, within the budget left.

        Returns None when nothing untried applies OR when everything left costs
        more time than remains — refusing to start an attack it cannot finish is
        part of being honest about being stuck.
        """
        sig = facts["signature"]
        ranked = []
        for skill in SKILLS:
            if self.memory.has_tried(skill.name):
                continue
            try:
                if not skill.applies(facts):
                    continue
            except Exception:
                continue
            cost = self.memory.expected_seconds(skill.name, skill.cost)
            if cost > seconds_left:
                self._say(f"skipping '{skill.name}': needs ~{cost:.0f}s, "
                          f"{seconds_left:.0f}s left")
                continue
            ranked.append((self.memory.score(skill.name, sig) / max(cost, 0.01),
                           -cost, skill))
        if not ranked:
            return None
        ranked.sort(key=lambda t: (t[0], t[1]), reverse=True)
        return ranked[0][2]

    def solve_once(self, files: dict, meta: dict | None = None) -> str | None:
        started = time.monotonic()
        facts = perceive(files, meta)
        self.memory.start_challenge()
        sig = facts["signature"]
        # Leave a margin: being killed mid-skill records nothing and teaches
        # the agent nothing about the attempt.
        budget = facts["time_limit_s"] * 0.9

        self._say(f"perceived {facts['n_bits']}-bit modulus, "
                  f"{len(facts['moduli'])} moduli, e is "
                  f"{'tiny' if facts['e_is_tiny'] else 'huge' if facts['e_is_huge'] else 'normal'}")
        self._say(f"signature {sig}")

        while True:
            left = budget - (time.monotonic() - started)
            skill = self.decide(facts, left)
            if skill is None:
                self._say("no affordable untried skill applies — stuck")
                return None
            self._say(f"trying '{skill.name}' "
                      f"(score {self.memory.score(skill.name, sig):.2f}, "
                      f"~{self.memory.expected_seconds(skill.name, skill.cost):.1f}s)")
            t0 = time.monotonic()
            try:
                flag = skill.run(facts)
                note = ""
            except Exception as exc:
                flag, note = None, f"{type(exc).__name__}: {exc}"
                self._say(f"'{skill.name}' raised {note}")
            elapsed = time.monotonic() - t0
            self.memory.record(skill.name, sig, bool(flag), elapsed, note)
            if flag:
                self._say(f"'{skill.name}' produced {flag} in {elapsed:.2f}s")
                return flag


_AGENT = Agent()


# ═══════════════════════════════════════════════════════════════════════════
#  PART 6 — THE ARENA CONTRACT
# ═══════════════════════════════════════════════════════════════════════════
def solve(files: dict, meta: dict | None = None) -> str | None:
    return _AGENT.solve_once(files, meta)


if __name__ == "__main__":
    _AGENT.verbose = True
    print("This is the agent module. Run the demo menu to exercise it:")
    print("    docker run --rm -it autoctf-advanced-agent")
