"""Challenges where the *model* is the target — adversarial machine learning.

The rest of this repo attacks cryptography and code. This tier attacks a
classifier: you are handed the model, and the flag is sealed under an input you
can only produce by making the model wrong on purpose. The two techniques are the
ones an adversarial-ML primer teaches — concentrate a bounded perturbation on the
coordinates that separate two classes, and descend the gradient of a white-box
network with the *parameters* frozen and the *input* free — but neither challenge
is a textbook instance, and that is the point:

  bandflip   A nearest-template biometric gate. The obvious move (rewrite the
             probe to the authorized template) always works and always costs too
             much; the gate only opens for the CHEAPEST rewrite. Recognising
             "adversarial example" gets you nothing. You have to notice that a
             whole-band rewrite has a fixed price and a computable payoff, that
             the payoff is `|A-R| + |x-A| - |x-R|` per band and is never negative,
             and that the decision therefore collapses to an exact 0/1 knapsack —
             then actually run the DP. There is no published script for this.

  gradgate   A two-layer ReLU feature map plus a reference activation vector. The
             gate opens for any probe whose features land on that vector, and the
             only route to one is gradient descent through the network onto the
             input. Reading the calibration point off the weights means inverting
             a random ReLU composition in closed form, which is exactly the thing
             ReLU nets are not invertible for; descending to it takes a few
             hundred steps and a correct hand-written backward pass. The answer is
             snapped to a coarse grid so the recovered point is exact, not
             approximate.

Both are hint-free, both seal the flag under a value that only a completed attack
produces, and neither writes the flag into a player artifact.
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
        lineage=Lineage(archetype_id=f"adversarial.{attack_class}", generation=generation,
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
    return f"adv-{kind}-g{generation}-{tag}"


# ---------------------------------------------------------------------------
# bandflip — cheapest adversarial rewrite against a nearest-template gate
# ---------------------------------------------------------------------------
BANDS = 64

_BANDFLIP_SOLVER = '''\
"""Open a nearest-template gate with the cheapest possible rewrite.

The gate scores a probe by L1 distance to two templates and accepts when the
authorized one is strictly nearer. A rewrite may only replace a WHOLE band, and
band i costs cost[i] whatever value is written — so the only value worth writing
into a band you are already paying for is the authorized template's own A[i].

Rewriting band i then has a fixed price cost[i] and a fixed payoff

    gain[i] = |A[i]-R[i]| + |x[i]-A[i]| - |x[i]-R[i]|

on `d_R - d_A`, the quantity that decides the match. Triangle inequality makes
every gain non-negative and the payoffs add across bands, so acceptance needs
`sum(gain over rewritten bands) > d_A - d_R`: a 0/1 knapsack for the min-cost
subset clearing that threshold. Exact DP over the gain axis, clamped at the
threshold because surplus gain buys nothing, with the per-band DP layers kept so
the chosen subset can be backtracked. Ties are broken toward the lexicographically
smallest band set, as the gate's manual specifies.
"""
import json

gate = json.load(open("gate.json", encoding="utf-8"))
A, R, cost = gate["template_authorized"], gate["template_rejected"], gate["band_cost"]
x = json.load(open("probe.json", encoding="utf-8"))["probe"]
n = len(x)

d_a = sum(abs(x[i] - A[i]) for i in range(n))
d_r = sum(abs(x[i] - R[i]) for i in range(n))
gain = [abs(A[i] - R[i]) + abs(x[i] - A[i]) - abs(x[i] - R[i]) for i in range(n)]
cap = d_a - d_r + 1                    # reaching the clamp == strictly ahead

INF = float("inf")
layers = [[INF] * (cap + 1) for _ in range(n + 1)]
layers[0][0] = 0
for i in range(n):
    cur, nxt = layers[i], layers[i + 1]
    gi = min(gain[i], cap)
    for g in range(cap + 1):
        c = cur[g]
        if c == INF:
            continue
        if c < nxt[g]:
            nxt[g] = c
        ng = min(cap, g + gi)
        if c + cost[i] < nxt[ng]:
            nxt[ng] = c + cost[i]

assert layers[n][cap] != INF, "gate cannot be opened by rewriting bands"

# Backtrack. At each band, prefer NOT rewriting when both routes are optimal, and
# walk bands high-index-first, which yields the lexicographically smallest set.
chosen, g, budget = [], cap, layers[n][cap]
for i in range(n - 1, -1, -1):
    if layers[i][g] == budget:
        continue                       # band i was skipped; cheapest tie wins
    gi = min(gain[i], cap)
    for pg in range(cap + 1):
        if min(cap, pg + gi) == g and layers[i][pg] == budget - cost[i]:
            chosen.append(i)
            g, budget = pg, budget - cost[i]
            break
    else:
        raise AssertionError("backtrack lost the optimal path")
chosen.reverse()

forged = list(x)
for i in chosen:
    forged[i] = A[i]
assert sum(abs(forged[i] - A[i]) for i in range(n)) < \\
       sum(abs(forged[i] - R[i]) for i in range(n)), "forged probe is still rejected"

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(),
                    ",".join(str(v) for v in forged)))
'''


def _bandflip_optimum(x, A, R, cost):
    """Min-cost band set whose rewrite flips the gate, plus how many tie for it.

    Same DP the solver runs; the generator needs it to build the seal key and to
    reject an instance whose optimum is not unique (a tie would make the sealed
    answer ambiguous even with a tie-break rule spelled out).
    """
    n = len(x)
    d_a = sum(abs(x[i] - A[i]) for i in range(n))
    d_r = sum(abs(x[i] - R[i]) for i in range(n))
    gain = [abs(A[i] - R[i]) + abs(x[i] - A[i]) - abs(x[i] - R[i]) for i in range(n)]
    cap = d_a - d_r + 1
    if cap <= 0 or sum(min(g, cap) for g in gain) < cap:
        return None, 0
    inf = float("inf")
    layers = [[inf] * (cap + 1) for _ in range(n + 1)]
    counts = [[0] * (cap + 1) for _ in range(n + 1)]
    layers[0][0] = 0
    counts[0][0] = 1
    for i in range(n):
        cur, nxt = layers[i], layers[i + 1]
        ccur, cnxt = counts[i], counts[i + 1]
        gi = min(gain[i], cap)
        for g in range(cap + 1):
            c = cur[g]
            if c == inf:
                continue
            for ng, nc in ((g, c), (min(cap, g + gi), c + cost[i])):
                if nc < nxt[ng]:
                    nxt[ng] = nc
                    cnxt[ng] = ccur[g]
                elif nc == nxt[ng]:
                    cnxt[ng] += ccur[g]
    if layers[n][cap] == inf:
        return None, 0
    budget, g, chosen = layers[n][cap], cap, []
    for i in range(n - 1, -1, -1):
        if layers[i][g] == budget:
            continue
        gi = min(gain[i], cap)
        for pg in range(cap + 1):
            if min(cap, pg + gi) == g and layers[i][pg] == budget - cost[i]:
                chosen.append(i)
                g, budget = pg, budget - cost[i]
                break
    chosen.reverse()
    return chosen, counts[n][cap]


def gen_bandflip(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="bandflip", seed=seed, generation=generation,
                          secret=flag_secret)
    for attempt in range(64):
        rng = random.Random(f"bandflip:{flag_secret}:{seed}:{generation}:{attempt}")
        A = [rng.randrange(256) for _ in range(BANDS)]
        R = [rng.randrange(256) for _ in range(BANDS)]
        # The probe sits on the rejected template with a little sensor noise, so
        # it is confidently the wrong identity and a large gain must be bought.
        x = [max(0, min(255, R[i] + rng.randrange(-9, 10))) for i in range(BANDS)]
        # Costs correlate with how far a band has to move, so the cheap-per-gain
        # ordering is genuinely ambiguous and greedy misses the optimum.
        cost = [max(1, abs(x[i] - A[i]) + rng.randrange(-45, 46)) for i in range(BANDS)]
        chosen, ties = _bandflip_optimum(x, A, R, cost)
        if chosen and ties == 1 and 6 <= len(chosen) <= BANDS - 6:
            break
    else:                                                  # pragma: no cover
        raise RuntimeError("bandflip: no unique-optimum instance found")

    forged = list(x)
    for i in chosen:
        forged[i] = A[i]
    key = ",".join(str(v) for v in forged)

    artifacts = {
        "gate.json": json.dumps({
            "match": "nearest-template, L1 distance, strict",
            "accept_when": "distance(probe, template_authorized) < distance(probe, template_rejected)",
            "template_authorized": A,
            "template_rejected": R,
            "band_cost": cost,
        }, indent=1) + "\n",
        "probe.json": json.dumps({"probe": x}, indent=1) + "\n",
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key, flag),
        "README.md": (
            "# Spectral access gate\n\n"
            "The gate reads a 64-band spectral probe from the badge and matches it "
            "against two stored templates by L1 distance. It opens when the "
            "authorized template is *strictly* nearer than the rejected one.\n\n"
            "You can drive the badge's rewrite port, but only a band at a time and "
            "only as a whole: a rewrite replaces band `i` entirely with any value "
            "you choose, and burns `band_cost[i]` write credits regardless of what "
            "you write. The audit board raises an alarm on any rewrite that spends "
            "more credits than the cheapest one that would have opened the gate, so "
            "an accepted probe is not enough — it has to be the cheapest accepted "
            "probe. If two rewrite sets tie on total credits, the board expects the "
            "lexicographically smaller set of band indices.\n\n"
            "The operator's recovery blob is sealed under the accepted probe, "
            "written as its 64 band values joined by commas with no spaces "
            "(`v0,v1,...,v63`). `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("bandflip", flag_secret, seed, generation),
        title="Spectral Access Gate", category="misc", challenge_type="adversarial-nearest-template",
        story=("A badge reader matches a 64-band spectral probe against two stored "
               "templates and opens for the nearer one. The rewrite port takes whole "
               "bands at a fixed price per band, and the audit board rejects any "
               "rewrite that overpays."),
        vulnerability=("a nearest-template decision is linear in per-band rewrites, so the "
                       "minimum-credit forged probe is an exact 0/1 knapsack"),
        solution=["derive the per-band payoff |A-R| + |x-A| - |x-R| on d_R - d_A",
                  "note the payoffs are additive and non-negative by triangle inequality",
                  "solve the resulting 0/1 knapsack exactly by DP over the gain axis",
                  "rewrite the chosen bands to the authorized template and unseal"],
        artifacts=artifacts,
        solver_files={"solver.py": _BANDFLIP_SOLVER, "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="bandflip",
        rank=14, max_runtime_s=120, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# gradgate — invert a white-box ReLU feature map by descending onto the input
# ---------------------------------------------------------------------------
GRAD_IN, GRAD_H1, GRAD_H2 = 16, 48, 48
GRAD_STEPS, GRAD_RESTARTS = 1400, 8
GRAD_GRID = 16          # the calibration point lives on a 1/16 lattice

_GRADGATE_CORE = '''\
"""Gate firmware: the calibration network and the rig's trim helper.

`features` is the forward pass the gate runs on every probe. `distance_grad`
reports the mismatch against a calibration activation together with its
sensitivity to each of the 16 probe channels; the calibration rig used it to
decide which lamp to nudge and by how much.
"""
import json


def load(path="model.json"):
    with open(path, encoding="utf-8") as fh:
        m = json.load(fh)
    return m["W1"], m["b1"], m["W2"], m["b2"]


def features(model, x):
    W1, b1, W2, b2 = model
    pre1 = [sum(w * xi for w, xi in zip(row, x)) + b for row, b in zip(W1, b1)]
    h1 = [p if p > 0.0 else 0.0 for p in pre1]
    pre2 = [sum(w * hi for w, hi in zip(row, h1)) + b for row, b in zip(W2, b2)]
    h2 = [p if p > 0.0 else 0.0 for p in pre2]
    return pre1, h1, pre2, h2


def distance_grad(model, x, target):
    """Return (sum of squared feature error, d(error)/dx)."""
    W1, b1, W2, b2 = model
    pre1, h1, pre2, h2 = features(model, x)
    diff = [a - b for a, b in zip(h2, target)]
    err = sum(d * d for d in diff)
    g2 = [2.0 * d if p > 0.0 else 0.0 for d, p in zip(diff, pre2)]
    g1 = [(sum(g2[k] * W2[k][j] for k in range(len(g2))) if p > 0.0 else 0.0)
          for j, p in enumerate(pre1)]
    gx = [sum(g1[j] * W1[j][i] for j in range(len(g1))) for i in range(len(x))]
    return err, gx
'''

_GRADGATE_SOLVER = '''\
"""Recover the calibration point of a two-layer ReLU gate.

The gate opens for a probe whose feature vector equals the published calibration
activation. Solving `features(x) == v` in closed form means inverting a random
ReLU composition — the activation pattern is unknown, so it is a mixed-integer
problem, not a linear one. Descending onto it is easy instead: freeze the weights,
take the gradient of ||features(x) - v||^2 with respect to the INPUT, and step.

Two details make the descent actually land:

  * squared error, not absolute error. An L1 objective has a constant-magnitude
    subgradient, so the iterate keeps overshooting and stalls a few hundredths
    away from the answer — close enough to look right, wrong enough to snap to the
    wrong lattice point.
  * random restarts. The objective is non-convex and some starts die in a corner
    where too many ReLUs are off; the run with the smallest final error is the one
    that reached the true preimage, so take the best rather than the first.

The recovered point is exact only after snapping to the 1/16 lattice the gate's
manual says the calibration point lies on.
"""
import math
import random

import gate_model

GRID = 16
STEPS, RESTARTS = 1400, 8

model = gate_model.load()
target = __import__("json").load(open("calibration.json", encoding="utf-8"))["activation"]
n = len(model[0][0])


def descend(x0):
    x = list(x0)
    m = [0.0] * n
    v = [0.0] * n
    for t in range(1, STEPS + 1):
        err, g = gate_model.distance_grad(model, x, target)
        if err < 1e-26:
            break
        for i in range(n):
            m[i] = 0.9 * m[i] + 0.1 * g[i]
            v[i] = 0.999 * v[i] + 0.001 * g[i] * g[i]
            mh = m[i] / (1.0 - 0.9 ** t)
            vh = v[i] / (1.0 - 0.999 ** t)
            x[i] = min(1.0, max(0.0, x[i] - 0.02 * mh / (math.sqrt(vh) + 1e-12)))
    err, _ = gate_model.distance_grad(model, x, target)
    return err, x


best = None
for trial in range(RESTARTS):
    rng = random.Random(1000 + trial)          # fixed seeds: the run is reproducible
    err, x = descend([rng.random() for _ in range(n)])
    if best is None or err < best[0]:
        best = (err, x)

point = [round(c * GRID) for c in best[1]]
assert best[0] < 1e-12, f"descent stalled at error {best[0]}"

import sealed
print(sealed.unseal(open("flag.enc", encoding="utf-8").read(),
                    "-".join(str(k) for k in point)))
'''


def _grad_features(model, x):
    W1, b1, W2, b2 = model
    pre1 = [sum(w * xi for w, xi in zip(row, x)) + b for row, b in zip(W1, b1)]
    h1 = [p if p > 0.0 else 0.0 for p in pre1]
    pre2 = [sum(w * hi for w, hi in zip(row, h1)) + b for row, b in zip(W2, b2)]
    return [p if p > 0.0 else 0.0 for p in pre2]


def _grad_recovers(model, target, point, trials=3):
    """Generator-side rehearsal: does the shipped attack actually land on `point`?

    Cheap insurance. A random model whose calibration point sits behind too many
    dead ReLUs is unreachable by descent, and shipping one would make the rung
    quietly unsolvable — `verify_spec` would catch it, but only by dropping the
    challenge from the catalogue with no explanation.
    """
    n = len(model[0][0])
    best = None
    for trial in range(trials):
        rng = random.Random(1000 + trial)
        x = [rng.random() for _ in range(n)]
        m = [0.0] * n
        v = [0.0] * n
        for t in range(1, GRAD_STEPS + 1):
            W1, b1, W2, b2 = model
            pre1 = [sum(w * xi for w, xi in zip(row, x)) + b for row, b in zip(W1, b1)]
            h1 = [p if p > 0.0 else 0.0 for p in pre1]
            pre2 = [sum(w * hi for w, hi in zip(row, h1)) + b for row, b in zip(W2, b2)]
            h2 = [p if p > 0.0 else 0.0 for p in pre2]
            diff = [a - b for a, b in zip(h2, target)]
            err = sum(d * d for d in diff)
            if err < 1e-26:
                break
            g2 = [2.0 * d if p > 0.0 else 0.0 for d, p in zip(diff, pre2)]
            g1 = [(sum(g2[k] * W2[k][j] for k in range(len(g2))) if p > 0.0 else 0.0)
                  for j, p in enumerate(pre1)]
            for i in range(n):
                gi = sum(g1[j] * W1[j][i] for j in range(len(g1)))
                m[i] = 0.9 * m[i] + 0.1 * gi
                v[i] = 0.999 * v[i] + 0.001 * gi * gi
                mh = m[i] / (1.0 - 0.9 ** t)
                vh = v[i] / (1.0 - 0.999 ** t)
                x[i] = min(1.0, max(0.0, x[i] - 0.02 * mh / (math.sqrt(vh) + 1e-12)))
        err = sum((a - b) ** 2 for a, b in zip(_grad_features(model, x), target))
        if best is None or err < best[0]:
            best = (err, x)
    return best[0] < 1e-12 and [round(c * GRAD_GRID) for c in best[1]] == point


def gen_gradgate(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="gradgate", seed=seed, generation=generation,
                          secret=flag_secret)
    for attempt in range(16):
        rng = random.Random(f"gradgate:{flag_secret}:{seed}:{generation}:{attempt}")
        s1, s2 = 1.0 / math.sqrt(GRAD_IN), 1.0 / math.sqrt(GRAD_H1)
        # Rounded at build time and used rounded everywhere, so the JSON the player
        # gets and the JSON the generator reasoned about are bit-identical.
        W1 = [[round(rng.gauss(0, s1), 9) for _ in range(GRAD_IN)] for _ in range(GRAD_H1)]
        b1 = [round(rng.gauss(0, 0.25), 9) for _ in range(GRAD_H1)]
        W2 = [[round(rng.gauss(0, s2), 9) for _ in range(GRAD_H1)] for _ in range(GRAD_H2)]
        b2 = [round(rng.gauss(0, 0.25), 9) for _ in range(GRAD_H2)]
        model = (W1, b1, W2, b2)
        # Interior lattice point: away from the [0,1] clamp, so the descent is not
        # solved for free by the box constraint pinning coordinates.
        point = [rng.randrange(2, GRAD_GRID - 1) for _ in range(GRAD_IN)]
        z = [k / GRAD_GRID for k in point]
        target = _grad_features(model, z)
        if sum(1 for a in target if a > 0.0) < GRAD_H2 // 2:
            continue                          # too many dead units to descend through
        if _grad_recovers(model, target, point):
            break
    else:                                                  # pragma: no cover
        raise RuntimeError("gradgate: no descendable model found")

    key = "-".join(str(k) for k in point)
    artifacts = {
        "model.json": json.dumps({"W1": W1, "b1": b1, "W2": W2, "b2": b2}) + "\n",
        "calibration.json": json.dumps({"activation": target}, indent=1) + "\n",
        "gate_model.py": _GRADGATE_CORE,
        "sealed.py": _SEAL_TOOL,
        "flag.enc": _seal(key, flag),
        "README.md": (
            "# Calibration gate\n\n"
            "The vault's optical gate feeds a 16-channel probe vector, each channel "
            "in `[0, 1]`, through the two-layer network in `model.json` and compares "
            "the result against the calibration activation in `calibration.json`. It "
            "opens when they agree.\n\n"
            "`gate_model.py` is the gate's own firmware routine — the forward pass "
            "and, because the calibration rig used it to trim the lamps, the "
            "derivative of the mismatch with respect to the probe.\n\n"
            "The calibration point was set on the rig's detent wheel, so every one of "
            "its 16 channels is an exact multiple of 1/16. The operator's recovery "
            "blob is sealed under those 16 detent counts (each an integer 0-16) "
            "joined by hyphens, `k0-k1-...-k15`. `sealed.py` opens it.\n"),
    }
    return _spec(
        slug=_slug("gradgate", flag_secret, seed, generation),
        title="Calibration Gate", category="misc", challenge_type="whitebox-model-inversion",
        story=("An optical vault gate opens for the one 16-channel probe whose network "
               "features match a published calibration activation. The network is fully "
               "disclosed; the probe that produces it is not."),
        vulnerability=("a white-box network is differentiable with respect to its INPUT, so "
                       "its preimage is reachable by descent even though it has no closed form"),
        solution=["freeze the weights and treat the probe as the free variable",
                  "descend the squared feature mismatch, not the absolute one",
                  "restart from several random probes and keep the lowest-error run",
                  "snap the recovered probe to the 1/16 detent lattice and unseal"],
        artifacts=artifacts,
        solver_files={"solver.py": _GRADGATE_SOLVER, "gate_model.py": _GRADGATE_CORE,
                      "sealed.py": _SEAL_TOOL},
        flag=flag, seed=seed, generation=generation, attack_class="gradgate",
        rank=16, max_runtime_s=180, flag_secret=flag_secret)


ADVERSARIAL_BUILDERS = [gen_bandflip, gen_gradgate]
