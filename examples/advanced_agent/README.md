# The advanced agent — the same circle, and a reason to be an image

`../docker_demo/` teaches the pattern. This one is the argument for the
*mechanism*: an agent that is genuinely stronger **because** it ships as an image.

Still no language model, no prompts, no network. Just a bigger loop.

```
════════ ADVANCED image (ships fpylll + sympy) ════════
  ✔ Gen-0 smalle       0.00s      ✔ Gen-3 wiener        0.02s
  ✔ Gen-1 hastad       0.00s      ✔ Gen-4 fermat        0.03s
  ✔ Gen-2 commonmod    0.00s      ✔ Gen-5 bonehdurfee   7.67s   ← the lattice
  6/6 rungs solved.

════════ SIMPLE demo image (stdlib only) ════════
  ✔ Gen-0 … ✔ Gen-4                ✗ Gen-5 bonehdurfee  no flag
  5/6 rungs solved.
```

Same six challenges, same loop, same contract. The only difference is what the
image carries.

---

## What actually got more complex

| | `demo_agent.py` | this agent |
|---|---|---|
| **Preconditions** | on **filenames** — "is there an `n.txt`?" | on **measured features** — modulus bit length, exponent class, how many moduli, whether any two share a factor |
| **Memory** | one win-rate per skill | win-rate per skill **per challenge signature**, Laplace-smoothed toward a global prior |
| **Scheduling** | highest score first | **expected value per second** — score ÷ measured cost, inside a time budget |
| **Time** | ignored | tracks `meta["time_limit_s"]`, refuses to start an attack it cannot finish |
| **Skills** | 6, stdlib | 10, including a real lattice attack |

### Feature-based perception

The demo agent asks *what files are here*. This one parses every artifact into
integers, then measures them: modulus size, whether `e` is tiny (a cube-root
tell) or nearly as large as `n` (the fingerprint of a **small private
exponent**), how many moduli there are, and whether any pair shares a prime.

Preconditions written over measurements survive a challenge that renames its
files — and they let a skill fire on evidence a filename could never carry.

### Memory that knows when experience transfers

The demo agent keeps one number per skill. That is enough to demonstrate the
idea and wrong in an obvious way: winning with `fermat` on a 1024-bit challenge
says nothing about a 512-bit one.

So this agent keys memory on a **signature** — a coarse fingerprint like
`n2|ehuge|m1|c1|x1`. Coarse on purpose: too fine and every challenge is unique
so nothing ever transfers; too coarse and unrelated challenges pool their
statistics and it learns the wrong lesson.

Scores are Laplace-smoothed, so one lucky win cannot pin a skill at 1.00 forever
and one failure cannot banish a skill that is usually right. Confidence in the
specific evidence grows with how much of it there is.

### Cost-aware decisions

`DECIDE` ranks by **score ÷ expected seconds**, not score alone, and the cost is
*measured* after the first run rather than trusted from the declaration. A
0.4-second long shot beats a 45-second near-certainty when the clock is short.

It also refuses to start anything it cannot finish inside the remaining budget —
and returns `None` instead. Being killed mid-attack records nothing and teaches
the agent nothing, which is strictly worse than stopping honestly.

You can watch all of this:

```bash
docker run --rm -it autoctf-advanced-agent    # then pick 2
```

```
perceived 512-bit modulus, 1 moduli, e is huge
signature n2|ehuge|m1|c1|x1
trying 'wiener' (score 0.67, ~0.0s)
trying 'fermat' (score 0.67, ~0.0s)
trying 'trial-division' (score 0.25, ~0.0s)
trying 'pollard-p-1' (score 0.50, ~6.0s)
trying 'boneh-durfee' (score 0.50, ~45.0s)
'boneh-durfee' produced flag{…} in 7.67s
```

Cheap skills first, the expensive lattice last — not because anyone ordered them
that way, but because cost divided into score put them there.

---

## Why this one must be an image

The lattice attack needs **fpylll** (for LLL) and **sympy** (for resultants).

A `.py` or `.zip` agent may only import what the arena host happens to have
installed. On a host without fpylll that agent is silently weaker — and the team
does not find out until it loses the rung. An image carries its own libraries, so
the attack is *guaranteed* to be there.

That is the entire case for image submission, and this folder is the measurement
that backs it: **6/6 versus 5/6**, same loop, same contract.

## Build it

```bash
# from the repository root
docker build -t autoctf-advanced-agent -f examples/advanced_agent/Dockerfile .
docker run --rm -it autoctf-advanced-agent
```

About 35 seconds, and no compiler: `fpylll` publishes a manylinux wheel with its
fplll/GMP/MPFR/QD shared objects already bundled.

An earlier version of this Dockerfile installed `build-essential` and the `-dev`
headers to compile it. That cost ~85 MB and several minutes and bought nothing —
the wheel was already there. Worth checking before you assume a package needs a
toolchain.

The one non-obvious pin is **`cysignals`**: fpylll's wheel imports it at runtime
but does not declare it, so pip will not install it for you. Leave it out and
`import fpylll` fails — silently, because `lattice.py` guards that import. See
below.

## Files

| File | What |
|---|---|
| `agent.py` | the agent — perception, memory, scheduling, 10 skills |
| `lattice.py` | **not here.** The Dockerfile takes the canonical copy from `../champion_agent/lattice.py`, which is written to be shipped verbatim |
| `Dockerfile` | the libraries, and the two required lines |

The menu and sample challenges come from `../docker_demo/`, so both images offer
the same front door.

---

## One thing worth stealing: silence is not evidence

```
✔ agent.py imports cleanly
✔ helper lattice.py imports
✔ 10 skills registered
✔ 'boneh-durfee' can import fpylll
✔ 'boneh-durfee' can import sympy
```

The last two lines exist because the same bug bit twice while building this
folder, each time one level deeper than the check that was supposed to catch it.

**First** the demo menu did not put `/opt/agent` on `sys.path`, so
`from lattice import boneh_durfee` failed. The agent's `try/except` caught it,
the lattice skill disabled itself, and everything reported healthy. Fix: import
every helper module explicitly.

**Then** with helpers importing fine, `fpylll` was still dead — installed from a
wheel, but unable to import without `cysignals`. `lattice.py` defers its fpylll
import behind a guard, so the helper imported cleanly and the capability was
gone anyway. All checks green; 5/6 rungs.

The pattern is the same each time. **A well-written agent degrades quietly — and
quiet degradation is indistinguishable from success unless you go and look.**
Every `try/except ImportError` you write is a place your agent can be weaker
than you think it is.

So skills declare their real dependencies as importable module names:

```python
Skill("boneh-durfee", …, needs=("fpylll", "sympy"))
```

and `check` imports each one. Not the helper — the thing the helper needs. That
is the layer where the failure actually lives.
