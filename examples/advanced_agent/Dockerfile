# The advanced agent's image — and the honest argument for image submission.
#
# Build from the REPOSITORY ROOT:
#   docker build -t autoctf-advanced-agent -f examples/advanced_agent/Dockerfile .
#
# The contract is identical to the simple demo's: /opt/agent/agent.py defining
# solve(), and `python` on PATH. What differs is everything in between.
#
# ── Why this agent MUST be an image ────────────────────────────────────────
# It ships a real lattice attack (Boneh-Durfee), which needs fpylll for LLL and
# sympy for resultants. A .py or .zip submission may only import what the arena
# host happens to have installed — so on a host without fpylll that agent is
# silently weaker, and the team never finds out until it loses a rung. An image
# carries its own libraries, and the attack is guaranteed to be there.
#
# The measured difference on the demo's own sample ladder: the stdlib agent gets
# stuck at the Boneh-Durfee rung, this one clears it in about eight seconds.
FROM python:3.11-slim

# ── Libraries ──────────────────────────────────────────────────────────────
# No apt, no compiler. fpylll 0.6.4 publishes a manylinux wheel with its
# fplll/GMP/MPFR/QD shared objects already bundled (that is the 154 MB
# `fpylll.libs` directory inside site-packages), so installing build-essential
# and the -dev headers only added ~85 MB and several minutes for nothing.
#
# cysignals IS required, and it is the subtle part: fpylll's wheel imports it at
# RUNTIME but does not declare it as a dependency, so pip will not install it
# for you. Without it `import fpylll` raises ModuleNotFoundError — and because
# lattice.py guards that import, the failure is silent: the agent loads, reports
# healthy, and simply never runs its best attack. 1.12.5 is the last release
# supporting Python 3.11; newer needs >=3.12.
#
# `check` inside this image imports every module a skill declares in `needs`,
# which is what turns that silent degradation into a visible ✗.
RUN pip install --no-cache-dir \
        cysignals==1.12.5 \
        fpylll==0.6.4 \
        sympy==1.13.3 \
        gmpy2==2.2.1 \
        pycryptodome==3.20.0

# ── The agent ──────────────────────────────────────────────────────────────
# Two files. lattice.py is taken from examples/champion_agent/ rather than
# copied into this folder: it is written to be shipped verbatim, and one
# canonical copy cannot drift from another.
COPY examples/advanced_agent/agent.py   /opt/agent/agent.py
COPY examples/champion_agent/lattice.py /opt/agent/lattice.py

# ── The interactive demo (ignored during a match) ──────────────────────────
COPY examples/docker_demo/menu.py examples/docker_demo/samples.py /opt/demo/

# The arena runs your image with --user <uid>:<gid>, never as root.
RUN chmod -R a+rX /opt/agent /opt/demo

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ARENA_AGENT_DIR=/opt/agent

# Humans only — a match overrides this with --entrypoint python.
ENTRYPOINT ["python", "/opt/demo/menu.py"]
CMD []
