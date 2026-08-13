# The demo submission image, and the template competitors copy.
#
# Build it from the REPOSITORY ROOT, because it packages the repo's canonical
# circle-memory agent rather than keeping a second copy that would drift:
#
#   docker build -t autoctf-demo-agent -f examples/docker_demo/Dockerfile .
#
# or just run examples/docker_demo/submit.sh, which does that and the rest.
#
# ── The only two things the arena requires ─────────────────────────────────
#   1. /opt/agent/agent.py defines solve(files, meta=None)
#   2. `python` is on PATH
#
# Everything else in this file is either the interactive demo (which the arena
# never runs) or ordinary hygiene. A real team's image would swap the base for
# whatever their attack needs — sagemath, a CUDA runtime, an image with their
# own compiled solver — and the arena would not care.
FROM python:3.11-slim

# ── 1. The agent ───────────────────────────────────────────────────────────
# This is the whole submission. demo_agent.py is the circle-memory template:
# PERCEIVE → RECALL → DECIDE → ACT → RECORD over an explicit memory, with no
# language model and no network anywhere in it.
COPY demo_agent.py /opt/agent/agent.py

# ── 2. Libraries ───────────────────────────────────────────────────────────
# The demo agent is stdlib-only, so this layer is empty and commented out — but
# THIS is the line that makes an image submission worth doing. Uploaded .py/.zip
# agents get only what the arena host happens to have installed; an image gets
# exactly what you pin here.
#
# RUN pip install --no-cache-dir pycryptodome==3.20.0 sympy==1.13.3 gmpy2==2.2.1

# ── 3. The interactive demo (ignored during a match) ───────────────────────
COPY examples/docker_demo/menu.py examples/docker_demo/samples.py /opt/demo/

# The arena starts your container with --user <uid>:<gid>, using the host's uid
# rather than root, so anything root-only-readable is unreadable during a match.
# Getting this wrong is the single most common way an otherwise correct image is
# rejected, which is why the submission check calls it out by name.
RUN chmod -R a+rX /opt/agent /opt/demo

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ARENA_AGENT_DIR=/opt/agent

# For humans only. A match overrides both of these with `--entrypoint python`
# and its own arguments, so the menu cannot run during competition — which is
# exactly why one image can be a teaching demo and a submission at once.
ENTRYPOINT ["python", "/opt/demo/menu.py"]
CMD []
