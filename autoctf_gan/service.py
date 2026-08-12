"""The challenge-maker as a container entrypoint.

This is the inside half of the architecture the outer platform assumes: the host
receives an upload and starts a container; everything that actually makes a
challenge — the CTF platform's build contract and the LLM call — happens in here.

The protocol is one JSON object on stdin, one JSON object on stdout. Stateless:
a match's generation counter and score live on the host, and each request names
exactly which challenge to build. That keeps the container disposable, so a
crashed or wedged build costs one container rather than the arena.

    $ echo '{"op":"capabilities"}' | python -m autoctf_gan.service
    {"ok": true, "capabilities": {"gcc": true, "fpylll": false, "llm": false}}

    $ echo '{"op":"build","seed":7,"generation":6,"flag_secret":"...",
             "campaign":{"start":"crypto"},"verify":true}' | python -m autoctf_gan.service
    {"ok": true, "spec": {...}, "verdict": {...}}

Two things move INTO the container by doing this:

  * `verify_spec` executes a generated solver. On the host that was a subprocess
    with the host's filesystem and network; here it is a process inside a
    container the arena can drop, cap and disconnect.
  * the LLM API key. It is an environment variable on the container, never a
    field in a request and never written to a spec.

Note the network asymmetry this creates, because it is a real operational
constraint rather than a detail: with `design=catalog` the maker needs no network
at all and should be run `--network none`. With `design=auto` and a key present it
must reach the model endpoint, so it cannot be. `capabilities` reports which case
this container is in so the host can pick the right isolation.
"""
from __future__ import annotations

import json
import sys
import traceback
from typing import Any

PROTOCOL_VERSION = 1


def capabilities() -> dict[str, Any]:
    """What this container can actually build — the host plans its route from it."""
    from .design import DesignBrain
    from .native import gcc_available

    try:
        import fpylll  # noqa: F401
        lattice = True
    except Exception:
        lattice = False

    brain = DesignBrain()
    return {
        "protocol": PROTOCOL_VERSION,
        "gcc": gcc_available(),          # the reverse ladder needs a compiler
        "fpylll": lattice,               # the Boneh-Durfee rung needs a lattice
        "llm": brain.configured,         # design brain -> this container needs egress
        "llm_model": brain.model if brain.configured else None,
        "python": sys.version.split()[0],
    }


def build(request: dict) -> dict[str, Any]:
    """Build (and optionally verify) one generation of one match's campaign."""
    from .campaign import default_campaign
    from .verify import verify_spec

    cfg = request.get("campaign") or {}
    campaign = default_campaign(
        start=cfg.get("start", "crypto"),
        cross_track=bool(cfg.get("cross_track", True)),
        authoring=bool(cfg.get("authoring", True)),
        probe=bool(cfg.get("probe", True)),
        design=cfg.get("design"),
    )
    spec = campaign.build(
        seed=int(request["seed"]),
        generation=int(request["generation"]),
        flag_secret=str(request.get("flag_secret", "")),
        parent_spec_id=request.get("parent_spec_id"),
        mutation_ops=request.get("mutation_ops"),
        target_solve_rate=float(request.get("target_solve_rate", 0.05)),
        recent=request.get("recent"),
    )

    out: dict[str, Any] = {"ok": True, "spec": spec.to_dict()}
    if request.get("verify"):
        verdict = verify_spec(spec)
        out["verdict"] = {"valid": verdict.valid, "reason": verdict.reason,
                          "poc_time_s": verdict.poc_time_s,
                          "checks": verdict.checks, "failures": verdict.failures}
        # verify_spec writes its findings back onto the spec
        out["spec"] = spec.to_dict()
    out["campaign"] = {
        "segments": [{"key": s.key, "category": s.category, "label": s.label,
                      "blurb": s.blurb, "rungs": list(s.rungs), "authoring": s.unbounded}
                     for s in campaign.segments],
        "skipped": campaign.describe_skipped(),
        "start_available": campaign.start_available,
        "bounded_rungs": campaign.bounded_rungs,
        "design": campaign.design,
    }
    return out


OPS = {"capabilities": lambda req: {"ok": True, "capabilities": capabilities()},
       "build": build}


def handle(request: dict) -> dict[str, Any]:
    op = request.get("op", "build")
    if op not in OPS:
        return {"ok": False, "error": f"unknown op {op!r}; expected one of {sorted(OPS)}"}
    try:
        return OPS[op](request)
    except Exception as exc:
        # A failed build is data the host must act on, not a crash it has to parse
        # out of a traceback on stderr.
        traceback.print_exc(file=sys.stderr)
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    raw = sys.stdin.read()
    try:
        request = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        json.dump({"ok": False, "error": f"request is not valid JSON: {exc}"}, sys.stdout)
        return 2
    if not isinstance(request, dict):
        json.dump({"ok": False, "error": "request must be a JSON object"}, sys.stdout)
        return 2
    response = handle(request)
    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0 if response.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
