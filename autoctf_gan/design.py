"""The maker's optional design brain — an LLM that PLANS, never that codes.

`generator._default_llm_call` used to raise "wire your provider SDK here", so the
competition path had no model in it at all: every challenge came from the offline
brain and the hand-written ladders. This is the wiring, and the shape of it is
the point.

A model is allowed to decide two things:

  * the ORDER of attack classes in a composition — which weaknesses to chain,
    and how deep
  * the PROSE — title, story, hints, designer note

It is allowed to decide nothing else. Stage names are resolved against `STAGES`
by `Plan.validate()`, so a hallucinated or hostile class name is a rejected plan,
not a build step; the key material and the exploit both come from reviewed code
in `rsa_stages`. That keeps the repository's standing boundary intact — the AI
does not emit vulnerability-executing code — while still letting it author
challenges that are not on any ladder.

Every failure path falls back to the deterministic catalogue, so a missing key, a
rate limit, a timeout or a malformed reply costs variety and never a match.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .compose import Plan, plan_at
from .rsa_stages import STAGES

DESIGN_SYSTEM_PROMPT = """\
You are the design brain of an authorized, sandboxed CTF challenge maker. You are
composing a multi-stage RSA challenge for a security competition whose players are
autonomous agents.

You choose ONLY the composition and the prose. You never write code. Every stage
you name is built and attacked by reviewed, pre-existing implementations.

RULES
1. Return exactly one JSON object. No prose outside it, no markdown fences.
2. "stages" MUST be an ordered list of 2 or more names taken VERBATIM from the
   supplied catalogue. Never invent a name. Never repeat a name back-to-back.
3. Difficulty comes from STRUCTURE — how many stages and which classes — never
   from bigger keys. Key sizes are not yours to set.
4. Order the stages so the challenge opens with the class you consider the most
   approachable and ends with the one that guards the flag.
5. Aim for the requested difficulty rank. The rank of a composition is the sum of
   its stages' ranks plus the number of stages.
6. Hints must help a solver reason, never hand over the answer. 2 to 5 short
   strings. Never mention a flag value, a key, or a file's contents.
7. The story is fiction. No real organizations, systems, people, or credentials.

OUTPUT
{"stages": [...], "title": "...", "story": "...", "hints": ["..."],
 "designer_note": "..."}
"""


class DesignBrain:
    """OpenAI-compatible chat client, matching the convention the repo already uses."""

    def __init__(self) -> None:
        self.base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self.api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.model = os.getenv("LLM_MODEL", "gpt-5-mini")
        self.timeout = int(os.getenv("LLM_TIMEOUT_S", "60"))

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, user: str, *, temperature: float = 0.7) -> str:
        if not self.api_key:
            raise RuntimeError("no LLM API key configured")
        body: dict[str, object] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "response_format": {"type": "json_object"},
        }
        if not self.model.startswith("gpt-5"):
            body["temperature"] = temperature
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self.api_key}",
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.load(response)["choices"][0]["message"]["content"].strip()


def catalogue() -> list[dict]:
    """The reviewed primitives a plan may draw on — the model sees exactly this."""
    return [{"name": s.name, "label": s.label, "rank": s.rank,
             "weakness": s.vulnerability} for s in
            sorted(STAGES.values(), key=lambda s: s.rank)]


def brain_status() -> dict:
    """What the UI shows instead of the Studio's OFFLINE BRAIN badge."""
    brain = DesignBrain()
    return {"configured": brain.configured,
            "model": brain.model if brain.configured else None,
            "base_url": brain.base_url if brain.configured else None,
            "mode": "llm" if brain.configured else "catalog"}


def propose_plan(*, index: int, recent: list[str] | None = None,
                 brain: DesignBrain | None = None,
                 complete=None) -> Plan:
    """Ask the model for a composition; fall back to the catalogue on any failure.

    `index` is the catalogue position this generation would otherwise get. It sets
    the difficulty target, so an LLM-authored challenge lands in the same band as
    the deterministic one it replaces and escalation stays honest.
    """
    fallback = plan_at(index)
    call = complete
    if call is None:
        brain = brain or DesignBrain()
        if not brain.configured:
            return fallback
        call = brain.complete

    request = json.dumps({
        "catalogue": catalogue(),
        "target_rank": fallback.rank,
        "target_depth": len(fallback.stages),
        "avoid_repeating": list(recent or [])[-8:],
    }, ensure_ascii=False)

    try:
        raw = call(DESIGN_SYSTEM_PROMPT, request)
        data = json.loads(raw)
        if not isinstance(data, dict):
            return fallback
        plan = Plan(
            stages=[str(s) for s in data.get("stages") or []],
            title=str(data.get("title") or "").strip()[:120] or fallback.title,
            story=str(data.get("story") or "").strip()[:600] or fallback.story,
            hints=[str(h).strip()[:200] for h in (data.get("hints") or [])][:5]
                  or fallback.hints,
            designer_note=str(data.get("designer_note") or "").strip()[:400],
            source="llm",
        ).validate()
    except (ValueError, TypeError, KeyError, json.JSONDecodeError,
            urllib.error.URLError, OSError, RuntimeError):
        # A design brain is a nice-to-have. It must never cost a match.
        return fallback

    if _leaks(plan):
        return fallback
    return plan


_FORBIDDEN = ("flag{", "n.txt", "c.txt", "e.txt", "stage2.enc", "solver")


def _leaks(plan: Plan) -> bool:
    """Refuse prose that hands over the answer path or a flag-shaped string."""
    blob = " ".join([plan.title, plan.story, *plan.hints, plan.designer_note]).lower()
    return any(token in blob for token in _FORBIDDEN)
