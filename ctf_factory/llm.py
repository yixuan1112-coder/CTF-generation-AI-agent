from __future__ import annotations

import json
import os
import urllib.request
from typing import Any


class CompatibleLLM:
    """Optional copywriter: templates retain control of all security properties."""

    def __init__(self) -> None:
        self.base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self.api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.model = os.getenv("LLM_MODEL", "gpt-5-mini")

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _complete(self, messages: list[dict[str, str]], *, temperature: float = 0.4) -> str:
        request_body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "response_format": {"type": "json_object"},
        }
        if not self.model.startswith("gpt-5"):
            request_body["temperature"] = temperature
        payload = json.dumps(request_body).encode()
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=payload,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)["choices"][0]["message"]["content"].strip()

    def design_challenge(self, *, brief: str, templates: list[dict[str, str]],
                         category: str = "", challenge_type: str = "",
                         difficulty: str = "medium",
                         experience_lessons: list[str] | None = None,
                         candidate_index: int = 0) -> dict[str, Any] | None:
        """Create a constrained blueprint; executable security behavior stays template-owned."""
        if not self.api_key:
            return None
        constraints = {
            "brief": brief[:2000], "requested_category": category,
            "requested_type": challenge_type, "requested_difficulty": difficulty,
            "allowed_build_primitives": templates,
            "sanitized_past_lessons": list(experience_lessons or [])[:8],
            "candidate_index": candidate_index,
        }
        system = (
            "You are the design brain for an authorized, local-only CTF challenge studio. "
            "Choose exactly one reviewed build primitive, then create a distinct challenge design around it. "
            "The primitive is a safety boundary, not a complete story or fixed puzzle template. "
            "Never propose real targets, credentials, malware, "
            "persistence, destructive actions, or an unreviewed vulnerability. Return JSON only with "
            "Use past lessons only to avoid previously observed failures; never reproduce hidden data. "
            "Make this candidate meaningfully distinct in narrative, data flow, and player reasoning. "
            "Return category, challenge_type, difficulty, title, story, hints, designer_notes. difficulty must "
            "be easy, medium, or hard; hints must contain 1-3 short strings. Do not include a flag or solution."
        )
        raw = self._complete([
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(constraints, ensure_ascii=False)},
        ])
        value = json.loads(raw)
        return value if isinstance(value, dict) else None

    def rewrite_story(self, *, theme: str, title: str, category: str, difficulty: str) -> str | None:
        if not self.api_key:
            return None
        prompt = (
            "Write one short CTF challenge story, maximum 45 words. Do not include solutions, "
            "flags, URLs, real targets, or credentials. "
            f"Theme={theme}; title={title}; category={category}; difficulty={difficulty}."
        )
        request_body: dict[str, Any] = {"model": self.model, "messages": [
            {"role": "system", "content": "You write fictional, sandboxed CTF flavor text only."},
            {"role": "user", "content": prompt},
        ]}
        if not self.model.startswith("gpt-5"):
            request_body["temperature"] = 0.8
        payload = json.dumps(request_body).encode()
        request = urllib.request.Request(f"{self.base_url}/chat/completions", data=payload, headers={
            "Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)["choices"][0]["message"]["content"].strip()

