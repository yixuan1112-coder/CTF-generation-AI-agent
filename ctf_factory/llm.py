from __future__ import annotations

import json
import os
import urllib.request
from typing import Any


SYSTEM_PROMPT = """You design legal, sandboxed CTF training challenges.
Return only one JSON object. Never target real systems, third parties, credentials,
malware persistence, phishing, or data theft. The challenge must be reproducible,
have exactly one intended vulnerability, and be solvable inside its own container.
Required keys: slug, title, category, difficulty, story, vulnerability,
intended_solution (array), hints (array), port. Supported category: web.
Supported vulnerability: path-normalization.
"""


class CompatibleLLM:
    """Small OpenAI-compatible client with an explicit offline fallback."""

    def __init__(self) -> None:
        self.base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self.api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.model = os.getenv("LLM_MODEL", "gpt-4.1-mini")

    def generate(self, brief: str) -> dict[str, Any]:
        if not self.api_key:
            return offline_spec(brief)
        payload = json.dumps({
            "model": self.model,
            "temperature": 0.8,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": brief},
            ],
        }).encode()
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=payload,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            result = json.load(response)
        return json.loads(result["choices"][0]["message"]["content"])


def offline_spec(brief: str) -> dict[str, Any]:
    theme = brief.strip()[:80] or "archive recovery"
    return {
        "slug": "double-decode-archive",
        "title": "The Archivist's Second Look",
        "category": "web",
        "difficulty": "easy",
        "story": f"{theme}: retrieve the protected archive note from a local training service.",
        "vulnerability": "path-normalization",
        "intended_solution": [
            "Notice that the route validates a path after one URL decode.",
            "Send a double-encoded traversal segment so the second decode changes its meaning.",
            "Read /srv/secret/flag.txt from inside the challenge container.",
        ],
        "hints": ["How many times is the path decoded?", "Percent signs can be encoded too."],
        "port": 8000,
    }

