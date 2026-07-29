from __future__ import annotations

import json
import os
import urllib.request


class CompatibleLLM:
    """Optional copywriter: templates retain control of all security properties."""

    def __init__(self) -> None:
        self.base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self.api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.model = os.getenv("LLM_MODEL", "gpt-4.1-mini")

    def rewrite_story(self, *, theme: str, title: str, category: str, difficulty: str) -> str | None:
        if not self.api_key:
            return None
        prompt = (
            "Write one short CTF challenge story, maximum 45 words. Do not include solutions, "
            "flags, URLs, real targets, or credentials. "
            f"Theme={theme}; title={title}; category={category}; difficulty={difficulty}."
        )
        payload = json.dumps({"model": self.model, "temperature": 0.8, "messages": [
            {"role": "system", "content": "You write fictional, sandboxed CTF flavor text only."},
            {"role": "user", "content": prompt},
        ]}).encode()
        request = urllib.request.Request(f"{self.base_url}/chat/completions", data=payload, headers={
            "Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)["choices"][0]["message"]["content"].strip()

