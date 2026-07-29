from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .catalog import TEMPLATES
from .llm import CompatibleLLM
from .models import DIFFICULTIES
from .orchestrator import ChallengeFactory


STATIC_ROOT = Path(__file__).with_name("studio_static")
MAX_BODY = 64 * 1024


def _templates() -> list[dict[str, str]]:
    return [{"category": c, "challenge_type": t, "title": info.title,
             "vulnerability": info.vulnerability, "delivery": info.delivery}
            for (c, t), info in TEMPLATES.items()]


def _offline_plan(brief: str, category: str, challenge_type: str, difficulty: str) -> dict[str, Any]:
    lowered = brief.lower()
    keywords = {"rsa": ("crypto", "weak-rsa"), "日志": ("forensics", "log-fragments"),
                "log": ("forensics", "log-fragments"), "rag": ("ai-ml", "rag-poisoning"),
                "prompt": ("ai-ml", "prompt-injection"), "sql": ("web", "query-injection"),
                "session": ("web", "weak-session"), "会话": ("web", "weak-session")}
    selected = next((value for key, value in keywords.items() if key in lowered), None)
    if category and challenge_type and (category, challenge_type) in TEMPLATES:
        selected = (category, challenge_type)
    elif category:
        selected = next((key for key in TEMPLATES if key[0] == category), selected)
    selected = selected or ("web", "weak-session")
    info = TEMPLATES[selected]
    theme = brief.strip()[:180] or "Local cyber range"
    return {"category": selected[0], "challenge_type": selected[1],
            "difficulty": difficulty if difficulty in DIFFICULTIES else "medium",
            "title": info.title, "story": f"{theme}：调查一处隔离训练环境中的异常，并找出隐藏证据。",
            "hints": list(info.hints[:2]), "designer_notes": "离线规划：已匹配最接近的审核模板。",
            "brain": "offline"}


def create_plan(payload: dict[str, Any], llm: CompatibleLLM) -> dict[str, Any]:
    brief = str(payload.get("brief", ""))[:2000]
    category = str(payload.get("category", ""))
    challenge_type = str(payload.get("challenge_type", ""))
    difficulty = str(payload.get("difficulty", "medium"))
    try:
        plan = llm.design_challenge(brief=brief, templates=_templates(), category=category,
                                    challenge_type=challenge_type, difficulty=difficulty)
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        plan = None
    if plan is None:
        return _offline_plan(brief, category, challenge_type, difficulty)
    key = (str(plan.get("category", "")), str(plan.get("challenge_type", "")))
    if key not in TEMPLATES:
        raise ValueError("AI selected a template outside the reviewed allow-list")
    plan["category"], plan["challenge_type"] = key
    plan["difficulty"] = plan.get("difficulty") if plan.get("difficulty") in DIFFICULTIES else difficulty
    plan["title"] = str(plan.get("title", TEMPLATES[key].title))[:120]
    plan["story"] = str(plan.get("story", ""))[:600]
    hints = plan.get("hints", [])
    plan["hints"] = [str(x)[:160] for x in hints[:3]] if isinstance(hints, list) else []
    plan["designer_notes"] = str(plan.get("designer_notes", ""))[:500]
    plan["brain"] = llm.model
    return plan


class StudioHandler(BaseHTTPRequestHandler):
    llm = CompatibleLLM()
    output = Path("generated")

    def _json(self, status: int, value: Any) -> None:
        data = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:")
        self.end_headers(); self.wfile.write(data)

    def _payload(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > MAX_BODY:
            raise ValueError("request body must be between 1 byte and 64 KiB")
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def do_GET(self) -> None:
        if not self._local_request(): return
        if self.path == "/api/bootstrap":
            self._json(200, {"templates": _templates(), "difficulties": DIFFICULTIES,
                             "brain": {"configured": self.llm.configured, "model": self.llm.model}}); return
        name = "index.html" if self.path in ("/", "/index.html") else self.path.lstrip("/")
        if name not in {"index.html", "app.js", "style.css"}:
            self.send_error(404); return
        path = STATIC_ROOT / name
        data = path.read_bytes(); content_type = {".html": "text/html", ".js": "text/javascript", ".css": "text/css"}[path.suffix]
        self.send_response(200); self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def do_POST(self) -> None:
        if not self._local_request(): return
        try:
            payload = self._payload()
            if self.path == "/api/plan":
                self._json(200, create_plan(payload, self.llm)); return
            if self.path == "/api/generate":
                plan = payload.get("plan")
                if not isinstance(plan, dict): raise ValueError("validated plan required")
                category, challenge_type = str(plan.get("category", "")), str(plan.get("challenge_type", ""))
                if (category, challenge_type) not in TEMPLATES: raise ValueError("unknown template")
                difficulty = str(plan.get("difficulty", ""))
                if difficulty not in DIFFICULTIES: raise ValueError("invalid difficulty")
                variant = str(payload.get("variant", "studio"))
                if not re.fullmatch(r"[a-z0-9-]{1,32}", variant): raise ValueError("invalid variant")
                bundle, reports = ChallengeFactory(self.llm).generate(
                    category=category, challenge_type=challenge_type, difficulty=difficulty,
                    theme=str(payload.get("brief", "Studio design")), output=self.output,
                    variant=variant, seed=str(payload.get("seed")) if payload.get("seed") else None,
                    design=plan)
                self._json(201, {"bundle": str(bundle.resolve()), "gates": [r.__dict__ for r in reports]}); return
            self._json(404, {"error": "not found"})
        except Exception as exc:
            self._json(400, {"error": str(exc)})

    def _local_request(self) -> bool:
        host = self.headers.get("Host", "").split(":", 1)[0]
        origin = self.headers.get("Origin", "")
        if host not in {"127.0.0.1", "localhost"} or (origin and not re.match(r"^http://(127\.0\.0\.1|localhost)(:\d+)?$", origin)):
            self._json(403, {"error": "local Studio requests only"}); return False
        return True

    def log_message(self, format: str, *args: object) -> None:
        print("[studio]", format % args)


def serve_studio(*, host: str = "127.0.0.1", port: int = 8787) -> None:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("Studio binds to localhost only")
    print(f"CTF Studio: http://{host}:{port}")
    ThreadingHTTPServer((host, port), StudioHandler).serve_forever()
