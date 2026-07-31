from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .catalog import CATEGORY_INFO, TEMPLATES, runtime_delivery
from .llm import CompatibleLLM
from .models import DIFFICULTIES
from .orchestrator import ChallengeFactory
from .operations import export_player_bundle


STATIC_ROOT = Path(__file__).with_name("studio_static")
MAX_BODY = 64 * 1024
INSTANCE_LOCK = threading.Lock()


class DockerInstanceManager:
    """Manage only reviewed Web bundles under the configured generated root."""

    def __init__(self, output: Path) -> None:
        self.output = output.resolve()

    def _bundle(self, slug: str) -> Path:
        if not re.fullmatch(r"[a-z0-9-]{1,96}", slug):
            raise ValueError("invalid challenge id")
        bundle = (self.output / slug).resolve()
        try:
            bundle.relative_to(self.output)
        except ValueError as exc:
            raise ValueError("challenge is outside the generated root") from exc
        metadata_path = bundle / "challenge.json"
        compose_path = bundle / "docker-compose.yml"
        runtime_path = bundle / "runtime.json"
        if not metadata_path.is_file() or not compose_path.is_file() or not runtime_path.is_file():
            raise ValueError("generated service challenge not found")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        if metadata.get("slug") != slug or runtime.get("kind") != "docker":
            raise ValueError("challenge is not an approved Docker bundle")
        return bundle

    @staticmethod
    def _run(bundle: Path, *args: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
        if shutil.which("docker") is None:
            raise RuntimeError("Docker CLI is not installed or not available on PATH")
        try:
            result = subprocess.run(
                ["docker", "compose", *args],
                cwd=bundle,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Docker operation timed out") from exc
        if result.returncode:
            detail = (result.stderr or result.stdout or "Docker operation failed").strip()
            raise RuntimeError(detail[-2000:])
        return result

    def status(self, slug: str) -> dict[str, Any]:
        bundle = self._bundle(slug)
        runtime = json.loads((bundle / "runtime.json").read_text(encoding="utf-8"))
        running = self._run(bundle, "ps", "--status", "running", "--services", timeout=20)
        if "challenge" not in running.stdout.split():
            return {"running": False, "url": None, "command": None}
        container_port = int(runtime["container_port"])
        published = self._run(bundle, "port", str(runtime.get("service", "challenge")),
                              str(container_port), timeout=20).stdout.strip()
        match = re.search(r":(\d+)\s*$", published)
        if not match:
            raise RuntimeError("Docker is running but no local challenge port was published")
        host, port = "127.0.0.1", match.group(1)
        protocol = str(runtime.get("protocol", "tcp"))
        url = f"http://{host}:{port}" if protocol in {"http", "json-rpc"} else None
        client = str(runtime.get("client", "")).format(host=host, port=port, url=url or "")
        return {"running": True, "protocol": protocol, "host": host, "port": int(port),
                "url": url, "command": client}

    def start(self, slug: str) -> dict[str, Any]:
        bundle = self._bundle(slug)
        with INSTANCE_LOCK:
            self._run(bundle, "up", "-d", "--build")
            state = self.status(slug)
            deadline = time.monotonic() + 10
            while state.get("running") and time.monotonic() < deadline:
                try:
                    with socket.create_connection((str(state["host"]), int(state["port"])), timeout=1):
                        # Docker Desktop may accept the first forwarded connection just
                        # before the container service is ready to answer it.
                        time.sleep(0.5)
                        return state
                except OSError:
                    time.sleep(0.2)
                    state = self.status(slug)
            raise RuntimeError("Docker started, but the challenge service did not become ready")

    def stop(self, slug: str) -> dict[str, Any]:
        bundle = self._bundle(slug)
        with INSTANCE_LOCK:
            self._run(bundle, "down", "--remove-orphans", timeout=60)
        return {"running": False, "url": None, "command": None}


def _templates() -> list[dict[str, str]]:
    return [{"category": c, "challenge_type": t, "title": info.title,
             "vulnerability": info.vulnerability,
             "delivery": runtime_delivery(c, info.delivery),
             "category_name": CATEGORY_INFO[c]["name"]}
            for (c, t), info in TEMPLATES.items()]


def _offline_plan(brief: str, category: str, challenge_type: str, difficulty: str) -> dict[str, Any]:
    lowered = brief.lower()
    keywords = {"rsa": ("crypto", "weak-rsa"), "日志": ("forensics", "log-fragments"),
                "log": ("forensics", "log-fragments"), "rag": ("ai-ml", "rag-poisoning"),
                "prompt": ("ai-ml", "prompt-injection"), "sql": ("web", "query-injection"),
                "session": ("web", "weak-session"), "会话": ("web", "weak-session"),
                "逆向": ("reverse", "bytecode-vm"), "reverse": ("reverse", "xor-strings"),
                "pwn": ("pwn", "stack-overflow-sim"), "溢出": ("pwn", "stack-overflow-sim"),
                "隐写": ("misc", "ppm-lsb"), "stego": ("misc", "ppm-lsb"),
                "区块链": ("blockchain", "storage-slots"), "web3": ("blockchain", "event-log"),
                "固件": ("iot", "firmware-strings"), "iot": ("iot", "mqtt-retain")}
    selected = next((value for key, value in keywords.items() if key in lowered), None)
    if category and challenge_type and (category, challenge_type) in TEMPLATES:
        selected = (category, challenge_type)
    elif category:
        selected = next((key for key in TEMPLATES if key[0] == category), selected)
    selected = selected or ("web", "weak-session")
    info = TEMPLATES[selected]
    theme = (brief.strip()[:180] or "Local cyber range").rstrip(".:;!? ")
    return {"category": selected[0], "challenge_type": selected[1],
            "difficulty": difficulty if difficulty in DIFFICULTIES else "medium",
            "title": info.title, "story": f"{theme}: Investigate an anomaly in an isolated training environment and recover the hidden evidence.",
            "hints": list(info.hints), "designer_notes": "Offline planner: matched the closest reviewed template.",
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
                             "categories": [{"id": key, **value} for key, value in CATEGORY_INFO.items()],
                             "brain": {"configured": self.llm.configured, "model": self.llm.model}}); return
        name = "index.html" if self.path in ("/", "/index.html") else self.path.lstrip("/")
        if name not in {"index.html", "app.js", "style.css", "knowledge.css", "instance.css"}:
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
                archive = export_player_bundle(bundle, Path("exports"))
                public = json.loads((bundle / "challenge.json").read_text(encoding="utf-8"))
                runtime = json.loads((bundle / "runtime.json").read_text(encoding="utf-8"))
                self._json(201, {
                    "bundle": str(bundle.resolve()), "archive": str(archive.resolve()),
                    "challenge": public, "category_info": CATEGORY_INFO[category],
                    "gates": [r.__dict__ for r in reports],
                    "launch": runtime.get("client", "Download player bundle"),
                    "runtime": runtime,
                    "instance_id": public["slug"] if runtime.get("kind") == "docker" else None,
                }); return
            if self.path in {"/api/instance/start", "/api/instance/status", "/api/instance/stop"}:
                slug = str(payload.get("instance_id", ""))
                manager = DockerInstanceManager(self.output)
                if self.path.endswith("/start"):
                    self._json(200, manager.start(slug)); return
                if self.path.endswith("/stop"):
                    self._json(200, manager.stop(slug)); return
                self._json(200, manager.status(slug)); return
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
