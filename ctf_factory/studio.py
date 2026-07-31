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
from .evolution import EvolutionEngine
from .execution import ExecutableChallengeEvaluator
from .llm import CompatibleLLM
from .memory import ExperienceMemory
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

        def published_port(value: int) -> int:
            published = self._run(bundle, "port", str(runtime.get("service", "challenge")),
                                  str(value), timeout=20).stdout.strip()
            match = re.search(r":(\d+)\s*$", published)
            if not match:
                raise RuntimeError("Docker is running but no local challenge port was published")
            return int(match.group(1))

        host, port = "127.0.0.1", published_port(container_port)
        protocol = str(runtime.get("protocol", "tcp"))
        ui_container_port = int(runtime.get("ui_port", 0))
        ui_port = published_port(ui_container_port) if ui_container_port else None
        url_port = ui_port or port
        url = f"http://{host}:{url_port}" if protocol in {
            "http", "json-rpc", "download", "adb",
        } or ui_port else None
        client = str(runtime.get("client", "")).format(host=host, port=port, url=url or "")
        launch_url = client if protocol == "http" and client.startswith(("http://", "https://")) else url
        return {"running": True, "protocol": protocol, "host": host, "port": int(port),
                "ui_port": ui_port, "url": url, "launch_url": launch_url, "command": client}

    def start(self, slug: str) -> dict[str, Any]:
        bundle = self._bundle(slug)
        with INSTANCE_LOCK:
            self._run(bundle, "up", "-d", "--build")
            state = self.status(slug)
            deadline = time.monotonic() + 10
            while state.get("running") and time.monotonic() < deadline:
                try:
                    ready_port = int(state.get("ui_port") or state["port"])
                    with socket.create_connection((str(state["host"]), ready_port), timeout=1):
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


def _normalize_plan(plan: dict[str, Any], *, difficulty: str) -> dict[str, Any]:
    key = (str(plan.get("category", "")), str(plan.get("challenge_type", "")))
    if key not in TEMPLATES:
        raise ValueError("AI selected a primitive outside the reviewed allow-list")
    plan["category"], plan["challenge_type"] = key
    plan["difficulty"] = plan.get("difficulty") if plan.get("difficulty") in DIFFICULTIES else difficulty
    plan["title"] = str(plan.get("title", TEMPLATES[key].title))[:120]
    plan["story"] = str(plan.get("story", ""))[:600]
    hints = plan.get("hints", [])
    plan["hints"] = [str(x)[:160] for x in hints[:3]] if isinstance(hints, list) else []
    plan["designer_notes"] = str(plan.get("designer_notes", ""))[:500]
    return plan


def create_plan(payload: dict[str, Any], llm: CompatibleLLM,
                memory: ExperienceMemory | None = None) -> dict[str, Any]:
    brief = str(payload.get("brief", ""))[:2000]
    category = str(payload.get("category", ""))
    challenge_type = str(payload.get("challenge_type", ""))
    difficulty = str(payload.get("difficulty", "medium"))
    owned_memory = memory is None
    memory = memory or ExperienceMemory(":memory:")
    lessons = memory.lessons_for(category, challenge_type)
    styles = (
        ("", "Investigate the primary trust boundary."),
        (" / Shadow State", "Trace how state changes across the system boundary."),
        (" / Fault Line", "Correlate conflicting evidence before exploiting the weakness."),
        (" / Echo Path", "Separate decoy behavior from the vulnerable data flow."),
        (" / Cold Start", "Reconstruct the system assumptions from minimal evidence."),
    )
    mechanic_profiles = (
        {"encoding_delta": 0, "decoy_density": 0, "reasoning_depth": 1,
         "mutation_tag": "seed-direct"},
        {"encoding_delta": 0, "decoy_density": 1, "reasoning_depth": 2,
         "mutation_tag": "seed-decoy"},
        {"encoding_delta": 1 if difficulty != "easy" else 0, "decoy_density": 2,
         "reasoning_depth": 3, "mutation_tag": "seed-layered"},
        {"encoding_delta": 0, "decoy_density": 3, "reasoning_depth": 3,
         "mutation_tag": "seed-noisy"},
        {"encoding_delta": 1 if difficulty == "hard" else 0, "decoy_density": 1,
         "reasoning_depth": 4, "mutation_tag": "seed-deep"},
    )

    def candidate_factory(index: int, past_lessons: list[str]) -> dict[str, Any]:
        try:
            plan = llm.design_challenge(
                brief=brief, templates=_templates(), category=category,
                challenge_type=challenge_type, difficulty=difficulty,
                experience_lessons=past_lessons, candidate_index=index,
            )
        except (OSError, ValueError, KeyError, json.JSONDecodeError, TypeError):
            plan = None
        if plan is None:
            plan = _offline_plan(brief, category, challenge_type, difficulty)
            suffix, perspective = styles[index % len(styles)]
            plan["title"] = (str(plan["title"]) + suffix)[:120]
            plan["story"] = (str(plan["story"]) + " " + perspective)[:600]
            plan["designer_notes"] = (
                f"Generator candidate {index + 1}; reviewed against Solver, Breaker, "
                "Judge, and sanitized experience memory."
            )
            plan["brain"] = "offline"
        else:
            plan["brain"] = getattr(llm, "model", "configured-model")
        supplied_mechanics = plan.get("mechanics")
        plan["mechanics"] = {
            **mechanic_profiles[index % len(mechanic_profiles)],
            **(supplied_mechanics if isinstance(supplied_mechanics, dict) else {}),
        }
        return _normalize_plan(plan, difficulty=difficulty)

    try:
        evaluator = ExecutableChallengeEvaluator(llm)
        return EvolutionEngine(memory).evolve(
            candidate_factory,
            allowed=set(TEMPLATES),
            count=int(payload.get("evolution_candidates", 3)),
            experience_lessons=lessons,
            executable_evaluator=lambda candidate, index, generation: evaluator.evaluate(
                candidate, candidate_index=index, generation=generation
            ),
            generations=int(payload.get("evolution_generations", 2)),
        )
    finally:
        if owned_memory:
            memory.close()


def record_experience(bundle: Path, plan: dict[str, Any], reports: list[Any],
                      memory: ExperienceMemory) -> tuple[dict[str, Any], dict[str, int]]:
    evolution = plan.get("evolution") if isinstance(plan.get("evolution"), dict) else {}
    review = evolution.get("winner_review", {}) if isinstance(evolution, dict) else {}
    candidate_risks = [
        str(risk)
        for candidate in evolution.get("candidates", [])
        if isinstance(candidate, dict)
        for risk in candidate.get("risks", [])
    ]
    lessons = candidate_risks + list(review.get("risks", [])) + list(review.get("evidence", []))
    memory.remember(
        plan, score=int(evolution.get("winner_score", 100)),
        passed=all(report.passed for report in reports), lessons=lessons,
    )
    stats = memory.stats()
    quality_path = bundle / "quality.json"
    quality = json.loads(quality_path.read_text(encoding="utf-8"))
    quality["version"] = "0.8"
    quality["score"] = int(evolution.get("winner_score", quality.get("score", 0)))
    quality["dimensions"] = dict(review.get("dimensions", quality.get("dimensions", {})))
    quality["passed"] = bool(review.get("passed")) and all(report.passed for report in reports)
    quality["evidence"] = list(review.get("evidence", quality.get("evidence", [])))
    quality["risks"] = list(review.get("risks", []))
    quality["adversarial_evolution"] = evolution
    quality["experience_memory"] = stats
    quality_path.write_text(json.dumps(quality, indent=2), encoding="utf-8")
    return evolution, stats


class StudioHandler(BaseHTTPRequestHandler):
    llm = CompatibleLLM()
    output = Path("generated")
    memory = ExperienceMemory()

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
                             "brain": {"configured": self.llm.configured, "model": self.llm.model},
                             "memory": self.memory.stats(),
                             "agents": ["Generator", "Solver", "Breaker", "Judge"]}); return
        name = "index.html" if self.path in ("/", "/index.html") else self.path.lstrip("/")
        if name not in {"index.html", "app.js", "style.css", "knowledge.css", "instance.css",
                        "evaluation.css"}:
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
                self._json(200, create_plan(payload, self.llm, self.memory)); return
            if self.path == "/api/generate":
                plan = payload.get("plan")
                if not isinstance(plan, dict): raise ValueError("validated plan required")
                category, challenge_type = str(plan.get("category", "")), str(plan.get("challenge_type", ""))
                if (category, challenge_type) not in TEMPLATES: raise ValueError("unknown template")
                difficulty = str(plan.get("difficulty", ""))
                if difficulty not in DIFFICULTIES: raise ValueError("invalid difficulty")
                variant = str(payload.get("variant", "studio"))
                if not re.fullmatch(r"[a-z0-9-]{1,32}", variant): raise ValueError("invalid variant")
                try:
                    bundle, reports = ChallengeFactory(self.llm).generate(
                        category=category, challenge_type=challenge_type, difficulty=difficulty,
                        theme=str(payload.get("brief", "Studio design")), output=self.output,
                        variant=variant, seed=str(payload.get("seed")) if payload.get("seed") else None,
                        design=plan)
                except Exception as exc:
                    evolution = plan.get("evolution", {})
                    self.memory.remember(
                        plan, score=int(evolution.get("winner_score", 0)),
                        passed=False, lessons=[f"Build gate failure: {type(exc).__name__}"],
                    )
                    raise
                archive = export_player_bundle(bundle, Path("exports"))
                public = json.loads((bundle / "challenge.json").read_text(encoding="utf-8"))
                runtime = json.loads((bundle / "runtime.json").read_text(encoding="utf-8"))
                evolution, memory_stats = record_experience(bundle, plan, reports, self.memory)
                self._json(201, {
                    "bundle": str(bundle.resolve()), "archive": str(archive.resolve()),
                    "challenge": public, "category_info": CATEGORY_INFO[category],
                    "gates": [r.__dict__ for r in reports],
                    "launch": runtime.get("client", "Download player bundle"),
                    "runtime": runtime,
                    "evolution": evolution,
                    "memory": memory_stats,
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
