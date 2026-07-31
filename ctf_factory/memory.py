from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any


SECRET_PATTERN = re.compile(r"flag\{[^}]+\}|sk-[A-Za-z0-9_-]{16,}", re.IGNORECASE)


class ExperienceMemory:
    """Sanitized, append-only experience memory for challenge evolution."""

    def __init__(self, path: Path | str | None = None) -> None:
        configured = path or os.getenv("CTF_MEMORY_DB", ".ctf-agent/memory.sqlite3")
        if configured != ":memory:":
            db_path = Path(configured)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            configured = str(db_path)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(configured, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("""
            CREATE TABLE IF NOT EXISTS experiences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signature TEXT NOT NULL,
                category TEXT NOT NULL,
                challenge_type TEXT NOT NULL,
                difficulty TEXT NOT NULL,
                score INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                lessons_json TEXT NOT NULL,
                mechanics_json TEXT NOT NULL DEFAULT '{}',
                metrics_json TEXT NOT NULL DEFAULT '{}',
                episode_json TEXT NOT NULL DEFAULT '{}',
                parent_signature TEXT NOT NULL DEFAULT '',
                generation INTEGER NOT NULL DEFAULT 0,
                run_id TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        existing = {
            row["name"] for row in self._connection.execute("PRAGMA table_info(experiences)").fetchall()
        }
        migrations = {
            "mechanics_json": "TEXT NOT NULL DEFAULT '{}'",
            "metrics_json": "TEXT NOT NULL DEFAULT '{}'",
            "episode_json": "TEXT NOT NULL DEFAULT '{}'",
            "parent_signature": "TEXT NOT NULL DEFAULT ''",
            "generation": "INTEGER NOT NULL DEFAULT 0",
            "run_id": "TEXT NOT NULL DEFAULT ''",
        }
        for name, declaration in migrations.items():
            if name not in existing:
                self._connection.execute(
                    f"ALTER TABLE experiences ADD COLUMN {name} {declaration}"
                )
        self._connection.commit()

    @staticmethod
    def signature(plan: dict[str, Any]) -> str:
        title_shape = re.sub(r"[^a-z0-9]+", " ", str(plan.get("title", "")).lower()).strip()
        story_shape = " ".join(re.findall(r"[a-z0-9]{4,}", str(plan.get("story", "")).lower())[:24])
        mechanics = json.dumps(plan.get("mechanics", {}), sort_keys=True, separators=(",", ":"))
        value = "|".join([
            str(plan.get("category", "")),
            str(plan.get("challenge_type", "")),
            str(plan.get("difficulty", "")),
            title_shape,
            story_shape,
            mechanics,
        ])
        return hashlib.sha256(value.encode()).hexdigest()

    @staticmethod
    def fingerprint(plan: dict[str, Any]) -> set[str]:
        public = " ".join([
            str(plan.get("title", "")),
            str(plan.get("story", "")),
            " ".join(map(str, plan.get("hints", []))) if isinstance(plan.get("hints"), list) else "",
            json.dumps(plan.get("mechanics", {}), sort_keys=True),
        ]).lower()
        return set(re.findall(r"[a-z0-9_-]{3,}", public))

    @staticmethod
    def _safe_lessons(lessons: list[str]) -> list[str]:
        safe: list[str] = []
        for lesson in lessons[:12]:
            value = SECRET_PATTERN.sub("[REDACTED]", str(lesson))[:160]
            if value:
                safe.append(value)
        return safe

    def remember(self, plan: dict[str, Any], *, score: int, passed: bool,
                 lessons: list[str]) -> None:
        self.remember_episode(
            plan, score=score, passed=passed, lessons=lessons,
            metrics={}, generation=0, run_id="", parent_signature="",
        )

    def remember_episode(
        self,
        plan: dict[str, Any],
        *,
        score: int,
        passed: bool,
        lessons: list[str],
        metrics: dict[str, Any],
        generation: int,
        run_id: str,
        parent_signature: str,
    ) -> None:
        safe_lessons = self._safe_lessons(lessons)
        mechanics = plan.get("mechanics", {}) if isinstance(plan.get("mechanics"), dict) else {}
        safe_metrics = {
            str(key)[:60]: value
            for key, value in metrics.items()
            if isinstance(value, (str, int, float, bool)) or value is None
        }
        episode = {
            "title": SECRET_PATTERN.sub("[REDACTED]", str(plan.get("title", "")))[:120],
            "mechanics": mechanics,
            "fingerprint": sorted(self.fingerprint(plan))[:80],
            "lessons": safe_lessons,
        }
        values = (
            self.signature(plan),
            str(plan.get("category", ""))[:40],
            str(plan.get("challenge_type", ""))[:80],
            str(plan.get("difficulty", ""))[:20],
            max(0, min(100, int(score))),
            int(bool(passed)),
            json.dumps(safe_lessons, ensure_ascii=False),
            json.dumps(mechanics, ensure_ascii=False, sort_keys=True),
            json.dumps(safe_metrics, ensure_ascii=False, sort_keys=True),
            json.dumps(episode, ensure_ascii=False, sort_keys=True),
            str(parent_signature)[:64],
            max(0, min(20, int(generation))),
            str(run_id)[:64],
        )
        with self._lock:
            self._connection.execute("""
                INSERT INTO experiences
                (signature, category, challenge_type, difficulty, score, passed, lessons_json,
                 mechanics_json, metrics_json, episode_json, parent_signature, generation, run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, values)
            self._connection.commit()

    def novelty_score(self, plan: dict[str, Any]) -> int:
        signature = self.signature(plan)
        current = self.fingerprint(plan)
        with self._lock:
            duplicate = self._connection.execute(
                "SELECT COUNT(*) FROM experiences WHERE signature = ?", (signature,)
            ).fetchone()[0]
            rows = self._connection.execute(
                """SELECT episode_json FROM experiences
                   WHERE category = ? AND challenge_type = ?
                   ORDER BY id DESC LIMIT 50""",
                (str(plan.get("category", "")), str(plan.get("challenge_type", ""))),
            ).fetchall()
        similarities: list[float] = []
        for row in rows:
            episode = json.loads(row["episode_json"] or "{}")
            previous = set(episode.get("fingerprint", []))
            union = current | previous
            similarities.append(len(current & previous) / len(union) if union else 0.0)
        similarity_penalty = round(max(similarities, default=0.0) * 65)
        reuse_penalty = min(len(rows), 12) * 2
        return max(0, 100 - duplicate * 35 - similarity_penalty - reuse_penalty)

    def retrieve(
        self,
        category: str,
        challenge_type: str,
        difficulty: str = "",
        *,
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        clauses = ["category = ?", "challenge_type = ?"]
        values: list[Any] = [category, challenge_type]
        if difficulty:
            clauses.append("difficulty = ?")
            values.append(difficulty)
        values.append(max(1, min(limit, 20)))
        with self._lock:
            rows = self._connection.execute(f"""
                SELECT signature, score, passed, lessons_json, mechanics_json, metrics_json,
                       parent_signature, generation, run_id, created_at
                FROM experiences WHERE {' AND '.join(clauses)}
                ORDER BY passed DESC, score DESC, id DESC LIMIT ?
            """, values).fetchall()
        return [{
            "signature": row["signature"],
            "score": int(row["score"]),
            "passed": bool(row["passed"]),
            "lessons": json.loads(row["lessons_json"] or "[]"),
            "mechanics": json.loads(row["mechanics_json"] or "{}"),
            "metrics": json.loads(row["metrics_json"] or "{}"),
            "parent_signature": row["parent_signature"],
            "generation": int(row["generation"]),
            "run_id": row["run_id"],
            "created_at": row["created_at"],
        } for row in rows]

    def lessons_for(self, category: str, challenge_type: str, *, limit: int = 8) -> list[str]:
        rows = self.retrieve(category, challenge_type, limit=max(1, min(limit, 20)))
        lessons: list[str] = []
        for row in rows:
            for lesson in row["lessons"]:
                if lesson not in lessons:
                    lessons.append(lesson)
        return lessons[:limit]

    def stats(self) -> dict[str, int]:
        with self._lock:
            row = self._connection.execute("""
                SELECT COUNT(*) AS total,
                       COALESCE(SUM(passed), 0) AS passed,
                       COUNT(DISTINCT signature) AS patterns
                FROM experiences
            """).fetchone()
        return {"experiences": int(row["total"]), "passed": int(row["passed"]),
                "patterns": int(row["patterns"])}

    def close(self) -> None:
        with self._lock:
            self._connection.close()
