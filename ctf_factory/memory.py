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
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self._connection.commit()

    @staticmethod
    def signature(plan: dict[str, Any]) -> str:
        title_shape = re.sub(r"[^a-z0-9]+", " ", str(plan.get("title", "")).lower()).strip()
        value = "|".join([
            str(plan.get("category", "")),
            str(plan.get("challenge_type", "")),
            str(plan.get("difficulty", "")),
            title_shape,
        ])
        return hashlib.sha256(value.encode()).hexdigest()

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
        values = (
            self.signature(plan),
            str(plan.get("category", ""))[:40],
            str(plan.get("challenge_type", ""))[:80],
            str(plan.get("difficulty", ""))[:20],
            max(0, min(100, int(score))),
            int(bool(passed)),
            json.dumps(self._safe_lessons(lessons), ensure_ascii=False),
        )
        with self._lock:
            self._connection.execute("""
                INSERT INTO experiences
                (signature, category, challenge_type, difficulty, score, passed, lessons_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, values)
            self._connection.commit()

    def novelty_score(self, plan: dict[str, Any]) -> int:
        signature = self.signature(plan)
        with self._lock:
            duplicate = self._connection.execute(
                "SELECT COUNT(*) FROM experiences WHERE signature = ?", (signature,)
            ).fetchone()[0]
            reused = self._connection.execute(
                "SELECT COUNT(*) FROM experiences WHERE category = ? AND challenge_type = ?",
                (str(plan.get("category", "")), str(plan.get("challenge_type", ""))),
            ).fetchone()[0]
        return max(0, 100 - duplicate * 45 - min(reused, 10) * 4)

    def lessons_for(self, category: str, challenge_type: str, *, limit: int = 8) -> list[str]:
        with self._lock:
            rows = self._connection.execute("""
                SELECT lessons_json FROM experiences
                WHERE category = ? AND challenge_type = ?
                ORDER BY id DESC LIMIT ?
            """, (category, challenge_type, max(1, min(limit, 20)))).fetchall()
        lessons: list[str] = []
        for row in rows:
            for lesson in json.loads(row["lessons_json"]):
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
