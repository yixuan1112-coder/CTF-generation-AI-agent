"""SQLite persistence for the arena.

Everything a real contest has to survive a restart lives here: teams and their
tokens, submitted agents, every match ever run, and the full event log of each
match so a run can be replayed long after it finished.

One connection per thread (SQLite objects are not shareable across threads), with
WAL enabled so the HTTP threads can read while a match worker writes.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

DEFAULT_DB = Path(".arena/arena.sqlite3")

SCHEMA = """
CREATE TABLE IF NOT EXISTS teams (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    token       TEXT NOT NULL,
    contact     TEXT DEFAULT '',
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id           TEXT PRIMARY KEY,
    team_id      TEXT NOT NULL REFERENCES teams(id),
    name         TEXT NOT NULL,
    kind         TEXT NOT NULL,              -- 'upload' | 'remote' | 'image'
    entry        TEXT DEFAULT 'agent.py',
    source_dir   TEXT DEFAULT '',            -- upload: where the code was unpacked
    remote_url   TEXT DEFAULT '',            -- remote: endpoint the server calls
    remote_token TEXT DEFAULT '',
    image_ref    TEXT DEFAULT '',            -- image: arena-owned tag on this host
    sha256       TEXT DEFAULT '',
    size_bytes   INTEGER DEFAULT 0,
    notes        TEXT DEFAULT '',
    created_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS matches (
    id             TEXT PRIMARY KEY,
    team_id        TEXT NOT NULL REFERENCES teams(id),
    agent_id       TEXT NOT NULL REFERENCES agents(id),
    track          TEXT NOT NULL,
    seed           INTEGER NOT NULL,
    status         TEXT NOT NULL,            -- queued | running | done | error | cancelled
    reached_gen    INTEGER DEFAULT -1,       -- deepest rung the agent actually SOLVED
    agent_gen      INTEGER DEFAULT 0,        -- where the challenge-maker ended up
    max_gen        INTEGER DEFAULT 0,
    score          INTEGER DEFAULT 0,
    solve_seconds  REAL DEFAULT 0.0,         -- agent CPU-wall time across solved rungs
    outcome        TEXT DEFAULT '',          -- human summary
    error          TEXT DEFAULT '',
    created_at     REAL NOT NULL,
    started_at     REAL,
    finished_at    REAL
);

CREATE TABLE IF NOT EXISTS match_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    match_id  TEXT NOT NULL REFERENCES matches(id),
    seq       INTEGER NOT NULL,
    ts        REAL NOT NULL,
    evt       TEXT NOT NULL,
    payload   TEXT NOT NULL
);

-- Challenges the maker AUTHORED during a match, kept after the match ends.
--
-- Composed challenges only exist because a team pushed the maker past every
-- bounded rung; without this table they were built, deployed, solved or not, and
-- thrown away when the Competition object was collected. Rows are player-safe by
-- construction: `files` holds exactly what the agent was handed, and the flag is
-- stored only as a hash so a submission can be checked without the answer being
-- in the database.
CREATE TABLE IF NOT EXISTS library (
    id            TEXT PRIMARY KEY,
    created_at    REAL NOT NULL,
    match_id      TEXT,                       -- provenance; NULL once the match is pruned
    team_name     TEXT DEFAULT '',            -- who pushed the maker this far
    track         TEXT NOT NULL,
    generation    INTEGER NOT NULL,
    attack_class  TEXT NOT NULL,
    title         TEXT NOT NULL,
    story         TEXT DEFAULT '',
    hints         TEXT DEFAULT '[]',          -- json
    stages        TEXT DEFAULT '[]',          -- json: the chained attack classes
    depth         INTEGER DEFAULT 0,
    rank          INTEGER DEFAULT 0,
    plan_source   TEXT DEFAULT 'catalog',     -- catalog | llm
    designer_note TEXT DEFAULT '',
    files         TEXT NOT NULL,              -- json: player artifacts, name -> content
    flag_sha256   TEXT NOT NULL,              -- 64-bit flag; the answer is not stored
    solved_in_match INTEGER DEFAULT 0,
    solve_count   INTEGER DEFAULT 0,
    origin        TEXT DEFAULT 'match'        -- 'match' (authored live) | 'practice' (curated)
);

CREATE INDEX IF NOT EXISTS idx_events_match ON match_events(match_id, seq);
CREATE INDEX IF NOT EXISTS idx_matches_team ON matches(team_id, status);
CREATE INDEX IF NOT EXISTS idx_matches_board ON matches(track, status, reached_gen);
CREATE INDEX IF NOT EXISTS idx_library_recent ON library(created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_library_dedup ON library(flag_sha256);
"""


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


class Store:
    def __init__(self, path: Path | str = DEFAULT_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        with self.conn() as c:
            c.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Add columns that arrived after a live arena was already running.

        CREATE TABLE IF NOT EXISTS silently keeps the OLD shape of a table that
        already exists, so a schema edit alone does nothing to a deployed
        database — the first query naming the new column raises OperationalError
        instead. Every added column needs a line here.
        """
        c = self.conn()
        have = {r["name"] for r in c.execute("PRAGMA table_info(agents)")}
        for column, ddl in (("image_ref", "TEXT DEFAULT ''"),):
            if column not in have:
                with self._write_lock:
                    c.execute(f"ALTER TABLE agents ADD COLUMN {column} {ddl}")
        lib = {r["name"] for r in c.execute("PRAGMA table_info(library)")}
        for column, ddl in (("origin", "TEXT DEFAULT 'match'"),):
            if column not in lib:
                with self._write_lock:
                    c.execute(f"ALTER TABLE library ADD COLUMN {column} {ddl}")

    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA busy_timeout=30000")
            self._local.conn = c
        return c

    # ---- practice ----------------------------------------------------------
    def practice_secret(self) -> str:
        """A per-server secret that seasons every practice flag.

        Persisted beside the database (inside the backed-up data dir) and created
        once. It is what lets the practice SEED be a public constant while the
        flags stay underivable from this public repo — a fresh server gets fresh
        practice flags, and they survive restarts. `ARENA_PRACTICE_SECRET`
        overrides it when an operator wants to pin the value explicitly.
        """
        import os
        override = os.environ.get("ARENA_PRACTICE_SECRET")
        if override:
            return override
        secret_file = self.path.with_name("practice_secret")
        try:
            existing = secret_file.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        except FileNotFoundError:
            pass
        value = secrets.token_hex(16)
        secret_file.write_text(value, encoding="utf-8")
        try:
            secret_file.chmod(0o600)
        except OSError:
            pass
        return value

    # ---- teams -------------------------------------------------------------
    def create_team(self, name: str, contact: str = "") -> dict[str, Any]:
        name = (name or "").strip()
        if not (2 <= len(name) <= 48):
            raise ValueError("team name must be 2-48 characters")
        row = self.conn().execute("SELECT id FROM teams WHERE name = ?", (name,)).fetchone()
        if row:
            raise ValueError(f"team name {name!r} is already taken")
        team = {"id": new_id("team"), "name": name, "token": secrets.token_urlsafe(24),
                "contact": (contact or "").strip()[:200], "created_at": time.time()}
        with self._write_lock:
            self.conn().execute(
                "INSERT INTO teams (id,name,token,contact,created_at) VALUES (?,?,?,?,?)",
                (team["id"], team["name"], team["token"], team["contact"], team["created_at"]))
        return team

    def team_by_token(self, token: str) -> dict | None:
        if not token:
            return None
        r = self.conn().execute("SELECT * FROM teams WHERE token = ?", (token,)).fetchone()
        return dict(r) if r else None

    def team(self, team_id: str) -> dict | None:
        r = self.conn().execute("SELECT * FROM teams WHERE id = ?", (team_id,)).fetchone()
        return dict(r) if r else None

    # ---- agents ------------------------------------------------------------
    def create_agent(self, **kw) -> dict[str, Any]:
        agent = {"id": new_id("agent"), "entry": "agent.py", "source_dir": "",
                 "remote_url": "", "remote_token": "", "image_ref": "", "sha256": "",
                 "size_bytes": 0, "notes": "", "created_at": time.time(), **kw}
        cols = ("id", "team_id", "name", "kind", "entry", "source_dir", "remote_url",
                "remote_token", "image_ref", "sha256", "size_bytes", "notes", "created_at")
        with self._write_lock:
            self.conn().execute(
                f"INSERT INTO agents ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                tuple(agent[c] for c in cols))
        return agent

    def agent(self, agent_id: str) -> dict | None:
        r = self.conn().execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
        return dict(r) if r else None

    def clear_agent_image(self, agent_id: str) -> None:
        """The image was reclaimed from the host; the row and its history stay."""
        with self._write_lock:
            self.conn().execute("UPDATE agents SET image_ref = '' WHERE id = ?",
                                (agent_id,))

    def agents_for_team(self, team_id: str) -> list[dict]:
        rows = self.conn().execute(
            "SELECT * FROM agents WHERE team_id = ? ORDER BY created_at DESC", (team_id,))
        return [dict(r) for r in rows]

    # ---- matches -----------------------------------------------------------
    def create_match(self, team_id: str, agent_id: str, track: str, seed: int,
                     max_gen: int) -> dict[str, Any]:
        m = {"id": new_id("match"), "team_id": team_id, "agent_id": agent_id,
             "track": track, "seed": seed, "status": "queued", "max_gen": max_gen,
             "created_at": time.time()}
        with self._write_lock:
            self.conn().execute(
                "INSERT INTO matches (id,team_id,agent_id,track,seed,status,max_gen,created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (m["id"], team_id, agent_id, track, seed, "queued", max_gen, m["created_at"]))
        return m

    def update_match(self, match_id: str, **fields) -> None:
        if not fields:
            return
        sets = ",".join(f"{k} = ?" for k in fields)
        with self._write_lock:
            self.conn().execute(f"UPDATE matches SET {sets} WHERE id = ?",
                                (*fields.values(), match_id))

    def match(self, match_id: str) -> dict | None:
        r = self.conn().execute(
            "SELECT m.*, t.name AS team_name, a.name AS agent_name, a.kind AS agent_kind"
            " FROM matches m JOIN teams t ON t.id = m.team_id"
            " JOIN agents a ON a.id = m.agent_id WHERE m.id = ?", (match_id,)).fetchone()
        return dict(r) if r else None

    def claim_next_queued(self) -> dict | None:
        """Atomically move one queued match to running. Safe across workers."""
        with self._write_lock:
            c = self.conn()
            c.execute("BEGIN IMMEDIATE")
            try:
                row = c.execute(
                    "SELECT id FROM matches WHERE status = 'queued'"
                    " ORDER BY created_at LIMIT 1").fetchone()
                if not row:
                    c.execute("COMMIT")
                    return None
                c.execute("UPDATE matches SET status='running', started_at=? WHERE id=?",
                          (time.time(), row["id"]))
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise
        return self.match(row["id"])

    def recent_matches(self, limit: int = 30, team_id: str | None = None) -> list[dict]:
        q = ("SELECT m.*, t.name AS team_name, a.name AS agent_name, a.kind AS agent_kind"
             " FROM matches m JOIN teams t ON t.id = m.team_id"
             " JOIN agents a ON a.id = m.agent_id")
        args: tuple = ()
        if team_id:
            q += " WHERE m.team_id = ?"
            args = (team_id,)
        q += " ORDER BY m.created_at DESC LIMIT ?"
        return [dict(r) for r in self.conn().execute(q, (*args, limit))]

    def requeue_stale_running(self) -> int:
        """Matches left 'running' by a crashed process are not lost on restart."""
        with self._write_lock:
            cur = self.conn().execute(
                "UPDATE matches SET status='queued', started_at=NULL WHERE status='running'")
        return cur.rowcount or 0

    # ---- events ------------------------------------------------------------
    def add_event(self, match_id: str, seq: int, evt: str, payload: dict) -> dict:
        row = {"match_id": match_id, "seq": seq, "ts": time.time(), "evt": evt,
               "payload": payload}
        with self._write_lock:
            self.conn().execute(
                "INSERT INTO match_events (match_id,seq,ts,evt,payload) VALUES (?,?,?,?,?)",
                (match_id, seq, row["ts"], evt, json.dumps(payload)))
        return row

    def events(self, match_id: str, after_seq: int = -1) -> list[dict]:
        rows = self.conn().execute(
            "SELECT seq, ts, evt, payload FROM match_events"
            " WHERE match_id = ? AND seq > ? ORDER BY seq", (match_id, after_seq))
        return [{"seq": r["seq"], "ts": r["ts"], "evt": r["evt"],
                 "payload": json.loads(r["payload"])} for r in rows]

    # ---- leaderboard -------------------------------------------------------
    def leaderboard(self, track: str | None = None, limit: int = 100) -> list[dict]:
        """One row per team: their BEST completed match on the track.

        Rank order is depth first (how far up the ladder the agent actually got),
        then total solve time, then who got there first.
        """
        q = ("SELECT m.*, t.name AS team_name, a.name AS agent_name, a.kind AS agent_kind"
             " FROM matches m JOIN teams t ON t.id = m.team_id"
             " JOIN agents a ON a.id = m.agent_id"
             " WHERE m.status = 'done'")
        args: tuple = ()
        if track:
            q += " AND m.track = ?"
            args = (track,)
        best: dict[str, dict] = {}
        for r in self.conn().execute(q, args):
            row = dict(r)
            key = row["team_id"]
            cur = best.get(key)
            if cur is None or _rank_key(row) < _rank_key(cur):
                best[key] = row
        ranked = sorted(best.values(), key=_rank_key)[:limit]
        for i, row in enumerate(ranked, 1):
            row["rank"] = i
        return ranked

    # ---- challenge library -------------------------------------------------
    def archive_challenge(self, *, spec, match_id: str = "", team_name: str = "",
                          track: str = "", solved: bool = False,
                          origin: str = "match") -> dict | None:
        """Keep an authored challenge after the match that produced it ends.

        Takes the organizer-side spec but stores only what a player may see: the
        artifacts, the prose, and sha256 of the flag. The real flag, the solver
        source and the match secret never reach the database.

        Deduplicated on flag_sha256, which is unique per (secret, seed, generation)
        — so replaying a match does not fill the library with copies.
        """
        mechanics = getattr(spec, "mechanics", {}) or {}
        entry = {
            "id": new_id("lib"), "created_at": time.time(),
            "match_id": match_id or None, "team_name": team_name or "",
            "track": track or spec.category, "generation": spec.lineage.generation,
            "attack_class": mechanics.get("attack_class") or spec.challenge_type,
            "title": spec.title, "story": spec.story or "",
            "hints": json.dumps(list(spec.hints or []), ensure_ascii=False),
            "stages": json.dumps(list(mechanics.get("stages") or []), ensure_ascii=False),
            "depth": int(mechanics.get("depth") or spec.intended_depth),
            "rank": int(mechanics.get("rank") or 0),
            "plan_source": mechanics.get("plan_source") or "catalog",
            "designer_note": mechanics.get("designer_note") or "",
            "files": json.dumps(dict(spec.artifacts or {}), ensure_ascii=False),
            "flag_sha256": spec.official_solver.expected_flag_sha256,
            "solved_in_match": 1 if solved else 0, "solve_count": 0,
            "origin": origin,
        }
        if not entry["flag_sha256"]:
            return None
        cols = tuple(entry)
        with self._write_lock:
            cur = self.conn().execute(
                f"INSERT OR IGNORE INTO library ({','.join(cols)}) "
                f"VALUES ({','.join('?' * len(cols))})",
                tuple(entry[c] for c in cols))
        return entry if cur.rowcount else None

    def library(self, *, limit: int = 60, offset: int = 0,
                plan_source: str = "", origin: str = "") -> list[dict]:
        q = "SELECT * FROM library"
        where, args = [], []
        if plan_source:
            where.append("plan_source = ?"); args.append(plan_source)
        if origin:
            where.append("origin = ?"); args.append(origin)
        if where:
            q += " WHERE " + " AND ".join(where)
        # Practice is a curriculum, so it reads easiest-first; the match feed is a
        # highlight reel, so it leads with the hardest thing anyone reached.
        q += (" ORDER BY rank ASC, created_at ASC" if origin == "practice"
              else " ORDER BY rank DESC, created_at DESC")
        q += " LIMIT ? OFFSET ?"
        rows = self.conn().execute(q, tuple(args) + (max(1, min(limit, 200)), max(0, offset)))
        return [_library_row(dict(r)) for r in rows]

    def library_count(self, *, origin: str = "") -> int:
        if origin:
            return self.conn().execute(
                "SELECT COUNT(*) AS n FROM library WHERE origin = ?", (origin,)
            ).fetchone()["n"]
        return self.conn().execute("SELECT COUNT(*) AS n FROM library").fetchone()["n"]

    def library_entry(self, entry_id: str, *, with_files: bool = False) -> dict | None:
        r = self.conn().execute("SELECT * FROM library WHERE id = ?", (entry_id,)).fetchone()
        if not r:
            return None
        return _library_row(dict(r), with_files=with_files)

    def mark_library_solved(self, entry_id: str) -> None:
        with self._write_lock:
            self.conn().execute(
                "UPDATE library SET solved_in_match = 1 WHERE id = ?", (entry_id,))

    def library_check_flag(self, entry_id: str, flag: str) -> bool:
        """Check a submission without the answer ever being stored."""
        import hashlib
        r = self.conn().execute(
            "SELECT flag_sha256 FROM library WHERE id = ?", (entry_id,)).fetchone()
        if not r:
            return False
        ok = hashlib.sha256((flag or "").strip().encode()).hexdigest() == r["flag_sha256"]
        if ok:
            with self._write_lock:
                self.conn().execute(
                    "UPDATE library SET solve_count = solve_count + 1 WHERE id = ?",
                    (entry_id,))
        return ok


def _library_row(row: dict, *, with_files: bool = False) -> dict:
    """Decode the json columns and drop anything a browser has no business seeing."""
    row["hints"] = json.loads(row.get("hints") or "[]")
    row["stages"] = json.loads(row.get("stages") or "[]")
    files = json.loads(row.pop("files", None) or "{}")
    row["file_list"] = [{"name": n, "bytes": len(c)} for n, c in sorted(files.items())]
    if with_files:
        row["files"] = files
    # The hash is only needed server-side to check submissions.
    row.pop("flag_sha256", None)
    return row


def _rank_key(m: dict) -> tuple:
    """Lower sorts better: deepest rung solved, then fastest, then earliest."""
    return (-int(m.get("reached_gen", -1)),
            float(m.get("solve_seconds") or 0.0),
            float(m.get("finished_at") or m.get("created_at") or 0.0))
