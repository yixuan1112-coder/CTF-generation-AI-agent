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
    kind         TEXT NOT NULL,              -- 'upload' | 'remote'
    entry        TEXT DEFAULT 'agent.py',
    source_dir   TEXT DEFAULT '',            -- upload: where the code was unpacked
    remote_url   TEXT DEFAULT '',            -- remote: endpoint the server calls
    remote_token TEXT DEFAULT '',
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

CREATE INDEX IF NOT EXISTS idx_events_match ON match_events(match_id, seq);
CREATE INDEX IF NOT EXISTS idx_matches_team ON matches(team_id, status);
CREATE INDEX IF NOT EXISTS idx_matches_board ON matches(track, status, reached_gen);
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
                 "remote_url": "", "remote_token": "", "sha256": "", "size_bytes": 0,
                 "notes": "", "created_at": time.time(), **kw}
        cols = ("id", "team_id", "name", "kind", "entry", "source_dir", "remote_url",
                "remote_token", "sha256", "size_bytes", "notes", "created_at")
        with self._write_lock:
            self.conn().execute(
                f"INSERT INTO agents ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                tuple(agent[c] for c in cols))
        return agent

    def agent(self, agent_id: str) -> dict | None:
        r = self.conn().execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
        return dict(r) if r else None

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


def _rank_key(m: dict) -> tuple:
    """Lower sorts better: deepest rung solved, then fastest, then earliest."""
    return (-int(m.get("reached_gen", -1)),
            float(m.get("solve_seconds") or 0.0),
            float(m.get("finished_at") or m.get("created_at") or 0.0))
