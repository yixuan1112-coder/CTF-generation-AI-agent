"""HTTP server: the public face of the arena.

Zero third-party dependencies — stdlib `ThreadingHTTPServer` only, so the arena
runs on any box that can run the engine. Serves the four UI pages, a JSON API for
teams and agents, and a Server-Sent-Events stream so a match can be watched rung
by rung as it happens.

Auth is a bearer token issued at team registration. Binary agent uploads are sent
as the raw request body (no multipart), which keeps both `fetch()` and
`curl --data-binary @agent.py` one-liners.
"""
from __future__ import annotations

import json
import mimetypes
import os
import queue
import tempfile
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import agents as agents_mod
from . import images as images_mod
from .runner import MatchEngine, fresh_seed
from .sandbox import IMAGE_AGENT_DIR, available_libraries, backend_report
from .store import Store, new_id
from .tracks import all_tracks, get_track, warmup

UI_DIR = Path(__file__).with_name("ui")
MAX_BODY = 12 * 1024 * 1024
MAX_ACTIVE_MATCHES_PER_TEAM = 1


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status, self.message = status, message


class RateLimiter:
    """Coarse per-IP bucket — enough to stop a loop from flooding the queue."""

    def __init__(self, limit: int, window_s: int):
        self.limit, self.window = limit, window_s
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.time()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < self.window]
            if len(hits) >= self.limit:
                raise ApiError(f"rate limit: max {self.limit} per "
                               f"{self.window}s from one address", 429)
            hits.append(now)
            self._hits[key] = hits


class Arena:
    """Wiring: store + engine + upload directory, shared by all request threads."""

    def __init__(self, data_dir: Path | str = ".arena", workers: int = 2,
                 backend: str = "auto", maker_backend: str = "auto"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.upload_root = self.data_dir / "uploads"
        self.upload_root.mkdir(exist_ok=True)
        self.store = Store(self.data_dir / "arena.sqlite3")
        # Where the challenge-maker runs. Probe it once here, before any track is
        # described: with a container maker the route depends on the IMAGE's
        # toolchain, not this host's, and the two can differ.
        self.maker_backend = maker_backend
        self.maker_report = self._probe_maker()
        self.engine = MatchEngine(self.store, self.upload_root, workers=workers,
                                  backend=backend, maker_backend=maker_backend)
        self._seed_practice()
        self.limit_teams = RateLimiter(limit=10, window_s=3600)
        self.limit_matches = RateLimiter(limit=30, window_s=3600)
        # Tighter than the others on purpose: every image submission costs a
        # multi-hundred-megabyte upload, a `docker load` and a probe container.
        self.limit_images = RateLimiter(limit=6, window_s=3600)

    def _probe_maker(self) -> dict:
        """Ask the maker what it can build, and tell `tracks` so routes match."""
        from autoctf_gan import maker as maker_mod
        from .tracks import set_maker_capabilities

        try:
            probe = maker_mod.for_arena(backend=self.maker_backend, start="crypto")
            report = probe.describe()
            set_maker_capabilities({"gcc": report["gcc"], "fpylll": report["fpylll"]})
        except maker_mod.MakerError as exc:
            # backend='docker' was demanded and could not be honoured. Fail here,
            # at startup, rather than at the first evolution of the first match.
            raise RuntimeError(f"challenge-maker unavailable: {exc}") from exc
        return report

    def _seed_practice(self) -> None:
        """Populate the curated practice catalogue once, so a player always has
        something to pick. A build failure here must never stop the arena from
        serving matches, so it is best-effort and merely logged."""
        try:
            from .practice import seed_practice
            added = seed_practice(self.store)
            if added:
                print(f"[arena] seeded {added} practice challenge(s)")
        except Exception as exc:                      # noqa: BLE001 — never fatal
            import traceback
            traceback.print_exc()
            print(f"[arena] practice seeding skipped: {type(exc).__name__}: {exc}")

    def start(self) -> None:
        self.engine.start()

    # ---- operations used by the request handler ----------------------------
    def auth(self, token: str) -> dict:
        team = self.store.team_by_token((token or "").strip())
        if not team:
            raise ApiError("invalid or missing team token", 401)
        return team

    def register_team(self, name: str, contact: str) -> dict:
        try:
            team = self.store.create_team(name, contact)
        except ValueError as exc:
            raise ApiError(str(exc), 409) from exc
        return {"team_id": team["id"], "name": team["name"], "token": team["token"]}

    def submit_agent(self, team: dict, params: dict, body: bytes) -> dict:
        name = (params.get("name") or "agent").strip()[:64] or "agent"
        kind = (params.get("kind") or "upload").strip()
        notes = (params.get("notes") or "").strip()[:500]

        if kind == "remote":
            url = agents_mod.validate_remote_url(params.get("remote_url", ""))
            agent = self.store.create_agent(
                team_id=team["id"], name=name, kind="remote", remote_url=url,
                remote_token=(params.get("remote_token") or "").strip()[:200],
                notes=notes)
        elif kind == "upload":
            # Mint the id first so the code lands in a directory named after the
            # agent row that will own it — a timestamp would collide when two
            # uploads from one team land in the same millisecond.
            agent_id = new_id("agent")
            stored = agents_mod.store_upload(self.upload_root, team["id"], agent_id,
                                             params.get("filename", "agent.py"), body)
            agent = self.store.create_agent(
                id=agent_id, team_id=team["id"], name=name, kind="upload",
                entry=stored["entry"], source_dir=stored["dir"],
                sha256=stored["sha256"], size_bytes=stored["size_bytes"], notes=notes)
        elif kind == "image":
            # The registry route: the team pushed it, we pull it by address.
            if not (params.get("image_ref") or "").strip():
                raise ApiError("give an image_ref to pull (e.g. youruser/my-agent:v1), "
                               "or POST a `docker save` tarball as the raw body")
            return self._accept_image(
                team, params,
                lambda agent_id: images_mod.pull_image(params["image_ref"], agent_id))
        else:
            raise ApiError("kind must be 'upload', 'image' or 'remote'")
        return _public_agent(agent)

    def submit_image_agent(self, team: dict, params: dict, tarball: Path) -> dict:
        """The tarball route: `docker save` output arrived as the request body."""
        return self._accept_image(
            team, params, lambda agent_id: images_mod.load_image(tarball, agent_id))

    def _accept_image(self, team: dict, params: dict, acquire) -> dict:
        """Shared tail of both image routes: acquire → probe → record → prune.

        Ordered so the host is never left holding an image no row points at:
        mint the id first so the image can be tagged with it, probe before the
        row exists, and remove the image on any failure.
        """
        name = (params.get("name") or "agent").strip()[:64] or "agent"
        notes = (params.get("notes") or "").strip()[:500]
        if not images_mod.images_supported():
            raise ApiError("this arena has no Docker daemon, so it cannot accept "
                           "image submissions — upload a .py or .zip instead", 409)

        agent_id = new_id("agent")
        acquired = acquire(agent_id)
        try:
            images_mod.probe_image(
                acquired["image_ref"],
                memory_mb=int(os.environ.get("ARENA_AGENT_MEMORY_MB", "2048")))
        except Exception:
            images_mod.remove_image(acquired["image_ref"])
            raise

        agent = self.store.create_agent(
            id=agent_id, team_id=team["id"], name=name, kind="image",
            entry="agent.py", image_ref=acquired["image_ref"],
            sha256=(acquired.get("image_id") or "").removeprefix("sha256:"),
            size_bytes=acquired.get("unpacked_bytes") or acquired.get("size_bytes") or 0,
            # Provenance: which address this came from, for an operator auditing
            # the host later. Empty for a tarball, which has no address.
            notes=" ".join(filter(None, [notes, acquired.get("source_ref", "")]))[:500])

        pruned = images_mod.prune_team_images(self.store, team["id"], agent_id)
        out = _public_agent(agent)
        out["pruned_images"] = len(pruned)
        out["source_ref"] = acquired.get("source_ref", "")
        return out

    def start_match(self, team: dict, agent_id: str, track_key: str) -> dict:
        agent = self.store.agent(agent_id)
        if not agent or agent["team_id"] != team["id"]:
            raise ApiError("unknown agent for this team", 404)
        try:
            track = get_track(track_key)
        except KeyError as exc:
            raise ApiError(str(exc)) from exc
        if not track.available:
            # Better an honest refusal than a match the team cannot win.
            raise ApiError(f"the {track.key} track is not currently playable: "
                           f"{track.unavailable_reason}", 409)

        active = [m for m in self.store.recent_matches(limit=50, team_id=team["id"])
                  if m["status"] in ("queued", "running")]
        if len(active) >= MAX_ACTIVE_MATCHES_PER_TEAM:
            raise ApiError(f"you already have a match in progress ({active[0]['id']}); "
                           "wait for it to finish", 409)

        match = self.store.create_match(team["id"], agent_id, track.key,
                                        fresh_seed(), track.max_gen)
        return {"match_id": match["id"], "status": "queued",
                "queue_position": self.engine.queue_position(match["id"]),
                "track": track.key, "max_gen": track.max_gen}


def _public_agent(agent: dict) -> dict:
    """Never echo a team's remote token back over the API."""
    out = {k: agent.get(k) for k in
           ("id", "name", "kind", "entry", "sha256", "size_bytes", "notes", "created_at")}
    if agent.get("kind") == "remote":
        out["remote_url"] = agent.get("remote_url")
    if agent.get("kind") == "image":
        # The tag is arena-owned and derived from the agent id, so it leaks
        # nothing — and showing it is how a team tells a live image from one the
        # pruner has already reclaimed.
        out["image_ref"] = agent.get("image_ref") or ""
    return out


def _library_zip(entry: dict) -> bytes:
    """The player package: exactly the artifacts the competing agent was handed."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in sorted((entry.get("files") or {}).items()):
            zf.writestr(name, content)
        zf.writestr("CHALLENGE.txt", _library_brief(entry))
    return buf.getvalue()


def _library_brief(entry: dict) -> str:
    hints = "\n".join(f"  - {h}" for h in entry.get("hints") or [])
    stages = " -> ".join(entry.get("stages") or []) or entry.get("attack_class", "")
    return (f"{entry.get('title', '')}\n{'=' * len(entry.get('title', ''))}\n\n"
            f"{entry.get('story', '')}\n\n"
            f"Composition : {stages}\n"
            f"Depth       : {entry.get('depth')}    Difficulty rank: {entry.get('rank')}\n"
            f"Designed by : {'a model' if entry.get('plan_source') == 'llm' else 'the catalogue'}\n"
            f"Authored during a match against {entry.get('team_name') or 'a team'}.\n\n"
            f"Hints:\n{hints}\n\n"
            f"Submit the flag at /library/{entry.get('id')}.\n")


def _public_match(m: dict) -> dict:
    keys = ("id", "team_name", "agent_name", "agent_kind", "track", "status",
            "reached_gen", "agent_gen", "max_gen", "score", "solve_seconds",
            "outcome", "error", "created_at", "started_at", "finished_at", "rank")
    out = {k: m.get(k) for k in keys if k in m}
    try:
        track = get_track(m["track"])
        reached = m.get("reached_gen")
        reached = -1 if reached is None else int(reached)   # 0 is a real solve
        out["rung_reached"] = track.rung_name(reached) if reached >= 0 else None
        out["rung_agent"] = track.rung_name(m.get("agent_gen") or 0)
        out["rungs"] = track.rungs
    except KeyError:
        pass
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "AutoCTFArena/1.0"
    arena: Arena                       # injected by serve()

    def log_message(self, fmt, *args):
        if os.environ.get("ARENA_ACCESS_LOG"):
            super().log_message(fmt, *args)

    # ---- plumbing ----------------------------------------------------------
    def _send(self, code: int, ctype: str, body, extra: dict | None = None) -> None:
        payload = body if isinstance(body, bytes) else str(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _json(self, data, code: int = 200) -> None:
        self._send(code, "application/json; charset=utf-8", json.dumps(data, default=str))

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ApiError(f"request body exceeds {MAX_BODY // (1024 * 1024)} MB", 413)
        return self.rfile.read(length) if length else b""

    def _read_body_to_file(self, max_bytes: int, suffix: str = ".tar") -> Path:
        """Stream a large body to disk. The caller owns (and must delete) the file.

        Image tarballs are hundreds of megabytes, and this arena is sized for a
        2-core VPS — reading one into memory the way `_read_body` does would be
        a denial of service with a single upload. Content-Length is checked
        first so an oversized submission is refused before the bytes arrive, and
        the running total is checked again while reading in case the header lied.
        """
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise ApiError("this endpoint needs a Content-Length and a raw body")
        if length > max_bytes:
            raise ApiError(f"upload is {length // (1024 * 1024)} MB; the limit is "
                           f"{max_bytes // (1024 * 1024)} MB", 413)

        fd, temp = tempfile.mkstemp(prefix="arena-image-", suffix=suffix)
        path = Path(temp)
        remaining, total = length, 0
        try:
            with os.fdopen(fd, "wb") as out:
                while remaining > 0:
                    chunk = self.rfile.read(min(1 << 20, remaining))
                    if not chunk:
                        raise ApiError("upload ended early — the connection dropped "
                                       "before the whole image arrived", 400)
                    total += len(chunk)
                    if total > max_bytes:
                        raise ApiError(f"upload exceeds "
                                       f"{max_bytes // (1024 * 1024)} MB", 413)
                    out.write(chunk)
                    remaining -= len(chunk)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return path

    def _token(self, qs: dict) -> str:
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return header[7:].strip()
        return (qs.get("token", [""])[0] or "").strip()

    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "?"

    # ---- routing -----------------------------------------------------------
    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str):
        parsed = urlparse(self.path)
        path, qs = parsed.path.rstrip("/") or "/", parse_qs(parsed.query)
        try:
            if method == "GET" and self._serve_page(path):
                return
            if path.startswith("/api/"):
                return self._api(method, path, qs)
            self._send(404, "text/plain; charset=utf-8", "not found")
        except ApiError as exc:
            self._json({"error": exc.message}, exc.status)
        except agents_mod.UploadError as exc:
            self._json({"error": str(exc)}, 400)
        except images_mod.ImageError as exc:
            self._json({"error": str(exc)}, 400)
        except BrokenPipeError:
            pass
        except Exception as exc:
            traceback.print_exc()
            self._json({"error": f"internal error: {type(exc).__name__}: {exc}"}, 500)

    # ---- pages -------------------------------------------------------------
    PAGES = {"/": "index.html", "/submit": "submit.html", "/docs": "docs.html",
             "/library": "library.html", "/practice": "library.html"}

    def _serve_page(self, path: str) -> bool:
        if path in self.PAGES:
            self._send_file(UI_DIR / self.PAGES[path])
            return True
        if path.startswith("/match/"):
            self._send_file(UI_DIR / "match.html")
            return True
        if path.startswith("/static/"):
            name = os.path.basename(path)
            target = UI_DIR / name
            if target.exists() and target.is_file():
                self._send_file(target)
            else:
                self._send(404, "text/plain; charset=utf-8", "not found")
            return True
        return False

    def _send_file(self, target: Path) -> None:
        if not target.exists():
            return self._send(404, "text/plain; charset=utf-8", "not found")
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        self._send(200, ctype, target.read_bytes(), {"Cache-Control": "no-cache"})

    # ---- API ---------------------------------------------------------------
    def _api(self, method: str, path: str, qs: dict):
        arena = self.arena
        store = arena.store

        if path == "/api/config" and method == "GET":
            tracks = {k: {"key": t.key, "label": t.label, "blurb": t.blurb,
                          "rungs": t.rungs, "max_gen": t.max_gen,
                          "per_gen_timeout_s": t.per_gen_timeout_s,
                          "match_budget_s": t.match_budget_s,
                          "available": t.available,
                          "unavailable_reason": t.unavailable_reason,
                          "route": t.route, "endless": t.endless,
                          "skipped_segments": t.skipped_segments}
                      for k, t in all_tracks().items()}
            from autoctf_gan.design import brain_status
            return self._json({"tracks": tracks, "isolation": backend_report(),
                               "libraries": available_libraries(),
                               "design_brain": brain_status(),
                               "maker": arena.maker_report,
                               "library_size": store.library_count(origin="match"),
                               "images": {
                                   "supported": images_mod.images_supported(),
                                   "agent_dir": IMAGE_AGENT_DIR,
                                   "max_image_mb": images_mod.MAX_IMAGE_BYTES // (1024 * 1024),
                                   "kept_per_team": 1},
                               "limits": {"max_upload_mb": agents_mod.MAX_UPLOAD_BYTES // (1024 * 1024),
                                          "max_image_mb": images_mod.MAX_IMAGE_BYTES // (1024 * 1024),
                                          "max_active_matches": MAX_ACTIVE_MATCHES_PER_TEAM}})

        if path == "/api/teams" and method == "POST":
            arena.limit_teams.check(self._client_ip())
            data = self._json_body()
            return self._json(arena.register_team(data.get("name", ""),
                                                  data.get("contact", "")), 201)

        if path == "/api/agents":
            team = arena.auth(self._token(qs))
            if method == "GET":
                return self._json({"agents": [_public_agent(a)
                                              for a in store.agents_for_team(team["id"])]})
            # POST: query params carry metadata, raw body carries the file.
            params = {k: v[0] for k, v in qs.items()}
            if (params.get("kind") or "").strip() == "image":
                # Streamed, not buffered — see _read_body_to_file.
                arena.limit_images.check(self._client_ip())
                tarball = self._read_body_to_file(images_mod.MAX_IMAGE_BYTES)
                try:
                    return self._json(arena.submit_image_agent(team, params, tarball), 201)
                finally:
                    tarball.unlink(missing_ok=True)
            body = self._read_body()
            if not params.get("kind") and body[:1] == b"{":
                params.update(self._parse_json(body))
                body = b""
            if (params.get("kind") or "").strip() == "image":
                # The registry route lands here (JSON body, no tarball). A pull
                # is as expensive as a load, so it gets the same budget.
                arena.limit_images.check(self._client_ip())
            return self._json(arena.submit_agent(team, params, body), 201)

        if path == "/api/matches":
            if method == "POST":
                arena.limit_matches.check(self._client_ip())
                team = arena.auth(self._token(qs))
                data = self._json_body()
                return self._json(arena.start_match(team, data.get("agent_id", ""),
                                                    data.get("track", "crypto")), 201)
            limit = min(100, int(qs.get("limit", ["25"])[0] or 25))
            return self._json({"matches": [_public_match(m)
                                           for m in store.recent_matches(limit)]})

        if path.startswith("/api/matches/"):
            rest = path[len("/api/matches/"):]
            match_id, _, tail = rest.partition("/")
            match = store.match(match_id)
            if not match:
                raise ApiError("unknown match", 404)
            if tail == "stream":
                return self._stream(match_id, int(qs.get("after", ["-1"])[0]))
            if tail in ("", "events"):
                after = int(qs.get("after", ["-1"])[0])
                out = {"match": _public_match(match), "events": store.events(match_id, after)}
                if match["status"] == "queued":
                    out["queue_position"] = arena.engine.queue_position(match_id)
                return self._json(out)
            raise ApiError("unknown match sub-resource", 404)

        if path == "/api/leaderboard" and method == "GET":
            track = qs.get("track", ["crypto"])[0]
            rows = store.leaderboard(track if track != "all" else None)
            return self._json({"track": track,
                               "leaderboard": [_public_match(r) for r in rows]})

        if path == "/api/library" and method == "GET":
            limit = min(200, int(qs.get("limit", ["60"])[0] or 60))
            offset = max(0, int(qs.get("offset", ["0"])[0] or 0))
            source = qs.get("source", [""])[0]
            if source not in ("", "catalog", "llm"):
                raise ApiError("source must be 'catalog' or 'llm'")
            origin = qs.get("origin", [""])[0]
            if origin not in ("", "practice", "match"):
                raise ApiError("origin must be 'practice' or 'match'")
            return self._json({"total": store.library_count(),
                               "practice_total": store.library_count(origin="practice"),
                               "match_total": store.library_count(origin="match"),
                               "entries": store.library(limit=limit, offset=offset,
                                                        plan_source=source, origin=origin)})

        if path.startswith("/api/library/"):
            rest = path[len("/api/library/"):]
            entry_id, _, tail = rest.partition("/")
            entry = store.library_entry(entry_id, with_files=tail == "download")
            if not entry:
                raise ApiError("unknown library challenge", 404)
            if tail == "" and method == "GET":
                return self._json(entry)
            if tail == "download" and method == "GET":
                return self._send(200, "application/zip", _library_zip(entry),
                                  {"Content-Disposition":
                                   f'attachment; filename="{entry_id}.zip"'})
            if tail == "submit" and method == "POST":
                flag = str(self._json_body().get("flag", ""))[:512]
                return self._json({"correct": store.library_check_flag(entry_id, flag)})
            raise ApiError("unknown library sub-resource", 404)

        if path == "/api/template" and method == "GET":
            template = Path(__file__).resolve().parents[1] / "team_agent.py"
            body = template.read_bytes() if template.exists() else b"# template missing\n"
            return self._send(200, "text/x-python; charset=utf-8", body,
                              {"Content-Disposition": 'attachment; filename="agent.py"'})

        raise ApiError("unknown endpoint", 404)

    def _json_body(self) -> dict:
        return self._parse_json(self._read_body())

    @staticmethod
    def _parse_json(body: bytes) -> dict:
        if not body:
            return {}
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(f"request body is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ApiError("request body must be a JSON object")
        return data

    # ---- SSE ---------------------------------------------------------------
    def _stream(self, match_id: str, after: int):
        store = self.arena.store
        bus = self.arena.engine.bus
        q = bus.subscribe(match_id)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        # This is an HTTP/1.0 server: the socket closing IS the end-of-stream
        # signal. Advertising keep-alive would leave clients waiting forever
        # after the final event.
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        self.close_connection = True

        def write(event: dict) -> None:
            self.wfile.write(f"data: {json.dumps(event, default=str)}\n\n".encode())
            self.wfile.flush()

        seen = after

        def drain() -> None:
            """Flush anything already durable in the DB — the bus can drop."""
            nonlocal seen
            for event in store.events(match_id, seen):
                write(event)
                seen = event["seq"]

        try:
            drain()                                   # replay history, then go live
            last_beat = time.monotonic()
            while True:
                match = store.match(match_id)
                finished = bool(match) and match["status"] in ("done", "error")
                try:
                    event = q.get(timeout=1.0)
                    if event["seq"] > seen:
                        write(event)
                        seen = event["seq"]
                    continue                          # drain the burst before polling
                except queue.Empty:
                    pass
                drain()
                if finished:
                    # The runner flips status to 'done' just before emitting the
                    # final event, so give that last write a moment to land.
                    time.sleep(0.25)
                    drain()
                    write({"seq": seen + 1, "evt": "stream.end", "payload": {}})
                    return
                if time.monotonic() - last_beat > 15:
                    self.wfile.write(b": keep-alive\n\n")   # keep proxies from closing
                    self.wfile.flush()
                    last_beat = time.monotonic()
        except (BrokenPipeError, ConnectionResetError):
            return
        finally:
            bus.unsubscribe(match_id, q)


def serve(host: str = "127.0.0.1", port: int = 8090, data_dir: str = ".arena",
          workers: int = 2, backend: str = "auto", maker_backend: str = "auto") -> None:
    # The maker is probed inside Arena(), and tracks plan their routes from what
    # it reports — so it has to exist before warmup() describes any ladder.
    arena = Arena(data_dir=data_dir, workers=workers, backend=backend,
                  maker_backend=maker_backend)
    warmup()          # main thread: see tracks.warmup for why this must come first
    arena.start()

    if host not in ("127.0.0.1", "localhost", "::1"):
        # Reachable from off-box: stop remote-agent URLs being used as an SSRF probe.
        os.environ.setdefault("ARENA_BLOCK_PRIVATE_REMOTE", "1")

    handler = type("BoundHandler", (Handler,), {"arena": arena})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    iso = backend_report()
    shown = "localhost" if host in ("0.0.0.0", "::") else host
    print(f"AutoCTF Arena   http://{shown}:{port}")
    print(f"  isolation     {iso['backend']} ({iso['strength']}) — {iso['note']}")
    mk = arena.maker_report
    print(f"  maker         {mk['backend']}"
          + (f" [{mk['image']}]" if mk.get("image") else "")
          + f" — network: {mk['network']}")
    if mk["backend"] == "inprocess":
        print("                the maker and verify_spec run in THIS process; build "
              "Dockerfile.maker and pass --maker-backend docker to isolate them")
    print(f"  toolchain     gcc={mk['gcc']} fpylll={mk['fpylll']} design-brain={mk['llm']}")
    print(f"  data dir      {Path(data_dir).resolve()}")
    print(f"  workers       {workers}    Ctrl-C to stop", flush=True)
    # Piped to a log file, stdout is block-buffered, so without this the banner —
    # including which maker backend is live — does not appear until the server
    # stops, which is exactly when nobody needs it.
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down…")
    finally:
        arena.engine.stop()
        httpd.server_close()


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="Run the AutoCTF Arena competition server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--data-dir", default=".arena")
    ap.add_argument("--workers", type=int, default=2, help="concurrent matches")
    ap.add_argument("--backend", choices=("auto", "docker", "subprocess"), default="auto",
                    help="isolation for TEAM agents")
    ap.add_argument("--maker-backend", choices=("auto", "docker", "inprocess"),
                    default="auto",
                    help="where the challenge-maker runs. 'docker' refuses to fall "
                         "back, so a deployment that requires containerization "
                         "fails at startup instead of quietly using the host")
    args = ap.parse_args()
    serve(args.host, args.port, args.data_dir, args.workers, args.backend,
          args.maker_backend)


if __name__ == "__main__":
    main()
