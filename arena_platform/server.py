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
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import agents as agents_mod
from .runner import MatchEngine, fresh_seed
from .sandbox import available_libraries, backend_report
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
        self.limit_teams = RateLimiter(limit=10, window_s=3600)
        self.limit_matches = RateLimiter(limit=30, window_s=3600)

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
        else:
            raise ApiError("kind must be 'upload' or 'remote'")
        return _public_agent(agent)

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
        except BrokenPipeError:
            pass
        except Exception as exc:
            traceback.print_exc()
            self._json({"error": f"internal error: {type(exc).__name__}: {exc}"}, 500)

    # ---- pages -------------------------------------------------------------
    PAGES = {"/": "index.html", "/submit": "submit.html", "/docs": "docs.html",
             "/library": "library.html"}

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
                               "library_size": store.library_count(),
                               "limits": {"max_upload_mb": agents_mod.MAX_UPLOAD_BYTES // (1024 * 1024),
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
            body = self._read_body()
            if not params.get("kind") and body[:1] == b"{":
                params.update(self._parse_json(body))
                body = b""
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
            return self._json({"total": store.library_count(),
                               "entries": store.library(limit=limit, offset=offset,
                                                        plan_source=source)})

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
