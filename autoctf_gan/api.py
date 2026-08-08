"""Web layer — Step 4.

Two implementations of the SAME event contract (design §6):

  * build_fastapi_app()  — the production FastAPI app with REST endpoints and a
                           /ws/arena WebSocket. Importable only if fastapi is
                           installed (`pip install fastapi uvicorn`).
  * serve_stdlib(port)   — a zero-dependency http.server that serves the dashboard
                           and streams the identical tournament events over SSE, so
                           the UI runs right now without any web framework.

Run:  python -m autoctf_gan.api            # stdlib SSE server on :8080
      python -m autoctf_gan.api --fastapi  # uvicorn app (needs fastapi/uvicorn)
"""
from __future__ import annotations

import json
from pathlib import Path

from .tournament import TournamentConfig, run_tournament_events

DASHBOARD = Path(__file__).with_name("dashboard.html")
CONSOLE = Path(__file__).with_name("console.html")
ARENA = Path(__file__).with_name("arena.html")


# ---------------------------------------------------------------------------
# Production FastAPI app (design §6.1 REST + §6.2 WebSocket)
# ---------------------------------------------------------------------------
def build_fastapi_app():  # pragma: no cover - requires fastapi at runtime
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse, JSONResponse

    app = FastAPI(title="AutoCTF-GAN", version="1.0")
    _tournaments: dict[str, TournamentConfig] = {}

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return DASHBOARD.read_text(encoding="utf-8")

    @app.post("/api/v1/tournaments")
    def create_tournament(cfg: dict) -> JSONResponse:
        t = TournamentConfig(**{k: v for k, v in cfg.items()
                                if k in TournamentConfig.__dataclass_fields__})
        tid = f"{t.archetype_id}:{t.seed}"
        _tournaments[tid] = t
        return JSONResponse({"tournament_id": tid, "config": cfg})

    @app.get("/api/v1/tournaments/{tid}/state")
    def state(tid: str) -> JSONResponse:
        t = _tournaments.get(tid)
        if not t:
            return JSONResponse({"error": "unknown tournament"}, status_code=404)
        return JSONResponse({"tournament_id": tid, "config": t.__dict__})

    @app.get("/api/v1/matrix/{tid}")
    def matrix(tid: str) -> JSONResponse:
        t = _tournaments.get(tid) or TournamentConfig()
        rows = [e for e in run_tournament_events(t) if e["evt"] == "gen.scored"]
        return JSONResponse({"rows": rows})

    # WS /ws/arena/{tid} — Agent Battle Arena live feed (design §6.2)
    @app.websocket("/ws/arena/{tid}")
    async def ws_arena(ws: WebSocket, tid: str) -> None:
        await ws.accept()
        t = _tournaments.get(tid) or TournamentConfig()
        try:
            for evt in run_tournament_events(t):
                await ws.send_json(evt)
        except WebSocketDisconnect:
            return

    return app


# ---------------------------------------------------------------------------
# Zero-dependency fallback: http.server + Server-Sent Events
# ---------------------------------------------------------------------------
def serve_stdlib(port: int = 8080, cfg: TournamentConfig | None = None) -> None:
    import http.server
    import socketserver

    cfg = cfg or TournamentConfig()

    from .competition import Competition
    comp = Competition(category="crypto", seed=1234, evolve_on=1, max_gen=6)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _send(self, code, ctype, body, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body if isinstance(body, bytes) else body.encode())

        def do_GET(self):
            from urllib.parse import parse_qs, urlparse

            from . import console
            parsed = urlparse(self.path)
            path, qs = parsed.path, parse_qs(parsed.query)

            if path.startswith("/events"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                for evt in run_tournament_events(cfg):
                    try:
                        self.wfile.write(f"data: {json.dumps(evt)}\n\n".encode())
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
                self.wfile.write(b"data: {\"evt\": \"stream.end\"}\n\n")
                return

            if path == "/console":
                return self._send(200, "text/html", CONSOLE.read_text(encoding="utf-8"))
            if path == "/api/menu":
                return self._send(200, "application/json", json.dumps(console.menu()))
            if path == "/api/generate":
                try:
                    data = console.generate_challenge(
                        qs.get("option", ["misc:easy"])[0],
                        int(qs.get("seed", ["1234"])[0]),
                        qs.get("verify", ["false"])[0] == "true")
                    return self._send(200, "application/json", json.dumps(data))
                except Exception as exc:
                    return self._send(200, "application/json", json.dumps({"error": str(exc)}))
            if path == "/api/download":
                try:
                    name, blob = console.challenge_zip(
                        qs.get("option", ["misc:easy"])[0], int(qs.get("seed", ["1234"])[0]))
                    return self._send(200, "application/zip", blob,
                                      {"Content-Disposition": f'attachment; filename="{name}"'})
                except Exception as exc:
                    return self._send(200, "application/json", json.dumps({"error": str(exc)}))

            # ---- live competition endpoints (real teams vs. evolving agent) ----
            if path == "/comp/status":
                return self._send(200, "application/json", json.dumps(comp.status()))
            if path == "/comp/scoreboard":
                return self._send(200, "application/json", json.dumps(comp.scoreboard()))
            if path == "/comp/register":
                return self._send(200, "application/json",
                                  json.dumps(comp.register(qs.get("name", ["anon"])[0])))
            if path == "/comp/challenge":
                return self._send(200, "application/json",
                                  json.dumps(comp.current(qs.get("team", [None])[0])))
            if path == "/comp/submit":
                r = comp.submit(qs.get("team", [""])[0], qs.get("challenge", [""])[0],
                                qs.get("flag", [""])[0])
                return self._send(200, "application/json", json.dumps(r))
            if path == "/arena":
                return self._send(200, "text/html", ARENA.read_text(encoding="utf-8"))
            if path == "/comp/simulate":
                from .competition import run_competition_demo
                n = max(1, min(6, int(qs.get("teams", ["3"])[0])))
                cat = qs.get("category", ["crypto"])[0]
                names = tuple(f"team-{i+1}" for i in range(n))
                res = run_competition_demo(category=cat, seed=1234,
                                           team_names=names, max_gen=6)
                return self._send(200, "application/json", json.dumps(res))

            self._send(200, "text/html", DASHBOARD.read_text(encoding="utf-8"))

    with socketserver.ThreadingTCPServer(("127.0.0.1", port), Handler) as httpd:
        print(f"AutoCTF-GAN dashboard: http://127.0.0.1:{port}  (Ctrl-C to stop)")
        httpd.serve_forever()


def main() -> None:
    import sys
    if "--fastapi" in sys.argv:
        import uvicorn  # pragma: no cover
        uvicorn.run(build_fastapi_app(), host="127.0.0.1", port=8080)
    else:
        serve_stdlib()


if __name__ == "__main__":
    main()
