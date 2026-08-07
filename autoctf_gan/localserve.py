"""Local Flask process helpers — lets the `web` category verify and run an
attack/defense arena WITHOUT Docker (Flask is available; Docker often isn't).

Shared by web.py (solvability verify) and arena_bridge.py (attack/defense).
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def http(url: str, timeout: float = 5.0) -> str:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.read().decode(errors="replace")


def serve_flask(app_path: Path, flag: str, port: int) -> subprocess.Popen:
    """Launch `python app.py` with FLAG/PORT set; wait until it answers."""
    env = {**os.environ, "FLAG": flag, "PORT": str(port)}
    proc = subprocess.Popen([sys.executable, str(app_path)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(40):
        try:
            http(base + "/?name=ready")
            return proc
        except OSError:
            time.sleep(0.15)
    proc.terminate()
    raise RuntimeError("flask app did not become ready")
