"""The three ways a real team gets its agent into a match.

  upload  — a .py file or a .zip of a package. The platform stores it and runs it
            per generation inside `sandbox.run_agent`. Same hardware for everyone,
            so wall-clock tiebreaks are fair.
  image   — a Docker image the team built and `docker save`d. The platform loads
            it and runs matches in the team's own container, so the team picks
            the interpreter and the libraries while the arena still supplies the
            hardware and the limits. Times stay comparable; see `images.py` for
            the intake and its threat model.
  remote  — the team runs the agent on their own box (sage, GPUs, a private LLM)
            and registers an HTTPS endpoint. The platform POSTs the challenge and
            reads a flag back. Fair on depth, not on speed — the leaderboard
            labels these rows so nobody is misled.

All three produce the same `sandbox.AgentRun`, so `runner.py` does not care which
is which.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from .sandbox import AgentRun, Limits, run_agent

MAX_UPLOAD_BYTES = 8 * 1024 * 1024        # 8 MB of source is a very large agent
MAX_ZIP_MEMBERS = 2000
MAX_UNPACKED_BYTES = 32 * 1024 * 1024
SAFE_NAME = re.compile(r"^[A-Za-z0-9._ -]{1,120}$")


# ---------------------------------------------------------------------------
# upload intake
# ---------------------------------------------------------------------------
class UploadError(ValueError):
    """A submission the platform refuses to store, with a player-readable reason."""


def _safe_member(name: str) -> bool:
    if name.startswith("/") or ".." in Path(name).parts:
        return False
    return not name.startswith("__MACOSX/")


def store_upload(root: Path | str, team_id: str, agent_id: str,
                 filename: str, blob: bytes) -> dict:
    """Validate and unpack a submission. Returns {dir, entry, sha256, size_bytes}."""
    if not blob:
        raise UploadError("the uploaded file is empty")
    if len(blob) > MAX_UPLOAD_BYTES:
        raise UploadError(f"submission is {len(blob) // 1024} KB; the limit is "
                          f"{MAX_UPLOAD_BYTES // 1024} KB")
    filename = os.path.basename(filename or "agent.py")
    if not SAFE_NAME.match(filename):
        raise UploadError("file name must be letters, digits, dot, dash, space or underscore")

    dest = Path(root) / team_id / agent_id
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    if filename.lower().endswith(".py"):
        (dest / "agent.py").write_bytes(blob)
        entry = "agent.py"
    elif filename.lower().endswith(".zip"):
        entry = _unpack_zip(blob, dest)
    else:
        raise UploadError("upload a single .py file or a .zip archive")

    _reject_compiled_only(dest)
    return {"dir": str(dest), "entry": entry, "sha256": hashlib.sha256(blob).hexdigest(),
            "size_bytes": len(blob)}


def _unpack_zip(blob: bytes, dest: Path) -> str:
    import io
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as exc:
        raise UploadError(f"not a readable zip archive: {exc}") from exc

    members = [m for m in zf.infolist() if not m.is_dir()]
    if len(members) > MAX_ZIP_MEMBERS:
        raise UploadError(f"archive has {len(members)} files; the limit is {MAX_ZIP_MEMBERS}")
    total = sum(m.file_size for m in members)
    if total > MAX_UNPACKED_BYTES:
        raise UploadError(f"archive expands to {total // 1024} KB; the limit is "
                          f"{MAX_UNPACKED_BYTES // 1024} KB (zip-bomb guard)")

    for m in members:
        if not _safe_member(m.filename):
            raise UploadError(f"unsafe path in archive: {m.filename}")
        target = dest / m.filename
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(m) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out, length=64 * 1024)

    # Entry point: agent.py at the root, else the only top-level .py, else fail.
    if (dest / "agent.py").exists():
        return "agent.py"
    roots = sorted(p for p in dest.glob("*.py"))
    if len(roots) == 1:
        return roots[0].name
    nested = sorted(dest.glob("*/agent.py"))
    if len(nested) == 1:
        # A zip of a folder — flatten one level so the entry point sits at the root.
        inner = nested[0].parent
        for item in list(inner.iterdir()):
            shutil.move(str(item), str(dest / item.name))
        inner.rmdir()
        return "agent.py"
    raise UploadError("archive must contain agent.py at its top level")


def _reject_compiled_only(dest: Path) -> None:
    if not any(dest.rglob("*.py")):
        raise UploadError("no Python source found in the submission")


# ---------------------------------------------------------------------------
# remote endpoint validation
# ---------------------------------------------------------------------------
def _is_private(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True                      # unresolvable: treat as unsafe
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return True
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return True
    return False


def validate_remote_url(url: str) -> str:
    """Reject anything that would turn the arena into an SSRF proxy."""
    url = (url or "").strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UploadError("remote agent URL must start with http:// or https://")
    if not parsed.hostname:
        raise UploadError("remote agent URL has no host")
    if os.environ.get("ARENA_BLOCK_PRIVATE_REMOTE") == "1" and _is_private(parsed.hostname):
        raise UploadError("this server only accepts remote agents on public addresses; "
                          "expose your endpoint publicly or upload the agent instead")
    return url


# ---------------------------------------------------------------------------
# clients
# ---------------------------------------------------------------------------
class SandboxAgent:
    kind = "upload"

    def __init__(self, agent_dir: str, entry: str, limits: Limits, backend: str = "auto"):
        self.agent_dir, self.entry, self.limits, self.backend = agent_dir, entry, limits, backend

    def attempt(self, challenge: dict, *, network: str = "") -> AgentRun:
        return run_agent(self.agent_dir, self.entry, challenge, self.limits,
                         backend=self.backend, network=network)


class ImageAgent:
    """The team's own container, started fresh for every rung, like every other
    agent. No host code is staged in — `sandbox.run_agent` points the harness at
    `/opt/agent` inside the image instead."""

    kind = "image"

    def __init__(self, image_ref: str, entry: str, limits: Limits):
        self.image_ref, self.entry, self.limits = image_ref, entry, limits

    def attempt(self, challenge: dict, *, network: str = "") -> AgentRun:
        if not self.image_ref:
            return AgentRun(ok=False, backend="docker",
                            error="this agent's image is no longer on the arena host "
                                  "(each team keeps only its most recent image) — "
                                  "resubmit it to run another match")
        return run_agent(None, self.entry, challenge, self.limits,
                         image=self.image_ref, network=network)


class RemoteAgent:
    kind = "remote"

    def __init__(self, url: str, token: str = "", timeout: int = 120):
        self.url, self.token, self.timeout = url, token, timeout

    def attempt(self, challenge: dict, *, network: str = "") -> AgentRun:
        if network:
            # A remote agent runs off-box; it cannot join the arena's --internal
            # instance network, so it can never reach a web target. Fail clearly
            # rather than hand it a URL it cannot route to.
            return AgentRun(ok=False, backend="remote",
                            error="remote agents cannot play the web track — its "
                                  "target lives on an internal network only an "
                                  "uploaded or image agent can join")
        body = json.dumps({
            "challenge_id": challenge.get("challenge_id"),
            "gen": challenge.get("gen"),
            "category": challenge.get("category"),
            "title": challenge.get("title"),
            "story": challenge.get("story"),
            "hints": challenge.get("hints") or [],
            "files": challenge.get("files") or {},
            "target_url": challenge.get("target_url"),
            "time_limit_s": self.timeout,
        }).encode()
        req = urllib.request.Request(self.url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "AutoCTF-Arena/1.0")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")

        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read(1 << 20).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return AgentRun(ok=False, backend="remote",
                            seconds=round(time.monotonic() - started, 3),
                            error=f"remote agent returned HTTP {exc.code}",
                            stderr=(exc.read(4096).decode('utf-8', 'replace')
                                    if hasattr(exc, "read") else ""))
        except Exception as exc:
            return AgentRun(ok=False, backend="remote",
                            seconds=round(time.monotonic() - started, 3),
                            error=f"could not reach remote agent: {type(exc).__name__}: {exc}")

        elapsed = round(time.monotonic() - started, 3)
        flag = None
        try:
            data = json.loads(raw)
            flag = data.get("flag") if isinstance(data, dict) else None
        except json.JSONDecodeError:
            flag = raw.strip() or None       # a bare flag string is accepted too
        if flag is not None and not isinstance(flag, str):
            return AgentRun(ok=False, backend="remote", seconds=elapsed,
                            error="remote agent's \"flag\" field must be a string or null")
        return AgentRun(ok=True, flag=(flag.strip()[:512] if flag else None),
                        seconds=elapsed, backend="remote", stdout=raw[:2000])


def build_client(agent_row: dict, limits: Limits, backend: str = "auto"):
    if agent_row["kind"] == "remote":
        return RemoteAgent(agent_row["remote_url"], agent_row.get("remote_token", ""),
                           timeout=limits.wall_seconds)
    if agent_row["kind"] == "image":
        return ImageAgent(agent_row.get("image_ref") or "",
                          agent_row.get("entry") or "agent.py", limits)
    return SandboxAgent(agent_row["source_dir"], agent_row.get("entry") or "agent.py",
                        limits, backend=backend)
