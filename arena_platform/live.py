"""On-demand broker for live (Docker per-instance) challenges.

Unlike the static practice catalogue, a live challenge is a running service the
player attacks over the network. This broker stands one up per request:

  * builds the challenge image from `live_challenges/<name>/` (cached by tag),
  * generates a FRESH per-instance flag and injects it as `-e FLAG=` so it exists
    only in that container,
  * publishes the service on a host port from a fixed range, hardened (non-root,
    read-only rootfs, caps dropped, memory/PID/CPU capped),
  * hands back the connection string, and
  * reaps the instance when its TTL expires, when the team relaunches, or on stop.

Flags are per-instance; a submission is checked against the flag of the submitting
team's own instance, so a leaked flag from one player's box does not clear another.
Solves persist to a small JSON file so a restart keeps the scoreboard.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

PORT_RANGE = range(20000, 20050)
DEFAULT_TTL_S = 1800
MAX_INSTANCES = 24
NAME_PREFIX = "live-"


class LiveError(RuntimeError):
    pass


def _docker(*args, timeout=180, check=True):
    proc = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise LiveError(f"docker {args[0]}: {(proc.stderr or proc.stdout).strip()[:300]}")
    return proc


@dataclass
class Instance:
    id: str
    team_id: str
    challenge: str
    port: int
    flag_sha256: str
    container: str
    expires_at: float
    solved: bool = False


class LiveBroker:
    def __init__(self, data_dir, challenges_dir, public_host="", ttl_s=DEFAULT_TTL_S):
        self.data_dir = Path(data_dir)
        self.challenges_dir = Path(challenges_dir)
        self.public_host = public_host or os.environ.get("ARENA_PUBLIC_HOST", "")
        self.ttl_s = ttl_s
        self._lock = threading.RLock()
        self._instances: dict[str, Instance] = {}
        self._solves_path = self.data_dir / "live_solves.json"
        self._solves = self._load_solves()
        self.challenges = self._discover()
        self._enabled = self._docker_ok()
        if self._enabled:
            self._cleanup_orphans()
            threading.Thread(target=self._reaper, daemon=True).start()

    # -- discovery ----------------------------------------------------------
    def _discover(self):
        out = {}
        if not self.challenges_dir.is_dir():
            return out
        for d in sorted(self.challenges_dir.iterdir()):
            if not d.is_dir() or not (d / "Dockerfile").is_file():
                continue
            readme = (d / "README.md").read_text(encoding="utf-8") if (d / "README.md").is_file() else ""
            title = readme.splitlines()[0].lstrip("# ").strip() if readme else d.name
            desc = ""
            for para in readme.split("\n\n")[1:]:
                if para.strip():
                    desc = " ".join(para.split())[:400]
                    break
            conn = "http" if "http" in title.lower() else "tcp"
            out[d.name] = {"name": d.name, "title": title, "desc": desc,
                           "dir": str(d), "conn": conn}
        return out

    def _docker_ok(self):
        try:
            _docker("version", timeout=10)
            return True
        except Exception:
            return False

    # -- solves persistence -------------------------------------------------
    def _load_solves(self):
        try:
            return json.loads(self._solves_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            return {}

    def _save_solves(self):
        try:
            self._solves_path.write_text(json.dumps(self._solves), encoding="utf-8")
        except OSError:
            pass

    # -- lifecycle ----------------------------------------------------------
    def _cleanup_orphans(self):
        try:
            proc = _docker("ps", "-aq", "--filter", f"name={NAME_PREFIX}", check=False)
            ids = [x for x in proc.stdout.split() if x]
            if ids:
                _docker("kill", *ids, check=False, timeout=60)
        except Exception:
            pass

    def _reaper(self):
        while True:
            time.sleep(15)
            now = time.time()
            with self._lock:
                dead = [i for i in self._instances.values() if i.expires_at <= now]
            for inst in dead:
                self._kill(inst)

    def _kill(self, inst: Instance):
        _docker("kill", inst.container, check=False, timeout=30)
        with self._lock:
            self._instances.pop(inst.id, None)

    def _free_port(self):
        used = {i.port for i in self._instances.values()}
        for p in PORT_RANGE:
            if p not in used:
                return p
        raise LiveError("no free instance port; the board is at capacity")

    def _image_for(self, challenge):
        tag = f"live-{challenge}:latest"
        proc = _docker("images", "-q", tag, check=False)
        if not proc.stdout.strip():
            _docker("build", "-q", "-t", tag, self.challenges[challenge]["dir"], timeout=300)
        return tag

    # -- public API ---------------------------------------------------------
    def list_challenges(self):
        return [{"name": c["name"], "title": c["title"], "desc": c["desc"],
                 "conn": c["conn"]} for c in self.challenges.values()]

    def launch(self, team_id, challenge):
        if not self._enabled:
            raise LiveError("live instances need a Docker backend, which is not available here")
        if challenge not in self.challenges:
            raise LiveError("unknown live challenge")
        with self._lock:
            # one instance per team per challenge: replace an existing one
            for inst in [i for i in self._instances.values()
                         if i.team_id == team_id and i.challenge == challenge]:
                self._kill(inst)
            if len(self._instances) >= MAX_INSTANCES:
                raise LiveError("the live board is at capacity; try again shortly")
            port = self._free_port()
        image = self._image_for(challenge)
        flag = "flag{" + secrets.token_hex(10) + "}"
        cid = uuid.uuid4().hex[:12]
        container = f"{NAME_PREFIX}{challenge}-{cid}"
        _docker(
            "run", "-d", "--rm", "--name", container,
            "-e", f"FLAG={flag}", "-e", "PORT=9000",
            "-p", f"0.0.0.0:{port}:9000",
            "--memory", "128m", "--memory-swap", "128m", "--pids-limit", "128",
            "--cpus", "0.5", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m",
            image, timeout=60)
        inst = Instance(id=cid, team_id=team_id, challenge=challenge, port=port,
                        flag_sha256=hashlib.sha256(flag.encode()).hexdigest(),
                        container=container, expires_at=time.time() + self.ttl_s)
        with self._lock:
            self._instances[cid] = inst
        return self._public(inst)

    def stop(self, team_id, instance_id):
        with self._lock:
            inst = self._instances.get(instance_id)
            if not inst or inst.team_id != team_id:
                raise LiveError("no such instance")
        self._kill(inst)
        return {"stopped": instance_id}

    def instances_for(self, team_id):
        with self._lock:
            return [self._public(i) for i in self._instances.values() if i.team_id == team_id]

    def submit(self, team_id, instance_id, flag):
        with self._lock:
            inst = self._instances.get(instance_id)
            if not inst or inst.team_id != team_id:
                raise LiveError("no such instance; launch one first")
            correct = hashlib.sha256(flag.strip().encode()).hexdigest() == inst.flag_sha256
            first = False
            if correct:
                inst.solved = True
                key = str(team_id)
                solved = set(self._solves.get(key, []))
                first = inst.challenge not in solved
                solved.add(inst.challenge)
                self._solves[key] = sorted(solved)
                self._save_solves()
        if correct:
            self._save_solves()
        return {"correct": correct, "first_time": first}

    def solved_by(self, team_id):
        return list(self._solves.get(str(team_id), []))

    def _public(self, inst: Instance):
        host = self.public_host or "127.0.0.1"
        conn = self.challenges.get(inst.challenge, {}).get("conn", "tcp")
        connect = (f"http://{host}:{inst.port}/" if conn == "http"
                   else f"nc {host} {inst.port}")
        return {"instance_id": inst.id, "challenge": inst.challenge,
                "host": host, "port": inst.port, "conn": conn, "connect": connect,
                "expires_in": max(0, int(inst.expires_at - time.time())),
                "solved": inst.solved}
