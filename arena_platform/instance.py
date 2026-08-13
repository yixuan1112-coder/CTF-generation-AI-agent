"""Live challenge instances for service-style tracks (web).

A web (SSTI) challenge is not a bundle of files to read — it is a running
service to attack, with the flag injected as $FLAG at deploy time so it exists
nowhere the player can `cat`. To let an agent win it on merit the arena has to
stand up that service per match and let the agent reach it.

`WebInstance` is that instance broker. For one challenge it:

  * builds the challenge image from the spec's own artifacts (its Dockerfile +
    app.py), with the REAL flag baked in only here, never in player files;
  * creates a per-match `docker network create --internal` — kernel-enforced to
    have no route off the box, so a container on it can talk to its peers and
    to nothing else;
  * runs the challenge as a target container on that network, under the same
    hardening every arena container gets (dropped caps, non-root, memory/PID
    caps, no published host port);
  * waits until the service actually answers;
  * hands back the in-network URL the agent should attack;
  * and on exit tears the target, the network, and the built image back down.

The agent is attached to the same network (see sandbox.run_agent(network=...)),
so it reaches the target by container name over Docker's embedded DNS and can
reach nothing else. Only the docker backend can do this; there is no subprocess
fallback for a live instance.
"""
from __future__ import annotations

import subprocess
import time
import uuid
from dataclasses import dataclass

from .sandbox import DEFAULT_IMAGE


class InstanceError(RuntimeError):
    """Raised when a live instance cannot be built or started."""


def _docker(*args: str, timeout: int = 120, check: bool = True,
            cwd: str | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(["docker", *args], capture_output=True, text=True,
                          timeout=timeout, cwd=cwd)
    if check and proc.returncode != 0:
        raise InstanceError(f"docker {args[0]} failed: "
                            f"{(proc.stderr or proc.stdout).strip()[:300]}")
    return proc


@dataclass
class Instance:
    url: str          # what the agent attacks, e.g. http://arena-tgt-abcd:8000
    network: str      # the --internal network the agent must join
    target: str       # target container name/id (for diagnostics)


class WebInstance:
    """Context manager owning one challenge's target container and network."""

    def __init__(self, spec, *, memory_mb: int = 512, pids_limit: int = 256,
                 boot_timeout_s: int = 25):
        self.spec = spec
        self.memory_mb = memory_mb
        self.pids_limit = pids_limit
        self.boot_timeout_s = boot_timeout_s

        sfx = uuid.uuid4().hex[:12]
        self.network = f"arena-net-{sfx}"
        self.target = f"arena-tgt-{sfx}"
        self.tag = f"autoctf-live/{spec.slug}:{sfx}"
        self.port = int(spec.mechanics.get("build", {}).get("port", 8000))
        self._built = False
        self._net_made = False
        self._started = False

    # -- lifecycle ----------------------------------------------------------
    def __enter__(self) -> Instance:
        try:
            self._build_image()
            self._make_network()
            self._start_target()
            self._await_ready()
        except BaseException:
            self.close()
            raise
        return Instance(url=f"http://{self.target}:{self.port}",
                        network=self.network, target=self.target)

    def __exit__(self, *exc) -> None:
        self.close()

    # -- steps --------------------------------------------------------------
    def _build_image(self) -> None:
        import tempfile
        from pathlib import Path

        # The challenge's Dockerfile ships the deploy placeholder, never the real
        # flag — the flag arrives as -e FLAG at run time, below. Build only the
        # player artifacts; the official solver stays out of the target image.
        with tempfile.TemporaryDirectory(prefix="arena-live-build-") as tmp:
            root = Path(tmp)
            for rel, content in (self.spec.artifacts or {}).items():
                dest = root / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8")
            if not (root / "Dockerfile").is_file():
                raise InstanceError("challenge has no Dockerfile; cannot build a live instance")
            _docker("build", "-q", "-t", self.tag, ".", timeout=300, cwd=str(root))
            self._built = True

    def _make_network(self) -> None:
        # --internal: no gateway to the outside world. The agent joined here can
        # reach the target and nothing off-box. This is the isolation boundary.
        _docker("network", "create", "--internal", "--driver", "bridge",
                self.network, timeout=60)
        self._net_made = True

    def _start_target(self) -> None:
        _docker("run", "-d", "--rm",
                "--name", self.target,
                "--network", self.network,
                "--env", f"FLAG={self.spec.flag}",
                "--memory", f"{self.memory_mb}m", "--memory-swap", f"{self.memory_mb}m",
                "--pids-limit", str(self.pids_limit),
                "--cpus", "1.0",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                self.tag, timeout=90)
        self._started = True

    def _await_ready(self) -> None:
        # Probe from a peer container ON the network, exactly how the agent will
        # reach it — over Docker DNS to the target's name, not loopback. A
        # loopback-only probe would pass even for an app bound to 127.0.0.1,
        # which then refuses the agent's connection; this catches that.
        url = f"http://{self.target}:{self.port}/"
        probe = ("import urllib.request,sys;"
                 f"urllib.request.urlopen('{url}',timeout=2)")
        deadline = time.monotonic() + self.boot_timeout_s
        last = ""
        while time.monotonic() < deadline:
            proc = _docker("run", "--rm", "--network", self.network,
                           "--entrypoint", "python", DEFAULT_IMAGE, "-c", probe,
                           timeout=20, check=False)
            if proc.returncode == 0:
                return
            last = (proc.stderr or proc.stdout).strip()[-200:]
            time.sleep(1)
        raise InstanceError(f"target did not answer at {url} within "
                            f"{self.boot_timeout_s}s: {last}")

    def close(self) -> None:
        if self._started:
            _docker("stop", "-t", "2", self.target, timeout=30, check=False)
            self._started = False
        if self._net_made:
            _docker("network", "rm", self.network, timeout=30, check=False)
            self._net_made = False
        if self._built:
            _docker("rmi", "-f", self.tag, timeout=60, check=False)
            self._built = False
