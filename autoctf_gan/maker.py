"""Where the challenge-maker runs: in this process, or in a container.

`Competition` used to call `campaign.build()` directly, which meant the maker —
and `verify_spec`, which EXECUTES a generated solver — ran with the arena's own
process, filesystem and network. This is the seam that lets the same maker run
behind `docker run` instead, so the outer platform is left holding only the two
jobs it should have: take the upload, start the container.

Two backends, one contract:

    DockerMaker      one container per build, disposable, resource-capped
    InProcessMaker   the original path; the fallback when Docker is absent

`for_arena()` picks between them and says which it picked, because "the maker is
containerized" and "the maker fell back to running on the host" are very
different operational claims and the arena should never blur them.

### The network rule

A maker that only enumerates its catalogue needs no network and gets
`--network none`. A maker with a design brain must reach the model endpoint and
therefore cannot be fully disconnected. That is a genuine trade — an LLM in the
loop is egress in the loop — so it is decided explicitly here rather than
falling out of a default, and `describe()` reports which case is live.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from .campaign import Campaign, default_campaign
from .models import ChallengeSpec, Verdict

DEFAULT_IMAGE = os.environ.get("ARENA_MAKER_IMAGE", "autoctf-maker:latest")
BUILD_TIMEOUT_S = int(os.environ.get("ARENA_MAKER_TIMEOUT_S", "600"))
MAKER_MEMORY_MB = int(os.environ.get("ARENA_MAKER_MEMORY_MB", "2048"))

# Passed through to a maker container when the design brain is enabled. The key
# is an environment variable ON the container and never a field in a request, so
# it is not in the protocol, not in a spec, and not in an event log.
LLM_ENV_KEYS = ("OPENAI_API_KEY", "LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL",
                "LLM_TIMEOUT_S", "AUTOCTF_DESIGN")

# Probing an image costs a container start and never changes while it is running.
_CAPS_CACHE: dict[str, dict] = {}


@dataclass
class BuildResult:
    spec: ChallengeSpec
    verdict: Verdict | None = None       # set when the maker verified it itself
    backend: str = "inprocess"


class MakerError(RuntimeError):
    """The maker could not produce a challenge — the caller must not deploy one."""


# ---------------------------------------------------------------------------
# in-process
# ---------------------------------------------------------------------------
class InProcessMaker:
    backend = "inprocess"

    def __init__(self, campaign: Campaign | None = None, **campaign_kw):
        self.campaign = campaign or default_campaign(**campaign_kw)

    def capabilities(self) -> dict[str, Any]:
        from .service import capabilities
        return capabilities()

    def describe(self) -> dict[str, Any]:
        caps = self.capabilities()
        return {"backend": self.backend, "image": None,
                "network": "host process (not isolated)",
                "isolation": "none — the maker and verify_spec run in the arena process",
                "gcc": caps["gcc"], "fpylll": caps["fpylll"], "llm": caps["llm"]}

    def build(self, *, verify: bool = True, **kw) -> BuildResult:
        from .verify import verify_spec
        spec = self.campaign.build(**kw)
        verdict = verify_spec(spec) if verify else None
        return BuildResult(spec=spec, verdict=verdict, backend=self.backend)


# ---------------------------------------------------------------------------
# container
# ---------------------------------------------------------------------------
def docker_available() -> bool:
    if os.environ.get("ARENA_DISABLE_DOCKER"):
        return False
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=15).returncode == 0
    except Exception:
        return False


def image_available(image: str = DEFAULT_IMAGE) -> bool:
    try:
        return subprocess.run(["docker", "image", "inspect", image],
                              capture_output=True, timeout=30).returncode == 0
    except Exception:
        return False


class DockerMaker:
    backend = "docker"

    def __init__(self, campaign_kw: dict | None = None, image: str = DEFAULT_IMAGE,
                 timeout_s: int = BUILD_TIMEOUT_S):
        self.image = image
        self.timeout_s = timeout_s
        # The container builds its own campaign from these, so it probes ITS OWN
        # toolchain — which is the point: the image ships gcc even if the host
        # has none.
        self.campaign_kw = dict(campaign_kw or {})
        self._caps: dict[str, Any] | None = None
        self._campaign: Campaign | None = None

    @property
    def campaign(self) -> Campaign:
        """The host's view of the route, planned against the CONTAINER's toolchain.

        Probing the host here would be the wrong question and would show teams a
        route that does not match what the image will actually build.
        """
        if self._campaign is None:
            self._campaign = default_campaign(**self.campaign_kw,
                                              capabilities=self.capabilities())
        return self._campaign

    # ---- plumbing ----------------------------------------------------------
    def _needs_network(self) -> bool:
        design = self.campaign_kw.get("design") or os.getenv("AUTOCTF_DESIGN", "auto")
        if design == "catalog":
            return False
        return any(os.getenv(k) for k in ("OPENAI_API_KEY", "LLM_API_KEY"))

    def _command(self) -> list[str]:
        cmd = [
            "docker", "run", "--rm", "-i",
            "--memory", f"{MAKER_MEMORY_MB}m", "--memory-swap", f"{MAKER_MEMORY_MB}m",
            "--pids-limit", "512", "--cpus", "2",
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL",
            "--read-only",
            # verify_spec materializes artifacts and runs a solver; give it a
            # writable tmpfs rather than a writable image.
            "--tmpfs", "/work:rw,size=256m,mode=1777",
            "--tmpfs", "/tmp:rw,size=64m,mode=1777",
        ]
        if self._needs_network():
            for key in LLM_ENV_KEYS:
                value = os.getenv(key)
                if value:
                    cmd += ["-e", f"{key}={value}"]
        else:
            cmd += ["--network", "none"]
            if self.campaign_kw.get("design"):
                cmd += ["-e", f"AUTOCTF_DESIGN={self.campaign_kw['design']}"]
        cmd.append(self.image)
        return cmd

    def _call(self, request: dict, timeout_s: int | None = None) -> dict:
        try:
            proc = subprocess.run(
                self._command(), input=json.dumps(request).encode(),
                capture_output=True, timeout=timeout_s or self.timeout_s)
        except subprocess.TimeoutExpired as exc:
            raise MakerError(f"maker container timed out after "
                             f"{timeout_s or self.timeout_s}s") from exc
        except FileNotFoundError as exc:
            raise MakerError("docker is not installed on this host") from exc

        stdout = proc.stdout.decode("utf-8", "replace").strip()
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        if not stdout:
            raise MakerError(f"maker container produced no response "
                             f"(exit {proc.returncode}): {stderr[-400:]}")
        try:
            data = json.loads(stdout.splitlines()[-1])
        except json.JSONDecodeError as exc:
            raise MakerError(f"maker container response was not JSON: "
                             f"{stdout[-400:]}") from exc
        if not data.get("ok"):
            raise MakerError(data.get("error") or "maker container reported failure")
        return data

    # ---- contract ----------------------------------------------------------
    def capabilities(self) -> dict[str, Any]:
        """Cached per image: this costs a container start, and every match asks."""
        if self._caps is None:
            cached = _CAPS_CACHE.get(self.image)
            if cached is None:
                cached = self._call({"op": "capabilities"}, timeout_s=120)["capabilities"]
                _CAPS_CACHE[self.image] = cached
            self._caps = cached
        return self._caps

    def describe(self) -> dict[str, Any]:
        caps = self.capabilities()
        networked = self._needs_network()
        return {
            "backend": self.backend, "image": self.image,
            "network": "egress to the model endpoint" if networked else "none",
            "isolation": ("read-only rootfs, all capabilities dropped, "
                          "no-new-privileges, memory/pid/cpu capped"),
            "gcc": caps["gcc"], "fpylll": caps["fpylll"], "llm": caps["llm"],
            "note": ("the design brain needs egress, so this container is not "
                     "network-isolated" if networked else
                     "catalogue-only, so the container is fully disconnected"),
        }

    def build(self, *, verify: bool = True, **kw) -> BuildResult:
        request = {"op": "build", "verify": verify,
                   "campaign": self.campaign_kw, **kw}
        data = self._call(request)
        spec = ChallengeSpec.from_dict(data["spec"])
        verdict = None
        if data.get("verdict"):
            v = data["verdict"]
            verdict = Verdict(valid=bool(v["valid"]), reason=v.get("reason", ""),
                              poc_time_s=v.get("poc_time_s"),
                              checks=v.get("checks") or [],
                              failures=v.get("failures") or [])
        return BuildResult(spec=spec, verdict=verdict, backend=self.backend)


# ---------------------------------------------------------------------------
# selection
# ---------------------------------------------------------------------------
def for_arena(*, backend: str = "auto", image: str = DEFAULT_IMAGE,
              **campaign_kw) -> InProcessMaker | DockerMaker:
    """Pick a maker. `backend='docker'` refuses to fall back, so a deployment that
    requires containerization fails loudly instead of quietly running on the host.
    """
    if backend == "inprocess":
        return InProcessMaker(**campaign_kw)
    if backend == "docker":
        if not docker_available():
            raise MakerError("backend='docker' requested but no Docker daemon answered")
        if not image_available(image):
            raise MakerError(
                f"backend='docker' requested but image {image!r} is not built; run:\n"
                f"    docker build -t {image} -f Dockerfile.maker .")
        return DockerMaker(campaign_kw=campaign_kw, image=image)
    if docker_available() and image_available(image):
        return DockerMaker(campaign_kw=campaign_kw, image=image)
    return InProcessMaker(**campaign_kw)
