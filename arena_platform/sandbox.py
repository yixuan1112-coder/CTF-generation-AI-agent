"""Runs an untrusted, team-supplied agent against one challenge instance.

Threat model: the uploaded code is hostile. It must not read the organizer's
files, reach the network, exhaust the host, or outlive its match.

Two backends, same contract:

  * docker  — used automatically when a Docker daemon answers. `--network none`,
              memory/PID/CPU caps, read-only agent mount, non-root user. This is
              the real isolation boundary and the recommended production setup.
  * subprocess — the portable fallback (and what runs on a plain WSL/macOS box).
              The child sets its own hard rlimits before any agent code is
              imported, runs in `start_new_session` so the whole group can be
              killed, sees a scrubbed environment, and gets a network-namespace
              via `unshare -rn` when the kernel allows unprivileged user
              namespaces. Where unshare is unavailable the harness still removes
              the socket API, which stops accidental and casual egress but is not
              a kernel-enforced boundary — see ARENA.md.

Two places the agent's code can live:

  * on the host — a .py/.zip the team uploaded, copied into the work dir as
                  `agent/` and imported from there. This is the default.
  * in the image — a team-supplied Docker image carrying its own `/opt/agent`.
                  Nothing is copied in; `ARENA_AGENT_DIR` points the harness at
                  the in-image path instead. Image agents are docker-only: there
                  is no subprocess fallback, because without the container the
                  agent's code is not present on the host at all.

Either way the run flags below are applied at `docker run` time, so an image
cannot opt out of them — a team's USER, ENTRYPOINT and CMD are all overridden.

The agent never receives the flag, the solver, or the spec. It receives exactly
what a human player would download.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

MAX_OUTPUT_CHARS = 8000
DEFAULT_IMAGE = os.environ.get("ARENA_DOCKER_IMAGE", "autoctf-arena-agent:latest")

# Where a team-supplied image must keep its agent. Absolute, so it cannot be
# confused with the ./agent directory an uploaded agent is staged into, and
# fixed, so the contract is one sentence long rather than a configuration
# option every competitor has to get right.
IMAGE_AGENT_DIR = "/opt/agent"


@dataclass
class Limits:
    wall_seconds: int = 120
    cpu_seconds: int = 120
    memory_mb: int = 2048
    max_file_mb: int = 64
    max_processes: int = 256
    allow_network: bool = False


@dataclass
class AgentRun:
    ok: bool
    flag: str | None = None
    seconds: float = 0.0
    error: str = ""
    stdout: str = ""
    stderr: str = ""
    backend: str = "subprocess"
    exit_code: int | None = None
    limits_hit: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# capability probes (cached — they shell out)
# ---------------------------------------------------------------------------
_probe_cache: dict[str, bool] = {}


def _probe(key: str, cmd: list[str]) -> bool:
    if key not in _probe_cache:
        try:
            _probe_cache[key] = subprocess.run(
                cmd, capture_output=True, timeout=15).returncode == 0
        except Exception:
            _probe_cache[key] = False
    return _probe_cache[key]


def docker_available() -> bool:
    if os.environ.get("ARENA_DISABLE_DOCKER"):
        return False
    return _probe("docker", ["docker", "info"])


def unshare_available() -> bool:
    return _probe("unshare", ["unshare", "-rn", "true"])


def loopback_available() -> bool:
    """Can we bring `lo` up inside the namespace?

    A fresh netns ships loopback DOWN. Binding still succeeds, but connecting
    does not — so without this an agent can start a local target and then fail
    to talk to it, which is exactly the web track's workflow.
    """
    if not unshare_available():
        return False
    return _probe("unshare_lo", [
        "unshare", "-rn", "--", "sh", "-c",
        "ip link set lo up 2>/dev/null && python3 -c "
        "'import socket,threading;"
        "s=socket.socket();s.bind((\"127.0.0.1\",0));s.listen(1);"
        "c=socket.create_connection(s.getsockname(),2);c.close()'"])


def backend_report() -> dict:
    """What isolation this host can actually deliver — surfaced in the UI."""
    docker = docker_available()
    unshare = unshare_available()
    return {
        "backend": "docker" if docker else "subprocess",
        "docker": docker,
        "network_namespace": docker or unshare,
        "strength": "strong" if docker else ("medium" if unshare else "basic"),
        "loopback": docker or loopback_available(),
        "note": ("Docker container with --network none: loopback works, "
                 "off-box traffic cannot leave."
                 if docker else
                 "Kernel network namespace: loopback works, off-box traffic "
                 "cannot leave."
                 if unshare else
                 "No kernel namespace on this host, so the socket API is removed "
                 "entirely — that also blocks loopback. Run behind Docker for "
                 "public submissions."),
    }


# ---------------------------------------------------------------------------
# the in-sandbox harness
# ---------------------------------------------------------------------------
HARNESS = r'''
"""Trusted harness. Applies limits, loads the team agent, calls it, records the
result. Runs INSIDE the sandbox, before any agent code is imported."""
import json, os, resource, sys, time, traceback

LIM = json.loads(os.environ["ARENA_LIMITS"])
MB = 1024 * 1024

def _cap(what, soft, hard=None):
    hard = soft if hard is None else hard
    try:
        cur_s, cur_h = resource.getrlimit(what)
        if cur_h != resource.RLIM_INFINITY:
            soft, hard = min(soft, cur_h), min(hard, cur_h)
        resource.setrlimit(what, (soft, hard))
    except (ValueError, OSError):
        pass

# Both soft AND hard, so agent code cannot raise them back.
_cap(resource.RLIMIT_CPU, LIM["cpu_seconds"])
_cap(resource.RLIMIT_FSIZE, LIM["max_file_mb"] * MB)
_cap(resource.RLIMIT_CORE, 0)
if not LIM.get("skip_as_limit"):
    _cap(resource.RLIMIT_AS, LIM["memory_mb"] * MB)
try:
    _cap(resource.RLIMIT_NPROC, LIM["max_processes"])
except Exception:
    pass

# Only when there is NO kernel network namespace. With one, the kernel already
# blocks egress while leaving loopback usable — and loopback is not a loophole,
# it is how you solve a web challenge: boot the target app locally and exploit
# it. Removing the socket API wholesale would make that track unsolvable.
if LIM.get("socket_guard"):
    import socket
    class _Blocked(OSError):
        pass
    def _deny(*a, **k):
        raise _Blocked("network access is disabled inside the arena sandbox")
    for _name in ("socket", "socketpair", "create_connection", "create_server",
                  "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        if hasattr(socket, _name):
            setattr(socket, _name, _deny)
    sys.modules.pop("urllib.request", None)

RESULT = {"ok": False, "flag": None, "seconds": 0.0, "error": "", "traceback": ""}
started = time.monotonic()
try:
    payload = json.load(open("_input.json", encoding="utf-8"))
    entry = os.environ["ARENA_ENTRY"]

    # HOME points at a scratch dir, so Python cannot derive the real user
    # site-packages itself. The parent resolved them and passes them here, or a
    # `pip install --user` host would offer agents no crypto libraries at all.
    for _site in json.loads(os.environ.get("ARENA_SITE", "[]")):
        if os.path.isdir(_site) and _site not in sys.path:
            sys.path.append(_site)

    import importlib.util
    # Uploaded agents are staged into ./agent inside the work dir. An agent that
    # ships as a Docker image is never copied anywhere — its code already sits at
    # an absolute path inside the container, and ARENA_AGENT_DIR points here.
    agent_dir = os.path.abspath(os.environ.get("ARENA_AGENT_DIR") or "agent")
    if not os.path.isdir(agent_dir):
        raise FileNotFoundError(f"agent directory {agent_dir!r} does not exist")
    sys.path.insert(0, agent_dir)
    spec = importlib.util.spec_from_file_location("team_agent_module",
                                                  os.path.join(agent_dir, entry))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load agent entry point {entry!r}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    fn = getattr(module, "solve", None)
    if not callable(fn):
        raise AttributeError(
            f"{entry} must define a callable solve(); found {type(fn).__name__}")

    # Accept solve(files), solve(files, meta) and solve(challenge=...) shapes.
    import inspect
    try:
        positional = [p for p in inspect.signature(fn).parameters.values()
                      if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
        arity = len(positional)
    except (TypeError, ValueError):
        arity = 1

    meta = {k: v for k, v in payload.items() if k != "files"}
    flag = fn(payload["files"], meta) if arity >= 2 else fn(payload["files"])

    RESULT["seconds"] = round(time.monotonic() - started, 3)
    if flag is None:
        RESULT.update(ok=True, flag=None)
    elif isinstance(flag, str):
        RESULT.update(ok=True, flag=flag.strip()[:512])
    else:
        RESULT.update(ok=False, error=f"solve() returned {type(flag).__name__}, "
                                      "expected str or None")
except MemoryError:
    RESULT.update(ok=False, error="agent exceeded the memory limit",
                  seconds=round(time.monotonic() - started, 3))
except BaseException as exc:
    RESULT.update(ok=False, error=f"{type(exc).__name__}: {exc}"[:500],
                  traceback=traceback.format_exc()[-2000:],
                  seconds=round(time.monotonic() - started, 3))

with open("_result.json", "w", encoding="utf-8") as fh:
    json.dump(RESULT, fh)
'''


def _clip(text: str) -> str:
    text = text or ""
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + f"\n… [{len(text) - MAX_OUTPUT_CHARS} more chars truncated]"


def _stage(work: Path, agent_dir: Path | None, entry: str, challenge: dict,
           limits: Limits) -> None:
    """Lay out the sandbox: agent code, player files, harness, input payload.

    `agent_dir` is None for an image agent — its code is already inside the
    container, so there is nothing to copy and nothing to verify here. The
    equivalent check ran once at submission time (`images.probe_image`).
    """
    if agent_dir is not None:
        dest = work / "agent"
        shutil.copytree(agent_dir, dest, dirs_exist_ok=True)
        if not (dest / entry).exists():
            raise FileNotFoundError(f"agent entry point {entry!r} not found in submission")

    files = dict(challenge.get("files") or {})
    player = work / "challenge"
    player.mkdir(exist_ok=True)
    for name, content in files.items():
        target = (player / name).resolve()
        if not str(target).startswith(str(player.resolve())):
            continue                            # never let a filename escape the dir
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    payload = {k: challenge.get(k) for k in
               ("challenge_id", "gen", "category", "title", "story", "hints")}
    payload["files"] = files
    # Service-style tracks (web) hand the agent a live target to attack instead
    # of a flag hidden in the files. Only present for those; None otherwise.
    if challenge.get("target_url"):
        payload["target_url"] = challenge["target_url"]
    payload["time_limit_s"] = limits.wall_seconds
    (work / "_input.json").write_text(json.dumps(payload), encoding="utf-8")
    (work / "_harness.py").write_text(HARNESS, encoding="utf-8")


def host_site_dirs() -> list[str]:
    """Import paths agents are allowed to use — whatever this host has installed.

    Every team gets the same list, so it is a level field: if the operator
    installs pycryptodome and fpylll, everyone may use them.
    """
    import site
    dirs: list[str] = []
    try:
        dirs.extend(site.getsitepackages())
    except AttributeError:                    # some virtualenv layouts
        pass
    try:
        user = site.getusersitepackages()
        if isinstance(user, str):
            dirs.append(user)
    except Exception:
        pass
    dirs.extend(p for p in sys.path if p.endswith(("site-packages", "dist-packages")))
    seen, unique = set(), []
    for d in dirs:
        if d and d not in seen and os.path.isdir(d):
            seen.add(d)
            unique.append(d)
    return unique


# Libraries worth telling competitors about. Presence is probed, not assumed —
# the arena advertises what this host actually offers, nothing more.
NOTABLE_LIBRARIES = (
    ("pycryptodome", "Crypto"), ("sympy", "sympy"), ("fpylll", "fpylll"),
    ("gmpy2", "gmpy2"), ("numpy", "numpy"), ("requests", "requests"),
    ("pwntools", "pwn"), ("z3-solver", "z3"), ("sage", "sage"),
    ("flask", "flask"), ("pycparser", "pycparser"),
)

_library_cache: list[str] | None = None


def available_libraries() -> list[str]:
    """Which notable libraries an uploaded agent can import here."""
    global _library_cache
    if _library_cache is None:
        import importlib.util
        found = []
        for label, module in NOTABLE_LIBRARIES:
            try:
                if importlib.util.find_spec(module) is not None:
                    found.append(label)
            except (ImportError, ValueError):
                continue
        _library_cache = found
    return list(_library_cache)


def _child_env(entry: str, limits: Limits, *, netns: bool = False,
               agent_dir_in_image: str | None = None) -> dict[str, str]:
    """A scrubbed environment — no API keys, no host paths, no repo on sys.path."""
    keep = ("PATH", "LANG", "LC_ALL", "TZ", "HOME", "TMPDIR")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env["HOME"] = env.get("TMPDIR", "/tmp")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["ARENA_ENTRY"] = entry
    if agent_dir_in_image:
        env["ARENA_AGENT_DIR"] = agent_dir_in_image
    # Host site-packages are the *host's* paths. They mean nothing inside a
    # team's own image — that image brings its own interpreter and its own
    # libraries, which is the entire point of submitting one.
    env["ARENA_SITE"] = json.dumps([] if agent_dir_in_image else host_site_dirs())
    env["ARENA_LIMITS"] = json.dumps({
        "cpu_seconds": limits.cpu_seconds,
        "memory_mb": limits.memory_mb,
        "max_file_mb": limits.max_file_mb,
        "max_processes": limits.max_processes,
        "allow_network": limits.allow_network,
        # Coarse socket removal is the fallback for hosts with no namespace
        # support; where the kernel enforces it we leave loopback alone.
        "socket_guard": not limits.allow_network and not netns,
        # RLIMIT_AS breaks any library that reserves large virtual arenas; the
        # container path caps real memory properly, so skip the VA cap there.
        "skip_as_limit": False,
    })
    return env


def _collect(work: Path, proc_rc: int | None, out: str, err: str,
             elapsed: float, backend: str, limits_hit: list[str]) -> AgentRun:
    result_path = work / "_result.json"
    if result_path.exists():
        try:
            data = json.loads(result_path.read_text(encoding="utf-8"))
        except Exception:
            data = {"ok": False, "error": "agent result file was corrupt"}
        detail = data.get("traceback") or ""
        return AgentRun(ok=bool(data.get("ok")), flag=data.get("flag"),
                        seconds=float(data.get("seconds") or elapsed),
                        error=data.get("error", ""), stdout=_clip(out),
                        stderr=_clip((err + "\n" + detail).strip()),
                        backend=backend, exit_code=proc_rc, limits_hit=limits_hit)
    reason = "agent produced no result"
    if limits_hit:
        reason = f"agent stopped: {', '.join(limits_hit)}"
    elif proc_rc in (-9, -24, 137, 152):
        # SIGKILL/SIGXCPU: the kernel enforced RLIMIT_CPU or the memory cap.
        reason = "agent killed by the resource limiter (CPU or memory cap reached)"
        limits_hit = [*limits_hit, "cpu/memory limit"]
    elif proc_rc not in (0, None):
        reason = f"agent process exited with code {proc_rc}"
    return AgentRun(ok=False, flag=None, seconds=elapsed, error=reason,
                    stdout=_clip(out), stderr=_clip(err), backend=backend,
                    exit_code=proc_rc, limits_hit=limits_hit)


def _run_subprocess(work: Path, entry: str, limits: Limits) -> AgentRun:
    # -E ignores PYTHONPATH/PYTHONHOME so the environment cannot inject imports;
    # -B keeps agent bytecode off disk. Deliberately NOT -I: that implies -s,
    # which hides user site-packages — on a `pip install --user` host that means
    # no pycryptodome, no sympy, no fpylll, and a crypto arena where nobody can
    # reach the lattice rung. sys.path[0] is this temp work dir either way, so
    # the repository stays unimportable.
    cmd = [sys.executable, "-E", "-B", "_harness.py"]
    limits_hit: list[str] = []
    netns = not limits.allow_network and unshare_available()
    if netns:
        # Kernel-enforced: the namespace has loopback and nothing else, so an
        # agent may run a local target but cannot reach off-box. `lo` ships DOWN
        # in a fresh namespace, so raise it first — otherwise connecting to your
        # own server fails and the web track becomes unsolvable.
        cmd = ["unshare", "-rn", "--", "sh", "-c",
               'ip link set lo up 2>/dev/null; exec "$0" "$@"', *cmd]

    started = time.monotonic()
    proc = subprocess.Popen(cmd, cwd=work, env=_child_env(entry, limits, netns=netns),
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, errors="replace",
                            start_new_session=True)
    try:
        out, err = proc.communicate(timeout=limits.wall_seconds)
    except subprocess.TimeoutExpired:
        limits_hit.append(f"wall-clock timeout after {limits.wall_seconds}s")
        _kill_group(proc)
        out, err = proc.communicate()
    elapsed = round(time.monotonic() - started, 3)
    return _collect(work, proc.returncode, out or "", err or "", elapsed,
                    "subprocess", limits_hit)


def _kill_group(proc: subprocess.Popen) -> None:
    """Kill the agent and anything it spawned."""
    for sig in ("SIGKILL",):
        try:
            os.killpg(os.getpgid(proc.pid), getattr(__import__("signal"), sig))
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except Exception:
                pass


def docker_run_argv(work: Path, env: dict[str, str], limits: Limits,
                    image: str, network: str = "") -> list[str]:
    """The confinement flags every container the arena starts is subject to.

    Shared with `images.probe_image` so a team's image is validated under exactly
    the conditions it will later compete under — a probe that ran with looser
    flags would accept images that then fail every match.

    `--entrypoint python` is what makes a team-supplied image safe to command: a
    bare `docker run IMAGE python …` appends those words as *arguments* to
    whatever ENTRYPOINT the image declared, so an image with its own entrypoint
    would run that instead of the harness. Overriding it means the image's
    ENTRYPOINT, CMD and USER are all ignored.

    `network` joins the agent to a specific network — used for the web track,
    where the agent must reach a live target. That network is created
    `--internal` (see instance.WebInstance), so the agent can talk to the target
    and nothing off-box. With no network given the agent gets `--network none`.
    """
    net = network or ("none" if not limits.allow_network else "bridge")
    argv = [
        "docker", "run", "--rm", "-i",
        "--network", net,
        "--memory", f"{limits.memory_mb}m", "--memory-swap", f"{limits.memory_mb}m",
        "--pids-limit", str(limits.max_processes),
        "--cpus", "1.0",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{work}:/work",
        "-w", "/work",
        "--entrypoint", "python",
    ]
    for key in ("ARENA_ENTRY", "ARENA_LIMITS", "ARENA_AGENT_DIR"):
        if key in env:
            argv += ["-e", f"{key}={env[key]}"]
    argv += ["-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "HOME=/tmp"]
    return argv + [image, "-E", "-B", "_harness.py"]


def _run_docker(work: Path, entry: str, limits: Limits, *,
                image: str = DEFAULT_IMAGE,
                agent_dir_in_image: str | None = None,
                network: str = "") -> AgentRun:
    # netns=True whenever the agent has a namespace (always, under docker): that
    # keeps the coarse socket_guard off so the agent may use loopback and, on a
    # web instance network, reach the target. Egress is stopped by the network
    # (--network none, or the --internal instance net), not by removing sockets.
    env = _child_env(entry, limits, netns=True,
                     agent_dir_in_image=agent_dir_in_image)
    env["ARENA_LIMITS"] = json.dumps({**json.loads(env["ARENA_LIMITS"]),
                                      "skip_as_limit": True})
    cmd = docker_run_argv(work, env, limits, image, network)
    limits_hit: list[str] = []
    started = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=limits.wall_seconds + 20)
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        limits_hit.append(f"wall-clock timeout after {limits.wall_seconds}s")
        rc, out, err = None, exc.stdout or "", exc.stderr or ""
    elapsed = round(time.monotonic() - started, 3)
    return _collect(work, rc, out, err, elapsed, "docker", limits_hit)


def run_agent(agent_dir: Path | str | None, entry: str, challenge: dict,
              limits: Limits | None = None, *, backend: str = "auto",
              image: str = "", agent_dir_in_image: str = "",
              network: str = "") -> AgentRun:
    """Execute one solve attempt. Never raises on agent misbehaviour.

    Pass `image` (and `agent_dir_in_image`) to run the team's own container
    instead of the arena's. That path is docker-only and never falls back to a
    subprocess: the fallback would run *no agent at all*, since an image agent's
    code exists only inside the image.

    Pass `network` to join the agent to a live-instance network (the web track).
    That is docker-only too: a subprocess agent cannot join a docker network, so
    a networked request never falls back — there would be no target to reach.
    """
    limits = limits or Limits()
    agent_dir = Path(agent_dir) if agent_dir is not None else None

    if network and not docker_available():
        return AgentRun(ok=False, backend="docker",
                        error="live-instance (web) matches need a Docker daemon, "
                              "which this arena has not got")

    if image:
        if not docker_available():
            return AgentRun(ok=False, backend="docker",
                            error="this arena has no Docker daemon, so image agents "
                                  "cannot run here")
        work = Path(tempfile.mkdtemp(prefix="arena-run-"))
        try:
            _stage(work, None, entry, challenge, limits)
            run = _run_docker(work, entry, limits, image=image,
                              agent_dir_in_image=agent_dir_in_image or IMAGE_AGENT_DIR,
                              network=network)
            if run.exit_code == 125:
                run = AgentRun(ok=False, backend="docker", exit_code=125,
                               seconds=run.seconds, stderr=run.stderr,
                               error="could not start your image — it may have been "
                                     "pruned from the arena host; resubmit it")
            return run
        except Exception as exc:
            return AgentRun(ok=False, error=f"sandbox setup failed: "
                                            f"{type(exc).__name__}: {exc}")
        finally:
            shutil.rmtree(work, ignore_errors=True)

    use_docker = bool(network) or backend == "docker" or (
        backend == "auto" and docker_available())

    work = Path(tempfile.mkdtemp(prefix="arena-run-"))
    try:
        _stage(work, agent_dir, entry, challenge, limits)
        if use_docker:
            run = _run_docker(work, entry, limits, network=network)
            # A networked (web) run must not fall back to subprocess: there is a
            # live target on a docker network a subprocess agent cannot reach.
            if run.exit_code == 125 and not network:
                run = _run_subprocess(work, entry, limits)
        else:
            run = _run_subprocess(work, entry, limits)
        return run
    except Exception as exc:
        return AgentRun(ok=False, error=f"sandbox setup failed: {type(exc).__name__}: {exc}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
