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


def backend_report() -> dict:
    """What isolation this host can actually deliver — surfaced in the UI."""
    docker = docker_available()
    unshare = unshare_available()
    return {
        "backend": "docker" if docker else "subprocess",
        "docker": docker,
        "network_namespace": docker or unshare,
        "strength": "strong" if docker else ("medium" if unshare else "basic"),
        "note": ("Docker containers with --network none."
                 if docker else
                 "Hardened subprocess with kernel network namespace."
                 if unshare else
                 "Hardened subprocess; socket API removed but no kernel netns. "
                 "Run behind Docker for public submissions."),
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

if not LIM.get("allow_network"):
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
    sys.path.insert(0, os.path.abspath("agent"))
    spec = importlib.util.spec_from_file_location("team_agent_module",
                                                  os.path.join("agent", entry))
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


def _stage(work: Path, agent_dir: Path, entry: str, challenge: dict, limits: Limits) -> None:
    """Lay out the sandbox: agent code, player files, harness, input payload."""
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


def _child_env(entry: str, limits: Limits) -> dict[str, str]:
    """A scrubbed environment — no API keys, no host paths, no repo on sys.path."""
    keep = ("PATH", "LANG", "LC_ALL", "TZ", "HOME", "TMPDIR")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env["HOME"] = env.get("TMPDIR", "/tmp")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["ARENA_ENTRY"] = entry
    env["ARENA_SITE"] = json.dumps(host_site_dirs())
    env["ARENA_LIMITS"] = json.dumps({
        "cpu_seconds": limits.cpu_seconds,
        "memory_mb": limits.memory_mb,
        "max_file_mb": limits.max_file_mb,
        "max_processes": limits.max_processes,
        "allow_network": limits.allow_network,
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
    if not limits.allow_network and unshare_available():
        cmd = ["unshare", "-rn", *cmd]          # kernel-enforced: no interfaces at all

    started = time.monotonic()
    proc = subprocess.Popen(cmd, cwd=work, env=_child_env(entry, limits),
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


def _run_docker(work: Path, entry: str, limits: Limits) -> AgentRun:
    env = _child_env(entry, limits)
    env["ARENA_LIMITS"] = json.dumps({**json.loads(env["ARENA_LIMITS"]),
                                      "skip_as_limit": True})
    cmd = [
        "docker", "run", "--rm", "-i",
        "--network", "none" if not limits.allow_network else "bridge",
        "--memory", f"{limits.memory_mb}m", "--memory-swap", f"{limits.memory_mb}m",
        "--pids-limit", str(limits.max_processes),
        "--cpus", "1.0",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{work}:/work",
        "-w", "/work",
        "-e", f"ARENA_ENTRY={env['ARENA_ENTRY']}",
        "-e", f"ARENA_LIMITS={env['ARENA_LIMITS']}",
        "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "HOME=/tmp",
        DEFAULT_IMAGE, "python", "-E", "-B", "_harness.py",
    ]
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


def run_agent(agent_dir: Path | str, entry: str, challenge: dict,
              limits: Limits | None = None, *, backend: str = "auto") -> AgentRun:
    """Execute one solve attempt. Never raises on agent misbehaviour."""
    limits = limits or Limits()
    agent_dir = Path(agent_dir)
    use_docker = backend == "docker" or (backend == "auto" and docker_available())

    work = Path(tempfile.mkdtemp(prefix="arena-run-"))
    try:
        _stage(work, agent_dir, entry, challenge, limits)
        if use_docker:
            run = _run_docker(work, entry, limits)
            if run.exit_code == 125:            # docker itself failed to start
                run = _run_subprocess(work, entry, limits)
        else:
            run = _run_subprocess(work, entry, limits)
        return run
    except Exception as exc:
        return AgentRun(ok=False, error=f"sandbox setup failed: {type(exc).__name__}: {exc}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
