"""Intake for the third submission kind: a team's own Docker image.

Why this exists: `upload` gives every team the same interpreter and the same
libraries, which is fair but limiting — a team that needs Sage, a pinned NumPy,
a compiled solver or a Rust binary has nowhere to put it. `remote` solves that
but moves the agent onto the team's hardware, so wall-clock stops being
comparable and the leaderboard has to mark those rows. An image is the missing
middle: the team controls the whole environment, and it still runs on the
arena's hardware under the arena's limits, so the times remain comparable.

Two ways to hand the image over, because contests run both ways:

  registry — the normal one. The team pushes to Docker Hub (or any public
      registry) and submits the *address*; the arena pulls it. Nothing large
      crosses the arena's own connection, and re-submitting a rebuilt `:v2` is
      one line.

        docker push you/my-agent:v1
        curl -X POST "$ARENA/api/agents" -H "Authorization: Bearer $TOKEN" \
             -d '{"kind":"image","name":"my-agent","image_ref":"you/my-agent:v1"}'

  tarball — for an air-gapped venue, a private image, or a team with no registry
      account. `docker save` output goes up as the raw request body.

        docker save my-agent | gzip > my-agent.tar.gz
        curl -X POST "$ARENA/api/agents?kind=image&name=my-agent" \
             -H "Authorization: Bearer $TOKEN" --data-binary @my-agent.tar.gz

Both converge on the same thing: an arena-owned tag, probed once, then run per
rung like any other agent.

The contract for the image itself is one line: **`/opt/agent/agent.py` must
define `solve(files, meta=None)`**, and `python` must be on `PATH`. Everything
else — base image, libraries, extra files — is the team's business.

────────────────────────────────────────────────────────────────────────────
What a hostile tarball can try, and what stops it

  Overwrite the arena's own image.  `docker load` honours the RepoTags baked
      into the tarball, so a tarball tagged `autoctf-arena-agent:latest` would
      silently replace the image every *other* team runs in. `inspect_tarball`
      reads manifest.json and refuses protected tags BEFORE loading, and
      `load_image` then retags to an arena-owned name and drops whatever tags
      the tarball brought.

  Escape the sandbox via image metadata.  It cannot: USER, ENTRYPOINT, CMD,
      VOLUME and ENV are all overridden at `docker run` time by
      `sandbox.docker_run_argv`, which the probe below reuses verbatim.

  Fill the disk.  Three caps: the upload is streamed to a temp file and cut off
      at MAX_IMAGE_BYTES; the *decompressed* image is re-measured after load and
      removed if it exceeds MAX_IMAGE_BYTES; and each team keeps exactly one
      image, older ones being pruned on the next submission.

  Ship a broken image and blame the arena.  `probe_image` runs the real
      confinement flags against a real import of `solve` at submission time, so
      the team gets the error at upload rather than as a lost match.

  Point the registry pull at the arena's own network.  `docker pull` runs on
      the arena host with the arena's routing, so a reference naming
      `localhost:5000/x` or a private address would make the daemon fetch from
      inside the perimeter. `validate_image_ref` resolves the registry host and
      refuses private, loopback and link-local addresses — the same rule
      `agents.validate_remote_url` applies to remote endpoints.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

from .sandbox import (DEFAULT_IMAGE, IMAGE_AGENT_DIR, Limits, docker_available,
                      docker_run_argv)

MAX_IMAGE_BYTES = int(os.environ.get("ARENA_MAX_IMAGE_MB", "512")) * 1024 * 1024
LOAD_TIMEOUT_S = int(os.environ.get("ARENA_IMAGE_LOAD_TIMEOUT_S", "600"))
PROBE_TIMEOUT_S = 120

# Every team image is retagged into this namespace, so an arena image is always
# distinguishable from anything else on the host and `docker images` stays
# readable for the operator.
NAMESPACE = "arena-team"

# Names a submitted tarball may not claim. The arena's own runner image is the
# one that matters — owning it means owning every other team's match.
PROTECTED_PREFIXES = (NAMESPACE + "/", "autoctf-", "autoctf_")


class ImageError(ValueError):
    """A submission the platform refuses, with a player-readable reason."""


def images_supported() -> bool:
    return docker_available()


# ---------------------------------------------------------------------------
# pre-load inspection — everything we can learn without handing bytes to dockerd
# ---------------------------------------------------------------------------
def _protected(tag: str) -> bool:
    tag = (tag or "").strip().lower()
    if not tag:
        return False
    if tag == DEFAULT_IMAGE.lower() or tag.split(":")[0] == DEFAULT_IMAGE.split(":")[0].lower():
        return True
    return any(tag.startswith(p) for p in PROTECTED_PREFIXES)


def inspect_tarball(path: Path) -> dict:
    """Read the image manifest without loading it. Returns {image_id, repo_tags}.

    `docker save` writes a manifest.json listing each image's config blob; the
    digest of that blob IS the image id, which is how we can address the loaded
    image later without trusting the tarball's own tags.
    """
    size = path.stat().st_size
    if size == 0:
        raise ImageError("the uploaded image is empty")
    if size > MAX_IMAGE_BYTES:
        raise ImageError(f"image is {size // (1024 * 1024)} MB; the limit is "
                         f"{MAX_IMAGE_BYTES // (1024 * 1024)} MB")

    try:
        # Transparent decompression, so `docker save | gzip` uploads work too.
        with tarfile.open(path, "r:*") as tf:
            member = tf.getmember("manifest.json")
            if member.size > 4 * 1024 * 1024:
                raise ImageError("manifest.json is implausibly large")
            handle = tf.extractfile(member)
            manifest = json.loads(handle.read().decode("utf-8")) if handle else None
    except KeyError as exc:
        raise ImageError("no manifest.json in the archive — this does not look like "
                         "`docker save` output. Build with `docker save IMAGE > "
                         "agent.tar`, not `docker export`") from exc
    except tarfile.TarError as exc:
        raise ImageError(f"not a readable tar archive: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImageError(f"manifest.json is not valid JSON: {exc}") from exc

    if not isinstance(manifest, list) or not manifest:
        raise ImageError("manifest.json is empty or malformed")
    if len(manifest) > 1:
        raise ImageError(f"the archive holds {len(manifest)} images; save exactly one "
                         "(`docker save my-agent > agent.tar`)")

    entry = manifest[0] if isinstance(manifest[0], dict) else {}
    repo_tags = [t for t in (entry.get("RepoTags") or []) if isinstance(t, str)]
    for tag in repo_tags:
        if _protected(tag):
            raise ImageError(f"the image is tagged {tag!r}, which is reserved by the "
                             "arena. Retag it (`docker tag`) and save it again")

    config = entry.get("Config") or ""
    digest = re.search(r"([0-9a-f]{64})", str(config))
    if not digest:
        raise ImageError("could not read the image id from manifest.json")
    return {"image_id": f"sha256:{digest.group(1)}", "repo_tags": repo_tags,
            "size_bytes": size}


# ---------------------------------------------------------------------------
# docker plumbing
# ---------------------------------------------------------------------------
def _docker(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          errors="replace", timeout=timeout)


def _image_size(ref: str) -> int:
    proc = _docker(["image", "inspect", "-f", "{{.Size}}", ref], 60)
    try:
        return int((proc.stdout or "0").strip())
    except ValueError:
        return 0


def remove_image(ref: str) -> None:
    """Best-effort delete. A leftover image costs disk, never correctness."""
    if not ref:
        return
    try:
        _docker(["rmi", "-f", ref], 120)
    except Exception:
        pass


def load_image(path: Path, agent_id: str) -> dict:
    """Load a validated tarball and give it an arena-owned tag.

    The order matters: tag OUR name onto the image id first, then drop the
    tarball's own tags. Doing it the other way round can delete the image, since
    removing its last tag removes the image with it.
    """
    if not images_supported():
        raise ImageError("this arena has no Docker daemon, so it cannot accept "
                         "image submissions — upload a .py or .zip instead")

    info = inspect_tarball(path)
    ref = f"{NAMESPACE}/{agent_id}:latest"

    try:
        proc = _docker(["load", "-i", str(path)], LOAD_TIMEOUT_S)
    except subprocess.TimeoutExpired as exc:
        raise ImageError(f"`docker load` timed out after {LOAD_TIMEOUT_S}s") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:400]
        raise ImageError(f"`docker load` refused the archive: {detail}")

    image_id = info["image_id"]
    tag = _docker(["tag", image_id, ref], 120)
    if tag.returncode != 0:
        # The id in the manifest did not survive the load — refuse rather than
        # guess at which of the loaded images was meant.
        for stray in info["repo_tags"]:
            remove_image(stray)
        raise ImageError("the loaded image could not be addressed by the id in its "
                         "manifest; rebuild and save it again")

    # The tarball's own tags are now redundant, and leaving them lets one team's
    # names accumulate on the host. Our tag already holds the image alive.
    for stray in info["repo_tags"]:
        if stray != ref:
            remove_image(stray)

    unpacked = _image_size(ref)
    if unpacked > MAX_IMAGE_BYTES:
        remove_image(ref)
        raise ImageError(f"the image unpacks to {unpacked // (1024 * 1024)} MB; the "
                         f"limit is {MAX_IMAGE_BYTES // (1024 * 1024)} MB. Try a "
                         "-slim base image and drop build toolchains in the same layer")

    return {"image_ref": ref, "image_id": image_id,
            "size_bytes": info["size_bytes"], "unpacked_bytes": unpacked,
            "repo_tags": info["repo_tags"]}


# ---------------------------------------------------------------------------
# registry intake — the normal route: the team pushes, the arena pulls
# ---------------------------------------------------------------------------
PULL_TIMEOUT_S = int(os.environ.get("ARENA_IMAGE_PULL_TIMEOUT_S", "900"))

# A pragmatic subset of the reference grammar: [host[:port]/]path[:tag][@digest].
_REF = re.compile(
    r"^(?:(?P<host>[A-Za-z0-9][A-Za-z0-9.\-]*(?::\d{1,5})?)/)?"
    r"(?P<path>[a-z0-9]+(?:[._\-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._\-][a-z0-9]+)*)*)"
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9._\-]{0,127}))?"
    r"(?:@sha256:(?P<digest>[0-9a-f]{64}))?$")


def _registry_host(ref: str) -> str:
    """Docker's own rule: the first path component is a registry only if it looks
    like a hostname — a dot, a port, or the literal `localhost`. Without this,
    `myuser/myagent` would read `myuser` as a registry."""
    head = ref.split("/")[0]
    if "/" not in ref:
        return ""
    if head == "localhost" or "." in head or ":" in head:
        return head
    return ""


def _is_private_host(host: str) -> bool:
    import ipaddress
    import socket

    host = host.split(":")[0]
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True                          # unresolvable: treat as unsafe
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return True
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return True
    return False


def validate_image_ref(ref: str) -> str:
    """Refuse references the arena must not pull, before dockerd sees them."""
    ref = (ref or "").strip()
    if not ref:
        raise ImageError("give the image address, e.g. youruser/my-agent:v1")
    if len(ref) > 300:
        raise ImageError("image reference is implausibly long")
    if "://" in ref:
        raise ImageError("drop the scheme — an image address is "
                         "`youruser/my-agent:v1`, not a URL")
    if not _REF.match(ref):
        raise ImageError(f"{ref!r} is not a valid image reference. Expected "
                         "[registry/]name[:tag][@sha256:…], all lowercase")
    if _protected(ref) or _protected(ref.split("/")[-1]):
        raise ImageError(f"{ref!r} names an image reserved by the arena — retag "
                         "and push it under your own name")

    host = _registry_host(ref)
    if host and _is_private_host(host):
        raise ImageError(f"the arena will not pull from {host!r}: it resolves to a "
                         "private or loopback address. Push to a public registry")
    return ref


def pull_image(ref: str, agent_id: str) -> dict:
    """Fetch a public image by address and give it an arena-owned tag.

    Deliberately no registry credentials: the arena authenticating to a team's
    private registry would mean storing that team's secret, and a contest image
    has no reason to be private. Public, or upload the tarball instead.
    """
    if not images_supported():
        raise ImageError("this arena has no Docker daemon, so it cannot accept "
                         "image submissions — upload a .py or .zip instead")

    ref = validate_image_ref(ref)
    local = f"{NAMESPACE}/{agent_id}:latest"

    try:
        proc = _docker(["pull", "--quiet", ref], PULL_TIMEOUT_S)
    except subprocess.TimeoutExpired as exc:
        raise ImageError(f"pulling {ref} timed out after {PULL_TIMEOUT_S}s — is the "
                         "image very large, or the registry slow?") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        if "not found" in detail or "manifest unknown" in detail:
            raise ImageError(f"{ref} was not found. Check the tag, and that the "
                             "repository is public — the arena pulls anonymously")
        if "denied" in detail or "unauthorized" in detail:
            raise ImageError(f"the registry denied anonymous access to {ref}. Make "
                             "the repository public, or submit the tarball instead")
        raise ImageError(f"could not pull {ref}: {detail[:400]}")

    # Retag before anything else can prune the pulled name, then drop it: leaving
    # a team's own tag on the host invites collisions between teams.
    if _docker(["tag", ref, local], 120).returncode != 0:
        raise ImageError(f"pulled {ref} but could not tag it for the arena")
    if ref != local:
        remove_image(ref)

    unpacked = _image_size(local)
    if unpacked > MAX_IMAGE_BYTES:
        remove_image(local)
        raise ImageError(f"{ref} unpacks to {unpacked // (1024 * 1024)} MB; the limit "
                         f"is {MAX_IMAGE_BYTES // (1024 * 1024)} MB. Try a -slim base "
                         "image and drop build toolchains in the same layer")

    digest = _docker(["image", "inspect", "-f", "{{.Id}}", local], 60)
    return {"image_ref": local, "image_id": (digest.stdout or "").strip(),
            "source_ref": ref, "size_bytes": unpacked, "unpacked_bytes": unpacked,
            "repo_tags": [ref]}


# ---------------------------------------------------------------------------
# post-load probe — fail at submission, not mid-match
# ---------------------------------------------------------------------------
PROBE = r'''
import importlib.util, os, sys
d = os.environ.get("ARENA_AGENT_DIR")
p = os.path.join(d, "agent.py")
if not os.path.isdir(d):
    sys.exit("no directory %s in the image" % d)
if not os.path.isfile(p):
    sys.exit("no %s in the image" % p)
if not os.access(p, os.R_OK):
    sys.exit("%s is not readable by the arena's run user "
             "(the arena runs your image with --user, not as root; "
             "add `RUN chmod -R a+rX /opt/agent`)" % p)
sys.path.insert(0, d)
spec = importlib.util.spec_from_file_location("probe_agent", p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
fn = getattr(m, "solve", None)
if not callable(fn):
    sys.exit("%s does not define a callable solve()" % p)
print("ok")
'''


def probe_image(ref: str, *, memory_mb: int = 2048) -> dict:
    """Import the agent inside the image, under real match confinement.

    Runs `solve`'s module top-level — which is team code — so it happens with
    the same flags a match uses. A failure here is a rejected submission with
    the reason attached, which is far kinder than a match that dies at Gen-0.
    """
    import tempfile

    limits = Limits(memory_mb=memory_mb, wall_seconds=PROBE_TIMEOUT_S)
    work = Path(tempfile.mkdtemp(prefix="arena-probe-"))
    try:
        (work / "_harness.py").write_text(PROBE, encoding="utf-8")
        env = {"ARENA_ENTRY": "agent.py", "ARENA_AGENT_DIR": IMAGE_AGENT_DIR,
               "ARENA_LIMITS": json.dumps({
                   "cpu_seconds": PROBE_TIMEOUT_S, "memory_mb": memory_mb,
                   "max_file_mb": 64, "max_processes": 256,
                   "allow_network": False, "socket_guard": False,
                   "skip_as_limit": True})}
        try:
            proc = subprocess.run(docker_run_argv(work, env, limits, ref),
                                  capture_output=True, text=True, errors="replace",
                                  timeout=PROBE_TIMEOUT_S + 20)
        except subprocess.TimeoutExpired as exc:
            raise ImageError(f"importing /opt/agent/agent.py inside your image took "
                             f"longer than {PROBE_TIMEOUT_S}s — do the slow work "
                             f"inside solve(), not at import time") from exc

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            if "executable file not found" in detail or "exec:" in detail:
                raise ImageError("`python` is not on PATH inside your image — the "
                                 "arena starts it with `--entrypoint python`")
            raise ImageError(f"your image did not pass the agent check: "
                             f"{detail[:600] or 'no output'}")
        return {"ok": True, "note": (proc.stdout or "").strip()[:200]}
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------
# disk hygiene
# ---------------------------------------------------------------------------
def prune_team_images(store, team_id: str, keep_agent_id: str) -> list[str]:
    """Keep one image per team.

    A 512 MB image per submission would fill a small VPS in an afternoon, and
    teams iterate. Older image agents keep their leaderboard history — only the
    image is reclaimed, and `image_ref` is blanked so a rerun of that agent
    fails with a clear "resubmit it" rather than a confusing docker error.
    """
    pruned = []
    for row in store.agents_for_team(team_id):
        if row.get("kind") != "image" or row["id"] == keep_agent_id:
            continue
        ref = row.get("image_ref") or ""
        if not ref:
            continue
        remove_image(ref)
        store.clear_agent_image(row["id"])
        pruned.append(ref)
    return pruned
