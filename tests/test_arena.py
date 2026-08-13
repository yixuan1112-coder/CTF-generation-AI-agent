"""Tests for the arena competition platform.

Covers the parts a real contest depends on: the sandbox actually contains hostile
agents, submissions are validated before they are stored, the match engine scores
a climb correctly, and the leaderboard ranks by depth before speed.
"""
from __future__ import annotations

import io
import json
import math
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from arena_platform import agents as agents_mod
from arena_platform import images as images_mod
from arena_platform.runner import MatchEngine, fresh_seed
from arena_platform.sandbox import Limits, docker_run_argv, run_agent
from arena_platform.store import Store, _rank_key
from arena_platform.tracks import all_tracks, get_track, warmup

warmup()          # fpylll must be imported on the main thread — see tracks.warmup

CHALLENGE = {"challenge_id": "c1", "gen": 0, "category": "crypto", "title": "t",
             "story": "s", "hints": [], "files": {"a.txt": "hello"}}


def write_agent(root: Path, source: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(source, encoding="utf-8")
    return root


class SandboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_returns_flag_and_captures_stdout(self):
        d = write_agent(self.tmp / "ok", "def solve(files):\n"
                                         "    print('working')\n"
                                         "    return 'flag{' + files['a.txt'] + '}'\n")
        run = run_agent(d, "agent.py", CHALLENGE, Limits(wall_seconds=30))
        self.assertTrue(run.ok)
        self.assertEqual(run.flag, "flag{hello}")
        self.assertIn("working", run.stdout)

    def test_two_argument_signature_receives_metadata(self):
        d = write_agent(self.tmp / "meta", "def solve(files, meta):\n"
                                           "    return 'flag{gen%d}' % meta['gen']\n")
        run = run_agent(d, "agent.py", {**CHALLENGE, "gen": 4}, Limits(wall_seconds=30))
        self.assertEqual(run.flag, "flag{gen4}")

    def test_egress_is_blocked(self):
        d = write_agent(self.tmp / "net", "import socket\n"
                                          "def solve(files):\n"
                                          "    socket.create_connection(('1.1.1.1', 80), 2)\n"
                                          "    return 'flag{leaked}'\n")
        run = run_agent(d, "agent.py", CHALLENGE, Limits(wall_seconds=30))
        self.assertFalse(run.ok)
        self.assertIsNone(run.flag)

    def test_loopback_stays_usable_when_the_kernel_enforces_the_boundary(self):
        """Booting a local target and exploiting it IS the web track's workflow.

        Blanket-removing the socket API would block egress and that workflow
        together, so where a real network namespace exists the guard stays off
        and the kernel does the enforcing.
        """
        from arena_platform.sandbox import backend_report

        if not backend_report()["loopback"]:
            self.skipTest("host has no network namespace; sockets are removed wholesale")
        d = write_agent(self.tmp / "loop",
                        "import http.server, threading, urllib.request\n"
                        "def solve(files):\n"
                        "    class H(http.server.BaseHTTPRequestHandler):\n"
                        "        def do_GET(s):\n"
                        "            s.send_response(200); s.end_headers()\n"
                        "            s.wfile.write(b'flag{loopback}')\n"
                        "        def log_message(s, *a): pass\n"
                        "    srv = http.server.HTTPServer(('127.0.0.1', 0), H)\n"
                        "    threading.Thread(target=srv.serve_forever, daemon=True).start()\n"
                        "    url = 'http://127.0.0.1:%d/' % srv.server_address[1]\n"
                        "    return urllib.request.urlopen(url, timeout=5).read().decode()\n")
        run = run_agent(d, "agent.py", CHALLENGE, Limits(wall_seconds=60))
        self.assertTrue(run.ok, run.error)
        self.assertEqual(run.flag, "flag{loopback}")

    def test_infinite_loop_is_killed(self):
        d = write_agent(self.tmp / "spin", "def solve(files):\n"
                                           "    while True:\n        pass\n")
        run = run_agent(d, "agent.py", CHALLENGE,
                        Limits(wall_seconds=10, cpu_seconds=3))
        self.assertFalse(run.ok)
        self.assertIsNone(run.flag)

    def test_crash_is_reported_not_raised(self):
        d = write_agent(self.tmp / "boom", "def solve(files):\n    return 1 / 0\n")
        run = run_agent(d, "agent.py", CHALLENGE, Limits(wall_seconds=30))
        self.assertFalse(run.ok)
        self.assertIn("ZeroDivisionError", run.error)

    def test_missing_solve_is_reported(self):
        d = write_agent(self.tmp / "nosolve", "x = 1\n")
        run = run_agent(d, "agent.py", CHALLENGE, Limits(wall_seconds=30))
        self.assertFalse(run.ok)
        self.assertIn("solve", run.error)

    def test_non_string_return_is_rejected(self):
        d = write_agent(self.tmp / "badtype", "def solve(files):\n    return 42\n")
        run = run_agent(d, "agent.py", CHALLENGE, Limits(wall_seconds=30))
        self.assertFalse(run.ok)
        self.assertIn("expected str", run.error)

    def test_agent_can_use_the_hosts_installed_libraries(self):
        """Agents must reach the same libraries the reference solvers use.

        Running the harness under `python -I` would also imply `-s`, hiding user
        site-packages — on a `pip install --user` host that silently removes
        fpylll/sympy and makes the lattice rung unreachable for everyone.
        """
        d = write_agent(self.tmp / "libs",
                        "def solve(files):\n"
                        "    import importlib\n"
                        "    found = []\n"
                        "    for name in ('Crypto', 'sympy', 'fpylll'):\n"
                        "        try:\n"
                        "            importlib.import_module(name); found.append(name)\n"
                        "        except ImportError:\n"
                        "            pass\n"
                        "    return 'flag{' + ','.join(found) + '}'\n")
        run = run_agent(d, "agent.py", CHALLENGE, Limits(wall_seconds=60))
        self.assertTrue(run.ok, run.error)
        import importlib
        for name in ("Crypto", "sympy", "fpylll"):
            try:
                importlib.import_module(name)
            except ImportError:
                continue                     # not installed here either — fine
            self.assertIn(name, run.flag,
                          f"{name} is installed on the host but invisible to agents")

    def test_agent_cannot_import_the_challenge_engine(self):
        """The generator and its flags must be unreachable from agent code."""
        d = write_agent(self.tmp / "peek",
                        "def solve(files):\n"
                        "    import autoctf_gan.crypto_ladder as cl\n"
                        "    return cl.gen_crypto_ladder(seed=1, generation=0).flag\n")
        run = run_agent(d, "agent.py", CHALLENGE, Limits(wall_seconds=30))
        self.assertFalse(run.ok)
        self.assertIsNone(run.flag)


class UploadTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def test_plain_python_file(self):
        got = agents_mod.store_upload(self.root, "t", "a", "solver.py", b"def solve(f): pass")
        self.assertEqual(got["entry"], "agent.py")
        self.assertTrue((Path(got["dir"]) / "agent.py").exists())

    def test_zip_with_nested_folder_is_flattened(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("mybot/agent.py", "def solve(f): pass")
            z.writestr("mybot/lattice.py", "X = 1")
        got = agents_mod.store_upload(self.root, "t", "b", "bot.zip", buf.getvalue())
        self.assertEqual(got["entry"], "agent.py")
        self.assertTrue((Path(got["dir"]) / "lattice.py").exists())

    def test_path_traversal_is_refused(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("../escape.py", "x")
        with self.assertRaises(agents_mod.UploadError):
            agents_mod.store_upload(self.root, "t", "c", "evil.zip", buf.getvalue())

    def test_zip_bomb_is_refused(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("agent.py", "A" * (agents_mod.MAX_UNPACKED_BYTES + 1))
        with self.assertRaises(agents_mod.UploadError):
            agents_mod.store_upload(self.root, "t", "d", "bomb.zip", buf.getvalue())

    def test_wrong_extension_and_empty_are_refused(self):
        for name, blob in [("agent.exe", b"MZ"), ("agent.py", b"")]:
            with self.assertRaises(agents_mod.UploadError):
                agents_mod.store_upload(self.root, "t", "e", name, blob)

    def test_remote_url_scheme_is_validated(self):
        self.assertEqual(agents_mod.validate_remote_url("https://x.example/solve"),
                         "https://x.example/solve")
        for bad in ("ftp://x/y", "file:///etc/passwd", "notaurl"):
            with self.assertRaises(agents_mod.UploadError):
                agents_mod.validate_remote_url(bad)


class ImageIntakeTests(unittest.TestCase):
    """A team-supplied Docker image is the most dangerous thing the arena accepts.

    These cover the checks that happen BEFORE any byte reaches dockerd, so they
    run on a host with no Docker at all — which is the point: the guard that
    stops a tarball from hijacking the arena's own image must not depend on the
    daemon it is protecting.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _tarball(self, repo_tags, *, name="img.tar", images=1, digest=None):
        """A minimal `docker save`-shaped archive."""
        import tarfile
        digest = digest or ("a" * 64)
        path = self.tmp / name
        manifest = [{"Config": f"blobs/sha256/{digest}", "RepoTags": repo_tags,
                     "Layers": []} for _ in range(images)]
        blob = json.dumps(manifest).encode()
        with tarfile.open(path, "w") as tf:
            info = tarfile.TarInfo("manifest.json")
            info.size = len(blob)
            tf.addfile(info, io.BytesIO(blob))
        return path

    def test_reads_the_image_id_and_tags(self):
        got = images_mod.inspect_tarball(self._tarball(["my-agent:latest"]))
        self.assertEqual(got["image_id"], "sha256:" + "a" * 64)
        self.assertEqual(got["repo_tags"], ["my-agent:latest"])

    def test_tarball_may_not_claim_the_arenas_own_image(self):
        """The attack this whole module exists to stop.

        `docker load` honours RepoTags, so a tarball tagged as the runner image
        would replace the container every OTHER team's match runs in.
        """
        for tag in ("autoctf-arena-agent:latest", "autoctf-arena-agent:v2",
                    "arena-team/agent_deadbeef:latest"):
            with self.assertRaises(images_mod.ImageError) as caught:
                images_mod.inspect_tarball(self._tarball([tag]))
            self.assertIn("reserved", str(caught.exception))

    def test_docker_export_output_is_refused_with_a_useful_reason(self):
        import tarfile
        path = self.tmp / "export.tar"
        with tarfile.open(path, "w") as tf:
            info = tarfile.TarInfo("bin/sh")
            info.size = 0
            tf.addfile(info, io.BytesIO(b""))
        with self.assertRaises(images_mod.ImageError) as caught:
            images_mod.inspect_tarball(path)
        self.assertIn("docker save", str(caught.exception))

    def test_multi_image_archive_is_refused(self):
        with self.assertRaises(images_mod.ImageError) as caught:
            images_mod.inspect_tarball(self._tarball(["a:1"], images=3))
        self.assertIn("3 images", str(caught.exception))

    def test_non_tar_and_empty_are_refused(self):
        junk = self.tmp / "junk.tar"
        junk.write_bytes(b"not a tar at all")
        empty = self.tmp / "empty.tar"
        empty.write_bytes(b"")
        for path in (junk, empty):
            with self.assertRaises(images_mod.ImageError):
                images_mod.inspect_tarball(path)

    def test_oversized_upload_is_refused_before_it_is_parsed(self):
        path = self._tarball(["a:1"])
        original = images_mod.MAX_IMAGE_BYTES
        images_mod.MAX_IMAGE_BYTES = 1
        self.addCleanup(setattr, images_mod, "MAX_IMAGE_BYTES", original)
        with self.assertRaises(images_mod.ImageError) as caught:
            images_mod.inspect_tarball(path)
        self.assertIn("limit", str(caught.exception))

    def test_loading_without_a_docker_daemon_is_a_clean_refusal(self):
        if images_mod.images_supported():
            self.skipTest("this host has Docker; the no-daemon path cannot be reached")
        with self.assertRaises(images_mod.ImageError) as caught:
            images_mod.load_image(self._tarball(["a:1"]), "agent_x")
        self.assertIn("upload a .py or .zip", str(caught.exception))


class ImageReferenceTests(unittest.TestCase):
    """The registry route: the team pushes, the arena pulls by address.

    `docker pull` runs on the arena host with the arena's routing, so the
    reference is attacker-controlled input that steers an outbound fetch.
    """

    def test_docker_hub_references_are_accepted(self):
        """No registry host, so no DNS — these must pass offline."""
        for ref in ("myuser/my-agent:v1", "myuser/my-agent", "python",
                    "myuser/my-agent@sha256:" + "a" * 64):
            self.assertEqual(images_mod.validate_image_ref(ref), ref)

    def test_third_party_registries_are_accepted_when_public(self):
        """DNS is stubbed: this asserts the grammar, not the resolver."""
        original = images_mod._is_private_host
        images_mod._is_private_host = lambda host: False
        self.addCleanup(setattr, images_mod, "_is_private_host", original)
        for ref in ("ghcr.io/org/team-agent:2024.1",
                    "registry.example.com:5000/team/agent:latest"):
            self.assertEqual(images_mod.validate_image_ref(ref), ref)

    def test_an_unresolvable_registry_is_treated_as_unsafe(self):
        """Fail closed: a name we cannot resolve might resolve internally on the
        arena host, where the daemon actually runs."""
        with self.assertRaises(images_mod.ImageError):
            images_mod.validate_image_ref(
                "no-such-registry.invalid/team/agent:v1")

    def test_malformed_references_are_refused(self):
        for ref in ("", "   ", "https://docker.io/user/img",
                    "UPPER/Case:v1", "user/img:bad tag", "user//img"):
            with self.assertRaises(images_mod.ImageError):
                images_mod.validate_image_ref(ref)

    def test_a_url_gets_a_targeted_hint(self):
        with self.assertRaises(images_mod.ImageError) as caught:
            images_mod.validate_image_ref("https://hub.docker.com/u/me/agent")
        self.assertIn("drop the scheme", str(caught.exception))

    def test_reserved_names_are_refused(self):
        for ref in ("autoctf-arena-agent:latest", "someone/autoctf-arena-agent:v1",
                    "arena-team/agent_abc:latest"):
            with self.assertRaises(images_mod.ImageError) as caught:
                images_mod.validate_image_ref(ref)
            self.assertIn("reserved", str(caught.exception))

    def test_the_arena_will_not_pull_from_its_own_network(self):
        """Otherwise a reference is a way to make the daemon fetch from inside."""
        for ref in ("localhost:5000/x/y:1", "127.0.0.1:5000/x/y:1",
                    "10.0.0.5:5000/x/y:1", "192.168.1.10/x/y"):
            with self.assertRaises(images_mod.ImageError) as caught:
                images_mod.validate_image_ref(ref)
            self.assertIn("private or loopback", str(caught.exception))

    def test_a_bare_user_name_is_not_mistaken_for_a_registry(self):
        """`myuser/img` must read myuser as a Docker Hub account, not a host —
        otherwise every Hub reference fails the private-address check."""
        self.assertEqual(images_mod._registry_host("myuser/img:v1"), "")
        self.assertEqual(images_mod._registry_host("ghcr.io/org/img"), "ghcr.io")
        self.assertEqual(images_mod._registry_host("localhost:5000/img"), "localhost:5000")


class ImageAgentTests(unittest.TestCase):
    def test_build_client_dispatches_on_kind(self):
        row = {"kind": "image", "image_ref": "arena-team/agent_x:latest",
               "entry": "agent.py"}
        client = agents_mod.build_client(row, Limits())
        self.assertIsInstance(client, agents_mod.ImageAgent)
        self.assertEqual(client.kind, "image")

    def test_a_pruned_image_fails_with_advice_not_a_docker_error(self):
        """Each team keeps one image, so an older agent's ref is blanked.

        Rerunning that agent must say what to do, not surface a raw
        "No such image" from the daemon.
        """
        client = agents_mod.build_client(
            {"kind": "image", "image_ref": "", "entry": "agent.py"}, Limits())
        run = client.attempt(CHALLENGE)
        self.assertFalse(run.ok)
        self.assertIn("resubmit", run.error)

    def test_run_flags_confine_the_teams_own_image(self):
        """The image supplies the filesystem; the arena supplies the rules.

        --entrypoint is the load-bearing one: without it, `docker run IMAGE
        python …` appends those words to the image's OWN entrypoint, so a team
        could run anything it liked instead of the harness.
        """
        argv = docker_run_argv(Path("/tmp/work"), {"ARENA_ENTRY": "agent.py"},
                               Limits(memory_mb=777, max_processes=42),
                               "arena-team/agent_x:latest")
        self.assertIn("--entrypoint", argv)
        self.assertEqual(argv[argv.index("--entrypoint") + 1], "python")
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertEqual(argv[argv.index("--memory") + 1], "777m")
        self.assertEqual(argv[argv.index("--pids-limit") + 1], "42")
        self.assertIn("--cap-drop", argv)
        self.assertEqual(argv[argv.index("--security-opt") + 1], "no-new-privileges")
        self.assertEqual(argv[-4:], ["arena-team/agent_x:latest", "-E", "-B",
                                     "_harness.py"])
        self.assertTrue(any(a.startswith("--user") for a in argv) or "--user" in argv)

    def test_host_site_packages_are_not_offered_to_an_image_agent(self):
        """An image brings its own interpreter; host paths would be nonsense."""
        from arena_platform.sandbox import _child_env
        env = _child_env("agent.py", Limits(), agent_dir_in_image="/opt/agent")
        self.assertEqual(json.loads(env["ARENA_SITE"]), [])
        self.assertEqual(env["ARENA_AGENT_DIR"], "/opt/agent")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.store = Store(self.tmp / "a.sqlite3")

    def test_image_ref_column_is_added_to_an_existing_database(self):
        """CREATE TABLE IF NOT EXISTS does nothing to a table that already exists.

        The live arena has a populated agents table predating image support, so
        without the migration the first image submission raises OperationalError
        on a column the schema string claims is there.
        """
        import sqlite3
        path = self.tmp / "legacy.sqlite3"
        legacy = sqlite3.connect(path)
        legacy.executescript("""
            CREATE TABLE teams (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                token TEXT NOT NULL, contact TEXT DEFAULT '', created_at REAL NOT NULL);
            CREATE TABLE agents (id TEXT PRIMARY KEY, team_id TEXT NOT NULL,
                name TEXT NOT NULL, kind TEXT NOT NULL, entry TEXT DEFAULT 'agent.py',
                source_dir TEXT DEFAULT '', remote_url TEXT DEFAULT '',
                remote_token TEXT DEFAULT '', sha256 TEXT DEFAULT '',
                size_bytes INTEGER DEFAULT 0, notes TEXT DEFAULT '',
                created_at REAL NOT NULL);
        """)
        legacy.commit()
        legacy.close()

        store = Store(path)
        team = store.create_team("legacy-team")
        agent = store.create_agent(team_id=team["id"], name="img", kind="image",
                                   image_ref="arena-team/agent_x:latest")
        self.assertEqual(store.agent(agent["id"])["image_ref"],
                         "arena-team/agent_x:latest")
        store.clear_agent_image(agent["id"])
        self.assertEqual(store.agent(agent["id"])["image_ref"], "")
        self.store = Store(self.tmp / "a.sqlite3")

    def _finished(self, name, reached, secs, at=1.0):
        team = self.store.create_team(name)
        agent = self.store.create_agent(team_id=team["id"], name="a", kind="upload")
        match = self.store.create_match(team["id"], agent["id"], "crypto", 1, 6)
        self.store.update_match(match["id"], status="done", reached_gen=reached,
                                solve_seconds=secs, finished_at=at)
        return match["id"]

    def test_duplicate_team_name_rejected(self):
        self.store.create_team("dup")
        with self.assertRaises(ValueError):
            self.store.create_team("dup")

    def test_depth_outranks_speed(self):
        self._finished("deep-slow", reached=5, secs=900.0)
        self._finished("shallow-fast", reached=3, secs=0.1)
        board = self.store.leaderboard("crypto")
        self.assertEqual([r["team_name"] for r in board], ["deep-slow", "shallow-fast"])
        self.assertEqual(board[0]["rank"], 1)

    def test_speed_breaks_ties_at_equal_depth(self):
        self._finished("slow", reached=4, secs=50.0)
        self._finished("fast", reached=4, secs=5.0)
        self.assertEqual([r["team_name"] for r in self.store.leaderboard("crypto")],
                         ["fast", "slow"])

    def test_leaderboard_keeps_only_a_team_best_run(self):
        team = self.store.create_team("solo")
        agent = self.store.create_agent(team_id=team["id"], name="a", kind="upload")
        for reached in (2, 5, 1):
            m = self.store.create_match(team["id"], agent["id"], "crypto", 1, 6)
            self.store.update_match(m["id"], status="done", reached_gen=reached,
                                    solve_seconds=1.0, finished_at=1.0)
        board = self.store.leaderboard("crypto")
        self.assertEqual(len(board), 1)
        self.assertEqual(board[0]["reached_gen"], 5)

    def test_claim_is_atomic_across_threads(self):
        team = self.store.create_team("racer")
        agent = self.store.create_agent(team_id=team["id"], name="a", kind="upload")
        for _ in range(8):
            self.store.create_match(team["id"], agent["id"], "crypto", 1, 6)
        claimed, lock = [], threading.Lock()

        def worker():
            while True:
                m = self.store.claim_next_queued()
                if not m:
                    return
                with lock:
                    claimed.append(m["id"])

        threads = [threading.Thread(target=worker) for _ in range(4)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(len(claimed), 8)
        self.assertEqual(len(set(claimed)), 8, "a match was handed to two workers")

    def test_restart_requeues_interrupted_matches(self):
        team = self.store.create_team("crashy")
        agent = self.store.create_agent(team_id=team["id"], name="a", kind="upload")
        self.store.create_match(team["id"], agent["id"], "crypto", 1, 6)
        self.store.claim_next_queued()
        self.assertEqual(self.store.requeue_stale_running(), 1)
        self.assertIsNotNone(self.store.claim_next_queued())

    def test_no_solve_sorts_below_any_solve(self):
        self.assertLess(_rank_key({"reached_gen": 0, "solve_seconds": 99}),
                        _rank_key({"reached_gen": -1, "solve_seconds": 0}))


class TrackTests(unittest.TestCase):
    def test_crypto_ladder_is_exposed_in_full(self):
        rungs = get_track("crypto").rungs
        self.assertEqual(rungs[:6], ["smalle", "hastad", "commonmod",
                                     "wiener", "fermat", "pollard"])

    def test_ladder_resolves_identically_off_the_main_thread(self):
        """A worker thread must not see a shorter ladder than the API advertises."""
        main = get_track("crypto").rungs
        seen = []
        t = threading.Thread(target=lambda: seen.append(get_track("crypto").rungs))
        t.start()
        t.join()
        self.assertEqual(seen[0], main)

    def test_unknown_track_is_rejected(self):
        with self.assertRaises(KeyError):
            get_track("quantum")

    def test_rung_name_past_the_ladder_names_an_authored_challenge(self):
        """The ladder no longer clamps: past its end the maker composes.

        This used to assert `rung_name(999) == rungs[-1]`, which was the whole
        problem — the arena redeployed the last rung forever and called the match
        cleared. A generation past the bounded route must now name a composition.
        """
        track = get_track("crypto")
        self.assertTrue(track.endless)
        deep = track.rung_name(track.max_gen + 1)
        self.assertNotEqual(deep, track.rungs[-1])
        self.assertTrue(deep.startswith("compose:"), deep)

    def test_authored_rungs_never_repeat(self):
        track = get_track("crypto")
        authored = [track.rung_name(track.max_gen + 1 + i) for i in range(40)]
        self.assertEqual(len(set(authored)), len(authored))

    def test_a_track_never_substitutes_another_discipline(self):
        """If the starting ladder cannot build here, the track is withdrawn.

        Cross-tracking is an escalation, not a fallback: a team that entered the
        reverse track must never be handed crypto rungs because gcc is missing.
        """
        for track in all_tracks().values():
            if not track.available:
                continue
            self.assertEqual(track.route[0]["category"], track.category)


class TrackLadderIntegrityTests(unittest.TestCase):
    """A track must not advertise more rungs than its generator can produce.

    A bounded ladder clamps at its last entry: ask for a deeper generation and you
    get the previous challenge back. If a Track declares more BOUNDED rungs than
    that, the arena redeploys an identical rung while telling the team it evolved.
    Tracks with an authoring tail escape this by construction — past the bounded
    route the maker composes a new challenge instead of repeating one — which is
    what `test_authored_rungs_never_repeat` covers.
    """

    def _distinct_rungs(self, category: str, probe_depth: int = 9, *,
                        cross_track: bool = True, authoring: bool = True) -> int:
        from autoctf_gan.competition import Competition

        # Build the probe competition the way the TRACK runs it. A track that
        # sets cross_track/authoring off (like web) clamps at its bounded rungs;
        # probing with the defaults on would cross-track past them and count
        # rungs the track never actually offers.
        comp = Competition(category=category, seed=99, evolve_on=1,
                           max_gen=probe_depth, verify_deploy=True,
                           cross_track=cross_track, authoring=authoring)
        team = comp.register("probe")["team_id"]
        signatures = []
        for _ in range(probe_depth + 1):
            spec = comp.spec
            signatures.append(spec.title.split(" (Gen-")[0])
            if not comp.submit(team, spec.spec_id, spec.flag).get("evolved"):
                break
        distinct = []
        for sig in signatures:
            if sig not in distinct:
                distinct.append(sig)
        return len(distinct)

    def test_web_track_stops_where_the_ladder_clamps(self):
        track = get_track("web")
        self.assertEqual(len(track.rungs),
                         self._distinct_rungs("web", cross_track=track.cross_track,
                                              authoring=track.authoring))

    def test_crypto_segment_matches_the_engine_ladder(self):
        """The crypto SEGMENT must mirror the engine, whatever follows it.

        Asserting on `track.rungs` would now depend on whether this host can build
        the cross-track reverse ladder, so pin the segment instead.
        """
        from autoctf_gan.crypto_ladder import LADDER_NAMES
        crypto = [s for s in get_track("crypto").route if s["key"] == "crypto-ladder"]
        self.assertEqual(len(crypto), 1)
        self.assertEqual(crypto[0]["rungs"], list(LADDER_NAMES))

    def test_reverse_track_rungs_are_all_reachable(self):
        """Reverse has no ceiling, so every declared rung must be distinct."""
        track = get_track("reverse")
        if not track.available:
            self.skipTest(f"reverse not buildable here: {track.unavailable_reason}")
        reverse = [s for s in track.route if s["key"] == "reverse-ladder"][0]
        self.assertLessEqual(len(reverse["rungs"]),
                             self._distinct_rungs("reverse", probe_depth=9))


class TrackAvailabilityTests(unittest.TestCase):
    """A track is only offered if an agent could win it from the files it gets."""

    def test_web_is_gated_with_a_stated_reason(self):
        web = get_track("web")
        self.assertFalse(web.available)
        self.assertTrue(web.unavailable_reason)

    def test_playable_set_excludes_gated_tracks(self):
        from arena_platform.tracks import playable_tracks
        self.assertNotIn("web", playable_tracks())
        self.assertIn("crypto", playable_tracks())

    def test_web_flag_really_is_absent_from_player_files(self):
        """The reason for the gate, asserted rather than assumed."""
        from autoctf_gan.web import gen_web_ssti

        spec = gen_web_ssti(seed=11, generation=0)
        blob = "\n".join(spec.artifacts.values())
        self.assertNotIn(spec.flag, blob,
                         "if the flag were in the player files the gate is wrong")

    def test_reverse_flag_is_recoverable_from_player_files(self):
        """Conversely, reverse stays open because its files do carry the answer."""
        from autoctf_gan.native import gen_compiled_crackme

        spec = gen_compiled_crackme(seed=11, rounds=2)
        self.assertIn("ENC[]", spec.artifacts["crackme.c"])
        self.assertIn("ROUNDS", spec.artifacts["crackme.c"])


class FlagLeakGateTests(unittest.TestCase):
    """A player artifact must never contain the real flag.

    The web generator used to bake `ENV FLAG=<real flag>` into the Dockerfile it
    hands players, and the gate meant to catch that only inspected app.py — so
    exporting a web challenge shipped the answer with it.
    """

    def test_no_web_artifact_contains_the_flag(self):
        from autoctf_gan.web import gen_web_ssti

        for generation in (0, 2, 4):
            spec = gen_web_ssti(seed=11, generation=generation)
            leaked = [name for name, content in spec.artifacts.items()
                      if spec.flag in content]
            self.assertEqual(leaked, [], f"gen {generation} leaked via {leaked}")

    def test_the_gate_rejects_a_reintroduced_leak(self):
        from autoctf_gan.verify import verify_spec
        from autoctf_gan.web import gen_web_ssti

        spec = gen_web_ssti(seed=11, generation=0)
        self.assertTrue(verify_spec(spec).valid, "clean spec should verify")

        leaky = gen_web_ssti(seed=11, generation=0)
        leaky.artifacts["Dockerfile"] = leaky.artifacts["Dockerfile"].replace(
            "ENV FLAG=flag{replace_at_deployment}", f"ENV FLAG={leaky.flag}")
        verdict = verify_spec(leaky)
        self.assertFalse(verdict.valid, "a leaked flag must fail verification")
        self.assertIn("Dockerfile", verdict.reason)

    def test_crypto_and_reverse_artifacts_are_clean_too(self):
        from autoctf_gan.crypto_ladder import gen_crypto_ladder
        from autoctf_gan.native import gen_compiled_crackme

        for spec in (gen_crypto_ladder(seed=5, generation=0),
                     gen_compiled_crackme(seed=5, rounds=2)):
            leaked = [n for n, c in spec.artifacts.items() if spec.flag in c]
            self.assertEqual(leaked, [], f"{spec.category} leaked via {leaked}")


class ReferenceAgentTests(unittest.TestCase):
    """The shipped example agents must actually beat the ladders they claim to."""

    def test_reverse_agent_clears_every_rung(self):
        import importlib.util

        from autoctf_gan.native import gen_compiled_crackme

        path = Path(__file__).resolve().parents[1] / "examples" / "reverse_agent" / "agent.py"
        spec = importlib.util.spec_from_file_location("reverse_reference", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        for rounds in range(1, len(get_track("reverse").rungs) + 1):
            challenge = gen_compiled_crackme(seed=3000 + rounds, rounds=rounds)
            self.assertEqual(module.solve(dict(challenge.artifacts)), challenge.flag,
                             f"reference agent failed at R={rounds}")


class LadderFairnessTests(unittest.TestCase):
    """The rungs have to be honest, or the depth-first ranking is a lottery."""

    def test_boss_rung_is_not_crackable_by_the_wiener_rung(self):
        """A Gen-3 attack must not win Gen-6.

        d sits just past Wiener's bound, and Wiener's search used to succeed on
        roughly 5% of instances — handing those teams the top of the leaderboard
        for free. gen_boneh_durfee now re-rolls any key Wiener can recover.
        """
        from autoctf_gan.crypto_ladder import gen_crypto_ladder

        track = get_track("crypto")
        if "bonehdurfee" not in track.rungs:
            self.skipTest("fpylll missing — the Boneh-Durfee rung is not built")

        def wiener(e, n):
            cf, a, b = [], e, n
            while b:
                cf.append(a // b)
                a, b = b, a % b
            for i in range(len(cf)):
                num, den = 1, 0
                for x in reversed(cf[: i + 1]):
                    num, den = x * num + den, num
                k, d = num, den
                if k == 0 or (e * d - 1) % k:
                    continue
                phi = (e * d - 1) // k
                bb = n - phi + 1
                disc = bb * bb - 4 * n
                if disc >= 0:
                    root = math.isqrt(disc)
                    if root * root == disc:
                        return d
            return None

        for seed in range(9000, 9012):
            spec = gen_crypto_ladder(seed=seed, generation=6)
            self.assertEqual(spec.mechanics["attack_class"], "bonehdurfee")
            n, e = int(spec.artifacts["n.txt"]), int(spec.artifacts["e.txt"])
            c = int(spec.artifacts["c.txt"])
            d = wiener(e, n)
            if not d:
                continue
            m = pow(c, d, n)
            try:
                recovered = m.to_bytes((m.bit_length() + 7) // 8, "big").decode()
            except (UnicodeDecodeError, OverflowError):
                continue
            self.assertFalse(recovered.startswith("flag{"),
                             f"seed {seed}: Wiener alone beat the Boneh-Durfee rung")


class MatchTests(unittest.TestCase):
    """End-to-end climbs with stub agents, against the real challenge ladder."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.store = Store(self.tmp / "a.sqlite3")
        self.engine = MatchEngine(self.store, self.tmp / "up", workers=1)

    def run_with(self, source: str, name: str):
        d = write_agent(self.tmp / name, source)
        team = self.store.create_team(name)
        agent = self.store.create_agent(team_id=team["id"], name=name, kind="upload",
                                        entry="agent.py", source_dir=str(d))
        self.store.create_match(team["id"], agent["id"], "crypto", fresh_seed(),
                                get_track("crypto").max_gen)
        return self.engine.run_match(self.store.claim_next_queued())

    def test_agent_that_solves_nothing_scores_no_depth(self):
        result = self.run_with("def solve(files):\n    return None\n", "nul")
        self.assertEqual(result["reached_gen"], -1)
        self.assertEqual(result["outcome"], "out_evolved")
        self.assertEqual(result["score"], 0)

    def test_wrong_flag_ends_the_climb(self):
        result = self.run_with("def solve(files):\n    return 'flag{nope}'\n", "wrong")
        self.assertEqual(result["outcome"], "wrong_flag")
        self.assertEqual(result["reached_gen"], -1)

    def test_solving_the_first_rung_advances_the_maker(self):
        source = (
            "def solve(files):\n"
            "    if not {'n.txt','e.txt','c.txt'} <= set(files): return None\n"
            "    n=int(files['n.txt']); e=int(files['e.txt']); c=int(files['c.txt'])\n"
            "    if e > 5: return None\n"
            "    lo, hi = 0, 1\n"
            "    while hi ** e <= c: hi <<= 1\n"
            "    while lo < hi:\n"
            "        mid = (lo + hi + 1) // 2\n"
            "        if mid ** e <= c: lo = mid\n"
            "        else: hi = mid - 1\n"
            "    if lo ** e != c: return None\n"
            "    return lo.to_bytes((lo.bit_length()+7)//8,'big').decode()\n")
        result = self.run_with(source, "cuberoot")
        self.assertEqual(result["reached_gen"], 0)
        self.assertGreater(result["score"], 0)

        events = [e["evt"] for e in self.store.events(self.store.recent_matches(1)[0]["id"])]
        self.assertIn("solve", events)
        self.assertGreaterEqual(events.count("challenge.deployed"), 2,
                                "the challenge-maker should have evolved after a solve")

    def test_flag_never_appears_in_the_event_log(self):
        self.run_with("def solve(files):\n    return None\n", "leak")
        match_id = self.store.recent_matches(1)[0]["id"]
        blob = json.dumps(self.store.events(match_id))
        self.assertNotIn("flag{", blob)

    def test_each_match_gets_its_own_seed(self):
        team = self.store.create_team("seeds")
        agent = self.store.create_agent(team_id=team["id"], name="a", kind="upload")
        seeds = {self.store.create_match(team["id"], agent["id"], "crypto",
                                         fresh_seed(), 6)["seed"] for _ in range(20)}
        self.assertEqual(len(seeds), 20, "seeds repeated — teams could trade flags")


class ApiTests(unittest.TestCase):
    """Drives the real HTTP server the way a competitor's script would."""

    @classmethod
    def setUpClass(cls):
        from arena_platform.server import Arena, Handler
        from http.server import ThreadingHTTPServer

        cls.tmp = Path(tempfile.mkdtemp())
        arena = Arena(data_dir=cls.tmp / "data", workers=1)
        arena.start()
        handler = type("BoundHandler", (Handler,), {"arena": arena})
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.httpd.daemon_threads = True
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.arena = arena

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.arena.engine.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def call(self, path, data=None, raw=None, token=None, method=None):
        url = self.base + path
        body = raw if raw is not None else (json.dumps(data).encode() if data is not None else None)
        req = urllib.request.Request(url, data=body,
                                     method=method or ("POST" if body is not None else "GET"))
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read() or b"{}")

    def test_config_advertises_tracks_and_isolation(self):
        cfg = self.call("/api/config")
        self.assertIn("crypto", cfg["tracks"])
        self.assertIn(cfg["isolation"]["strength"], ("strong", "medium", "basic"))
        self.assertEqual(cfg["tracks"]["crypto"]["rungs"], get_track("crypto").rungs)

    def test_pages_are_served(self):
        for path in ("/", "/submit", "/docs", "/match/anything", "/static/arena.css"):
            with urllib.request.urlopen(self.base + path, timeout=10) as resp:
                self.assertEqual(resp.status, 200, path)
                self.assertTrue(resp.read())

    def test_register_upload_and_queue_a_match(self):
        team = self.call("/api/teams", {"name": "api-team"})
        self.assertIn("token", team)
        agent = self.call("/api/agents?kind=upload&name=v1&filename=agent.py",
                          raw=b"def solve(files):\n    return None\n", token=team["token"])
        self.assertEqual(agent["entry"], "agent.py")
        match = self.call("/api/matches", {"agent_id": agent["id"], "track": "crypto"},
                          token=team["token"])
        self.assertEqual(match["status"], "queued")
        state = self.call(f"/api/matches/{match['match_id']}")
        self.assertEqual(state["match"]["team_name"], "api-team")

    def test_duplicate_team_name_returns_409(self):
        self.call("/api/teams", {"name": "twice"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.call("/api/teams", {"name": "twice"})
        self.assertEqual(ctx.exception.code, 409)

    def test_agent_endpoints_require_a_token(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.call("/api/agents")
        self.assertEqual(ctx.exception.code, 401)

    def test_one_team_cannot_use_another_teams_agent(self):
        a = self.call("/api/teams", {"name": "owner"})
        b = self.call("/api/teams", {"name": "borrower"})
        agent = self.call("/api/agents?kind=upload&name=x&filename=agent.py",
                          raw=b"def solve(f):\n    return None\n", token=a["token"])
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.call("/api/matches", {"agent_id": agent["id"], "track": "crypto"},
                      token=b["token"])
        self.assertEqual(ctx.exception.code, 404)

    def test_remote_token_is_never_echoed_back(self):
        team = self.call("/api/teams", {"name": "secretive"})
        self.call("/api/agents", {"kind": "remote", "name": "r",
                                  "remote_url": "https://example.com/solve",
                                  "remote_token": "super-secret"}, token=team["token"])
        blob = json.dumps(self.call("/api/agents", token=team["token"]))
        self.assertNotIn("super-secret", blob)

    def test_gen_zero_solve_is_reported_as_a_solve(self):
        """reached_gen == 0 is a real solve, not a falsy 'no solve'."""
        from arena_platform.server import _public_match

        row = {"track": "crypto", "reached_gen": 0, "agent_gen": 1}
        self.assertEqual(_public_match(row)["rung_reached"],
                         get_track("crypto").rungs[0])
        self.assertIsNone(_public_match({"track": "crypto", "reached_gen": -1,
                                         "agent_gen": 0})["rung_reached"])

    def test_uploads_land_in_their_own_agent_directory(self):
        team = self.call("/api/teams", {"name": "many-uploads"})
        ids = set()
        for i in range(3):
            agent = self.call(f"/api/agents?kind=upload&name=v{i}&filename=agent.py",
                              raw=b"def solve(f):\n    return None\n",
                              token=team["token"])
            ids.add(agent["id"])
        self.assertEqual(len(ids), 3)
        listed = self.call("/api/agents", token=team["token"])["agents"]
        self.assertEqual(len({a["id"] for a in listed}), 3)

    def test_unknown_match_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.call("/api/matches/nope")
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
