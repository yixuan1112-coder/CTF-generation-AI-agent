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
from arena_platform.runner import MatchEngine, fresh_seed
from arena_platform.sandbox import Limits, run_agent
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


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
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

    def test_rung_name_clamps_past_the_end(self):
        track = get_track("crypto")
        self.assertEqual(track.rung_name(999), track.rungs[-1])


class TrackLadderIntegrityTests(unittest.TestCase):
    """A track must not advertise more rungs than its generator can produce.

    Each of these ladders clamps at its last entry: ask for a deeper generation
    and you get the previous challenge back. If a Track declares more rungs than
    that, the arena redeploys an identical rung while telling the team it evolved,
    and "cleared" stops meaning anything.
    """

    def _distinct_rungs(self, category: str, probe_depth: int = 9) -> int:
        from autoctf_gan.competition import Competition

        comp = Competition(category=category, seed=99, evolve_on=1,
                           max_gen=probe_depth, verify_deploy=True)
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
        self.assertEqual(len(get_track("web").rungs), self._distinct_rungs("web"))

    def test_crypto_track_matches_the_engine_ladder(self):
        from autoctf_gan.crypto_ladder import LADDER_NAMES
        self.assertEqual(get_track("crypto").rungs, list(LADDER_NAMES))

    def test_reverse_track_rungs_are_all_reachable(self):
        """Reverse has no ceiling, so every declared rung must be distinct."""
        track = get_track("reverse")
        self.assertLessEqual(len(track.rungs),
                             self._distinct_rungs("reverse", probe_depth=9))


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
