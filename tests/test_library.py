"""The challenge library — authored challenges outlive the match that made them.

The rows here are published to a browser, so the tests that matter are the ones
that check what is NOT in them: the flag, the official solver, and the match
secret all stay server-side. A library entry must be exactly the package the
competing agent was handed, plus prose.
"""
from __future__ import annotations

import hashlib
import io
import json
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from autoctf_gan.compose import gen_composed
from autoctf_gan.crypto_ladder import CRYPTO_LADDER, gen_crypto_ladder
from arena_platform.store import Store

SECRET = "library-test-secret"


def _composed(seed: int = 1234, offset: int = 0):
    return gen_composed(seed=seed, generation=len(CRYPTO_LADDER) + offset,
                        flag_secret=SECRET)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.store = Store(self.tmp / "arena.sqlite3")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_an_archived_challenge_carries_no_answer(self):
        spec = _composed()
        entry = self.store.archive_challenge(spec=spec, track="crypto",
                                             team_name="alpha", match_id="match_x")
        self.assertIsNotNone(entry)
        stored = self.store.library_entry(entry["id"], with_files=True)
        blob = json.dumps(stored)
        self.assertNotIn(spec.flag, blob)
        self.assertNotIn(SECRET, blob)
        for name in spec.official_solver.files:
            self.assertNotIn(name, stored["files"])
        self.assertNotIn("flag_sha256", stored)

    def test_the_archived_files_are_what_the_agent_received(self):
        spec = _composed()
        entry = self.store.archive_challenge(spec=spec, track="crypto")
        stored = self.store.library_entry(entry["id"], with_files=True)
        self.assertEqual(stored["files"], dict(spec.artifacts))

    def test_the_composition_is_recorded(self):
        spec = _composed()
        entry = self.store.archive_challenge(spec=spec, track="crypto")
        stored = self.store.library_entry(entry["id"])
        self.assertEqual(stored["stages"], spec.mechanics["stages"])
        self.assertEqual(stored["depth"], spec.mechanics["depth"])
        self.assertEqual(stored["plan_source"], spec.mechanics["plan_source"])

    def test_replaying_a_match_does_not_duplicate_the_shelf(self):
        spec = _composed()
        self.assertIsNotNone(self.store.archive_challenge(spec=spec, track="crypto"))
        self.assertIsNone(self.store.archive_challenge(spec=spec, track="crypto"))
        self.assertEqual(self.store.library_count(), 1)

    def test_distinct_generations_are_distinct_entries(self):
        for offset in range(3):
            self.store.archive_challenge(spec=_composed(offset=offset), track="crypto")
        self.assertEqual(self.store.library_count(), 3)

    def test_a_flag_can_be_checked_without_being_stored(self):
        spec = _composed()
        entry = self.store.archive_challenge(spec=spec, track="crypto")
        self.assertFalse(self.store.library_check_flag(entry["id"], "flag{wrong}"))
        self.assertTrue(self.store.library_check_flag(entry["id"], spec.flag))
        self.assertEqual(self.store.library_entry(entry["id"])["solve_count"], 1)

    def test_a_ladder_rung_can_be_archived_but_reports_its_class(self):
        """Only authored challenges are archived by the runner; the store is generic."""
        spec = gen_crypto_ladder(seed=5, generation=0, flag_secret=SECRET)
        entry = self.store.archive_challenge(spec=spec, track="crypto")
        self.assertEqual(self.store.library_entry(entry["id"])["attack_class"], "smalle")

    def test_the_stored_hash_covers_a_64_bit_flag(self):
        """The hash is published; 48 bits of flag would be a tractable offline grind."""
        spec = _composed()
        body = spec.flag[len("flag{"):-1]
        self.assertGreaterEqual(len(body) * 4, 64)
        self.assertEqual(spec.official_solver.expected_flag_sha256,
                         hashlib.sha256(spec.flag.encode()).hexdigest())


class LibraryApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import ThreadingHTTPServer

        from arena_platform.server import Arena, Handler

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

        cls.spec = _composed(seed=42)
        cls.entry = arena.store.archive_challenge(
            spec=cls.spec, track="crypto", team_name="alpha", match_id="match_x")

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.arena.engine.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=20) as resp:
            return json.loads(resp.read() or b"{}")

    def post(self, path, data):
        req = urllib.request.Request(self.base + path, data=json.dumps(data).encode(),
                                     method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read() or b"{}")

    def test_the_library_page_is_served(self):
        with urllib.request.urlopen(self.base + "/library", timeout=10) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn(b"AutoCTF Arena \xe2\x80\x94 Challenges", resp.read())

    def test_the_practice_alias_serves_the_same_page(self):
        with urllib.request.urlopen(self.base + "/practice", timeout=10) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn(b"Practice set", resp.read())

    def test_config_reports_the_design_brain_and_shelf_size(self):
        cfg = self.get("/api/config")
        self.assertIn("design_brain", cfg)
        self.assertIn(cfg["design_brain"]["mode"], ("llm", "catalog"))
        self.assertGreaterEqual(cfg["library_size"], 1)
        self.assertTrue(cfg["tracks"]["crypto"]["endless"])
        self.assertTrue(cfg["tracks"]["crypto"]["route"])

    def test_listing_never_ships_a_flag_or_a_solver(self):
        data = self.get("/api/library")
        self.assertGreaterEqual(data["total"], 1)
        blob = json.dumps(data)
        self.assertNotIn(self.spec.flag, blob)
        self.assertNotIn("solver.py", blob)
        self.assertNotIn("rsa_stages.py", blob)

    def test_an_entry_lists_its_files_without_their_contents(self):
        entry = self.get(f"/api/library/{self.entry['id']}")
        names = {f["name"] for f in entry["file_list"]}
        self.assertEqual(names, set(self.spec.artifacts))
        self.assertNotIn("files", entry)

    def test_the_download_is_the_players_package(self):
        url = f"{self.base}/api/library/{self.entry['id']}/download"
        with urllib.request.urlopen(url, timeout=20) as resp:
            blob = resp.read()
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            names = set(zf.namelist())
            self.assertEqual(names, set(self.spec.artifacts) | {"CHALLENGE.txt"})
            for name in names:
                self.assertNotIn(self.spec.flag, zf.read(name).decode("utf-8", "replace"))

    def test_submitting_the_flag_is_checked_server_side(self):
        entry_id = self.entry["id"]
        self.assertFalse(self.post(f"/api/library/{entry_id}/submit",
                                   {"flag": "flag{nope}"})["correct"])
        self.assertTrue(self.post(f"/api/library/{entry_id}/submit",
                                  {"flag": self.spec.flag})["correct"])

    def test_filtering_by_designer_is_validated(self):
        """`source` reaches a SQL WHERE clause, so it is allow-listed, not escaped."""
        self.assertIn("entries", self.get("/api/library?source=catalog"))
        self.assertIn("entries", self.get("/api/library?source=llm"))
        hostile = urllib.parse.quote("'; DROP TABLE library; --")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.get(f"/api/library?source={hostile}")
        self.assertEqual(ctx.exception.code, 400)
        # and the table is still there
        self.assertGreaterEqual(self.get("/api/library")["total"], 1)

    def test_an_unknown_entry_is_a_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.get("/api/library/lib_doesnotexist")
        self.assertEqual(ctx.exception.code, 404)

    # ---- practice catalogue ------------------------------------------------
    def test_practice_catalogue_is_seeded_and_ordered(self):
        data = self.get("/api/library?origin=practice&limit=100")
        entries = data["entries"]
        # at least the whole crypto ladder is present, easiest first
        self.assertGreaterEqual(data["practice_total"], len(CRYPTO_LADDER))
        ranks = [e["rank"] for e in entries]
        self.assertEqual(ranks, sorted(ranks), "practice must read easiest-first")
        classes = {e["attack_class"] for e in entries}
        self.assertIn("smalle", classes)

    def test_a_practice_flag_checks_out(self):
        """The seeded flag is checkable, and never present in the served files."""
        from autoctf_gan.crypto_ladder import gen_crypto_ladder
        from arena_platform.practice import PRACTICE_SEED

        secret = self.arena.store.practice_secret()
        spec = gen_crypto_ladder(seed=PRACTICE_SEED, generation=0, flag_secret=secret)
        entries = self.get("/api/library?origin=practice&limit=100")["entries"]
        match = next(e for e in entries if e["title"] == spec.title)
        stored = self.get(f"/api/library/{match['id']}")
        self.assertNotIn("flag_sha256", json.dumps(stored))
        self.assertFalse(self.post(f"/api/library/{match['id']}/submit",
                                   {"flag": "flag{nope}"})["correct"])
        self.assertTrue(self.post(f"/api/library/{match['id']}/submit",
                                  {"flag": spec.flag})["correct"])

    def test_origin_is_allow_listed(self):
        hostile = urllib.parse.quote("' OR 1=1 --")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.get(f"/api/library?origin={hostile}")
        self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
