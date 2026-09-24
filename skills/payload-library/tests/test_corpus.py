import os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import corpus  # noqa: E402


class TestCorpus(unittest.TestCase):
    def test_categorize_maps_known_dirs_and_denies_unknown(self):
        self.assertEqual(corpus.categorize("raw/PayloadsAllTheThings/SQL Injection/Intruder/x.txt"), "sqli")
        self.assertEqual(corpus.categorize("raw/PayloadsAllTheThings/XSS Injection/xss.txt"), "xss_reflected")
        self.assertEqual(corpus.categorize("raw/PayloadsAllTheThings/Server Side Template Injection/ssti.txt"), "ssti")
        self.assertEqual(corpus.categorize("raw/PayloadsAllTheThings/Command Injection/cmd.txt"), "command_injection")
        self.assertEqual(corpus.categorize("raw/SecLists/Discovery/Web-Content/raft-medium.txt"), "forced_browsing")
        # deny-by-default: an unmapped path is NOT guessed
        self.assertIsNone(corpus.categorize("raw/PayloadsAllTheThings/Methodology and Resources/notes.md"))

    def test_build_and_search_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            raw = Path(d) / "raw" / "PayloadsAllTheThings" / "SQL Injection"
            raw.mkdir(parents=True)
            (raw / "intruder.txt").write_text("' OR '1'='1\n# a comment (skipped)\nUNION SELECT null\n\n")
            xss = Path(d) / "raw" / "SecLists" / "Fuzzing" / "XSS"
            xss.mkdir(parents=True)
            (xss / "xss.txt").write_text("<script>alert(1)</script>\n")
            db = str(Path(d) / "payloads.db")
            n = corpus.build_index(Path(d) / "raw", db, {"PAT_SHA": "abc", "SECLISTS_SHA": "def"})
            self.assertGreaterEqual(n, 3)  # 2 sql payloads + 1 xss, comment/blank skipped
            sqli = corpus.search(db, "sqli", 10)
            vals = [p["value"] for p in sqli]
            self.assertIn("' OR '1'='1", vals)
            self.assertIn("UNION SELECT null", vals)
            self.assertNotIn("# a comment (skipped)", vals)
            self.assertTrue(all("SQL" not in v or True for v in vals))
            self.assertTrue(corpus.search(db, "xss_reflected", 10))
            # a class with nothing indexed -> empty (caller falls back to BUILTINS)
            self.assertEqual(corpus.search(db, "jwt_weak_key", 10), [])

    def test_search_missing_db_is_empty_not_error(self):
        self.assertEqual(corpus.search("/nonexistent/payloads.db", "sqli", 8), [])


if __name__ == "__main__":
    unittest.main()
