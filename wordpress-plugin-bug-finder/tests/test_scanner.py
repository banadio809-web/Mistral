import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wpbugfinder import scanner

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample-plugin", "trunk")


class TestScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = scanner.scan_plugin(
            FIXTURE, slug="sample-plugin", version="1.2.3",
            active_installs=1000)
        cls.rules = {(f.rule, f.attacker) for f in cls.res["findings"]}

    def test_finds_signals(self):
        self.assertIn(("missing_authorization", "unauthenticated"), self.rules)
        self.assertIn(("sqli", "unauthenticated"), self.rules)
        self.assertIn(("xss", "unauthenticated"), self.rules)
        self.assertIn(("open_redirect", "subscriber"), self.rules)
        self.assertIn(("missing_nonce", "subscriber"), self.rules)

    def test_sanitizer_no_finding(self):
        opts = [f for f in self.res["findings"] if f.rule == "options_update"]
        for f in opts:
            self.assertNotIn("sp_title", f.snippet)

    def test_scope_flags(self):
        for f in self.res["findings"]:
            self.assertTrue(f.in_scope)
            self.assertIn("PR:", f.vector)


if __name__ == "__main__":
    unittest.main()
