import os, sys, unittest
sys.path.insert(0, os.path.dirname(__file__))       # sqlite test client
os.environ["WPBF_DB_MODE"] = "test"
os.environ["DATABASE_URL"] = "sqlite://./tests/prisma-test/wpbf-test.db"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

if not os.path.isdir(os.path.join(os.path.dirname(__file__), "prisma-test", "prisma_client")):
    raise unittest.SkipTest(
        "sqlite prisma client not generated; run: WPBF_DB_MODE=test "
        "python3 -m prisma generate --schema tests/prisma-test/schema.prisma")

from wpbugfinder import scanner, db


class TestDbRoundTrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = scanner.scan_plugin(
            "tests/fixtures/sample-plugin/trunk",
            slug="sample-plugin", version="1.2.3", active_installs=1000)

    def test_store_and_query(self):
        scan_id = db.store(self.results)
        self.assertTrue(scan_id)
        rows = db.query(in_scope=False)
        mine = [r for r in rows if r.scanId == scan_id]
        self.assertTrue(mine)
        crit = [r for r in mine if r.severity == "Critical" and r.inScope]
        self.assertTrue(crit)
        row = mine[0]
        self.assertEqual(row.scan.plugin.slug, "sample-plugin")
        import json as _json
        cwes = _json.loads(row.cwe)
        self.assertIsInstance(cwes, list)


if __name__ == "__main__":
    unittest.main()
