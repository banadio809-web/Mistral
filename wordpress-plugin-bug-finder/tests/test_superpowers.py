import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wpbugfinder import scanner, taint as T
from wpbugfinder.verify import poc as P
from wpbugfinder.verify import checks
from wpbugfinder.verify.poc import Attempt

HERE = os.path.dirname(__file__)


class TwoPluginFileCase(unittest.TestCase):
    """Two-file plugin: hook registered in includes/hooks.php, vulnerable
    callback body in includes/sink.php — the classic cross-file blind spot."""

    @classmethod
    def setUpClass(cls):
        base = os.path.join(HERE, "fixtures", "cross-file-plugin")
        cls.res = scanner.scan_plugin(
            base, slug="cross-file-plugin", version="1.0.0",
            active_installs=5000)

    def test_cross_file_callback_gets_attacker_context(self):
        rules = {(f.rule, f.attacker, f.file) for f in self.res["findings"]}
        # the sink lives in sink.php but its entry is wp_ajax_nopriv_ → unauth
        self.assertTrue(
            any(r == "sqli" and a == "unauthenticated" for (r, a, _f) in rules),
            f"expected unauth sqli via cross-file endpoint, got {rules}")

    def test_xor_helper_interprocedural(self):
        from wpbugfinder import php as phpmod
        src = open(os.path.join(HERE, "fixtures", "cross-file-plugin",
                                "includes", "sink.php"),
                   encoding="utf-8").read()
        masked = phpmod.mask_php(src)
        sums = T.helper_summaries(masked)
        self.assertTrue(sums.get("wpbf_decode"),
                        "helper returning its param must be flagged tainted")
        rules = [f.rule for f in self.res["findings"]]
        self.assertIn("sqli", rules)


class NewSinkCase(unittest.TestCase):
    def _scan_src(self, php: str):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            slug = "sinkfixture"
            d = os.path.join(td, slug)
            os.makedirs(d)
            open(os.path.join(d, f"{slug}.php"), "w", encoding="utf-8").write(
                "<?php // Plugin Name: sinkfixture\n"
                "function sf_cb() {\n"
                "    global $wpdb;\n    "
                + php.replace("\n", "\n    ") + "\n}\n")
            return scanner.scan_plugin(d, slug=slug, active_installs=5000)

    def test_include_is_file_inclusion(self):
        res = self._scan_src(
            "$p = $_GET['tpl']; include($p . '.php');")
        self.assertIn("file_inclusion", [f.rule for f in res["findings"]])

    def test_extract_is_variable_overwrite(self):
        res = self._scan_src("extract($_REQUEST); trigger_error('x');")
        self.assertIn("variable_overwrite", [f.rule for f in res["findings"]])

    def test_extract_with_extr_skip_not_flagged(self):
        res = self._scan_src("extract($_REQUEST, EXTR_SKIP); $x = 1;")
        self.assertNotIn("variable_overwrite", [f.rule for f in res["findings"]])

    def test_parse_str_two_args_not_flagged(self):
        res = self._scan_src("parse_str($_POST['s'], $out); $x = 1;")
        self.assertNotIn("variable_overwrite", [f.rule for f in res["findings"]])

    def test_die_with_get_is_xss(self):
        res = self._scan_src("die($_GET['msg']);")
        self.assertIn("xss", [f.rule for f in res["findings"]])

    def test_mkdir_taint_is_file_write(self):
        res = self._scan_src("mkdir($_GET['dir']); $x = 1;")
        self.assertIn("file_write", [f.rule for f in res["findings"]])


class PoCCase(unittest.TestCase):
    def _finding(self, src, hook="wp_ajax_nopriv_do_it",
                 rule="sqli", kind="ajax"):
        res = self._scan(src)  # reuse NewSinkCase._scan_src style
        if res["findings"]:
            f = res["findings"][0]
            f.rule = rule
            f.entry = {"hook": hook, "kind": kind, "line": f.line}
            return f.finalize()
        raise AssertionError("fixture produced no finding")

    def _scan(self, php):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "pocfix")
            os.makedirs(d)
            open(os.path.join(d, "pocfix.php"), "w", encoding="utf-8").write(
                "<?php // Plugin Name: pocfix\n"
                "function poc_cb() {\n    global $wpdb;\n    "
                + php.replace("\n", "\n    ") + "\n}\n")
            return scanner.scan_plugin(d, slug="pocfix", active_installs=5000)

    def test_ajax_poc_targets_admin_ajax_with_action(self):
        f = self._finding("$v = $_GET['q']; $wpdb->query($v);")
        poc = P.build_poc(f, "WPBFTESTMARKER")
        self.assertEqual(poc.base_url, "/wp-admin/admin-ajax.php")
        a = poc.attempts[0]
        self.assertEqual(a.params.get("action"), "do_it")
        self.assertIn("q", a.params)
        self.assertIn("EXTRACTVALUE", a.params["q"])
        # quote-free payload: the marker rides as a MySQL hex literal
        self.assertIn(f"0x{'WPBFTESTMARKER'.encode().hex()}", a.params["q"])

    def test_param_keys_come_from_snippet(self):
        f = self._finding("echo $_POST['cmt'];", rule="stored_xss")
        poc = P.build_poc(f, "WPBFM")
        a = poc.attempts[0]
        self.assertIn("cmt", a.body_params)

    def test_rest_route_from_source(self):
        src = ("register_rest_route('acme/v1', '/export/(?P<id>[0-9]+)', "
               "[ 'callback' => 'acme_export', 'permission_callback' => "
               "'__return_true' ]);")
        self.assertEqual(P.rest_route_from_source(src),
                         "/wp-json/acme/v1/export/(?P<id>[0-9]+)")

    def test_poc_dict_roundtrip(self):
        f = self._finding("echo $_GET['m'];", rule="xss")
        poc = P.build_poc(f, "WPBFM")
        d = poc.to_dict()
        self.assertEqual(d["marker"], "WPBFM")
        self.assertTrue(d["attempts"])


class ChecksCase(unittest.TestCase):
    def test_body_contains_verified(self):
        a = Attempt(label="x", success_requires={"body_contains": "~WPBF1"})
        ok, ev = checks.evaluate(a, "200", "error: ~WPBF1 near LIMIT", 0.1)
        self.assertTrue(ok)

    def test_rejection_not_verified(self):
        a = Attempt(label="x", success_requires={"handler_replied": True})
        ok, _ = checks.evaluate(a, "200", "0", 0.1)
        self.assertFalse(ok)

    def test_rest_forbidden_not_verified(self):
        a = Attempt(label="x", success_requires={"handler_replied": True})
        ok, _ = checks.evaluate(
            a, "401", '{"code":"rest_forbidden","message":"Sorry..."}', 0.1)
        self.assertFalse(ok)

    def test_time_based(self):
        a = Attempt(label="t", expect_delay_secs=3.5)
        ok, ev = checks.evaluate(a, "200", "ok", 4.2)
        self.assertTrue(ok)
        ok2, _ = checks.evaluate(a, "200", "ok", 0.8)
        self.assertFalse(ok2)


if __name__ == "__main__":
    unittest.main()
