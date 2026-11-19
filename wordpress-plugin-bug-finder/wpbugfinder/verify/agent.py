"""The Verification Agent.

For every finding the scanner emits, the agent:

 1. provisions (or reuses) a real WordPress sandbox in Docker;
 2. installs & activates the plugin under test;
 3. records a browser video of the end-to-end story:
       WP-Admin login  →  setup (activation screen, pages, files, users)
       →  the PoC being fired  →  the observed response / side effect;
 4. decides VERIFIED / NOT REPRODUCED from marker evidence, never vibes;
 5. writes per-finding artifacts (video, HAR, screenshots, curl repro,
    response body, result.json) plus a run summary.

Deliberately conservative: when the sandbox, Docker or the browser is not
available it says so in the verdict instead of guessing.
"""

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from ..criteria import SEVERITY_RANK
from . import checks, driver, poc as P


class _ProbeHandler(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):  # noqa: N802
        _ProbeHandler.hits.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"wpbf-probe-ok")

    def log_message(self, *a):  # silence
        pass


class Probe:
    """Tiny HTTP listener the sandbox can reach at host.docker.internal —
    proves Server-Side Request Forgery end-to-end."""

    def __init__(self):
        self.hits = _ProbeHandler.hits
        self.port = None
        self._srv = None

    def start(self):
        self._srv = HTTPServer(("0.0.0.0", 0), _ProbeHandler)
        self.port = self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True,
                         name="wpbf-ssrf-probe").start()

    def url(self):
        return (f"http://host.docker.internal:{self.port}/wpbf-probe"
                if self.port else None)

    def stop(self):
        if self._srv:
            self._srv.shutdown()


class VerifyAgent:
    def __init__(self, results: dict, plugin_source_dir: str,
                 runs_dir: str = None, sandbox_mode: str = "reuse",
                 video: bool = True, limit: int = None,
                 only_rule: str = None, min_severity: str = "low",
                 verbose: bool = True):
        self.results = results
        self.plugin_source_dir = plugin_source_dir
        self.slug = results.get("slug") or "plugin"
        run_id = time.strftime("%Y%m%d-%H%M%S")
        # default artifact home: <cwd>/.wpbf-cache/verify-runs/<ts>
        self.run_dir = os.path.abspath(
            runs_dir or os.path.join(os.getcwd(), ".wpbf-cache",
                                     "verify-runs", run_id))
        self.sandbox_mode = sandbox_mode
        self.video = video
        self.limit = limit or 10
        self.only_rule = only_rule
        self.min_sev = SEVERITY_RANK.get(min_severity.title(), 1)
        self.verbose = verbose
        self.sandbox = None
        self.probe = Probe()
        self.outcomes: list = []

    # -- helpers --------------------------------------------------------------
    def log(self, msg: str):
        if self.verbose:
            print(msg, flush=True)

    def _select_findings(self):
        fnd = self.results.get("findings", [])
        fnd = [f for f in fnd if SEVERITY_RANK[f.severity] >= self.min_sev]
        if self.only_rule:
            fnd = [f for f in fnd if f.rule == self.only_rule]
        return fnd[: self.limit]

    def _driver(self, out_dir: str, with_video: bool):
        if with_video and self.video and driver.HAS_PLAYWRIGHT:
            try:
                return driver.Recorder(out_dir).start()
            except Exception as exc:  # browser missing etc.
                self.log(f"  . video unavailable ({exc}); falling back to "
                         f"headless HTTP")
        return driver.PlainClient(out_dir)

    # -- main loop -------------------------------------------------------------
    def run(self) -> dict:
        os.makedirs(self.run_dir, exist_ok=True)
        findings = self._select_findings()
        summary = {"run_dir": self.run_dir, "plugin": self.results.get("plugin"),
                   "slug": self.slug, "sandbox_mode": self.sandbox_mode,
                   "findings_total": len(self.results.get("findings", [])),
                   "verification_attempts": []}

        if not findings:
            self.log("verify: no findings selected — nothing to verify")
            return summary

        if self.sandbox_mode != "off":
            self._start_sandbox()
            self._setup_plugin()
            self.probe.start()

        for i, finding in enumerate(findings, 1):
            self.log(f"\n[{i}/{len(findings)}] verifying {finding.rule} "
                     f"@ {finding.file}:{finding.line}")
            outcome = self._verify_one(i, finding)
            self.outcomes.append(outcome)
            summary["verification_attempts"].append(outcome)
            self.log(f"  → {outcome['verdict'].upper()} — "
                     f"{outcome['evidence'][:160]}")
        self._write_artifacts(summary)
        if self.sandbox:
            self.sandbox.down()
        self.probe.stop()
        return summary

    def _start_sandbox(self):
        from .sandbox import Sandbox, SandboxError
        sb = Sandbox(unique=f"{self.slug}-{time.strftime('%Y%m%d')}",
                     reuse=True, keep=True)
        if not sb.docker_ok():
            self.sandbox_mode = "off"
            self.log("  . docker not reachable — running headless checks only")
            return
        try:
            self.log("  . provisioning WordPress sandbox (docker)…")
            sb.up()
            self.sandbox = sb
            self.log(f"  . sandbox ready: {sb.url()}")
        except SandboxError as exc:
            self.sandbox_mode = "off"
            self.log(f"  !! sandbox failed: {exc} — headless checks only")

    def _setup_plugin(self):
        if not self.sandbox:
            return
        try:
            self.sandbox.install_plugin(self.plugin_source_dir, self.slug)
            self.log(f"  . plugin installed + activated: {self.slug}")
        except Exception as exc:
            self.log(f"  !! plugin install failed: {exc}")

    def _apply_setup(self, action: dict):
        """Sandbox-side state prep for a PoC (files, options, cleanup)."""
        if not self.sandbox:
            return
        try:
            t = action.get("type")
            if t == "create_file":
                content = action.get("content", "wpbf")
                self.sandbox.exec_sh(
                    f"printf '%s' '{content}' > '{action['container_path']}'")
            elif t == "cleanup_file":
                self.sandbox.exec_sh(
                    f"rm -f '{action['container_path']}'")
            elif t == "cleanup_upload":
                self.sandbox.exec_sh(
                    "find /var/www/html/wp-content/uploads "
                    f"-name '{action['filename']}' -delete")
            elif t == "check_option_absent":
                self.sandbox.exec_sh(
                    "cd /var/www/html && wp option delete "
                    f"{action['option']} --allow-root || true")
            elif t == "enable_debug":
                # SQL-injection (and similar) PoCs surface MySQL errors only
                # when debug display is on; the sandbox is disposable so
                # enabling it is the honest way to make the leak observable.
                self.sandbox.wpcli("config", "set", "WP_DEBUG", "true", "--raw")
                self.sandbox.wpcli("config", "set", "WP_DEBUG_DISPLAY",
                                   "true", "--raw")
        except Exception as exc:
            self.log(f"  . setup action {action.get('type')} failed: {exc}")

    # -- one finding ---------------------------------------------------------
    def _verify_one(self, index: int, finding) -> dict:
        marker = P.new_run_token()
        case_dir = os.path.join(self.run_dir, f"{index:02d}-{finding.rule}")
        os.makedirs(case_dir, exist_ok=True)

        poc = P.build_poc(
            finding, marker, host_probe_url=self.probe.url(),
            plugin_source_dir=self.plugin_source_dir)
        self._dump_json(os.path.join(case_dir, "finding.json"),
                        finding.to_dict())
        self._dump_json(os.path.join(case_dir, "poc.json"), poc.to_dict())

        if not poc.attempts:
            outcome = self._outcome(case_dir, finding, poc, "unverifiable",
                                    poc.notes or "no automated PoC", [])
            self._dump_json(os.path.join(case_dir, "result.json"), outcome)
            return outcome

        site = self.sandbox.url() if self.sandbox else "http://127.0.0.1:0"
        d = self._driver(case_dir, with_video=self.sandbox is not None)

        recorded: list = []   # (attempt, status, body, elapsed, ok, ev)
        evidence = ""
        try:
            self._record_story(d, site, finding, poc, marker, recorded)
        except Exception as exc:
            evidence = f"story crashed: {exc.__class__.__name__}: {exc}"[:400]
        finally:
            verdict = ("verified" if any(r[4] for r in recorded)
                       else "not_reproduced")
            ok_rows = [r for r in recorded if r[4]]
            if evidence and not recorded:
                verdict = "error"
            elif ok_rows:
                evidence = ok_rows[0][5]
            elif recorded:
                evidence = evidence or recorded[0][5]
            d.verdict_banner(verdict == "verified",
                             f"case {index:02d} {finding.rule} — "
                             f"{verdict.upper()}")
            d.screenshot("final-state.png")
            video = d.finalize_video()
            d.stop()

            outs = [{"attempt": a.label, "status": s,
                     "elapsed": round(e, 2), "ok": ok, "evidence": ev,
                     "response": (body or "")[:4000]}
                    for (a, s, body, e, ok, ev) in recorded]
            outcome = self._outcome(case_dir, finding, poc, verdict,
                                    evidence, recorded, video)
            self._dump_json(os.path.join(case_dir, "result.json"), outcome)
            self._write_text(os.path.join(case_dir, "response.txt"),
                             "\n\n".join(
                                 f"### {o['attempt']} (HTTP {o['status']})\n"
                                 f"{o['response']}" for o in outs)
                             or "(no responses)")
        return outcome

    # the full on-camera story: login -> setup -> exploit -> check
    def _record_story(self, d, site: str, finding, poc, marker: str,
                      recorded: list):
        idx = 1
        d.caption(f"CASE: {finding.title}" if finding.title
                  else f"CASE: {poc.rule}",
                  f"finding at {finding.file}:{finding.line} — "
                  f"verifying in the sandbox")

        # 1) login (whoever the finding assumes the attacker is)
        if poc.needs_auth != "none":
            from .sandbox import SUB_USER, SUB_PASS, ADMIN_USER, ADMIN_PASS
            user, pw = ((SUB_USER, SUB_PASS) if poc.needs_auth == "subscriber"
                        else (ADMIN_USER, ADMIN_PASS))
            d.login_wordpress(site, user, pw, who=poc.needs_auth)
        else:
            d.caption("Attack context: UNAUTHENTICATED (no login needed)",
                      "firing the PoC anonymously")

        # 2) setup: prepare whatever the PoC needs before firing
        if poc.endpoint_kind == "shortcode" and self.sandbox:
            d.caption("Setup: creating a page that renders the shortcode",
                      "wp post create --_shortcode")
            try:
                tag = (finding.entry.get("hook") or "").split(":", 1)[-1]
                pid = self.sandbox.wpcli(
                    "post", "create", "--post_title=wpbf PoC page",
                    f"--post_name=wpbf-poc-page",
                    f"--post_content=[{tag}]", "--porcelain").strip()
                poc.base_url = f"/?p={pid}"
            except Exception as exc:
                self.log(f"  !! shortcode page setup failed: {exc}")
        if poc.setup and self.sandbox:
            for action in poc.setup:
                kind = action.get("type")
                d.caption(f"Setup: {kind}", str(action))
                self._apply_setup(action)
        if self.sandbox and poc.needs_auth != "none":
            d.caption("Setup: the plugin under test", f"slug: {self.slug}")
            try:
                d.goto(self.sandbox.url(
                    "/wp-admin/plugins.php?s=" + self.slug))
            except Exception:
                pass

        # 3) fire the PoC (each attempt on camera)
        observed = {"probe_hits": self.probe.hits,
                    "js_property": getattr(d, "js_property_seen", {})}
        for attempt in poc.attempts:
            d.caption(f"Firing PoC ({idx}/{len(poc.attempts)}): "
                      f"{attempt.label}", poc.base_url + "?action=…")
            if poc.upload:
                t0 = time.time()
                status, body = d.upload_multipart(
                    site + poc.base_url, poc.upload["field"],
                    poc.upload["filename"], poc.upload["content"],
                    extra_params={**attempt.params, **attempt.body_params})
                elapsed = time.time() - t0
            elif attempt.method == "POST":
                t0 = time.time()
                status, body = d.show_exploit(
                    site + poc.base_url, "POST", attempt.params,
                    attempt.body_params, label="POST PoC payload")
                elapsed = time.time() - t0
            else:
                t0 = time.time()
                status, body = d.show_exploit(
                    site + poc.base_url, "GET", attempt.params,
                    label="GET PoC request")
                elapsed = time.time() - t0
            ok, ev = checks.evaluate(attempt, status, body, elapsed,
                                     sandbox=self.sandbox, observed=observed)
            recorded.append((attempt, status, body, elapsed, ok, ev))
            d.caption(("✓ evidence collected" if ok else "✗ no evidence"),
                      ev)
            idx += 1
        d.caption("Done — collecting artifacts",
                  f"marker for this run: {marker}")

    # -- artifacts -------------------------------------------------------------
    def _outcome(self, case_dir, finding, poc, verdict, evidence, attempts,
                 video=None) -> dict:
        at = [{"attempt": a.label, "status": s, "elapsed": round(e, 2),
               "ok": ok, "evidence": ev}
              for (a, s, b, e, ok, ev) in attempts]
        return {
            "rule": finding.rule, "severity": finding.severity,
            "score": finding.score, "title": finding.title,
            "file": finding.file, "line": finding.line,
            "entry": finding.entry, "verdict": verdict,
            "evidence": evidence, "marker": poc.marker,
            "observable": poc.observable, "attempts": at,
            "video": os.path.relpath(video, self.run_dir)
            if video and os.path.isabs(video) else video,
            "case_dir": os.path.relpath(case_dir, self.run_dir),
        }

    def _write_artifacts(self, summary: dict):
        # summary.md + index.json
        self._dump_json(os.path.join(self.run_dir, "index.json"), summary)
        lines = [f"# Verification run — {self.results.get('plugin')}",
                 "", f"*run dir:* `{self.run_dir}`", "",
                 "| case | rule | severity | verdict | evidence |", "|---|---|---|---|---|"]
        for o in summary.get("verification_attempts", []):
            lines.append(f"| {o['case_dir']} | {o['rule']} | {o['severity']} |"
                         f" **{o['verdict']}** | {o['evidence'][:150]} |")
        lines.append("")
        self._write_text(os.path.join(self.run_dir, "summary.md"),
                         "\n".join(lines))
        self.log(f"\nartifacts: {self.run_dir}")

    @staticmethod
    def _dump_json(path, obj):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, default=str)

    @staticmethod
    def _write_text(path, text):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
