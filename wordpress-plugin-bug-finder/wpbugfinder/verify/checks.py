"""Verdict evaluation: success criteria per PoC attempt.

Reads the observed HTTP response(s) + post-request sandbox state and returns
(ok, evidence) so the agent can record VERIFIED / NOT REPRODUCED with proof
instead of gut feeling.
"""

import base64
import re
import time

DEFAULT_REJECTS = ("0", "-1", '{"code":"rest_forbidden"', "wp_verify_nonce")


def _reject_pattern(body: str) -> bool:
    s = body.strip()
    if s in DEFAULT_REJECTS or s.startswith('{"code":"rest_forbidden"'):
        return True
    if re.search(r"\brest_forbidden\b|cheatin|are you sure", s[:400], re.I):
        return True
    return False


def evaluate(attempt, status: str, body: str, elapsed: float,
             sandbox=None, observed=None) -> tuple:
    """(ok, evidence) against `attempt.success_requires`.

    `observed` carries driver-collected side channels (dialog/js/probe hits).
    """
    req = attempt.success_requires or {}
    responded = status not in ("0", "", None)
    if not responded:
        return False, f"no response (status {status!r})"

    # baseline handler-rejection semantics
    if req.get("handler_replied") and _reject_pattern(body):
        return False, "handler rejected the request (0/-1/rest_forbidden)"
    if req.get("handler_replied") and not body.strip():
        return False, "handler returned an empty body (no usable evidence)"

    want = req.get("body_contains")
    if want and want in body:
        return True, f"response contains {want!r}"

    want_raw = req.get("body_contains_raw")
    if want_raw and want_raw in body:
        return True, f"unescaped payload reflected verbatim: {want_raw!r}"

    rx = req.get("body_regex")
    if rx and re.search(rx, body):
        return True, f"response matches {rx!r} "

    want64 = req.get("base64_contains")
    if want64:
        for b64 in re.findall(r"[A-Za-z0-9+/=\n]{50,}", body):
            try:
                dec = base64.b64decode(b64, validate=False).decode(
                    "utf-8", "replace")
            except Exception:
                continue
            if want64 in dec:
                return True, (f"base64 chunk decodes to content containing "
                              f"{want64!r} (wp-config leaked)")

    delay = attempt.expect_delay_secs
    if delay and elapsed >= delay:
        return True, (f"response took {elapsed:.1f}s >= SLEEP threshold "
                      f"{delay}s (time-based SQLi)")

    # sandbox state checks ---------------------------------------------------
    if sandbox is not None:
        want_file = req.get("file_exists")
        if want_file is not None:
            if sandbox.file_exists(want_file):
                return True, f"sandbox file exists: {want_file}"
            return False, f"sandbox file missing: {want_file}"

        want_gone = req.get("file_missing")
        if want_gone is not None:
            time.sleep(0.5)
            if not sandbox.file_exists(want_gone):
                return True, f"sandbox file deleted: {want_gone}"
            return False, f"sandbox file still present: {want_gone}"

        opt = req.get("option_eq")
        if opt and sandbox.option_eq(opt[0], opt[1]):
            return True, f"option {opt[0]!r} == {opt[1]!r} in the sandbox DB"

    # driver side channels ---------------------------------------------------
    obs = observed or {}
    nav = req.get("navbar_event")
    if nav and nav in str(obs.get("navbar_event", "")):
        return True, f"browser navigated to {obs['navbar_event']!r}"

    jsprop = req.get("js_property")
    if jsprop and obs.get("js_property", {}).get(jsprop):
        return True, f"payload's onload handler executed ({jsprop} set)"

    hit = req.get("probe_hit")
    if hit and obs.get("probe_hits"):
        for h in obs["probe_hits"]:
            if hit in h:
                return True, f"probe listener was hit: {h!r}"

    up = req.get("uploaded_exec")
    if up:
        m = re.search(r"https?://[^\s'\"<>]+?", body)
        if m:
            return (False, "uploaded but no executing URL found") \
                if "wpbf_poc_shell" not in m.group(0) else _probe_upload(
                    m.group(0), up)

    return False, "criteria not met in response or sandbox state"


def _probe_upload(path: str, marker: str):
    try:
        import urllib.request
        with urllib.request.urlopen(path, timeout=15) as r:
            txt = r.read().decode("utf-8", "replace")
        if marker in txt:
            return True, f"uploaded file executes: {path} returned {marker!r}"
        return False, f"uploaded file at {path} did not execute"
    except Exception as exc:  # noqa: BLE001
        return False, f"uploaded file fetch failed: {exc}"
