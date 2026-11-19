"""Missing Authorization / Missing Capability Check / Missing Nonce
Verification — the most commonly reported Wordfence bug classes.

Approach: resolve every attacker-reachable entry point (AJAX, admin-post,
REST, shortcode) to its callback function, then inspect the callback body for
state-changing writes, nonce verification and capability checks. A finding is
only emitted when the callback is actually reachable with the claimed
attacker privilege AND performs a sensitive action unsanctioned by checks.
"""

import re

from .. import context as C
from .. import php as phpmod

REST_SENSITIVE = re.compile(r"->\s*(set_args|get_param)\s*\(")


def scan(masked: str, source: str, relpath: str, ctx_info: dict) -> list:
    from ..finding import Finding
    findings = []
    # hook names live inside string literals -> resolve on RAW source
    eps = C.endpoints(source)
    if not eps:
        return findings
    funcs = {name: (bpos, bend) for (name, bpos, bend, fpos)
             in phpmod.functions(masked)}

    for ep in eps:
        if not ep.callback or len(ep.callback) != 2:
            continue
        _cls, fn = ep.callback
        if not fn or ep.func_pos is None:
            continue
        bend_pair = funcs.get(fn)
        if not bend_pair:
            continue
        bpos, bend = bend_pair
        body = masked[bpos + 1:bend]
        if not C.STATE_WRITES.search(body):
            continue
        reads_input = C.body_iterates_post(body)
        has_nonce = bool(C.HAS_NONCE_CHECK.search(body))
        has_cap = bool(C.HAS_CAP_CHECK.search(body))
        line = phpmod.line_of(masked, ep.func_pos)
        entry = {"hook": ep.hook, "kind": ep.kind, "line": ep.line,
                 "callback": fn}
        m_wr = C.STATE_WRITES.search(body)
        writes = (m_wr.groupdict().get("write") or m_wr.group(0)).replace(" ", "")
        # normalize e.g. "$wpdb->query" / "->get_results(" to a name

        if ep.privilege == "unauthenticated" and not has_cap:
            # Unauthenticated reachability + write + no capability check.
            findings.append(Finding(
                rule="missing_authorization", attacker="unauthenticated",
                file=relpath, line=line,
                snippet=phpmod.snippet(source, *_lines(masked, bpos, bend)),
                entry=entry, taint_path=[f"{fn}() -> {writes}()"],
                note=(f"callback for '{ep.hook}' performs {writes}() with no capability "
                      "check and is reachable by unauthenticated users"),
            ).finalize())
        elif ep.privilege == "subscriber" and not has_cap:
            re.search(
                r"update_option|update_site_option|update_user_meta|"
                r"wp_update_user|unlink|fwrite|file_put_contents|switch_theme|"
                r"deactivate_plugins|wp_insert_user|delete_user", writes or "")
            rule = "missing_authorization"
            note = (f"callback for '{ep.hook}' performs {writes}() with no capability "
                    "check; reachable by Subscriber-level users")
            findings.append(Finding(
                rule=rule, attacker="subscriber", file=relpath, line=line,
                snippet=phpmod.snippet(source, *_lines(masked, bpos, bend)),
                entry=entry, taint_path=[f"{fn}() -> {writes}()"], note=note,
            ).finalize())

        # Missing nonce/CSRF: state-changing privileged handler without a
        # nonce check.  Only meaningful when the action requires an
        # authenticated victim (CSRF).
        if ep.privilege != "unauthenticated" and not has_nonce and reads_input:
            findings.append(Finding(
                rule="missing_nonce", attacker=ep.privilege,
                file=relpath, line=line,
                snippet=phpmod.snippet(source, *_lines(masked, bpos, bend)),
                entry=entry, taint_path=[fn],
                note=(f"state-changing callback '{fn}' (hook '{ep.hook}') reads request "
                      "data without check_admin_referer/wp_verify_nonce"),
            ).finalize())

    # REST routes without permission_callback performing writes
    for m in C.REGISTER_REST.finditer(masked):
        open_pos = masked.index("(", m.start())
        close_pos = phpmod.match_paren(masked, open_pos)
        if close_pos == -1 or "permission_callback" in masked[open_pos:close_pos]:
            continue
        route_line = phpmod.line_of(masked, m.start())
        if STATE_WRITE_AFTER(masked, close_pos):
            findings.append(Finding(
                rule="missing_authorization", attacker="unauthenticated",
                file=relpath, line=route_line,
                snippet=phpmod.snippet(source, route_line, route_line + 6),
                entry={"hook": "rest_route", "kind": "rest"},
                taint_path=[],
                note="REST route registered without permission_callback and "
                     "writes state in its callback",
            ).finalize())

    return _dedupe(findings)


WRITE_AFTER_WINDOW = re.compile(r"\b(function\s|\})")


def STATE_WRITE_AFTER(masked: str, pos: int) -> bool:
    """Does one of the functions declared shortly after a REST registration
    perform state writes?  Weak heuristic: any state write anywhere in file
    combined with a REST route lacking permission_callback."""
    bodies = list(phpmod.functions(masked))
    for (name, bpos, bend, fpos) in bodies:
        if C.STATE_WRITES.search(masked[bpos + 1:bend]):
            return True
    return False


def _lines(masked, a, b):
    return (phpmod.line_of(masked, a), phpmod.line_of(masked, b))


def _dedupe(findings):
    seen = set()
    out = []
    for f in sorted(findings, key=lambda x: -x.score):
        k = (f.rule, f.entry.get("hook"), f.file)
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out
