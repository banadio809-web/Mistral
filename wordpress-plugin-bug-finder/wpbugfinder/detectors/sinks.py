"""Taint-flow sink detectors — the core 'real signal' rules.

A finding is only emitted when attacker-controlled data (superglobal or a
variable proven tainted by the taint engine) reaches a dangerous sink and is
not neutralized by a sanitizer at the sink.  Class naming follows the
Wordfence Intelligence vulnerability taxonomy.
"""

import re

from .. import php as phpmod
from .. import taint as T

SINK = r"(?<![\\$\w>])%s\s*\("


def _paren_arg(masked: str, open_off: int) -> tuple:
    """(arg_text, arg_abs_offset, close_pos) for a call opened at open_off."""
    close = phpmod.match_paren(masked, open_off)
    if close == -1:
        return "", open_off, -1
    inner = open_off + 1
    lead = len(masked[inner:close]) - len(masked[inner:close].lstrip())
    return masked[inner + lead:close].strip(), inner + lead, close


def _sink_occurrences(masked: str, stmt: str, stmt_off: int,
                      state: dict, sink_regex: str, mode: str = "any",
                      arg_index: int = None):
    """Yield (var, pos,开放的arg_offset) — unsanitized tainted occurrences
    inside a sink call found in this statement."""
    for m in re.finditer(sink_regex, stmt):
        rel_lp = m.end() - 1
        open_off = stmt_off + rel_lp
        arg, arg_off, close = _paren_arg(masked, open_off)
        if close == -1 or not arg:
            continue
        occ = [o for o in T.tainted_occurrences(masked, arg, arg_off, state)
               if o[2]]
        if not occ:
            continue
        if arg_index is not None:
            first = _first_top_level_arg_span(masked, open_off)
            if first:
                a_start, a_end = first
                if not any(a_start <= p < a_end for (_, p, _) in occ):
                    continue
        yield occ, open_off


def _first_top_level_arg_span(masked: str, open_off: int):
    """Span (start,end) of the first top-level argument of a call."""
    depth = 0
    i = open_off + 1
    start = i
    while i < len(masked):
        ch = masked[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                return (start, i)
            depth -= 1
        elif ch == "," and depth == 0:
            return (start, i)
        i += 1
    return None


def _has_top_level_comma(masked: str, open_off: int) -> bool:
    """True when the call opened at open_off has more than one top-level
    argument (a top-level comma between its parens)."""
    close = phpmod.match_paren(masked, open_off)
    if close == -1:
        return False
    depth = 0
    for i in range(open_off + 1, close):
        ch = masked[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return True
    return False


# sink tables ---------------------------------------------------------------

SQL_SINKS = [
    (r"(?<![\\$\w>])\$\w+\s*->\s*query\s*\(", "wpdb->query"),
    (r"(?<![\\$\w>])\$\w+\s*->\s*get_(?:results|var|row|col)\s*\(", "wpdb->get_*"),
    (r"(?<![\\$\w>])mysql_query\s*\(", "mysql_query"),
    (r"(?<![\\$\w>])mysqli_query\s*\(", "mysqli_query"),
    (r"(?<![\\$\w>])\$\w+\s*->\s*rawQuery\s*\(", "rawQuery"),
]

RCE_SINKS = [
    (r"(?<![\\$\w>])eval\s*\(", "eval"),
    (r"(?<![\\$\w>])assert\s*\(", "assert"),
    (r"(?<![\\$\w>])create_function\s*\(", "create_function"),
    (r"(?<![\\$\w>])system\s*\(", "system"),
    (r"(?<![\\$\w>])shell_exec\s*\(", "shell_exec"),
    (r"(?<![\\$\w>])passthru\s*\(", "passthru"),
    (r"(?<![\\$\w>])exec\s*\(", "exec"),
    (r"(?<![\\$\w>])proc_open\s*\(", "proc_open"),
    (r"(?<![\\$\w>])popen\s*\(", "popen"),
]

FILE_READ_SINKS = [
    (r"(?<![\\$\w>])file_get_contents\s*\(", "file_get_contents"),
    (r"(?<![\\$\w>])\bfile\s*\(", "file"),
    (r"(?<![\\$\w>])readfile\s*\(", "readfile"),
    (r"(?<![\\$\w>])fopen\s*\(", "fopen"),
    (r"(?<![\\$\w>])highlight_file\s*\(", "highlight_file"),
]

FILE_WRITE_SINKS = [
    (r"(?<![\\$\w>])file_put_contents\s*\(", "file_put_contents"),
    (r"(?<![\\$\w>])fwrite\s*\(", "fwrite"),
    (r"(?<![\\$\w>])fputs\s*\(", "fputs"),
    (r"(?<![\\$\w>])mkdir\s*\(", "mkdir"),
    (r"(?<![\\$\w>])touch\s*\(", "touch"),
    (r"(?<![\\$\w>])copy\s*\(", "copy"),
    (r"->\s*extractTo\s*\(", "ZipArchive->extractTo"),
]

# include/require + taint = local/remote file execution (CWE-22/98/94)
FILE_INCLUSION_SINKS = [
    (r"(?<![\$\w>])include\s*\(", "include"),
    (r"(?<![\$\w>])include_once\s*\(", "include_once"),
    (r"(?<![\$\w>])require\s*\(", "require"),
    (r"(?<![\$\w>])require_once\s*\(", "require_once"),
]

# extract() / parse_str() with attacker data rewrite arbitrary variables
VARIABLE_OVERWRITE_SOURCE_RE = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE|FILES)\b|php://input",
    re.I)
EXTR_SKIP_RE = re.compile(r"EXTR_(SKIP|PREFIX_ALL|PREFIX_SAME|PREFIX_IF_EXISTS)")

FILE_DELETE_SINKS = [
    (r"(?<![\\$\w>])unlink\s*\(", "unlink"),
    (r"(?<![\\$\w>])rmdir\s*\(", "rmdir"),
    (r"(?<![\\$\w>])wp_delete_file\s*\(", "wp_delete_file"),
]

SSRF_SINKS = [
    (r"(?<![\\$\w>])wp_remote_get\s*\(", "wp_remote_get"),
    (r"(?<![\\$\w>])wp_remote_post\s*\(", "wp_remote_post"),
    (r"(?<![\\$\w>])wp_remote_request\s*\(", "wp_remote_request"),
    (r"(?<![\\$\w>])curl_init\s*\(", "curl_init"),
    (r"(?<![\\$\w>])fsockopen\s*\(", "fsockopen"),
]

REDIRECT_SINKS = [
    (r"(?<![\\$\w>])wp_redirect\s*\(", "wp_redirect"),
    (r"(?<![\\$\w>])header\s*\(", "header"),
]

XSS_FUNCS = [
    (r"(?<![\$\w>])printf\s*\(", "printf"),
    (r"(?<![\$\w>])_e\s*\(", "_e"),
    (r"(?<![\$\w>])print_r\s*\(", "print_r"),
    (r"(?<![\$\w>])var_dump\s*\(", "var_dump"),
]

ECHO_RE = re.compile(r"^(?:echo|print|printf|die|exit)\b|^=\s*")

OTHER_SINKS = {
    "unserialize": "object_injection",
    "do_shortcode": "shortcode_exec",
    "update_option": "options_update",
    "update_site_option": "options_update",
    "update_network_option": "options_update",
}


def scan(masked: str, source: str, relpath: str, ctx_info: dict) -> list:
    """Run all taint-flow sink checks over one PHP file.

    ctx_info: {'privilege_default': str, 'entry_by_func': {fn: (priv, entry_dict)}} —
    resolves the attacker context of a sink from the WordPress hook that
    reaches the enclosing function (Wordfence-style 'Authenticated (X)'
    attribution).
    """
    from ..finding import Finding
    findings = []
    entry_by_func = ctx_info.get("entry_by_func", {})

    def ctx_for(fname):
        if fname in entry_by_func:
            priv, entry = entry_by_func[fname]
            return priv, entry
        return ctx_info.get("privilege_default", "subscriber"), None

    for (stmt, off, end, sl, el), state, fname in T.statements_with_state(masked):
        occ_cache = {}

        def occs(sink_regex, mode="any", arg_index=None):
            key = (sink_regex, mode, arg_index, off)
            if key not in occ_cache:
                occ_cache[key] = list(_sink_occurrences(
                    masked, stmt, off, state, sink_regex, mode, arg_index))
            return occ_cache[key]

        def add(rule, occ, open_off, note="", line=None, entry_base=None):
            vars_in = []
            for (v, pos, _) in occ:
                if v not in vars_in:
                    vars_in.append(v)
            if not vars_in:
                return
            priv, entry0 = ctx_for(fname)
            entry = dict(entry0 or {})
            if entry_base:
                entry.update(entry_base)
            find = Finding(
                rule=rule,
                attacker=priv,
                file=relpath,
                line=line or phpmod.line_of(masked, open_off),
                snippet=phpmod.snippet(source, sl, el),
                entry=entry,
                taint_path=vars_in,
                note=note,
            ).finalize()
            findings.append(find)

        # echo / print / <?= — attacker data printed unescaped
        if ECHO_RE.match(stmt):
            occ = [o for o in T.tainted_occurrences(masked, stmt, off, state)
                   if o[2]]
            if occ:
                srcvar = occ[0][0]
                is_reflected = srcvar in ("$_SERVER",) or "REQUEST_URI" in stmt \
                    or "PHP_SELF" in stmt or srcvar in T.SOURCES
                add("xss" if is_reflected else "stored_xss", occ, off,
                    note="request data echoed without escaping",
                    line=sl)
        for rx, name in XSS_FUNCS:
            for occ, open_off in occs(rx):
                add("xss", occ, open_off,
                    note=f"{name}() prints request data without escaping")
        for rx, name in SQL_SINKS:
            for occ, open_off in occs(rx):
                # prepare args are already sanitizer-wrapped; drop those
                add("sqli", occ, open_off,
                    note=f"unsanitized request data concatenated into {name}()")
        for rx, name in RCE_SINKS:
            for occ, open_off in occs(rx):
                add("rce", occ, open_off, note=f"{name}() with request data")
        for rx, name in FILE_READ_SINKS:
            for occ, open_off in occs(rx):
                add("file_read", occ, open_off,
                    note=f"{name}() path from request data (path traversal)")
        for rx, name in FILE_WRITE_SINKS:
            for occ, open_off in occs(rx):
                add("file_write", occ, open_off,
                    note=f"{name}() destination/content from request data")
        for rx, name in FILE_DELETE_SINKS:
            for occ, open_off in occs(rx):
                add("file_deletion", occ, open_off,
                    note=f"{name}() path from request data")
        for rx, name in SSRF_SINKS:
            for occ, open_off in occs(rx):
                add("ssrf", occ, open_off, note=f"{name}() URL from request data")

        # include/require of an attacker-controlled path (LFI / RFI)
        for rx, name in FILE_INCLUSION_SINKS:
            for occ, open_off in occs(rx):
                add("file_inclusion", occ, open_off,
                    note=f"{name}() of a request-controlled path "
                         f"(local/remote file inclusion → execution)")

        # redirect — wp_safe_redirect is not a sink (validated)
        for occ, open_off in occs(SINK % "wp_redirect"):
            add("open_redirect", occ, open_off, note="wp_redirect() with request data")
        for occ, open_off in occs(SINK % "header"):
            add("open_redirect", occ, open_off,
                note="header('Location: ...') with request data")

        # unserialize / extract / do_shortcode / arbitrary options update
        for call, rule in OTHER_SINKS.items():
            if rule == "options_update":
                for occ, open_off in occs(SINK % call, arg_index=0):
                    add(rule, occ, open_off,
                        note=f"{call}() option name from request data "
                             f"(arbitrary options update / privilege escalation)")
            else:
                for occ, open_off in occs(SINK % call):
                    if rule == "shortcode_exec" and call == "extract":
                        continue  # handled via its own signal below
                    note = {
                        "object_injection": "unserialize() of request data",
                        "shortcode_exec": f"{call}() with request data",
                    }[rule]
                    add(rule, occ, open_off, note=note)

        # extract($_REQUEST) / parse_str($input) — arbitrary variable rewrite
        for call in ("extract", "parse_str", "mb_parse_str",
                     "import_request_variables"):
            cm = re.search(SINK % call, stmt)
            if not cm:
                continue
            open_off = off + cm.end() - 1
            arg, arg_off, close = _paren_arg(masked, open_off)
            if close == -1 or not arg:
                continue
            if call == "extract" and EXTR_SKIP_RE.search(arg):
                continue  # EXTR_SKIP / prefixed modes don't overwrite
            if call not in ("import_request_variables",):
                if _has_top_level_comma(masked, open_off):
                    continue  # target array given: no symbol-table rewrite
            if not VARIABLE_OVERWRITE_SOURCE_RE.search(arg):
                continue
            occ = [o for o in T.tainted_occurrences(masked, arg, arg_off, state)
                   if o[2]]
            if occ:
                add("variable_overwrite", occ, cm.end() - 1,
                    note=f"{call}() rewrites the symbol table from request "
                         f"data (attacker-controlled variable overwrite)")

    return _dedupe(findings)


def _dedupe(findings: list) -> list:
    seen = set()
    out = []
    for f in sorted(findings, key=lambda x: -x.score):
        k = (f.rule, f.file, f.line)
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out
