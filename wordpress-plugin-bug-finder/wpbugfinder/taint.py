"""Taint tracking for PHP sources written for WordPress plugin code.

A variable is TAINTED when attacker-controlled data can reach it (wp
superglobals, php://input). Sanitization (esc_*, sanitize_*, intval,
$wpdb->prepare, int casts, ...) clears taint. Propagation is statement-based
and function-scoped, following assignments, concatenation, string
interpolation and foreach destructuring.
"""

import re

from . import php as phpmod

SOURCES = ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES",
           "$HTTP_RAW_POST_DATA")

SERVER_TAINTED_PREFIXES = ("HTTP_", "PHP_SELF", "REQUEST_URI", "QUERY_STRING",
                           "SCRIPT_URI", "argv")

SANITIZERS = frozenset({
    "intval", "absint", "floatval", "doubleval", "boolval", "abs",
    "sanitize_text_field", "sanitize_textarea_field", "sanitize_email",
    "sanitize_key", "sanitize_title", "sanitize_user", "sanitize_file_name",
    "sanitize_meta", "sanitize_hex_color", "sanitize_hex_color_no_hash",
    "sanitize_option", "sanitize_sql_orderby", "wp_parse_id_list",
    "wp_parse_slug_list", "wp_check_filetype", "wp_check_filetype_and_ext",
    "wp_kses", "wp_kses_post", "wp_kses_data", "wp_filter_kses",
    "wp_strip_all_tags", "strip_tags",
    "esc_html", "esc_attr", "esc_url", "esc_url_raw", "esc_js",
    "esc_textarea", "esc_sql", "esc_xml", "esc_textarea",
    "esc_attr__", "esc_html__", "esc_html_x", "esc_attr_x",
    "sanitize_term_field", "sanitize_post_field", "sanitize_user_field",
    "sanitize_mime_type", "wp_check_invalid_utf8",
    "escapeshellarg", "escapeshellcmd", "htmlentities", "htmlspecialchars",
    "urlencode", "rawurlencode", "wp_json_encode", "json_encode",
    "wp_slash", "wp_validate_redirect", "serialize", "md5", "sha1",
    "wp_hash", "password_hash", "password_verify", "count", "strlen",
})

# WP record loaders / link builders: their return values originate from the
# database or are server-generated, so request data "passing through" them is
# no longer raw attacker input for first-order sink purposes.
SAFE_TRANSFORM = frozenset({
    "get_post", "get_posts", "get_term", "get_terms", "get_comment",
    "get_user_by", "get_userdata", "get_user", "get_page_by_path",
    "get_the_title", "get_the_ID", "get_permalink", "get_edit_post_link",
    "get_post_type_object", "get_page", "get_term_by", "get_children",
    "get_bookmark", "get_category", "get_tag", "get_avatar",
})

prepared_call = re.compile(
    r"(?<![\\$\w>])(\$wpdb\s*->\s*prepare|->\s*prepare|" +
    "|".join(sorted(SANITIZERS, key=len, reverse=True)) + r")\s*\(")

VAR_RE = re.compile(r"\$[A-Za-z_]\w*")
PROP_RE = re.compile(r"\$this\s*->\s*[A-Za-z_]\w*")
CAST_RE = re.compile(r"^\s*\(\s*(int|integer|float|double|bool|boolean)\s*\)")


def _enclosed_by_sanitizer(masked: str, pos: int) -> bool:
    for m in prepared_call.finditer(masked[:pos + 1]):
        open_off = m.end() - 1
        close_pos = phpmod.match_paren(masked, open_off)
        if close_pos != -1 and open_off < pos < close_pos:
            return True
    return False


_enclosed_cache: dict = {}
_SAFE_CALL = re.compile(
    r"(?<![\$\w>])(" + "|".join(sorted(SAFE_TRANSFORM, key=len, reverse=True)) + r")\s*\(")


def _enclosed_by_safe_transform(masked: str, pos: int) -> bool:
    for m in _SAFE_CALL.finditer(masked[:pos + 1]):
        open_off = m.end() - 1
        close_pos = phpmod.match_paren(masked, open_off)
        if close_pos != -1 and open_off < pos < close_pos:
            return True
    return False


def is_source(masked: str, var: str, pos: int) -> bool:
    if var in SOURCES:
        return True
    if var == "$_SERVER":
        bracket = masked.find("[", pos)
        if bracket == -1:
            return False
        close = masked.find("]", bracket)
        key = masked[bracket + 1:close].strip().strip("'\"") if close != -1 else ""
        return any(key.startswith(p) for p in SERVER_TAINTED_PREFIXES)
    return False


def tainted_occurrences(masked: str, expr: str, expr_offset: int,
                        tainted_vars: dict) -> list:
    """[(var, abs_pos, unsanitized)] for every attacker-controlled occurrence
    inside `expr` located at `expr_offset` in the masked text."""
    lead = len(expr) - len(expr.lstrip())
    base = expr_offset + lead
    out = []
    blank = list(expr)
    for m in PROP_RE.finditer(expr):
        tok = re.sub(r"\s+", "", m.group(0))
        abs_pos = base + m.start()
        if tainted_vars.get(tok):
            clean = (_enclosed_by_sanitizer(masked, abs_pos)
                     or _enclosed_by_safe_transform(masked, abs_pos))
            out.append((tok, abs_pos, not clean))
        for k in range(m.start(), m.end()):
            if blank[k] != ".":
                blank[k] = " "
    for m in VAR_RE.finditer("".join(blank)):
        var = m.group(0)
        if var == "$this":
            continue
        abs_pos = base + m.start()
        if is_source(masked, var, abs_pos):
            clean = (_enclosed_by_sanitizer(masked, abs_pos)
                     or _enclosed_by_safe_transform(masked, abs_pos))
            out.append((var, abs_pos, not clean))
        elif var != "$_SERVER" and tainted_vars.get(var):
            clean = (_enclosed_by_sanitizer(masked, abs_pos)
                     or _enclosed_by_safe_transform(masked, abs_pos))
            out.append((var, abs_pos, not clean))
    if "php://input" in expr.lower():
        out.append(("php://input", base, True))
    return out


def _single_sanitizer_wrap(masked: str, expr: str, offset: int, occ) -> bool:
    """True when every unsanitized occurrence is wrapped by a sanitizer call
    spanning the whole expression (e.g. `$q = $wpdb->prepare($sql, $v);`)."""
    if not occ:
        return True
    lead = len(expr) - len(expr.lstrip())
    e = expr.strip()
    first_open = e.find("(")
    if first_open == -1:
        return False
    open_off = offset + first_open
    close_pos = phpmod.match_paren(masked, open_off)
    if close_pos == -1:
        return False
    if not prepared_call.search(masked[offset + lead:open_off + 1]):
        return False
    tail = masked[close_pos + 1:offset + lead + len(e)].strip()
    if tail != "":
        return False
    for (_, pos, _) in occ:
        if not (open_off < pos < close_pos):
            return False
        if not _enclosed_by_sanitizer(masked, pos):
            return False
    return True


def expr_tainted(masked: str, expr: str, offset: int, tainted_vars: dict) -> bool:
    if not expr:
        return False
    lead = len(expr) - len(expr.lstrip())
    e = expr.strip()
    if e in ("array()", "[]", "''", '""', "0", "1", "null", "false", "true"):
        return False
    if CAST_RE.match(e):
        return False
    occ = [o for o in tainted_occurrences(masked, e, offset + lead, tainted_vars)
           if o[2]]
    if not occ:
        return False
    if _single_sanitizer_wrap(masked, e, offset + lead, occ):
        return False
    return True


TOP_ASSIGN = re.compile(r"(\+=|-=|\*=|/=|\.=|=(?!=))")


RETURN_RE = re.compile(r"^return\b")


def function_params(masked: str, name: str, bpos: int, fpos: int) -> list:
    """Parameter variable names of a function ('...$a, ... $b' -> ['$a','$b'])."""
    decl = masked[fpos:bpos]
    lp = decl.find("(")
    if lp == -1:
        return []
    rp = decl.rfind(")", lp)
    if rp == -1:
        return []
    params = []
    for piece in _split_top_level(decl[lp + 1:rp], ","):
        m = re.search(r"(&?\$[A-Za-z_]\w*)\s*(?:=|$)", piece.strip())
        if m:
            params.append(m.group(1).lstrip("&"))
    return params


def _split_top_level(text: str, sep: str) -> list:
    out, depth, cur = [], 0, []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == sep and depth == 0:
            out.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    if cur:
        out.append("".join(cur))
    return [s.strip() for s in out if s.strip()]


SUMMARIZE_PASSES = 2


def helper_summaries(masked: str) -> dict:
    """For each local function, decide whether its RETURN VALUE can carry
    attacker-controlled data.  A function is a 'tainted-returning helper'
    when a `return` statement returns an expression proven tainted given
    that its parameters start tainted and calls to other known tainted
    helpers propagate taint.  Two passes: the second resolves helpers that
    call other helpers defined later in the file."""
    funcs = list(phpmod.functions(masked))
    summaries: dict = {}
    for _ in range(SUMMARIZE_PASSES):
        nxt = dict(summaries)
        for (name, bpos, bend, fpos) in funcs:
            if name in nxt and nxt[name]:
                continue
            state = {p: True
                     for p in function_params(masked, name, bpos, fpos)}
            base_line = phpmod.line_of(masked, bpos)
            tainted_ret = False
            for (text, off, end, sl, el) in phpmod.statements(
                    masked[bpos + 1:bend], base_line=base_line):
                abs_off = bpos + 1 + off
                rm = RETURN_RE.match(text)
                if rm and expr_tainted(masked, text[rm.end():],
                                       abs_off + rm.end(), state):
                    tainted_ret = True
                    break
                apply_statement(state, masked, text, abs_off, summaries=nxt)
            nxt[name] = tainted_ret
        if nxt == summaries:
            break
        summaries = nxt
    return {k: v for k, v in summaries.items() if v}


def top_level_assigns(stmt: str):
    """Yield (lhs_text, operator, rhs_text, rhs_rel_offset) for top-level
    assignments in a statement."""
    depth = 0
    i = 0
    results = []
    while i < len(stmt):
        ch = stmt[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        elif depth == 0:
            m = TOP_ASSIGN.match(stmt, i)
            if m:
                results.append((stmt[:i].strip(), m.group(1),
                                stmt[m.end():].strip(), m.end()))
                i = m.end()
                continue
        i += 1
    return results


def apply_statement(state: dict, masked: str, stmt: str, offset: int,
                    summaries: dict = None):
    """Propagate taint through one statement (mutates `state`).  `summaries`
    maps tainted-returning helper names → True: calling `helper($tainted)`
    taints the call expression, so `$v = helper($_GET['q'])` taints `$v`."""
    low = stmt.strip()

    if low.startswith("unset("):
        open_off = offset + low.index("(")
        close_pos = phpmod.match_paren(masked, open_off)
        if close_pos != -1:
            for var in VAR_RE.findall(masked[open_off:close_pos]):
                state.pop(var, None)
        return

    fm = re.match(r"foreach\s*", low)
    if fm and "(" in low:
        head_off = offset + low.index("(")
        close_pos = phpmod.match_paren(masked, head_off)
        if close_pos == -1:
            return
        head = masked[head_off:close_pos]
        am = re.search(r"as\s+(&?\$[A-Za-z_]\w*)(?:\s*=>\s*(&?\$[A-Za-z_]\w*))?",
                       head)
        if am:
            src = head[:am.start()]
            if expr_tainted(masked, src, head_off, state):
                for v in (am.group(1), am.group(2)):
                    if v:
                        state[v.lstrip("&")] = True
        return

    lead = len(low) - len(low.lstrip())
    for (lhs, op, rhs, rhs_rel) in top_level_assigns(low):
        rhs_off = offset + rhs_rel
        t = expr_tainted(masked, rhs, rhs_off, state)
        if not t and summaries:
            t = _helper_call_tainted(masked, rhs, rhs_off, state, summaries)
        prop_targets = [re.sub(r"\s+", "", m.group(0))
                        for m in PROP_RE.finditer(lhs)]
        plain_targets = [v.split("[")[0] for v in VAR_RE.findall(
            re.sub(r"\$this\s*->\s*\w+", " ", lhs)) if v != "$this"]
        for key in prop_targets + plain_targets:
            if op == "=":
                if t:
                    state[key] = True
                else:
                    state.pop(key, None)
            else:
                if t:
                    state[key] = True


CALL_ARG_RE_TEMPLATE = r"(?<![\$\w>\\])%s\s*\("


def _helper_call_tainted(masked: str, rhs: str, rhs_off: int,
                         state: dict, summaries: dict) -> bool:
    """True when the RHS expression contains a call to a known
    tainted-returning helper with an unsanitized tainted argument."""
    for hname in summaries:
        m = re.search(CALL_ARG_RE_TEMPLATE % re.escape(hname), rhs)
        if not m:
            continue
        open_off = rhs_off + m.end() - 1
        close = phpmod.match_paren(masked, open_off)
        if close == -1:
            continue
        arg = masked[open_off + 1:close]
        occ = [o for o in tainted_occurrences(masked, arg,
                                              open_off + 1, state) if o[2]]
        if occ:
            return True
    return False


def replay_function(masked: str, funcs, target_offset: int | None = None,
                    summaries: dict = None):
    """Replay a function's statements, yielding (stmt_tuple, state_copy).
    stmt_tuple = (text, abs_offset, end_offset, line_start, line_end)."""
    for (name, bpos, bend, _) in funcs:
        state = {}
        base_line = phpmod.line_of(masked, bpos)
        for (text, off, end, sl, el) in phpmod.statements(masked[bpos + 1:bend],
                                                          base_line=base_line):
            abs_off = bpos + 1 + off
            apply_statement(state, masked, text, abs_off,
                            summaries=summaries)
            yield (text, abs_off, bpos + 1 + end, sl, el), dict(state), name
            if target_offset is not None and abs_off > target_offset:
                return


def statements_with_state(masked: str):
    funcs = list(phpmod.functions(masked))
    try:
        summaries = helper_summaries(masked)
    except Exception:
        summaries = {}
    for (text, off, end, sl, el), state, fname in replay_function(
            masked, funcs, summaries=summaries):
        yield (text, off, end, sl, el), state, fname
