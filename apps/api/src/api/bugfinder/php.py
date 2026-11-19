"""Minimal PHP source handling: masking of HTML / comments / strings so that
static analysis operates on structural code only, plus helpers for statements,
balanced parens and function extraction."""

import re

_HEREDOC = re.compile(r"<<<\s*'?\"?(\w+)'?\"?[\r\n]")


def mask_php(source: str) -> str:
    """Return text of the same length and line layout where HTML outside
    PHP blocks, comments and string literals are blanked with spaces.
    Newlines are preserved so offsets map directly to original line numbers.
    String quotes themselves are blanked so sinks never match inside strings
    and operators inside strings disappear."""
    out = list(source)
    i, n = 0, len(source)

    def blank(a, b):
        for j in range(a, min(b, n)):
            if out[j] != "\n":
                out[j] = " "

    while i < n:
        # HTML mode until '<?'
        while i < n:
            if source.startswith("<?", i):
                break
            if out[i] != "\n":
                out[i] = " "
            i += 1
        if i >= n:
            break
        i += 2  # skip '<?'
        # php mode
        while i < n:
            ch = source[i]
            nxt = source[i + 1] if i + 1 < n else ""
            if ch == "?" and nxt == ">":
                blank(i, i + 2)
                i += 2
                break
            if ch in ("'", '"'):
                quote = ch
                blank(i, i + 1)
                i += 1
                while i < n:
                    if source[i] == "\\":
                        blank(i, i + 2)
                        i += 2
                        continue
                    if source[i] == quote:
                        blank(i, i + 1)
                        i += 1
                        break
                    if quote == '"' and source[i] == "$":
                        vm = re.match(r"\$[A-Za-z_]\w*", source[i:])
                        if vm:  # keep interpolation vars so taint analysis
                            i += vm.end()  # can see them; blanks around them
                            continue
                    if out[i] != "\n":
                        out[i] = " "
                    i += 1
                continue
            if ch == "/" and nxt == "/":
                j = i
                while j < n and out[j] != "\n":
                    blank(j, j + 1)
                    j += 1
            elif ch == "#":
                j = i
                while j < n and out[j] != "\n":
                    blank(j, j + 1)
                    j += 1
                i = j
                continue
            elif ch == "/" and nxt == "*":
                j = source.find("*/", i + 2)
                j = n if j == -1 else j + 2
                blank(i, j)
                i = j
                continue
            elif ch == "<" and source.startswith("<<<", i):
                m = _HEREDOC.match(source, i)
                if m:
                    tag = m.group(1)
                    blank(i, m.end())
                    endre = re.compile(r"^[\t ]*" + tag + r"\b", re.MULTILINE)
                    em = endre.search(source, m.end())
                    j = em.start() if em else n
                    blank(m.end(), j)
                    i = j
                    continue
            i += 1
    return "".join(out)


def line_of(masked: str, offset: int) -> int:
    return masked.count("\n", 0, offset) + 1


def line_span(masked: str, start: int, end: int) -> tuple:
    return (masked.count("\n", 0, start) + 1, masked.count("\n", 0, min(end, len(masked) - 1)) + 1)


def get_lines(source: str) -> list:
    return source.split("\n")


def snippet(source: str, start: int, end: int, pad: int = 0) -> str:
    lines = get_lines(source)
    lo = max(0, start - 1 - pad)
    hi = min(len(lines), end + pad)
    return "\n".join(lines[lo:hi])


def statements(masked: str, base_line: int = 1):
    """Yield (text, start_offset, end_offset, start_line, end_line) splitting
    on top-level ';' and brace-delimited blocks. Returned offsets are ABSOLUTE
    positions in `masked`, text is stripped, lines are absolute (base_line is
    the line of masked[0])."""
    stmts = []
    depth_paren = 0
    cur_start = 0
    i, n = 0, len(masked)
    while i < n:
        ch = masked[i]
        if ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren = max(0, depth_paren - 1)
        elif depth_paren == 0 and (ch in ";{" or ch == "}"):
            raw = masked[cur_start:i]
            text = raw.strip()
            if text:
                off = cur_start + (len(raw) - len(raw.lstrip()))
                sl = base_line + masked.count("\n", 0, off)
                el = base_line + masked.count("\n", 0, i) + 1
                stmts.append((text, off, i, sl, el))
            cur_start = i + 1
        i += 1
    raw = masked[cur_start:]
    text = raw.strip()
    if text:
        off = cur_start + (len(raw) - len(raw.lstrip()))
        sl = base_line + masked.count("\n", 0, off)
        el = base_line + masked.count("\n", 0, len(masked)) + 1
        stmts.append((text, off, len(masked), sl, el))
    return stmts


def match_paren(masked: str, open_pos: int) -> int:
    """Given position of '(' return position of matching ')' or -1."""
    depth = 0
    for i in range(open_pos, len(masked)):
        ch = masked[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def match_brace(masked: str, open_pos: int) -> int:
    depth = 0
    for i in range(open_pos, len(masked)):
        ch = masked[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def functions(masked: str):
    """Yield (name, body_start, body_end_offset_incl, braces_pos) for each
    top-level or method function definition."""
    for m in re.finditer(r"\bfunction\s+&?\s*(?:\\?\w+::)?(\\?[A-Za-z_]\w*)\s*\(",
                         masked):
        open_paren = masked.index("(", m.end() - 1)
        close_paren = match_paren(masked, open_paren)
        if close_paren == -1:
            continue
        bm = re.search(r"\S", masked[close_paren + 1:])
        if not bm or masked[close_paren + 1 + bm.start()] != "{":
            continue
        bpos = close_paren + 1 + bm.start()
        bend = match_brace(masked, bpos)
        if bend == -1:
            continue
        yield (m.group(1).lstrip("\\"), bpos, bend, m.start())


def enclosing_function(funcs, offset: int):
    for (name, bpos, bend, _) in funcs:
        if bpos <= offset <= bend:
            return name
    return None
