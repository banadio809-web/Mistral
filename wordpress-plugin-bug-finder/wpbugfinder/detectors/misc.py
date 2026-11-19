"""Pattern-level checks that Wordfence researchers regularly run into:
unrestricted file uploads, use of PHP APIs removed in modern PHP (fatal
errors), and missing direct-access guards (low-value hardening signals)."""

import re
from .. import php as phpmod

# PHP/WP APIs that are removed in PHP 7/8 or deprecated — cause real fatals
DEPRECATED = [
    (r"\bmysql_(?:connect|query|real_escape_string|fetch_array|select_db|"
    r"fetch_object|error|num_rows)\s*\(",
     "ext/mysql removed in PHP 7.0 (fatal error)"),
    (r"\beach\s*\(\s*\$", "each() removed in PHP 8.0 (fatal error)"),
    (r"\bcreate_function\s*\(", "create_function() removed in PHP 8.0"),
    (r"\b(?:split|ereg|eregi)\s*\(", "POSIX regex functions removed in PHP 7.0"),
    (r"\bget_magic_quotes_gpc\s*\(", "get_magic_quotes_gpc() removed in PHP 8.0"),
    (r"preg_replace\s*\(\s*['\"][^'\"]*/e['\"]",
     "preg_replace /e modifier removed in PHP 7.0"),
    (r"\bmoney_format\s*\(", "money_format() removed in PHP 8.0"),
    (r"\bget_settings\s*\(", "get_settings() removed (use get_option)"),
    (r"\bwp_specialchars\s*\(", "wp_specialchars() removed (use esc_html)"),
    (r"\b(?:attribute_escape|js_escape)\s*\(",
     "removed WordPress escaping API (use esc_attr/esc_js)"),
    (r"\bwp_get_single_post\s*\(", "wp_get_single_post() removed (get_post)"),
    (r"\bget_page_by_title\s*\(", "get_page_by_title() deprecated in WP 6.2"),
    (r"\bscreen_icon\s*\(", "screen_icon() removed in WP 4.4"),
    (r"\b(?:add_object_page|add_utility_page)\s*\(",
     "add_object_page()/add_utility_page() removed in WP 4.5"),
    (r"\bwp_make_content_images_responsive\s*\(",
     "wp_make_content_images_responsive() deprecated in WP 5.5"),
    (r"\bwp_get_sites\s*\(", "wp_get_sites() deprecated (use get_sites)"),
]

GUARD = re.compile(r"ABSPATH|WPINC|wp-load\.php|_wp_normalize_path")


def scan(masked: str, source: str, relpath: str, ctx_info: dict) -> list:
    from ..finding import Finding
    findings = []
    raw_lines = source.split("\n")

    for pattern, why in DEPRECATED:
        for m in re.finditer(pattern, source):
            pre = source[max(0, m.start() - 12):m.start()]
            if "function" in pre:   # definition, not a call
                continue
            if m.start() > 0 and source[m.start() - 1] in ">:":
                continue            # ->method() or ::method()
            line_no = source.count("\n", 0, m.start()) + 1
            findings.append(Finding(
                rule="deprecated_php", attacker="unauthenticated",
                file=relpath, line=line_no, snippet=raw_lines[line_no - 1],
                taint_path=[], note=why,
            ).finalize())

    # uploads handled without filetype validation
    handles_upload = re.search(r"wp_handle_upload|move_uploaded_file", source)
    reads_upload = re.search(r"\$_FILES\s*\[", source)
    if handles_upload and reads_upload and not re.search(
            r"wp_check_filetype(?:_and_ext)?|get_allowed_mime_types", source):
        hu_line = source[:handles_upload.start()].count("\n") + 1
        findings.append(Finding(
            rule="file_upload", attacker="subscriber",
            file=relpath, line=hu_line, snippet=raw_lines[hu_line - 1],
            taint_path=["$_FILES"],
            note="upload handler without wp_check_filetype(_and_ext) validation"
                 " — possible arbitrary file upload",
        ).finalize())

    # missing direct-access guard (LOW/hardening signal)
    exec_at_top = re.search(
        r"^\s*(?:echo\s|print\s|include[\s_]|require[\s_]|\$\w+\s*=|"
        r"add_action\s*\(|add_filter\s*\()", masked, re.M)
    if exec_at_top and not GUARD.search(source):
        line_no = phpmod.line_of(masked, exec_at_top.start())
        findings.append(Finding(
            rule="hardening", attacker="unauthenticated",
            file=relpath, line=line_no, snippet=raw_lines[line_no - 1],
            taint_path=[],
            note="PHP file executes without an ABSPATH/WPINC guard "
                 "(direct request reveals errors / runs bootstrap code)",
        ).finalize())

    return _dedupe(findings)


def _dedupe(findings):
    seen, out = set(), []
    for f in sorted(findings, key=lambda x: -x.score):
        k = (f.rule, f.file, f.note)
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out
