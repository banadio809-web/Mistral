"""Scan orchestration: walk plugin sources, run every detector per file,
attach plugin metadata, dedupe and rank."""

import os

from . import php as phpmod
from . import context as C
from .detectors import sinks, authorization, misc

SKIP_DIRS = {".git", "node_modules", ".wordpress-org"}
VENDOR_DIR = "vendor"
SKIP_FILES = {".phpcs.xml.dist", "phpunit.xml.dist"}


def iter_php_files(root: str, include_vendor: bool = False):
    if os.path.isfile(root):
        yield root, root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS
                       and not (d == VENDOR_DIR and not include_vendor)]
        for fn in sorted(filenames):
            if not fn.endswith(".php") or fn in SKIP_FILES:
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root)
            yield p, rel


def read_plugin_header(path: str) -> dict:
    try:
        head = open(path, encoding="utf-8", errors="replace").read(8192)
    except OSError:
        return {}
    m = re_search_plugin_name(head)
    return m or {}


def re_search_plugin_name(head: str):
    import re
    name = re.search(r"Plugin Name:\s*(.+)", head)
    return {"name": name.group(1).strip()} if name else {}


def scan_plugin(source_dir: str, slug: str = None, version: str = None,
                active_installs=None, privilege_default: str = "subscriber",
                include_vendor: bool = False) -> dict:
    if not os.path.isdir(source_dir):
        raise ValueError(f"plugin source not found: {source_dir}")
    import re as _re
    findings = []
    files_scanned = 0

    main_header = {}
    for p, rel in iter_php_files(source_dir, include_vendor):
        if rel.count(os.sep) <= 1 and not main_header:
            main_header = read_plugin_header(p)
    plugin_name = slug or main_header.get("name") or os.path.basename(
        os.path.normpath(source_dir))

    # ---- PASS 1: plugin-wide entry-point registry (cross-file) ------------
    # Hook registrations often live in a different file than the callback
    # body.  Index every attacker-reachable hook on the raw source of every
    # file first, then hand the full map to each per-file scan so a sink in
    # file B gets the attacker context of the add_action() in file A.
    entry_by_func: dict = {}
    files_php = []
    for path, rel in iter_php_files(source_dir, include_vendor):
        try:
            source = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if "<?php" not in source and "<?=" not in source:
            continue
        files_php.append((path, rel, source))
        try:
            for ep in C.endpoints(source):
                fn = ep.callback[1] if ep.callback else None
                if fn:
                    entry_by_func.setdefault(fn, (
                        ep.privilege,
                        {"hook": ep.hook, "kind": ep.kind, "line": ep.line,
                         "file": rel}))
        except Exception:
            continue

    ctx_info = {"privilege_default": privilege_default,
                "entry_by_func": entry_by_func}

    findings = []
    for path, rel, source in files_php:
        files_scanned += 1
        masked = phpmod.mask_php(source)
        if not masked.strip():
            continue
        findings += sinks.scan(masked, source, rel, ctx_info)
        findings += authorization.scan(masked, source, rel, ctx_info)
        findings += misc.scan(masked, source, rel, ctx_info)

    # attach plugin metadata + dedupe globally
    out = []
    seen = set()
    for f in findings:
        f.plugin_slug = slug or plugin_name
        f.version = version
        f.active_installs = active_installs
        k = (f.rule, f.file, f.line, f.title)
        if k in seen:
            continue
        seen.add(k)
        out.append(f.finalize())   # re-finalize with plugin metadata for scope
    out.sort(key=lambda f: (-f.score, f.file, f.line))
    return {
        "plugin": plugin_name,
        "slug": slug,
        "version": version,
        "active_installs": active_installs,
        "files_scanned": files_scanned,
        "findings": out,
    }
