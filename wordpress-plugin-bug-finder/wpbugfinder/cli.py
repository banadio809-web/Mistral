#!/usr/bin/env python3
"""wpbugfinder — Wordfence-researcher-aware WordPress plugin bug finder.

Commands:
  search <query>             list matching plugins on wordpress.org
  fetch <slug|url>           download + extract a plugin into the cache
  scan <slug|path>           fetch (if needed) and scan one plugin
  audit                      batch: fetch many plugins and scan them all
"""

import argparse
import os
import sys

from . import fetch as fetcher
from . import scanner, report as R
from .criteria import SEVERITY_RANK

SEV_CHOICES = ["critical", "high", "medium", "low"]


def _load_plugins(targets):
    for t in targets:
        try:
            data = fetcher.resolve(t)
            yield data
        except Exception as exc:
            print(f"  !! failed to fetch {t}: {exc}", file=sys.stderr)


def _maybe_store(results, args):
    """Persist to Postgres (Prisma) when --db was passed."""
    if not getattr(args, "db", False):
        return
    from . import db
    try:
        scan_id = db.store(results)
        print(f"  stored in Postgres: scan id {scan_id}", file=sys.stderr)
    except Exception as exc:
        print(f"  !! database store failed: {exc}", file=sys.stderr)


def cmd_db_init(args):
    from . import db
    db.db_init()
    print("schema pushed to DATABASE_URL")


def cmd_db_find(args):
    from . import db
    rows = db.query(rule=args.rule, severity=args.severity.title(),
                    plugin=args.plugin, limit=args.limit,
                    in_scope=not args.include_out_of_scope)
    if not rows:
        print("no findings stored for this query")
        return
    def sev(x):
        return x.value if hasattr(x, "value") else str(x)
    for f in rows:
        print(f"[{sev(f.severity).upper():8}] {f.score:<4} {f.title}")
        print(f"           {f.scan.plugin.slug} / {f.file}:{f.line} "
              f"(scan {f.scanId}, {'IN-SCOPE' if f.inScope else 'out'})")


def cmd_db_stats(args):
    from . import db
    rows = db.query(limit=100000, in_scope=False)
    from collections import Counter
    by_rule = Counter(r.rule for r in rows)
    by_sev = Counter(
        (r.severity.value if hasattr(r.severity, "value") else str(r.severity))
        for r in rows)
    print("stored findings by severity:")
    for sev, n in by_sev.most_common():
        print(f"  {sev:>8}: {n}")
    print("by rule:")
    for rule, n in by_rule.most_common():
        print(f"  {rule:>24}: {n}")


def cmd_search(args):
    rows = fetcher.search(query=args.query, browse=args.browse, limit=args.limit)
    print(f"{'SLUG':40} {'VERSION':10} {'INSTALLS':>12}  NAME")
    for p in rows:
        print(f"{p.get('slug','')[:40]:40} {p.get('version','')[:10]:10} "
              f"{p.get('active_installs',0):>12,}  {p.get('name','')[:44]}")


def cmd_fetch(args):
    meta = fetcher.resolve(args.target)
    print(f"fetched {meta['name']} ({meta['slug']}) {meta['version'] or ''}")
    print(f"  path: {meta['path']}")
    if meta.get("active_installs") is not None:
        print(f"  active installs: {meta['active_installs']:,}")


def _emit(results, args):
    res = R.summarize(
        results, min_severity=args.min_severity,
        include_out_of_scope=args.include_out_of_scope)
    print(R.to_console(res))
    _maybe_store(res, args)
    if args.json:
        open(args.json, "w").write(R.to_json(res))
        print(f"JSON report: {args.json}", file=sys.stderr)
    if args.markdown:
        open(args.markdown, "w").write(R.to_markdown(res))
        print(f"Markdown report: {args.markdown}", file=sys.stderr)
    return len(res["findings"])


def cmd_scan(args):
    for meta in _load_plugins([args.target]):
        results = scanner.scan_plugin(
            meta["path"], slug=meta.get("slug"), version=meta.get("version"),
            active_installs=meta.get("active_installs"),
            include_vendor=args.include_vendor)
        _emit(results, args)


def cmd_audit(args):
    plugins = []
    if args.slugs:
        plugins += args.slugs.split(",")
    if args.search:
        rows = fetcher.search(query=args.search, limit=args.top)
        plugins += [p["slug"] for p in rows]
    if args.browse:
        rows = fetcher.search(browse=args.browse, limit=args.top)
        plugins += [p["slug"] for p in rows]
    plugins = [p for p in dict.fromkeys(s.strip() for s in plugins) if p]
    print(f"auditing {len(plugins)} plugins ...")
    grand = 0
    for i, slug in enumerate(plugins, 1):
        print(f"\n[{i}/{len(plugins)}] {slug}")
        try:
            meta = fetcher.resolve(slug)
        except Exception as exc:
            print(f"  !! fetch failed: {exc}", file=sys.stderr)
            continue
        try:
            results = scanner.scan_plugin(
                meta["path"], slug=meta.get("slug"), version=meta.get("version"),
                active_installs=meta.get("active_installs"),
            include_vendor=args.include_vendor)
        except Exception as exc:
            print(f"  !! scan failed: {exc}", file=sys.stderr)
            continue
        grand += _emit(results, args)
    print(f"\ntotal findings: {grand}")


def cmd_verify(args):
    """Run the end-to-end verification agent against a scanned plugin."""
    from .verify import HAS_PLAYWRIGHT
    from .verify.agent import VerifyAgent
    from .verify.sandbox import SandboxError

    for meta in _load_plugins([args.target]):
        results = scanner.scan_plugin(
            meta["path"], slug=meta.get("slug"), version=meta.get("version"),
            active_installs=meta.get("active_installs"),
            include_vendor=args.include_vendor)
        if args.video and not HAS_PLAYWRIGHT:
            print("  . playwright not installed — videos will be skipped "
                  "(pip install playwright && playwright install chromium)",
                  file=sys.stderr)
        agent = VerifyAgent(
            results, meta["path"],
            runs_dir=args.runs_dir, sandbox_mode=args.sandbox,
            video=args.video and args.sandbox != "off",
            limit=args.limit, only_rule=args.only_rule,
            min_severity=args.min_severity)
        try:
            summary = agent.run()
        except SandboxError as exc:
            print(f"  !! sandbox error: {exc}", file=sys.stderr)
            continue
        print(f"\n=== verification summary ({summary['slug']}) ===")
        for a in summary.get("verification_attempts", []):
            print(f"  [{a['verdict']:>16}] {a['rule']:>24} "
                  f"{a['file']}:{a['line']}  {a['evidence'][:100]}")
        print(f"  artifacts: {summary['run_dir']}")


def build_parser():
    ap = argparse.ArgumentParser(prog="wpbugfinder", description=__doc__)
    ap.add_argument("--min-severity", default="low", choices=SEV_CHOICES)
    ap.add_argument("--include-out-of-scope", action="store_true")
    ap.add_argument("--include-vendor", action="store_true",
                    help="also scan bundled vendor/ libraries")
    ap.add_argument("--db", action="store_true",
                    help="persist scans/findings to Postgres (Prisma); "
                         "requires DATABASE_URL")
    ap.add_argument("--json", help="write JSON report to file")
    ap.add_argument("--markdown", help="write Markdown report to file")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("db-init", help="create/update tables (prisma db push)")
    d.set_defaults(fn=cmd_db_init)

    df = sub.add_parser("db-find", help="query stored findings from Postgres")
    df.add_argument("--rule")
    df.add_argument("--severity", choices=SEV_CHOICES)
    df.add_argument("--plugin", help="filter by plugin slug")
    df.add_argument("--limit", type=int, default=25)
    df.add_argument("--include-out-of-scope", action="store_true")
    df.set_defaults(fn=cmd_db_find)

    ds = sub.add_parser("db-stats", help="aggregate stats over stored findings")
    ds.set_defaults(fn=cmd_db_stats)

    s = sub.add_parser("search", help="search wordpress.org plugins")
    s.add_argument("query", nargs="?", default=None)
    s.add_argument("--browse", choices=["popular", "new", "recent", "updated"])
    s.add_argument("-n", "--limit", type=int, default=20)
    s.set_defaults(fn=cmd_search)

    f = sub.add_parser("fetch", help="download + extract a plugin")
    f.add_argument("target", help="slug, wordpress.org URL, or local path")
    f.set_defaults(fn=cmd_fetch)

    sc = sub.add_parser("scan", help="fetch (if needed) and scan one plugin")
    sc.add_argument("target", help="slug, wordpress.org URL, or local path")
    sc.set_defaults(fn=cmd_scan)

    a = sub.add_parser("audit", help="batch fetch + scan")
    a.add_argument("--slugs", help="comma-separated plugin slugs")
    a.add_argument("--search", help="audit all plugins matching a search")
    a.add_argument("--browse", choices=["popular", "new", "recent", "updated"])
    a.add_argument("--top", type=int, default=10,
                   help="how many plugins to audit with --search/--browse")
    a.set_defaults(fn=cmd_audit)

    v = sub.add_parser(
        "verify", help="verify findings end-to-end: docker WordPress "
                       "sandbox + recorded browser PoC runs")
    v.add_argument("target", help="slug, wordpress.org URL, or local path")
    v.add_argument("--limit", type=int, default=10,
                   help="max findings to verify (default 10)")
    v.add_argument("--only-rule", help="verify only this rule (e.g. sqli)")
    v.add_argument("--no-video", dest="video", action="store_false",
                   help="skip video recording (headless HTTP checks only)")
    v.set_defaults(video=True)
    v.add_argument("--sandbox", choices=["reuse", "fresh", "off"],
                   default="reuse", help="reuse/fresh docker sandbox or off")
    v.add_argument("--runs-dir", default=None,
                   help="where to write verification artifacts")
    v.set_defaults(fn=cmd_verify)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
