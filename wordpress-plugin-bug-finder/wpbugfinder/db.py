"""Prisma (Postgres) persistence layer.

Every scan can be stored with `wpbugfinder scan <slug> --db` and queried with
`db-find` / `db-stats`.  Requires:
    pip install prisma
    prisma generate            (from the repo root, reads prisma/schema.prisma)
    export DATABASE_URL=postgresql://user:pass@host:5432/wpbugfinder
    wpbugfinder db-init        (creates tables, prisma db push)

The generated client lives at <repo>/prisma/prisma_client.  A task
WPBF_DB_MODE=test switches to the sqlite twin client in tests/prisma-test,
used by the automated tests (same models, provider=sqlite).
"""

import asyncio
import json
import os
import sys

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_client_dir = (
    os.path.join(_root, "tests", "prisma-test")
    if os.environ.get("WPBF_DB_MODE") == "test"
    else os.path.join(_root, "prisma")
)
if _client_dir not in sys.path:
    sys.path.insert(0, _client_dir)

_engine = None
_client_mod = None
_loop = None


def _run(coro):
    """Run a coroutine on a persistent event loop.  asyncio.run() would close
    the loop the Prisma engine registers cleanup callbacks on."""
    global _loop
    if _loop is None or _loop.is_closed():
        _loop = asyncio.new_event_loop()
    return _loop.run_until_complete(coro)


def _get_engine():
    global _engine, _client_mod
    if _client_mod is None:
        try:
            import prisma_client
        except ImportError as exc:
            raise RuntimeError(
                "Prisma client not generated. Run: pip install prisma "
                "&& prisma generate (repo root)") from exc
        _client_mod = prisma_client
    if _engine is None:
        _engine = _client_mod.Prisma()
    return _engine


def db_configured() -> bool:
    return bool(os.environ.get("DATABASE_URL"))


def _severity(s):
    if os.environ.get("WPBF_DB_MODE") == "test":
        return s.title()
    from prisma_client import enums
    return getattr(enums.Severity, s.title())


async def _store(results: dict) -> str:
    if not (results.get("slug") or results.get("plugin")):
        raise RuntimeError("scan results missing plugin slug; cannot store")
    db = _get_engine()
    if not db.is_connected():
        await db.connect()

    plugin = await db.plugin.upsert(
        where={"slug": results["slug"] or results["plugin"]},
        data={
            "create": {
                "slug": results["slug"] or results["plugin"],
                "name": results["plugin"],
                "version": results.get("version"),
                "activeInstalls": results.get("active_installs"),
                "sourcePath": results.get("path"),
            },
            "update": {
                "name": results["plugin"],
                "version": results.get("version"),
                "activeInstalls": results.get("active_installs"),
                "sourcePath": results.get("path"),
            },
        },
    )

    findings = results["findings"]
    scan = await db.scan.create(
        data={
            "pluginId": plugin.id,
            "filesScanned": results["files_scanned"],
            "findingCount": len(findings),
            "criticalCount": sum(1 for f in findings if f.severity == "Critical"),
            "highCount": sum(1 for f in findings if f.severity == "High"),
            "inScopeCount": sum(1 for f in findings if f.in_scope),
        },
    )
    if findings:
        await db.finding.create_many(
            data=[
                {
                    "scanId": scan.id,
                    "rule": f.rule,
                    "title": f.title,
                    "severity": _severity(f.severity),
                    "score": f.score,
                    "vector": f.vector,
                    "attacker": f.attacker,
                    "cwe": json.dumps(list(f.cwes or [])),
                    "file": f.file,
                    "line": f.line,
                    "snippet": (f.snippet or "")[:4000],
                    "entryHook": (f.entry or {}).get("hook"),
                    "taintPath": json.dumps([str(t) for t in (f.taint_path or [])]),
                    "note": f.note,
                    "inScope": bool(f.in_scope),
                    "scopeNote": f.scope_note,
                }
                for f in findings
            ],
        )
    return scan.id


def store(results: dict) -> str:
    """Persist one scan result set; returns the scan id."""
    if not db_configured():
        raise RuntimeError("DATABASE_URL is not set (postgresql connection string)")
    try:
        return _run(_store(results))
    except RuntimeError as exc:
        if "cannot be called from a running event loop" in str(exc):
            return asyncio.run(_store(results))
        raise


async def _findings_rows():
    db = _get_engine()
    if not db.is_connected():
        await db.connect()
    return await db.finding.find_many(
        include={"scan": {"include": {"plugin": True}}},
        order={"score": "desc"},
    )


def findings_rows():
    try:
        return _run(_findings_rows())
    except RuntimeError as exc:
        if "cannot be called from a running event loop" in str(exc):
            return asyncio.run(_findings_rows())
        raise


def query(rule=None, severity=None, plugin=None, limit=25, in_scope=True) -> list:
    if not db_configured():
        raise RuntimeError("DATABASE_URL is not set")
    rows = findings_rows()
    out = []
    for f in rows:
        if in_scope and not f.inScope:
            continue
        if rule and f.rule != rule:
            continue
        if severity and f.severity.title() != severity.title():
            continue
        if plugin and f.scan.plugin.slug != plugin:
            continue
        out.append(f)
        if len(out) >= limit:
            break
    return out


def db_init() -> None:
    """Create/refresh tables using `prisma db push` (safe, additive DDL)."""
    if not db_configured():
        raise RuntimeError("DATABASE_URL is not set")
    import subprocess
    cmd = [sys.executable, "-m", "prisma", "db", "push", "--skip-generate",
           "--schema", os.path.join(_root, "prisma", "schema.prisma")]
    subprocess.run(cmd, check=True, env=os.environ)
