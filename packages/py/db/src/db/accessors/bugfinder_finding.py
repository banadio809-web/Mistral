"""Store and query bug-finder findings."""

import json
from typing import Any

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from db.models.bugfinder_finding import BugfinderFinding

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _roll_up(rows: list[BugfinderFinding]) -> tuple[int, float, str]:
    if not rows:
        return 0, 0.0, ""
    top = max(rows, key=lambda row: row.score)
    return sum(1 for row in rows if row.in_scope), top.score, top.severity


async def add_findings(session: AsyncSession, scan_id: int, findings: list[dict[str, Any]]) -> list[BugfinderFinding]:
    rows = []
    for f in findings:
        rows.append(
            BugfinderFinding(
                scan_id=scan_id,
                plugin_slug=f.get("plugin_slug") or "",
                version=f.get("version") or "",
                rule=f.get("rule") or "",
                severity=f.get("severity") or "",
                score=float(f.get("score") or 0.0),
                vector=f.get("vector") or "",
                title=f.get("title") or "",
                attacker=f.get("attacker") or "",
                cwe=json.dumps(f.get("cwes") or []),
                file=f.get("file") or "",
                line=int(f.get("line") or 0),
                snippet=f.get("snippet") or "",
                entry=json.dumps(f.get("entry") or {}),
                taint_path=json.dumps(f.get("taint_path") or []),
                in_scope=bool(f.get("in_scope", False)),
                scope_note=f.get("scope_note") or "",
                note=f.get("note") or "",
                active_installs=f.get("active_installs"),
            )
        )
    session.add_all(rows)
    await session.commit()
    for row in rows:
        await session.refresh(row)
    return rows


async def list_findings(
    session: AsyncSession,
    *,
    scan_id: int | None = None,
    plugin_slug: str | None = None,
    severity: str | None = None,
    rule: str | None = None,
    in_scope: bool | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[BugfinderFinding]:
    statement = select(BugfinderFinding)
    if scan_id is not None:
        statement = statement.where(BugfinderFinding.scan_id == scan_id)
    if plugin_slug:
        statement = statement.where(BugfinderFinding.plugin_slug == plugin_slug)
    if severity:
        statement = statement.where(BugfinderFinding.severity == severity)
    if rule:
        statement = statement.where(BugfinderFinding.rule == rule)
    if in_scope is not None:
        statement = statement.where(BugfinderFinding.in_scope == in_scope)
    statement = statement.order_by(BugfinderFinding.score.desc(), BugfinderFinding.id.desc())
    return list((await session.exec(statement.offset(offset).limit(limit))).all())


async def update_scan_rollup(session: AsyncSession, scan_id: int, findings: list[BugfinderFinding]) -> None:
    """Backfill a scan's counts once its findings are inserted."""
    from db.models.bugfinder_scan import BugfinderScan

    row = (await session.exec(select(BugfinderScan).where(BugfinderScan.id == scan_id))).first()
    if row is None:
        return
    in_scope, max_score, max_severity = _roll_up(findings)
    row.findings_count = len(findings)
    row.in_scope_count = in_scope
    row.max_score = max_score
    row.max_severity = max_severity
    session.add(row)
    await session.commit()


async def stats(session: AsyncSession) -> dict[str, Any]:
    rows = (await session.exec(select(BugfinderFinding))).all()
    by_severity: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    plugins: set[str] = set()
    for row in rows:
        by_severity[row.severity] = by_severity.get(row.severity, 0) + 1
        by_rule[row.rule] = by_rule.get(row.rule, 0) + 1
        plugins.add(row.plugin_slug)
    return {"plugins": len(plugins), "findings": len(rows), "by_severity": by_severity, "by_rule": by_rule}
