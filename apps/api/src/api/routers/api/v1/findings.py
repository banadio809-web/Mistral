"""Stored findings, filterable by plugin, scan, severity, rule and bounty scope."""

from db import get_session_maker
from db.accessors import bugfinder_finding as finding_accessor
from fastapi import APIRouter, Query

from ._schemas import FindingsOut, finding_row_to_out

router = APIRouter()


@router.get("")
async def read_findings(
    scan_id: int | None = None,
    plugin_slug: str | None = None,
    severity: str | None = None,
    rule: str | None = None,
    in_scope: bool | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> FindingsOut:
    async with get_session_maker()() as session:
        rows = await finding_accessor.list_findings(
            session,
            scan_id=scan_id,
            plugin_slug=plugin_slug,
            severity=severity,
            rule=rule,
            in_scope=in_scope,
            limit=limit,
            offset=offset,
        )
    return FindingsOut(findings=[finding_row_to_out(f) for f in rows])
