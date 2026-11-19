"""One stored scan with its finding rows."""

from db import get_session_maker
from db.accessors import bugfinder_finding as finding_accessor
from db.accessors import bugfinder_scan as scan_accessor
from fastapi import APIRouter, HTTPException

from .._schemas import ScanStoredOut, finding_row_to_out

router = APIRouter()


@router.get("")
async def read_scan(scan_id: int, limit: int = 500) -> ScanStoredOut:
    async with get_session_maker()() as session:
        row = await scan_accessor.get_scan(session, scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")
        rows = await finding_accessor.list_findings(session, scan_id=scan_id, limit=min(max(limit, 1), 1000))
    return ScanStoredOut(
        scan_id=row.id,
        plugin_slug=row.plugin_slug,
        version=row.version,
        files_scanned=row.files_scanned,
        findings_count=row.findings_count,
        in_scope_count=row.in_scope_count,
        max_score=row.max_score,
        max_severity=row.max_severity,
        created_at=row.created_at,
        findings=[finding_row_to_out(f) for f in rows],
    )
