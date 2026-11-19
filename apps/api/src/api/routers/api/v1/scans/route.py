"""Fetch + scan one plugin, store the result. The write path of the bug finder."""

from typing import Any

from db import get_session_maker
from db.accessors import bugfinder_finding as finding_accessor
from db.accessors import bugfinder_plugin as plugin_accessor
from db.accessors import bugfinder_scan as scan_accessor
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from api.bugfinder import fetch as wf
from api.bugfinder import scanner

from .._schemas import ScanStoredOut, finding_row_to_out

router = APIRouter()


class ScanRequest(BaseModel):
    # A plugin slug, a wordpress.org plugin URL, or a local source directory.
    target: str = Field(min_length=1, max_length=500)
    privilege_default: str = "subscriber"
    include_vendor: bool = False


async def persist_scan(result: dict[str, Any], findings: list[dict[str, Any]]) -> ScanStoredOut:
    async with get_session_maker()() as session:
        await plugin_accessor.upsert_plugin(
            session,
            slug=result["slug"],
            name=result.get("plugin") or "",
            version=result.get("version") or "",
            active_installs=result.get("active_installs"),
        )
        scan = await scan_accessor.create_scan(
            session,
            plugin_slug=result["slug"],
            version=result.get("version") or "",
            files_scanned=result.get("files_scanned") or 0,
        )
        rows = await finding_accessor.add_findings(session, scan.id, findings)
        await finding_accessor.update_scan_rollup(session, scan.id, rows)
    return ScanStoredOut(
        scan_id=scan.id,
        plugin_slug=result["slug"],
        version=result.get("version") or "",
        files_scanned=result.get("files_scanned") or 0,
        findings_count=len(rows),
        in_scope_count=sum(1 for f in findings if f.get("in_scope")),
        max_score=max((f.get("score") or 0.0) for f in findings) if findings else 0.0,
        max_severity=max((f.get("severity") or "" for f in findings), default=""),
        created_at=scan.created_at,
        findings=[finding_row_to_out(row) for row in rows],
    )


@router.post("", response_model=ScanStoredOut)
async def run_scan(body: ScanRequest) -> ScanStoredOut:
    try:
        resolved = await run_in_threadpool(wf.resolve, body.target)
        result = await run_in_threadpool(
            scanner.scan_plugin,
            resolved["path"],
            resolved["slug"],
            resolved.get("version"),
            resolved.get("active_installs"),
            body.privilege_default,
            body.include_vendor,
        )
        findings = [f.to_dict() for f in result["findings"]]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"scan failed: {str(exc)[:300]}") from exc
    return await persist_scan(result, findings)
