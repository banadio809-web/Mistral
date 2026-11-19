"""Response schemas for the bug-finder routes."""

import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class SearchHit(BaseModel):
    slug: str
    name: str = ""
    version: str = ""
    active_installs: int | None = None
    last_updated: str = ""
    author: str = ""
    short_description: str = ""


class SearchHitsOut(BaseModel):
    hits: list[SearchHit] = Field(default_factory=list)


class FindingOut(BaseModel):
    rule: str
    severity: str
    score: float
    title: str = ""
    vector: str = ""
    attacker: str = ""
    cwe: list[str] = Field(default_factory=list)
    file: str = ""
    line: int = 0
    snippet: str = ""
    entry: dict = Field(default_factory=dict)
    taint_path: list[str] = Field(default_factory=list)
    in_scope: bool = False
    scope_note: str = ""
    note: str = ""
    active_installs: int | None = None
    version: str = ""


class FindingStoredOut(FindingOut):
    id: int
    scan_id: int
    plugin_slug: str
    created_at: datetime


class PluginOut(BaseModel):
    slug: str
    name: str = ""
    version: str = ""
    active_installs: int | None = None
    updated_at: datetime | None = None


class PluginsOut(BaseModel):
    plugins: list[PluginOut] = Field(default_factory=list)


class ScanOut(BaseModel):
    scan_id: int
    plugin_slug: str
    version: str = ""
    files_scanned: int = 0
    findings: list[FindingStoredOut] = Field(default_factory=list)


class ScanStoredOut(ScanOut):
    findings_count: int = 0
    in_scope_count: int = 0
    max_score: float = 0.0
    max_severity: str = ""
    created_at: datetime | None = None


class FindingsOut(BaseModel):
    findings: list[FindingStoredOut] = Field(default_factory=list)


class StatsOut(BaseModel):
    plugins: int = 0
    findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_rule: dict[str, int] = Field(default_factory=dict)


def finding_row_to_out(row: Any) -> FindingStoredOut:
    """The stored finding row, as the API answers it (JSON columns decoded)."""

    return FindingStoredOut(
        id=row.id,
        scan_id=row.scan_id,
        plugin_slug=row.plugin_slug,
        created_at=row.created_at or datetime.now(UTC),
        rule=row.rule,
        severity=row.severity,
        score=row.score,
        title=row.title,
        vector=row.vector,
        attacker=row.attacker,
        cwe=json.loads(row.cwe or "[]"),
        file=row.file,
        line=row.line,
        snippet=row.snippet,
        entry=json.loads(row.entry or "{}"),
        taint_path=json.loads(row.taint_path or "[]"),
        in_scope=row.in_scope,
        scope_note=row.scope_note,
        note=row.note,
        active_installs=row.active_installs,
        version=row.version,
    )
