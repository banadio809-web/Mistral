"""A single bug signal produced by one scan of one plugin.

``cwe``, ``entry`` and ``taint_path`` are JSON-encoded; the bug finder runs
Wordfence taxonomy checks, so ``severity`` is one of low/medium/high/critical.
"""

from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class BugfinderFinding(SQLModel, table=True):
    __tablename__ = "bugfinder_finding"

    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(index=True)
    plugin_slug: str = Field(max_length=190, index=True)
    version: str = Field(default="", max_length=100)
    rule: str = Field(max_length=50, index=True)
    severity: str = Field(max_length=20, index=True)
    score: float = 0.0
    vector: str = Field(default="", max_length=120)
    title: str = Field(default="", max_length=250)
    attacker: str = Field(default="", max_length=30)
    cwe: str = Field(default="[]")
    file: str = Field(default="", max_length=500)
    line: int = 0
    snippet: str = ""
    entry: str = Field(default="{}")
    taint_path: str = Field(default="[]")
    in_scope: bool = False
    scope_note: str = Field(default="", max_length=250)
    note: str = ""
    active_installs: int | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
