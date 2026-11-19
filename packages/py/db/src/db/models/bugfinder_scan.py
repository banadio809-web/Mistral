"""One static-analysis run of a plugin, with a roll-up of its findings."""

from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class BugfinderScan(SQLModel, table=True):
    __tablename__ = "bugfinder_scan"

    id: int | None = Field(default=None, primary_key=True)
    plugin_slug: str = Field(max_length=190, index=True)
    version: str = Field(default="", max_length=100)
    files_scanned: int = 0
    findings_count: int = 0
    in_scope_count: int = 0
    max_score: float = 0.0
    max_severity: str = Field(default="", max_length=20)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
