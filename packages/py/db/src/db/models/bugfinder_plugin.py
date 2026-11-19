"""A WordPress plugin known to the bug finder, keyed by its wordpress.org slug."""

from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class BugfinderPlugin(SQLModel, table=True):
    __tablename__ = "bugfinder_plugin"

    id: int | None = Field(default=None, primary_key=True)
    slug: str = Field(unique=True, max_length=190, index=True)
    name: str = Field(default="", max_length=250)
    version: str = Field(default="", max_length=100)
    active_installs: int | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
