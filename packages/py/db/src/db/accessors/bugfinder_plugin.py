"""Create or refresh the bug-finder plugin row for a slug."""

from datetime import UTC, datetime

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from db.models.bugfinder_plugin import BugfinderPlugin


async def upsert_plugin(
    session: AsyncSession,
    *,
    slug: str,
    name: str = "",
    version: str = "",
    active_installs: int | None = None,
) -> BugfinderPlugin:
    row = (await session.exec(select(BugfinderPlugin).where(BugfinderPlugin.slug == slug))).first()
    if row is None:
        row = BugfinderPlugin(slug=slug)
        session.add(row)
    if name:
        row.name = name
    if version:
        row.version = version
    if active_installs is not None:
        row.active_installs = active_installs
    row.updated_at = datetime.now(UTC)
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row


async def list_plugins(session: AsyncSession, *, limit: int = 50, offset: int = 0) -> list[BugfinderPlugin]:
    statement = select(BugfinderPlugin).order_by(BugfinderPlugin.updated_at.desc(), BugfinderPlugin.id.desc())
    return list((await session.exec(statement.offset(offset).limit(limit))).all())
