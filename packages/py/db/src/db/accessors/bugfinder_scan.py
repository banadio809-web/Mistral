"""Create bug-finder scans; read one back with its finding rows."""

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from db.models.bugfinder_scan import BugfinderScan


async def create_scan(session: AsyncSession, *, plugin_slug: str, version: str, files_scanned: int) -> BugfinderScan:
    row = BugfinderScan(plugin_slug=plugin_slug, version=version or "", files_scanned=files_scanned)
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row


async def get_scan(session: AsyncSession, scan_id: int) -> BugfinderScan | None:
    return (await session.exec(select(BugfinderScan).where(BugfinderScan.id == scan_id))).first()


async def list_scans(session: AsyncSession, *, limit: int = 50, offset: int = 0) -> list[BugfinderScan]:
    statement = select(BugfinderScan).order_by(BugfinderScan.created_at.desc(), BugfinderScan.id.desc())
    return list((await session.exec(statement.offset(offset).limit(limit))).all())
