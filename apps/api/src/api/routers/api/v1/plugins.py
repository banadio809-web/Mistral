"""Stored plugins (everything the bug finder has scanned, newest first)."""

from db import get_session_maker
from db.accessors import bugfinder_plugin as plugin_accessor
from fastapi import APIRouter, Query

from ._schemas import PluginOut, PluginsOut

router = APIRouter()


@router.get("")
async def read_plugins(
    limit: int = Query(default=50, ge=1, le=250),
    offset: int = Query(default=0, ge=0),
) -> PluginsOut:
    async with get_session_maker()() as session:
        rows = await plugin_accessor.list_plugins(session, limit=limit, offset=offset)
    return PluginsOut(
        plugins=[
            PluginOut(
                slug=row.slug,
                name=row.name,
                version=row.version,
                active_installs=row.active_installs,
                updated_at=row.updated_at,
            )
            for row in rows
        ]
    )
