"""Search the wordpress.org plugin directory (fetch side; nothing is stored)."""

from fastapi import APIRouter, HTTPException, Query
from starlette.concurrency import run_in_threadpool

from api.bugfinder import fetch as wf

from ._schemas import SearchHit, SearchHitsOut

router = APIRouter()


@router.get("")
async def search_directory(
    q: str = Query(default="", max_length=200),
    browse: str | None = Query(default=None, pattern="^(popular|new|updated)$"),
    limit: int = Query(default=20, ge=1, le=100),
    page: int = Query(default=1, ge=1),
) -> SearchHitsOut:
    try:
        plugins = await run_in_threadpool(wf.search, q or None, browse, limit, page)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"wordpress.org search failed: {str(exc)[:200]}") from exc
    hits = [
        SearchHit(
            slug=p.get("slug", ""),
            name=p.get("name", ""),
            version=p.get("version", ""),
            active_installs=p.get("active_installs"),
            last_updated=p.get("last_updated", ""),
            author=_author(p),
            short_description=p.get("short_description", ""),
        )
        for p in plugins
        if p.get("slug")
    ]
    return SearchHitsOut(hits=hits)


def _author(plugin: dict) -> str:
    author = plugin.get("author")
    return author if isinstance(author, str) else ""
