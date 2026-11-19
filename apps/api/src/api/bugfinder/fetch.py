"""Automated fetching of WordPress plugins from the official directory.

 - search()  → query_plugins search, returns plugin metadata (slug, version,
   active_installs, …) so scope can be assessed against Wordfence thresholds
 - fetch()   → download latest-stable zip, sanitize-extract into the cache
"""

import io
import json
import os
import re
import urllib.parse
import urllib.request
import zipfile

API = "https://api.wordpress.org/plugins/info/1.2/"
DOWNLOADS = "https://downloads.wordpress.org/plugin/{slug}.latest-stable.zip"
UA = "wpbugfinder/0.1 (plugin vulnerability research; static analysis)"

CACHE_DIR = os.environ.get("WPBF_CACHE", "/tmp/wpbf-cache")


def _get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _api(request: dict) -> dict:
    url = API + "?" + urllib.parse.urlencode(
        {"action": "query_plugins", **{f"request[{k}]": v for k, v in request.items()}})
    return json.loads(_get(url).decode("utf-8", "replace"))


def search(query: str | None = None, browse: str | None = None, limit: int = 20,
           page: int = 1) -> list:
    """Return plugin metadata dicts (slug/name/version/active_installs/...)."""
    req = {"per_page": min(max(limit, 1), 250), "page": page, "fields":
           "slug,name,version,active_installs,last_updated,author,short_description"}
    if query:
        req["search"] = query
    if browse:
        req["browse"] = browse
    data = _api(req)
    plugins = data.get("plugins") or []
    if limit:
        plugins = plugins[:limit]
    return plugins


def info(slug: str) -> dict:
    url = ("https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&"
           "request[slug]=" + urllib.parse.quote(slug))
    data = json.loads(_get(url).decode("utf-8", "replace"))
    return data


def install_count(slug: str):
    try:
        return int(info(slug).get("active_installs") or 0)
    except Exception:
        return None


def cache_path(slug: str, version: str | None = None) -> str:
    return os.path.join(CACHE_DIR, "plugins", slug, version or "latest")


def _safe_extract(zf: zipfile.ZipFile, dest: str):
    dest_real = os.path.realpath(dest)
    for member in zf.infolist():
        name = member.filename
        if name.startswith("__MACOSX") or name.endswith("/"):
            continue
        target = os.path.realpath(os.path.join(dest, name))
        if not target.startswith(dest_real + os.sep) and target != dest_real:
            raise ValueError(f"zip-slip attempt blocked: {name}")
    zf.extractall(dest)


def fetch(slug: str) -> dict:
    """Download and extract the latest stable plugin. Returns
    {slug, version, path, active_installs, name}."""
    slug = slug.strip().strip("/")
    meta = info(slug)
    if not meta or not meta.get("version"):
        raise ValueError(f"unknown plugin slug: {slug!r}")
    version = meta["version"]
    dest = cache_path(slug, version)
    src = os.path.join(dest, slug)
    if not os.path.isdir(src):
        os.makedirs(dest, exist_ok=True)
        url = meta.get("download_link") or DOWNLOADS.format(slug=slug)
        blob = _get(url)
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            _safe_extract(zf, dest)
    # normalize the source dir: usually <dest>/<slug>/
    src = os.path.join(dest, slug)
    if not os.path.isdir(src):
        src = dest
    return {
        "slug": slug,
        "name": meta.get("name", slug),
        "version": version,
        "path": src,
        "active_installs": int(meta.get("active_installs") or 0),
        "last_updated": meta.get("last_updated", ""),
    }


def resolve(target: str) -> dict:
    """Accepts a slug, a wordpress.org URL, or a local filesystem path."""
    if os.path.isdir(target):
        return {"slug": os.path.basename(os.path.normpath(target)),
                "version": None, "path": target, "active_installs": None,
                "name": os.path.basename(os.path.normpath(target))}
    m = re.match(r"https?://(?:[^/]*\.)?wordpress\.org/plugins/([^/]+)/?", target)
    slug = m.group(1) if m else target
    return fetch(slug)
