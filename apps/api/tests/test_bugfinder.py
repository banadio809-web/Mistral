"""The bug finder inside the app: engine behaviour and the v1 routes around it."""

import json
from pathlib import Path

import pytest
from api.bugfinder import fetch as wf
from api.bugfinder import scanner

VULNERABLE_PLUGIN = """
<?php
/*
 * Plugin Name: VF Test
 */

add_action('wp_ajax_nopriv_vf_load', 'vf_load');

function vf_load() {
    global $wpdb;
    $id = $_GET['id'];
    $rows = $wpdb->get_results("SELECT * FROM wp_vf WHERE org_id = $id");
    echo $rows;
}
"""

SEARCH_RESPONSE = json.dumps(
    {
        "plugins": [
            {
                "slug": "vf-hit",
                "name": "VF Hit",
                "version": "2.3.4",
                "active_installs": 600000,
                "last_updated": "2026-01-01",
                "author": {"display_name": "Someone"},
                "short_description": "a widget",
            }
        ],
        "info": {"page": 1, "pages": 1},
    }
)


@pytest.fixture
def plugin_dir(tmp_path: Path) -> Path:
    (tmp_path / "vf-test").mkdir()
    (tmp_path / "vf-test" / "vf-test.php").write_text(VULNERABLE_PLUGIN)
    return tmp_path / "vf-test"


def test_scan_finds_an_unauthenticated_sqli_signal(plugin_dir: Path) -> None:
    result = scanner.scan_plugin(str(plugin_dir), slug="vf-test", version="1.0.0", active_installs=600000)
    sqli = [f for f in result["findings"] if f.rule == "sqli"]
    assert sqli, "expected the nopriv ajax SQLi to be flagged"
    top = result["findings"][0]
    assert top.attacker == "unauthenticated"
    assert top.in_scope, "unauthenticated SQLi on a 600k-install plugin is in Wordfence scope"
    assert top.score >= 7.0


def test_clean_plugin_produces_no_findings(tmp_path: Path) -> None:
    (tmp_path / "clean").mkdir()
    (tmp_path / "clean" / "clean.php").write_text(
        "<?php\n/* Plugin Name: Clean */\nfunction c_render() { return esc_html('ok'); }\n"
    )
    result = scanner.scan_plugin(str(tmp_path / "clean"), slug="clean", version="1.0.0", active_installs=100000)
    assert result["findings"] == []


def test_search_route_serves_directory_results(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wf, "_get", lambda url, timeout=30: SEARCH_RESPONSE.encode())
    res = client.get("/api/v1/search", params={"q": "widget", "limit": 5})
    assert res.status_code == 200
    body = res.json()
    assert body["hits"][0]["slug"] == "vf-hit"
    assert body["hits"][0]["active_installs"] == 600000


def test_search_route_reports_upstream_failure(client, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(url: str, timeout: int = 30) -> bytes:
        raise OSError("network down")

    monkeypatch.setattr(wf, "_get", boom)
    res = client.get("/api/v1/search", params={"q": "widget"})
    assert res.status_code == 502


def test_scan_route_persists_and_answers(client, monkeypatch: pytest.MonkeyPatch, plugin_dir: Path) -> None:
    from api.routers.api.v1._schemas import FindingStoredOut, ScanStoredOut
    from api.routers.api.v1.scans import route as scans_route

    def fake_resolve(target: str) -> dict:
        return {"slug": "vf-test", "version": "1.0.0", "path": str(plugin_dir), "active_installs": 600000, "name": "VF Test"}

    async def fake_persist(result, findings) -> ScanStoredOut:
        return ScanStoredOut(
            scan_id=1,
            plugin_slug=result["slug"],
            version=result["version"],
            files_scanned=result["files_scanned"],
            findings_count=len(findings),
            findings=[
                FindingStoredOut(
                    id=1,
                    scan_id=1,
                    plugin_slug=result["slug"],
                    created_at=__import__("datetime").datetime.now(),
                    rule=f["rule"],
                    severity=f["severity"],
                    score=f["score"],
                    title=f["title"],
                )
                for f in findings
            ],
        )

    monkeypatch.setattr(scans_route.wf, "resolve", fake_resolve)
    monkeypatch.setattr(scans_route, "persist_scan", fake_persist)
    res = client.post("/api/v1/scans", json={"target": "vf-test"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["scan_id"] == 1
    assert body["plugin_slug"] == "vf-test"
    assert body["findings_count"] >= 1
    assert any(f["rule"] == "sqli" for f in body["findings"])
