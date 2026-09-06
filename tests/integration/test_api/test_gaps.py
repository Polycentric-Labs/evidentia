"""TestClient coverage for /api/gap/* endpoints.

Uses the Meridian v2 sample inventory from the examples/ directory as
a realistic fixture. No LLM calls; pure gap-arithmetic pipeline.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[3]
MERIDIAN_V2 = REPO_ROOT / "examples" / "meridian-fintech-v2"


@pytest.fixture
def meridian_inventory() -> str:
    """Return the Meridian v2 baseline inventory YAML as a string."""
    return (MERIDIAN_V2 / "my-controls.yaml").read_text(encoding="utf-8")


class TestGapAnalyze:
    def test_rejects_empty_body(self, api_client: TestClient) -> None:
        r = api_client.post("/api/gap/analyze", json={})
        assert r.status_code == 422

    def test_requires_inventory(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/gap/analyze",
            json={"frameworks": ["soc2-tsc"]},
        )
        # 400 (not 422) — runtime body-content validation; structured
        # detail shape (F-V08-DAST-3 status normalization; 2026-07-06
        # error-shape convergence).
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "inventory_path or inventory_content" in detail["message"]

    def test_runs_with_inline_content(self, api_client: TestClient, meridian_inventory: str) -> None:
        r = api_client.post(
            "/api/gap/analyze",
            json={
                "frameworks": ["soc2-tsc"],
                "inventory_content": meridian_inventory,
                "inventory_format": "yaml",
            },
        )
        assert r.status_code == 200, r.text
        report = r.json()
        assert report["total_gaps"] >= 0
        assert "soc2-tsc" in report["frameworks_analyzed"]
        # Organization from the inventory propagates.
        assert report["organization"]

    def test_organization_override_propagates(self, api_client: TestClient, meridian_inventory: str) -> None:
        r = api_client.post(
            "/api/gap/analyze",
            json={
                "frameworks": ["soc2-tsc"],
                "inventory_content": meridian_inventory,
                "organization": "Overridden Org, Inc.",
            },
        )
        assert r.status_code == 200
        assert r.json()["organization"] == "Overridden Org, Inc."


class TestGapReports:
    def test_empty_store_returns_empty_list(self, api_client: TestClient) -> None:
        r = api_client.get("/api/gap/reports")
        assert r.status_code == 200
        assert r.json()["total"] == 0
        assert r.json()["reports"] == []

    def test_analyze_then_list_shows_report(self, api_client: TestClient, meridian_inventory: str) -> None:
        # Analyze once so the gap store has something.
        api_client.post(
            "/api/gap/analyze",
            json={
                "frameworks": ["soc2-tsc"],
                "inventory_content": meridian_inventory,
            },
        )
        r = api_client.get("/api/gap/reports")
        assert r.status_code == 200
        payload = r.json()
        assert payload["total"] >= 1
        report_meta = payload["reports"][0]
        assert set(report_meta.keys()) >= {
            "key",
            "mtime_iso",
            "size_bytes",
            "organization",
            "frameworks_analyzed",
        }
        assert report_meta["organization"]


class TestGapExport:
    """Coverage for POST /api/gap/export — reuses the CLI emitters."""

    def _analyze(self, api_client: TestClient, meridian_inventory: str) -> dict:
        r = api_client.post(
            "/api/gap/analyze",
            json={
                "frameworks": ["soc2-tsc"],
                "inventory_content": meridian_inventory,
            },
        )
        assert r.status_code == 200, r.text
        return r.json()

    def test_rejects_unknown_format(self, api_client: TestClient, meridian_inventory: str) -> None:
        report = self._analyze(api_client, meridian_inventory)
        # 'console' is a gap-*diff* format, not a gap-*report* format.
        r = api_client.post(
            "/api/gap/export",
            json={"format": "console", "report": report},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "unsupported_format"
        assert detail["format"] == "console"
        assert "Unsupported format" in detail["message"]

    def test_requires_exactly_one_source(self, api_client: TestClient, meridian_inventory: str) -> None:
        # Neither report nor report_key.
        r = api_client.post("/api/gap/export", json={"format": "json"})
        assert r.status_code == 400
        report = self._analyze(api_client, meridian_inventory)
        # Both report and report_key.
        r2 = api_client.post(
            "/api/gap/export",
            json={
                "format": "json",
                "report": report,
                "report_key": "0123456789abcdef",
            },
        )
        assert r2.status_code == 400

    def test_inline_json_export_roundtrips(self, api_client: TestClient, meridian_inventory: str) -> None:
        report = self._analyze(api_client, meridian_inventory)
        r = api_client.post(
            "/api/gap/export",
            json={"format": "json", "report": report},
        )
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("application/json")
        cd = r.headers["content-disposition"]
        assert cd.startswith("attachment;")
        assert cd.endswith('.json"')
        # The exported JSON parses back to a report with the same id.
        import json

        exported = json.loads(r.content)
        assert exported["id"] == report["id"]
        assert exported["organization"] == report["organization"]

    def test_sarif_export_has_sarif_media_type(self, api_client: TestClient, meridian_inventory: str) -> None:
        report = self._analyze(api_client, meridian_inventory)
        r = api_client.post(
            "/api/gap/export",
            json={"format": "sarif", "report": report},
        )
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("application/sarif+json")
        assert r.headers["content-disposition"].endswith('.sarif"')
        import json

        sarif = json.loads(r.content)
        assert sarif.get("version") == "2.1.0"

    def test_export_by_report_key(self, api_client: TestClient, meridian_inventory: str) -> None:
        # Analyze persists to the gap store; export by the stored key.
        self._analyze(api_client, meridian_inventory)
        reports = api_client.get("/api/gap/reports").json()["reports"]
        key = reports[0]["key"]
        r = api_client.post(
            "/api/gap/export",
            json={"format": "csv", "report_key": key},
        )
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("text/csv")
        # CSV header row is present.
        assert r.content.split(b"\n", 1)[0].startswith(b"gap_id,")

    def test_export_missing_key_is_404(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/gap/export",
            json={"format": "json", "report_key": "0123456789abcdef"},
        )
        assert r.status_code == 404
        detail = r.json()["detail"]
        assert detail["error"] == "not_found"
        assert detail["resource"] == "gap_report"

    def test_filename_is_sanitized(self, api_client: TestClient, meridian_inventory: str) -> None:
        report = self._analyze(api_client, meridian_inventory)
        # Inject a hostile organization name with path + header chars.
        report["organization"] = '../../etc/passwd "evil'
        r = api_client.post(
            "/api/gap/export",
            json={"format": "json", "report": report},
        )
        assert r.status_code == 200, r.text
        cd = r.headers["content-disposition"]
        # No path separators or quotes leaked into the filename.
        assert "/" not in cd.split("filename=", 1)[1]
        assert ".." not in cd


class TestGapDiff:
    def test_rejects_invalid_key(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/gap/diff",
            json={"base_key": "not-a-hex-key", "head_key": "also-bad"},
        )
        # 400 (not 422) — runtime body-content validation; structured
        # detail shape (F-V08-DAST-3 status normalization; 2026-07-06
        # error-shape convergence).
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_id"
        assert detail["resource"] == "gap_report"

    def test_missing_report_returns_404(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/gap/diff",
            json={
                "base_key": "0123456789abcdef",
                "head_key": "fedcba9876543210",
            },
        )
        assert r.status_code == 404

    def test_diff_between_same_report_has_all_unchanged(self, api_client: TestClient, meridian_inventory: str) -> None:
        # Analyze once -> one report in store. Diff it against itself.
        r1 = api_client.post(
            "/api/gap/analyze",
            json={
                "frameworks": ["soc2-tsc"],
                "inventory_content": meridian_inventory,
            },
        )
        assert r1.status_code == 200
        reports = api_client.get("/api/gap/reports").json()["reports"]
        key = reports[0]["key"]
        r2 = api_client.post(
            "/api/gap/diff",
            json={"base_key": key, "head_key": key},
        )
        assert r2.status_code == 200
        diff = r2.json()
        # Self-diff: no opened/closed/changed; all unchanged (or zero gaps).
        summary = diff["summary"]
        assert summary["opened"] == 0
        assert summary["closed"] == 0
        assert summary["severity_increased"] == 0
        assert summary["severity_decreased"] == 0


class TestGapsOpenApiErrorDocs:
    """2026-07-06 error-shape convergence: every deliberate 4xx the
    gaps router raises is documented on its OpenAPI operation."""

    def test_gaps_error_statuses_documented_in_openapi(self, api_client: TestClient) -> None:
        schema = api_client.get("/api/openapi.json").json()
        expected: list[tuple[str, str, list[str]]] = [
            ("/api/gap/analyze", "post", ["400"]),
            ("/api/gap/export", "post", ["400", "404"]),
            ("/api/gap/reports/{key}", "get", ["400", "404"]),
            ("/api/gap/diff", "post", ["400", "404"]),
        ]
        for path, method, statuses in expected:
            responses = schema["paths"][path][method]["responses"]
            for status in statuses:
                assert status in responses, f"{method.upper()} {path} missing {status}"
