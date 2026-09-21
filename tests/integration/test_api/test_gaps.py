"""TestClient coverage for /api/gap/* endpoints.

Uses the Meridian v2 sample inventory from the examples/ directory as
a realistic fixture. No LLM calls; pure gap-arithmetic pipeline.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

import pytest
from evidentia_core.gap_analyzer.reporter import export_report
from evidentia_core.models.gap import GapAnalysisReport
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jsonschema import Draft7Validator
from referencing import Registry

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

    def _analyze(self, api_client: TestClient, meridian_inventory: str) -> dict[str, Any]:
        r = api_client.post(
            "/api/gap/analyze",
            json={
                "frameworks": ["soc2-tsc"],
                "inventory_content": meridian_inventory,
            },
        )
        assert r.status_code == 200, r.text
        return cast(dict[str, Any], r.json())

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


@pytest.fixture
def synthetic_vex_report() -> GapAnalysisReport:
    """An empty control-gap report with a fixed, offset-bearing source clock."""
    return GapAnalysisReport(
        id="synthetic-vex-surface",
        organization="Synthetic VEX Review",
        frameworks_analyzed=["soc2-tsc"],
        analyzed_at=datetime.fromisoformat("2026-01-01T00:00:00+05:30"),
        total_controls_required=0,
        total_controls_in_inventory=0,
        total_gaps=0,
        critical_gaps=0,
        high_gaps=0,
        medium_gaps=0,
        low_gaps=0,
        coverage_percentage=100,
        gaps=[],
    )


class TestVexVersionExport:
    @pytest.mark.parametrize("version", [None, "1.6", "1.7"])
    @pytest.mark.parametrize("stored", [False, True])
    def test_real_export_bytes_version_and_cleanup(
        self,
        api_client: TestClient,
        synthetic_vex_report: GapAnalysisReport,
        monkeypatch: pytest.MonkeyPatch,
        version: str | None,
        stored: bool,
    ) -> None:
        from evidentia_api.routers import gaps as routes
        from evidentia_core.gap_store import save_report

        original = synthetic_vex_report.model_dump(mode="json")
        body: dict[str, Any] = {"format": "cyclonedx-vex"}
        if stored:
            path = save_report(synthetic_vex_report)
            body["report_key"] = path.stem
        else:
            body["report"] = original
        if version is not None:
            body["vex_spec_version"] = version
        captured: list[tuple[Path, bytes]] = []
        real_export = export_report

        def record_export(*args: Any, **kwargs: Any) -> Path:
            result = real_export(*args, **kwargs)
            captured.append((result, result.read_bytes()))
            return result

        monkeypatch.setattr(routes, "export_report", record_export)
        response = api_client.post("/api/gap/export", json=body)
        assert response.status_code == 200, response.text
        assert len(captured) == 1
        assert response.content == captured[0][1]
        assert not captured[0][0].exists()
        assert response.headers["content-type"] == "application/vnd.cyclonedx+json"
        assert response.headers["content-disposition"] == 'attachment; filename="Synthetic-VEX-Review.vex.cdx.json"'
        document = response.json()
        assert document["bomFormat"] == "CycloneDX"
        assert document["specVersion"] == (version or "1.6")
        assert document["metadata"]["timestamp"] == "2025-12-31T18:30:00.000000Z"
        assert document["vulnerabilities"] == []
        assert synthetic_vex_report.model_dump(mode="json") == original
        schema = json.loads(
            (REPO_ROOT / "tests/fixtures/cyclonedx" / f"bom-{version or '1.6'}.schema.json").read_bytes()
        )
        Draft7Validator(schema, registry=Registry()).validate(document)

    @pytest.mark.parametrize("value", ["1.5", "1.8", " 1.7", "1.7 ", "", None, True, 1.7, [], {}])
    def test_invalid_typed_selector_precedes_endpoint_effects(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        value: Any,
    ) -> None:
        from evidentia_api.routers import gaps as routes

        effects = Mock(side_effect=AssertionError("endpoint effect before validation"))
        monkeypatch.setattr(routes, "load_report_by_key", effects)
        monkeypatch.setattr(tempfile, "NamedTemporaryFile", effects)
        response = api_client.post(
            "/api/gap/export",
            json={
                "format": "cyclonedx-vex",
                "report_key": "0123456789abcdef",
                "vex_spec_version": value,
            },
        )
        assert response.status_code == 422
        effects.assert_not_called()

    @pytest.mark.parametrize("version", ["1.6", "1.7"])
    def test_cross_format_presence_refuses_before_store_or_temp(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        version: str,
    ) -> None:
        from evidentia_api.routers import gaps as routes

        effects = Mock(side_effect=AssertionError("cross-format effect"))
        monkeypatch.setattr(routes, "load_report_by_key", effects)
        monkeypatch.setattr(tempfile, "NamedTemporaryFile", effects)
        response = api_client.post(
            "/api/gap/export",
            json={
                "format": "json",
                "report_key": "0123456789abcdef",
                "vex_spec_version": version,
            },
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "invalid_body"
        assert "vex_spec_version" in response.json()["detail"]["message"]
        effects.assert_not_called()

    @pytest.mark.parametrize(
        "format,error,fragment",
        [
            ("bad", "unsupported_format", "Unsupported format"),
            ("json", "invalid_body", "exactly one"),
        ],
    )
    def test_format_and_xor_precedence(
        self,
        api_client: TestClient,
        format: str,
        error: str,
        fragment: str,
    ) -> None:
        body: dict[str, Any] = {"format": format, "vex_spec_version": "1.7"}
        response = api_client.post("/api/gap/export", json=body)
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == error
        assert fragment in response.json()["detail"]["message"]

    def test_both_sources_keep_xor_precedence(
        self,
        api_client: TestClient,
        synthetic_vex_report: GapAnalysisReport,
    ) -> None:
        response = api_client.post(
            "/api/gap/export",
            json={
                "format": "json",
                "vex_spec_version": "1.7",
                "report_key": "0123456789abcdef",
                "report": synthetic_vex_report.model_dump(mode="json"),
            },
        )
        assert response.status_code == 400
        assert "exactly one" in response.json()["detail"]["message"]

    @pytest.mark.parametrize(
        "timestamp", ["2026-01-01T00:00:00", "0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"]
    )
    def test_invalid_source_clock_is_fixed_body_error_and_temp_is_removed(
        self,
        api_client: TestClient,
        synthetic_vex_report: GapAnalysisReport,
        monkeypatch: pytest.MonkeyPatch,
        timestamp: str,
    ) -> None:
        real_temp = tempfile.NamedTemporaryFile
        paths: list[Path] = []

        def capture_temp(*args: Any, **kwargs: Any) -> Any:
            result = real_temp(*args, **kwargs)
            paths.append(Path(result.name))
            return result

        monkeypatch.setattr(tempfile, "NamedTemporaryFile", capture_temp)
        source = synthetic_vex_report.model_dump(mode="json")
        source["analyzed_at"] = timestamp
        response = api_client.post("/api/gap/export", json={"format": "cyclonedx-vex", "report": source})
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "invalid_body"
        assert response.json()["detail"]["message"] == "VEX requires an aware timestamp representable in UTC"
        assert len(paths) == 1 and not paths[0].exists()

    def test_unknown_field_and_auth_remain_before_export(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from evidentia_api.routers import gaps as routes
        from evidentia_core.plugins.auth._base import AuthResult

        effects = Mock(side_effect=AssertionError("unexpected export effect"))
        monkeypatch.setattr(routes, "load_report_by_key", effects)
        response = api_client.post("/api/gap/export", json={"unknown_vex_option": "1.7"})
        assert response.status_code == 422
        provider = Mock()
        provider.authenticate.return_value = AuthResult(authenticated=False, reason="synthetic denial")
        provider.name.return_value = "synthetic"
        cast(FastAPI, api_client.app).state.auth_provider = provider
        response = api_client.post("/api/gap/export", json={"vex_spec_version": None})
        assert response.status_code == 401
        provider.authenticate.assert_called_once()
        effects.assert_not_called()

    def test_schema_is_nonnullable_closed_default_with_presence_metadata(self) -> None:
        from evidentia_api.schemas import GapExportRequest

        schema = GapExportRequest.model_json_schema()
        value = schema["properties"]["vex_spec_version"]
        assert value["type"] == "string"
        assert value["enum"] == ["1.6", "1.7"]
        assert value["default"] == "1.6"
        assert "vex_spec_version" not in schema.get("required", [])
        assert schema["additionalProperties"] is False
        assert "vex_spec_version" not in GapExportRequest().model_fields_set
        assert "vex_spec_version" in GapExportRequest(vex_spec_version="1.6").model_fields_set

    @pytest.mark.parametrize(
        "key,status,error",
        [("../outside", 400, "invalid_id"), ("0123456789abcdef", 404, "not_found")],
    )
    def test_vex_stored_key_errors_precede_export_file(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        key: str,
        status: int,
        error: str,
    ) -> None:
        effects = Mock(side_effect=AssertionError("temporary file before stored-report validation"))
        monkeypatch.setattr(tempfile, "NamedTemporaryFile", effects)
        response = api_client.post(
            "/api/gap/export",
            json={"format": "cyclonedx-vex", "vex_spec_version": "1.7", "report_key": key},
        )
        assert response.status_code == status
        assert response.json()["detail"]["error"] == error
        effects.assert_not_called()

    @pytest.mark.parametrize("format", ["ocsf", "ocsf-detection"])
    def test_non_vex_optional_feature_refusal_retains_cleanup(
        self,
        api_client: TestClient,
        synthetic_vex_report: GapAnalysisReport,
        monkeypatch: pytest.MonkeyPatch,
        format: str,
    ) -> None:
        from evidentia_api.routers import gaps as routes
        from evidentia_core.ocsf.finding_mapping import OCSFMappingError

        paths: list[Path] = []

        def unavailable(_report: GapAnalysisReport, path: Path, **kwargs: Any) -> Path:
            assert kwargs == {"format": format}
            assert path.exists()
            paths.append(path)
            raise OCSFMappingError("synthetic optional dependency absence")

        monkeypatch.setattr(routes, "export_report", unavailable)
        response = api_client.post(
            "/api/gap/export",
            json={"format": format, "report": synthetic_vex_report.model_dump(mode="json")},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "feature_unavailable"
        assert response.json()["detail"]["format"] == format
        assert len(paths) == 1 and not paths[0].exists()
