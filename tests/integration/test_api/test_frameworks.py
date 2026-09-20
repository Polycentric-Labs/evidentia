"""TestClient coverage for the /api/frameworks/* endpoints."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


class TestListFrameworks:
    def test_lists_all_bundled(self, api_client: TestClient) -> None:
        r = api_client.get("/api/frameworks")
        assert r.status_code == 200
        payload = r.json()
        assert payload["total"] > 0
        # 82 is the current v0.3.1/v0.4.0 bundled count.
        assert payload["total"] >= 80
        # Entries carry the manifest shape, including the derived text depth.
        fw = payload["frameworks"][0]
        assert set(fw.keys()) >= {"id", "name", "version", "tier", "category", "text_depth"}
        assert all("text_depth" in entry for entry in payload["frameworks"])

    def test_filter_by_tier(self, api_client: TestClient) -> None:
        r = api_client.get("/api/frameworks", params={"tier": "A"})
        assert r.status_code == 200
        for fw in r.json()["frameworks"]:
            assert fw["tier"] == "A"

    def test_filter_by_category(self, api_client: TestClient) -> None:
        r = api_client.get("/api/frameworks", params={"category": "control"})
        assert r.status_code == 200
        for fw in r.json()["frameworks"]:
            assert fw["category"] == "control"

    def test_filter_by_unknown_tier_returns_empty_list(self, api_client: TestClient) -> None:
        r = api_client.get("/api/frameworks", params={"tier": "Z"})
        assert r.status_code == 200
        assert r.json()["frameworks"] == []
        assert r.json()["total"] == 0


class TestGetFramework:
    def test_known_framework_returns_catalog(self, api_client: TestClient) -> None:
        # NIST 800-53 sample is one of the most-loaded bundled catalogs.
        r = api_client.get("/api/frameworks/nist-800-53-mod")
        assert r.status_code == 200
        payload = r.json()
        assert payload["framework_id"] == "nist-800-53-mod"
        assert isinstance(payload["controls"], list)
        assert len(payload["controls"]) > 0

    def test_unknown_framework_returns_404(self, api_client: TestClient) -> None:
        r = api_client.get("/api/frameworks/does-not-exist-xyz")
        assert r.status_code == 404
        detail = r.json()["detail"]
        assert detail["error"] == "not_found"
        assert detail["resource"] == "framework"


class TestGetControl:
    def test_known_control_returns_detail(self, api_client: TestClient) -> None:
        # AC-2 is ubiquitous across NIST catalogs.
        r = api_client.get("/api/frameworks/nist-800-53-mod/controls/AC-2")
        assert r.status_code == 200
        payload = r.json()
        assert payload["id"].upper().startswith("AC-2")
        assert "title" in payload

    def test_unknown_control_returns_404(self, api_client: TestClient) -> None:
        r = api_client.get("/api/frameworks/nist-800-53-mod/controls/NOPE-999")
        assert r.status_code == 404
        detail = r.json()["detail"]
        assert detail["error"] == "not_found"
        assert detail["resource"] == "control"
        assert "not found" in detail["message"].lower()

    def test_unknown_framework_id_returns_404_not_500(self, api_client: TestClient) -> None:
        """Regression for F-V08-DAST-1 — Schemathesis fuzz hit
        ``/api/frameworks/0/controls/0`` and got 500 because the route
        handler caught only (FileNotFoundError, KeyError) but
        ``resolve_catalog_path`` raises ValueError when the framework_id
        isn't in either the user-imported or bundled manifest. v0.7.8
        Step 5.A widened the catch to include ValueError so the path
        normalizes to a 404 from the client's perspective.
        """
        r = api_client.get("/api/frameworks/0/controls/0")
        assert r.status_code == 404
        detail = r.json()["detail"]
        assert detail["error"] == "not_found"
        assert "not found" in detail["message"].lower()


class TestFrameworksOpenApiErrorDocs:
    """2026-07-06 error-shape convergence: every deliberate 4xx the
    frameworks router raises is documented on its OpenAPI operation."""

    def test_frameworks_error_statuses_documented_in_openapi(self, api_client: TestClient) -> None:
        schema = api_client.get("/api/openapi.json").json()
        expected: list[tuple[str, str, list[str]]] = [
            ("/api/frameworks/{framework_id}", "get", ["404"]),
            (
                "/api/frameworks/{framework_id}/controls/{control_id}",
                "get",
                ["404"],
            ),
        ]
        for path, method, statuses in expected:
            responses = schema["paths"][path][method]["responses"]
            for status in statuses:
                assert status in responses, f"{method.upper()} {path} missing {status}"


def test_source_row_response_schema_preserves_declared_fields(api_client: TestClient) -> None:
    schemas = api_client.get("/api/openapi.json").json()["components"]["schemas"]
    row_ref = schemas["CatalogControl"]["properties"]["source_rows"]["items"]["$ref"].rsplit("/", 1)[-1]
    row = schemas[row_ref]
    assert set(row["properties"]) == {
        "source_sha256",
        "sheet",
        "row",
        "source_id",
        "source_id_format",
        "interpreted_id",
        "kind",
        "values",
        "resolved_values",
        "provenance",
    }
    assert row["additionalProperties"] is False
    assert row["properties"]["values"]["type"] == "object"
    assert row["properties"]["kind"]["enum"] == ["aggregate", "clause", "fragment"]


@pytest.mark.parametrize(
    ("framework", "selected_control", "expected_rows"),
    [("cms-ars-5.2", "MA-04(04)", 1681), ("cjis-v6.1", "5.20", 1533)],
)
def test_bundled_source_rows_survive_full_http_responses(
    api_client: TestClient,
    framework: str,
    selected_control: str,
    expected_rows: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EVIDENTIA_CATALOG_DIR", str(tmp_path / "user-catalogs"))
    root = Path(__file__).resolve().parents[3]
    path = root / "packages/evidentia-core/src/evidentia_core/catalogs/data/us-federal" / f"{framework}.json"
    original = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        control["id"]: [
            {"source_id_format": None, "interpreted_id": None, "resolved_values": {}, "provenance": {}, **row}
            for row in control["source_rows"]
        ]
        for control in original["controls"]
    }
    response = api_client.get(f"/api/frameworks/{framework}")
    assert response.status_code == 200, response.text[:1000]
    actual = {control["id"]: control["source_rows"] for control in response.json()["controls"]}
    assert sum(map(len, actual.values())) == expected_rows
    # JSON text comparison also distinguishes true/1, 5/5.0 and negative zero.
    assert json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True)
    detail = api_client.get(f"/api/frameworks/{framework}/controls/{selected_control}")
    assert detail.status_code == 200, detail.text[:1000]
    assert json.dumps(detail.json()["source_rows"], sort_keys=True) == json.dumps(
        expected[selected_control], sort_keys=True
    )


@pytest.mark.parametrize(
    "query",
    [
        "",
        "?bundle_sha256=bad",
        "?bundle_sha256=" + "0" * 64 + "&extra=1",
        "?bundle_sha256=" + "0" * 64 + "&bundle_sha256=" + "0" * 64,
    ],
)
def test_native_source_rejects_invalid_selection_before_loading(api_client, monkeypatch, query):
    from evidentia_core.catalogs.registry import FrameworkRegistry

    def forbidden(*args, **kwargs):
        pytest.fail("Invalid selection reached catalog loading")

    monkeypatch.setattr(FrameworkRegistry, "get_catalog", forbidden)
    response = api_client.get("/api/frameworks/cisa-scuba/native-source" + query)
    assert response.status_code == 422
    assert response.json() == {"code": "native_source_invalid"}


def test_native_source_http_retains_complete_bundle_and_exact_generation(api_client, monkeypatch, tmp_path):
    from evidentia_core.catalogs.registry import FrameworkRegistry

    monkeypatch.setenv("EVIDENTIA_CATALOG_DIR", str(tmp_path / "catalogs"))
    catalog = FrameworkRegistry.get_instance().get_catalog("cisa-scuba")
    bundle = catalog.native_source
    assert bundle is not None
    expected = bundle.model_dump(mode="json")
    response = api_client.get(
        "/api/frameworks/cisa-scuba/native-source", params={"bundle_sha256": bundle.bundle_sha256}
    )
    assert response.status_code == 200, response.text[:200]
    assert response.json() == expected
    full = api_client.get("/api/frameworks/cisa-scuba")
    assert full.status_code == 200
    assert full.json()["native_source"] == expected
    control = next(item for item in catalog.controls if item.native_source_ref is not None)
    selected = api_client.get("/api/frameworks/cisa-scuba/controls/" + control.id)
    assert selected.status_code == 200
    assert selected.json()["native_source_ref"] == control.native_source_ref.model_dump(mode="json")
    assert "native_source" not in selected.json()
    stale = api_client.get("/api/frameworks/cisa-scuba/native-source", params={"bundle_sha256": "0" * 64})
    assert stale.status_code == 409
    assert stale.json() == {"code": "catalog_generation_changed"}


@pytest.mark.parametrize(
    "error,status,code",
    [
        (OSError("synthetic-private-path"), 503, "native_source_unavailable"),
        (FileNotFoundError("synthetic-private-path"), 404, "native_source_unavailable"),
    ],
)
def test_native_source_read_error_has_no_host_detail(api_client, monkeypatch, error, status, code):
    from evidentia_core.catalogs.registry import FrameworkRegistry

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(FrameworkRegistry, "get_catalog", fail)
    response = api_client.get("/api/frameworks/cisa-scuba/native-source", params={"bundle_sha256": "0" * 64})
    assert response.status_code == status
    assert response.json() == {"code": code}


def test_native_source_schema_requires_exact_bundle_digest(api_client):
    schema = api_client.get("/api/openapi.json").json()
    operation = schema["paths"]["/api/frameworks/{framework_id}/native-source"]["get"]
    query = next(item for item in operation["parameters"] if item["name"] == "bundle_sha256")
    assert query["required"] is True
    assert query["schema"]["pattern"] == "^[0-9a-f]{64}$"
    assert set(operation["responses"]) >= {"200", "404", "409", "422", "503"}
