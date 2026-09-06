"""Smoke coverage for the SSE endpoints (/api/risk/generate, /api/explain/...).

These endpoints call the LLM, so full happy-path tests require a live API
key. Here we cover the validation + 404 paths + structural response shape
so regressions in the router wiring are caught in CI without making
actual LLM calls.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestRiskGenerateValidation:
    def test_missing_report_returns_404(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/risk/generate",
            json={"report_key": "0123456789abcdef", "top_n": 1},
        )
        # SSE endpoints are queried via POST; FastAPI still returns 404 JSON
        # for missing upstream resources (the handler raises HTTPException
        # before starting the stream).
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "not_found"

    def test_invalid_key_returns_400(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/risk/generate",
            json={"report_key": "not-hex", "top_n": 1},
        )
        # 400 (not 422) — runtime body-content validation (the Pydantic
        # parser accepts the string, then the report-key validator
        # rejects it). The F-V08-DAST-3 status normalization is
        # unchanged; the detail is the structured object from
        # evidentia_api.errors.
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_id"

    def test_top_n_out_of_range(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/risk/generate",
            json={"report_key": "0123456789abcdef", "top_n": 99},
        )
        # Pydantic Field(le=50) should reject top_n>50.
        assert r.status_code == 422


class TestExplainValidation:
    def test_unknown_framework_returns_404(self, api_client: TestClient) -> None:
        r = api_client.post("/api/explain/does-not-exist/AC-2")
        assert r.status_code == 404
        detail = r.json()["detail"]
        assert detail["error"] == "not_found"
        assert detail["resource"] == "framework"

    def test_unknown_control_returns_404(self, api_client: TestClient) -> None:
        r = api_client.post("/api/explain/nist-800-53-mod/NOPE-999")
        assert r.status_code == 404
        detail = r.json()["detail"]
        assert detail["error"] == "not_found"
        assert detail["resource"] == "control"

    def test_explain_error_statuses_documented_in_openapi(self, api_client: TestClient) -> None:
        """2026-07-06 error-shape convergence: the deliberate 404s +
        the deliberate 500 (evidentia-ai import failure) are documented
        on the explain operation."""
        schema = api_client.get("/api/openapi.json").json()
        expected: list[tuple[str, str, list[str]]] = [
            (
                "/api/explain/{framework}/{control_id}",
                "post",
                ["404", "500"],
            ),
        ]
        for path, method, statuses in expected:
            responses = schema["paths"][path][method]["responses"]
            for status in statuses:
                assert status in responses, f"{method.upper()} {path} missing {status}"


class TestOpenApi:
    def test_openapi_schema_includes_all_routers(self, api_client: TestClient) -> None:
        r = api_client.get("/api/openapi.json")
        assert r.status_code == 200
        paths = r.json()["paths"]
        # Spot-check that every router we register is reachable.
        assert "/api/health" in paths
        assert "/api/version" in paths
        assert "/api/config" in paths
        assert "/api/doctor" in paths
        assert "/api/doctor/check-air-gap" in paths
        assert "/api/llm-status" in paths
        assert "/api/frameworks" in paths
        assert "/api/gap/analyze" in paths
        assert "/api/gap/reports" in paths
        assert "/api/gap/diff" in paths
        assert "/api/risk/generate" in paths
        assert "/api/init/wizard" in paths
