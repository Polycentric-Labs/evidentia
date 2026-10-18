"""An unknown /api path is a JSON 404 with the console built or not (v0.13.0 review, probe-8)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_unknown_api_path_is_a_json_404(api_client: TestClient) -> None:
    response = api_client.get("/api/does-not-exist")
    assert response.status_code == 404, response.text
    assert response.headers["content-type"].startswith("application/json")
    detail = response.json()["detail"]
    if isinstance(detail, dict):
        assert detail["error"] == "not_found"
    else:
        # FastAPI's own 404 when no SPA is mounted (fresh checkout without a build).
        assert detail == "Not Found"
