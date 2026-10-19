"""Non-finite JSON numbers in integer body fields are a 400, not a 500 (v0.13.0 review D5)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.mark.parametrize(
    ("path", "body", "field"),
    [
        (
            "/api/collectors/nessus/collect",
            '{"content": "<x/>", "plugin_output_max_chars": 1e999}',
            "plugin_output_max_chars",
        ),
        (
            "/api/collectors/greenbone/collect",
            '{"content": "<x/>", "description_max_chars": 1e999}',
            "description_max_chars",
        ),
        ("/api/collectors/google-workspace/collect", '{"inactive_threshold_days": 1e999}', "inactive_threshold_days"),
        ("/api/collectors/google-workspace/collect", '{"max_users": -1e999}', "max_users"),
    ],
)
def test_infinite_integer_fields_are_refused_with_400(api_client: TestClient, path: str, body: str, field: str) -> None:
    response = api_client.post(path, content=body.encode(), headers={"content-type": "application/json"})
    if response.status_code == 503 and response.json()["detail"].get("error") == "feature_unavailable":
        pytest.skip("optional collector extra not installed in this environment")
    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert detail["field"] == field
