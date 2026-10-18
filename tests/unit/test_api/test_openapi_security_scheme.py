"""The OpenAPI document advertises the bearer scheme the middleware enforces (v0.13.0 review, probe-4)."""

from __future__ import annotations

import pytest


@pytest.fixture()
def schema(monkeypatch: pytest.MonkeyPatch, tmp_path: object) -> dict:  # type: ignore[type-arg]
    monkeypatch.setenv("EVIDENTIA_SKIP_FRONTEND_BUILD", "1")
    monkeypatch.delenv("EVIDENTIA_RBAC_POLICY_FILE", raising=False)
    from evidentia_api.app import create_app

    return create_app().openapi()


def test_bearer_scheme_is_declared(schema: dict) -> None:  # type: ignore[type-arg]
    scheme = schema["components"]["securitySchemes"]["bearerAuth"]
    assert scheme["type"] == "http"
    assert scheme["scheme"] == "bearer"
    assert schema["security"] == [{"bearerAuth": []}]


def test_probe_paths_are_opted_out(schema: dict) -> None:  # type: ignore[type-arg]
    for path in ("/api/health", "/api/version"):
        for operation in schema["paths"][path].values():
            assert operation["security"] == [], path


def test_regular_operations_inherit_the_requirement(schema: dict) -> None:  # type: ignore[type-arg]
    operation = schema["paths"]["/api/config"]["get"]
    assert "security" not in operation or operation["security"] != []
