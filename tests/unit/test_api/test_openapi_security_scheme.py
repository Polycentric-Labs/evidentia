"""The OpenAPI document advertises the bearer scheme the middleware enforces (v0.13.0 review, probe-4).

The scheme is always declared; the global requirement appears only when an
AuthProvider is configured, because the default deployment is anonymous.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("EVIDENTIA_SKIP_FRONTEND_BUILD", "1")
    monkeypatch.delenv("EVIDENTIA_RBAC_POLICY_FILE", raising=False)
    monkeypatch.delenv("EVIDENTIA_API_AUTH_TOKEN_FILE", raising=False)
    monkeypatch.chdir(tmp_path)


def _anonymous_schema() -> dict[str, Any]:
    from evidentia_api.app import create_app

    return create_app().openapi()


def _configured_schema(tmp_path: Path) -> dict[str, Any]:
    from evidentia_api.app import create_app
    from evidentia_core.plugins.auth.local_token import LocalTokenAuthProvider

    token_file = tmp_path / "synthetic-api-token"
    token_file.write_text("synthetic-test-token-not-a-real-credential\n", encoding="utf-8")
    app = create_app(auth_provider=LocalTokenAuthProvider(token_file=token_file))
    return app.openapi()


def test_scheme_is_declared_without_a_provider() -> None:
    schema = _anonymous_schema()
    scheme = schema["components"]["securitySchemes"]["bearerAuth"]
    assert scheme["type"] == "http"
    assert scheme["scheme"] == "bearer"
    assert "Not enforced" in scheme["description"]
    assert "security" not in schema


def test_requirement_appears_with_a_provider(tmp_path: Path) -> None:
    schema = _configured_schema(tmp_path)
    assert schema["security"] == [{"bearerAuth": []}]
    assert "Enforced" in schema["components"]["securitySchemes"]["bearerAuth"]["description"]
    for path in ("/api/health", "/api/version"):
        for operation in schema["paths"][path].values():
            assert operation["security"] == [], path
    operation = schema["paths"]["/api/config"]["get"]
    assert "security" not in operation or operation["security"] != []
