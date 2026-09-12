"""Authenticate before streaming and bind full registry responses to their request."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from evidentia_collectors.registries._client import RegistryReadSession
from evidentia_collectors.registries._contracts import EndpointTarget, RegistryLookupResult, result_bytes
from evidentia_core.plugins.auth import AuthProvider, AuthResult
from evidentia_core.rbac import RBACPolicy, Role
from fastapi.testclient import TestClient

ROUTE = "/api/collectors/registry"
AUTH = {"Authorization": "Bearer synthetic-registry-actor"}
VALID = {"registry": "ssl-labs", "target": {"hostname": "endpoint.example.org", "endpoint_ip": "93.184.216.34"}}


class Actor(AuthProvider):
    def __init__(self, principal: str | None = "synthetic-reader") -> None:
        self.principal = principal

    def authenticate(self, *, authorization_header: str | None) -> AuthResult:
        return AuthResult(authorization_header == AUTH["Authorization"], self.principal)

    def name(self) -> str:
        return "synthetic-registry-provider"


def actual_result(request: object = VALID) -> RegistryLookupResult:
    session = RegistryReadSession(request, _utc=lambda: datetime(2026, 9, 11, tzinfo=UTC))
    target = session.request.root.target
    assert type(target) is EndpointTarget
    return session.read_ssl_labs(target, lambda value: pytest.fail("disabled projection"))


@pytest.fixture
def clients(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Callable[..., TestClient]]:
    for name in (
        "EVIDENTIA_API_AUTH_TOKEN_FILE",
        "EVIDENTIA_RBAC_POLICY_FILE",
        "EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(tmp_path / "gaps"))
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path / "evidence"))
    monkeypatch.chdir(tmp_path)
    from evidentia_api.app import create_app

    with ExitStack() as stack:

        def create(provider: AuthProvider | None = None, policy: RBACPolicy | None = None) -> TestClient:
            app = create_app(auth_provider=provider, trust_proxy_headers=False)
            if policy is not None:
                app.state.rbac_policy = policy
            return stack.enter_context(TestClient(app))

        yield create


@pytest.mark.parametrize("body", [b"{", b" " * 65537], ids=["malformed", "oversized"])
def test_missing_auth_precedes_body(clients: Callable[..., TestClient], body: bytes) -> None:
    response = clients().post(ROUTE, content=body)
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "auth_not_configured"


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer synthetic-invalid"}])
def test_authentication_precedes_input(clients: Callable[..., TestClient], headers: dict[str, str]) -> None:
    assert clients(Actor()).post(ROUTE, content=b"{", headers=headers).status_code == 401


@pytest.mark.parametrize("principal", [None, "", "   "])
def test_real_principal_required(clients: Callable[..., TestClient], principal: str | None) -> None:
    assert clients(Actor(principal)).post(ROUTE, json=VALID, headers=AUTH).status_code == 403


def test_read_role_precedes_input(clients: Callable[..., TestClient]) -> None:
    policy = RBACPolicy(identities={"other": Role.READER}, default_role=Role.DENY)
    response = clients(Actor(), policy).post(ROUTE, content=b"{", headers=AUTH)
    assert response.status_code == 403 and response.json()["detail"]["error"] == "rbac_denied"


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"[]",
        b"null",
        b"{",
        b'{"registry":"tls","registry":"rdap"}',
        b'{"scope_label":NaN}',
        b'{"scope_label":"\\ud800"}',
        b"{}",
        b" " * 65537,
    ],
    ids=["empty", "array", "null", "malformed", "duplicate", "nonfinite", "surrogate", "empty-object", "oversized"],
)
def test_invalid_body_is_422_without_dispatch(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    from evidentia_api.routers import registry

    worker = Mock(side_effect=AssertionError("unexpected collection"))
    monkeypatch.setattr(registry, "_collect_registry", worker)
    response = clients(Actor()).post(ROUTE, content=body, headers={**AUTH, "Content-Type": "application/json"})
    assert response.status_code == 422 and set(response.json()["detail"]) == {"error", "message"}
    worker.assert_not_called()


def test_actual_bytes_override_content_length(clients: Callable[..., TestClient]) -> None:
    raw = json.dumps(VALID).encode()
    response = clients(Actor()).post(
        ROUTE,
        content=raw + b" " * (65537 - len(raw)),
        headers={**AUTH, "Content-Type": "application/json", "Content-Length": "1"},
    )
    assert response.status_code == 422


def test_full_validated_bytes_use_200(clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_api.routers import registry

    expected = actual_result()
    monkeypatch.setattr(registry, "_collect_registry", lambda selected: expected)
    response = clients(Actor()).post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 200 and response.content == result_bytes(expected)
    assert response.json()["lookup_outcome"] == "unavailable"


def test_mutated_argument_cannot_change_expected_identity(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidentia_api.routers import registry

    def worker(selected: Any) -> RegistryLookupResult:
        object.__setattr__(selected.root.target, "hostname", "different.example.org")
        return actual_result(selected)

    monkeypatch.setattr(registry, "_collect_registry", worker)
    response = clients(Actor()).post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 500 and "different.example.org" not in response.text


@pytest.mark.parametrize(
    "failure", [RuntimeError("internal-only-detail"), ModuleNotFoundError("internal-only-detail", name="lxml")]
)
def test_worker_errors_are_sanitized(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    from evidentia_api.routers import registry

    worker = Mock(side_effect=failure)
    monkeypatch.setattr(registry, "_collect_registry", worker)
    response = clients(Actor()).post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 500 and "internal-only-detail" not in response.text


def test_openapi_has_exact_operation_models(clients: Callable[..., TestClient]) -> None:
    schema = clients(Actor()).get("/api/openapi.json", headers=AUTH).json()
    operation = schema["paths"]["/api/collectors/registry"]["post"]
    assert operation["operationId"] == "collect_registry"
    assert len(operation["requestBody"]["content"]["application/json"]["schema"]["oneOf"]) == 11
    assert operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/RegistryLookupResult"
    )
