"""Authentication, bounded input and complete-result contracts for Entra/M365."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock

import pytest
from evidentia_core.plugins.auth import AuthProvider, AuthResult
from evidentia_core.rbac import RBACPolicy, Role, TenantRBACPolicy
from fastapi.testclient import TestClient

_ROUTE = "/api/collectors/entra-m365/collect"
_BODY_LIMIT = 8_388_608
_AUTH = {"Authorization": "Bearer synthetic-api-actor"}


class SyntheticAuthProvider(AuthProvider):
    """An explicit synthetic actor without a credential file or token lookup."""

    def __init__(self, principal: str = "synthetic-reader") -> None:
        self.principal = principal

    def authenticate(self, *, authorization_header: str | None) -> AuthResult:
        if authorization_header == _AUTH["Authorization"]:
            return AuthResult(authenticated=True, principal=self.principal)
        return AuthResult(authenticated=False, reason="synthetic authentication rejected")

    def name(self) -> str:
        return "synthetic-test-provider"


@pytest.fixture
def client_factory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Callable[..., TestClient]]:
    for name in (
        "EVIDENTIA_API_AUTH_TOKEN_FILE",
        "EVIDENTIA_RBAC_POLICY_FILE",
        "ENTRA_M365_ACCESS_TOKEN",
        "ENTRA_M365_RETENTION_ACCESS_TOKEN",
        "ENTRA_M365_AUTH_MODE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(tmp_path / "gaps"))
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path / "evidence"))
    monkeypatch.chdir(tmp_path)
    from evidentia_api.app import create_app

    with ExitStack() as stack:

        def create(
            *,
            provider: AuthProvider | None = None,
            policy: RBACPolicy | TenantRBACPolicy | None = None,
        ) -> TestClient:
            app = create_app(auth_provider=provider, trust_proxy_headers=False)
            if policy is not None:
                app.state.rbac_policy = policy
            return stack.enter_context(TestClient(app))

        yield create


@pytest.fixture
def no_graph(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    from evidentia_collectors.entra_m365 import _client

    credentials = Mock(side_effect=AssertionError("unexpected credential access"))
    graph = Mock(side_effect=AssertionError("unexpected Graph reader access"))
    monkeypatch.setattr(_client._EnvironmentCredentials, "resolve", credentials)
    monkeypatch.setattr(_client.EntraM365GraphReader, "read_collection", graph)
    yield
    assert credentials.call_count == 0
    assert graph.call_count == 0


@pytest.mark.usefixtures("no_graph")
class TestRequestBoundary:
    @pytest.mark.parametrize(
        "body",
        [
            b"",
            b"[]",
            b"null",
            b"false",
            b"1",
            b'"text"',
            b"{",
            b'{"tenant_label":"one","tenant_label":"two"}',
            b'{"tenant_label":"fixture","unknown":NaN}',
            b'{"tenant_label":"fixture","unknown":Infinity}',
            b'{"tenant_label":"fixture","unknown":-Infinity}',
            b'{"tenant_label":"\xff"}',
            b"{" + b'"nested":{' * 33 + b'"value":0' + b"}" * 34,
        ],
    )
    def test_invalid_json_is_sanitized_before_collection(
        self, client_factory: Callable[..., TestClient], body: bytes
    ) -> None:
        response = client_factory().post(_ROUTE, content=body, headers={"Content-Type": "application/json"})
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "invalid_body"
        assert set(response.json()["detail"]) == {"error", "message"}

    @pytest.mark.parametrize(
        "update",
        [
            {"tenant_label": "sensitive-alias with spaces"},
            {"tenant_label": "a" * 65},
            {"tenant_label": None},
            {"lookback_days": True},
            {"lookback_days": "1"},
            {"lookback_days": 1.0},
            {"lookback_days": 0},
            {"lookback_days": 31},
            {"max_items": False},
            {"max_items": 10001},
            {"max_pages": 101},
            {"capabilities": []},
            {"capabilities": None},
            {"capabilities": ["dlp-export", "dlp-export"]},
            {"capabilities": ["sensitive-unknown-capability"]},
            {"sensitive-unknown-key": "sensitive-value"},
            {"dlp_format": "evidentia-dlp-v1"},
            {"dlp_content": "supplied export", "capabilities": ["directory-roles"]},
            {"dlp_content": "x" * (4_194_304 + 1)},
        ],
    )
    def test_invalid_fields_never_echo_values_or_keys(
        self, client_factory: Callable[..., TestClient], update: dict[str, object]
    ) -> None:
        body = {"tenant_label": "fixture", "capabilities": ["dlp-export"], **update}
        response = client_factory().post(
            _ROUTE, content=json.dumps(body, ensure_ascii=True), headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "invalid_field"
        assert set(response.json()["detail"]) == {"error", "message"}
        assert "sensitive" not in response.text
        assert "input" not in response.json()["detail"]

    @pytest.mark.parametrize("content_type", [None, "text/plain", "application/xml", "application/problem+json"])
    def test_rejects_unsupported_media_before_reading(
        self, client_factory: Callable[..., TestClient], content_type: str | None
    ) -> None:
        headers = {} if content_type is None else {"Content-Type": content_type}
        response = client_factory().post(_ROUTE, content=b"{", headers=headers)
        assert response.status_code == 415
        assert response.json()["detail"]["error"] == "unsupported_format"

    @pytest.mark.parametrize("extra,expected", [(0, 403), (1, 413)])
    def test_real_cumulative_body_boundary(
        self, client_factory: Callable[..., TestClient], extra: int, expected: int
    ) -> None:
        body = b'{"tenant_label":"fixture","capabilities":["directory-roles"]}'
        body += b" " * (_BODY_LIMIT + extra - len(body))
        response = client_factory().post(
            _ROUTE,
            content=body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Content-Length": "1",
            },
        )
        assert response.status_code == expected
        code = "auth_not_configured" if expected == 403 else "response_limit"
        assert response.json()["detail"]["error"] == code

    @pytest.mark.parametrize("capabilities", [["directory-roles"], ["retention-labels"], ["dlp-export", "sign-ins"]])
    def test_graph_requires_a_configured_api_auth_provider(
        self, client_factory: Callable[..., TestClient], capabilities: list[str]
    ) -> None:
        response = client_factory().post(_ROUTE, json={"tenant_label": "fixture", "capabilities": capabilities})
        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "auth_not_configured"

    @pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer synthetic-invalid"}])
    def test_missing_or_invalid_auth_keeps_existing_401(
        self, client_factory: Callable[..., TestClient], headers: dict[str, str]
    ) -> None:
        response = client_factory(provider=SyntheticAuthProvider()).post(_ROUTE, content=b"{", headers=headers)
        assert response.status_code == 401
        assert response.json()["detail"] == "Authentication required"

    @pytest.mark.parametrize("capabilities", [["directory-roles"], ["dlp-export"]])
    def test_denied_actor_is_not_authorized_by_tenant_label(
        self, client_factory: Callable[..., TestClient], capabilities: list[str]
    ) -> None:
        policy = RBACPolicy(identities={"allowed-alias": Role.READER}, default_role=Role.DENY)
        response = client_factory(provider=SyntheticAuthProvider(), policy=policy).post(
            _ROUTE, headers=_AUTH, json={"tenant_label": "allowed-alias", "capabilities": capabilities}
        )
        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "rbac_denied"

    def test_denied_actor_does_not_parse_body(self, client_factory: Callable[..., TestClient]) -> None:
        response = client_factory(provider=SyntheticAuthProvider(), policy=RBACPolicy(default_role=Role.DENY)).post(
            _ROUTE, headers=_AUTH, content=b"not json"
        )
        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "rbac_denied"

    def test_tenant_policy_uses_authenticated_claim(self, client_factory: Callable[..., TestClient]) -> None:
        policy = TenantRBACPolicy(
            tenants={
                "allowed-tenant": RBACPolicy(default_role=Role.READER),
                "denied-tenant": RBACPolicy(default_role=Role.DENY),
            }
        )
        response = client_factory(
            provider=SyntheticAuthProvider("synthetic-reader@@denied-tenant"), policy=policy
        ).post(_ROUTE, headers=_AUTH, json={"tenant_label": "allowed-tenant", "capabilities": ["dlp-export"]})
        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "rbac_denied"

    def test_local_dlp_only_honors_explicit_anonymous_deny(self, client_factory: Callable[..., TestClient]) -> None:
        response = client_factory(policy=RBACPolicy(default_role=Role.DENY)).post(
            _ROUTE, json={"tenant_label": "fixture", "capabilities": ["dlp-export"]}
        )
        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "rbac_denied"


def test_invalid_unicode_escape_is_a_body_error(client_factory: Callable[..., TestClient], no_graph: None) -> None:
    body = json.dumps({"tenant_label": "fixture", "dlp_content": "\ud800"}, ensure_ascii=True)
    response = client_factory().post(_ROUTE, content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_body"
