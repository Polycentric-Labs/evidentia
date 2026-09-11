"""Profile grants, request binding and exact output through the real API."""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock

import httpx
import pytest
from evidentia_collectors.enterprise_retention import _contracts as contracts
from evidentia_collectors.enterprise_retention import _profiles as profiles
from evidentia_collectors.enterprise_retention._credentials import CredentialMaterial
from evidentia_collectors.enterprise_retention.collector import EnterpriseRetentionCollector
from evidentia_core import network_guard
from evidentia_core.plugins.auth import AuthProvider, AuthResult
from evidentia_core.rbac import RBACPolicy, Role
from fastapi.testclient import TestClient
from starlette.concurrency import run_in_threadpool

ROUTE = "/api/collectors/enterprise-retention/collect"
AUTH = {"Authorization": "Bearer synthetic-enterprise-actor"}
VALID = {
    "provider": "splunk-enterprise",
    "profile_alias": "selected",
    "scope_label": "synthetic",
    "targets": [{"index": "events-0"}],
}
NOW = datetime(2026, 1, 1, tzinfo=UTC)


class Actor(AuthProvider):
    def __init__(self, principal: str | None = "synthetic-reader") -> None:
        self.principal = principal

    def authenticate(self, *, authorization_header: str | None) -> AuthResult:
        return AuthResult(authorization_header == AUTH["Authorization"], self.principal)

    def name(self) -> str:
        return "synthetic-enterprise-provider"


class Resolver:
    def __init__(self) -> None:
        self.calls = 0

    def resolve(self, profile: profiles.FrozenProfile) -> CredentialMaterial:
        self.calls += 1
        return CredentialMaterial(profile.provider, "synthetic")


def registry(principal: str = "synthetic-reader", *, local: bool = False) -> profiles.ProfileRegistry:
    return profiles.ProfileRegistry(
        (
            profiles.FrozenProfile(
                alias="selected",
                provider="splunk-enterprise",
                origin="https://splunk.example.invalid:8089",
                credential_ref="ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
                address_policy=profiles.AddressPolicy("public"),
                api_principals=frozenset({principal}),
                allow_local_cli=local,
            ),
        ),
        Resolver(),
    )


def selection(status: str = "complete") -> dict[str, Any]:
    return {
        **VALID,
        "targets": [{"index": "events-0"}, {"index": "events-1"}] if status == "partial" else [{"index": "events-0"}],
    }


def full_result(status: str = "complete") -> contracts.EnterpriseRetentionCollectResult:
    """Generate actual session/factory evidence with only synthetic transport."""
    source = registry()
    capability = profiles.authorize_api_profile(
        source, provider="splunk-enterprise", alias="selected", principal="synthetic-reader"
    )

    def dns(host: object, port: int, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]

    def response(request: httpx.Request) -> httpx.Response:
        index = request.url.path.rsplit("/", 1)[-1]
        code = 403 if status == "unavailable" or (status == "partial" and index == "events-1") else 200
        body = {
            "entry": [
                {
                    "name": index,
                    "content": {
                        "datatype": "event",
                        "disabled": False,
                        "frozenTimePeriodInSecs": 9007199254740993,
                        "maxTotalDataSizeMB": "00042",
                        "coldToFrozenDir": "",
                        "coldToFrozenScript": "",
                    },
                }
            ]
        }
        return httpx.Response(code, stream=httpx.ByteStream(json.dumps(body).encode()))

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(socket, "getaddrinfo", dns)
        patch.setattr(network_guard, "_GETADDRINFO_DELEGATE", dns)
        patch.setattr(network_guard._pin_state, "hosts", {}, raising=False)
        patch.setattr(network_guard, "_offline_enabled", False)
        patch.setattr(socket, "create_connection", Mock(side_effect=AssertionError("unexpected real connection")))
        with EnterpriseRetentionCollector(
            profile=capability,
            transport_factory=lambda context: httpx.MockTransport(response),
            utc_clock=lambda: NOW,
            monotonic_clock=lambda: 0.0,
            run_id_factory=lambda: "01K00000000000000000000000",
        ) as collector:
            return collector.collect_v2(contracts.validated_request(selection(status)))


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

        def create(
            provider: AuthProvider | None = None,
            policy: RBACPolicy | None = None,
            configured: profiles.ProfileRegistry | None = None,
        ) -> TestClient:
            app = create_app(
                auth_provider=provider,
                enterprise_retention_profiles=configured if configured is not None else registry(),
                trust_proxy_headers=False,
            )
            if policy is not None:
                app.state.rbac_policy = policy
            return stack.enter_context(TestClient(app))

        yield create


@pytest.fixture
def no_collection(monkeypatch: pytest.MonkeyPatch) -> Iterator[Mock]:
    from evidentia_api.routers import enterprise_retention

    worker = Mock(side_effect=AssertionError("unexpected collection"))
    monkeypatch.setattr(enterprise_retention, "_collect_enterprise_retention", worker)
    yield worker
    worker.assert_not_called()


@pytest.mark.usefixtures("no_collection")
class TestEntryBoundary:
    @pytest.mark.parametrize("body", [b"{", b" " * 65537], ids=["malformed", "oversized"])
    def test_missing_auth_before_input(self, clients: Callable[..., TestClient], body: bytes) -> None:
        response = clients().post(ROUTE, content=body)
        assert response.status_code == 403 and response.json()["detail"]["error"] == "auth_not_configured"

    @pytest.mark.parametrize("principal", [None, "", "   "])
    def test_canonical_principal_required(self, clients: Callable[..., TestClient], principal: str | None) -> None:
        response = clients(Actor(principal)).post(ROUTE, content=b"{", headers=AUTH)
        assert response.status_code == 403 and response.json()["detail"]["error"] == "auth_not_configured"

    @pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer synthetic-invalid"}])
    def test_authentication_before_input(self, clients: Callable[..., TestClient], headers: dict[str, str]) -> None:
        assert clients(Actor()).post(ROUTE, content=b"{", headers=headers).status_code == 401

    def test_read_role_before_input(self, clients: Callable[..., TestClient]) -> None:
        policy = RBACPolicy(identities={"unrelated": Role.READER}, default_role=Role.DENY)
        response = clients(Actor(), policy).post(ROUTE, content=b"{", headers=AUTH)
        assert response.status_code == 403 and response.json()["detail"]["error"] == "rbac_denied"

    @pytest.mark.parametrize("media", ["", "text/plain", "application/xml", "application/problem+json"])
    def test_media_before_json(self, clients: Callable[..., TestClient], media: str) -> None:
        assert clients(Actor()).post(ROUTE, content=b"{", headers={**AUTH, "Content-Type": media}).status_code == 415

    @pytest.mark.parametrize(
        "body",
        [
            b"",
            b"[]",
            b"null",
            b"false",
            b"{",
            b"\xef\xbb\xbf{}",
            b'{"provider":"splunk-enterprise","provider":"elastic-ilm"}',
            b'{"scope_label":NaN}',
            b'{"scope_label":"\\ud800"}',
            b'{"scope_label":"\xff"}',
        ],
    )
    def test_strict_input(self, clients: Callable[..., TestClient], body: bytes) -> None:
        response = clients(Actor()).post(ROUTE, content=body, headers={**AUTH, "Content-Type": "application/json"})
        assert response.status_code == 400 and set(response.json()["detail"]) == {"error", "message"}

    @pytest.mark.parametrize(
        "principal", ["Synthetic-reader", "synthetic-reader ", "synthetic-reader:tenant", " synthetic-reader"]
    )
    def test_profile_principal_is_exact(self, clients: Callable[..., TestClient], principal: str) -> None:
        response = clients(Actor(principal)).post(ROUTE, json=VALID, headers=AUTH)
        assert response.status_code == 403 and response.json()["detail"] == {
            "error": "profile_unavailable",
            "message": "The selected collection profile is unavailable.",
        }

    @pytest.mark.parametrize("update", [{"profile_alias": "unknown"}, {"provider": "elastic-ilm"}])
    def test_unknown_or_wrong_provider_profile_has_identical_denial(
        self, clients: Callable[..., TestClient], update: dict[str, str]
    ) -> None:
        response = clients(Actor()).post(ROUTE, json={**VALID, **update}, headers=AUTH)
        assert response.status_code == 403 and response.json()["detail"] == {
            "error": "profile_unavailable",
            "message": "The selected collection profile is unavailable.",
        }

    def test_empty_registry_denies(self, clients: Callable[..., TestClient]) -> None:
        response = clients(Actor(), configured=profiles.ProfileRegistry()).post(ROUTE, json=VALID, headers=AUTH)
        assert response.status_code == 403 and response.json()["detail"]["error"] == "profile_unavailable"

    def test_actual_bytes_override_content_length(self, clients: Callable[..., TestClient]) -> None:
        raw = json.dumps(VALID).encode()
        response = clients(Actor()).post(
            ROUTE,
            content=raw + b" " * (65537 - len(raw)),
            headers={**AUTH, "Content-Type": "application/json", "Content-Length": "1"},
        )
        assert response.status_code == 413


@pytest.mark.parametrize("status", ["complete", "partial", "unavailable"])
def test_full_status_and_canonical_bytes_after_collector_cleanup(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    from evidentia_api.routers import enterprise_retention

    result = full_result(status)
    instance = MagicMock()
    instance.__enter__.return_value = instance
    instance.collect_v2.return_value = result
    constructor = Mock(return_value=instance)
    monkeypatch.setattr(enterprise_retention, "EnterpriseRetentionCollector", constructor)
    response = clients(Actor()).post(ROUTE, json=selection(status), headers=AUTH)
    assert response.status_code == 200 and response.content == result.publication_bytes()
    assert contracts.EnterpriseRetentionCollectResult.model_validate_json(response.content).root.status == status
    assert instance.__exit__.call_count == 1
    assert type(constructor.call_args.kwargs["profile"]) is profiles.AuthorizedProfile
    if status != "unavailable":
        assert b"9007199254740993" in response.content and b'"00042"' in response.content


@pytest.mark.parametrize("principal", ["synthetic-reader", " synthetic-reader:tenant "])
def test_complete_opaque_principal_can_be_explicitly_allowed(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, principal: str
) -> None:
    from evidentia_api.routers import enterprise_retention

    result = full_result()
    monkeypatch.setattr(enterprise_retention, "_collect_enterprise_retention", Mock(return_value=result))
    response = clients(Actor(principal), configured=registry(principal)).post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 200


@pytest.mark.parametrize(
    "field,changed", [("profile_alias", "other"), ("scope_label", "other"), ("targets", [{"index": "different"}])]
)
@pytest.mark.parametrize("mutate_request", [False, True])
def test_worker_cannot_replace_the_original_selection(
    clients: Callable[..., TestClient],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    changed: object,
    mutate_request: bool,
) -> None:
    from evidentia_api.routers import enterprise_retention

    result = full_result()
    request = {**VALID, field: changed}
    configured = registry()
    if field == "profile_alias":
        configured = profiles.ProfileRegistry(
            (
                profiles.FrozenProfile(
                    alias="other",
                    provider="splunk-enterprise",
                    origin="https://splunk.example.invalid:8089",
                    credential_ref="ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
                    address_policy=profiles.AddressPolicy("public"),
                    api_principals=frozenset({"synthetic-reader"}),
                ),
            ),
            Resolver(),
        )

    def worker(
        selected: contracts.EnterpriseRetentionCollectRequest, capability: profiles.AuthorizedProfile
    ) -> contracts.EnterpriseRetentionCollectResult:
        if mutate_request:
            selected.root = contracts.validated_request(VALID).root
        return result

    monkeypatch.setattr(enterprise_retention, "_collect_enterprise_retention", worker)
    response = clients(Actor(), configured=configured).post(ROUTE, json=request, headers=AUTH)
    assert response.status_code == 500 and response.json()["detail"]["error"] == "collector_failed"


@pytest.mark.parametrize("fault", ["foreign_object", "forged_status", "missing_resources", "wrong_false_literal"])
def test_malformed_results_are_fixed_server_errors(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    from evidentia_api.routers import enterprise_retention

    result: object = full_result()
    if fault == "foreign_object":
        result = {"private-field": "synthetic-private-value"}
    else:
        assert isinstance(result, contracts.EnterpriseRetentionCollectResult)
        update: dict[str, Any] = (
            {"status": "unavailable"}
            if fault == "forged_status"
            else {"resources": []}
            if fault == "missing_resources"
            else {"authenticated_identity_verified": 0}
        )
        for key, value in update.items():
            object.__setattr__(result.root, key, value)
    monkeypatch.setattr(enterprise_retention, "_collect_enterprise_retention", Mock(return_value=result))
    response = clients(Actor()).post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 500 and "private" not in response.text
    assert set(response.json()["detail"]) == {"error", "message"}


@pytest.mark.parametrize(
    "error",
    [
        ModuleNotFoundError("synthetic-private-path", name="evidentia_collectors.enterprise_retention._client"),
        ImportError("synthetic-private-path"),
        RuntimeError("synthetic-private-path"),
    ],
)
def test_installed_worker_errors_are_sanitized(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    from evidentia_api.routers import enterprise_retention

    monkeypatch.setattr(enterprise_retention, "_collect_enterprise_retention", Mock(side_effect=error))
    response = clients(Actor()).post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 500 and "synthetic-private-path" not in response.text


def test_exact_request_limit_and_synchronous_worker_isolation(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidentia_api.routers import enterprise_retention

    result = full_result()
    threads: dict[str, int] = {}

    def worker(
        selected: contracts.EnterpriseRetentionCollectRequest, capability: profiles.AuthorizedProfile
    ) -> contracts.EnterpriseRetentionCollectResult:
        threads["worker"] = threading.get_ident()
        assert selected.model_dump(mode="python") == VALID
        return result

    async def dispatch(function: Callable[..., object], *args: object) -> object:
        threads["request"] = threading.get_ident()
        return await run_in_threadpool(function, *args)

    monkeypatch.setattr(enterprise_retention, "_collect_enterprise_retention", worker)
    monkeypatch.setattr(enterprise_retention, "run_in_threadpool", dispatch)
    raw = json.dumps(VALID).encode()
    response = clients(Actor()).post(
        ROUTE,
        content=raw + b" " * (65536 - len(raw)),
        headers={**AUTH, "Content-Type": "APPLICATION/JSON; charset=utf-8", "Content-Length": "1"},
    )
    assert response.status_code == 200 and threads["worker"] != threads["request"]


def test_status_has_no_profile_or_credential_disclosure(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_api.routers import enterprise_retention
    from evidentia_collectors.enterprise_retention._credentials import EnvironmentCredentialResolver

    resolve = Mock(side_effect=AssertionError("status cannot resolve credentials"))
    monkeypatch.setattr(EnvironmentCredentialResolver, "resolve", resolve)
    assert enterprise_retention.configuration_status() == {
        "installed": True,
        "live_validated": False,
        "credential_identity_verified": False,
    }
    resolve.assert_not_called()


@pytest.mark.parametrize("status", ["complete", "partial", "unavailable"])
def test_application_runs_actual_collector_and_session(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    from evidentia_api.routers import enterprise_retention

    expected = full_result(status).publication_bytes()
    requested: list[str] = []
    closed: list[bool] = []

    class Transport(httpx.MockTransport):
        def close(self) -> None:
            closed.append(True)
            super().close()

    def dns(host: object, port: int, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]

    def response(request: httpx.Request) -> httpx.Response:
        index = request.url.path.rsplit("/", 1)[-1]
        requested.append(index)
        code = 403 if status == "unavailable" or (status == "partial" and index == "events-1") else 200
        body = {
            "entry": [
                {
                    "name": index,
                    "content": {
                        "datatype": "event",
                        "disabled": False,
                        "frozenTimePeriodInSecs": 9007199254740993,
                        "maxTotalDataSizeMB": "00042",
                        "coldToFrozenDir": "",
                        "coldToFrozenScript": "",
                    },
                }
            ]
        }
        return httpx.Response(code, stream=httpx.ByteStream(json.dumps(body).encode()))

    def construct(*, profile: profiles.AuthorizedProfile) -> EnterpriseRetentionCollector:
        return EnterpriseRetentionCollector(
            profile=profile,
            transport_factory=lambda context: Transport(response),
            utc_clock=lambda: NOW,
            monotonic_clock=lambda: 0.0,
            run_id_factory=lambda: "01K00000000000000000000000",
        )

    monkeypatch.setattr(socket, "getaddrinfo", dns)
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", dns)
    monkeypatch.setattr(network_guard, "_offline_enabled", False)
    monkeypatch.setattr(socket, "create_connection", Mock(side_effect=AssertionError("unexpected real connection")))
    monkeypatch.setattr(enterprise_retention, "EnterpriseRetentionCollector", construct)
    result = clients(Actor()).post(ROUTE, json=selection(status), headers=AUTH)
    assert result.status_code == 200 and result.content == expected
    assert requested == [target["index"] for target in selection(status)["targets"]]
    assert closed == [True] * len(requested)
    assert contracts.EnterpriseRetentionCollectResult.model_validate_json(result.content).root.status == status
