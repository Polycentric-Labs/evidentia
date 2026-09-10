"""Storage collection authenticates before input and retains complete results."""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, Mock

import httpx
import pytest
from evidentia_collectors.retention import _contracts as contracts
from evidentia_core.plugins.auth import AuthProvider, AuthResult
from evidentia_core.rbac import RBACPolicy, Role
from fastapi.testclient import TestClient
from starlette.concurrency import run_in_threadpool

ROUTE = "/api/collectors/retention/collect"
AUTH = {"Authorization": "Bearer synthetic-storage-actor"}
VALID = {"provider": "gcs", "scope_label": "selected-scope", "targets": [{"bucket": "example-bucket"}]}


def full_result(status: str = "complete") -> contracts.StorageRetentionCollectResult:
    selected = contracts.validated_request(VALID)
    target = selected.root.targets[0]
    now = datetime(2026, 1, 1, tzinfo=UTC)
    unavailable = status == "unavailable"
    projection = (
        None
        if unavailable
        else contracts.ProjectedComponent(
            api_version="synthetic-api-contract", native_scope="bucket", fields={"retentionPeriod": "9007199254740993"}
        )
    )
    diagnostics = (
        (contracts.StorageRetentionDiagnostic(code="configuration_missing"),)
        if unavailable
        else (contracts.StorageRetentionDiagnostic(code="unsupported_source_value"),)
        if status == "partial"
        else ()
    )
    component = contracts.make_component_result(
        "gcs-bucket",
        target,
        attempts=0 if unavailable else 1,
        raw_bytes=0 if unavailable else 100,
        decoded_bytes=0 if unavailable else 100,
        started_at=None if unavailable else now,
        finished_at=None if unavailable else now,
        http_status=None if unavailable else 200,
        projection=projection,
        diagnostics=diagnostics,
    )
    return contracts.make_result(
        selected,
        run_id="synthetic-api-run",
        started_at=now,
        finished_at=now,
        components={contracts.target_identity(target): [component]},
        diagnostics=(),
    )


class Actor(AuthProvider):
    def __init__(self, principal: str | None = "synthetic-reader") -> None:
        self.principal = principal

    def authenticate(self, *, authorization_header: str | None) -> AuthResult:
        return AuthResult(authorization_header == AUTH["Authorization"], self.principal)

    def name(self) -> str:
        return "synthetic-storage-provider"


@pytest.fixture
def clients(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Callable[..., TestClient]]:
    for name in ("EVIDENTIA_API_AUTH_TOKEN_FILE", "EVIDENTIA_RBAC_POLICY_FILE"):
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


@pytest.fixture
def no_collection(monkeypatch: pytest.MonkeyPatch) -> Iterator[Mock]:
    from evidentia_api.routers import storage_retention

    collect = Mock(side_effect=AssertionError("unexpected credential or provider work"))
    monkeypatch.setattr(storage_retention, "_collect_storage_retention", collect)
    yield collect
    assert collect.call_count == 0


@pytest.mark.usefixtures("no_collection")
class TestInputBoundary:
    @pytest.mark.parametrize("body", [b"{", b" " * 65537], ids=["invalid", "oversized"])
    def test_no_provider_refuses_before_body(self, clients: Callable[..., TestClient], body: bytes) -> None:
        response = clients().post(ROUTE, content=body)
        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "auth_not_configured"

    @pytest.mark.parametrize("principal", [None, "", "   "])
    def test_provider_needs_authenticated_principal(
        self, clients: Callable[..., TestClient], principal: str | None
    ) -> None:
        response = clients(Actor(principal)).post(ROUTE, content=b"{", headers=AUTH)
        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "auth_not_configured"

    @pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer synthetic-invalid"}])
    def test_existing_authentication_failure(self, clients: Callable[..., TestClient], headers: dict[str, str]) -> None:
        response = clients(Actor()).post(ROUTE, content=b"{", headers=headers)
        assert response.status_code == 401

    def test_read_role_before_input(self, clients: Callable[..., TestClient]) -> None:
        policy = RBACPolicy(identities={"selected-scope": Role.READER}, default_role=Role.DENY)
        response = clients(Actor(), policy).post(ROUTE, content=b"{", headers=AUTH)
        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "rbac_denied"

    @pytest.mark.parametrize("media", ["", "text/plain", "application/xml", "application/problem+json"])
    def test_media_before_input(self, clients: Callable[..., TestClient], media: str) -> None:
        response = clients(Actor()).post(ROUTE, content=b"{", headers={**AUTH, "Content-Type": media})
        assert response.status_code == 415

    @pytest.mark.parametrize(
        "body",
        [
            b"",
            b"[]",
            b"null",
            b"false",
            b"1",
            b"{",
            b"\xef\xbb\xbf{}",
            b'{"provider":"gcs","provider":"s3"}',
            b'{"scope_label":NaN}',
            b'{"scope_label":"\\ud800"}',
            b'{"scope_label":"\xff"}',
        ],
    )
    def test_strict_json(self, clients: Callable[..., TestClient], body: bytes) -> None:
        response = clients(Actor()).post(ROUTE, content=body, headers={**AUTH, "Content-Type": "application/json"})
        assert response.status_code == 400
        assert set(response.json()["detail"]) == {"error", "message"}

    @pytest.mark.parametrize(
        "update",
        [
            {"provider": "sensitive-unknown"},
            {"scope_label": True},
            {"scope_label": "sensitive alias"},
            {"targets": []},
            {"targets": [{"bucket": "sensitive/path"}]},
            {"sensitive-private-field": "sensitive-value"},
        ],
    )
    def test_fields_are_sanitized(self, clients: Callable[..., TestClient], update: dict[str, object]) -> None:
        response = clients(Actor()).post(ROUTE, json={**VALID, **update}, headers=AUTH)
        assert response.status_code == 400
        assert "sensitive" not in response.text

    def test_actual_size_ignores_declared_length(self, clients: Callable[..., TestClient]) -> None:
        body = json.dumps(VALID).encode()
        response = clients(Actor()).post(
            ROUTE,
            content=body + b" " * (65537 - len(body)),
            headers={**AUTH, "Content-Type": "application/json", "Content-Length": "1"},
        )
        assert response.status_code == 413


@pytest.mark.parametrize("status", ["complete", "partial", "unavailable"])
def test_full_result_round_trip_and_owned_lifecycle(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    from evidentia_api.routers import storage_retention

    result = full_result(status)
    instance = MagicMock()
    instance.__enter__.return_value = instance
    instance.collect_v2.return_value = result
    constructor = Mock(return_value=instance)
    monkeypatch.setattr(storage_retention, "StorageRetentionCollector", constructor)
    response = clients(Actor()).post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 200
    returned = contracts.StorageRetentionCollectResult.model_validate_json(response.content)
    assert returned.model_dump(mode="json") == result.model_dump(mode="json")
    assert returned.status == status
    assert len(returned.resources) == 1
    assert returned.object_enforcement_assessed is False
    assert returned.recordset_completeness_assessed is False
    constructor.assert_called_once_with()
    instance.__exit__.assert_called_once()
    assert instance.collect_v2.call_args.args[0].model_dump(mode="json") == VALID


@pytest.mark.parametrize("update", [{"status": "unavailable"}, {"object_enforcement_assessed": 0}, {"resources": []}])
def test_invalid_result_is_server_failure_with_cleanup(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, update: dict[str, object]
) -> None:
    from evidentia_api.routers import storage_retention

    instance = MagicMock()
    instance.__enter__.return_value = instance
    instance.collect_v2.return_value = contracts.StorageRetentionCollectResult.model_construct(
        **{**full_result().__dict__, **update}
    )
    monkeypatch.setattr(storage_retention, "StorageRetentionCollector", Mock(return_value=instance))
    response = clients(Actor()).post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 500
    assert response.json()["detail"]["error"] == "collector_failed"
    assert set(response.json()["detail"]) == {"error", "message"}
    instance.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "provider,error,expected",
    [
        ("s3", ModuleNotFoundError("private-text", name="botocore"), 503),
        ("s3", ModuleNotFoundError("private-text", name="defusedxml"), 503),
        ("s3", ModuleNotFoundError("private-text", name="botocore.auth"), 500),
        ("s3", ImportError("private-text"), 500),
        ("gcs", ModuleNotFoundError("private-text", name="botocore"), 500),
        ("gcs", contracts.StorageRetentionInputError("invalid_result"), 500),
        ("gcs", RuntimeError("private-text"), 500),
    ],
)
def test_only_exact_selected_optional_absence_is_unavailable(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, provider: str, error: Exception, expected: int
) -> None:
    from evidentia_api.routers import storage_retention

    monkeypatch.setattr(storage_retention, "_collect_storage_retention", Mock(side_effect=error))
    targets = [{"bucket": "example-bucket", "region": "us-east-1"}] if provider == "s3" else VALID["targets"]
    response = clients(Actor()).post(ROUTE, json={**VALID, "provider": provider, "targets": targets}, headers=AUTH)
    assert response.status_code == expected
    assert "private-text" not in response.text
    assert set(response.json()["detail"]) == {"error", "message"}


def test_inclusive_request_limit_runs_in_worker_thread(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidentia_api.routers import storage_retention

    threads: dict[str, int] = {}
    original = run_in_threadpool

    def collect(selected: contracts.StorageRetentionCollectRequest) -> contracts.StorageRetentionCollectResult:
        threads["worker"] = threading.get_ident()
        assert selected.model_dump(mode="json") == VALID
        return full_result()

    async def dispatch(function: Callable[..., object], *args: object) -> object:
        threads["request"] = threading.get_ident()
        return await original(function, *args)

    monkeypatch.setattr(storage_retention, "_collect_storage_retention", collect)
    monkeypatch.setattr(storage_retention, "run_in_threadpool", dispatch)
    body = json.dumps(VALID).encode()
    response = clients(Actor()).post(
        ROUTE,
        content=body + b" " * (65536 - len(body)),
        headers={**AUTH, "Content-Type": "APPLICATION/JSON; charset=utf-8", "Content-Length": "1"},
    )
    assert response.status_code == 200
    assert threads["worker"] != threads["request"]


@pytest.mark.parametrize("provider", ["s3", "azure", "gcs"])
def test_status_uses_only_actual_fixed_reference_presence(monkeypatch: pytest.MonkeyPatch, provider: str) -> None:
    from evidentia_api.routers import storage_retention
    from evidentia_collectors.retention import _credentials

    references = {
        "s3": ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
        "azure": ("STORAGE_RETENTION_AZURE_ACCESS_TOKEN",),
        "gcs": ("STORAGE_RETENTION_GCS_ACCESS_TOKEN",),
    }
    for names in references.values():
        for name in names:
            monkeypatch.delenv(name, raising=False)
    resolver = Mock(side_effect=AssertionError("status must not resolve credentials"))
    monkeypatch.setattr(_credentials.EnvironmentCredentialProvider, "resolve", resolver)
    for name in references[provider]:
        monkeypatch.setenv(name, "synthetic-private-material")
    status = storage_retention.configuration_status()
    assert status["providers"] == {key: {"configured": key == provider} for key in references}
    assert status["live_validated"] is False
    assert status["credential_identity_verified"] is False
    assert "synthetic-private-material" not in json.dumps(status)
    resolver.assert_not_called()


@pytest.mark.parametrize("mutate_request", [False, True])
def test_result_must_match_request_snapshot(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, mutate_request: bool
) -> None:
    from evidentia_api.routers import storage_retention

    expected = {**VALID, "scope_label": "different-request-scope"}
    instance = MagicMock()
    instance.__enter__.return_value = instance

    def collect(selected: contracts.StorageRetentionCollectRequest) -> contracts.StorageRetentionCollectResult:
        if mutate_request:
            selected.root.scope_label = "selected-scope"
        return full_result()

    instance.collect_v2.side_effect = collect
    monkeypatch.setattr(storage_retention, "StorageRetentionCollector", Mock(return_value=instance))
    response = clients(Actor()).post(ROUTE, json=expected, headers=AUTH)
    assert response.status_code == 500
    assert response.json()["detail"]["error"] == "collector_failed"
    assert "different-request-scope" not in response.text
    instance.__exit__.assert_called_once()


@pytest.mark.parametrize("original,changed,expected", [("gcs", "s3", 500), ("s3", "gcs", 503)])
def test_optional_error_uses_original_request_provider(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, original: str, changed: str, expected: int
) -> None:
    from evidentia_api.routers import storage_retention

    def request_for(provider: str) -> contracts.StorageRetentionCollectRequest:
        targets = [{"bucket": "example-bucket", "region": "us-east-1"}] if provider == "s3" else VALID["targets"]
        return contracts.validated_request({**VALID, "provider": provider, "targets": targets})

    def worker(selected: contracts.StorageRetentionCollectRequest) -> contracts.StorageRetentionCollectResult:
        selected.root = request_for(changed).root
        raise ModuleNotFoundError("private-internal-path", name="botocore")

    monkeypatch.setattr(storage_retention, "_collect_storage_retention", worker)
    response = clients(Actor()).post(ROUTE, json=request_for(original).model_dump(mode="json"), headers=AUTH)
    assert response.status_code == expected
    assert "private-internal-path" not in response.text


@pytest.mark.parametrize(
    "fixture_name,status",
    [
        ("bucket-locked.json", "complete"),
        ("bucket-unknown-mode.json", "partial"),
        ("bucket-wrong-identity.json", "unavailable"),
    ],
)
def test_actual_gcs_pipeline_keeps_native_evidence_through_api(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, fixture_name: str, status: str
) -> None:
    from evidentia_api.routers import storage_retention
    from evidentia_collectors.retention import StorageRetentionCollector
    from evidentia_collectors.retention._credentials import BearerCredentials, CredentialResolution
    from evidentia_core import network_guard

    body = (Path(__file__).resolve().parents[2] / "fixtures" / "retention" / "gcs" / fixture_name).read_bytes()
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", network_guard._GETADDRINFO_DELEGATE)
    monkeypatch.setattr(network_guard, "_offline_enabled", False)

    def resolve(host: object, *args: object, **kwargs: object) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        assert host == "storage.googleapis.com"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "create_connection", Mock(side_effect=AssertionError("unexpected real connection")))

    class Wire(httpx.BaseTransport):
        calls = 0
        closed = 0

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            self.calls += 1
            assert request.method == "GET" and request.content == b""
            assert str(request.url) == (
                "https://storage.googleapis.com/storage/v1/b/synthetic-retention-bucket?projection=noAcl"
            )
            assert {entry[4][0] for entry in socket.getaddrinfo(request.url.host, 443)} == {"8.8.8.8"}
            return httpx.Response(200, headers={"ETag": '"synthetic-api-etag"'}, stream=httpx.ByteStream(body))

        def close(self) -> None:
            self.closed += 1

    credentials = Mock()
    credentials.resolve.return_value = CredentialResolution(BearerCredentials("synthetic-storage-value"), None)
    wire = Wire()
    monkeypatch.setattr(
        storage_retention,
        "StorageRetentionCollector",
        lambda: StorageRetentionCollector(
            credentials=credentials,
            transport_factory=lambda: wire,
            utc_clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
            monotonic_clock=lambda: 0.0,
            run_id_factory=lambda: "synthetic-api-gcs-run",
        ),
    )
    response = clients(Actor()).post(
        ROUTE, json={**VALID, "targets": [{"bucket": "synthetic-retention-bucket"}]}, headers=AUTH
    )
    assert response.status_code == 200
    result = contracts.StorageRetentionCollectResult.model_validate_json(response.content)
    assert result.status == status and len(result.resources) == 1
    assert wire.calls == 1 and wire.closed == 1
    credentials.resolve.assert_called_once_with("gcs")
    component = result.resources[0].components[0]
    assert component.raw_bytes == component.decoded_bytes == len(body)
    assert "synthetic-storage-value" not in response.text
    if status == "unavailable":
        assert component.projection is None and result.findings == []
    else:
        assert component.projection is not None
        assert component.projection.source_etag == '"synthetic-api-etag"'
        assert component.projection.fields["name"] == "synthetic-retention-bucket"
        assert result.findings[0].compliance_status.value == "unknown"
    if status == "complete":
        assert component.projection is not None
        policy = component.projection.fields["retentionPolicy"]
        assert isinstance(policy, dict)
        assert policy["retentionPeriod"] == "00086400"
        assert policy["effectiveTime"] == "2026-09-10T01:02:03.123456789+05:30"
        assert component.projection.source_metageneration == "0009007199254740993"
