"""Verify authentication and complete source-bound incident results at the API boundary."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from evidentia_collectors.incident_clock import _client as source_client
from evidentia_collectors.incident_clock import _contracts as contract
from evidentia_collectors.incident_clock import _profiles as profiles
from evidentia_collectors.incident_clock._http import HTTPReceipt
from evidentia_collectors.incident_clock.collector import IncidentClockCollector
from evidentia_core.plugins.auth import AuthProvider, AuthResult
from evidentia_core.rbac import RBACPolicy, Role
from fastapi.testclient import TestClient

ROUTE = "/api/collectors/incident-clock"
AUTH = {"Authorization": "Bearer synthetic-incident-actor"}


class Actor(AuthProvider):
    def __init__(self, principal: str | None = "synthetic-reader") -> None:
        self.principal = principal

    def authenticate(self, *, authorization_header: str | None) -> AuthResult:
        return AuthResult(authorization_header == AUTH["Authorization"], self.principal)

    def name(self) -> str:
        return "synthetic-incident-provider"


def configuration(provider: str = "servicenow") -> tuple[dict[str, Any], dict[str, Any]]:
    request: dict[str, Any] = {
        "provider": provider,
        "profile_alias": "session-test",
        "clock_alias": "workflow",
        "record_id": "10001",
    }
    start: dict[str, Any] = {"label": "Start", "meaning": "Configured workflow start"}
    end: dict[str, Any] = {"label": "End", "meaning": "Configured workflow end"}
    if provider == "servicenow":
        request["record_id"] = "1" * 32
        start["field"], end["field"] = "u_start", "u_end"
    elif provider == "jira":
        start.update(
            field_id="status", **{"from": {"state": "null", "value": None}, "to": {"state": "value", "value": "100"}}
        )
        end.update(
            field_id="status", **{"from": {"state": "value", "value": "100"}, "to": {"state": "value", "value": "200"}}
        )
    else:
        request.update(record_id="P-123", since="2024-01-01T00:00:00Z", until="2025-01-01T00:00:00Z")
        start["event_type"], end["event_type"] = "acknowledge_log_entry", "resolve_log_entry"
    configured: dict[str, Any] = {
        "alias": "session-test",
        "provider": provider,
        "credential_ref": "INCIDENT_CLOCK_SESSION_TEST_TOKEN",
        "allow_local_cli": True,
        "api_principals": ["synthetic-reader"],
        "record_ids": [request["record_id"]],
        "clocks": [
            {
                "clock_alias": "workflow",
                "label": "Workflow",
                "mapping_reference": "Synthetic runbook",
                "declared_workflow_meaning": "Two operational events",
                "start": start,
                "end": end,
            }
        ],
    }
    if provider == "jira":
        configured["cloud_id"] = "11111111-1111-1111-1111-111111111111"
    elif provider == "servicenow":
        configured["origin"] = "https://instance.example.org"
    return request, {"schema_version": "1", "profiles": [configured]}


VALID, CONFIG = configuration()


def install_transport(
    monkeypatch: pytest.MonkeyPatch, provider: str = "servicenow", mode: str = "complete"
) -> list[str]:
    base = Path(__file__).resolve().parents[3] / "tests/fixtures/incident_clock"
    names = {
        "jira": ["accessible-resources.json", "issue.json", "changelog-page1.json", "changelog-page2.json"],
        "servicenow": ["record.json"],
        "pagerduty": ["incident.json", "logs-page1.json", "logs-page2.json"],
    }[provider]
    bodies = [(base / provider / name).read_bytes() for name in names]
    if mode in {"unresolved", "reversed"}:
        assert provider == "servicenow"
        native = json.loads(bodies[0])
        native["result"]["u_end"] = "" if mode == "unresolved" else "2023-12-31 23:59:59"
        bodies[0] = json.dumps(native).encode()
    monkeypatch.setenv("INCIDENT_CLOCK_SESSION_TEST_TOKEN", "Synthetic-" + str(12345))
    monkeypatch.setenv("INCIDENT_CLOCK_SESSION_TEST_EXPIRES_AT", "2099-01-01T00:00:00Z")
    if mode == "unavailable":
        monkeypatch.delenv("INCIDENT_CLOCK_SESSION_TEST_TOKEN")
    calls: list[str] = []

    def receive(
        selected: Any, material: Any, template: str, start: int | None, deadline: float, budget: Any
    ) -> HTTPReceipt:
        calls.append(template)
        body = bodies.pop(0)
        if mode == "incomplete" and not bodies:
            return HTTPReceipt(403, datetime.now(UTC), None, 0, 128, "http_forbidden")
        budget.body_bytes += len(body)
        budget.wire_bytes += len(body) + 128
        return HTTPReceipt(200, datetime.now(UTC), body, len(body), len(body) + 128, None)

    monkeypatch.setattr(source_client, "get_identity", receive)
    return calls


def actual_result(
    monkeypatch: pytest.MonkeyPatch, provider: str = "servicenow", mode: str = "complete"
) -> contract.IncidentClockResult:
    install_transport(monkeypatch, provider, mode)
    request, configured = configuration(provider)
    selected = contract.validated_request(request)
    grant = profiles.authorize_api_selection(profiles.ProfileStore(configured), selected, principal="synthetic-reader")
    with IncidentClockCollector(grant) as instance:
        return instance.collect_v2(selected)


@pytest.fixture
def clients(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Callable[..., TestClient]]:
    for name in (
        "EVIDENTIA_API_AUTH_TOKEN_FILE",
        "EVIDENTIA_RBAC_POLICY_FILE",
        "EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE",
        "EVIDENTIA_INCIDENT_CLOCK_PROFILES_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(tmp_path / "gaps"))
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path / "evidence"))
    monkeypatch.chdir(tmp_path)
    from evidentia_api.app import create_app

    with ExitStack() as stack:

        def create(
            provider: AuthProvider | None = None, policy: RBACPolicy | None = None, store: object = None
        ) -> TestClient:
            app = create_app(auth_provider=provider, incident_clock_profiles=store, trust_proxy_headers=False)
            if policy is not None:
                app.state.rbac_policy = policy
            return stack.enter_context(TestClient(app))

        yield create


@pytest.mark.parametrize("body", [b"{", b" " * 16385])
def test_unconfigured_auth_precedes_body(clients: Callable[..., TestClient], body: bytes) -> None:
    response = clients().post(ROUTE, content=body)
    assert response.status_code == 403 and response.json()["detail"]["error"] == "auth_not_configured"


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
        b'{"provider":"jira","provider":"jira"}',
        b'{"record_id":NaN}',
        b'{"profile_alias":"\\ud800"}',
        b"{}",
    ],
)
def test_invalid_body_precedes_profiles_and_credentials(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    from evidentia_api.routers import incident_clock

    worker = Mock(side_effect=AssertionError("Unexpected profile access"))
    monkeypatch.setattr(incident_clock, "_authorize", worker)
    response = clients(Actor()).post(ROUTE, content=body, headers={**AUTH, "Content-Type": "application/json"})
    assert response.status_code == 400 and set(response.json()["detail"]) == {"error", "message"}
    worker.assert_not_called()


@pytest.mark.parametrize("provider", ["servicenow", "jira", "pagerduty"])
def test_installed_providers_return_complete_native_results(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, provider: str
) -> None:
    request, configured = configuration(provider)
    calls = install_transport(monkeypatch, provider)
    response = clients(Actor(), store=profiles.ProfileStore(configured)).post(ROUTE, json=request, headers=AUTH)
    assert response.status_code == 200 and calls
    result = contract.IncidentClockResult.model_validate_json(response.content)
    assert result.request == contract.validated_request(request) and result.source_state == "complete"
    assert result.clock.elapsed_seconds == "1" and len(result.events) == 2


@pytest.mark.parametrize("mode", ["complete", "unresolved", "reversed", "unavailable"])
def test_exact_issued_bytes_are_preserved_for_all_outcomes(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    from evidentia_api.routers import incident_clock

    observed = actual_result(monkeypatch, mode=mode)
    raw = contract.result_bytes(observed)
    monkeypatch.setattr(incident_clock, "_collect_incident_clock", lambda selected, profile: observed)
    response = clients(Actor(), store=profiles.ProfileStore(CONFIG)).post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 200 and response.content == raw


@pytest.mark.parametrize("mode", ["wrong-request", "unissued", "mutated", "failure"])
def test_invalid_or_substituted_results_are_static_failures(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    from evidentia_api.routers import incident_clock

    observed = actual_result(monkeypatch, provider="jira" if mode == "wrong-request" else "servicenow")
    if mode == "unissued":
        observed = contract.IncidentClockResult.model_validate_json(contract.result_bytes(observed))
    if mode == "mutated":
        observed.events.clear()

    def collect(selected: Any, profile: Any) -> Any:
        if mode == "failure":
            raise RuntimeError("synthetic-private-detail")
        return observed

    monkeypatch.setattr(incident_clock, "_collect_incident_clock", collect)
    response = clients(Actor(), store=profiles.ProfileStore(CONFIG)).post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 500 and response.json()["detail"]["error"] == "collector_failed"
    assert "synthetic-private-detail" not in response.text
