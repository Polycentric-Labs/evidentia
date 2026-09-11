"""Synthetic runtime controls for retention-only Entra/M365 reuse."""

from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from evidentia_collectors.entra_m365 import _client
from evidentia_collectors.entra_m365._contracts import (
    CAPABILITIES,
    AuthMode,
    EntraM365CollectRequest,
    EntraM365CollectResult,
)
from evidentia_collectors.entra_m365.collector import EntraM365Collector
from evidentia_core import network_guard

ORIGIN = "https://graph.microsoft.com"
ROUTE = "/v1.0/security/labels/retentionLabels"
NOW = datetime(2026, 9, 10, tzinfo=UTC)
ENVIRONMENT_RESOLVE = _client._EnvironmentCredentials.resolve
FIELDS = (
    "displayName",
    "retentionTrigger",
    "retentionDuration",
    "behaviorDuringRetentionPeriod",
    "actionAfterRetentionPeriod",
)


class SyntheticCredentials:
    def __init__(self, mode: AuthMode = "delegated", missing: bool = False) -> None:
        self.mode = mode
        self.missing = missing
        self.calls: list[str] = []

    def resolve(self, group: _client.CredentialGroup) -> _client._CredentialResolution:
        self.calls.append(group)
        assert group == "retention", "primary credentials must never be requested"
        return _client._CredentialResolution(
            token=None if self.missing else "SYNTHETIC_LABEL_TOKEN", declared_auth_mode=self.mode
        )


class TrackedBody(httpx.SyncByteStream):
    def __init__(self, body: object) -> None:
        self.body = json.dumps(body, ensure_ascii=True, allow_nan=False).encode("utf-8")
        self.closed = 0

    def __iter__(self) -> Iterator[bytes]:
        yield self.body

    def close(self) -> None:
        self.closed += 1


class Runtime:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.streams: list[TrackedBody] = []
        self.credentials: list[SyntheticCredentials] = []
        self.public_checks: list[str] = []
        self.pin_entries = 0
        self.pinned = False
        self.external_attempts = 0

    def collect(
        self,
        pages: list[dict[str, Any]],
        *,
        mode: AuthMode = "delegated",
        missing: bool = False,
        max_items: int = 10000,
        provider: _client._CredentialProvider | None = None,
    ) -> EntraM365CollectResult:
        if provider is None:
            provider = SyntheticCredentials(mode=mode, missing=missing)
            self.credentials.append(provider)
        sent = 0

        def send(request: httpx.Request) -> httpx.Response:
            nonlocal sent
            assert self.pinned
            assert request.method == "GET"
            assert str(request.url).startswith(ORIGIN + ROUTE)
            assert request.url.path == ROUTE
            assert request.headers["authorization"] == "Bearer SYNTHETIC_LABEL_TOKEN"
            self.requests.append(request)
            assert sent < len(pages), "unexpected extra request"
            page = pages[sent]
            sent += 1
            body = TrackedBody(page["body"])
            self.streams.append(body)
            return httpx.Response(page.get("status", 200), stream=body)

        with httpx.Client(transport=httpx.MockTransport(send), trust_env=False) as client:
            with EntraM365Collector(
                credentials=provider,
                client=client,
                utc_clock=lambda: NOW,
                monotonic_clock=lambda: 1.0,
                sleep=lambda _: None,
                run_id_factory=lambda: "synthetic-label-run",
            ) as collector:
                try:
                    result = collector.collect_v2(
                        EntraM365CollectRequest(
                            tenant_label="synthetic-label-scope",
                            capabilities=["retention-labels"],
                            max_items=max_items,
                        )
                    )
                finally:
                    assert not client.is_closed
            assert not client.is_closed
        assert client.is_closed
        assert all(body.closed == 1 for body in self.streams)
        assert result.model_validate_json(result.model_dump_json(warnings="error")) == result
        return result


@pytest.fixture
def runtime(monkeypatch: pytest.MonkeyPatch) -> Iterator[Runtime]:
    state = Runtime()
    prior_offline = network_guard.is_offline()

    def refuse(*args: object, **kwargs: object) -> None:
        state.external_attempts += 1
        raise AssertionError("real network or ambient credential access is forbidden")

    def public(url: str, *, subsystem: str) -> list[str]:
        assert url == ORIGIN and subsystem == "entra-m365"
        assert network_guard.is_offline() is False
        state.public_checks.append(url)
        return ["8.8.8.8"]

    @contextmanager
    def pin(host: str, addresses: list[str]) -> Iterator[None]:
        assert host == "graph.microsoft.com" and addresses == ["8.8.8.8"]
        assert state.pinned is False
        state.pinned = True
        state.pin_entries += 1
        try:
            yield
        finally:
            state.pinned = False

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(_client._EnvironmentCredentials, "resolve", refuse)
    monkeypatch.setattr(network_guard, "enforce_public_host", public)
    monkeypatch.setattr(network_guard, "pin_resolved_host", pin)
    with network_guard.offline_mode(False):
        yield state
    assert network_guard.is_offline() is prior_offline
    assert state.external_attempts == 0
    assert state.pinned is False


def assert_envelope(result: EntraM365CollectResult, status: str) -> None:
    assert result.status == status
    assert result.requested_capabilities == ["retention-labels"]
    assert result.full_surface_complete is False
    assert [cap.name for cap in result.capabilities] == list(CAPABILITIES)
    assert len(result.capabilities) == 9
    for cap in result.capabilities:
        if cap.name != "retention-labels":
            assert cap.state == "not_requested"
            assert cap.credential_basis is None and cap.declared_auth_mode is None
            assert cap.scanned == cap.matched_filter == cap.collected == cap.requests_attempted == 0
            assert cap.pages_completed == 0 and cap.field_coverage == {} and cap.diagnostics == []
    assert result.provenance.identity_basis == "operator-declared"
    assert result.provenance.authenticated_identity_verified is False
    assert result.provenance.tenant_label == "synthetic-label-scope"
    assert result.manifest.is_complete is (status == "complete")
    assert result.manifest.total_findings == len(result.findings)
    assert result.capabilities[5].declared_auth_mode == "delegated"
    assert result.capabilities[5].credential_basis == "unverified:retention-token"


def test_exact_route_delegated_only_and_literal_coverage(runtime: Runtime) -> None:
    known = {
        "id": " literal-label ",
        "displayName": "<script>literal</script>",
        "retentionTrigger": "dateLabeled",
        "retentionDuration": {"days": 0, "enabled": False, "nested": {"future": None}},
        "behaviorDuringRetentionPeriod": "retainAsRecord",
        "actionAfterRetentionPeriod": "relabel",
    }
    rows = [
        known,
        {"id": "absent"},
        {"id": "null", **dict.fromkeys(FIELDS)},
        {
            "id": "future",
            **{field: "FUTURE_VALUE" for field in FIELDS if field != "retentionDuration"},
            "retentionDuration": {"futureUnit": "source-literal"},
        },
        {"id": "empty", **{field: "" for field in FIELDS if field != "retentionDuration"}, "retentionDuration": {}},
    ]
    next_link = ORIGIN + ROUTE + "?$skiptoken=opaque%2f%2F+a%20b"
    result = runtime.collect(
        [
            {"body": {"value": [dict(known, unselected="DO_NOT_RETAIN")], "@odata.nextLink": next_link}},
            {"body": {"value": rows[1:]}},
        ]
    )
    assert_envelope(result, "complete")
    assert [str(request.url) for request in runtime.requests] == [ORIGIN + ROUTE, next_link]
    assert runtime.credentials[0].calls == ["retention"]
    assert runtime.public_checks == [ORIGIN, ORIGIN] and runtime.pin_entries == 2
    assert [finding.raw_data["source"] for finding in result.findings] == rows
    assert all(finding.raw_data["observation"] == {"scope": "label_configuration"} for finding in result.findings)
    assert "DO_NOT_RETAIN" not in result.model_dump_json()
    assert all(finding.compliance_status.value == "unknown" for finding in result.findings)
    assert all(finding.severity.value == "informational" for finding in result.findings)
    cap = result.capabilities[5]
    assert (cap.scanned, cap.matched_filter, cap.collected, cap.pages_completed, cap.requests_attempted) == (
        5,
        5,
        5,
        2,
        2,
    )
    assert set(cap.field_coverage) == {"id", *FIELDS}
    assert cap.field_coverage["id"].model_dump() == {"absent": 0, "null": 0, "known": 5, "unknown": 0}
    assert all([item.control_id for item in finding.control_mappings] == ["SI-12"] for finding in result.findings)
    for field in FIELDS:
        expected = {"absent": 1, "null": 1, "known": 3, "unknown": 0}
        if field not in {"displayName", "retentionDuration"}:
            expected = {"absent": 1, "null": 1, "known": 1, "unknown": 2}
        assert cap.field_coverage[field].model_dump() == expected
    assert cap.diagnostics == []
    assert result.manifest.warnings == ["retention-labels: unknown source values retained"]


def test_complete_empty_is_a_nine_capability_result(runtime: Runtime) -> None:
    result = runtime.collect([{"body": {"value": []}}])
    assert_envelope(result, "complete")
    assert result.findings == [] and result.manifest.empty_categories == ["retention-labels"]
    assert all(sum(value.model_dump().values()) == 0 for value in result.capabilities[5].field_coverage.values())
    assert runtime.credentials[0].calls == ["retention"]


def test_missing_retention_credential_never_falls_back(runtime: Runtime) -> None:
    result = runtime.collect([], missing=True)
    assert_envelope(result, "unavailable")
    assert runtime.requests == [] and runtime.credentials[0].calls == ["retention"]
    assert [item.code for item in result.capabilities[5].diagnostics] == ["credentials_missing"]


def test_application_credential_is_refused_before_send(runtime: Runtime) -> None:
    with pytest.raises(ValueError) as caught:
        runtime.collect([], mode="application")
    assert caught.value.args == ("collector_failed",)
    assert runtime.requests == [] and runtime.credentials[0].calls == ["retention"]
    assert runtime.pin_entries == 0


@pytest.mark.parametrize("status,diagnostic", [(401, "authentication_failed"), (403, "permission_denied")])
def test_source_denials_preserve_full_unavailable_result(runtime: Runtime, status: int, diagnostic: str) -> None:
    result = runtime.collect([{"status": status, "body": {"message": "UNTRUSTED_SOURCE_TEXT"}}])
    assert_envelope(result, "unavailable")
    assert runtime.credentials[0].calls == ["retention"]
    assert len(runtime.requests) == 1 and result.findings == []
    assert [(item.code, item.http_status) for item in result.capabilities[5].diagnostics] == [(diagnostic, status)]
    assert "UNTRUSTED_SOURCE_TEXT" not in result.model_dump_json()


def test_real_offline_guard_refuses_before_resolution(runtime: Runtime) -> None:
    with network_guard.offline_mode(True):
        result = runtime.collect([])
        assert network_guard.is_offline() is True
    assert_envelope(result, "unavailable")
    assert runtime.credentials[0].calls == [] and runtime.requests == [] and runtime.public_checks == []
    assert [item.code for item in result.capabilities[5].diagnostics] == ["configuration_invalid"]


def test_later_source_failure_retains_prior_label(runtime: Runtime) -> None:
    result = runtime.collect(
        [
            {"body": {"value": [{"id": "kept"}], "@odata.nextLink": ORIGIN + ROUTE + "?$skiptoken=next"}},
            {"status": 403, "body": {"message": "NOT_OUTPUT"}},
        ]
    )
    assert_envelope(result, "partial")
    assert [finding.raw_data["source"] for finding in result.findings] == [{"id": "kept"}]
    cap = result.capabilities[5]
    assert (cap.pages_completed, cap.scanned, cap.collected, cap.requests_attempted) == (1, 1, 1, 2)
    assert [item.code for item in cap.diagnostics] == ["permission_denied"]
    assert runtime.credentials[0].calls == ["retention"]


def test_item_limit_is_partial_with_retained_manifest(runtime: Runtime) -> None:
    result = runtime.collect([{"body": {"value": [{"id": "first"}, {"id": "second"}]}}], max_items=1)
    assert_envelope(result, "partial")
    assert result.findings[0].raw_data["source"] == {"id": "first"}
    assert result.manifest.coverage_counts[0].scanned == 2
    assert [item.code for item in result.capabilities[5].diagnostics] == ["item_limit"]


@pytest.mark.parametrize(
    "row",
    [
        {"id": "bad", "retentionDuration": []},
        {"id": "bad", "retentionTrigger": 1},
        {"id": "bad", "displayName": False},
    ],
)
def test_invalid_selected_detail_rejects_atomic_page(runtime: Runtime, row: dict[str, Any]) -> None:
    result = runtime.collect([{"body": {"value": [{"id": "good"}, row]}}])
    assert_envelope(result, "unavailable")
    assert result.findings == []
    cap = result.capabilities[5]
    assert cap.scanned == cap.pages_completed == 0 and cap.field_coverage == {}
    assert [item.code for item in cap.diagnostics] == ["invalid_record"]


@pytest.mark.parametrize("primary_mode", ["application", "delegated", "UNSUPPORTED_PRIMARY_MODE"])
def test_normal_environment_provider_reads_only_delegated_retention(
    runtime: Runtime, monkeypatch: pytest.MonkeyPatch, primary_mode: str
) -> None:
    reads: list[str] = []

    class SyntheticEnvironment:
        def get(self, key: str, default: str | None = None) -> str | None:
            reads.append(key)
            assert key == "ENTRA_M365_RETENTION_ACCESS_TOKEN"
            values = {
                "ENTRA_M365_ACCESS_TOKEN": "SYNTHETIC_UNUSED_PRIMARY_TOKEN",
                "ENTRA_M365_AUTH_MODE": primary_mode,
                "ENTRA_M365_RETENTION_ACCESS_TOKEN": "SYNTHETIC_LABEL_TOKEN",
            }
            return values.get(key, default)

    monkeypatch.setattr(_client, "os", SimpleNamespace(environ=SyntheticEnvironment()))
    monkeypatch.setattr(_client._EnvironmentCredentials, "resolve", ENVIRONMENT_RESOLVE)
    result = runtime.collect(
        [{"body": {"value": [{"id": "synthetic-env-label"}]}}], provider=_client._EnvironmentCredentials()
    )
    assert_envelope(result, "complete")
    assert reads == ["ENTRA_M365_RETENTION_ACCESS_TOKEN"]
    assert len(runtime.requests) == 1 and runtime.requests[0].url.raw_path == ROUTE.encode("ascii")


def test_normal_environment_missing_retention_keeps_unavailable_envelope(
    runtime: Runtime, monkeypatch: pytest.MonkeyPatch
) -> None:
    reads: list[str] = []

    class SyntheticEnvironment:
        def get(self, key: str, default: str | None = None) -> str | None:
            reads.append(key)
            assert key == "ENTRA_M365_RETENTION_ACCESS_TOKEN"
            return default

    monkeypatch.setattr(_client, "os", SimpleNamespace(environ=SyntheticEnvironment()))
    monkeypatch.setattr(_client._EnvironmentCredentials, "resolve", ENVIRONMENT_RESOLVE)
    result = runtime.collect([], provider=_client._EnvironmentCredentials())
    assert_envelope(result, "unavailable")
    assert reads == ["ENTRA_M365_RETENTION_ACCESS_TOKEN"] and runtime.requests == []
    assert [item.code for item in result.capabilities[5].diagnostics] == ["credentials_missing"]
