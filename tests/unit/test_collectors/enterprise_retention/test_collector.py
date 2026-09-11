"""Exercise the enterprise entry point with real sessions and synthetic I/O."""

from __future__ import annotations

import json
import socket
import ssl
from datetime import UTC, datetime
from typing import Any
from unittest.mock import Mock

import httpx
import pytest
from evidentia_collectors.enterprise_retention import _contracts as contracts
from evidentia_collectors.enterprise_retention import _profiles as profiles
from evidentia_collectors.enterprise_retention._client import EnterpriseReadSession, EnterpriseRetentionOperationalError
from evidentia_collectors.enterprise_retention._credentials import CredentialMaterial
from evidentia_collectors.enterprise_retention.collector import EnterpriseRetentionCollector
from evidentia_core import network_guard


class CollectorWire:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, provider: str, *, count: int = 1) -> None:
        self.provider = provider
        self.requests: list[httpx.Request] = []
        self.dns_calls = 0
        self.resolutions = 0
        self.closed = 0
        self.statuses: list[int] = []
        self.error: BaseException | None = None
        self.request = contracts.validated_request(
            {
                "provider": provider,
                "profile_alias": "selected",
                "scope_label": "synthetic",
                "targets": [
                    {"matter_id": f"matter-{i}"} if provider == "google-vault" else {"index": f"events-{i}"}
                    for i in range(count)
                ],
            }
        )
        origin = {
            "google-vault": "https://vault.googleapis.com:443",
            "splunk-enterprise": "https://splunk.example.invalid:8089",
            "elastic-ilm": "https://elastic.example.invalid:9200",
        }[provider]
        self.profile = profiles.AuthorizedProfile(
            profiles.FrozenProfile(
                alias="selected",
                provider=self.request.root.provider,
                origin=origin,
                credential_ref="ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
                address_policy=profiles.AddressPolicy("public"),
            ),
            self,
        )
        monkeypatch.setattr(socket, "getaddrinfo", self.dns)
        monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", self.dns)
        monkeypatch.setattr(network_guard._pin_state, "hosts", {}, raising=False)
        monkeypatch.setattr(network_guard, "_offline_enabled", False)
        monkeypatch.setattr(socket, "create_connection", Mock(side_effect=AssertionError("unexpected real connection")))
        monkeypatch.setattr(socket.socket, "connect", Mock(side_effect=AssertionError("unexpected real socket")))

    def dns(self, host: object, port: int, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        self.dns_calls += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]

    def resolve(self, profile: profiles.FrozenProfile) -> CredentialMaterial:
        self.resolutions += 1
        return CredentialMaterial(profile.provider, "synthetic")

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        path = request.url.path
        body: dict[str, Any]
        if self.provider == "google-vault":
            body = {"holds": []} if path.endswith("/holds") else {"matterId": path.rsplit("/", 1)[-1], "state": "OPEN"}
        elif self.provider == "splunk-enterprise":
            body = {
                "entry": [
                    {
                        "name": path.rsplit("/", 1)[-1],
                        "content": {"datatype": "event", "frozenTimePeriodInSecs": "0009007199254740993"},
                    }
                ]
            }
        elif path == "/_ilm/status":
            body = {"operation_mode": "RUNNING"}
        else:
            index = path.split("/")[1]
            body = {"indices": {index: {"index": index, "managed": False}}}
        return httpx.Response(
            self.statuses.pop(0) if self.statuses else 200,
            stream=httpx.ByteStream(json.dumps(body).encode()),
        )

    def factory(self, context: ssl.SSLContext) -> httpx.BaseTransport:
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        owner = self

        class Wire(httpx.MockTransport):
            def close(self) -> None:
                owner.closed += 1
                super().close()

        return Wire(self.handle)

    def collector(self, **updates: Any) -> EnterpriseRetentionCollector:
        return EnterpriseRetentionCollector(
            profile=self.profile,
            transport_factory=self.factory,
            utc_clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
            monotonic_clock=lambda: 0.0,
            sleep=lambda delay: None,
            run_id_factory=lambda: "01K00000000000000000000000",
            **updates,
        )


@pytest.mark.parametrize("provider", ["google-vault", "splunk-enterprise", "elastic-ilm"])
def test_constructor_and_close_have_no_provider_side_effects(monkeypatch: pytest.MonkeyPatch, provider: str) -> None:
    wire = CollectorWire(monkeypatch, provider)
    instance = wire.collector()
    assert wire.requests == [] and wire.resolutions == wire.dns_calls == wire.closed == 0
    instance.close()
    instance.close()
    with pytest.raises(EnterpriseRetentionOperationalError):
        instance.collect_v2(wire.request)
    with pytest.raises(EnterpriseRetentionOperationalError):
        instance.__enter__()
    assert wire.requests == [] and wire.resolutions == wire.dns_calls == wire.closed == 0


@pytest.mark.parametrize("provider,reads", [("google-vault", 4), ("splunk-enterprise", 2), ("elastic-ilm", 3)])
def test_actual_all_provider_pipeline_and_shared_read_accounting(
    monkeypatch: pytest.MonkeyPatch, provider: str, reads: int
) -> None:
    wire = CollectorWire(monkeypatch, provider, count=2)
    original = wire.request.model_dump(mode="python")
    with wire.collector() as collector:
        result = collector.collect_v2(wire.request)
    assert result.root.provider == provider and result.root.status == "complete"
    assert [value.target.model_dump(mode="python") for value in result.root.resources] == original["targets"]
    assert wire.request.model_dump(mode="python") == original
    assert len(wire.requests) == len(result.root.source_reads) == reads
    assert wire.closed == reads and wire.resolutions == 1
    assert all(request.method == "GET" and request.content == b"" for request in wire.requests)
    assert result.root.authenticated_identity_verified is False
    assert result.root.recordset_completeness_assessed is False
    assert (
        contracts.EnterpriseRetentionCollectResult.model_validate_json(result.publication_bytes()).publication_bytes()
        == result.publication_bytes()
    )
    if provider == "google-vault":
        assert all(
            "view=BASIC" in str(value.url) or "view=FULL_HOLD&pageSize=100" in str(value.url) for value in wire.requests
        )
    elif provider == "splunk-enterprise":
        assert all(value.url.query == b"output_mode=json&summarize=false" for value in wire.requests)
        assert b"0009007199254740993" in result.publication_bytes()
    else:
        assert [value.url.path for value in wire.requests].count("/_ilm/status") == 1
        assert not any("/_ilm/policy/" in value.url.path for value in wire.requests)


@pytest.mark.parametrize("statuses,status", [([200, 403], "partial"), ([403, 404], "unavailable")])
def test_entry_point_preserves_partial_and_unavailable_selection(
    monkeypatch: pytest.MonkeyPatch, statuses: list[int], status: str
) -> None:
    wire = CollectorWire(monkeypatch, "splunk-enterprise", count=2)
    wire.statuses = statuses.copy()
    with wire.collector() as collector:
        result = collector.collect_v2(wire.request)
    assert result.root.status == status
    assert len(result.root.resources) == len(result.root.source_reads) == 2
    assert len(wire.requests) == wire.closed == 2
    assert result.root.source_reads[1].diagnostics[0].code in {"http_denied", "http_not_found"}


def test_collect_compatibility_returns_validated_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = CollectorWire(monkeypatch, "splunk-enterprise")
    with wire.collector() as collector:
        findings = collector.collect(wire.request)
    assert len(findings) == 1 and findings[0].compliance_status == "unknown"
    assert wire.closed == 1


def test_each_collect_call_owns_its_credential_and_read_state(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = CollectorWire(monkeypatch, "splunk-enterprise")
    with wire.collector() as collector:
        first = collector.collect_v2(wire.request)
        second = collector.collect_v2(wire.request)
    assert wire.resolutions == wire.closed == len(wire.requests) == 2
    first.root.resources.clear()
    assert len(second.root.resources) == 1
    assert (
        len(contracts.EnterpriseRetentionCollectResult.model_validate_json(second.publication_bytes()).root.resources)
        == 1
    )


@pytest.mark.parametrize("field,value", [("profile_alias", "other"), ("provider", "elastic-ilm")])
def test_mismatched_profile_is_refused_before_dns_or_credentials(
    monkeypatch: pytest.MonkeyPatch, field: str, value: str
) -> None:
    wire = CollectorWire(monkeypatch, "splunk-enterprise")
    selected = wire.request.model_dump(mode="python")
    selected[field] = value
    request = contracts.validated_request(selected)
    with wire.collector() as collector, pytest.raises(EnterpriseRetentionOperationalError):
        collector.collect_v2(request)
    assert wire.requests == [] and wire.resolutions == wire.dns_calls == wire.closed == 0


def test_invalid_request_refuses_before_session_work(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = CollectorWire(monkeypatch, "splunk-enterprise")
    invalid = wire.request.model_copy()
    object.__setattr__(invalid, "root", {"provider": "splunk-enterprise"})
    with wire.collector() as collector, pytest.raises(contracts.EnterpriseRetentionInputError):
        collector.collect_v2(invalid)
    assert wire.requests == [] and wire.resolutions == wire.dns_calls == wire.closed == 0


def test_original_cancellation_propagates_and_closes_owned_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = CollectorWire(monkeypatch, "splunk-enterprise")
    cancellation = KeyboardInterrupt("synthetic cancellation")
    wire.error = cancellation
    with wire.collector() as collector, pytest.raises(KeyboardInterrupt) as caught:
        collector.collect_v2(wire.request)
    assert caught.value is cancellation and wire.closed == 1


def test_unexpected_dispatch_failure_is_sanitized_and_session_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_collectors.enterprise_retention import collector as implementation

    wire = CollectorWire(monkeypatch, "splunk-enterprise")
    captured: list[EnterpriseReadSession] = []

    def fail(target: object, session: EnterpriseReadSession) -> Any:
        captured.append(session)
        raise RuntimeError("synthetic private failure")

    monkeypatch.setattr(implementation, "_read_target", fail)
    with wire.collector() as collector, pytest.raises(EnterpriseRetentionOperationalError) as caught:
        collector.collect_v2(wire.request)
    assert "private" not in str(caught.value)
    assert len(captured) == 1 and captured[0]._closed is True
    assert wire.requests == [] and wire.resolutions == 0
