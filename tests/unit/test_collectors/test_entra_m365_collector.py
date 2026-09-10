"""Collector orchestration and lifecycle with synthetic transports."""

from __future__ import annotations

import json
import socket
import threading
from collections import Counter
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import NoReturn
from unittest.mock import Mock

import httpx
import pytest
from evidentia_collectors.entra_m365 import _client
from evidentia_collectors.entra_m365 import collector as _collector_implementation
from evidentia_collectors.entra_m365._contracts import (
    CAPABILITIES,
    EntraM365CollectRequest,
    EntraM365CollectResult,
    EntraM365InputError,
    EntraM365RunContext,
)
from evidentia_collectors.entra_m365.collector import EntraM365Collector
from evidentia_core import network_guard

_NOW = datetime(2026, 9, 10, tzinfo=UTC)
_DLP = Path(__file__).resolve().parents[2] / "fixtures" / "entra_m365" / "purview" / "cisa-dlp-recorded.json"


class SyntheticCredentials:
    def __init__(self, missing: bool = False) -> None:
        self.calls: list[str] = []
        self.missing = missing

    def resolve(self, group: _client.CredentialGroup) -> _client._CredentialResolution:
        self.calls.append(group)
        return _client._CredentialResolution(
            None if self.missing else "SYNTHETIC_COLLECTOR_TOKEN",
            "delegated" if group == "retention" else "application",
        )


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network_guard, "check_url", lambda *args, **kwargs: None)
    monkeypatch.setattr(network_guard, "enforce_public_host", lambda *args, **kwargs: ["8.8.8.8"])
    monkeypatch.setattr(network_guard, "pin_resolved_host", lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr("socket.getaddrinfo", Mock(side_effect=AssertionError("unexpected real DNS")))
    monkeypatch.setattr("socket.create_connection", Mock(side_effect=AssertionError("unexpected real socket")))


def response(body: object = None, *, status: int = 200) -> httpx.Response:
    content = json.dumps({"value": []} if body is None else body).encode()
    return httpx.Response(status, stream=httpx.ByteStream(content))


def collector(credentials: SyntheticCredentials, client: httpx.Client) -> EntraM365Collector:
    return EntraM365Collector(
        credentials=credentials,
        client=client,
        utc_clock=lambda: _NOW,
        monotonic_clock=lambda: 1.0,
        sleep=lambda _: None,
        run_id_factory=lambda: "synthetic-controller-run",
    )


def test_constructor_is_lazy_and_borrowed_client_remains_open() -> None:
    credentials = SyntheticCredentials()
    with httpx.Client(transport=httpx.MockTransport(lambda _: response())) as client:
        with collector(credentials, client):
            assert credentials.calls == []
        assert not client.is_closed


def test_full_surface_uses_all_actual_readers_and_one_shared_result() -> None:
    credentials = SyntheticCredentials()
    requests: list[httpx.Request] = []

    def send(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return response()

    with httpx.Client(transport=httpx.MockTransport(send)) as client:
        result = collector(credentials, client).collect_v2(
            EntraM365CollectRequest(
                tenant_label="fixture",
                dlp_content=_DLP.read_text(encoding="utf-8"),
            )
        )
        assert not client.is_closed
    assert [request.url.path for request in requests] == list(_client.ROUTES.values())
    assert credentials.calls == ["primary", "retention"]
    assert result.status == "complete"
    assert result.full_surface_complete is True
    assert [cap.name for cap in result.capabilities] == list(CAPABILITIES)
    assert all(cap.state == "complete" for cap in result.capabilities)
    assert len(result.findings) == 11
    assert result.manifest.total_findings == 11
    assert result.manifest.run_id == "synthetic-controller-run"
    assert result.manifest.is_complete is True
    assert result.provenance.authenticated_identity_verified is False
    assert result.model_validate_json(result.model_dump_json()) == result


def test_requested_subset_is_canonical_and_omitted_sources_are_explicit() -> None:
    credentials = SyntheticCredentials()
    paths: list[str] = []

    def send(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return response()

    request = EntraM365CollectRequest(tenant_label="fixture", capabilities=["retention-labels", "directory-roles"])
    with httpx.Client(transport=httpx.MockTransport(send)) as client:
        result = collector(credentials, client).collect_v2(request)
    assert paths == [_client.ROUTES["directory-roles"], _client.ROUTES["retention-labels"]]
    assert result.requested_capabilities == ["directory-roles", "retention-labels"]
    assert result.status == "complete"
    assert result.full_surface_complete is False
    assert sum(cap.state == "not_requested" for cap in result.capabilities) == 7
    assert result.findings == []


@pytest.mark.parametrize("content", ["{", "[]", '{"schema_version":1,"schema_version":1}', '{"schema_version":false}'])
def test_full_dlp_preflight_precedes_graph_reader_creation(content: str, monkeypatch: pytest.MonkeyPatch) -> None:
    credentials = SyntheticCredentials()
    constructor = Mock(side_effect=AssertionError("Graph reader constructed before preflight"))
    monkeypatch.setattr(_client, "EntraM365GraphReader", constructor)
    with httpx.Client(transport=httpx.MockTransport(lambda _: response())) as client:
        with pytest.raises(EntraM365InputError):
            collector(credentials, client).collect_v2(
                EntraM365CollectRequest(
                    tenant_label="fixture",
                    capabilities=["directory-roles", "dlp-export"],
                    dlp_content=content,
                )
            )
        assert not client.is_closed
    assert credentials.calls == []
    assert constructor.call_count == 0


def test_mutated_request_is_revalidated_before_credentials() -> None:
    request = EntraM365CollectRequest(tenant_label="fixture")
    request.capabilities.append("directory-roles")
    credentials = SyntheticCredentials()
    with (
        httpx.Client(transport=httpx.MockTransport(lambda _: response())) as client,
        pytest.raises(EntraM365InputError, match="invalid_field"),
    ):
        collector(credentials, client).collect_v2(request)
    assert credentials.calls == []


def test_dlp_only_needs_no_graph_client_or_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    credentials = SyntheticCredentials()
    construction = Mock(side_effect=AssertionError("unexpected HTTP transport"))
    monkeypatch.setattr(httpx, "HTTPTransport", construction)
    result = EntraM365Collector(credentials=credentials).collect_v2(
        EntraM365CollectRequest(
            tenant_label="fixture",
            capabilities=["dlp-export"],
            dlp_content=_DLP.read_text(encoding="utf-8"),
        )
    )
    assert result.status == "complete"
    assert credentials.calls == []
    assert construction.call_count == 0


def test_primary_401_latch_is_run_local_and_retention_is_independent() -> None:
    credentials = SyntheticCredentials()
    requests: list[str] = []
    first = True

    def send(request: httpx.Request) -> httpx.Response:
        nonlocal first
        requests.append(request.url.path)
        if first:
            first = False
            return response(status=401)
        return response()

    request = EntraM365CollectRequest(tenant_label="fixture")
    with httpx.Client(transport=httpx.MockTransport(send)) as client:
        runner = collector(credentials, client)
        first_result = runner.collect_v2(request)
        second_result = runner.collect_v2(request)
    assert first_result.status == "partial"
    assert first_result.capabilities[5].state == "complete"
    assert requests[:2] == [_client.ROUTES["conditional-access"], _client.ROUTES["retention-labels"]]
    assert requests[2:] == list(_client.ROUTES.values())
    assert credentials.calls == ["primary", "retention", "primary", "retention"]
    assert second_result.status == "partial"
    assert sum(cap.state == "complete" for cap in second_result.capabilities) == 8


def test_missing_credentials_return_unavailable_without_creating_http_client(monkeypatch: pytest.MonkeyPatch) -> None:
    constructor = Mock(side_effect=AssertionError("unexpected HTTP transport"))
    monkeypatch.setattr(httpx, "HTTPTransport", constructor)
    result = EntraM365Collector(credentials=SyntheticCredentials(missing=True)).collect_v2(
        EntraM365CollectRequest(tenant_label="fixture")
    )
    assert result.status == "unavailable"
    assert result.findings == []
    assert result.manifest.is_complete is False
    assert constructor.call_count == 0


def test_findings_convention_preserves_the_full_result_finding_list() -> None:
    credentials = SyntheticCredentials()
    with httpx.Client(transport=httpx.MockTransport(lambda _: response({"value": [{"id": "role"}]}))) as client:
        result = collector(credentials, client).collect(
            EntraM365CollectRequest(
                tenant_label="fixture",
                capabilities=["directory-roles"],
            )
        )
    assert len(result) == 1
    assert result[0].raw_data["source"] == {"id": "role"}


def test_closed_collector_refuses_collection_without_credentials() -> None:
    credentials = SyntheticCredentials()
    runner = EntraM365Collector(credentials=credentials)
    runner.close()
    with pytest.raises(ValueError, match="collector_closed"):
        runner.collect_v2(EntraM365CollectRequest(tenant_label="fixture"))
    assert credentials.calls == []


_LIFECYCLE_NOW = datetime(2026, 6, 1, tzinfo=UTC)
_LIFECYCLE_ERROR = "SYNTHETIC_COLLECTOR_ERROR_DETAIL"


@pytest.fixture(autouse=True)
def lifecycle_network_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("Collector tests cannot use network")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(network_guard, "check_url", lambda *args, **kwargs: None)
    monkeypatch.setattr(network_guard, "enforce_public_host", lambda *args, **kwargs: ["8.8.8.8"])
    monkeypatch.setattr(network_guard, "pin_resolved_host", lambda *args, **kwargs: nullcontext())


class LifecycleCredentials:
    def __init__(self) -> None:
        self.calls: list[_client.CredentialGroup] = []

    def resolve(self, group: _client.CredentialGroup) -> _client._CredentialResolution:
        self.calls.append(group)
        return _client._CredentialResolution(
            "SYNTHETIC_COLLECTOR_TOKEN", "delegated" if group == "retention" else "application"
        )


class LifecycleStream(httpx.SyncByteStream):
    def __init__(self, body: object) -> None:
        self.data = json.dumps(body).encode("utf-8")
        self.closed = 0

    def __iter__(self) -> Iterator[bytes]:
        yield self.data

    def close(self) -> None:
        self.closed += 1


def _lifecycle_response(
    rows: list[dict[str, str]] | None = None, *, status: int = 200, streams: list[LifecycleStream] | None = None
) -> httpx.Response:
    stream = LifecycleStream({"value": [{"id": "source"}] if rows is None else rows})
    if streams is not None:
        streams.append(stream)
    return httpx.Response(status, stream=stream)


class LifecycleTransport(httpx.MockTransport):
    def __init__(self, handler: Callable[[httpx.Request], httpx.Response], *, close_error: bool = False) -> None:
        super().__init__(handler)
        self.closed = 0
        self.close_error = close_error

    def close(self) -> None:
        self.closed += 1
        if self.close_error:
            raise RuntimeError(_LIFECYCLE_ERROR)


def _lifecycle_collector(
    credentials: _client._CredentialProvider,
    *,
    client: httpx.Client | None = None,
    tick: Callable[[], float] = lambda: 0.0,
    run_id: Callable[[], str] = lambda: "synthetic-lifecycle-run",
) -> EntraM365Collector:
    return EntraM365Collector(
        credentials=credentials,
        client=client,
        utc_clock=lambda: _LIFECYCLE_NOW,
        monotonic_clock=tick,
        sleep=lambda seconds: None,
        run_id_factory=run_id,
    )


def _owned_transports(
    monkeypatch: pytest.MonkeyPatch, *, close_error: bool = False
) -> tuple[list[LifecycleTransport], list[LifecycleStream]]:
    created: list[LifecycleTransport] = []
    streams: list[LifecycleStream] = []

    def create(**options: object) -> LifecycleTransport:
        assert options == {"trust_env": False, "http2": False, "retries": 0}
        transport = LifecycleTransport(lambda request: _lifecycle_response(streams=streams), close_error=close_error)
        created.append(transport)
        return transport

    monkeypatch.setattr(httpx, "HTTPTransport", create)
    return created, streams


def test_repeated_runs_close_each_owned_transport_and_all_responses(monkeypatch: pytest.MonkeyPatch) -> None:
    created, streams = _owned_transports(monkeypatch)
    credentials = LifecycleCredentials()
    collector = _lifecycle_collector(credentials)
    request = EntraM365CollectRequest(tenant_label="fixture", capabilities=["directory-roles"])
    first = collector.collect_v2(request)
    first_source = first.findings[0].raw_data["source"]
    assert isinstance(first_source, dict)
    first_source["id"] = "caller-mutated"
    second = collector.collect_v2(request)
    assert len(created) == 2 and all(item.closed == 1 for item in created)
    assert len(streams) == 2 and all(item.closed == 1 for item in streams)
    assert second.findings[0].raw_data["source"] == {"id": "source"}
    assert credentials.calls == ["primary", "primary"]
    assert EntraM365CollectResult.model_validate_json(second.model_dump_json()) == second
    collector.close()
    collector.close()
    assert all(item.closed == 1 for item in created)


@pytest.mark.parametrize("stage", ["reader", "result", "close", "cancel"])
def test_resource_cleanup_and_exception_boundary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture, stage: str
) -> None:
    created, streams = _owned_transports(monkeypatch, close_error=stage == "close")

    def fail(*args: object, **kwargs: object) -> NoReturn:
        if stage == "cancel":
            raise KeyboardInterrupt("synthetic-cancel")
        raise RuntimeError(_LIFECYCLE_ERROR)

    if stage in {"reader", "cancel"}:
        monkeypatch.setattr(
            _collector_implementation,
            "_READERS",
            tuple(
                (name, fail if name == "directory-roles" else read) for name, read in _collector_implementation._READERS
            ),
        )
    elif stage == "result":
        monkeypatch.setattr(EntraM365RunContext, "build_result", fail)
    request = EntraM365CollectRequest(tenant_label="fixture", capabilities=["conditional-access", "directory-roles"])
    with pytest.raises(KeyboardInterrupt if stage == "cancel" else ValueError) as error:
        _lifecycle_collector(LifecycleCredentials()).collect_v2(request)
    assert str(error.value) == ("synthetic-cancel" if stage == "cancel" else "collector_failed")
    assert len(created) == 1 and created[0].closed == 1
    assert streams and all(item.closed == 1 for item in streams)
    captured = capsys.readouterr()
    assert _LIFECYCLE_ERROR not in captured.out + captured.err + caplog.text


@pytest.mark.parametrize("stage", ["reader", "result"])
def test_borrowed_client_survives_aborted_run(monkeypatch: pytest.MonkeyPatch, stage: str) -> None:
    def fail(*args: object, **kwargs: object) -> NoReturn:
        raise RuntimeError(_LIFECYCLE_ERROR)

    if stage == "reader":
        monkeypatch.setattr(
            _collector_implementation,
            "_READERS",
            tuple(
                (name, fail if name == "directory-roles" else read) for name, read in _collector_implementation._READERS
            ),
        )
    else:
        monkeypatch.setattr(EntraM365RunContext, "build_result", fail)
    transport = LifecycleTransport(lambda request: _lifecycle_response())
    with httpx.Client(transport=transport) as client:
        collector = _lifecycle_collector(LifecycleCredentials(), client=client)
        with pytest.raises(ValueError, match=r"^collector_failed$"):
            collector.collect_v2(
                EntraM365CollectRequest(tenant_label="fixture", capabilities=["conditional-access", "directory-roles"])
            )
        collector.close()
        assert not client.is_closed and transport.closed == 0
    assert transport.closed == 1


@pytest.mark.parametrize(
    "change",
    [
        {"max_items": True},
        {"max_items": 0},
        {"max_pages": "2"},
        {"lookback_days": 2.0},
        {"tenant_label": _LIFECYCLE_ERROR + "/invalid"},
        {"capabilities": ["directory-roles", "directory-roles"]},
    ],
)
def test_copy_updates_are_revalidated_before_clocks_and_reader_creation(
    monkeypatch: pytest.MonkeyPatch, change: dict[str, object]
) -> None:
    construction = Mock(side_effect=AssertionError("Request must fail before reader"))
    clock = Mock(side_effect=AssertionError("Request must fail before clock"))
    monkeypatch.setattr(_client, "EntraM365GraphReader", construction)
    credentials = LifecycleCredentials()
    request = EntraM365CollectRequest(tenant_label="fixture", capabilities=["directory-roles"]).model_copy(
        update=change
    )
    with pytest.raises(EntraM365InputError) as error:
        EntraM365Collector(credentials=credentials, utc_clock=clock).collect_v2(request)
    assert str(error.value) == "invalid_field"
    assert error.value.code == "invalid_field"
    assert not credentials.calls and not construction.called and not clock.called


def test_complete_dlp_shape_preflight_does_not_construct_run_or_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    value = {
        "schema_version": 1,
        "source": {
            "kind": "authored-synthetic",
            "producer": "Synthetic collector fixture",
            "producer_version": None,
            "captured_at": None,
            "parent_sha256": None,
            "source_uri": None,
            "sanitization": "synthetic",
        },
        "policies": [
            {
                "Guid": "p",
                "Name": "p",
                "Mode": "Enable",
                "DistributionStatus": "Pending",
                "Workload": "Exchange",
                "Enabled": True,
                "IsValid": True,
            }
        ],
        "rules": [
            {
                "Guid": "r",
                "Policy": "p",
                "ParentPolicyName": "p",
                "Mode": "Enforce",
                "Workload": "Exchange",
                "Disabled": 0,
                "IsValid": True,
            }
        ],
    }
    construction = Mock(side_effect=AssertionError("DLP preflight must precede reader"))
    clock = Mock(side_effect=AssertionError("DLP preflight must precede run"))
    monkeypatch.setattr(_client, "EntraM365GraphReader", construction)
    credentials = LifecycleCredentials()
    request = EntraM365CollectRequest(
        tenant_label="fixture", capabilities=["conditional-access", "dlp-export"], dlp_content=json.dumps(value)
    )
    with pytest.raises(EntraM365InputError, match=r"^invalid_field$"):
        EntraM365Collector(credentials=credentials, utc_clock=clock).collect_v2(request)
    assert not credentials.calls and not construction.called and not clock.called


def test_request_mutation_during_transport_cannot_change_effective_scope() -> None:
    request = EntraM365CollectRequest(tenant_label="original", capabilities=["conditional-access", "directory-roles"])
    paths: list[str] = []

    def send(wire: httpx.Request) -> httpx.Response:
        paths.append(wire.url.path)
        if len(paths) == 1:
            request.tenant_label = "changed"
            request.capabilities[:] = ["conditional-access", "conditional-access"]
            request.max_items = 0
        return _lifecycle_response()

    credentials = LifecycleCredentials()
    with httpx.Client(transport=httpx.MockTransport(send)) as client:
        collector = _lifecycle_collector(credentials, client=client)
        result = collector.collect_v2(request)
        assert result.status == "complete"
        assert result.requested_capabilities == ["conditional-access", "directory-roles"]
        assert result.provenance.tenant_label == "original"
        assert len(result.findings) == 2
        assert all(item.resource_account == "original" for item in result.findings)
        assert paths == [_client.ROUTES["conditional-access"], _client.ROUTES["directory-roles"]]
        with pytest.raises(EntraM365InputError):
            collector.collect_v2(request)
    assert credentials.calls == ["primary"]


def test_budget_expiration_in_first_run_does_not_consume_second_run_budget() -> None:
    tick = [0.0]
    sent: list[str] = []

    def send(wire: httpx.Request) -> httpx.Response:
        sent.append(wire.url.path)
        if len(sent) == 1:
            tick[0] = 700.0
        return _lifecycle_response()

    credentials = LifecycleCredentials()
    request = EntraM365CollectRequest(tenant_label="fixture", capabilities=["conditional-access", "directory-roles"])
    with httpx.Client(transport=httpx.MockTransport(send)) as client:
        collector = _lifecycle_collector(credentials, client=client, tick=lambda: tick[0])
        first = collector.collect_v2(request)
        second = collector.collect_v2(request)
    assert first.status == "unavailable"
    assert first.findings == []
    assert all(
        {item.code for item in cap.diagnostics} == {"run_budget"}
        for cap in first.capabilities
        if cap.name in first.requested_capabilities
    )
    assert second.status == "complete" and len(second.findings) == 2
    assert sent == [
        _client.ROUTES["conditional-access"],
        _client.ROUTES["conditional-access"],
        _client.ROUTES["directory-roles"],
    ]
    assert credentials.calls == ["primary", "primary"]
    assert EntraM365CollectResult.model_validate_json(first.model_dump_json()) == first
    assert EntraM365CollectResult.model_validate_json(second.model_dump_json()) == second


def test_concurrent_runs_keep_identity_401_latches_and_findings_separate() -> None:
    class ThreadState(threading.local):
        label: str

    local = ThreadState()
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    calls: list[tuple[str, _client.CredentialGroup]] = []
    streams: list[LifecycleStream] = []

    class ThreadCredentials:
        def resolve(self, group: _client.CredentialGroup) -> _client._CredentialResolution:
            with lock:
                calls.append((local.label, group))
            return _client._CredentialResolution(
                "SYNTHETIC_" + local.label + "_TOKEN",
                "delegated" if group == "retention" else "application",
            )

    def send(wire: httpx.Request) -> httpx.Response:
        if wire.url.path == _client.ROUTES["conditional-access"]:
            barrier.wait(timeout=5)
            if local.label == "denied":
                return _lifecycle_response(status=401, streams=streams)
        return _lifecycle_response([{"id": local.label}], streams=streams)

    transport = LifecycleTransport(send)
    with httpx.Client(transport=transport) as client:
        collector = _lifecycle_collector(ThreadCredentials(), client=client, run_id=lambda: "synthetic-" + local.label)

        def collect(label: str) -> EntraM365CollectResult:
            local.label = label
            request = EntraM365CollectRequest(
                tenant_label=label, capabilities=["conditional-access", "directory-roles", "retention-labels"]
            )
            return collector.collect_v2(request)

        with ThreadPoolExecutor(max_workers=2) as pool:
            denied_future = pool.submit(collect, "denied")
            allowed_future = pool.submit(collect, "allowed")
            denied = denied_future.result(timeout=10)
            allowed = allowed_future.result(timeout=10)
        assert denied.status == "partial" and allowed.status == "complete"
        assert len(denied.findings) == 1 and len(allowed.findings) == 3
        assert [cap.state for cap in denied.capabilities if cap.name in denied.requested_capabilities] == [
            "unavailable",
            "unavailable",
            "complete",
        ]
        for label, result in (("denied", denied), ("allowed", allowed)):
            assert result.manifest.run_id == "synthetic-" + label
            assert result.provenance.tenant_label == label
            for item in result.findings:
                assert item.resource_account == label
                assert item.raw_data["source"] == {"id": label}
            assert EntraM365CollectResult.model_validate_json(result.model_dump_json()) == result
        assert Counter(calls) == Counter(
            {
                ("denied", "primary"): 1,
                ("allowed", "primary"): 1,
                ("denied", "retention"): 1,
                ("allowed", "retention"): 1,
            }
        )
        assert len(streams) == 5 and all(item.closed == 1 for item in streams)
        collector.close()
        assert not client.is_closed and transport.closed == 0
    assert transport.closed == 1


def test_findings_compatibility_is_exact_for_a_partial_collection() -> None:
    def send(wire: httpx.Request) -> httpx.Response:
        return (
            _lifecycle_response(status=403)
            if wire.url.path == _client.ROUTES["directory-roles"]
            else _lifecycle_response()
        )

    credentials = LifecycleCredentials()
    request = EntraM365CollectRequest(tenant_label="fixture", capabilities=["conditional-access", "directory-roles"])
    with httpx.Client(transport=httpx.MockTransport(send)) as client:
        collector = _lifecycle_collector(credentials, client=client)
        full = collector.collect_v2(request)
        findings = collector.collect(request)
    assert full.status == "partial" and not full.manifest.is_complete
    assert len(findings) == 1 and findings == full.findings
    assert full.findings[0].raw_data["source"] == {"id": "source"}


def test_every_fixture_has_verified_public_provenance() -> None:
    root = Path(__file__).resolve().parents[2] / "fixtures" / "entra_m365"
    manifest = json.loads((root / "provenance.json").read_text(encoding="utf-8"))
    rows = [*manifest["recorded_fixtures"], *manifest["synthetic_fixtures"]]
    named = {row["path"]: row for row in rows if "path" in row}
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*.json") if path.name != "provenance.json"}
    assert set(named) == actual
    assert manifest["live_tenant_acceptance"] == "unverified"
    for name, row in named.items():
        data = (root / name).read_bytes().replace(b"\r\n", b"\n")
        assert sha256(data).hexdigest() == row["sha256_lf"]
        if row["kind"] == "authored-synthetic":
            assert row["recorded_graph_responses"] is False
            assert row["tenant_access"] is False
