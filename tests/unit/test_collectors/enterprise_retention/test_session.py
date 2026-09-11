"""Synthetic session scheduling, clocks, counters and terminal publication."""

from __future__ import annotations

import gzip
import json
import socket
import ssl
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import httpx
import pytest
from evidentia_collectors.enterprise_retention import _client as session_client
from evidentia_collectors.enterprise_retention import _contracts as session_contracts
from evidentia_collectors.enterprise_retention import _credentials as session_credentials
from evidentia_collectors.enterprise_retention import _profiles as session_profiles
from evidentia_core import network_guard as session_guard


class SessionBody(httpx.SyncByteStream):
    def __init__(
        self,
        body: bytes,
        *,
        error: BaseException | None = None,
        close_error: Exception | None = None,
        before: Callable[[], None] | None = None,
    ) -> None:
        self.body = body
        self.error = error
        self.close_error = close_error
        self.before = before
        self.closes = 0

    def __iter__(self) -> Iterator[bytes]:
        if self.before is not None:
            self.before()
        yield self.body
        if self.error is not None:
            raise self.error

    def close(self) -> None:
        self.closes += 1
        if self.close_error is not None:
            raise self.close_error


class SessionWire:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, count: int = 2) -> None:
        self.clock = 0.0
        self.wall = 0.0
        self.sleeps: list[float] = []
        self.requests: list[httpx.Request] = []
        self.responses: list[httpx.Response] = []
        self.bodies: list[SessionBody] = []
        self.actions: list[dict[str, Any] | Exception] = []
        self.resolutions = 0
        self.dns = 0
        self.expiry: datetime | None = None
        self.address = "8.8.8.8"
        self.resolver_error: Exception | None = None
        self.request = session_contracts.validated_request(
            {
                "provider": "splunk-enterprise",
                "profile_alias": "selected",
                "scope_label": "synthetic",
                "targets": [{"index": f"events-{n}"} for n in range(count)],
            }
        )
        self.profile = session_profiles.FrozenProfile(
            alias="selected",
            provider="splunk-enterprise",
            origin="https://splunk.example.invalid:8089",
            credential_ref="ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
            address_policy=session_profiles.AddressPolicy("public"),
        )
        monkeypatch.setattr(socket, "getaddrinfo", self.resolve_dns)
        monkeypatch.setattr(session_guard, "_GETADDRINFO_DELEGATE", self.resolve_dns)
        monkeypatch.setattr(session_guard._pin_state, "hosts", {}, raising=False)
        monkeypatch.setattr(session_guard, "_offline_enabled", False)

    def resolve_dns(self, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        self.dns += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (self.address, args[1]))]

    def resolve(self, profile: session_profiles.FrozenProfile) -> session_credentials.CredentialMaterial:
        self.resolutions += 1
        if self.resolver_error is not None:
            raise self.resolver_error
        return session_credentials.CredentialMaterial(profile.provider, "synthetic-value", self.expiry)

    def utc(self) -> datetime:
        return datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=self.wall)

    def tick(self) -> float:
        return self.clock

    def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        self.clock += delay
        self.wall += delay

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        action = self.actions.pop(0) if self.actions else {}
        if isinstance(action, Exception):
            raise action
        default = {"entry": [{"name": request.url.path.rsplit("/", 1)[-1], "content": {"datatype": "event"}}]}
        body = action.get("body", json.dumps(default).encode())
        stream = SessionBody(
            body, error=action.get("error"), close_error=action.get("close_error"), before=action.get("before")
        )
        self.bodies.append(stream)
        response = httpx.Response(action.get("status", 200), headers=action.get("headers", []), stream=stream)
        self.responses.append(response)
        return response

    def factory(self, context: ssl.SSLContext) -> httpx.BaseTransport:
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        return httpx.MockTransport(self.handle)

    def session(self, **updates: Any) -> session_client.EnterpriseReadSession:
        return session_client.EnterpriseReadSession(
            self.request,
            profile=session_profiles.AuthorizedProfile(self.profile, self),
            transport_factory=self.factory,
            utc_clock=self.utc,
            monotonic_clock=self.tick,
            sleep=self.sleep,
            run_id_factory=lambda: "01K00000000000000000000000",
            **updates,
        )


def project_session_index(
    response: session_client.ParsedResponse, subject: session_client.ReadSubject
) -> session_client.ProjectedPage:
    entries = response.data["entry"]
    assert isinstance(entries, list)
    source = entries[0]
    assert isinstance(source, dict)
    expected = session_contracts.expected_fields(subject.kind, source)
    return session_client.ProjectedPage(
        (
            session_client.ProjectedRecord(
                0,
                subject.source_id,
                "index",
                expected.fields,
                expected.coverage,
                expected.diagnostics,
            ),
        )
    )


def complete_session(
    wire: SessionWire, session: session_client.EnterpriseReadSession | None = None
) -> session_contracts.EnterpriseRetentionCollectResult:
    selected = session or wire.session()
    resources = []
    for target in wire.request.root.targets:
        assert isinstance(target, session_contracts.SplunkIndexTarget)
        handle = selected.read_splunk_index(target, project_session_index)
        resources.append(selected.finish_resource(target, reads=(handle,)))
    return selected.finish(tuple(resources))


def test_session_constructor_has_no_destination_or_credential_effect(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = SessionWire(monkeypatch)
    selected = wire.session()
    assert wire.dns == wire.resolutions == len(wire.requests) == 0
    detached = selected.context.request
    detached.root.targets.clear()
    assert len(selected.context.request.root.targets) == 2


def test_session_selected_success_has_detached_result_and_one_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = SessionWire(monkeypatch)
    result = complete_session(wire)
    assert result.root.status == "complete"
    assert wire.resolutions == 1 and wire.dns == 2 and len(wire.requests) == 2
    assert all(read.attempts == read.pages_admitted == read.records_admitted == 1 for read in result.root.source_reads)
    assert all(body.closes == 1 for body in wire.bodies)
    assert len(result.root.findings) == 2
    assert (
        session_contracts.EnterpriseRetentionCollectResult.model_validate_json(
            result.publication_bytes()
        ).publication_bytes()
        == result.publication_bytes()
    )


@pytest.mark.parametrize(
    "status,code",
    [
        (401, "credential_rejected"),
        (403, "http_denied"),
        (404, "http_not_found"),
        (204, "http_error"),
        (206, "http_error"),
        (302, "redirect_refused"),
    ],
)
def test_session_status_refusal_and_profile_latch(monkeypatch: pytest.MonkeyPatch, status: int, code: str) -> None:
    wire = SessionWire(monkeypatch)
    wire.actions = [{"status": status, "headers": [("Location", "synthetic-invalid-location")]}]
    result = complete_session(wire)
    first, second = result.root.source_reads
    assert first.status == "unavailable" and first.terminal_reason == code
    assert first.responses_received == 1 and first.safe_http_status == status
    assert len(wire.requests) == (1 if status == 401 else 2)
    assert second.attempts == (0 if status == 401 else 1)
    assert len(result.root.resources) == 2


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
def test_session_only_retry_statuses_recover_with_honest_counts(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    wire = SessionWire(monkeypatch, count=1)
    wire.actions = [{"status": status, "body": b"unparsed retry body"}]
    result = complete_session(wire)
    read = result.root.source_reads[0]
    assert read.status == "complete" and read.attempts == read.responses_received == 2
    assert read.pages_received == read.pages_admitted == 1 and read.safe_http_status is None
    assert read.raw_bytes == sum(len(body.body) for body in wire.bodies)
    assert wire.sleeps == [1.0] and wire.resolutions == 1 and wire.dns == 2


def test_session_three_attempt_limit_preserves_final_response(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = SessionWire(monkeypatch, count=1)
    wire.actions = [{"status": 503}] * 3
    read = complete_session(wire).root.source_reads[0]
    assert read.attempts == read.responses_received == 3
    assert read.safe_http_status == 503 and read.terminal_reason == "http_error"
    assert read.pages_received == 0 and wire.sleeps == [1.0, 2.0]


@pytest.mark.parametrize(
    "error_type,retry",
    [
        (httpx.ConnectTimeout, True),
        (httpx.ReadTimeout, True),
        (httpx.ConnectError, True),
        (httpx.ReadError, True),
        (httpx.PoolTimeout, False),
        (httpx.WriteTimeout, False),
        (httpx.WriteError, False),
        (httpx.RemoteProtocolError, False),
    ],
)
def test_session_exact_transport_exception_retry_set(
    monkeypatch: pytest.MonkeyPatch, error_type: type[httpx.TransportError], retry: bool
) -> None:
    wire = SessionWire(monkeypatch, count=1)
    wire.actions = [error_type("synthetic transport failure")]
    read = complete_session(wire).root.source_reads[0]
    assert read.attempts == (2 if retry else 1)
    assert read.status == ("complete" if retry else "unavailable")
    assert wire.sleeps == ([1.0] if retry else [])


@pytest.mark.parametrize(
    "header,code", [("11", "retry_after_invalid"), ("invalid", "retry_after_invalid"), ("1000", "retry_after_invalid")]
)
def test_session_invalid_retry_after_does_not_retry_early(
    monkeypatch: pytest.MonkeyPatch, header: str, code: str
) -> None:
    wire = SessionWire(monkeypatch, count=1)
    wire.actions = [{"status": 429, "headers": [("Retry-After", header)]}]
    read = complete_session(wire).root.source_reads[0]
    assert read.terminal_reason == code and read.attempts == 1 and wire.sleeps == []


@pytest.mark.parametrize(
    "fault,code", [("json", "invalid_json"), ("encoding", "invalid_encoding"), ("identity", "identity_mismatch")]
)
def test_session_admission_faults_are_not_retried(monkeypatch: pytest.MonkeyPatch, fault: str, code: str) -> None:
    wire = SessionWire(monkeypatch, count=1)
    if fault == "json":
        wire.actions = [{"body": b'{"duplicate":1,"duplicate":2}'}]
    elif fault == "encoding":
        wire.actions = [{"headers": [("Content-Encoding", "br")]}]
    else:
        wire.actions = [{"body": b'{"entry":[{"name":"other","content":{}}]}'}]
    read = complete_session(wire).root.source_reads[0]
    assert read.terminal_reason == code and read.attempts == 1 and wire.sleeps == []
    assert read.records_admitted == 0


def test_session_destination_refusal_precedes_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = SessionWire(monkeypatch, count=1)
    wire.address = "127.0.0.1"
    result = complete_session(wire)
    assert result.root.source_reads[0].terminal_reason == "destination_refused"
    assert wire.resolutions == 0 and wire.requests == []


def test_session_offline_refusal_precedes_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = SessionWire(monkeypatch, count=1)
    with session_guard.offline_mode():
        result = complete_session(wire)
    assert result.root.source_reads[0].terminal_reason == "offline_refused"
    assert wire.dns == wire.resolutions == 0 and wire.requests == []


@pytest.mark.parametrize(
    "error,code",
    [
        (session_credentials.CredentialError("credential_missing"), "credential_missing"),
        (ValueError("synthetic"), "credential_resolution_failed"),
    ],
)
def test_session_credential_failure_latches_remaining_work(
    monkeypatch: pytest.MonkeyPatch, error: Exception, code: str
) -> None:
    wire = SessionWire(monkeypatch)
    wire.resolver_error = error
    result = complete_session(wire)
    assert result.root.diagnostics[0].code == code
    assert result.root.source_reads[1].attempts == 0
    assert wire.resolutions == wire.dns == 1 and wire.requests == []


def test_session_known_expiry_after_request_construction_refuses_send(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = SessionWire(monkeypatch, count=1)
    wire.expiry = wire.utc() + timedelta(seconds=1)
    original = httpx.Request

    def slow_request(*args: Any, **kwargs: Any) -> httpx.Request:
        value = original(*args, **kwargs)
        wire.wall = 2.0
        return value

    monkeypatch.setattr(httpx, "Request", slow_request)
    result = complete_session(wire)
    assert result.root.diagnostics[0].code == "credential_expired"
    assert wire.requests == [] and wire.resolutions == 1


def test_session_final_send_timeout_uses_fresh_remaining_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = SessionWire(monkeypatch, count=1)
    original = httpx.Request

    def slow_request(*args: Any, **kwargs: Any) -> httpx.Request:
        value = original(*args, **kwargs)
        wire.clock = 119.0
        return value

    monkeypatch.setattr(httpx, "Request", slow_request)
    assert complete_session(wire).root.status == "complete"
    assert wire.requests[0].extensions["timeout"] == {"connect": 1.0, "pool": 1.0, "read": 1.0, "write": 1.0}


def test_session_deadline_before_work_keeps_every_unattempted_target(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = SessionWire(monkeypatch)
    selected = wire.session()
    wire.clock = 120.0
    result = complete_session(wire, selected)
    assert result.root.status == "unavailable" and len(result.root.resources) == 2
    assert all(read.attempts == 0 for read in result.root.source_reads)
    assert wire.requests == [] and result.root.diagnostics[0].code == "deadline_exceeded"


def test_session_delivered_chunk_is_counted_before_deadline_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = SessionWire(monkeypatch, count=1)
    wire.actions = [{"before": lambda: setattr(wire, "clock", 120.0)}]
    result = complete_session(wire)
    read = result.root.source_reads[0]
    assert read.raw_bytes == read.decoded_bytes == len(wire.bodies[0].body)
    assert read.pages_received == 0 and read.terminal_reason == "deadline_exceeded"
    assert wire.bodies[0].closes == 1


def test_session_read_failure_counts_retry_bytes_without_admitting_failed_page(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = SessionWire(monkeypatch, count=1)
    wire.actions = [{"body": b"partial", "error": httpx.ReadTimeout("synthetic timeout")}]
    read = complete_session(wire).root.source_reads[0]
    assert read.status == "complete" and read.attempts == 2 and read.pages_received == read.pages_admitted == 1
    assert read.raw_bytes == sum(len(body.body) for body in wire.bodies)
    assert all(body.closes == 1 for body in wire.bodies)


def test_session_eof_cleanup_failure_keeps_valid_current_page_and_stops_later_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wire = SessionWire(monkeypatch)
    wire.actions = [{"close_error": RuntimeError("synthetic cleanup detail")}]
    result = complete_session(wire)
    assert result.root.status == "partial" and len(result.root.findings) == 1
    assert result.root.diagnostics[0].code == "cleanup_failed"
    assert result.root.source_reads[0].pages_admitted == 1 and result.root.source_reads[1].attempts == 0
    assert len(wire.requests) == 1


def test_session_unexpected_transport_error_is_fixed_operational_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = SessionWire(monkeypatch, count=1)
    wire.actions = [RuntimeError("synthetic hidden operational detail")]
    with pytest.raises(
        session_client.EnterpriseRetentionOperationalError, match=r"^enterprise_retention_internal_error$"
    ):
        complete_session(wire)


def test_session_capacity_refusal_keeps_prior_evidence_and_all_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = SessionWire(monkeypatch)
    selected = wire.session()
    target = cast(session_contracts.SplunkIndexTarget, wire.request.root.targets[0])
    first = selected.read_splunk_index(target, project_session_index)
    resource = selected.finish_resource(target, reads=(first,))
    state = selected._models()
    bound = selected.context.capacity.admission_bound(state)
    selected.context.capacity = session_contracts.CapacityPlan(wire.request, _result_byte_limit=bound)
    target2 = cast(session_contracts.SplunkIndexTarget, wire.request.root.targets[1])
    second = selected.read_splunk_index(target2, project_session_index)
    resource2 = selected.finish_resource(target2, reads=(second,))
    result = selected.finish((resource, resource2))
    assert result.root.status == "partial" and result.root.diagnostics[0].code == "result_limit"
    assert (
        result.root.source_reads[0].observations[0].canonical_projection_sha256
        == state[0].observations[0].canonical_projection_sha256
    )
    assert result.root.source_reads[1].pages_received == 1 and result.root.source_reads[1].pages_admitted == 0


@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), "0", None])
def test_session_invalid_native_monotonic_clock_refuses_constructor(
    monkeypatch: pytest.MonkeyPatch, value: Any
) -> None:
    wire = SessionWire(monkeypatch)
    with pytest.raises(session_client.EnterpriseRetentionOperationalError):
        session_client.EnterpriseRunContext(wire.request, monotonic_clock=lambda: value)
    assert wire.dns == wire.resolutions == 0


@pytest.mark.parametrize("encoding", ["identity", "gzip"])
def test_session_run_bytes_include_failed_attempts_and_refused_chunk(
    monkeypatch: pytest.MonkeyPatch, encoding: str
) -> None:
    wire = SessionWire(monkeypatch, count=20)
    payload = b"x" * 1_048_576
    encoded = gzip.compress(payload, mtime=0) if encoding == "gzip" else payload
    for _ in range(20):
        wire.actions.extend(
            [
                {"status": 503, "body": encoded, "headers": [("Content-Encoding", encoding)]},
                {"status": 503, "body": encoded, "headers": [("Content-Encoding", encoding)]},
                {},
            ]
        )
    result = complete_session(wire)
    reads = result.root.source_reads
    assert result.root.status == "partial" and len(result.root.resources) == 20
    assert result.root.diagnostics[0].code == "run_byte_limit"
    assert sum(read.records_admitted for read in reads) == 7
    assert sum(read.raw_bytes for read in reads) == sum(len(body.body) for body in wire.bodies)
    assert sum(read.decoded_bytes for read in reads) > 16_777_216
    if encoding == "gzip":
        assert sum(read.raw_bytes for read in reads) < 16_777_216
    else:
        assert sum(read.raw_bytes for read in reads) == sum(read.decoded_bytes for read in reads)
    assert len(wire.requests) == 23 and wire.resolutions == 1
    assert all(read.attempts == 0 for read in reads[8:])
    assert all(body.closes == 1 for body in wire.bodies)


def project_session_vault(
    response: session_client.ParsedResponse, subject: session_client.ReadSubject
) -> session_client.ProjectedPage:
    sources: list[dict[str, Any]] = (
        [response.data]
        if subject.kind == "vault-matter"
        else cast(list[dict[str, Any]], response.data.get("holds", []))
    )
    records = []
    for ordinal, source in enumerate(sources):
        expected = session_contracts.expected_fields(subject.kind, source)
        identity = source["matterId"] if subject.kind == "vault-matter" else source["holdId"]
        records.append(
            session_client.ProjectedRecord(
                ordinal,
                identity,
                "matter" if subject.kind == "vault-matter" else "hold",
                expected.fields,
                expected.coverage,
                expected.diagnostics,
            )
        )
    return session_client.ProjectedPage(tuple(records))


def test_session_global_attempt_limit_stops_at_one_hundred_real_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = SessionWire(monkeypatch, count=1)
    wire.request = session_contracts.validated_request(
        {
            "provider": "google-vault",
            "profile_alias": "selected",
            "scope_label": "synthetic",
            "targets": [{"matter_id": f"matter-{n}"} for n in range(20)],
        }
    )
    wire.profile = session_profiles.FrozenProfile(
        alias="selected",
        provider="google-vault",
        origin="https://vault.googleapis.com:443",
        credential_ref="ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
        address_policy=session_profiles.AddressPolicy("public"),
    )
    for n in range(20):
        for body in [{"matterId": f"matter-{n}", "state": "OPEN"}, {"holds": []}]:
            wire.actions.extend([{"status": 503}, {"status": 503}, {"body": json.dumps(body).encode()}])
    selected = wire.session()
    resources = []
    for target in wire.request.root.targets:
        assert isinstance(target, session_contracts.VaultMatterTarget)
        matter = selected.read_vault_matter(target, project_session_vault)
        holds = selected.read_vault_holds(target, project_session_vault)
        resources.append(selected.finish_resource(target, reads=(matter, holds)))
    result = selected.finish(tuple(resources))
    assert len(wire.requests) == wire.dns == 100 and wire.resolutions == 1
    assert sum(read.attempts for read in result.root.source_reads) == 100
    assert result.root.diagnostics[0].code == "attempt_limit" and result.root.status == "partial"
    assert len(result.root.resources) == 20 and len(result.root.findings) == 17
    assert result.root.source_reads[33].attempts == 1
    assert all(read.attempts == 0 for read in result.root.source_reads[34:])


def test_session_oversized_observation_is_local_projection_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = SessionWire(monkeypatch)
    wire.actions = [
        {"body": json.dumps({"entry": [{"name": "events-0", "content": {"datatype": "x" * 65536}}]}).encode()}
    ]
    result = complete_session(wire)
    first, second = result.root.source_reads
    assert first.pages_received == 1 and first.pages_admitted == 0
    assert first.terminal_reason == "projection_limit" and second.status == "complete"
    assert result.root.status == "partial" and len(wire.requests) == 2


@pytest.mark.parametrize("elapsed,code", [(120.0, "deadline_exceeded"), (119.0, None)])
def test_session_final_utc_work_is_included_in_deadline_and_timeouts(
    monkeypatch: pytest.MonkeyPatch, elapsed: float, code: str | None
) -> None:
    wire = SessionWire(monkeypatch, count=1)
    constructed = False
    original_request = httpx.Request

    def build(*args: Any, **kwargs: Any) -> httpx.Request:
        nonlocal constructed
        result = original_request(*args, **kwargs)
        constructed = True
        return result

    def utc() -> datetime:
        if constructed:
            wire.clock = elapsed
        return wire.utc()

    monkeypatch.setattr(httpx, "Request", build)
    selected = session_client.EnterpriseReadSession(
        wire.request,
        profile=session_profiles.AuthorizedProfile(wire.profile, wire),
        transport_factory=wire.factory,
        utc_clock=utc,
        monotonic_clock=wire.tick,
        sleep=wire.sleep,
        run_id_factory=lambda: "01K00000000000000000000000",
    )
    result = complete_session(wire, selected)
    if code is not None:
        assert result.root.diagnostics[0].code == code and wire.requests == []
    else:
        assert result.root.status == "complete"
        assert wire.requests[0].extensions["timeout"] == {"connect": 1.0, "pool": 1.0, "read": 1.0, "write": 1.0}


@pytest.mark.parametrize(
    "source,primary", [("timeout", "timeout"), ("read_error", "transport_failed"), ("http", "http_error")]
)
def test_session_cleanup_stops_retry_without_losing_prior_failure(
    monkeypatch: pytest.MonkeyPatch, source: str, primary: str
) -> None:
    wire = SessionWire(monkeypatch)
    action: dict[str, Any] = {"close_error": RuntimeError("synthetic close detail")}
    if source == "http":
        action["status"] = 503
    else:
        action["error"] = (
            httpx.ReadTimeout("synthetic timeout") if source == "timeout" else httpx.ReadError("synthetic read failure")
        )
    wire.actions = [action]
    result = complete_session(wire)
    assert result.root.diagnostics[0].code == "cleanup_failed"
    first, second = result.root.source_reads
    assert first.terminal_reason == primary and first.diagnostics[0].code == primary
    assert len(wire.requests) == 1 and wire.sleeps == [] and second.attempts == 0
    assert first.raw_bytes == len(wire.bodies[0].body) and first.pages_admitted == 0


def test_session_cancellation_survives_failing_final_clock_and_closes_scopes(monkeypatch: pytest.MonkeyPatch) -> None:
    class Cancelled(BaseException):
        pass

    cancellation = Cancelled()
    wire = SessionWire(monkeypatch)
    fail_clock = False

    def arm_clock() -> None:
        nonlocal fail_clock
        fail_clock = True

    def utc() -> datetime:
        if fail_clock:
            raise RuntimeError("synthetic clock failure")
        return wire.utc()

    wire.actions = [{"before": arm_clock, "error": cancellation}]
    selected = session_client.EnterpriseReadSession(
        wire.request,
        profile=session_profiles.AuthorizedProfile(wire.profile, wire),
        transport_factory=wire.factory,
        utc_clock=utc,
        monotonic_clock=wire.tick,
        sleep=wire.sleep,
        run_id_factory=lambda: "01K00000000000000000000000",
    )
    target = cast(session_contracts.SplunkIndexTarget, wire.request.root.targets[0])
    with pytest.raises(Cancelled) as caught:
        selected.read_splunk_index(target, project_session_index)
    assert caught.value is cancellation
    assert wire.bodies[0].closes == 1 and session_guard._pin_state.hosts == {}
    with pytest.raises(session_client.EnterpriseRetentionOperationalError):
        selected.read_splunk_index(target, project_session_index)
    assert len(wire.requests) == 1
