"""Synthetic Defender source-to-finding contract tests without external IO."""

from __future__ import annotations

import copy
import json
import socket
from collections import deque
from collections.abc import Iterator
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

import httpx
import pytest
from evidentia_collectors.entra_m365 import defender
from evidentia_collectors.entra_m365._client import (
    CredentialGroup,
    EntraM365GraphReader,
    _CredentialResolution,
)
from evidentia_collectors.entra_m365._contracts import (
    EntraM365CapabilityRead,
    EntraM365CollectRequest,
    EntraM365CollectResult,
    EntraM365RunContext,
    JsonObject,
    JsonValue,
)
from evidentia_core import network_guard
from evidentia_core.models.common import Severity, deterministic_finding_id
from evidentia_core.models.finding import ComplianceStatus, FindingStatus, SecurityFinding

type DefenderCapability = Literal["defender-alerts", "defender-incidents"]

CAPABILITIES: tuple[DefenderCapability, ...] = ("defender-alerts", "defender-incidents")
PATHS = {
    "defender-alerts": "/v1.0/security/alerts_v2",
    "defender-incidents": "/v1.0/security/incidents",
}
ORIGIN = "https://graph.microsoft.com"
NOW = datetime(2026, 9, 10, 0, 0, 0, 123456, tzinfo=UTC)
START = "2026-09-09T00:00:00.123456Z"
END = "2026-09-10T00:00:00.123456Z"
TOKEN = "SYNTHETIC_DEFENDER_TEST_TOKEN"
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "entra_m365" / "defender"
ALERT_FIELDS = {
    "id",
    "incidentId",
    "severity",
    "status",
    "createdDateTime",
    "lastUpdateDateTime",
    "resolvedDateTime",
    "serviceSource",
    "detectionSource",
}
INCIDENT_FIELDS = {"id", "severity", "status", "createdDateTime", "lastUpdateDateTime"}


@dataclass
class Reply:
    body: JsonObject | bytes
    status: int = 200
    headers: dict[str, str] = field(default_factory=lambda: {"content-type": "application/json"})


class Stream(httpx.SyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.closed = 0

    def __iter__(self) -> Iterator[bytes]:
        yield self.body

    def close(self) -> None:
        self.closed += 1


class Provider:
    def __init__(self) -> None:
        self.groups: list[CredentialGroup] = []

    def resolve(self, group: CredentialGroup) -> _CredentialResolution:
        self.groups.append(group)
        return _CredentialResolution(token=TOKEN, declared_auth_mode="application")


@dataclass
class Outcome:
    read: EntraM365CapabilityRead
    result: EntraM365CollectResult
    requests: list[httpx.Request]
    groups: list[CredentialGroup]


def refuse_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("Synthetic Defender tests cannot use DNS or sockets")


def collect(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
    replies: list[Reply],
    *,
    max_items: int = 100,
    max_pages: int = 10,
    run_id: str = "synthetic-defender-run",
) -> Outcome:
    monkeypatch.setattr(socket, "getaddrinfo", refuse_network)
    monkeypatch.setattr(socket.socket, "connect", refuse_network)
    monkeypatch.setattr(socket, "create_connection", refuse_network)
    monkeypatch.setattr(network_guard, "check_url", lambda *args, **kwargs: None)
    monkeypatch.setattr(network_guard, "enforce_public_host", lambda *args, **kwargs: ["93.184.216.34"])
    monkeypatch.setattr(network_guard, "pin_resolved_host", lambda *args, **kwargs: nullcontext())
    request = EntraM365CollectRequest(
        tenant_label="synthetic-defender",
        capabilities=[capability],
        lookback_days=1,
        max_items=max_items,
        max_pages=max_pages,
    )
    context = EntraM365RunContext.start(
        request,
        utc_clock=lambda: NOW,
        monotonic_clock=lambda: 0.0,
        sleep=lambda seconds: None,
        run_id_factory=lambda: run_id,
    )
    pending = deque(replies)
    requests: list[httpx.Request] = []
    streams: list[Stream] = []

    def handle(message: httpx.Request) -> httpx.Response:
        requests.append(message)
        assert pending, "Unexpected extra source request"
        reply = pending.popleft()
        body = reply.body if isinstance(reply.body, bytes) else json.dumps(reply.body).encode("utf-8")
        stream = Stream(body)
        streams.append(stream)
        return httpx.Response(reply.status, headers=reply.headers, stream=stream)

    provider = Provider()
    with httpx.Client(transport=httpx.MockTransport(handle), trust_env=False) as client:
        reader = EntraM365GraphReader(credentials=provider, client=client)
        try:
            function = (
                defender.read_defender_alerts if capability == "defender-alerts" else defender.read_defender_incidents
            )
            read = function(request, reader, context, None)
            result = context.build_result([read])
            assert not client.is_closed
        finally:
            reader.close()
        assert not client.is_closed
    assert all(stream.closed == 1 for stream in streams)
    for message in requests:
        assert message.method == "GET"
        assert message.url.scheme == "https"
        assert message.url.host == "graph.microsoft.com"
        assert message.url.path == PATHS[capability]
        assert message.headers["authorization"] == "Bearer " + TOKEN
        assert message.headers["accept"] == "application/json"
        assert message.headers.get("prefer") is None
    if requests:
        assert requests[0].url.query == b""
    assert all(group == "primary" for group in provider.groups)
    wire = result.model_dump_json()
    assert TOKEN not in wire
    assert "SYNTHETIC_EXCLUDED" not in wire
    round_trip = EntraM365CollectResult.model_validate_json(wire)
    assert round_trip.model_dump(mode="json") == result.model_dump(mode="json")
    return Outcome(read, result, requests, provider.groups)


def row(identifier: str, **fields: JsonValue) -> JsonObject:
    return {"id": identifier, "createdDateTime": END, **fields}


def page(*records: JsonObject, next_link: str | None = None) -> Reply:
    data: JsonObject = {"value": list(records)}
    if next_link is not None:
        data["@odata.nextLink"] = next_link
    return Reply(data)


def next_link(capability: DefenderCapability) -> str:
    return ORIGIN + PATHS[capability] + "?$skiptoken=SYNTHETIC_NEXT"


def diagnostics(outcome: Outcome) -> dict[str, int]:
    return {item.code: item.count for item in outcome.read.capability.diagnostics}


def data(finding: SecurityFinding, key: Literal["source", "observation"]) -> JsonObject:
    assert finding.raw_data is not None
    value: object = finding.raw_data[key]
    assert isinstance(value, dict)
    return cast(JsonObject, value)


def load_fixture(name: str) -> JsonObject:
    value: object = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return cast(JsonObject, value)


@pytest.mark.parametrize(
    "capability,name", [("defender-alerts", "alerts.json"), ("defender-incidents", "incidents.json")]
)
def test_authored_fixtures_preserve_source_projection_and_routes(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
    name: str,
) -> None:
    fixture = load_fixture(name)
    assert fixture["kind"] == "authored-synthetic"
    exchange_values = fixture["requests"]
    assert isinstance(exchange_values, list)
    exchanges: list[JsonObject] = []
    source_rows: list[JsonObject] = []
    replies = []
    for sequence, value in enumerate(exchange_values, 1):
        assert isinstance(value, dict)
        exchanges.append(value)
        assert value["pagination_sequence"] == sequence
        assert value["method"] == "GET"
        assert value["route"] == PATHS[capability]
        assert value["headers"] == {"content-type": "application/json"}
        body = value["body"]
        assert isinstance(body, dict)
        rows = body["value"]
        assert isinstance(rows, list)
        for source in rows:
            assert isinstance(source, dict)
            source_rows.append(source)
        replies.append(Reply(body))
    outcome = collect(monkeypatch, capability, replies)
    assert outcome.read.capability.state == "complete"
    assert outcome.read.capability.pages_completed == 2
    assert outcome.read.capability.scanned == outcome.read.capability.collected == 2
    selected = ALERT_FIELDS if capability == "defender-alerts" else INCIDENT_FIELDS
    expected = [{key: value for key, value in source.items() if key in selected} for source in source_rows]
    actual = [data(finding, "source") for finding in outcome.read.findings]
    assert actual == expected
    for source, found in zip(expected, actual, strict=True):
        assert isinstance(found, dict)
        assert {key: type(value) for key, value in found.items()} == {key: type(value) for key, value in source.items()}
    assert [message.url.query.decode("ascii") for message in outcome.requests] == [item["query"] for item in exchanges]
    assert outcome.read.capability.observed_last == "2026-09-10T00:00:00.123456000000Z"
    first, second = outcome.read.findings
    if capability == "defender-alerts":
        assert first.severity is Severity.HIGH and first.status is FindingStatus.RESOLVED
        assert first.resolved_at == datetime(2026, 9, 9, 23, 30, 0, 765432, tzinfo=UTC)
        assert data(first, "observation") == {
            "severity": "high",
            "status": "resolved",
            "last_update_age_seconds": "3600",
        }
        assert second.severity is Severity.INFORMATIONAL and second.status is FindingStatus.ACTIVE
        assert outcome.read.capability.field_coverage["severity"].unknown == 1
    else:
        assert first.severity is Severity.MEDIUM and first.status is FindingStatus.ACTIVE
        assert data(first, "observation")["last_update_age_seconds"] == "1.0000001"
        assert second.severity is Severity.LOW and second.status is FindingStatus.RESOLVED
        assert data(second, "observation")["last_update_age_seconds"] is None
        assert all(finding.resolved_at is None for finding in outcome.read.findings)
        assert diagnostics(outcome)["future_timestamp"] == 1


@pytest.mark.parametrize("capability", CAPABILITIES)
@pytest.mark.parametrize(
    "source_severity,expected",
    [
        ("informational", Severity.INFORMATIONAL),
        ("low", Severity.LOW),
        ("medium", Severity.MEDIUM),
        ("high", Severity.HIGH),
        ("critical", Severity.INFORMATIONAL),
        ("unknown", Severity.INFORMATIONAL),
        ("unknownFutureValue", Severity.INFORMATIONAL),
        ("HIGH", Severity.INFORMATIONAL),
        (" high ", Severity.INFORMATIONAL),
        ("futureSeverity", Severity.INFORMATIONAL),
        (None, Severity.INFORMATIONAL),
    ],
)
def test_severity_is_literal_source_state(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
    source_severity: str | None,
    expected: Severity,
) -> None:
    outcome = collect(monkeypatch, capability, [page(row("severity", severity=source_severity))])
    finding = outcome.read.findings[0]
    assert finding.severity is expected
    assert data(finding, "source")["severity"] == source_severity
    assert finding.compliance_status is ComplianceStatus.UNKNOWN
    assert outcome.read.capability.state == "complete"


@pytest.mark.parametrize("capability", CAPABILITIES)
@pytest.mark.parametrize(
    "source_status",
    [
        "resolved",
        "new",
        "active",
        "inProgress",
        "redirected",
        "awaitingAction",
        "unknown",
        "unknownFutureValue",
        "RESOLVED",
        " resolved ",
        "futureStatus",
        None,
    ],
)
def test_only_exact_resolved_status_is_resolved(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
    source_status: str | None,
) -> None:
    outcome = collect(monkeypatch, capability, [page(row("status", status=source_status))])
    finding = outcome.read.findings[0]
    expected = FindingStatus.RESOLVED if source_status == "resolved" else FindingStatus.ACTIVE
    assert finding.status is expected
    assert finding.resolved_at is None
    assert data(finding, "source")["status"] == source_status
    assert data(finding, "observation")["status"] == expected.value
    assert outcome.read.capability.state == "complete"


@pytest.mark.parametrize("capability", CAPABILITIES)
def test_absent_null_and_unknown_fields_remain_distinct(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
) -> None:
    rows = [
        row("absent"),
        row("null", severity=None, status=None),
        row("unknown", severity="unknownFutureValue", status="futureStatus"),
    ]
    outcome = collect(monkeypatch, capability, [page(*rows)])
    assert [data(finding, "source") for finding in outcome.read.findings] == rows
    for key in ("severity", "status"):
        assert outcome.read.capability.field_coverage[key].model_dump() == {
            "absent": 1,
            "null": 1,
            "known": 0,
            "unknown": 1,
        }
    assert all(
        finding.severity is Severity.INFORMATIONAL and finding.status is FindingStatus.ACTIVE
        for finding in outcome.read.findings
    )
    assert outcome.read.capability.state == "complete"


@pytest.mark.parametrize(
    "literal,expected",
    [
        ("2026-09-09T01:00:00Z", datetime(2026, 9, 9, 1, tzinfo=UTC)),
        ("2026-09-09t02:00:00.123456+01:00", datetime(2026, 9, 9, 1, 0, 0, 123456, tzinfo=UTC)),
        ("2026-09-09T01:00:00.123456000000000000z", datetime(2026, 9, 9, 1, 0, 0, 123456, tzinfo=UTC)),
        ("2026-09-09T01:00:00.0000000-00:00", datetime(2026, 9, 9, 1, tzinfo=UTC)),
        ("2026-09-09T01:00:00.1234561Z", None),
        ("2026-09-09T01:00:00.123456000001Z", None),
    ],
)
def test_alert_resolution_projects_only_exact_microseconds(
    monkeypatch: pytest.MonkeyPatch,
    literal: str,
    expected: datetime | None,
) -> None:
    outcome = collect(
        monkeypatch, "defender-alerts", [page(row("resolved", status="resolved", resolvedDateTime=literal))]
    )
    finding = outcome.read.findings[0]
    assert finding.status is FindingStatus.RESOLVED
    assert finding.resolved_at == expected
    assert data(finding, "source")["resolvedDateTime"] == literal
    assert outcome.read.capability.state == "complete"
    assert diagnostics(outcome).get("timestamp_precision_unrepresentable", 0) == (1 if expected is None else 0)
    assert outcome.result.manifest.is_complete
    assert outcome.result.manifest.errors == []


def test_unrepresentable_resolution_warnings_are_aggregated(monkeypatch: pytest.MonkeyPatch) -> None:
    outcome = collect(
        monkeypatch,
        "defender-alerts",
        [
            page(
                *[
                    row(str(index), status="resolved", resolvedDateTime="2026-09-09T01:00:00.0000001Z")
                    for index in range(3)
                ]
            )
        ],
    )
    assert diagnostics(outcome)["timestamp_precision_unrepresentable"] == 3
    assert outcome.read.capability.collected == 3
    assert outcome.read.capability.state == "complete"


def test_precision_warning_uses_only_final_in_window_alerts(monkeypatch: pytest.MonkeyPatch) -> None:
    precise: JsonObject = {"status": "resolved", "resolvedDateTime": "2026-09-09T01:00:00.0000001Z"}
    contested = row("contested", **precise)
    duplicate = row("duplicate", **precise)
    outcome = collect(
        monkeypatch,
        "defender-alerts",
        [
            page(
                row("older", **(precise | {"createdDateTime": "2026-09-08T00:00:00Z"})),
                row("future", **(precise | {"createdDateTime": "2026-09-10T00:00:00.1234561Z"})),
                contested,
                duplicate,
                next_link=next_link("defender-alerts"),
            ),
            page(contested | {"severity": "high"}, duplicate),
        ],
    )
    assert [finding.resource_id for finding in outcome.read.findings] == ["duplicate"]
    assert diagnostics(outcome)["timestamp_precision_unrepresentable"] == 1
    assert diagnostics(outcome)["conflicting_duplicate"] == 1
    assert outcome.read.capability.duplicate_records == 1
    assert outcome.read.capability.state == "partial"


@pytest.mark.parametrize("trailing", ["0", "1"])
def test_maximum_source_resolution_precision_is_retained(monkeypatch: pytest.MonkeyPatch, trailing: str) -> None:
    literal = "2026-09-09T01:00:00." + "0" * 2026 + trailing + "Z"
    assert len(literal) == 2048
    outcome = collect(monkeypatch, "defender-alerts", [page(row("long", status="resolved", resolvedDateTime=literal))])
    finding = outcome.read.findings[0]
    assert data(finding, "source")["resolvedDateTime"] == literal
    assert finding.resolved_at == (datetime(2026, 9, 9, 1, tzinfo=UTC) if trailing == "0" else None)
    assert diagnostics(outcome).get("timestamp_precision_unrepresentable", 0) == int(trailing)
    assert outcome.read.capability.state == "complete"


@pytest.mark.parametrize("literal", [False, 1, "2026-09-09T00:00:60Z", "2026-09-09T00:00:00", " 2026-09-09T00:00:00Z"])
def test_invalid_alert_resolution_rejects_its_whole_page(monkeypatch: pytest.MonkeyPatch, literal: JsonValue) -> None:
    outcome = collect(
        monkeypatch,
        "defender-alerts",
        [
            page(
                row("valid", status="resolved", resolvedDateTime=END),
                row("invalid", status="resolved", resolvedDateTime=literal),
            )
        ],
    )
    assert outcome.read.findings == ()
    assert outcome.read.capability.state == "unavailable"
    assert outcome.read.capability.scanned == 0
    assert diagnostics(outcome) == {"invalid_record": 1}


@pytest.mark.parametrize("capability", CAPABILITIES)
@pytest.mark.parametrize(
    "literal,age",
    [
        (None, None),
        ("2026-09-10T00:00:00.123456000000Z", "0"),
        ("2026-09-10T00:00:00.123455999999Z", "0.000000000001"),
        ("2026-09-10T00:00:00.123456000001Z", None),
    ],
)
def test_update_age_has_exact_precision_and_no_risk_threshold(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
    literal: str | None,
    age: str | None,
) -> None:
    outcome = collect(monkeypatch, capability, [page(row("age", lastUpdateDateTime=literal))])
    finding = outcome.read.findings[0]
    assert data(finding, "observation") == {
        "severity": "informational",
        "status": "active",
        "last_update_age_seconds": age,
    }
    assert data(finding, "source")["lastUpdateDateTime"] == literal
    assert outcome.read.capability.state == "complete"


def test_unselected_incident_resolution_cannot_create_conflict(monkeypatch: pytest.MonkeyPatch) -> None:
    first = row("incident", status="resolved", resolvedDateTime="SYNTHETIC_UNSELECTED_FIRST")
    second = first | {"resolvedDateTime": "SYNTHETIC_UNSELECTED_SECOND"}
    outcome = collect(monkeypatch, "defender-incidents", [page(first, second)])
    assert outcome.read.capability.state == "complete"
    assert outcome.read.capability.duplicate_records == 1
    assert outcome.read.capability.collected == 1
    finding = outcome.read.findings[0]
    assert "resolvedDateTime" not in data(finding, "source")
    assert finding.status is FindingStatus.RESOLVED
    assert finding.resolved_at is None
    assert "timestamp_precision_unrepresentable" not in diagnostics(outcome)


@pytest.mark.parametrize("status", ["new", "RESOLVED", None])
def test_active_alert_never_gets_resolution_time(monkeypatch: pytest.MonkeyPatch, status: str | None) -> None:
    outcome = collect(
        monkeypatch, "defender-alerts", [page(row("active", status=status, resolvedDateTime="2026-09-09T01:00:00Z"))]
    )
    assert outcome.read.findings[0].status is FindingStatus.ACTIVE
    assert outcome.read.findings[0].resolved_at is None
    assert "timestamp_precision_unrepresentable" not in diagnostics(outcome)


@pytest.mark.parametrize("capability", CAPABILITIES)
def test_exact_inclusive_window_has_no_fractional_rounding(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
) -> None:
    times = [
        ("start", START),
        ("start-offset", "2026-09-09T01:00:00.123456000+01:00"),
        ("older", "2026-09-09T00:00:00.123455999999Z"),
        ("end", END),
        ("end-long", "2026-09-10T00:00:00.123456000000Z"),
        ("future-100ns", "2026-09-10T00:00:00.1234561Z"),
        ("future-1ps", "2026-09-10T00:00:00.123456000001Z"),
    ]
    outcome = collect(
        monkeypatch, capability, [page(*[row(identifier, createdDateTime=when) for identifier, when in times])]
    )
    assert [finding.resource_id for finding in outcome.read.findings] == ["start", "start-offset", "end", "end-long"]
    cap = outcome.read.capability
    assert (cap.scanned, cap.matched_filter, cap.collected) == (7, 4, 4)
    assert cap.observed_first == "2026-09-09T00:00:00.123456000Z"
    assert cap.observed_last == "2026-09-10T00:00:00.123456000000Z"
    assert diagnostics(outcome)["future_timestamp"] == 2
    assert cap.state == "complete"
    for finding in outcome.read.findings:
        assert finding.first_observed == finding.last_observed == NOW


@pytest.mark.parametrize("capability", CAPABILITIES)
def test_duplicates_and_conflicts_use_final_source_set(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
) -> None:
    contested = row("contested", createdDateTime=START, severity="low")
    survivor = row("survivor", severity="medium")
    discarded_variant = copy.deepcopy(survivor) | {"description": "SYNTHETIC_EXCLUDED_DIFFERENCE"}
    outcome = collect(
        monkeypatch,
        capability,
        [
            page(contested, survivor, next_link=next_link(capability)),
            page(discarded_variant, contested | {"severity": "high"}),
        ],
    )
    assert [finding.resource_id for finding in outcome.read.findings] == ["survivor"]
    cap = outcome.read.capability
    assert (cap.scanned, cap.matched_filter, cap.collected, cap.duplicate_records) == (4, 1, 1, 1)
    assert cap.observed_first == cap.observed_last == END
    assert cap.state == "partial"
    assert diagnostics(outcome)["conflicting_duplicate"] == 1
    assert not outcome.result.manifest.is_complete


@pytest.mark.parametrize("capability", CAPABILITIES)
@pytest.mark.parametrize(
    "field,value",
    [
        ("id", False),
        ("severity", 1),
        ("status", []),
        ("createdDateTime", "invalid"),
        ("lastUpdateDateTime", "2026-09-10T00:00:00"),
    ],
)
def test_invalid_page_is_atomic_and_preserves_prior_evidence(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
    field: str,
    value: JsonValue,
) -> None:
    outcome = collect(
        monkeypatch,
        capability,
        [
            page(row("prior"), next_link=next_link(capability)),
            page(row("rejected-valid"), row("invalid") | {field: value}),
        ],
    )
    assert [finding.resource_id for finding in outcome.read.findings] == ["prior"]
    assert outcome.read.capability.state == "partial"
    assert outcome.read.capability.scanned == outcome.read.capability.pages_completed == 1
    assert outcome.read.capability.requests_attempted == 2
    assert diagnostics(outcome)["invalid_record"] == 1


@pytest.mark.parametrize("capability", CAPABILITIES)
@pytest.mark.parametrize(
    "body",
    [
        b'{"value":[],"value":[]}',
        b'{"value":[{"id":"x","createdDateTime":"2026-09-10T00:00:00Z","discarded":NaN}]}',
        b'{"value":null}',
    ],
)
def test_invalid_first_envelope_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
    body: bytes,
) -> None:
    outcome = collect(monkeypatch, capability, [Reply(body)])
    assert outcome.read.findings == ()
    assert outcome.read.capability.state == "unavailable"
    assert outcome.result.status == "unavailable"
    assert outcome.result.manifest.empty_categories == []
    assert outcome.read.capability.observed_first is None
    assert outcome.read.capability.observed_last is None


@pytest.mark.parametrize("capability", CAPABILITIES)
def test_empty_accepted_page_then_refused_continuation_stays_partial(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
) -> None:
    outcome = collect(
        monkeypatch,
        capability,
        [
            page(next_link=next_link(capability)),
            page(row("not-admitted"), next_link="https://127.0.0.1/v1.0/security/incidents"),
        ],
    )
    assert outcome.read.findings == ()
    assert outcome.read.capability.pages_completed == 1
    assert outcome.read.capability.scanned == 0
    assert outcome.read.capability.state == "partial"
    assert outcome.result.status == "partial"
    assert outcome.result.manifest.empty_categories == []
    assert len(outcome.requests) == 2


@pytest.mark.parametrize("capability", CAPABILITIES)
def test_empty_page_at_page_limit_is_partial(monkeypatch: pytest.MonkeyPatch, capability: DefenderCapability) -> None:
    outcome = collect(monkeypatch, capability, [page(next_link=next_link(capability))], max_pages=1)
    assert outcome.read.findings == ()
    assert outcome.read.capability.state == "partial"
    assert diagnostics(outcome)["page_limit"] == 1
    assert not outcome.result.manifest.is_complete
    assert outcome.result.manifest.empty_categories == []


@pytest.mark.parametrize("capability", CAPABILITIES)
def test_unexpected_finding_failure_is_not_complete(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise RuntimeError("synthetic-factory-failure")

    monkeypatch.setattr(EntraM365RunContext, "make_finding", fail)
    with pytest.raises(RuntimeError, match=r"^synthetic-factory-failure$"):
        collect(monkeypatch, capability, [page(row("not-complete"))])


@pytest.mark.parametrize("capability", CAPABILITIES)
@pytest.mark.parametrize("status", [401, 403])
def test_auth_refusal_has_no_findings_or_completion_claim(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
    status: int,
) -> None:
    outcome = collect(monkeypatch, capability, [Reply(b"SYNTHETIC_EXCLUDED_UPSTREAM_BODY", status)])
    assert outcome.read.findings == ()
    assert outcome.read.capability.state == "unavailable"
    assert outcome.read.capability.requests_attempted == 1
    assert not outcome.result.manifest.is_complete
    assert outcome.result.manifest.empty_categories == []
    assert outcome.read.capability.diagnostics[0].http_status == status


@pytest.mark.parametrize("capability", CAPABILITIES)
def test_successful_empty_collection_preserves_complete_evidence(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
) -> None:
    outcome = collect(monkeypatch, capability, [page()])
    assert outcome.read.findings == ()
    assert outcome.read.capability.state == "complete"
    assert outcome.read.capability.pages_completed == 1
    assert outcome.read.capability.collected == 0
    assert outcome.result.manifest.empty_categories == [capability]
    assert outcome.result.manifest.is_complete
    assert outcome.result.status == "complete"
    assert not outcome.result.full_surface_complete
    assert len(outcome.result.capabilities) == 9
    assert sum(item.state == "not_requested" for item in outcome.result.capabilities) == 8


@pytest.mark.parametrize("capability", CAPABILITIES)
@pytest.mark.parametrize("with_continuation", [False, True])
def test_terminal_at_cap_completes_but_continuation_is_partial(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
    with_continuation: bool,
) -> None:
    outcome = collect(
        monkeypatch,
        capability,
        [page(row("one"), next_link=next_link(capability) if with_continuation else None)],
        max_items=1,
    )
    assert len(outcome.requests) == len(outcome.read.findings) == 1
    assert outcome.read.capability.state == ("partial" if with_continuation else "complete")
    assert ("item_limit" in diagnostics(outcome)) is with_continuation


@pytest.mark.parametrize("capability", CAPABILITIES)
def test_static_mapping_identity_and_detached_results(
    monkeypatch: pytest.MonkeyPatch,
    capability: DefenderCapability,
) -> None:
    literal_id = " opaque/source:id \u00e9 "
    first = collect(monkeypatch, capability, [page(row(literal_id))], run_id="first")
    second = collect(monkeypatch, capability, [page(row(literal_id))], run_id="second")
    finding = first.read.findings[0]
    natural = "synthetic-defender:" + capability + ":" + literal_id
    assert finding.source_finding_id == natural
    assert finding.resource_id == literal_id
    assert finding.id == deterministic_finding_id("entra-m365", natural) == second.read.findings[0].id
    expected_controls = ["SI-4", "IR-5"] if capability == "defender-alerts" else ["IR-4", "IR-5"]
    assert [mapping.control_id for mapping in finding.control_mappings] == expected_controls
    assert all(mapping.relationship == "intersects-with" for mapping in finding.control_mappings)
    assert finding.resource_type == (
        "MicrosoftDefender::Alert" if capability == "defender-alerts" else "MicrosoftDefender::Incident"
    )
    assert finding.compliance_status is ComplianceStatus.UNKNOWN
    assert finding.collection_context.run_id == "first"
    assert second.read.findings[0].collection_context.run_id == "second"
    assert finding.collection_context.source_system_id == "entra-m365:operator-label:synthetic-defender"
    assert finding.collection_context.credential_identity == "unverified:primary-token"
    data(finding, "source")["id"] = "mutated"
    finding.control_mappings[0].control_id = "mutated"
    assert data(first.result.findings[0], "source")["id"] == literal_id
    assert data(second.read.findings[0], "source")["id"] == literal_id
    assert first.result.findings[0].control_mappings[0].control_id == expected_controls[0]
