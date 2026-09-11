"""Synthetic Splunk field fidelity and selected-leaf session acceptance."""

from __future__ import annotations

import hashlib
import json
import math
import socket
import ssl
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn, cast

import httpx
import pytest
from evidentia_collectors.enterprise_retention import _client, _credentials
from evidentia_collectors.enterprise_retention import splunk as reader
from evidentia_collectors.enterprise_retention._contracts import (
    CoverageState,
    EnterpriseRetentionCollectRequest,
    EnterpriseRetentionCollectResult,
    EnterpriseRetentionReadResult,
    ReadKind,
    SplunkIndexTarget,
)
from evidentia_collectors.enterprise_retention._credentials import CredentialMaterial
from evidentia_collectors.enterprise_retention._parsing import JsonObject, parse_strict_json
from evidentia_collectors.enterprise_retention._profiles import AddressPolicy, AuthorizedProfile, FrozenProfile
from evidentia_core import network_guard
from pydantic import JsonValue

INDEX = "audit-events"
NOW = datetime(2026, 1, 1, 12, 0, 0, 123456, tzinfo=UTC)
FIXTURES = Path(__file__).resolve().parents[3] / "fixtures/enterprise_retention/splunk"
CONTENT: JsonObject = {
    "datatype": "event",
    "disabled": False,
    "frozenTimePeriodInSecs": "0003600",
    "maxTotalDataSizeMB": 0,
    "coldToFrozenDir": "",
    "coldToFrozenScript": "/synthetic/archive-script",
}
FIELDS: JsonObject = {
    "name": INDEX,
    "datatype": "event",
    "disabled": False,
    "frozenTimePeriodInSecs": "0003600",
    "maxTotalDataSizeMB": 0,
    "coldToFrozenDirState": "empty",
    "coldToFrozenScriptState": "nonempty",
}
COVERAGE: dict[str, CoverageState] = {
    "name": "known",
    "datatype": "known",
    "disabled": "known",
    "frozenTimePeriodInSecs": "known",
    "maxTotalDataSizeMB": "known",
    "coldToFrozenDir": "known",
    "coldToFrozenScript": "known",
}


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def envelope(content: JsonObject, identity: str = INDEX) -> JsonObject:
    return {"entry": [{"name": identity, "content": content}]}


def projected(content: JsonObject) -> _client.ProjectedRecord:
    page = reader.project_index(
        _client.ParsedResponse(envelope(content), 200), _client.ReadSubject("splunk-index", INDEX)
    )
    assert len(page.records) == 1 and page.diagnostics == ()
    record = page.records[0]
    assert record.source_ordinal == 0 and record.source_identity == INDEX and record.native_scope == "index"
    return record


@pytest.fixture(autouse=True)
def isolated_destination(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    ambient_reads: list[str] = []

    def dns(
        host: str | bytes, port: int, family: int = 0, type: int = 0, proto: int = 0, flags: int = 0
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        assert host in ("splunk.example.invalid", b"splunk.example.invalid") and port == 8089
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]

    def no_environment(name: str) -> str | None:
        ambient_reads.append(name)
        raise AssertionError("ambient credential resolution is forbidden")

    def no_connect(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("a real socket connection is forbidden")

    monkeypatch.setattr(socket, "getaddrinfo", dns)
    monkeypatch.setattr(socket.socket, "connect", no_connect)
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", dns)
    monkeypatch.setattr(network_guard._pin_state, "hosts", {}, raising=False)
    monkeypatch.setattr(_credentials, "_environment_value", no_environment)
    monkeypatch.setattr(_client, "ssl_context", lambda profile: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    with network_guard.offline_mode(False):
        yield
    assert ambient_reads == []


class Body(httpx.SyncByteStream):
    def __init__(self, value: bytes) -> None:
        self.value = value
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        middle = len(self.value) // 2
        yield self.value[:middle]
        yield self.value[middle:]

    def close(self) -> None:
        self.closed = True


@dataclass(frozen=True)
class Reply:
    index: str
    body: bytes
    status: int = 200


@dataclass
class Wire:
    replies: list[Reply]
    requests: list[httpx.Request] = field(default_factory=list)
    bodies: list[Body] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    resolutions: int = 0

    def resolve(self, profile: FrozenProfile) -> CredentialMaterial:
        self.resolutions += 1
        assert profile.provider == "splunk-enterprise"
        return CredentialMaterial(profile.provider, "synthetic")

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not self.replies:
            self.violations.append("unexpected request")
            raise AssertionError("unexpected request")
        reply = self.replies.pop(0)
        expected = b"/services/data/indexes/" + reply.index.encode("ascii") + b"?output_mode=json&summarize=false"
        if (
            request.method != "GET"
            or request.url.raw_path != expected
            or request.url.host != "splunk.example.invalid"
            or request.url.port != 8089
            or request.content != b""
            or request.headers["host"] != "splunk.example.invalid:8089"
        ):
            self.violations.append("changed leaf contract")
            raise AssertionError("changed leaf contract")
        body = Body(reply.body)
        self.bodies.append(body)
        return httpx.Response(reply.status, headers={"Content-Type": "application/json"}, stream=body)

    def factory(self, context: ssl.SSLContext) -> httpx.MockTransport:
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        return httpx.MockTransport(self.handle)

    def collect(self, targets: tuple[str, ...] = (INDEX,)) -> EnterpriseRetentionCollectResult:
        request = EnterpriseRetentionCollectRequest.model_validate(
            {
                "provider": "splunk-enterprise",
                "profile_alias": "synthetic",
                "scope_label": "selected-indexes",
                "targets": [{"index": index} for index in targets],
            }
        )
        profile = FrozenProfile(
            "synthetic",
            "splunk-enterprise",
            "https://splunk.example.invalid:8089",
            "ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
            AddressPolicy("public"),
        )

        def no_wait(delay: float) -> NoReturn:
            raise AssertionError("these domain cases must not retry")

        with _client.EnterpriseReadSession(
            request,
            profile=AuthorizedProfile(profile, self),
            transport_factory=self.factory,
            utc_clock=lambda: NOW,
            monotonic_clock=lambda: 0.0,
            sleep=no_wait,
            run_id_factory=lambda: "01K00000000000000000000000",
        ) as session:
            resources = []
            for target in request.root.targets:
                assert isinstance(target, SplunkIndexTarget)
                resources.append(reader.read_splunk(target, session))
            result = session.finish(tuple(resources))
        assert self.violations == [] and self.replies == []
        assert all(body.closed for body in self.bodies)
        checked = EnterpriseRetentionCollectResult.model_validate_json(result.publication_bytes())
        assert checked.publication_bytes() == result.publication_bytes()
        assert checked.root.manifest.attempts == len(self.requests)
        assert checked.root.manifest.records_received == sum(
            item.records_received for item in checked.root.source_reads
        )
        assert checked.root.manifest.records_admitted == sum(
            item.records_admitted for item in checked.root.source_reads
        )
        return checked


def only_read(result: EnterpriseRetentionCollectResult) -> EnterpriseRetentionReadResult:
    assert len(result.root.source_reads) == 1
    return result.root.source_reads[0]


def fixture(name: str) -> tuple[str, list[Reply]]:
    data = parse_strict_json((FIXTURES / name).read_bytes())
    assert isinstance(data, dict) and data["authored_synthetic"] is True and data["recorded_response"] is False
    index, responses = data["target"], data["responses"]
    assert isinstance(index, str) and isinstance(responses, list)
    replies = []
    for response in responses:
        assert isinstance(response, dict) and type(response["status"]) is int
        replies.append(Reply(index, encoded(response["body"]), response["status"]))
    return index, replies


@pytest.mark.parametrize(
    "name,value,state",
    [
        ("datatype", "event", "known"),
        ("datatype", "metric", "known"),
        ("datatype", "EVENT", "unknown"),
        ("datatype", "future-data", "unknown"),
        ("datatype", "", "unknown"),
        ("datatype", None, "null"),
        ("disabled", False, "known"),
        ("disabled", True, "known"),
        ("disabled", 0, "known"),
        ("disabled", 1, "known"),
        ("disabled", "0", "known"),
        ("disabled", "1", "known"),
        ("disabled", 0.0, "unknown"),
        ("disabled", -0.0, "unknown"),
        ("disabled", 1.0, "unknown"),
        ("disabled", 2, "unknown"),
        ("disabled", -1, "unknown"),
        ("disabled", "false", "unknown"),
        ("disabled", "00", "unknown"),
        ("disabled", None, "null"),
        ("frozenTimePeriodInSecs", 0, "known"),
        ("frozenTimePeriodInSecs", 10**127, "known"),
        ("frozenTimePeriodInSecs", "0003600", "known"),
        ("frozenTimePeriodInSecs", -1, "unknown"),
        ("frozenTimePeriodInSecs", 0.0, "unknown"),
        ("frozenTimePeriodInSecs", "-1", "unknown"),
        ("frozenTimePeriodInSecs", " 0", "unknown"),
        ("frozenTimePeriodInSecs", "", "unknown"),
        ("frozenTimePeriodInSecs", "\u0661\u0662", "unknown"),
        ("frozenTimePeriodInSecs", None, "null"),
        ("maxTotalDataSizeMB", 0, "known"),
        ("maxTotalDataSizeMB", 2**53 + 1, "known"),
        ("maxTotalDataSizeMB", "0000", "known"),
        ("maxTotalDataSizeMB", "9" * 200, "known"),
        ("maxTotalDataSizeMB", -1, "unknown"),
        ("maxTotalDataSizeMB", 0.1, "unknown"),
        ("maxTotalDataSizeMB", "+1", "unknown"),
        ("maxTotalDataSizeMB", "1e3", "unknown"),
        ("maxTotalDataSizeMB", "\uff11", "unknown"),
        ("maxTotalDataSizeMB", None, "null"),
    ],
)
def test_scalar_selection_has_an_independent_native_and_coverage_oracle(
    name: str, value: JsonValue, state: CoverageState
) -> None:
    content = {**CONTENT, name: value}
    expected = {**FIELDS, name: value}
    record = projected(content)
    assert encoded(record.fields) == encoded(expected)
    assert type(record.fields[name]) is type(value)
    assert record.field_coverage == {**COVERAGE, name: state}
    assert record.diagnostics == (
        ("unsupported_source_value",) if state == "unknown" else ("missing_source_detail",) if state == "null" else ()
    )


@pytest.mark.parametrize("name", list(CONTENT))
def test_omission_is_never_filled_with_a_provider_default(name: str) -> None:
    content = dict(CONTENT)
    del content[name]
    expected = dict(FIELDS)
    if name in ("coldToFrozenDir", "coldToFrozenScript"):
        expected[name + "State"] = "absent"
    else:
        del expected[name]
    record = projected(content)
    assert encoded(record.fields) == encoded(expected)
    assert record.field_coverage == {**COVERAGE, name: "absent"}
    assert record.diagnostics == ("missing_source_detail",)


@pytest.mark.parametrize("name", ["coldToFrozenDir", "coldToFrozenScript"])
@pytest.mark.parametrize(
    "value,state,coverage",
    [
        (None, "null", "null"),
        ("", "empty", "known"),
        (" ", "nonempty", "known"),
        ("/synthetic/raw-path", "nonempty", "known"),
    ],
)
def test_archive_derivation_preserves_presence_without_exposing_text(
    name: str, value: JsonValue, state: str, coverage: CoverageState
) -> None:
    record = projected({**CONTENT, name: value})
    assert record.fields == {**FIELDS, name + "State": state}
    assert name not in record.fields
    assert record.field_coverage == {**COVERAGE, name: coverage}
    assert record.diagnostics == (("missing_source_detail",) if value is None else ())


@pytest.mark.parametrize(
    "name,bad",
    [
        ("datatype", 0),
        ("datatype", False),
        ("datatype", 0.0),
        ("datatype", []),
        ("datatype", {}),
        ("disabled", []),
        ("disabled", {}),
        ("frozenTimePeriodInSecs", False),
        ("frozenTimePeriodInSecs", True),
        ("frozenTimePeriodInSecs", []),
        ("frozenTimePeriodInSecs", {}),
        ("maxTotalDataSizeMB", False),
        ("maxTotalDataSizeMB", True),
        ("maxTotalDataSizeMB", []),
        ("maxTotalDataSizeMB", {}),
        ("coldToFrozenDir", 0),
        ("coldToFrozenDir", False),
        ("coldToFrozenDir", 0.0),
        ("coldToFrozenDir", []),
        ("coldToFrozenDir", {}),
        ("coldToFrozenScript", 0),
        ("coldToFrozenScript", False),
        ("coldToFrozenScript", 0.0),
        ("coldToFrozenScript", []),
        ("coldToFrozenScript", {}),
    ],
)
def test_wrong_declared_native_types_refuse_the_projection(name: str, bad: JsonValue) -> None:
    with pytest.raises(_client.AuthorityError, match=r"^invalid_response$"):
        projected({**CONTENT, name: bad})


def test_projection_and_returned_views_are_detached() -> None:
    content = dict(CONTENT)
    response = _client.ParsedResponse(envelope(content), 200)
    content["datatype"] = "changed"
    record = reader.project_index(response, _client.ReadSubject("splunk-index", INDEX)).records[0]
    fields = record.fields
    fields["disabled"] = True
    record.field_coverage.clear()
    assert record.fields == FIELDS and record.field_coverage == COVERAGE
    assert record.diagnostics == ()


@pytest.mark.parametrize("kind,identity", [("vault-matter", INDEX), ("splunk-index", "other-index")])
def test_projector_rejects_wrong_subject_or_identity(kind: str, identity: str) -> None:
    subject = _client.ReadSubject(cast(ReadKind, kind), identity)
    with pytest.raises(_client.AuthorityError):
        reader.project_index(_client.ParsedResponse(envelope(CONTENT), 200), subject)


@pytest.mark.parametrize("fixture_name", ["index-event.json", "index-metric.json"])
def test_known_fixture_uses_one_fixed_leaf_and_full_unassessed_scope(fixture_name: str) -> None:
    index, replies = fixture(fixture_name)
    wire = Wire(replies)
    result = wire.collect((index,))
    entry = only_read(result)
    expected: JsonObject = (
        dict(FIELDS)
        if fixture_name == "index-event.json"
        else {
            "name": "audit-metrics",
            "datatype": "metric",
            "disabled": "1",
            "frozenTimePeriodInSecs": 0,
            "maxTotalDataSizeMB": "0000",
            "coldToFrozenDirState": "nonempty",
            "coldToFrozenScriptState": "empty",
        }
    )
    observation = entry.observations[0]
    assert encoded(observation.fields) == encoded(expected)
    assert observation.field_coverage == COVERAGE and observation.interpretation_status == "known"
    expected_digest = hashlib.sha256(
        encoded(
            {
                "projection_version": "enterprise-retention-projection/v1",
                "method_id": "splunk.data.indexes.get",
                "native_scope": "index",
                "source_identity": index,
                "fields": expected,
            }
        )
    ).hexdigest()
    assert observation.canonical_projection_sha256 == expected_digest
    assert observation.api_version == "splunk-enterprise-10.4"
    assert (entry.pages_received, entry.pages_admitted, entry.records_received, entry.records_admitted) == (1, 1, 1, 1)
    assert result.root.status == "complete" and len(result.root.findings) == 1
    assert result.root.unassessed_surfaces == (
        "event_coverage",
        "archive_execution_and_durability",
        "smartstore_and_volume_configuration",
        "cluster_wide_configuration",
    )
    assert result.root.resources[0].policy_resolution == "not_applicable"
    assert wire.resolutions == 1 and len(wire.requests) == 1
    output = result.publication_bytes()
    assert b"/synthetic/archive" not in output and b"synthetic excluded" not in output


def test_unknown_and_null_fixture_is_complete_but_interpretation_is_limited() -> None:
    index, replies = fixture("index-unknown-null.json")
    result = Wire(replies).collect((index,))
    observation = only_read(result).observations[0]
    expected = {
        "name": "future-index",
        "datatype": "future-data",
        "disabled": -0.0,
        "frozenTimePeriodInSecs": None,
        "maxTotalDataSizeMB": "+001",
        "coldToFrozenDirState": "absent",
        "coldToFrozenScriptState": "null",
    }
    assert encoded(observation.fields) == encoded(expected)
    assert math.copysign(1.0, cast(float, observation.fields["disabled"])) == -1.0
    assert observation.field_coverage == {
        "name": "known",
        "datatype": "unknown",
        "disabled": "unknown",
        "frozenTimePeriodInSecs": "null",
        "maxTotalDataSizeMB": "unknown",
        "coldToFrozenDir": "absent",
        "coldToFrozenScript": "null",
    }
    assert [item.code for item in observation.diagnostics] == ["unsupported_source_value", "missing_source_detail"]
    assert result.root.status == "complete" and observation.interpretation_status == "limited"


def test_four_archive_fixture_states_remain_distinct() -> None:
    index, replies = fixture("index-archive-states.json")
    digests = []
    for reply, state in zip(replies, ("absent", "null", "empty", "nonempty"), strict=True):
        result = Wire([reply]).collect((index,))
        observation = only_read(result).observations[0]
        assert observation.fields == {"name": index, "coldToFrozenDirState": state, "coldToFrozenScriptState": state}
        assert result.root.status == "complete"
        digests.append(observation.canonical_projection_sha256)
    assert len(set(digests)) == 4


def test_changed_nonempty_archive_text_does_not_change_the_projection_digest(caplog: pytest.LogCaptureFixture) -> None:
    digests = []
    for suffix in ("first", "second"):
        content = {
            **CONTENT,
            "coldToFrozenDir": "/synthetic/" + suffix,
            "coldToFrozenScript": "synthetic-script-" + suffix,
        }
        result = Wire([Reply(INDEX, encoded(envelope(content)))]).collect()
        digests.append(only_read(result).observations[0].canonical_projection_sha256)
        output = result.publication_bytes().decode()
        assert "/synthetic/" + suffix not in output and "synthetic-script-" + suffix not in output
    assert digests[0] == digests[1]
    assert "/synthetic/" not in caplog.text and "synthetic-script-" not in caplog.text


@pytest.mark.parametrize(
    "name,value,state",
    [
        ("disabled", False, "known"),
        ("disabled", 0, "known"),
        ("disabled", "0", "known"),
        ("disabled", 0.0, "unknown"),
        ("disabled", -0.0, "unknown"),
        ("frozenTimePeriodInSecs", 10**128 - 1, "known"),
        ("maxTotalDataSizeMB", 2**53 + 1, "known"),
        ("frozenTimePeriodInSecs", "0000", "known"),
        ("maxTotalDataSizeMB", "9" * 200, "known"),
        ("frozenTimePeriodInSecs", -1, "unknown"),
        ("maxTotalDataSizeMB", None, "null"),
    ],
)
def test_real_session_preserves_exact_native_values(name: str, value: JsonValue, state: CoverageState) -> None:
    result = Wire([Reply(INDEX, encoded(envelope({**CONTENT, name: value})))]).collect()
    observation = only_read(result).observations[0]
    assert type(observation.fields[name]) is type(value)
    assert encoded(observation.fields[name]) == encoded(value)
    assert observation.field_coverage[name] == state
    assert result.root.status == "complete"


@pytest.mark.parametrize(
    "kinds,expected,status",
    [
        (["WARN"], ["upstream_warning"], "complete"),
        (["WARN", "WARN"], ["upstream_warning"], "complete"),
        (["INFO", "DEBUG"], [], "complete"),
        (["future"], ["unsupported_source_value"], "complete"),
        (["future", "WARN"], ["upstream_warning", "unsupported_source_value"], "complete"),
        (["ERROR"], ["upstream_error"], "unavailable"),
        (["future", "WARN", "ERROR"], ["upstream_error"], "unavailable"),
        (["ERROR", "WARN", "future"], ["upstream_error"], "unavailable"),
    ],
)
def test_session_owns_message_refusal_and_fixed_warning_deduplication(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    kinds: list[str],
    expected: list[str],
    status: str,
) -> None:
    calls = []
    actual = reader.project_index

    def observed(response: _client.ParsedResponse, subject: _client.ReadSubject) -> _client.ProjectedPage:
        calls.append(subject.source_id)
        return actual(response, subject)

    monkeypatch.setattr(reader, "project_index", observed)
    data = envelope(CONTENT)
    data["messages"] = [{"type": kind, "text": "synthetic-message-not-for-output"} for kind in kinds]
    result = Wire([Reply(INDEX, encoded(data))]).collect()
    entry = only_read(result)
    assert result.root.status == status and [item.code for item in entry.diagnostics] == expected
    assert calls == ([] if "ERROR" in kinds else [INDEX])
    assert entry.records_received == 1 and entry.records_admitted == (0 if "ERROR" in kinds else 1)
    assert "synthetic-message-not-for-output" not in result.publication_bytes().decode()
    assert "synthetic-message-not-for-output" not in caplog.text


@pytest.mark.parametrize("messages", [None, {}, [None], [{}], [{"type": 1}]])
def test_malformed_messages_cannot_become_empty_success(messages: JsonValue) -> None:
    data = envelope(CONTENT)
    data["messages"] = messages
    result = Wire([Reply(INDEX, encoded(data))]).collect()
    entry = only_read(result)
    assert result.root.status == "unavailable" and entry.observations == []
    assert [item.code for item in entry.diagnostics] == ["invalid_response"]


@pytest.mark.parametrize(
    "fixture_name,code",
    [("index-body-error.json", "upstream_error"), ("index-invalid-identity.json", "identity_mismatch")],
)
def test_error_and_identity_fixtures_refuse_without_a_fallback(fixture_name: str, code: str) -> None:
    index, replies = fixture(fixture_name)
    wire = Wire(replies)
    result = wire.collect((index,))
    entry = only_read(result)
    assert result.root.status == "unavailable" and entry.observations == []
    assert entry.pages_admitted == entry.records_admitted == 0
    assert [item.code for item in entry.diagnostics] == [code]
    assert len(wire.requests) == 1 and len(result.root.resources) == 1 and result.root.findings == []


@pytest.mark.parametrize(
    "data,code,count",
    [
        ({}, "invalid_response", 0),
        ({"entry": []}, "invalid_response", 0),
        ({"entry": None}, "invalid_response", 0),
        ({"entry": {}}, "invalid_response", 0),
        ({"entry": [None]}, "invalid_response", 1),
        ({"entry": [{"name": INDEX, "content": {}}, {"name": INDEX, "content": {}}]}, "invalid_response", 2),
        ({"entry": [{"name": "other", "content": {}}]}, "identity_mismatch", 1),
        ({"entry": [{"content": {}}]}, "identity_mismatch", 1),
        ({"entry": [{"name": INDEX}]}, "invalid_response", 1),
        ({"entry": [{"name": INDEX, "content": None}]}, "invalid_response", 1),
        ({"entry": [{"name": INDEX, "content": []}]}, "invalid_response", 1),
    ],
)
def test_envelope_refusal_preserves_actual_received_count(data: JsonObject, code: str, count: int) -> None:
    result = Wire([Reply(INDEX, encoded(data))]).collect()
    entry = only_read(result)
    assert entry.records_received == count and entry.records_admitted == 0
    assert entry.pages_received == 1 and entry.pages_admitted == 0
    assert entry.status == "unavailable" and [item.code for item in entry.diagnostics] == [code]


@pytest.mark.parametrize("bad_number", ["1.0000000000000001", "1e-10000", "1" + "0" * 128])
def test_unrepresentable_source_number_refuses_instead_of_changing_evidence(bad_number: str) -> None:
    body = ('{"entry":[{"name":"audit-events","content":{"frozenTimePeriodInSecs":' + bad_number + "}}]}").encode()
    result = Wire([Reply(INDEX, body)]).collect()
    entry = only_read(result)
    assert result.root.status == "unavailable" and entry.records_admitted == 0
    assert [item.code for item in entry.diagnostics] == ["invalid_json"]


@pytest.mark.parametrize("status", [403, 404])
def test_one_failed_index_does_not_remove_or_prevent_another_selected_index(status: int) -> None:
    wire = Wire(
        [
            Reply("failed-index", b"{}", status),
            Reply("good-index", encoded(envelope(CONTENT, "good-index"))),
        ]
    )
    result = wire.collect(("failed-index", "good-index"))
    assert result.root.status == "partial"
    assert [resource.target.model_dump() for resource in result.root.resources] == [
        {"index": "failed-index"},
        {"index": "good-index"},
    ]
    assert [resource.status for resource in result.root.resources] == ["unavailable", "complete"]
    assert len(result.root.findings) == 1 and wire.resolutions == 1
    assert [read.records_admitted for read in result.root.source_reads] == [0, 1]
