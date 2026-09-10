"""Authored synthetic GCS responses through the shared guarded session."""

from __future__ import annotations

import copy
import json
import socket
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import cast

import httpx
import pytest
from evidentia_collectors.retention._client import ComponentProjector, StorageReadSession
from evidentia_collectors.retention._contracts import (
    ComponentId,
    GcsTarget,
    ProviderName,
    StorageRetentionComponentResult,
    StorageTarget,
    make_result,
    target_identity,
)
from evidentia_collectors.retention._credentials import BearerCredentials, CredentialResolution
from evidentia_collectors.retention._parsing import JsonObject, JsonValue
from evidentia_collectors.retention.gcs import read_gcs
from evidentia_core import network_guard

BUCKET = "synthetic-retention-bucket"
FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "retention" / "gcs"
NOW = datetime(2026, 9, 10, tzinfo=UTC)


def fixture(name: str = "bucket-locked.json") -> JsonObject:
    value = json.loads((FIXTURES / name).read_text(encoding="ascii"))
    assert isinstance(value, dict)
    return cast(JsonObject, value)


def nested(value: JsonObject, key: str) -> JsonObject:
    selected = value[key]
    assert isinstance(selected, dict)
    return selected


def set_field(value: JsonObject, path: str, replacement: JsonValue) -> None:
    keys = path.split(".")
    selected = value if len(keys) == 1 else nested(value, keys[0])
    selected[keys[-1]] = replacement


def omit_field(value: JsonObject, path: str) -> None:
    keys = path.split(".")
    selected = value if len(keys) == 1 else nested(value, keys[0])
    del selected[keys[-1]]


def codes(result: StorageRetentionComponentResult) -> list[str]:
    return [item.code for item in result.diagnostics]


class SyntheticCredentials:
    def __init__(self) -> None:
        self.calls: list[ProviderName] = []

    def resolve(self, provider: ProviderName) -> CredentialResolution:
        self.calls.append(provider)
        return CredentialResolution(BearerCredentials("SYNTHETIC_GCS_TEST_VALUE"), None)


class BodyStream(httpx.SyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        yield self.body[:11]
        yield self.body[11:]

    def close(self) -> None:
        self.closed = True


@dataclass
class Reply:
    body: bytes
    status: int = 200
    headers: list[tuple[str, str]] = field(default_factory=lambda: [("ETag", '"synthetic-gcs-etag"')])


class SyntheticTransport(httpx.BaseTransport):
    def __init__(self, replies: list[Reply]) -> None:
        self.replies = list(replies)
        self.requests: list[httpx.Request] = []
        self.streams: list[BodyStream] = []
        self.closed = False

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.url.host == "storage.googleapis.com"
        assert {row[4][0] for row in socket.getaddrinfo(request.url.host, 443)} == {"8.8.8.8"}
        assert self.replies, "Unexpected synthetic request"
        reply = self.replies.pop(0)
        stream = BodyStream(reply.body)
        self.streams.append(stream)
        return httpx.Response(reply.status, headers=reply.headers, stream=stream)

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def isolate_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", network_guard._GETADDRINFO_DELEGATE)
    monkeypatch.setattr(network_guard, "_offline_enabled", False)

    def resolve(
        host: object, port: object, *args: object, **kwargs: object
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        assert host == "storage.googleapis.com"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

    def refuse_socket(*args: object, **kwargs: object) -> None:
        raise AssertionError("Synthetic GCS tests cannot open a connection")

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "create_connection", refuse_socket)
    yield


def session(
    replies: list[Reply], buckets: tuple[str, ...] = (BUCKET,)
) -> tuple[StorageReadSession, SyntheticTransport, SyntheticCredentials]:
    transport = SyntheticTransport(replies)
    credentials = SyntheticCredentials()
    value = StorageReadSession(
        {"provider": "gcs", "scope_label": "synthetic-gcs", "targets": [{"bucket": name} for name in buckets]},
        credentials=credentials,
        transport_factory=lambda: transport,
        utc_clock=lambda: NOW,
        monotonic_clock=lambda: 0.0,
        sleep=lambda seconds: None,
        run_id_factory=lambda: "synthetic-gcs-run",
    )
    return value, transport, credentials


def read(value: JsonValue, *, status: int = 200) -> StorageRetentionComponentResult:
    body = json.dumps(value, ensure_ascii=True, allow_nan=False).encode("ascii")
    active, transport, _ = session([Reply(body, status)])
    try:
        results = read_gcs(GcsTarget(bucket=BUCKET), active)
        assert len(results) == 1
        assert results[0].component_id == "gcs-bucket"
        return results[0]
    finally:
        active.close()
        assert transport.closed
        assert all(stream.closed for stream in transport.streams)


def expected_locked() -> JsonObject:
    return {
        "name": BUCKET,
        "metageneration": "0009007199254740993",
        "retentionPolicy": {
            "retentionPeriod": "00086400",
            "effectiveTime": "2026-09-10T01:02:03.123456789+05:30",
            "isLocked": True,
        },
        "versioning": {"enabled": True},
        "objectRetention": {"mode": "Enabled"},
    }


def test_exact_projection_wire_metadata_and_independent_digest() -> None:
    result = read(fixture())
    assert result.status == "complete" and result.attempts == 1 and codes(result) == []
    projection = result.projection
    assert projection is not None
    assert projection.fields == expected_locked()
    assert projection.api_version == "v1" and projection.native_scope == "bucket"
    assert projection.source_metageneration == "0009007199254740993"
    assert projection.source_etag == '"synthetic-gcs-etag"'
    wire = {
        "api_version": "v1",
        "projection_version": "storage-retention-projection/v1",
        "native_scope": "bucket",
        "fields": expected_locked(),
        "source_etag": '"synthetic-gcs-etag"',
        "source_metageneration": "0009007199254740993",
    }
    independent = json.dumps(wire, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
        "utf-8"
    )
    assert projection.canonical_projection_sha256 == sha256(independent).hexdigest()
    assert StorageRetentionComponentResult.model_validate_json(result.model_dump_json(warnings="error")) == result


def test_exactly_one_shared_component_call_and_fixed_wire_request(monkeypatch: pytest.MonkeyPatch) -> None:
    body = (FIXTURES / "bucket-no-policy.json").read_bytes()
    active, transport, credentials = session([Reply(body)])
    calls: list[tuple[ComponentId, StorageTarget, ComponentProjector]] = []
    original = active.read_component

    def record(
        component_id: ComponentId, target: StorageTarget, projector: ComponentProjector
    ) -> StorageRetentionComponentResult:
        calls.append((component_id, target, projector))
        return original(component_id, target, projector)

    monkeypatch.setattr(active, "read_component", record)
    selected = GcsTarget(bucket=BUCKET)
    try:
        results = read_gcs(selected, active)
        assert len(results) == len(calls) == len(transport.requests) == 1
        assert calls[0][:2] == ("gcs-bucket", selected)
        request = transport.requests[0]
        assert request.method == "GET" and request.content == b""
        assert (
            str(request.url)
            == "https://storage.googleapis.com/storage/v1/b/synthetic-retention-bucket?projection=noAcl"
        )
        assert credentials.calls == ["gcs"]
        assert results[0].raw_bytes == results[0].decoded_bytes == len(body)
        assert results[0].started_at == results[0].finished_at == NOW
    finally:
        active.close()
    assert transport.closed and all(item.closed for item in transport.streams)


@pytest.mark.parametrize(
    "name,status,diagnostics",
    [
        ("bucket-locked.json", "complete", []),
        ("bucket-unlocked.json", "complete", []),
        ("bucket-no-policy.json", "complete", []),
        ("bucket-null.json", "partial", ["missing_source_detail"]),
        ("bucket-missing-detail.json", "partial", ["missing_source_detail"]),
        ("bucket-unknown-mode.json", "partial", ["unsupported_source_value"]),
        ("bucket-wrong-identity.json", "unavailable", ["source_identity_mismatch"]),
        ("bucket-wrong-scalar.json", "unavailable", ["invalid_response"]),
    ],
)
def test_authored_fixture_statuses(name: str, status: str, diagnostics: list[str]) -> None:
    result = read(fixture(name))
    assert result.status == status and codes(result) == diagnostics
    assert (result.projection is None) == (status == "unavailable")


def test_omission_null_false_and_true_remain_distinct() -> None:
    values = [
        read(fixture(name)).projection
        for name in ("bucket-no-policy.json", "bucket-null.json", "bucket-unlocked.json", "bucket-locked.json")
    ]
    assert all(value is not None for value in values)
    absent, null, unlocked, locked = values
    assert absent is not None and null is not None and unlocked is not None and locked is not None
    assert "retentionPolicy" not in absent.fields
    assert null.fields["retentionPolicy"] is None
    assert nested(unlocked.fields, "retentionPolicy")["isLocked"] is False
    assert nested(locked.fields, "retentionPolicy")["isLocked"] is True
    assert "objectRetention" not in unlocked.fields
    assert null.fields["objectRetention"] is None
    assert nested(locked.fields, "objectRetention")["mode"] == "Enabled"


@pytest.mark.parametrize(
    "field",
    [
        "metageneration",
        "retentionPolicy",
        "versioning",
        "objectRetention",
        "retentionPolicy.retentionPeriod",
        "retentionPolicy.effectiveTime",
        "retentionPolicy.isLocked",
        "versioning.enabled",
        "objectRetention.mode",
    ],
)
def test_selected_null_is_preserved_as_partial(field: str) -> None:
    value = fixture()
    set_field(value, field, None)
    result = read(value)
    assert result.status == "partial" and codes(result) == ["missing_source_detail"]
    assert result.projection is not None
    keys = field.split(".")
    selected = result.projection.fields if len(keys) == 1 else nested(result.projection.fields, keys[0])
    assert selected[keys[-1]] is None


@pytest.mark.parametrize(
    "field",
    [
        "metageneration",
        "retentionPolicy.retentionPeriod",
        "retentionPolicy.effectiveTime",
        "retentionPolicy.isLocked",
        "versioning.enabled",
        "objectRetention.mode",
    ],
)
def test_missing_detail_is_omitted_and_partial(field: str) -> None:
    value = fixture()
    omit_field(value, field)
    result = read(value)
    assert result.status == "partial" and codes(result) == ["missing_source_detail"]
    assert result.projection is not None
    keys = field.split(".")
    selected = result.projection.fields if len(keys) == 1 else nested(result.projection.fields, keys[0])
    assert keys[-1] not in selected


@pytest.mark.parametrize("field", ["retentionPolicy", "versioning", "objectRetention"])
def test_optional_config_omission_does_not_invent_disabled_state(field: str) -> None:
    value = fixture()
    del value[field]
    result = read(value)
    assert result.status == "complete" and result.projection is not None
    assert field not in result.projection.fields


@pytest.mark.parametrize(
    "field",
    ["metageneration", "retentionPolicy.retentionPeriod", "retentionPolicy.effectiveTime", "objectRetention.mode"],
)
@pytest.mark.parametrize("wrong", [True, 1, 1.0, [], {}])
def test_wrong_string_scalar_invalidates_entire_component(field: str, wrong: JsonValue) -> None:
    value = fixture()
    set_field(value, field, wrong)
    result = read(value)
    assert result.status == "unavailable" and result.projection is None
    assert codes(result) == ["invalid_response"]


@pytest.mark.parametrize("field", ["retentionPolicy.isLocked", "versioning.enabled"])
@pytest.mark.parametrize("wrong", ["true", "false", 0, 1, 0.0, [], {}])
def test_boolean_requires_native_boolean(field: str, wrong: JsonValue) -> None:
    value = fixture()
    set_field(value, field, wrong)
    result = read(value)
    assert result.status == "unavailable" and codes(result) == ["invalid_response"]


@pytest.mark.parametrize("field", ["retentionPolicy", "versioning", "objectRetention"])
@pytest.mark.parametrize("wrong", [False, 0, 1.0, "", "synthetic", []])
def test_config_requires_object_or_retained_null(field: str, wrong: JsonValue) -> None:
    value = fixture()
    set_field(value, field, wrong)
    result = read(value)
    assert result.status == "unavailable" and codes(result) == ["invalid_response"]


@pytest.mark.parametrize("body", [None, [], ["synthetic"], True, 1, 1.0, "synthetic", {}])
def test_bucket_envelope_and_identity_are_required(body: JsonValue) -> None:
    result = read(body)
    assert result.status == "unavailable" and codes(result) == ["invalid_response"]


@pytest.mark.parametrize("name", [None, True, 1, 1.0, [], {}, ""])
def test_name_wrong_scalar_or_empty_is_invalid(name: JsonValue) -> None:
    value = fixture()
    value["name"] = name
    result = read(value)
    assert result.status == "unavailable" and codes(result) == ["invalid_response"]


@pytest.mark.parametrize("name", ["synthetic-other", "SYNTHETIC-retention-bucket", BUCKET + " ", " " + BUCKET])
def test_identity_match_is_literal(name: str) -> None:
    value = fixture()
    value["name"] = name
    result = read(value)
    assert result.status == "unavailable" and codes(result) == ["source_identity_mismatch"]


@pytest.mark.parametrize("field", ["metageneration", "retentionPolicy.retentionPeriod"])
@pytest.mark.parametrize("value", ["", "+1", "-1", " 1", "1 ", "1.0", "1e1", "\u0661", "1\n", "0" * 129])
def test_unsigned_string_grammar_is_strict(field: str, value: str) -> None:
    data = fixture()
    set_field(data, field, value)
    result = read(data)
    assert result.status == "unavailable" and codes(result) == ["invalid_response"]


@pytest.mark.parametrize("generation", ["0", "000", "9007199254740993", "18446744073709551615", "9" * 128])
def test_metageneration_remains_exact_string(generation: str) -> None:
    data = fixture()
    data["metageneration"] = generation
    result = read(data)
    assert result.status == "complete" and result.projection is not None
    assert result.projection.source_metageneration == generation
    assert result.projection.fields["metageneration"] == generation


@pytest.mark.parametrize(
    "period,status",
    [
        ("1", "complete"),
        ("00086400", "complete"),
        ("3155759999", "complete"),
        ("0", "partial"),
        ("0000", "partial"),
        ("3155760000", "partial"),
        ("9" * 128, "partial"),
    ],
)
def test_period_range_preserves_unsupported_literal(period: str, status: str) -> None:
    data = fixture()
    nested(data, "retentionPolicy")["retentionPeriod"] = period
    result = read(data)
    assert result.status == status and result.projection is not None
    assert codes(result) == ([] if status == "complete" else ["unsupported_source_value"])
    assert nested(result.projection.fields, "retentionPolicy")["retentionPeriod"] == period


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-09-10T00:00:00Z",
        "2026-09-10T00:00:00.0000000001Z",
        "2026-09-10T01:02:03.123456789+05:30",
        "2024-02-29t12:00:00-00:00",
        "0001-01-01T00:00:00+14:00",
        "9999-12-31T23:59:59-14:00",
        "2026-09-10T23:59:59.000z",
    ],
)
def test_timestamp_literal_is_not_normalized_or_rounded(timestamp: str) -> None:
    data = fixture()
    nested(data, "retentionPolicy")["effectiveTime"] = timestamp
    result = read(data)
    assert result.status == "complete" and result.projection is not None
    assert nested(result.projection.fields, "retentionPolicy")["effectiveTime"] == timestamp


@pytest.mark.parametrize(
    "timestamp",
    [
        "",
        "synthetic-unknown-time",
        "2026-02-30T00:00:00Z",
        "2026-09-10",
        "2026-09-10T00:00:00",
        "2026-09-10T24:00:00Z",
        "2026-09-10T00:00:61Z",
        "2026-09-10T00:00:00+24:00",
        "2026-09-10T00:00:00+00:60",
        "2026-09-10T00:00:00Z\n",
        "2016-12-31T23:59:60Z",
        "2026-09-10T00:00:60Z",
    ],
)
def test_unsupported_timestamp_is_retained_without_clock_claim(timestamp: str) -> None:
    data = fixture()
    nested(data, "retentionPolicy")["effectiveTime"] = timestamp
    result = read(data)
    assert result.status == "partial" and result.projection is not None
    assert codes(result) == ["unsupported_source_value"]
    assert nested(result.projection.fields, "retentionPolicy")["effectiveTime"] == timestamp


@pytest.mark.parametrize(
    "mode", ["Disabled", "enabled", "", "SyntheticFutureMode", " Enabled ", "<script>synthetic</script>"]
)
def test_unknown_mode_is_exact_partial_source_data(mode: str) -> None:
    data = fixture()
    nested(data, "objectRetention")["mode"] = mode
    result = read(data)
    assert result.status == "partial" and codes(result) == ["unsupported_source_value"]
    assert result.projection is not None and nested(result.projection.fields, "objectRetention")["mode"] == mode


def test_multiple_detail_causes_are_deduplicated_in_fixed_order() -> None:
    data = fixture()
    data["metageneration"] = None
    nested(data, "retentionPolicy")["retentionPeriod"] = "0"
    nested(data, "versioning")["enabled"] = None
    nested(data, "objectRetention")["mode"] = "Future"
    result = read(data)
    assert result.status == "partial"
    assert codes(result) == ["missing_source_detail", "unsupported_source_value"]


def test_ignored_provider_fields_do_not_enter_projection_or_digest() -> None:
    first = fixture()
    second = copy.deepcopy(first)
    second["labels"] = {"synthetic": "x" * 40_000}
    second["acl"] = ["synthetic-discarded"]
    nested(second, "retentionPolicy")["futureIgnored"] = {"different": [1, None, False]}
    nested(second, "versioning")["futureIgnored"] = "new"
    nested(second, "objectRetention")["futureIgnored"] = "new"
    left, right = read(first), read(second)
    assert left.projection is not None and right.projection is not None
    assert left.projection == right.projection
    assert left.raw_bytes != right.raw_bytes
    assert "synthetic-discarded" not in right.model_dump_json()


@pytest.mark.parametrize(
    "raw",
    [
        b'{"name":"synthetic-retention-bucket","name":"other"}',
        b'{"name":"synthetic-retention-bucket","retentionPolicy":{"isLocked":true,"isLocked":false}}',
        b'{"name":"synthetic-retention-bucket","ignored":NaN}',
        rb'{"name":"synthetic-retention-bucket","ignored":"\ud800"}',
    ],
)
def test_strict_shared_json_refusal_never_admits_prefix(raw: bytes) -> None:
    active, transport, _ = session([Reply(raw)])
    try:
        result = read_gcs(GcsTarget(bucket=BUCKET), active)[0]
        assert result.projection is None and codes(result) == ["invalid_response"]
    finally:
        active.close()
    assert transport.closed and all(item.closed for item in transport.streams)


@pytest.mark.parametrize(
    "status,code",
    [(401, "credential_rejected"), (403, "forbidden"), (404, "resource_not_found"), (302, "redirect_refused")],
)
def test_http_failure_uses_shared_status_rules(status: int, code: str) -> None:
    result = read(fixture(), status=status)
    assert result.status == "unavailable" and result.projection is None and codes(result) == [code]


def test_invalid_bucket_does_not_erase_other_selected_bucket() -> None:
    second_name = "synthetic-next-bucket"
    second = fixture("bucket-no-policy.json")
    second["name"] = second_name
    active, transport, _ = session(
        [Reply((FIXTURES / "bucket-wrong-scalar.json").read_bytes()), Reply(json.dumps(second).encode())],
        (BUCKET, second_name),
    )
    first_target, second_target = GcsTarget(bucket=BUCKET), GcsTarget(bucket=second_name)
    try:
        first = read_gcs(first_target, active)
        later = read_gcs(second_target, active)
        result = make_result(
            active.context.request,
            run_id="synthetic-gcs-run",
            started_at=NOW,
            finished_at=NOW,
            components={target_identity(first_target): first, target_identity(second_target): later},
            diagnostics=(),
        )
        assert result.status == "partial" and len(result.findings) == 1
        assert first[0].status == "unavailable" and later[0].status == "complete"
        assert result.manifest.is_complete is False
    finally:
        active.close()
    assert len(transport.requests) == 2


def test_bucket_configuration_finding_cannot_claim_object_protection() -> None:
    target = GcsTarget(bucket=BUCKET)
    active, _, _ = session([Reply((FIXTURES / "bucket-locked.json").read_bytes())])
    try:
        components = read_gcs(target, active)
        result = make_result(
            active.context.request,
            run_id="synthetic-gcs-run",
            started_at=NOW,
            finished_at=NOW,
            components={target_identity(target): components},
            diagnostics=(),
        )
        finding = result.findings[0]
        assert finding.severity.value == "informational"
        assert finding.status.value == "active" and finding.compliance_status.value == "unknown"
        assert finding.control_mappings == [] and finding.resolved_at is None
        assert finding.raw_data["object_enforcement_assessed"] is False
        assert result.manifest.is_complete is True
    finally:
        active.close()


def test_pure_projector_detaches_selected_fields_and_preserves_inputs() -> None:
    from evidentia_collectors.retention._client import ComponentResponse
    from evidentia_collectors.retention.gcs import _project_bucket

    body = fixture()
    before = copy.deepcopy(body)
    target = GcsTarget(bucket=BUCKET)
    response = ComponentResponse("gcs-bucket", 200, body, '"synthetic-gcs-etag"')
    projected = _project_bucket(response, target)
    assert body == before and target.bucket == BUCKET
    assert projected.fields == expected_locked()
    nested(body, "retentionPolicy")["isLocked"] = False
    leaked = projected.fields
    nested(leaked, "retentionPolicy")["retentionPeriod"] = "1"
    assert projected.fields == expected_locked()
    assert response.body is body


def test_invalid_late_selected_field_cannot_admit_earlier_fields() -> None:
    data = fixture()
    nested(data, "objectRetention")["mode"] = ["Enabled"]
    result = read(data)
    assert result.status == "unavailable" and result.projection is None
    assert codes(result) == ["invalid_response"]
    assert result.raw_bytes > 0 and result.decoded_bytes > 0


def test_selected_projection_limit_uses_shared_specific_diagnostic() -> None:
    data = fixture()
    nested(data, "objectRetention")["mode"] = "x" * 16_384
    result = read(data)
    assert result.status == "unavailable" and result.projection is None
    assert codes(result) == ["projection_limit"]
    assert result.raw_bytes == result.decoded_bytes > 16_384


def test_omitted_etag_stays_null_without_erasing_metageneration() -> None:
    body = (FIXTURES / "bucket-no-policy.json").read_bytes()
    active, _, _ = session([Reply(body, headers=[])])
    try:
        result = read_gcs(GcsTarget(bucket=BUCKET), active)[0]
        assert result.status == "complete" and result.projection is not None
        assert result.projection.source_etag is None
        assert result.projection.source_metageneration == "3"
    finally:
        active.close()
