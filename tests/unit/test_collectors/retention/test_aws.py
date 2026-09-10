"""Synthetic S3 XML fidelity and shared-session integration controls."""

from __future__ import annotations

import socket
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from evidentia_collectors.retention._client import StorageReadSession
from evidentia_collectors.retention._contracts import (
    S3Target,
    StorageRetentionCollectResult,
    StorageRetentionComponentResult,
    make_result,
)
from evidentia_collectors.retention._credentials import AwsCredentials, CredentialResolution
from evidentia_collectors.retention._parsing import JsonObject
from evidentia_collectors.retention.aws import read_s3
from evidentia_core import network_guard

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "retention" / "aws"
NS = "http://s3.amazonaws.com/doc/2006-03-01/"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def lock(contents: str, namespace: str = "") -> bytes:
    declaration = f' xmlns="{namespace}"' if namespace else ""
    return f"<ObjectLockConfiguration{declaration}>{contents}</ObjectLockConfiguration>".encode()


def versioning(contents: str, namespace: str = "") -> bytes:
    declaration = f' xmlns="{namespace}"' if namespace else ""
    return f"<VersioningConfiguration{declaration}>{contents}</VersioningConfiguration>".encode()


@dataclass(frozen=True)
class Reply:
    body: bytes
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)


class Stream(httpx.SyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.closed = 0

    def __iter__(self) -> Iterator[bytes]:
        yield self.body[:7]
        yield self.body[7:31]
        yield self.body[31:]

    def close(self) -> None:
        self.closed += 1


class Wire(httpx.BaseTransport):
    def __init__(self, replies: list[Reply]) -> None:
        self.replies = list(replies)
        self.requests: list[httpx.Request] = []
        self.streams: list[Stream] = []
        self.closed = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        addresses = socket.getaddrinfo(request.url.host, 443)
        assert {str(item[4][0]) for item in addresses} == {"8.8.8.8"}
        assert self.replies, "Unexpected synthetic send"
        reply = self.replies.pop(0)
        self.requests.append(request)
        stream = Stream(reply.body)
        self.streams.append(stream)
        return httpx.Response(reply.status, headers=reply.headers, stream=stream)

    def close(self) -> None:
        self.closed += 1


class Credentials:
    def __init__(self) -> None:
        self.calls = 0

    def resolve(self, provider: str) -> CredentialResolution:
        assert provider == "s3"
        self.calls += 1
        return CredentialResolution(AwsCredentials("SYNTHETIC_ACCESS", "SYNTHETIC_SECRET"), None)


MakeSession = Callable[[list[Reply]], tuple[S3Target, StorageReadSession, Wire, Credentials]]


@pytest.fixture
def session(monkeypatch: pytest.MonkeyPatch) -> Iterator[MakeSession]:
    sessions: list[tuple[StorageReadSession, Wire]] = []
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", network_guard._GETADDRINFO_DELEGATE)
    monkeypatch.setattr(network_guard, "_offline_enabled", False)

    def refuse_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("Real DNS and socket calls are forbidden")

    monkeypatch.setattr(socket, "getaddrinfo", refuse_network)
    monkeypatch.setattr(socket, "create_connection", refuse_network)
    monkeypatch.setattr(socket.socket, "connect", refuse_network)
    monkeypatch.setattr(network_guard, "enforce_public_host", lambda *args, **kwargs: ["8.8.8.8"])

    def make(replies: list[Reply]) -> tuple[S3Target, StorageReadSession, Wire, Credentials]:
        target = S3Target(bucket="synthetic-retention", region="us-east-1", expected_owner="123456789012")
        wire = Wire(replies)
        credentials = Credentials()
        seconds = [0.0]

        def wait(delay: float) -> None:
            seconds[0] += delay

        value = StorageReadSession(
            {"provider": "s3", "scope_label": "synthetic", "targets": [target.model_dump()]},
            credentials=credentials,
            transport_factory=lambda: wire,
            monotonic_clock=lambda: seconds[0],
            utc_clock=lambda: datetime(2025, 1, 2, 3, 4, 5, 123456, tzinfo=UTC),
            sleep=wait,
            run_id_factory=lambda: "synthetic_run",
        )
        sessions.append((value, wire))
        return target, value, wire, credentials

    yield make
    for value, wire in sessions:
        value.close()
        assert wire.closed == (1 if wire.requests else 0)
        assert all(stream.closed == 1 for stream in wire.streams)


def fields(result: StorageRetentionComponentResult) -> JsonObject:
    assert result.projection is not None
    return result.projection.fields


def codes(result: StorageRetentionComponentResult) -> list[str]:
    return [item.code for item in result.diagnostics]


@pytest.mark.parametrize(
    "lock_fixture,version_fixture,expected_lock,expected_version",
    [
        (
            "lock-governance-days.xml",
            "versioning-enabled-mfa.xml",
            {"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 37}}},
            {"Status": "Enabled", "MFADelete": "Enabled"},
        ),
        (
            "lock-compliance-years.xml",
            "versioning-suspended.xml",
            {"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Years": 4}}},
            {"Status": "Suspended"},
        ),
        (
            "lock-enabled-no-default.xml",
            "versioning-never-enabled.xml",
            {"ObjectLockEnabled": "Enabled"},
            {},
        ),
    ],
)
def test_documented_projection_and_real_session_order(
    session: MakeSession,
    lock_fixture: str,
    version_fixture: str,
    expected_lock: JsonObject,
    expected_version: JsonObject,
) -> None:
    first_body, second_body = fixture(lock_fixture), fixture(version_fixture)
    target, value, wire, credentials = session(
        [Reply(first_body, headers={"ETag": '"synthetic-lock"'}), Reply(second_body)]
    )
    results = read_s3(target, value)
    assert [item.component_id for item in results] == ["s3-object-lock", "s3-versioning"]
    assert [item.status for item in results] == ["complete", "complete"]
    assert fields(results[0]) == expected_lock
    assert fields(results[1]) == expected_version
    assert [(item.raw_bytes, item.decoded_bytes) for item in results] == [
        (len(first_body), len(first_body)),
        (len(second_body), len(second_body)),
    ]
    assert [request.url.raw_path for request in wire.requests] == [
        b"/synthetic-retention?object-lock",
        b"/synthetic-retention?versioning",
    ]
    assert all(request.method == "GET" and request.content == b"" for request in wire.requests)
    assert all(request.headers["x-amz-expected-bucket-owner"] == "123456789012" for request in wire.requests)
    assert credentials.calls == 1
    projection = results[0].projection
    assert projection is not None
    assert projection.api_version == "2006-03-01" and projection.native_scope == "bucket"
    assert projection.source_etag == '"synthetic-lock"'
    final = make_result(
        value.context.request,
        run_id=value.context.run_id,
        started_at=value.context.started_at,
        finished_at=value.context.utc_now(),
        components={"s3:us-east-1:synthetic-retention": results},
        diagnostics=(),
    )
    restored = StorageRetentionCollectResult.model_validate_json(final.model_dump_json(warnings="error"))
    assert restored.status == "complete" and len(restored.findings) == 1
    assert restored.findings[0].control_mappings == []
    assert restored.findings[0].compliance_status.value == "unknown"


def test_only_exact_404_error_is_complete_absence(session: MakeSession) -> None:
    target, value, _, _ = session(
        [Reply(fixture("lock-absent-error.xml"), 404), Reply(fixture("versioning-never-enabled.xml"))]
    )
    result = read_s3(target, value)[0]
    assert result.status == "complete" and result.http_status == 404
    assert fields(result) == {} and codes(result) == []
    assert "Synthetic absence detail" not in result.model_dump_json()


@pytest.mark.parametrize("namespace", ["", NS])
def test_consistent_documented_namespaces(session: MakeSession, namespace: str) -> None:
    target, value, _, _ = session(
        [
            Reply(lock("<ObjectLockEnabled>Enabled</ObjectLockEnabled>", namespace)),
            Reply(versioning("<Status>Enabled</Status><MfaDelete>Disabled</MfaDelete>", namespace)),
        ]
    )
    results = read_s3(target, value)
    assert fields(results[0]) == {"ObjectLockEnabled": "Enabled"}
    assert fields(results[1]) == {"Status": "Enabled", "MFADelete": "Disabled"}


def test_prefixed_documented_namespace_and_scalar_text_are_preserved(session: MakeSession) -> None:
    body = (
        f'<s:ObjectLockConfiguration xmlns:s="{NS}"><s:ObjectLockEnabled>Enabled</s:ObjectLockEnabled>'
        "<s:Rule><s:DefaultRetention><s:Mode>FUTURE&#xA0;MODE</s:Mode><s:Days>9</s:Days>"
        "</s:DefaultRetention></s:Rule></s:ObjectLockConfiguration>"
    ).encode()
    target, value, _, _ = session([Reply(body), Reply(versioning(""))])
    result = read_s3(target, value)[0]
    assert fields(result) == {
        "ObjectLockEnabled": "Enabled",
        "Rule": {"DefaultRetention": {"Mode": "FUTURE\u00a0MODE", "Days": 9}},
    }
    assert result.status == "partial" and codes(result) == ["unsupported_source_value"]


@pytest.mark.parametrize(
    "content,expected,expected_codes",
    [
        ("", {}, ["missing_source_detail"]),
        ("<ObjectLockEnabled/>", {"ObjectLockEnabled": ""}, ["unsupported_source_value"]),
        (
            "<ObjectLockEnabled>Disabled</ObjectLockEnabled>",
            {"ObjectLockEnabled": "Disabled"},
            ["unsupported_source_value"],
        ),
        (
            "<ObjectLockEnabled> Enabled </ObjectLockEnabled>",
            {"ObjectLockEnabled": " Enabled "},
            ["unsupported_source_value"],
        ),
        (
            "<ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule/>",
            {"ObjectLockEnabled": "Enabled", "Rule": {}},
            ["missing_source_detail"],
        ),
        (
            "<ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention/></Rule>",
            {"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {}}},
            ["missing_source_detail"],
        ),
        (
            "<ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Days>7</Days></DefaultRetention></Rule>",
            {"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Days": 7}}},
            ["missing_source_detail"],
        ),
        (
            "<ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode></DefaultRetention></Rule>",
            {"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE"}}},
            ["missing_source_detail"],
        ),
    ],
)
def test_missing_and_unknown_lock_detail_is_partial(
    session: MakeSession, content: str, expected: JsonObject, expected_codes: list[str]
) -> None:
    target, value, _, _ = session([Reply(lock(content)), Reply(versioning(""))])
    result = read_s3(target, value)[0]
    assert fields(result) == expected
    assert result.status == "partial" and codes(result) == expected_codes


@pytest.mark.parametrize(
    "content,expected,expected_codes",
    [
        ("<Status>FutureState</Status>", {"Status": "FutureState"}, ["unsupported_source_value"]),
        ("<Status/>", {"Status": ""}, ["unsupported_source_value"]),
        ("<Status> Enabled </Status>", {"Status": " Enabled "}, ["unsupported_source_value"]),
        ("<MfaDelete>Disabled</MfaDelete>", {"MFADelete": "Disabled"}, ["missing_source_detail"]),
        (
            "<Status>Enabled</Status><MfaDelete>Pending</MfaDelete>",
            {"Status": "Enabled", "MFADelete": "Pending"},
            ["unsupported_source_value"],
        ),
        (
            "<Status>Future</Status><MfaDelete>Pending</MfaDelete>",
            {"Status": "Future", "MFADelete": "Pending"},
            ["unsupported_source_value"],
        ),
    ],
)
def test_versioning_unknowns_and_omission_remain_distinct(
    session: MakeSession, content: str, expected: JsonObject, expected_codes: list[str]
) -> None:
    target, value, _, _ = session([Reply(fixture("lock-enabled-no-default.xml")), Reply(versioning(content))])
    result = read_s3(target, value)[1]
    assert fields(result) == expected
    assert result.status == "partial" and codes(result) == expected_codes


@pytest.mark.parametrize(
    "bad",
    [
        b"<VersioningConfiguration/>",
        lock("<ObjectLockEnabled>Enabled</ObjectLockEnabled>", "urn:wrong"),
        lock('<ObjectLockEnabled xmlns="">Enabled</ObjectLockEnabled>', NS),
        lock(f'<ObjectLockEnabled xmlns="{NS}">Enabled</ObjectLockEnabled>'),
        lock("<ObjectLockEnabled>Enabled</ObjectLockEnabled><ObjectLockEnabled>Enabled</ObjectLockEnabled>"),
        lock("<ObjectLockEnabled><Value>Enabled</Value></ObjectLockEnabled>"),
        lock('<ObjectLockEnabled xml:lang="en">Enabled</ObjectLockEnabled>'),
        lock('<ObjectLockEnabled xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"/>'),
        lock("<Status>Enabled</Status>"),
        lock("mixed<ObjectLockEnabled>Enabled</ObjectLockEnabled>"),
        lock("<ObjectLockEnabled>Enabled</ObjectLockEnabled>mixed"),
        lock("<Rule><DefaultRetention/><DefaultRetention/></Rule>"),
        lock("<Rule><Mode>GOVERNANCE</Mode></Rule>"),
        lock("<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>1</Days><Years>1</Years></DefaultRetention></Rule>"),
        lock("<Rule><DefaultRetention><Days>1</Days><Days>1</Days></DefaultRetention></Rule>"),
        lock("<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Mode>GOVERNANCE</Mode></DefaultRetention></Rule>"),
        b'<ObjectLockConfiguration extra="x"/>',
        b"<!DOCTYPE ObjectLockConfiguration [<!ENTITY x 'Enabled'>]><ObjectLockConfiguration><ObjectLockEnabled>&x;</ObjectLockEnabled></ObjectLockConfiguration>",
        b"<ObjectLockConfiguration>",
        b'{"ObjectLockEnabled":"Enabled"}',
    ],
)
def test_invalid_lock_component_is_atomic_and_versioning_continues(session: MakeSession, bad: bytes) -> None:
    target, value, wire, _ = session([Reply(bad), Reply(versioning("<Status>Enabled</Status>"))])
    first, second = read_s3(target, value)
    assert first.status == "unavailable" and first.projection is None
    assert codes(first) == ["invalid_response"]
    assert second.status == "complete" and fields(second) == {"Status": "Enabled"}
    assert len(wire.requests) == 2


@pytest.mark.parametrize(
    "content",
    [
        "<MFADelete>Enabled</MFADelete>",
        "<Status>Enabled</Status><Status>Enabled</Status>",
        "<MfaDelete>Enabled</MfaDelete><MfaDelete>Disabled</MfaDelete>",
        "<Status><Value>Enabled</Value></Status>",
        '<Status xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"/>',
        "<ObjectLockEnabled>Enabled</ObjectLockEnabled>",
        "<Rule/>",
        "mixed<Status>Enabled</Status>",
        "<Status>Enabled</Status>mixed",
        '<Status attr="x">Enabled</Status>',
    ],
)
def test_invalid_versioning_does_not_erase_lock(session: MakeSession, content: str) -> None:
    target, value, _, _ = session([Reply(fixture("lock-enabled-no-default.xml")), Reply(versioning(content))])
    first, second = read_s3(target, value)
    assert first.status == "complete" and fields(first) == {"ObjectLockEnabled": "Enabled"}
    assert second.status == "unavailable" and second.projection is None
    assert codes(second) == ["invalid_response"]


@pytest.mark.parametrize("unit", ["Days", "Years"])
@pytest.mark.parametrize("token", ["true", "1.0", "1e2", " 7 ", "", "null", "1_000", "++1", "\u0661", "9" * 129])
def test_duration_rejects_non_integer_scalar(session: MakeSession, unit: str, token: str) -> None:
    content = (
        "<ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention>"
        f"<Mode>GOVERNANCE</Mode><{unit}>{token}</{unit}></DefaultRetention></Rule>"
    )
    target, value, _, _ = session([Reply(lock(content)), Reply(versioning(""))])
    first = read_s3(target, value)[0]
    assert first.status == "unavailable" and first.projection is None
    assert codes(first) == ["invalid_response"]


@pytest.mark.parametrize("unit", ["Days", "Years"])
@pytest.mark.parametrize("token,number", [("1", 1), ("+7", 7), ("0007", 7), ("0", 0), ("-0", 0), ("-2", -2)])
def test_duration_preserves_native_integer_units(session: MakeSession, unit: str, token: str, number: int) -> None:
    content = (
        "<ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention>"
        f"<Mode>COMPLIANCE</Mode><{unit}>{token}</{unit}></DefaultRetention></Rule>"
    )
    target, value, _, _ = session([Reply(lock(content)), Reply(versioning(""))])
    result = read_s3(target, value)[0]
    assert fields(result) == {
        "ObjectLockEnabled": "Enabled",
        "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", unit: number}},
    }
    assert result.status == ("complete" if number > 0 else "partial")
    assert codes(result) == ([] if number > 0 else ["unsupported_source_value"])


@pytest.mark.parametrize(
    "status,code,expected,second_attempted",
    [
        (403, "AccessDenied", "forbidden", True),
        (404, "NoSuchBucket", "resource_not_found", True),
        (404, "ObjectLockConfigurationNotFoundError", "", True),
        (403, "ObjectLockConfigurationNotFoundError", "forbidden", True),
        (200, "ObjectLockConfigurationNotFoundError", "invalid_response", True),
        (401, "AccessDenied", "credential_rejected", False),
        (400, "ExpiredToken", "credential_rejected", False),
        (403, "InvalidAccessKeyId", "credential_rejected", False),
    ],
)
def test_status_and_exact_error_code_control_absence_and_latch(
    session: MakeSession, status: int, code: str, expected: str, second_attempted: bool
) -> None:
    body = f"<Error><Code>{code}</Code><Message>Synthetic source detail</Message></Error>".encode()
    replies = [Reply(body, status)]
    if second_attempted:
        replies.append(Reply(versioning("")))
    target, value, wire, credentials = session(replies)
    first, second = read_s3(target, value)
    if expected:
        assert first.status == "unavailable" and codes(first) == [expected]
    else:
        assert first.status == "complete" and fields(first) == {}
    assert second.attempts == (1 if second_attempted else 0)
    assert len(wire.requests) == (2 if second_attempted else 1) and credentials.calls == 1
    assert "Synthetic source detail" not in first.model_dump_json()


@pytest.mark.parametrize(
    "body",
    [
        b"<Error><Code>ObjectLockConfigurationNotFoundError</Code><Code>NoSuchBucket</Code></Error>",
        b"<Error><Code><Nested/></Code></Error>",
        b"<Error xmlns='urn:wrong'><Code>ObjectLockConfigurationNotFoundError</Code></Error>",
        b"<Error><Message>ObjectLockConfigurationNotFoundError</Message></Error>",
    ],
)
def test_malformed_absence_error_is_not_admitted(session: MakeSession, body: bytes) -> None:
    target, value, _, _ = session([Reply(body, 404), Reply(versioning(""))])
    first = read_s3(target, value)[0]
    assert first.status == "unavailable" and first.projection is None
    assert codes(first) == ["invalid_response"]


def test_unknown_mode_fixture_remains_literal_and_partial(session: MakeSession) -> None:
    target, value, _, _ = session([Reply(fixture("lock-unknown-mode.xml")), Reply(versioning(""))])
    first = read_s3(target, value)[0]
    assert fields(first) == {
        "ObjectLockEnabled": "Enabled",
        "Rule": {"DefaultRetention": {"Mode": "SYNTHETIC_FUTURE_MODE", "Days": 19}},
    }
    assert first.status == "partial" and codes(first) == ["unsupported_source_value"]


def test_wrong_selected_target_is_refused_before_send(session: MakeSession) -> None:
    _, value, wire, credentials = session([])
    wrong = S3Target(bucket="unselected-bucket", region="us-east-1")
    with pytest.raises(ValueError):
        read_s3(wrong, value)
    assert wire.requests == [] and credentials.calls == 0


def test_unrelated_vendor_fields_are_omitted_without_becoming_evidence(session: MakeSession) -> None:
    first_body = lock(
        "<ObjectLockEnabled>Enabled</ObjectLockEnabled>"
        "<VendorExtension><Nested sensitive='synthetic'>discard this</Nested></VendorExtension>"
        "<Rule><OtherSetting>ignored</OtherSetting><DefaultRetention>"
        "<Mode>GOVERNANCE</Mode><Days>3</Days><VendorFlag>ignored</VendorFlag>"
        "</DefaultRetention></Rule>"
    )
    second_body = versioning(
        "<Status>Enabled</Status><VendorMetadata><Status>not a selected state</Status></VendorMetadata>"
    )
    target, value, _, _ = session([Reply(first_body), Reply(second_body)])
    first, second = read_s3(target, value)
    assert first.status == second.status == "complete"
    assert fields(first) == {
        "ObjectLockEnabled": "Enabled",
        "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 3}},
    }
    assert fields(second) == {"Status": "Enabled"}
    assert "discard this" not in first.model_dump_json()


def test_duplicate_unrelated_siblings_still_reject(session: MakeSession) -> None:
    body = lock("<ObjectLockEnabled>Enabled</ObjectLockEnabled><Vendor>one</Vendor><Vendor>two</Vendor>")
    target, value, _, _ = session([Reply(body), Reply(versioning(""))])
    first = read_s3(target, value)[0]
    assert first.status == "unavailable" and codes(first) == ["invalid_response"]


def test_maximum_supported_integer_preserves_value(session: MakeSession) -> None:
    token = "9" * 128
    body = lock(
        "<ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention>"
        f"<Mode>GOVERNANCE</Mode><Days>{token}</Days></DefaultRetention></Rule>"
    )
    target, value, _, _ = session([Reply(body), Reply(versioning(""))])
    first = read_s3(target, value)[0]
    assert fields(first) == {
        "ObjectLockEnabled": "Enabled",
        "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": int(token)}},
    }


@pytest.mark.parametrize("failed", ["lock", "versioning", "both"])
def test_component_failures_derive_aggregate_status_after_round_trip(session: MakeSession, failed: str) -> None:
    first_body = b"<wrong/>" if failed in {"lock", "both"} else fixture("lock-enabled-no-default.xml")
    second_body = b"<wrong/>" if failed in {"versioning", "both"} else versioning("")
    target, value, wire, _ = session([Reply(first_body), Reply(second_body)])
    components = read_s3(target, value)
    final = make_result(
        value.context.request,
        run_id=value.context.run_id,
        started_at=value.context.started_at,
        finished_at=value.context.utc_now(),
        components={"s3:us-east-1:synthetic-retention": components},
        diagnostics=(),
    )
    restored = StorageRetentionCollectResult.model_validate_json(final.model_dump_json(warnings="error"))
    expected = "unavailable" if failed == "both" else "partial"
    assert restored.status == restored.resources[0].status == expected
    assert len(restored.findings) == (0 if failed == "both" else 1)
    assert len(wire.requests) == 2
    assert [item.projection is None for item in restored.resources[0].components] == [
        failed in {"lock", "both"},
        failed in {"versioning", "both"},
    ]


def test_absence_code_on_versioning_is_not_lock_absence(session: MakeSession) -> None:
    target, value, _, _ = session(
        [Reply(fixture("lock-enabled-no-default.xml")), Reply(fixture("lock-absent-error.xml"), 404)]
    )
    first, second = read_s3(target, value)
    assert first.status == "complete"
    assert second.status == "unavailable" and second.projection is None
    assert codes(second) == ["resource_not_found"]


@pytest.mark.parametrize("oversized", ["lock", "versioning"])
def test_oversized_selected_value_refuses_only_its_component(session: MakeSession, oversized: str) -> None:
    large_value = "X" * 16_384
    first_body = (
        lock(f"<ObjectLockEnabled>{large_value}</ObjectLockEnabled>")
        if oversized == "lock"
        else fixture("lock-enabled-no-default.xml")
    )
    second_body = versioning(f"<Status>{large_value}</Status>" if oversized == "versioning" else "")
    target, value, wire, _ = session([Reply(first_body), Reply(second_body)])
    results = read_s3(target, value)
    refused, admitted = (results[0], results[1]) if oversized == "lock" else (results[1], results[0])
    assert refused.status == "unavailable" and refused.projection is None
    assert codes(refused) == ["projection_limit"]
    assert admitted.status == "complete" and admitted.projection is not None
    assert len(wire.requests) == 2
    assert [(item.raw_bytes, item.decoded_bytes) for item in results] == [
        (len(first_body), len(first_body)),
        (len(second_body), len(second_body)),
    ]


def test_multiple_unknown_and_missing_fields_emit_each_diagnostic_once(session: MakeSession) -> None:
    target, value, _, _ = session(
        [
            Reply(
                lock(
                    "<ObjectLockEnabled>Future</ObjectLockEnabled><Rule><DefaultRetention><Mode>Future</Mode></DefaultRetention></Rule>"
                )
            ),
            Reply(versioning("<MfaDelete>Future</MfaDelete>")),
        ]
    )
    first, second = read_s3(target, value)
    for result in (first, second):
        assert result.status == "partial"
        assert codes(result) == ["unsupported_source_value", "missing_source_detail"]
        assert all(item.http_status == 200 for item in result.diagnostics)


def test_transient_lock_retry_precedes_versioning_and_charges_all_bodies(session: MakeSession) -> None:
    transient = b"Synthetic retry response"
    accepted = fixture("lock-enabled-no-default.xml")
    target, value, wire, credentials = session([Reply(transient, 503), Reply(accepted), Reply(versioning(""))])
    first, second = read_s3(target, value)
    assert first.status == second.status == "complete"
    assert (first.attempts, second.attempts) == (2, 1)
    assert (first.raw_bytes, first.decoded_bytes) == (len(transient) + len(accepted),) * 2
    assert [request.url.raw_path for request in wire.requests] == [
        b"/synthetic-retention?object-lock",
        b"/synthetic-retention?object-lock",
        b"/synthetic-retention?versioning",
    ]
    assert credentials.calls == 1
