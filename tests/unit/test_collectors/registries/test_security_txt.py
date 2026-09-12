"""Keep ordered security.txt evidence separate from its finite syntax checks."""

from __future__ import annotations

import hashlib
import socket
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from evidentia_collectors.registries import _client, security_txt
from evidentia_collectors.registries._contracts import RegistryInputError
from evidentia_core import network_guard

FIXTURES = Path(__file__).parents[3] / "fixtures/registries/security_txt"
NOW = datetime(2026, 9, 12, 12, tzinfo=UTC)
URL = "https://example.org/.well-known/security.txt"
Reply = tuple[int, bytes, dict[str, str]]
Transport = tuple[list[Reply], list[httpx.Request]]
EXPECTED_FIELDS: list[dict[str, Any]] = [
    {"name": "Contact", "value": " mailto:security@example.org", "source_line": 1, "body_line": 1},
    {"name": "Contact", "value": " https://example.org/security", "source_line": 2, "body_line": 2},
    {"name": "Expires", "value": " 2026-10-01t00:00:00z", "source_line": 3, "body_line": 3},
    {"name": "Preferred-Languages", "value": " en, fr", "source_line": 4, "body_line": 4},
    {"name": "Canonical", "value": " https://example.org/.well-known/security.txt", "source_line": 5, "body_line": 5},
    {"name": "Encryption", "value": " https://example.org/public-key.txt", "source_line": 6, "body_line": 6},
    {"name": "Acknowledgments", "value": " https://example.org/thanks", "source_line": 7, "body_line": 7},
    {"name": "Policy", "value": " https://example.org/policy", "source_line": 8, "body_line": 8},
    {"name": "Hiring", "value": " https://example.org/jobs", "source_line": 9, "body_line": 9},
]


def raw_fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes().replace(b"\r\n", b"\n")


@pytest.fixture
def transport(monkeypatch: pytest.MonkeyPatch) -> Iterator[Transport]:
    replies: list[Reply] = []
    requests: list[httpx.Request] = []
    original = socket.getaddrinfo
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", original)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))],
    )

    def send(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        status, body, headers = replies.pop(0)
        return httpx.Response(status, stream=httpx.ByteStream(body), headers=headers)

    monkeypatch.setattr(_client, "_http_transport", lambda context, approved, owned: httpx.MockTransport(send))
    with network_guard.offline_mode(False):
        yield replies, requests


def session(hostname: str = "example.org") -> _client.RegistryReadSession:
    return _client.RegistryReadSession(
        {"registry": "security-txt", "target": {"hostname": hostname}}, _utc=lambda: NOW, _monotonic=lambda: 0.0
    )


def append_text(transport: Transport, body: bytes, media: str = "text/plain; charset=utf-8") -> None:
    transport[0].append((200, body, {"Content-Type": media}))


def test_projector_copies_only_reviewed_adapter_fields() -> None:
    source = {
        "fields": [dict(field, extra="DO-NOT-RETAIN") for field in EXPECTED_FIELDS],
        "signed": False,
        "signature_state": "not_applicable",
        "extra": "DO-NOT-RETAIN",
    }
    selected = security_txt.project_security_txt(source)
    assert selected == {"fields": EXPECTED_FIELDS, "signed": False, "signature_state": "not_applicable"}
    selected["fields"][0]["value"] = "changed"
    assert cast(list[dict[str, Any]], source["fields"])[0]["value"] == " mailto:security@example.org"


@pytest.mark.parametrize("hostname", ["example.org", "EXAMPLE.ORG", "EXAMPLE.ORG."])
@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
def test_complete_evidence_and_checks_preserve_order_and_original_request(
    transport: Transport, hostname: str, newline: bytes
) -> None:
    body = raw_fixture("valid.txt").replace(b"\n", newline)
    append_text(transport, body)
    current = session(hostname)
    result = security_txt.lookup(current)
    assert result.lookup_outcome == "found" and result.collection_status == "complete"
    observation = result.observations[0]
    assert observation.fields == {"fields": EXPECTED_FIELDS, "signed": False, "signature_state": "not_applicable"}
    assert observation.matched_identity == "example.org"
    assert observation.source_identity["hostname"] == "example.org"
    assert observation.source_identity["initial_retrieval_uri"] == URL
    checks = cast(dict[str, Any], observation.source_identity["controller_checks"])
    assert checks["contact_present"] is True and checks["expires_single"] is True
    assert checks["preferred_languages_at_most_one"] is True
    assert checks["expires_normalized_utc"] == "2026-10-01T00:00:00.000000Z"
    assert checks["expiry_relation"] == "after" and checks["canonical_lists_retrieval_uri"] is True
    assert checks["uri_semantic_validation"] == checks["language_registry_validation"] == "not_performed"
    assert result.source_reads[0].source_digest == hashlib.sha256(body).hexdigest()
    assert result.source_reads[0].raw_bytes == result.source_reads[0].decoded_bytes == len(body)
    assert [str(request.url) for request in transport[1]] == [URL]
    dumped = result.model_dump(mode="json")
    assert dumped["findings"][0]["raw_data"]["observation"] == dumped["observations"][0]
    assert dumped["findings"][0]["compliance_status"] == "unknown"
    assert current.request.model_dump(mode="json")["target"]["hostname"] == hostname
    assert security_txt.lookup(current).model_dump(mode="json") == dumped and len(transport[1]) == 1


def test_expired_source_is_stale_evidence_not_a_compliance_verdict(transport: Transport) -> None:
    append_text(transport, raw_fixture("expired.txt"))
    result = security_txt.lookup(session())
    assert result.lookup_outcome == "found" and result.collection_status == "complete"
    assert result.source_reads[0].freshness == "stale"
    assert [item.code for item in result.diagnostics] == ["expired_source"]
    assert result.model_dump(mode="json")["findings"][0]["compliance_status"] == "unknown"


def test_duplicate_singletons_preserve_all_occurrences_and_report_syntax(transport: Transport) -> None:
    append_text(transport, raw_fixture("duplicate-singleton.txt"))
    result = security_txt.lookup(session())
    assert result.lookup_outcome == "found"
    fields = cast(list[dict[str, Any]], result.observations[0].fields["fields"])
    assert [field["name"] for field in fields] == [
        "Contact",
        "Expires",
        "Expires",
        "Preferred-Languages",
        "Preferred-Languages",
    ]
    checks = cast(dict[str, Any], result.observations[0].source_identity["controller_checks"])
    assert checks["expires_count"] == 2 and checks["expires_single"] is False
    assert checks["preferred_languages_at_most_one"] is False
    assert {item.code for item in result.diagnostics} == {"syntax_invalid", "source_time_unsupported"}


def test_unknown_optional_fields_and_repeated_defined_values_remain_ordered(transport: Transport) -> None:
    append_text(transport, raw_fixture("unknown-fields.txt"))
    result = security_txt.lookup(session())
    fields = cast(list[dict[str, Any]], result.observations[0].fields["fields"])
    assert [(field["name"], field["value"]) for field in fields[2:]] == [
        ("X-Custom", " future optional text"),
        ("X-Custom", " "),
        ("Preferred-Languages", " en"),
        ("Policy", " https://example.org/policy"),
        ("Policy", " https://example.org/another-policy"),
    ]
    assert {item.code for item in result.diagnostics} == {"syntax_invalid"}


def test_cleartext_template_is_framed_in_memory_and_signature_stays_unverified(transport: Transport) -> None:
    body = raw_fixture("signed-unverified.txt").replace(b"\n", b"\r\n")
    append_text(transport, body)
    result = security_txt.lookup(session())
    assert result.lookup_outcome == "found" and result.collection_status == "complete"
    assert result.observations[0].fields == {
        "fields": [
            {"name": "Contact", "value": " mailto:security@example.org", "source_line": 4, "body_line": 1},
            {"name": "Expires", "value": " 2026-10-01T00:00:00Z", "source_line": 5, "body_line": 2},
            {"name": "-X-Note", "value": " retained", "source_line": 6, "body_line": 3},
        ],
        "signed": True,
        "signature_state": "unverified",
    }
    assert result.source_reads[0].source_signature == "unverified"
    assert {item.code for item in result.diagnostics} == {"signature_unverified"}
    assert result.source_reads[0].source_digest == hashlib.sha256(body).hexdigest()


@pytest.mark.parametrize("body,media", [(b"<html>not source</html>", "text/html"), (b"\xff", "text/plain")])
def test_bad_text_or_media_does_not_become_an_observation(transport: Transport, body: bytes, media: str) -> None:
    append_text(transport, body, media)
    result = security_txt.lookup(session())
    assert result.lookup_outcome == "unavailable" and not result.observations
    assert [item.code for item in result.diagnostics] == ["invalid_response"]


def test_raw_response_cap_charges_refused_complete_chunk(transport: Transport) -> None:
    body = b"#" + b"a" * 65536
    append_text(transport, body)
    result = security_txt.lookup(session())
    assert result.lookup_outcome == "unavailable" and not result.observations
    assert [item.code for item in result.diagnostics] == ["body_limit"]
    assert result.source_reads[0].raw_bytes == len(body)


def test_unicode_separator_does_not_create_a_new_contact(transport: Transport) -> None:
    body = "Contact: mailto:security@example.org\u2028Contact: mailto:second@example.org\nExpires: 2026-10-01T00:00:00Z\n".encode()
    append_text(transport, body)
    result = security_txt.lookup(session())
    fields = cast(list[dict[str, Any]], result.observations[0].fields["fields"])
    assert (
        len(fields) == 2
        and fields[0]["value"] == " mailto:security@example.org\u2028Contact: mailto:second@example.org"
    )
    assert {item.code for item in result.diagnostics} == {"syntax_invalid"}


@pytest.mark.parametrize(
    "expiry,relation,normalized,diagnostic",
    [
        ("2026-09-12t12:00:00z", "equal", "2026-09-12T12:00:00.000000Z", None),
        ("2026-09-12T13:00:00+01:00", "equal", "2026-09-12T12:00:00.000000Z", None),
        ("2026-09-12T12:00:00.000000000Z", "equal", "2026-09-12T12:00:00.000000Z", None),
        ("2026-09-12T12:00:00.0000001Z", "unknown", None, "source_time_unsupported"),
        ("2026-09-12T12:00:00-00:00", "unknown", None, "source_time_unsupported"),
        ("2026-12-31T23:59:60Z", "unknown", None, "source_time_unsupported"),
        ("2028-09-12T12:00:00Z", "after", "2028-09-12T12:00:00.000000Z", "expiry_beyond_one_year"),
    ],
)
def test_expiry_comparison_is_exact_and_unsupported_instants_remain_unknown(
    transport: Transport, expiry: str, relation: str, normalized: str | None, diagnostic: str | None
) -> None:
    append_text(transport, ("Contact: mailto:security@example.org\nExpires: " + expiry + "\n").encode())
    result = security_txt.lookup(session())
    assert result.lookup_outcome == "found"
    checks = cast(dict[str, Any], result.observations[0].source_identity["controller_checks"])
    assert checks["expiry_relation"] == relation and checks["expires_normalized_utc"] == normalized
    fields = cast(list[dict[str, Any]], result.observations[0].fields["fields"])
    assert fields[1]["value"] == " " + expiry
    assert ([item.code for item in result.diagnostics]) == ([] if diagnostic is None else [diagnostic])


@pytest.mark.parametrize(
    "location", ["https://other.example.org/security.txt", "https:security.txt", "/.well-known/security.txt"]
)
def test_redirect_refusals_never_fetch_links_or_legacy_fallback(transport: Transport, location: str) -> None:
    transport[0].append((302, b"", {"Location": location}))
    result = security_txt.lookup(session())
    assert result.lookup_outcome == "unavailable" and len(transport[1]) == 1
    assert [item.code for item in result.diagnostics] == ["redirect_refused"]


def test_same_origin_redirect_records_scope_and_canonical_conflict(transport: Transport) -> None:
    transport[0].append((302, b"", {"Location": "/security/notice.txt"}))
    append_text(transport, raw_fixture("valid.txt"))
    result = security_txt.lookup(session())
    assert result.lookup_outcome == "found"
    assert result.observations[0].source_identity["retrieval_uri"] == "https://example.org/security/notice.txt"
    assert len(transport[1]) == 2 and {item.code for item in result.diagnostics} == {"syntax_invalid"}


def test_redirect_cap_is_three_and_does_not_restart(transport: Transport) -> None:
    transport[0].extend((302, b"", {"Location": "/hop" + str(i)}) for i in range(4))
    current = session()
    result = security_txt.lookup(current)
    assert result.lookup_outcome == "unavailable" and len(transport[1]) == 4
    assert [item.code for item in result.diagnostics] == ["redirect_refused"]
    assert security_txt.lookup(current).model_dump(mode="json") == result.model_dump(mode="json")
    assert len(transport[1]) == 4


def test_missing_contact_is_visible_without_losing_other_source_fields(transport: Transport) -> None:
    append_text(transport, b"Expires: 2026-10-01T00:00:00Z\nPolicy: https://example.org/policy\n")
    result = security_txt.lookup(session())
    assert result.lookup_outcome == "found"
    assert {item.code for item in result.diagnostics} == {"syntax_invalid"}
    assert cast(dict[str, Any], result.observations[0].source_identity["controller_checks"])["contact_present"] is False


def test_wrong_selector_and_offline_refuse_without_a_request(transport: Transport) -> None:
    with pytest.raises(RegistryInputError):
        security_txt.lookup(_client.RegistryReadSession({"registry": "tls", "target": {"hostname": "example.org"}}))
    with network_guard.offline_mode():
        result = security_txt.lookup(session())
    assert [item.code for item in result.diagnostics] == ["offline_refused"] and transport[1] == []


def test_bare_carriage_return_stays_in_one_invalid_source_line(transport: Transport) -> None:
    append_text(transport, b"Contact: x\rExpires: 2026-10-01T00:00:00Z\r")
    result = security_txt.lookup(session())
    assert result.lookup_outcome == "found"
    assert result.observations[0].fields["fields"] == [
        {"name": "Contact", "value": " x\rExpires: 2026-10-01T00:00:00Z\r", "source_line": 1, "body_line": 1}
    ]
    assert {item.code for item in result.diagnostics} == {"syntax_invalid", "source_time_unsupported"}
