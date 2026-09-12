"""Check exact LEI identity and independent selected GLEIF field expectations."""

from __future__ import annotations

import copy
import hashlib
import json
import socket
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from evidentia_collectors.registries import _client, gleif
from evidentia_collectors.registries._contracts import RegistryInputError
from evidentia_core import network_guard

FIXTURES = Path(__file__).parents[3] / "fixtures/registries/gleif"
NOW = datetime(2026, 9, 12, 12, tzinfo=UTC)
LEI = "AAAAAAAAAAAAAAAAAAAA"
Reply = tuple[int, bytes, dict[str, str]]
Transport = tuple[list[Reply], list[httpx.Request]]
EXPECTED_ACTIVE: dict[str, Any] = {
    "id": LEI,
    "type": "lei-records",
    "attributes": {
        "lei": LEI,
        "entity": {
            "legalName": {"name": "Synthetic Example Organization", "language": "en"},
            "status": "ACTIVE",
            "successorEntities": [],
        },
        "registration": {
            "initialRegistrationDate": "2020-01-02T03:04:05Z",
            "lastUpdateDate": "2026-09-01T12:00:00Z",
            "status": "ISSUED",
            "nextRenewalDate": "2027-01-02T03:04:05Z",
        },
    },
}


def raw_fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes().replace(b"\r\n", b"\n")


def fixture(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(raw_fixture(name)))


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


def session() -> _client.RegistryReadSession:
    return _client.RegistryReadSession(
        {"registry": "gleif", "target": {"lei": LEI}}, _utc=lambda: NOW, _monotonic=lambda: 0.0
    )


def test_projector_excludes_unselected_envelope_and_contact_fields() -> None:
    source = fixture("lei-active.json")["data"]
    projected = gleif.project_gleif(source)
    assert projected == EXPECTED_ACTIVE
    projected["attributes"]["entity"]["legalName"]["name"] = "changed"
    assert source["attributes"]["entity"]["legalName"]["name"] == "Synthetic Example Organization"


def test_single_lei_reader_uses_fixed_path_and_keeps_complete_evidence(transport: Transport) -> None:
    replies, requests = transport
    body = raw_fixture("lei-active.json")
    replies.append((200, body, {"Content-Type": "application/vnd.api+json"}))
    current = session()
    result = gleif.lookup(current)
    assert result.lookup_outcome == "found" and result.collection_status == "complete"
    assert len(result.observations) == len(result.findings) == 1
    assert result.observations[0].fields == EXPECTED_ACTIVE
    assert result.observations[0].source_identity == {"lei": LEI}
    assert result.observations[0].match_basis == "exact_identifier"
    assert result.source_reads[0].source_digest == hashlib.sha256(body).hexdigest()
    assert result.source_reads[0].raw_bytes == result.source_reads[0].decoded_bytes == len(body)
    assert str(requests[0].url) == "https://api.gleif.org/api/v1/lei-records/" + LEI
    assert "DO-NOT-RETAIN" not in result.model_dump_json()
    dumped = result.model_dump(mode="json")
    assert dumped["findings"][0]["raw_data"]["observation"] == dumped["observations"][0]
    assert dumped["findings"][0]["compliance_status"] == "unknown"
    assert dumped["findings"][0]["severity"] == "informational" and dumped["findings"][0]["control_mappings"] == []
    assert gleif.lookup(current).model_dump(mode="json") == dumped and len(requests) == 1


def test_lapsed_registration_does_not_replace_active_entity_or_successors(transport: Transport) -> None:
    replies, _ = transport
    replies.append((200, raw_fixture("lei-lapsed-successors.json"), {}))
    result = gleif.lookup(session())
    assert result.lookup_outcome == "found" and result.collection_status == "complete"
    attributes = cast(dict[str, Any], result.observations[0].fields["attributes"])
    assert attributes["entity"]["status"] == "ACTIVE"
    assert attributes["registration"]["status"] == "LAPSED"
    assert attributes["entity"]["successorEntities"] == [
        {"lei": "BBBBBBBBBBBBBBBBBBBB", "name": "First synthetic successor"},
        {"lei": "CCCCCCCCCCCCCCCCCCCC", "name": "Second synthetic successor"},
    ]
    assert len(result.observations) == 1


def test_unknown_status_null_and_literal_dates_remain_distinct(transport: Transport) -> None:
    replies, _ = transport
    replies.append((200, raw_fixture("unknown-null.json"), {}))
    result = gleif.lookup(session())
    assert result.lookup_outcome == "found" and result.collection_status == "complete"
    observation = result.observations[0]
    attributes = cast(dict[str, Any], observation.fields["attributes"])
    assert attributes["entity"] == {
        "legalName": None,
        "status": "FUTURE_ENTITY_STATUS",
        "successorEntities": [None, {}, {"lei": None, "name": ""}],
    }
    assert attributes["registration"]["status"] == "FUTURE_REGISTRATION_STATUS"
    assert observation.field_coverage["/attributes/entity/legalName"] == "null"
    times = {time.path: (time.literal, time.normalized_utc) for time in observation.source_times}
    assert times["/attributes/registration/initialRegistrationDate"] == (None, None)
    assert times["/attributes/registration/lastUpdateDate"] == ("2026-09-12T12:00:00.0000001Z", None)
    assert times["/attributes/registration/nextRenewalDate"] == ("2026-10-01", None)
    assert {item.code for item in result.diagnostics} == {"source_time_unsupported"}


@pytest.mark.parametrize(
    "where,value",
    [
        ("id", "B" * 20),
        ("id", None),
        ("id", 1),
        ("type", "other"),
        ("type", None),
        ("lei", "B" * 20),
        ("lei", True),
        ("lei", None),
    ],
)
def test_source_identity_refusal_is_visible_and_never_a_resource(
    transport: Transport, where: str, value: object
) -> None:
    replies, requests = transport
    body = fixture("lei-active.json")
    target = body["data"]["attributes"] if where == "lei" else body["data"]
    target[where] = value
    replies.append((200, json.dumps(body).encode(), {}))
    result = gleif.lookup(session())
    assert result.lookup_outcome == "unavailable" and not result.observations and not result.findings
    assert [item.code for item in result.diagnostics] == ["identity_mismatch"]
    assert len(requests) == 1


def test_saved_identity_mismatch_fixture_is_refused(transport: Transport) -> None:
    replies, _ = transport
    replies.append((200, raw_fixture("identity-mismatch.json"), {}))
    assert [item.code for item in gleif.lookup(session()).diagnostics] == ["identity_mismatch"]


@pytest.mark.parametrize("field,value", [("status", True), ("successorEntities", "wrong-array"), ("legalName", 4)])
def test_wrong_selected_type_is_not_silently_dropped(transport: Transport, field: str, value: object) -> None:
    replies, _ = transport
    body = fixture("lei-active.json")
    body["data"]["attributes"]["entity"][field] = value
    replies.append((200, json.dumps(body).encode(), {}))
    result = gleif.lookup(session())
    assert result.lookup_outcome == "unavailable" and not result.observations
    assert [item.code for item in result.diagnostics] == ["invalid_response"]


def test_absent_empty_and_null_nested_objects_preserve_shape() -> None:
    base: dict[str, Any] = {"id": LEI, "type": "lei-records", "attributes": {"lei": LEI}}
    assert gleif.project_gleif(base) == base
    values: tuple[dict[str, Any] | None, ...] = (None, {})
    for value in values:
        source = copy.deepcopy(base)
        source["attributes"]["entity"] = value
        assert gleif.project_gleif(source)["attributes"]["entity"] == value


def test_wrong_selector_is_refused_without_io(transport: Transport) -> None:
    current = _client.RegistryReadSession({"registry": "tls", "target": {"hostname": "example.org"}})
    with pytest.raises(RegistryInputError):
        gleif.lookup(current)
    assert transport[1] == []


def test_offline_is_unavailable_without_a_request(transport: Transport) -> None:
    with network_guard.offline_mode():
        result = gleif.lookup(session())
    assert result.lookup_outcome == "unavailable" and result.source_reads[0].network_attempts == 0
    assert [item.code for item in result.diagnostics] == ["offline_refused"]
    assert transport[1] == []


@pytest.mark.parametrize("mode", ["absent", "null", "empty", "null_dates"])
def test_missing_and_null_source_dates_do_not_claim_unsupported_comparison(transport: Transport, mode: str) -> None:
    body = fixture("lei-active.json")
    attributes = body["data"]["attributes"]
    if mode == "absent":
        attributes.pop("registration")
    elif mode == "null":
        attributes["registration"] = None
    elif mode == "empty":
        attributes["registration"] = {}
    else:
        attributes["registration"] = {"initialRegistrationDate": None, "lastUpdateDate": None, "nextRenewalDate": None}
    transport[0].append((200, json.dumps(body).encode(), {}))
    result = gleif.lookup(session())
    assert result.lookup_outcome == "found" and result.diagnostics == []
    selected = cast(dict[str, Any], result.observations[0].fields["attributes"])
    if mode == "absent":
        assert "registration" not in selected
    else:
        assert selected["registration"] == attributes["registration"]
