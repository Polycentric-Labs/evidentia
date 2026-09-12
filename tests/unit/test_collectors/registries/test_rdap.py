"""Exercise exact domain evidence and the adopted IANA discovery boundary."""

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
from evidentia_collectors.registries import _client, rdap
from evidentia_collectors.registries._contracts import RegistryInputError
from evidentia_collectors.registries._snapshots import RDAPBootstrap, load_bootstrap
from evidentia_core import network_guard

FIXTURES = Path(__file__).parents[3] / "fixtures/registries/rdap"
NOW = datetime(2026, 9, 12, 12, tzinfo=UTC)
Reply = tuple[int, bytes, dict[str, str]]
Transport = tuple[list[Reply], list[httpx.Request]]
EXPECTED_FOUND: dict[str, Any] = {
    "objectClassName": "domain",
    "ldhName": "EXAMPLE.COM",
    "unicodeName": "example.com",
    "status": ["active", "future-status"],
    "events": [{"eventAction": "registration", "eventDate": "2020-01-02T03:04:05Z"}],
    "notices": [
        {
            "title": "Synthetic terms",
            "description": ["Synthetic notice."],
            "type": "remark",
            "links": [
                {
                    "rel": "terms-of-service",
                    "title": "Terms",
                    "media": "screen",
                    "type": "text/plain",
                    "hreflang": ["en"],
                }
            ],
        }
    ],
    "rdapConformance": ["rdap_level_0"],
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


def session(domain: str = "example.com", bootstrap: RDAPBootstrap | None = None) -> _client.RegistryReadSession:
    return _client.RegistryReadSession(
        {"registry": "rdap", "target": {"domain": domain}},
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        _bootstrap_factory=(lambda: bootstrap) if bootstrap is not None else load_bootstrap,
    )


def synthetic_bootstrap(services: list[Any]) -> RDAPBootstrap:
    body = json.dumps(
        {
            "description": "Authored synthetic discovery table",
            "publication": "2026-09-01T00:00:00Z",
            "version": "1.0",
            "services": services,
        },
        separators=(",", ":"),
    ).encode()
    return RDAPBootstrap(
        hashlib.sha256(body).hexdigest(),
        "2026-09-01T00:00:00Z",
        b'{"kind":"synthetic"}',
        tuple((tuple(suffixes), tuple(urls)) for suffixes, urls in services),
    )


def test_projector_preserves_selected_fields_and_excludes_personal_contacts() -> None:
    source = fixture("domain-found.json")
    selected = rdap.project_rdap(source)
    assert selected == EXPECTED_FOUND
    selected["notices"][0]["links"][0]["hreflang"].append("fr")
    assert source["notices"][0]["links"][0]["hreflang"] == ["en"]


@pytest.mark.parametrize("domain", ["example.com", "EXAMPLE.COM", "EXAMPLE.COM."])
def test_canonical_query_keeps_literal_source_and_packaged_bootstrap(transport: Transport, domain: str) -> None:
    replies, requests = transport
    body = raw_fixture("domain-found.json")
    replies.append((200, body, {"Content-Type": "application/rdap+json"}))
    current = session(domain)
    result = rdap.lookup(current)
    assert result.lookup_outcome == "found" and result.collection_status == "complete"
    observation = result.observations[0]
    assert observation.fields == EXPECTED_FOUND and observation.matched_identity == "example.com"
    identity = cast(dict[str, Any], observation.source_identity)
    assert identity["domain"] == "example.com" and identity["ldhName"] == "EXAMPLE.COM"
    assert identity["bootstrap"]["matched_suffix"] == "com"
    assert identity["bootstrap"]["selected_service_base"] == "https://rdap.verisign.com/com/v1/"
    assert identity["bootstrap"]["sha256"] == load_bootstrap().sha256
    assert str(requests[0].url) == "https://rdap.verisign.com/com/v1/domain/example.com"
    assert result.source_reads[0].source_digest == hashlib.sha256(body).hexdigest()
    assert result.source_reads[0].raw_bytes == result.source_reads[0].decoded_bytes == len(body)
    dumped = result.model_dump(mode="json")
    assert dumped["findings"][0]["raw_data"]["observation"] == dumped["observations"][0]
    assert dumped["findings"][0]["compliance_status"] == "unknown"
    assert "DO-NOT-RETAIN" not in result.model_dump_json() and "contact@example.org" not in result.model_dump_json()
    assert current.request.model_dump(mode="json")["target"]["domain"] == domain
    assert rdap.lookup(current).model_dump(mode="json") == dumped and len(requests) == 1


def test_redaction_null_missing_and_empty_values_remain_distinct(transport: Transport) -> None:
    replies, _ = transport
    replies.append((200, raw_fixture("domain-redacted.json"), {}))
    result = rdap.lookup(session())
    assert result.lookup_outcome == "found"
    fields = result.observations[0].fields
    assert fields["status"] == [] and fields["unicodeName"] is None
    assert fields["events"] == [None, {}, {"eventAction": "expiration", "eventDate": None}]
    assert fields["notices"] == [{"title": None, "description": [], "links": [None, {}], "type": None}]
    assert fields["redacted"] == [
        {
            "name": {"type": "Registrant Name", "description": "Synthetic redaction"},
            "reason": {"type": "Server policy", "description": None},
            "prePath": "$.entities[0].vcardArray",
            "postPath": None,
            "replacementPath": "",
            "pathLang": "jsonpath",
            "method": "removal",
        },
        None,
        {},
    ]
    assert result.observations[0].field_coverage["/unicodeName"] == "null"
    assert "DO-NOT-RETAIN" not in result.model_dump_json()


@pytest.mark.parametrize(
    "field,value",
    [
        ("objectClassName", "entity"),
        ("objectClassName", None),
        ("ldhName", "other.example.org"),
        ("ldhName", None),
        ("ldhName", 1),
        ("ldhName", "ex\u00e4mple.com"),
    ],
)
def test_wrong_or_missing_domain_identity_refuses_resource(transport: Transport, field: str, value: object) -> None:
    body = fixture("domain-found.json")
    body[field] = value
    transport[0].append((200, json.dumps(body).encode(), {}))
    result = rdap.lookup(session())
    assert result.lookup_outcome == "unavailable" and not result.observations
    assert [item.code for item in result.diagnostics] == ["identity_mismatch"]


def test_saved_identity_mismatch_is_unavailable(transport: Transport) -> None:
    transport[0].append((200, raw_fixture("identity-mismatch.json"), {}))
    assert [item.code for item in rdap.lookup(session()).diagnostics] == ["identity_mismatch"]


def test_conflicting_unicode_name_is_literal_and_visible(transport: Transport) -> None:
    body = fixture("domain-found.json")
    body["unicodeName"] = "other.example.org"
    transport[0].append((200, json.dumps(body).encode(), {}))
    result = rdap.lookup(session())
    assert result.lookup_outcome == "found"
    assert result.observations[0].fields["unicodeName"] == "other.example.org"
    assert [item.code for item in result.diagnostics] == ["source_name_conflict"]


def test_longest_label_suffix_and_first_https_base_keep_source_order(transport: Transport) -> None:
    bootstrap = synthetic_bootstrap(
        [
            [["com"], ["https://fallback.example.org/"]],
            [
                ["example.com"],
                ["http://rdap.example.org/base/", "https://rdap.example.org/base/", "https://second.example.org/"],
            ],
        ]
    )
    transport[0].append((200, raw_fixture("domain-found.json"), {}))
    result = rdap.lookup(session(bootstrap=bootstrap))
    assert result.lookup_outcome == "found"
    identity = cast(dict[str, Any], result.observations[0].source_identity)
    assert identity["bootstrap"]["matched_suffix"] == "example.com"
    assert identity["bootstrap"]["alternatives"] == [
        "http://rdap.example.org/base/",
        "https://rdap.example.org/base/",
        "https://second.example.org/",
    ]
    assert str(transport[1][0].url) == "https://rdap.example.org/base/domain/example.com"


def test_http_only_discovery_never_rewrites_scheme_or_requests(transport: Transport) -> None:
    body = fixture("bootstrap-http-only.json")
    result = rdap.lookup(session(bootstrap=synthetic_bootstrap(body["services"])))
    assert result.lookup_outcome == "unavailable" and transport[1] == []
    assert [item.code for item in result.diagnostics] == ["destination_refused"]


@pytest.mark.parametrize(
    "location",
    [
        "https://other.example.org/base/domain/example.com",
        "/outside/domain/example.com",
        "/base/%2e%2e/domain/example.com",
        "https:domain/example.com",
    ],
)
def test_redirect_cannot_escape_selected_service(transport: Transport, location: str) -> None:
    bootstrap = synthetic_bootstrap([[["com"], ["https://rdap.example.org/base/"]]])
    transport[0].append((302, b"", {"Location": location}))
    result = rdap.lookup(session(bootstrap=bootstrap))
    assert result.lookup_outcome == "unavailable" and len(transport[1]) == 1
    assert [item.code for item in result.diagnostics] == ["redirect_refused"]


def test_same_origin_redirect_preserves_base_and_records_both_hops(transport: Transport) -> None:
    bootstrap = synthetic_bootstrap([[["com"], ["https://rdap.example.org/base/"]]])
    transport[0].extend([(302, b"", {"Location": "/base/v2/example.com"}), (200, raw_fixture("domain-found.json"), {})])
    result = rdap.lookup(session(bootstrap=bootstrap))
    assert result.lookup_outcome == "found"
    assert [str(request.url) for request in transport[1]] == [
        "https://rdap.example.org/base/domain/example.com",
        "https://rdap.example.org/base/v2/example.com",
    ]
    assert len(cast(list[Any], result.observations[0].source_identity["redirects"])) == 1


def test_wrong_selected_native_type_is_not_silently_dropped(transport: Transport) -> None:
    body = fixture("domain-found.json")
    body["status"] = True
    transport[0].append((200, json.dumps(body).encode(), {}))
    result = rdap.lookup(session())
    assert result.lookup_outcome == "unavailable" and not result.observations
    assert [item.code for item in result.diagnostics] == ["invalid_response"]


def test_absent_and_null_arrays_are_preserved_by_projection() -> None:
    base: dict[str, Any] = {"objectClassName": "domain", "ldhName": "example.com"}
    assert rdap.project_rdap(base) == base
    values: tuple[list[Any] | None, ...] = (None, [])
    for value in values:
        source = copy.deepcopy(base)
        source["events"] = value
        assert rdap.project_rdap(source)["events"] == value


def test_wrong_selector_and_offline_refuse_without_http(transport: Transport) -> None:
    with pytest.raises(RegistryInputError):
        rdap.lookup(_client.RegistryReadSession({"registry": "tls", "target": {"hostname": "example.org"}}))
    with network_guard.offline_mode():
        result = rdap.lookup(session())
    assert [item.code for item in result.diagnostics] == ["offline_refused"]
    assert transport[1] == []
