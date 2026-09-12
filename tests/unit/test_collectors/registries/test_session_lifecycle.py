"""Exercise session authority and final publication through owned transports."""

from __future__ import annotations

import hashlib
import json
import socket
from datetime import UTC, datetime
from typing import Any, cast

import httpx
import pytest
from evidentia_collectors.registries import _client
from evidentia_collectors.registries._contracts import (
    CertificateTarget,
    DomainTarget,
    EndpointTarget,
    EntityTarget,
    FCCOrganizationTarget,
    HostnameTarget,
    LEITarget,
    ProductTarget,
    RegistryInputError,
    SAMOrganizationTarget,
    UEITarget,
    _CapacityLimits,
    result_bytes,
)
from evidentia_collectors.registries._contracts import (
    make_result as contracts_make_result,
)
from evidentia_collectors.registries._sam_http import SamAttempt
from evidentia_core import network_guard

NOW = datetime(2026, 9, 11, 12, tzinfo=UTC)
LEI = "A" * 20


def record() -> dict[str, Any]:
    return {
        "id": LEI,
        "type": "lei-records",
        "attributes": {"lei": LEI, "entity": {"legalName": {"name": "Synthetic entity"}}},
    }


def project(value: dict[str, Any]) -> dict[str, Any]:
    return {name: value[name] for name in ("id", "type", "attributes")}


@pytest.fixture
def transport(monkeypatch: pytest.MonkeyPatch) -> Any:
    replies: list[tuple[int, bytes, dict[str, str]]] = []
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


def session(**kwargs: Any) -> _client.RegistryReadSession:
    return _client.RegistryReadSession(
        {"registry": "gleif", "target": {"lei": LEI}},
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        **kwargs,
    )


def test_owned_read_admission_digest_and_repeat_coalescing(transport: Any) -> None:
    replies, requests = transport
    body = json.dumps({"data": record()}).encode()
    replies.append((200, body, {}))
    current = session()
    result = current.read_gleif(LEITarget(lei=LEI), project)
    assert result.collection_status == "complete" and result.lookup_outcome == "found"
    assert result.source_reads[0].source_digest == hashlib.sha256(body).hexdigest()
    assert result.source_reads[0].raw_bytes == result.source_reads[0].decoded_bytes == len(body)
    assert result.source_reads[0].source_records == result.source_reads[0].admitted_records == 1
    assert result.observations[0].fields == record()
    assert json.loads(result_bytes(result))["findings"][0]["raw_data"]["observation"]["fields"] == record()
    again = current.read_gleif(LEITarget(lei=LEI), lambda value: pytest.fail("repeated projection"))
    assert result_bytes(again) == result_bytes(result) and len(requests) == 1


def test_identity_refusal_precedes_projector(transport: Any) -> None:
    replies, _ = transport
    source = record()
    source["attributes"]["lei"] = "B" * 20
    replies.append((200, json.dumps({"data": source}).encode(), {}))
    result = session().read_gleif(LEITarget(lei=LEI), lambda value: pytest.fail("mismatched projection"))
    assert result.lookup_outcome == "unavailable" and not result.observations
    assert result.source_reads[0].source_records == 1
    assert [item.code for item in result.diagnostics] == ["identity_mismatch"]


def test_mutated_projection_cannot_change_captured_source_or_request(transport: Any) -> None:
    replies, _ = transport
    replies.append((200, json.dumps({"data": record()}).encode(), {}))
    current = session()

    def mutated(value: dict[str, Any]) -> dict[str, Any]:
        object.__setattr__(current.request.root.target, "lei", "B" * 20)
        value["attributes"]["lei"] = "B" * 20
        return value

    result = current.read_gleif(LEITarget(lei=LEI), mutated)
    assert result.lookup_outcome == "unavailable" and result.request.root.target == LEITarget(lei=LEI)
    assert [item.code for item in result.diagnostics] == ["projection_mismatch"]


def test_retries_are_owned_and_status_errors_do_not_supply_bodies(transport: Any) -> None:
    replies, requests = transport
    body = json.dumps({"data": record()}).encode()
    replies.extend([(503, b"ignored error body", {"Retry-After": "0"}), (200, body, {})])
    waits: list[float] = []
    result = session(_sleep=waits.append).read_gleif(LEITarget(lei=LEI), project)
    assert result.collection_status == "complete" and len(requests) == 2 and waits == [0.0]
    assert result.source_reads[0].network_attempts == 2 and result.source_reads[0].raw_bytes == len(body)


def test_authorization_error_is_not_retried(transport: Any) -> None:
    replies, requests = transport
    replies.append((401, b"untrusted error detail", {}))
    result = session(_sleep=lambda delay: pytest.fail("unexpected retry")).read_gleif(LEITarget(lei=LEI), project)
    assert result.lookup_outcome == "unavailable" and len(requests) == 1
    assert result.source_reads[0].http_status == 401 and result.source_reads[0].raw_bytes == 0
    assert [item.code for item in result.diagnostics] == ["http_error"]


def test_result_capacity_refuses_whole_observation(transport: Any) -> None:
    replies, _ = transport
    replies.append((200, json.dumps({"data": record()}).encode(), {}))
    result = session(_capacity_limits=_CapacityLimits(result_bytes=1)).read_gleif(LEITarget(lei=LEI), project)
    assert result.lookup_outcome == "unavailable" and not result.observations and not result.findings
    assert result.source_reads[0].admitted_records == result.source_reads[0].accepted_pages == 0
    assert [item.code for item in result.diagnostics] == ["result_limit"]


def test_cancellation_identity_survives_projector_boundary(transport: Any) -> None:
    replies, _ = transport
    replies.append((200, json.dumps({"data": record()}).encode(), {}))
    cancellation = KeyboardInterrupt("synthetic cancellation")

    def cancel(value: Any) -> Any:
        raise cancellation

    with pytest.raises(KeyboardInterrupt) as raised:
        session().read_gleif(LEITarget(lei=LEI), cancel)
    assert raised.value is cancellation


def test_target_mismatch_precedes_transport(transport: Any) -> None:
    _, requests = transport
    with pytest.raises(RegistryInputError):
        session().read_gleif(LEITarget(lei="B" * 20), project)
    assert requests == []


def test_disabled_ssl_labs_has_zero_transport_or_projection_calls() -> None:
    target = EndpointTarget(hostname="example.org", endpoint_ip="93.184.216.34")
    current = _client.RegistryReadSession(
        {"registry": "ssl-labs", "target": target},
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        _http_factory=lambda: pytest.fail("disabled network factory"),
    )
    result = current.read_ssl_labs(target, lambda value: pytest.fail("disabled projection"))
    assert result.lookup_outcome == "unavailable" and result.source_reads[0].network_attempts == 0
    assert result.source_reads[0].raw_bytes is None
    assert [item.code for item in result.diagnostics] == ["live_disabled"]


def test_final_validation_overrun_keeps_admitted_evidence_as_partial(
    transport: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    replies, _ = transport
    replies.append((200, json.dumps({"data": record()}).encode(), {}))
    ticks = [0.0]
    current = _client.RegistryReadSession(
        {"registry": "gleif", "target": {"lei": LEI}}, _utc=lambda: NOW, _monotonic=lambda: ticks[0]
    )
    make_result = contracts_make_result
    run_ids: list[str] = []

    def delayed(*args: Any, **kwargs: Any) -> Any:
        result = make_result(*args, **kwargs)
        run_ids.append(result.run_id)
        ticks[0] = 61.0
        return result

    monkeypatch.setattr(_client, "make_result", delayed)
    result = current.read_gleif(LEITarget(lei=LEI), project)
    assert result.collection_status == "partial" and result.lookup_outcome == "found"
    assert len(result.observations) == len(result.findings) == 1
    assert [item.code for item in result.diagnostics] == ["deadline_exceeded"]
    assert len(set(run_ids)) == 1


@pytest.mark.parametrize("value", ["11", "-1", "1.0", "9, 9", "", "0" * 129, "９"])
def test_retry_header_invalid_or_over_policy_limit(value: str) -> None:
    with pytest.raises(_client.ReadFault, match=r"^retry_exhausted$"):
        _client._retry_wait((value,), attempt=1, now=NOW, remaining=60.0)


@pytest.mark.parametrize(
    "value", ["Fri, 11 Sep 2026 12:00:05 GMT", "Friday, 11-Sep-26 12:00:05 GMT", "Fri Sep 11 12:00:05 2026", "5"]
)
def test_retry_three_http_date_forms_and_decimal_seconds(value: str) -> None:
    assert _client._retry_wait((value,), attempt=1, now=NOW, remaining=10.0) == 5.0


def test_retry_duplicate_header_and_insufficient_time() -> None:
    with pytest.raises(_client.ReadFault, match=r"^retry_exhausted$"):
        _client._retry_wait(("1", "1"), attempt=1, now=NOW, remaining=60.0)
    with pytest.raises(_client.ReadFault, match=r"^deadline_exceeded$"):
        _client._retry_wait(("5",), attempt=1, now=NOW, remaining=4.0)
    assert _client._retry_wait((), attempt=2, now=NOW, remaining=10.0) == 2.0


def test_expired_session_starts_no_http_attempt(transport: Any) -> None:
    _, requests = transport
    ticks = [0.0]
    current = _client.RegistryReadSession(
        {"registry": "gleif", "target": {"lei": LEI}},
        _utc=lambda: NOW,
        _monotonic=lambda: ticks[0],
    )
    ticks[0] = 61.0
    result = current.read_gleif(LEITarget(lei=LEI), project)
    assert result.lookup_outcome == "unavailable" and requests == []
    assert result.source_reads[0].network_attempts == 0


def test_attempt_reservation_preserves_all_observed_bytes_below_run_cap(transport: Any) -> None:
    replies, requests = transport
    replies.extend([(200, b"x" * 1_048_576, {}) for _ in range(8)])
    current = session()
    for _ in range(7):
        read = current._read(kind="https", method="GET")
        assert len(current._http(read, "https://api.gleif.org/api/v1/lei-records/" + LEI)) == 1_048_576
    last = current._read(kind="https", method="GET")
    with pytest.raises(_client.ReadFault, match=r"^run_byte_limit$"):
        current._http(last, "https://api.gleif.org/api/v1/lei-records/" + LEI)
    current._diagnose("run_byte_limit", last)
    result = current._finish()
    assert len(requests) == 7 and len(replies) == 1
    assert sum(read.raw_bytes or 0 for read in result.source_reads) == 7 * 1_048_576
    assert sum(read.decoded_bytes or 0 for read in result.source_reads) == 7 * 1_048_576
    assert result.collection_status == "unavailable"


class _SyntheticSam(SamAttempt):
    """Supply detached response bytes for session-only source-contract tests."""

    def __init__(self, replies: list[dict[str, Any]], pages: list[int]) -> None:
        super().__init__()
        self.replies, self.pages = replies, pages

    def fetch(self, request: Any, *, page: int, credentials: Any, remaining: Any, utc_now: Any, consume: Any) -> bytes:
        self.pages.append(page)
        remaining()
        content = json.dumps(self.replies.pop(0)).encode()
        self.status_code = 200
        consume(len(content), len(content))
        return content


def sam_session(
    registry: str, target: Any, replies: list[dict[str, Any]], **kwargs: Any
) -> tuple[_client.RegistryReadSession, list[int]]:
    pages: list[int] = []
    current = _client.RegistryReadSession(
        {"registry": registry, "target": target},
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        _sam_factory=lambda: _SyntheticSam(replies, pages),
        **kwargs,
    )
    return current, pages


def exclusion(index: int, *, name: str | None = None) -> dict[str, Any]:
    return {
        "exclusionDetails": {"classificationType": "Firm", "excludingAgencyName": "Synthetic agency"},
        "exclusionIdentification": {"ueiSAM": "A" * 12, "entityName": name or "Synthetic firm " + str(index)},
        "exclusionActions": {
            "listOfActions": [
                {"recordStatus": "Active", "createDate": "09-11-2026", "terminationDate": None},
                {"recordStatus": "Active", "createDate": "09-11-2026", "terminationDate": None},
            ]
        },
    }


def test_sam_entity_preserves_distinct_occurrences_and_partial_scope() -> None:
    target = UEITarget(uei="A" * 12)
    rows = [
        {"entityRegistration": {"ueiSAM": target.uei, "samRegistered": "Yes"}},
        {"entityRegistration": {"ueiSAM": target.uei, "samRegistered": "Yes", "entityEFTIndicator": ""}},
    ]
    current, pages = sam_session("sam-entity", target, [{"entityData": rows}])
    result = current.read_sam_entity(target, lambda value: value)
    assert pages == [0] and result.collection_status == "partial" and result.lookup_outcome == "ambiguous"
    assert len(result.observations) == 2
    assert "entityEFTIndicator" not in result.observations[0].fields
    assert result.observations[1].fields["entityEFTIndicator"] == ""
    assert {item.code for item in result.diagnostics} == {"source_terminal_unproven", "traversal_incomplete"}
    assert result.source_reads[0].source_records == result.source_reads[0].admitted_records == 2


def test_sam_entity_checks_all_row_identities_before_projectors() -> None:
    target = UEITarget(uei="A" * 12)
    rows = [{"entityRegistration": {"ueiSAM": value, "samRegistered": "Yes"}} for value in (target.uei, "B" * 12)]
    current, _ = sam_session("sam-entity", target, [{"entityData": rows}])
    result = current.read_sam_entity(target, lambda value: pytest.fail("projection before complete identity capture"))
    assert result.lookup_outcome == "unavailable" and not result.observations
    assert "identity_mismatch" in [item.code for item in result.diagnostics]


def test_exclusions_full_numbered_pages_keep_all_outer_and_action_occurrences() -> None:
    target = UEITarget(uei="A" * 12)
    rows = [exclusion(index) for index in range(12)]
    current, pages = sam_session(
        "sam-exclusions",
        target,
        [
            {"totalRecords": 12, "excludedEntity": rows[:10]},
            {"totalRecords": 12, "excludedEntity": rows[10:]},
        ],
    )
    result = current.read_sam_exclusions(target, lambda value: value)
    assert pages == [0, 1] and result.collection_status == "complete"
    assert len(result.observations) == 12 and len(result.findings) == 12
    assert [read.source_records for read in result.source_reads] == [10, 2]
    assert all(read.accepted_pages == read.network_attempts == 1 for read in result.source_reads)
    assert [dict(item.fields) for item in result.observations] == rows
    assert len({item.matched_identity for item in result.observations}) == 12


def test_exclusion_name_filter_cannot_change_raw_pagination_counts() -> None:
    target = SAMOrganizationTarget(organization_name="Target Firm")
    first = [exclusion(index) for index in range(10)]
    last = [exclusion(10, name="  TARGET  firm ")]
    current, pages = sam_session(
        "sam-exclusions",
        target,
        [
            {"totalRecords": 11, "excludedEntity": first},
            {"totalRecords": 11, "excludedEntity": last},
        ],
    )
    result = current.read_sam_exclusions(target, lambda value: value)
    assert pages == [0, 1] and result.collection_status == "complete" and result.lookup_outcome == "found"
    assert [read.source_records for read in result.source_reads] == [10, 1]
    assert [read.admitted_records for read in result.source_reads] == [0, 1]
    assert result.observations[0].match_basis == "exact_normalized_name"
    current, _ = sam_session("sam-exclusions", target, [{"totalRecords": 0, "excludedEntity": []}])
    no_match = current.read_sam_exclusions(target, lambda value: pytest.fail("empty projection"))
    assert no_match.lookup_outcome == "unavailable" and not no_match.observations
    assert [item.code for item in no_match.diagnostics] == ["source_match_scope_limited"]


@pytest.mark.parametrize("failure", ["total_changed", "repeated_page", "short_page"])
def test_exclusions_later_gaps_preserve_accepted_page(failure: str) -> None:
    target = UEITarget(uei="A" * 12)
    first = [exclusion(index) for index in range(10)]
    second = first if failure == "repeated_page" else [exclusion(index) for index in range(10, 19)]
    total = 21 if failure == "total_changed" else 20
    current, pages = sam_session(
        "sam-exclusions",
        target,
        [
            {"totalRecords": 20, "excludedEntity": first},
            {"totalRecords": total, "excludedEntity": second},
        ],
    )
    result = current.read_sam_exclusions(target, lambda value: value)
    assert pages == [0, 1] and result.collection_status == "partial" and len(result.observations) == 10
    assert result.source_reads[0].accepted_pages == 1 and result.source_reads[1].accepted_pages == 0
    assert result.source_reads[1].body_complete and result.source_reads[1].source_digest is not None
    assert [item.code for item in result.diagnostics] == [
        "traversal_incomplete" if failure == "short_page" else failure
    ]


@pytest.mark.parametrize("total", [True, "0", 0.0, None, -1])
def test_exclusions_native_totals_are_required(total: Any) -> None:
    target = UEITarget(uei="A" * 12)
    current, _ = sam_session("sam-exclusions", target, [{"totalRecords": total, "excludedEntity": []}])
    result = current.read_sam_exclusions(target, lambda value: pytest.fail("invalid source projected"))
    assert result.lookup_outcome == "unavailable" and not result.observations
    assert [item.code for item in result.diagnostics] == ["invalid_response"]


def test_exclusions_page_capacity_and_projection_are_atomic() -> None:
    target = UEITarget(uei="A" * 12)
    body = {"totalRecords": 2, "excludedEntity": [exclusion(0), exclusion(1)]}
    current, _ = sam_session("sam-exclusions", target, [body], _capacity_limits=_CapacityLimits(records=1))
    result = current.read_sam_exclusions(target, lambda value: value)
    assert not result.observations and result.source_reads[0].admitted_records == 0
    assert result.source_reads[0].accepted_pages == 0
    assert [item.code for item in result.diagnostics] == ["record_limit"]
    current, _ = sam_session("sam-exclusions", target, [body])
    calls = []

    def mutate_second(value: dict[str, Any]) -> dict[str, Any]:
        calls.append(1)
        if len(calls) == 2:
            value["exclusionActions"]["listOfActions"].pop()
        return value

    result = current.read_sam_exclusions(target, mutate_second)
    assert len(calls) == 2 and not result.observations
    assert [item.code for item in result.diagnostics] == ["projection_mismatch"]


def test_cancelled_session_cannot_be_restarted(transport: Any) -> None:
    replies, _ = transport
    replies.append((200, json.dumps({"data": record()}).encode(), {}))
    current = session()

    def cancel(value: Any) -> Any:
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        current.read_gleif(LEITarget(lei=LEI), cancel)
    with pytest.raises(RegistryInputError):
        current.read_gleif(LEITarget(lei=LEI), project)


@pytest.mark.parametrize(
    "registry,target",
    [
        ("fedramp", ProductTarget(product_id="F1607067912")),
        ("cmvp", CertificateTarget(certificate_number="5517")),
        (
            "fcc-covered-list",
            FCCOrganizationTarget(
                organization_name="Huawei Technologies Company", query_scope="named_organization_entries"
            ),
        ),
    ],
)
def test_snapshot_session_uses_complete_dated_package(registry: str, target: Any) -> None:
    current = _client.RegistryReadSession(
        {"registry": registry, "target": target},
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        _http_factory=lambda: pytest.fail("snapshot network attempt"),
    )
    result = current.read_snapshot(target, lambda value: value)
    assert result.collection_status == "complete" and result.lookup_outcome == "found"
    assert result.freshness == ("unknown" if registry == "cmvp" else "dated_snapshot")
    assert result.source_reads[0].network_attempts == 0 and result.source_reads[0].source_digest
    assert len(result.observations) == len(result.findings) == 1
    assert result.observations[0].trust.transport_verified is None
    if registry == "fcc-covered-list":
        assert len(result.diagnostics) == 3 and all(item.effect == "advisory" for item in result.diagnostics)
        footnotes = result.observations[0].fields["linked_footnotes"]
        assert isinstance(footnotes, list) and len(footnotes) == 2


@pytest.mark.parametrize(
    ("expiry", "freshness", "relation", "future"),
    [
        ("2026-09-12T12:00:00Z", "current_observation", "after", True),
        ("2026-09-10T12:00:00Z", "stale", "before", False),
        ("2026-09-11T12:00:00Z", "current_observation", "equal", False),
        ("2026-09-12T12:00:00.0000001Z", "unknown", "unknown", None),
    ],
)
def test_security_source_checks_remain_visible_without_compliance_claim(
    transport: Any, expiry: str, freshness: str, relation: str, future: bool | None
) -> None:
    replies, requests = transport
    body = ("Contact: mailto:security@example.com\nExpires: " + expiry + "\nX-Source:  exact  \n").encode()
    replies.append((200, body, {"Content-Type": "text/plain; charset=UTF-8"}))
    target = HostnameTarget(hostname="example.com")
    current = _client.RegistryReadSession(
        {"registry": "security-txt", "target": target}, _utc=lambda: NOW, _monotonic=lambda: 0.0
    )
    result = current.read_security_txt(target, lambda value: value)
    assert result.collection_status == "complete" and result.freshness == freshness
    observation = result.observations[0]
    fields = observation.fields["fields"]
    assert isinstance(fields, list) and fields[-1] == {
        "name": "X-Source",
        "value": "  exact  ",
        "source_line": 3,
        "body_line": 3,
    }
    checks = observation.source_identity["controller_checks"]
    assert isinstance(checks, dict) and checks["expiry_relation"] == relation and checks["expires_future"] is future
    assert checks["uri_semantic_validation"] == "not_performed"
    assert result.source_reads[0].source_digest == hashlib.sha256(body).hexdigest()
    assert str(requests[0].url) == "https://example.com/.well-known/security.txt"


@pytest.mark.parametrize("compressed", [False, True])
def test_security_raw_and_decoded_limit_uses_owned_decoder(transport: Any, compressed: bool) -> None:
    import gzip

    replies, requests = transport
    body = b"#" + b"x" * 65_536
    headers = {"Content-Type": "text/plain"}
    if compressed:
        body = gzip.compress(body)
        headers["Content-Encoding"] = "gzip"
    replies.append((200, body, headers))
    target = HostnameTarget(hostname="example.com")
    current = _client.RegistryReadSession(
        {"registry": "security-txt", "target": target}, _utc=lambda: NOW, _monotonic=lambda: 0.0
    )
    result = current.read_security_txt(target, lambda value: pytest.fail("oversized body projection"))
    assert [item.code for item in result.diagnostics] == ["body_limit"]
    assert not result.observations and len(requests) == 1
    assert not result.source_reads[0].body_complete
    assert result.source_reads[0].decoded_bytes == 65_537


@pytest.mark.parametrize(
    "location",
    [
        "https://other.example/security.txt",
        "http://example.com/security.txt",
        "//example.com/security.txt",
        "/a/../security.txt",
        "/%2E%2E/security.txt",
        "/%252e/security.txt",
        "/a//security.txt",
        "/security.txt?",
        "/security.txt#",
        "https://EXAMPLE.com/security.txt",
        "/.well-known/security.txt",
    ],
)
def test_security_refuses_unsafe_or_repeated_redirect_before_next_attempt(transport: Any, location: str) -> None:
    replies, requests = transport
    replies.append((302, b"", {"Location": location}))
    target = HostnameTarget(hostname="example.com")
    current = _client.RegistryReadSession(
        {"registry": "security-txt", "target": target}, _utc=lambda: NOW, _monotonic=lambda: 0.0
    )
    result = current.read_security_txt(target, lambda value: pytest.fail("unsafe redirect projection"))
    assert [item.code for item in result.diagnostics] == ["redirect_refused"]
    assert len(requests) == result.source_reads[0].network_attempts == 1
    assert result.source_reads[0].http_status == 302


def test_security_three_redirects_preserve_exact_final_retrieval_scope(transport: Any) -> None:
    replies, requests = transport
    replies.extend(
        [(301, b"", {"Location": "/a.txt"}), (307, b"", {"Location": "b.txt"}), (308, b"", {"Location": "/final.txt"})]
    )
    replies.append(
        (
            200,
            b"Contact: mailto:security@example.com\nExpires: 2026-09-12T12:00:00Z\nCanonical: https://example.com/final.txt\n",
            {"Content-Type": "text/plain"},
        )
    )
    target = HostnameTarget(hostname="example.com")
    current = _client.RegistryReadSession(
        {"registry": "security-txt", "target": target}, _utc=lambda: NOW, _monotonic=lambda: 0.0
    )
    result = current.read_security_txt(target, lambda value: value)
    identity = result.observations[0].source_identity
    assert result.collection_status == "complete" and len(requests) == 4
    assert identity["retrieval_uri"] == "https://example.com/final.txt"
    redirects = identity["redirects"]
    checks = identity["controller_checks"]
    assert isinstance(redirects, list) and len(redirects) == 3
    assert isinstance(checks, dict) and checks["canonical_lists_retrieval_uri"] is True


def test_security_fourth_redirect_is_refused_without_following(transport: Any) -> None:
    replies, requests = transport
    replies.extend((302, b"", {"Location": "/" + str(index)}) for index in range(4))
    target = HostnameTarget(hostname="example.com")
    current = _client.RegistryReadSession(
        {"registry": "security-txt", "target": target}, _utc=lambda: NOW, _monotonic=lambda: 0.0
    )
    result = current.read_security_txt(target, lambda value: pytest.fail("fourth redirect projection"))
    assert len(requests) == 4 and result.diagnostics[0].code == "redirect_refused"


def test_rdap_keeps_bootstrap_scope_and_excludes_contacts(transport: Any) -> None:
    replies, requests = transport
    body = {
        "objectClassName": "domain",
        "ldhName": "EXAMPLE.COM",
        "unicodeName": "other.example",
        "status": ["unknown-source-status"],
        "entities": [{"vcardArray": ["vcard", []]}],
    }
    replies.append((200, json.dumps(body).encode(), {}))
    target = DomainTarget(domain="example.com")
    current = _client.RegistryReadSession(
        {"registry": "rdap", "target": target}, _utc=lambda: NOW, _monotonic=lambda: 0.0
    )
    result = current.read_rdap(
        target, lambda source: {name: source[name] for name in ("objectClassName", "ldhName", "unicodeName", "status")}
    )
    assert result.collection_status == "complete" and len(requests) == 1
    observation = result.observations[0]
    assert "entities" not in observation.fields and observation.fields["ldhName"] == "EXAMPLE.COM"
    assert [item.code for item in result.diagnostics] == ["source_name_conflict"]
    bootstrap = observation.source_identity["bootstrap"]
    assert (
        isinstance(bootstrap, dict)
        and bootstrap["sha256"] == "203262f750f2db107c74b167382b5bcf30fafb95dabc1ec2f55a4c2b85b53a75"
    )
    assert str(requests[0].url) == str(bootstrap["selected_service_base"]) + "domain/example.com"
    assert result.source_reads[0].snapshot_source == "data/rdap/bootstrap.json"


@pytest.mark.parametrize(
    "body",
    [
        {"objectClassName": "entity", "ldhName": "example.com"},
        {"objectClassName": "domain", "ldhName": "other.example"},
        {"objectClassName": "domain", "ldhName": None},
    ],
)
def test_rdap_identity_gate_precedes_projector(transport: Any, body: dict[str, Any]) -> None:
    replies, _ = transport
    replies.append((200, json.dumps(body).encode(), {}))
    target = DomainTarget(domain="example.com")
    current = _client.RegistryReadSession(
        {"registry": "rdap", "target": target}, _utc=lambda: NOW, _monotonic=lambda: 0.0
    )
    result = current.read_rdap(target, lambda value: pytest.fail("wrong RDAP identity projection"))
    assert result.lookup_outcome == "unavailable" and result.diagnostics[0].code == "identity_mismatch"


def test_rdap_refuses_redirect_outside_selected_service_path(transport: Any) -> None:
    replies, requests = transport
    replies.append((302, b"", {"Location": "/different/domain/example.com"}))
    target = DomainTarget(domain="example.com")
    current = _client.RegistryReadSession(
        {"registry": "rdap", "target": target}, _utc=lambda: NOW, _monotonic=lambda: 0.0
    )
    result = current.read_rdap(target, lambda value: pytest.fail("outside RDAP base"))
    assert len(requests) == 1 and result.diagnostics[0].code == "redirect_refused"


def test_incommon_missing_extra_precedes_http_or_projection(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_collectors.registries._xml_signature import XMLSignatureError

    def absent() -> None:
        raise XMLSignatureError("missing_extra")

    monkeypatch.setattr(_client, "require_xml_extra", absent)
    target = EntityTarget(entity_id="urn:synthetic:entity")
    current = _client.RegistryReadSession(
        {"registry": "incommon", "target": target},
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        _http_factory=lambda: pytest.fail("I/O before optional dependency check"),
    )
    result = current.read_incommon(target, lambda value: pytest.fail("unverified projection"))
    assert result.diagnostics[0].code == "missing_extra"
    assert result.source_reads[0].network_attempts == 0 and not result.observations


@pytest.mark.parametrize("slot", ["request", "read_scope"])
def test_returned_result_target_tampering_cannot_change_private_cache(transport: Any, slot: str) -> None:
    replies, requests = transport
    replies.append((200, json.dumps({"data": record()}).encode(), {}))
    current = session()
    target = LEITarget(lei=LEI)
    result = current.read_gleif(target, project)
    original = result_bytes(result)
    exposed = result.request if slot == "request" else result.source_reads[0].query_scope
    object.__setattr__(exposed.root.target, "lei", "B" * 20)
    again = current.read_gleif(target, lambda value: pytest.fail("cached projection"))
    assert result_bytes(again) == original and len(requests) == 1


@pytest.mark.parametrize("location", ["https:/security.txt", "https:///security.txt", "https:security.txt"])
def test_redirect_scheme_without_authority_is_not_repaired(location: str) -> None:
    with pytest.raises(_client.ReadFault, match="redirect_refused"):
        _client._redirect_target("https://example.com/.well-known/security.txt", location, service_base=None)


def test_clock_native_type_guard_does_not_invoke_metaclass() -> None:
    calls: list[str] = []

    class Meta(type):
        def __eq__(cls, other: object) -> bool:
            calls.append("equality")
            return False

    class ClockValue(metaclass=Meta):
        pass

    with pytest.raises(RegistryInputError):
        _client.RegistryReadSession(
            {"registry": "gleif", "target": {"lei": LEI}},
            _utc=lambda: NOW,
            _monotonic=lambda: cast(float, ClockValue()),
        )
    assert not calls


@pytest.mark.parametrize("registry", ["gleif", "rdap", "security-txt"])
def test_callback_mutation_of_caller_target_cannot_rebind_request(transport: Any, registry: str) -> None:
    replies, requests = transport
    if registry == "gleif":
        target: Any = LEITarget(lei=LEI)
        body = record()
        body["id"] = body["attributes"]["lei"] = "B" * 20
        replies.append((200, json.dumps({"data": body}).encode(), {}))
        attribute, changed = "lei", "B" * 20
    elif registry == "rdap":
        target = DomainTarget(domain="example.com")
        replies.append((200, b'{"objectClassName":"domain","ldhName":"other.example"}', {}))
        attribute, changed = "domain", "other.example"
    else:
        target = HostnameTarget(hostname="example.com")
        replies.append(
            (
                200,
                b"Contact: mailto:security@example.com\nExpires: 2026-09-12T12:00:00Z\n",
                {"Content-Type": "text/plain"},
            )
        )
        attribute, changed = "hostname", "other.example"

    def clock() -> datetime:
        if requests:
            object.__setattr__(target, attribute, changed)
        return NOW

    current = _client.RegistryReadSession({"registry": registry, "target": target}, _utc=clock, _monotonic=lambda: 0.0)
    if registry == "gleif":
        result = current.read_gleif(target, lambda value: pytest.fail("rebound LEI"))
    elif registry == "rdap":
        result = current.read_rdap(target, lambda value: pytest.fail("rebound domain"))
    else:
        result = current.read_security_txt(target, lambda value: value)
    assert getattr(target, attribute) == changed
    if registry == "security-txt":
        assert result.observations[0].source_identity["hostname"] == "example.com"
        assert result.observations[0].matched_identity == "example.com"
    else:
        assert result.lookup_outcome == "unavailable" and result.diagnostics[0].code == "identity_mismatch"
