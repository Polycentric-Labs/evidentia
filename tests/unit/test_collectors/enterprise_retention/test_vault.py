"""Exact Vault configuration projection and real shared-session controls."""

from __future__ import annotations

import copy
import json
import math
import socket
import ssl
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from evidentia_collectors.enterprise_retention import _client, _contracts, _credentials
from evidentia_collectors.enterprise_retention._client import (
    AuthorityError,
    EnterpriseReadSession,
    ParsedResponse,
    ProjectedRecord,
    ReadSubject,
)
from evidentia_collectors.enterprise_retention._contracts import (
    CoverageState,
    EnterpriseRetentionCollectRequest,
    EnterpriseRetentionCollectResult,
    EnterpriseRetentionReadResult,
    VaultMatterTarget,
)
from evidentia_collectors.enterprise_retention._credentials import CredentialMaterial
from evidentia_collectors.enterprise_retention._parsing import JsonObject, parse_strict_json
from evidentia_collectors.enterprise_retention._profiles import AddressPolicy, AuthorizedProfile, FrozenProfile
from evidentia_collectors.enterprise_retention.vault import project_holds, project_matter, read_vault
from evidentia_core import network_guard
from pydantic import JsonValue

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "enterprise_retention" / "vault"
NOW = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
RUN_ID = "01K4RZP8V00000000000000000"
MATTER_ID = "synthetic-matter"
TIME = "2026-01-02T03:04:05.123456789+05:30"
HOLD: JsonObject = {
    "holdId": "synthetic-hold",
    "name": "Synthetic hold",
    "corpus": "DRIVE",
    "updateTime": TIME,
    "accounts": [],
    "orgUnit": {"orgUnitId": "synthetic-ou", "holdTime": TIME},
    "query": {"driveQuery": {"includeSharedDriveFiles": False, "includeTeamDriveFiles": True}},
}
ALL_KNOWN: dict[str, CoverageState] = {
    "holdId": "known",
    "name": "known",
    "corpus": "known",
    "updateTime": "known",
    "accounts": "known",
    "orgUnit": "known",
    "query": "known",
}


def fixture_body(name: str) -> JsonObject:
    document = parse_strict_json((FIXTURES / name).read_bytes())
    assert type(document) is dict
    assert document["authored_synthetic"] is True
    assert document["recorded_response"] is False
    body = document["body"]
    assert type(body) is dict
    return body


def hold_record(source: JsonObject) -> ProjectedRecord:
    page = project_holds(ParsedResponse({"holds": [source]}, 200), ReadSubject("vault-holds", MATTER_ID))
    assert len(page.records) == 1
    assert page.diagnostics == ()
    return page.records[0]


def same_json(actual: JsonValue, expected: JsonValue) -> None:
    assert type(actual) is type(expected)
    if isinstance(actual, dict):
        assert isinstance(expected, dict)
        assert actual.keys() == expected.keys()
        for key in actual:
            same_json(actual[key], expected[key])
    elif isinstance(actual, list):
        assert isinstance(expected, list)
        assert len(actual) == len(expected)
        for left, right in zip(actual, expected, strict=True):
            same_json(left, right)
    elif isinstance(actual, float):
        assert isinstance(expected, float)
        assert actual == expected
        if actual == 0:
            assert math.copysign(1.0, actual) == math.copysign(1.0, expected)
    else:
        assert actual == expected


def test_basic_matter_projection_is_exact_and_excludes_unselected_fields() -> None:
    source = fixture_body("matter-open.json")
    original = copy.deepcopy(source)
    page = project_matter(ParsedResponse(source, 200), ReadSubject("vault-matter", MATTER_ID))
    assert len(page.records) == 1
    record = page.records[0]
    assert record.source_ordinal == 0
    assert record.source_identity == MATTER_ID
    assert record.native_scope == "matter"
    same_json(record.fields, {"matterId": MATTER_ID, "state": "OPEN"})
    assert record.field_coverage == {"matterId": "known", "state": "known"}
    assert record.diagnostics == ()
    same_json(source, original)


@pytest.mark.parametrize("state", ["OPEN", "CLOSED", "DELETED", "STATE_UNSPECIFIED", "FUTURE_STATE", "", None])
def test_matter_state_is_literal_and_does_not_invent_effectiveness(state: str | None) -> None:
    source: JsonObject = {"matterId": MATTER_ID, "state": state}
    record = project_matter(ParsedResponse(source, 200), ReadSubject("vault-matter", MATTER_ID)).records[0]
    same_json(record.fields, source)
    known = state in ("OPEN", "CLOSED", "DELETED")
    expected_state = "null" if state is None else "known" if known else "unknown"
    assert record.field_coverage["state"] == expected_state
    assert record.diagnostics == (
        () if known else ("missing_source_detail",) if state is None else ("unsupported_source_value",)
    )


def test_absent_matter_state_stays_absent() -> None:
    record = project_matter(
        ParsedResponse({"matterId": MATTER_ID}, 200), ReadSubject("vault-matter", MATTER_ID)
    ).records[0]
    assert record.fields == {"matterId": MATTER_ID}
    assert record.field_coverage == {"matterId": "known", "state": "absent"}
    assert record.diagnostics == ("missing_source_detail",)


@pytest.mark.parametrize("state", [False, 0, 1.0, [], {}])
def test_wrong_matter_state_type_refuses(state: JsonValue) -> None:
    with pytest.raises(AuthorityError, match="invalid_response"):
        project_matter(
            ParsedResponse({"matterId": MATTER_ID, "state": state}, 200), ReadSubject("vault-matter", MATTER_ID)
        )


@pytest.mark.parametrize(
    "source", [{}, {"matterId": None}, {"matterId": False}, {"matterId": ""}, {"matterId": "other"}]
)
def test_missing_or_foreign_matter_identity_refuses(source: JsonObject) -> None:
    with pytest.raises(AuthorityError):
        project_matter(ParsedResponse(source, 200), ReadSubject("vault-matter", MATTER_ID))


def test_hold_projection_does_not_use_the_shared_correspondence_oracle(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("The domain must independently select its fields")

    monkeypatch.setattr(_contracts, "expected_fields", forbidden)
    source = copy.deepcopy(HOLD)
    source["unselectedMetadata"] = {"email": "excluded@example.invalid"}
    record = hold_record(source)
    same_json(record.fields, HOLD)
    assert record.field_coverage == ALL_KNOWN
    assert record.diagnostics == ()


@pytest.mark.parametrize("name", ["name", "corpus", "updateTime", "accounts", "orgUnit", "query"])
@pytest.mark.parametrize("presence", ["absent", "null"])
def test_optional_root_fields_preserve_absent_and_null(name: str, presence: str) -> None:
    source = copy.deepcopy(HOLD)
    if presence == "absent":
        del source[name]
    else:
        source[name] = None
    record = hold_record(source)
    same_json(record.fields, source)
    expected = dict(ALL_KNOWN)
    expected[name] = "absent" if presence == "absent" else "null"
    assert record.field_coverage == expected
    assert record.diagnostics == ("missing_source_detail",)


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("name", False),
        ("name", 0),
        ("name", 1.0),
        ("name", []),
        ("name", {}),
        ("corpus", False),
        ("corpus", 0),
        ("corpus", 1.0),
        ("corpus", []),
        ("corpus", {}),
        ("updateTime", False),
        ("updateTime", 0),
        ("updateTime", 1.0),
        ("updateTime", []),
        ("updateTime", {}),
        ("accounts", False),
        ("accounts", 0),
        ("accounts", 1.0),
        ("accounts", ""),
        ("accounts", {}),
        ("orgUnit", False),
        ("orgUnit", 0),
        ("orgUnit", 1.0),
        ("orgUnit", ""),
        ("orgUnit", []),
        ("query", False),
        ("query", 0),
        ("query", 1.0),
        ("query", ""),
        ("query", []),
    ],
)
def test_wrong_root_scalar_or_container_invalidates_the_hold(name: str, bad: JsonValue) -> None:
    source = copy.deepcopy(HOLD)
    source[name] = bad
    with pytest.raises(AuthorityError, match="invalid_response"):
        hold_record(source)


@pytest.mark.parametrize("corpus", ["DRIVE", "MAIL", "GROUPS", "HANGOUTS_CHAT", "VOICE", "CALENDAR", "GEMINI"])
def test_known_corpus_literals_are_kept(corpus: str) -> None:
    source = copy.deepcopy(HOLD)
    source["corpus"] = corpus
    record = hold_record(source)
    assert record.fields["corpus"] == corpus
    assert record.field_coverage["corpus"] == "known"


@pytest.mark.parametrize("corpus", ["CORPUS_TYPE_UNSPECIFIED", "FUTURE_CORPUS", "", "drive"])
def test_unknown_corpus_is_retained_without_a_new_query_parser(corpus: str) -> None:
    source = copy.deepcopy(HOLD)
    source["corpus"] = corpus
    record = hold_record(source)
    assert record.fields["corpus"] == corpus
    assert record.field_coverage["corpus"] == "unknown"
    assert record.diagnostics == ("unsupported_source_value",)


@pytest.mark.parametrize(
    ("value", "known"),
    [
        (TIME, True),
        ("2024-02-29t23:59:59.0000000001z", True),
        ("0001-01-01T00:00:00+23:59", True),
        ("9999-12-31T23:59:59-23:59", True),
        ("2026-01-01T00:00:00-00:00", True),
        ("2026-01-01T00:00:00.0Z", True),
        ("2023-02-29T00:00:00Z", False),
        ("0000-01-01T00:00:00Z", False),
        ("2026-01-01T24:00:00Z", False),
        ("2026-01-01T00:60:00Z", False),
        ("2026-01-01T00:00:60Z", False),
        ("2026-01-01T00:00:00+24:00", False),
        ("2026-01-01T00:00:00+00:60", False),
        ("2026-01-01T00:00:00", False),
        ("2026-01-01 00:00:00Z", False),
        ("2026-01-01T00:00:00Z\n", False),
        ("", False),
        ("not-a-time", False),
    ],
)
def test_timestamp_classification_preserves_exact_fraction_and_offset(value: str, known: bool) -> None:
    source = copy.deepcopy(HOLD)
    source["updateTime"] = value
    record = hold_record(source)
    assert record.fields["updateTime"] == value
    assert record.field_coverage["updateTime"] == ("known" if known else "unknown")
    assert record.diagnostics == (() if known else ("unsupported_source_value",))


@pytest.mark.parametrize("identity", ["", " ", "\t\n", None, False, 0, 1.0, [], {}, "a" * 1025, "\u00e9" * 513])
def test_invalid_hold_identity_refuses_without_source_text(identity: JsonValue) -> None:
    with pytest.raises(AuthorityError, match="invalid_response"):
        hold_record({"holdId": identity})


@pytest.mark.parametrize("identity", ["a" * 1024, "\u00e9" * 512, "  literal id  ", "../opaque/?x=%2f#fragment"])
def test_supported_hold_identity_is_literal_and_never_a_path(identity: str) -> None:
    record = hold_record({"holdId": identity})
    assert record.source_identity == identity
    assert record.fields["holdId"] == identity


def test_missing_hold_identity_is_not_synthesized() -> None:
    with pytest.raises(AuthorityError):
        hold_record({"name": "No identity"})


def test_accounts_keep_order_duplicates_and_only_selected_child_fields() -> None:
    body = fixture_body("holds-accounts-page-1.json")
    page = project_holds(ParsedResponse(body, 200), ReadSubject("vault-holds", MATTER_ID))
    record = page.records[0]
    same_json(
        record.fields,
        {
            "holdId": "synthetic-mail-hold",
            "name": "Synthetic mail hold",
            "corpus": "MAIL",
            "updateTime": TIME,
            "accounts": [
                {"accountId": "synthetic-account-1", "holdTime": "2025-01-01T00:00:00.000000001Z"},
                {"accountId": "synthetic-account-1", "holdTime": "2025-01-01T00:00:00.000000001Z"},
            ],
            "query": {
                "mailQuery": {"startTime": "2020-01-01T00:00:00Z", "endTime": None, "terms": "subject:synthetic"}
            },
        },
    )
    assert record.field_coverage == {
        "holdId": "known",
        "name": "known",
        "corpus": "known",
        "updateTime": "known",
        "accounts": "known",
        "orgUnit": "absent",
        "query": "known",
    }
    assert record.diagnostics == ("missing_source_detail",)


def test_empty_accounts_with_selected_org_unit_does_not_invent_a_conflict() -> None:
    body = fixture_body("holds-org-unit-page-2.json")
    record = project_holds(ParsedResponse(body, 200), ReadSubject("vault-holds", MATTER_ID)).records[0]
    same_json(record.fields["orgUnit"], {"orgUnitId": "synthetic-ou", "holdTime": "2025-01-01T00:00:00-07:00"})
    assert record.fields["accounts"] == []
    assert record.fields["updateTime"] == "2026-01-01t00:00:00.100000000z"
    assert record.field_coverage == ALL_KNOWN
    assert record.diagnostics == ()


@pytest.mark.parametrize("container", ["accounts", "orgUnit"])
@pytest.mark.parametrize(
    "bad", [{}, {"id": "wrong-key"}, {"accountId": None, "orgUnitId": None}, {"accountId": " ", "orgUnitId": " "}]
)
def test_selected_child_identity_is_required(container: str, bad: JsonObject) -> None:
    source = copy.deepcopy(HOLD)
    source[container] = [bad] if container == "accounts" else bad
    with pytest.raises(AuthorityError, match="invalid_response"):
        hold_record(source)


@pytest.mark.parametrize("bad", [None, False, 0, 1.0, "", []])
def test_accounts_member_must_be_an_object(bad: JsonValue) -> None:
    source = copy.deepcopy(HOLD)
    source["accounts"] = [bad]
    with pytest.raises(AuthorityError, match="invalid_response"):
        hold_record(source)


@pytest.mark.parametrize("container", ["accounts", "orgUnit"])
@pytest.mark.parametrize("bad", [False, 0, 1.0, [], {}])
def test_child_hold_time_wrong_primitive_invalidates(container: str, bad: JsonValue) -> None:
    child: JsonObject = {"accountId" if container == "accounts" else "orgUnitId": "synthetic-child", "holdTime": bad}
    source = copy.deepcopy(HOLD)
    source[container] = [child] if container == "accounts" else child
    with pytest.raises(AuthorityError, match="invalid_response"):
        hold_record(source)


@pytest.mark.parametrize("container", ["accounts", "orgUnit"])
@pytest.mark.parametrize("mode", ["absent", "null", "future"])
def test_nested_time_presence_is_retained_instead_of_inferred(container: str, mode: str) -> None:
    child: JsonObject = {"accountId" if container == "accounts" else "orgUnitId": "  synthetic child  "}
    if mode != "absent":
        child["holdTime"] = None if mode == "null" else "future-time"
    source = copy.deepcopy(HOLD)
    source[container] = [child] if container == "accounts" else child
    if container == "accounts":
        source["orgUnit"] = None
    record = hold_record(source)
    same_json(record.fields[container], source[container])
    assert record.field_coverage[container] == ("unknown" if mode == "future" else "known")
    assert ("unsupported_source_value" in record.diagnostics) is (mode == "future")
    assert ("missing_source_detail" in record.diagnostics) is (mode != "future" or container == "accounts")


def test_nonempty_accounts_and_org_unit_remain_present_with_limited_interpretation() -> None:
    source = copy.deepcopy(HOLD)
    source["accounts"] = [{"accountId": "synthetic-account", "holdTime": TIME}]
    record = hold_record(source)
    same_json(record.fields, source)
    assert record.field_coverage == ALL_KNOWN
    assert record.diagnostics == ("unsupported_source_value",)


QUERY_LEAVES = [
    ("driveQuery", "includeSharedDriveFiles", False),
    ("driveQuery", "includeTeamDriveFiles", True),
    ("hangoutsChatQuery", "includeRooms", False),
    ("mailQuery", "startTime", TIME),
    ("mailQuery", "endTime", TIME),
    ("mailQuery", "terms", ""),
    ("groupsQuery", "startTime", TIME),
    ("groupsQuery", "endTime", TIME),
    ("groupsQuery", "terms", "synthetic terms"),
    ("voiceQuery", "coveredData", ["TEXT_MESSAGES", "VOICEMAILS", "CALL_LOGS"]),
]


@pytest.mark.parametrize(("branch", "leaf", "value"), QUERY_LEAVES)
@pytest.mark.parametrize("null", [False, True])
def test_known_query_leaf_values_and_null_are_exact(branch: str, leaf: str, value: JsonValue, null: bool) -> None:
    query: JsonObject = {branch: {leaf: None if null else value}}
    source = copy.deepcopy(HOLD)
    source["query"] = query
    record = hold_record(source)
    same_json(record.fields["query"], query)
    assert record.field_coverage["query"] == "known"
    if null:
        assert "missing_source_detail" in record.diagnostics


@pytest.mark.parametrize(("branch", "leaf", "value"), QUERY_LEAVES)
def test_declared_query_leaf_wrong_type_refuses_page(branch: str, leaf: str, value: JsonValue) -> None:
    source = copy.deepcopy(HOLD)
    source["query"] = {branch: {leaf: 1 if isinstance(value, bool) else False}}
    with pytest.raises(AuthorityError, match="invalid_response"):
        hold_record(source)


@pytest.mark.parametrize(
    "branch",
    ["driveQuery", "hangoutsChatQuery", "mailQuery", "groupsQuery", "voiceQuery", "calendarQuery", "geminiQuery"],
)
@pytest.mark.parametrize("bad", [False, 0, 1.0, "", []])
def test_known_query_branch_wrong_container_refuses(branch: str, bad: JsonValue) -> None:
    source = copy.deepcopy(HOLD)
    source["query"] = {branch: bad}
    with pytest.raises(AuthorityError, match="invalid_response"):
        hold_record(source)


@pytest.mark.parametrize("query", [{}, {"calendarQuery": {}}, {"geminiQuery": {}}, {"voiceQuery": {"coveredData": []}}])
def test_absent_alternative_query_branches_do_not_create_missing_detail(query: JsonObject) -> None:
    source = copy.deepcopy(HOLD)
    source["query"] = query
    record = hold_record(source)
    same_json(record.fields["query"], query)
    assert record.field_coverage["query"] == "known"
    assert record.diagnostics == ()


@pytest.mark.parametrize("values", [["COVERED_DATA_UNSPECIFIED"], ["FUTURE_KIND"], ["TEXT_MESSAGES", "future"]])
def test_voice_future_values_are_retained_as_unknown(values: list[str]) -> None:
    source = copy.deepcopy(HOLD)
    source["query"] = {"voiceQuery": {"coveredData": list(values)}}
    record = hold_record(source)
    same_json(record.fields["query"], source["query"])
    assert record.field_coverage["query"] == "unknown"
    assert record.diagnostics == ("unsupported_source_value",)


@pytest.mark.parametrize("bad", [None, False, 0, 1.0, [], {}])
def test_voice_list_member_must_be_a_string(bad: JsonValue) -> None:
    source = copy.deepcopy(HOLD)
    source["query"] = {"voiceQuery": {"coveredData": ["TEXT_MESSAGES", bad]}}
    with pytest.raises(AuthorityError, match="invalid_response"):
        hold_record(source)


def test_unknown_query_subtrees_preserve_native_identity_and_are_not_semantically_redacted() -> None:
    values: JsonObject = {
        "email": "user-authored-synthetic-value",
        "_meta": {"name": "retained configuration"},
        "integer": 9007199254740993,
        "large": 10**100 + 7,
        "float": 1.0,
        "negativeZero": -0.0,
        "fraction": 0.1,
        "string": "0001",
        "null": None,
        "bool": False,
        "escaped": {'quoted"key': ["} [", "\u00e9"]},
    }
    source = copy.deepcopy(HOLD)
    source["query"] = {"futureQuery": values, "calendarQuery": {"futureOption": False}}
    source["email"] = "excluded@example.invalid"
    record = hold_record(source)
    same_json(record.fields["query"], source["query"])
    assert "email" not in record.fields
    assert record.field_coverage["query"] == "unknown"
    assert record.diagnostics == ("unsupported_source_value",)


def test_unknown_null_fixture_has_independently_expected_coverage() -> None:
    body = fixture_body("holds-unknown-null.json")
    record = project_holds(ParsedResponse(body, 200), ReadSubject("vault-holds", MATTER_ID)).records[0]
    assert record.field_coverage == {
        "holdId": "known",
        "name": "null",
        "corpus": "unknown",
        "updateTime": "unknown",
        "accounts": "null",
        "orgUnit": "null",
        "query": "unknown",
    }
    assert record.diagnostics == ("unsupported_source_value", "missing_source_detail")


def test_projected_records_and_views_are_detached_without_sorting_source_records() -> None:
    source: JsonObject = {
        "holds": [
            {"holdId": "later", "updateTime": "2099-01-01T00:00:00Z"},
            {"holdId": "earlier", "updateTime": "2000-01-01T00:00:00Z"},
            {"holdId": "later", "updateTime": "2099-01-01T00:00:00Z"},
        ]
    }
    response = ParsedResponse(source, 200)
    page = project_holds(response, ReadSubject("vault-holds", MATTER_ID))
    assert [r.source_ordinal for r in page.records] == [0, 1, 2]
    assert [r.source_identity for r in page.records] == ["later", "earlier", "later"]
    page.records[0].fields["holdId"] = "changed-view"
    response.data["holds"] = []
    source["holds"] = []
    assert page.records[0].fields["holdId"] == "later"
    assert len(project_holds(response, ReadSubject("vault-holds", MATTER_ID)).records) == 3


@pytest.mark.parametrize("body", [{}, {"holds": []}])
def test_pure_empty_page_has_zero_records(body: JsonObject) -> None:
    page = project_holds(ParsedResponse(body, 200), ReadSubject("vault-holds", MATTER_ID))
    assert page.records == ()
    assert page.diagnostics == ()


@pytest.mark.parametrize("bad", [None, False, 0, 1.0, "", {}])
def test_holds_container_does_not_use_truthiness(bad: JsonValue) -> None:
    with pytest.raises(AuthorityError, match="invalid_response"):
        project_holds(ParsedResponse({"holds": bad}, 200), ReadSubject("vault-holds", MATTER_ID))


def test_pure_projector_refuses_a_valid_prefix_followed_by_invalid_detail() -> None:
    with pytest.raises(AuthorityError, match="invalid_response"):
        project_holds(
            ParsedResponse(fixture_body("holds-invalid-member.json"), 200), ReadSubject("vault-holds", MATTER_ID)
        )


def test_projectors_refuse_wrong_read_kind() -> None:
    with pytest.raises(AuthorityError):
        project_matter(ParsedResponse({"matterId": MATTER_ID}, 200), ReadSubject("vault-holds", MATTER_ID))
    with pytest.raises(AuthorityError):
        project_holds(ParsedResponse({}, 200), ReadSubject("vault-matter", MATTER_ID))


@dataclass(frozen=True)
class Reply:
    path: str
    body: JsonObject
    query: tuple[tuple[str, str], ...]
    status: int = 200


class Stream(httpx.SyncByteStream):
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.closed = False
        self.delivered = 0

    def __iter__(self) -> Iterator[bytes]:
        half = max(1, len(self.content) // 2)
        for chunk in (self.content[:half], self.content[half:]):
            self.delivered += len(chunk)
            yield chunk

    def close(self) -> None:
        self.closed = True


class Transport(httpx.MockTransport):
    def __init__(self, wire: VaultWire) -> None:
        super().__init__(wire.handle)
        self.closed = False

    def close(self) -> None:
        self.closed = True
        super().close()


@dataclass
class VaultWire:
    replies: list[Reply]
    calls: list[tuple[str, str, str, tuple[tuple[str, str], ...]]] = field(default_factory=list)
    streams: list[Stream] = field(default_factory=list)
    transports: list[Transport] = field(default_factory=list)
    resolutions: int = 0

    def resolve(self, profile: FrozenProfile) -> CredentialMaterial:
        assert profile.provider == "google-vault"
        self.resolutions += 1
        return CredentialMaterial("google-vault", "synthetic-vault-token")

    def handle(self, request: httpx.Request) -> httpx.Response:
        call = (request.method, request.url.host, request.url.path, tuple(request.url.params.multi_items()))
        self.calls.append(call)
        assert self.replies, "Unplanned provider request"
        reply = self.replies.pop(0)
        assert call[:3] == ("GET", "vault.googleapis.com", reply.path)
        assert sorted(call[3]) == sorted(reply.query)
        assert len(call[3]) == len({name for name, _ in call[3]})
        assert request.headers["Authorization"] == "Bearer synthetic-vault-token"
        assert request.content == b""
        body = json.dumps(reply.body, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        stream = Stream(body)
        self.streams.append(stream)
        return httpx.Response(reply.status, headers={"content-type": "application/json"}, stream=stream)

    def factory(self, context: ssl.SSLContext) -> httpx.BaseTransport:
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        transport = Transport(self)
        self.transports.append(transport)
        return transport

    def assert_finished(self) -> None:
        assert not self.replies
        assert all(s.closed for s in self.streams)
        assert all(t.closed for t in self.transports)


@pytest.fixture(autouse=True)
def isolated_destination(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def dns(
        host: str | bytes, port: int, family: int = 0, type: int = 0, proto: int = 0, flags: int = 0
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        assert host in ("vault.googleapis.com", b"vault.googleapis.com")
        assert port == 443
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]

    def forbidden_environment(name: str) -> str | None:
        raise AssertionError("Ambient credentials must not be read")

    def forbidden_connect(*args: object, **kwargs: object) -> None:
        raise AssertionError("A real connection is forbidden")

    monkeypatch.setattr(socket, "getaddrinfo", dns)
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", network_guard._GETADDRINFO_DELEGATE)
    monkeypatch.setattr(socket.socket, "connect", forbidden_connect)
    monkeypatch.setattr(_client, "ssl_context", lambda profile: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    monkeypatch.setattr(_credentials, "_environment_value", forbidden_environment)
    with network_guard.offline_mode(False):
        yield


def matter_reply(body: JsonObject | None = None, *, status: int = 200, identity: str = MATTER_ID) -> Reply:
    return Reply(
        "/v1/matters/" + identity,
        {"matterId": identity, "state": "OPEN"} if body is None else body,
        (("view", "BASIC"),),
        status,
    )


def holds_reply(body: JsonObject, *, token: str | None = None, status: int = 200, identity: str = MATTER_ID) -> Reply:
    query: tuple[tuple[str, str], ...] = (("view", "FULL_HOLD"), ("pageSize", "100"))
    if token is not None:
        query += (("pageToken", token),)
    return Reply("/v1/matters/" + identity + "/holds", body, query, status)


def complete(wire: VaultWire, identities: tuple[str, ...] = (MATTER_ID,)) -> EnterpriseRetentionCollectResult:
    request = EnterpriseRetentionCollectRequest.model_validate(
        {
            "provider": "google-vault",
            "profile_alias": "synthetic",
            "scope_label": "selected-configuration",
            "targets": [{"matter_id": identity} for identity in identities],
        }
    )
    profile = FrozenProfile(
        "synthetic",
        "google-vault",
        "https://vault.googleapis.com:443",
        "ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
        AddressPolicy("public"),
    )

    def no_sleep(delay: float) -> None:
        raise AssertionError("These domain cases must not retry")

    with EnterpriseReadSession(
        request,
        profile=AuthorizedProfile(profile, wire),
        transport_factory=wire.factory,
        utc_clock=lambda: NOW,
        monotonic_clock=lambda: 0.0,
        sleep=no_sleep,
        run_id_factory=lambda: RUN_ID,
    ) as session:
        targets = request.root.targets
        assert all(isinstance(t, VaultMatterTarget) for t in targets)
        resources = tuple(read_vault(t, session) for t in targets if isinstance(t, VaultMatterTarget))
        result = session.finish(resources)
    wire.assert_finished()
    encoded = result.model_dump_json(warnings="error")
    checked = EnterpriseRetentionCollectResult.model_validate_json(encoded)
    assert checked.model_dump(mode="python") == result.model_dump(mode="python")
    assert checked.root.manifest.attempts == len(wire.calls)
    assert checked.root.manifest.raw_bytes == sum(s.delivered for s in wire.streams)
    assert checked.root.manifest.decoded_bytes == checked.root.manifest.raw_bytes
    assert wire.resolutions == 1
    return checked


def selected_read(
    result: EnterpriseRetentionCollectResult, kind: str, identity: str = MATTER_ID
) -> EnterpriseRetentionReadResult:
    matches = [r for r in result.root.source_reads if r.kind == kind and r.source_id == identity]
    assert len(matches) == 1
    return matches[0]


def observation_ids(read: EnterpriseRetentionReadResult) -> list[str]:
    return [o.source_identity for o in read.observations]


def test_real_session_reads_only_basic_matter_and_full_hold_pages() -> None:
    token = "synthetic next/+?&=%"
    wire = VaultWire(
        [
            matter_reply(fixture_body("matter-open.json")),
            holds_reply(fixture_body("holds-accounts-page-1.json")),
            holds_reply(fixture_body("holds-org-unit-page-2.json"), token=token),
        ]
    )
    result = complete(wire)
    assert result.root.status == "complete"
    assert result.root.resources[0].status == "complete"
    holds = selected_read(result, "vault-holds")
    assert observation_ids(holds) == ["synthetic-mail-hold", "synthetic-calendar-hold"]
    assert (
        holds.attempts,
        holds.pages_received,
        holds.pages_admitted,
        holds.records_received,
        holds.records_admitted,
    ) == (2, 2, 2, 2, 2)
    assert holds.observations[0].fields["updateTime"] == TIME
    assert isinstance(result.root, _contracts.VaultCollectResult)
    assert result.root.provider == "google-vault"
    assert result.root.retention_rules_assessed is False
    assert result.root.recordset_completeness_assessed is False
    assert result.root.object_enforcement_assessed is False
    assert result.root.authenticated_identity_verified is False
    assert result.root.unassessed_surfaces == (
        "default_retention_rules",
        "custom_retention_rules",
        "held_record_coverage",
    )
    assert len(result.root.findings) == 1


@pytest.mark.parametrize("body", [{}, fixture_body("holds-empty.json"), {"holds": [], "nextPageToken": ""}])
def test_real_session_empty_terminal_holds_is_complete_but_rules_unassessed(body: JsonObject) -> None:
    result = complete(VaultWire([matter_reply(), holds_reply(body)]))
    holds = selected_read(result, "vault-holds")
    assert holds.status == "complete"
    assert holds.observations == []
    assert holds.pages_admitted == 1
    assert holds.records_received == holds.records_admitted == 0
    assert isinstance(result.root, _contracts.VaultCollectResult)
    assert result.root.retention_rules_assessed is False


def test_real_session_empty_intermediate_page_still_follows_raw_continuation() -> None:
    wire = VaultWire(
        [
            matter_reply(),
            holds_reply({"nextPageToken": "next"}),
            holds_reply({"holds": [{"holdId": "final"}]}, token="next"),
        ]
    )
    result = complete(wire)
    holds = selected_read(result, "vault-holds")
    assert holds.status == "complete"
    assert holds.pages_admitted == 2
    assert observation_ids(holds) == ["final"]


@pytest.mark.parametrize("status", [403, 404])
def test_later_failed_page_preserves_earlier_admitted_configuration(status: int) -> None:
    wire = VaultWire(
        [
            matter_reply(),
            holds_reply({"holds": [{"holdId": "retained"}], "nextPageToken": "next"}),
            holds_reply({"error": {"message": "SYNTHETIC_UNRETAINED_DETAIL"}}, token="next", status=status),
        ]
    )
    result = complete(wire)
    holds = selected_read(result, "vault-holds")
    assert result.root.status == "partial"
    assert holds.status == "partial"
    assert observation_ids(holds) == ["retained"]
    assert holds.pages_received == holds.pages_admitted == 1
    assert holds.attempts == holds.responses_received == 2
    assert wire.streams[-1].delivered == 0
    assert "SYNTHETIC_UNRETAINED_DETAIL" not in result.model_dump_json()


@pytest.mark.parametrize("status", [401, 403, 404])
def test_unavailable_matter_leaves_holds_unattempted(status: int) -> None:
    result = complete(VaultWire([matter_reply({"error": {}}, status=status)]))
    matter = selected_read(result, "vault-matter")
    holds = selected_read(result, "vault-holds")
    assert matter.status == holds.status == "unavailable"
    assert holds.attempts == holds.pages_received == 0
    assert result.root.status == "unavailable"


def test_unknown_matter_and_hold_detail_does_not_make_enumeration_partial() -> None:
    result = complete(
        VaultWire(
            [
                matter_reply({"matterId": MATTER_ID, "state": "FUTURE_STATE"}),
                holds_reply(fixture_body("holds-unknown-null.json")),
            ]
        )
    )
    assert result.root.status == "complete"
    for read in result.root.source_reads:
        assert read.status == "complete"
        assert read.observations[0].interpretation_status == "limited"


def test_wrong_matter_identity_prevents_holds_request() -> None:
    result = complete(VaultWire([matter_reply({"matterId": "foreign", "state": "OPEN"})]))
    assert selected_read(result, "vault-matter").terminal_reason == "identity_mismatch"
    assert selected_read(result, "vault-holds").attempts == 0


def test_invalid_later_member_refuses_whole_page_and_does_not_commit_prefix_conflict() -> None:
    wire = VaultWire(
        [
            matter_reply(),
            holds_reply({"holds": [{"holdId": "synthetic-mail-hold", "name": "original"}], "nextPageToken": "next"}),
            holds_reply(fixture_body("holds-invalid-member.json"), token="next"),
        ]
    )
    result = complete(wire)
    holds = selected_read(result, "vault-holds")
    assert holds.status == "partial"
    assert holds.records_received == 3 and holds.records_admitted == 1
    assert holds.pages_received == 2 and holds.pages_admitted == 1
    assert holds.conflicts_quarantined == 0
    assert holds.observations[0].fields["name"] == "original"
    assert holds.terminal_reason == "invalid_response"


@pytest.mark.parametrize("within_page", [False, True])
def test_ignored_source_fields_cannot_create_duplicate_conflicts(within_page: bool) -> None:
    first: JsonObject = {
        "holdId": "same",
        "accounts": [{"accountId": "same-account", "email": "first@example.invalid"}],
        "unselected": 1,
    }
    second: JsonObject = {
        "holdId": "same",
        "accounts": [{"accountId": "same-account", "email": "other@example.invalid", "firstName": "Excluded"}],
        "unselected": {"changed": True},
    }
    pages = (
        [holds_reply({"holds": [first, second]})]
        if within_page
        else [holds_reply({"holds": [first], "nextPageToken": "next"}), holds_reply({"holds": [second]}, token="next")]
    )
    result = complete(VaultWire([matter_reply(), *pages]))
    holds = selected_read(result, "vault-holds")
    assert holds.status == "complete"
    assert observation_ids(holds) == ["same"]
    assert holds.records_received == 2 and holds.records_admitted == 1
    assert holds.duplicates_coalesced == 1 and holds.conflicts_quarantined == 0


def test_conflicting_identity_is_quarantined_permanently_without_losing_other_records() -> None:
    second = fixture_body("holds-conflict-page-2.json")
    second["nextPageToken"] = "last"
    wire = VaultWire(
        [
            matter_reply(),
            holds_reply({"holds": [{"holdId": "synthetic-mail-hold", "name": "original"}], "nextPageToken": "next"}),
            holds_reply(second, token="next"),
            holds_reply(
                {"holds": [{"holdId": "synthetic-mail-hold", "name": "original"}, {"holdId": "after"}]}, token="last"
            ),
        ]
    )
    result = complete(wire)
    holds = selected_read(result, "vault-holds")
    assert holds.status == "partial"
    assert observation_ids(holds) == ["synthetic-survivor", "after"]
    assert (holds.records_received, holds.records_admitted, holds.conflicts_quarantined) == (5, 2, 1)
    assert holds.pages_admitted == 3


def test_native_integer_and_float_query_values_are_different_source_projections() -> None:
    wire = VaultWire(
        [
            matter_reply(),
            holds_reply(
                {
                    "holds": [
                        {"holdId": "same", "query": {"futureQuery": {"value": 1}}},
                        {"holdId": "same", "query": {"futureQuery": {"value": 1.0}}},
                    ]
                }
            ),
        ]
    )
    result = complete(wire)
    holds = selected_read(result, "vault-holds")
    assert holds.status == "partial"
    assert holds.records_admitted == 0 and holds.conflicts_quarantined == 1


@pytest.mark.parametrize("token", [None, False, 0, 1.0, [], {}, "a" * 4097, "\u00e9" * 2049])
def test_invalid_raw_continuation_refuses_entire_page_without_followup(token: JsonValue) -> None:
    result = complete(
        VaultWire([matter_reply(), holds_reply({"holds": [{"holdId": "not-admitted"}], "nextPageToken": token})])
    )
    holds = selected_read(result, "vault-holds")
    assert holds.terminal_reason == "token_invalid"
    assert holds.pages_received == 1 and holds.pages_admitted == 0
    assert holds.records_received == 1 and holds.records_admitted == 0


def test_repeated_token_refuses_current_page_and_retains_prior_page() -> None:
    result = complete(
        VaultWire(
            [
                matter_reply(),
                holds_reply({"holds": [{"holdId": "first"}], "nextPageToken": "same"}),
                holds_reply({"holds": [{"holdId": "second"}], "nextPageToken": "same"}, token="same"),
            ]
        )
    )
    holds = selected_read(result, "vault-holds")
    assert holds.terminal_reason == "token_repeated"
    assert observation_ids(holds) == ["first"]
    assert holds.pages_received == 2 and holds.pages_admitted == 1


def test_hold_identity_never_changes_selected_endpoint_and_duplicate_scope_is_per_matter() -> None:
    identity = "../opaque/?x=%2f#fragment"
    wire = VaultWire(
        [
            matter_reply(identity="first"),
            holds_reply({"holds": [{"holdId": identity, "name": "first"}]}, identity="first"),
            matter_reply(identity="second"),
            holds_reply({"holds": [{"holdId": identity, "name": "second"}]}, identity="second"),
        ]
    )
    result = complete(wire, ("first", "second"))
    assert result.root.status == "complete"
    for matter_id in ("first", "second"):
        read = selected_read(result, "vault-holds", matter_id)
        assert observation_ids(read) == [identity]
        assert read.conflicts_quarantined == 0


def test_page_cap_refuses_last_candidate_without_losing_admitted_empty_pages() -> None:
    pages = [
        holds_reply({"holds": [], "nextPageToken": str(i + 1)}, token=None if i == 0 else str(i)) for i in range(20)
    ]
    result = complete(VaultWire([matter_reply(), *pages]))
    holds = selected_read(result, "vault-holds")
    assert holds.terminal_reason == "page_limit"
    assert holds.status == "partial"
    assert holds.pages_received == 20 and holds.pages_admitted == 19
    assert holds.records_received == holds.records_admitted == 0


def test_received_record_cap_is_not_bypassed_by_duplicate_coalescing() -> None:
    members: list[JsonValue] = [{"holdId": "same"} for _ in range(2001)]
    result = complete(VaultWire([matter_reply(), holds_reply({"holds": members})]))
    holds = selected_read(result, "vault-holds")
    assert holds.terminal_reason == "record_limit"
    assert holds.records_received == 2001 and holds.records_admitted == 0
    assert holds.pages_received == 1 and holds.pages_admitted == 0


def test_pure_full_fixture_and_real_session_native_json_values_agree_without_rounding() -> None:
    source = copy.deepcopy(HOLD)
    source["query"] = {"futureQuery": {"large": 9007199254740993, "float": 1.0, "negativeZero": -0.0, "time": TIME}}
    expected = copy.deepcopy(source)
    result = complete(VaultWire([matter_reply(), holds_reply({"holds": [source]})]))
    read = selected_read(result, "vault-holds")
    same_json(read.observations[0].fields, expected)
    assert read.status == "complete"
    assert read.observations[0].interpretation_status == "limited"
