"""Synthetic acceptance for stateless envelopes and callback correspondence."""

from __future__ import annotations

import copy
import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Any, cast

import pytest
from evidentia_collectors.enterprise_retention._client import (
    COUNTER_MAX,
    AuthorityError,
    NativeScope,
    ParsedResponse,
    ProjectedPage,
    ProjectedRecord,
    RawExplainRelation,
    ReadSubject,
    SourceOccurrence,
    SourceOptionalText,
    extract_authority,
    received_record_count,
    validate_projected_page,
)
from evidentia_collectors.enterprise_retention._contracts import ReadKey, ReadKind, expected_fields
from evidentia_collectors.enterprise_retention._parsing import (
    JsonObject,
    canonical_json,
    checked_json,
    parse_strict_json,
)
from pydantic import ValidationError

# Authored synthetic source cases; no tenant recording or live acceptance is implied.
CASE_DIR = Path(__file__).resolve().parents[3] / "fixtures" / "enterprise_retention"
POSITIVES: list[dict[str, Any]] = json.loads((CASE_DIR / "source-field-cases.json").read_text(encoding="utf-8"))[
    "cases"
]
NEGATIVES: list[dict[str, Any]] = json.loads(
    (CASE_DIR / "source-field-negative-cases.json").read_text(encoding="utf-8")
)["cases"]
BY_ID = {case["id"]: case for case in POSITIVES}
SCOPE: dict[str, NativeScope] = {
    "vault-matter": "matter",
    "vault-holds": "hold",
    "splunk-index": "index",
    "elastic-explain": "index",
    "elastic-policy": "policy",
    "elastic-status": "service",
}


def encode(value: object) -> bytes:
    return canonical_json(checked_json(value))


def sources(kind: ReadKind, raw: JsonObject, identity: str) -> list[JsonObject]:
    if kind == "vault-holds":
        return cast(list[JsonObject], raw.get("holds", []))
    if kind == "splunk-index":
        return cast(list[JsonObject], raw["entry"])
    if kind == "elastic-explain":
        return [cast(dict[str, JsonObject], raw["indices"])[identity]]
    if kind == "elastic-policy":
        return [cast(JsonObject, raw[identity])]
    return [raw]


def key_for(case: dict[str, Any]) -> ReadKey:
    return ReadKey(kind=case["read_kind"], source_id=case["subject"]["source_id"])


def project(key: ReadKey, raw: JsonObject) -> ProjectedPage:
    records = []
    for ordinal, source in enumerate(sources(key.kind, raw, key.source_id)):
        selected = expected_fields(key.kind, source)
        identity = str(source["holdId"]) if key.kind == "vault-holds" else key.source_id
        records.append(
            ProjectedRecord(
                ordinal, identity, SCOPE[key.kind], selected.fields, selected.coverage, selected.diagnostics
            )
        )
    return ProjectedPage(tuple(records))


def change(value: Any, recipe: dict[str, Any]) -> None:
    path = recipe["path"]
    for key in path[:-1]:
        value = value[key]
    key = path[-1]
    if recipe["operation"] == "delete":
        del value[key]
    elif recipe["operation"] == "reverse":
        value[key].reverse()
    else:
        value[key] = parse_strict_json(recipe["value_json"].encode("utf-8"))


def earlier_witness() -> ProjectedPage:
    return project(
        ReadKey(kind="vault-holds", source_id="earlier-matter"),
        {"holds": [{"holdId": "earlier-hold", "query": {"future": [1, -0.0]}}]},
    )


def witness_bytes(page: ProjectedPage) -> bytes:
    return encode(
        [
            {"ordinal": r.source_ordinal, "id": r.source_identity, "fields": r.fields, "coverage": r.field_coverage}
            for r in page.records
        ]
    )


@pytest.mark.parametrize("case", POSITIVES, ids=[case["id"] for case in POSITIVES])
def test_all_adopted_positive_envelopes(case: dict[str, Any]) -> None:
    key = key_for(case)
    raw = copy.deepcopy(case["raw_response"])
    body = encode(raw)
    count = received_record_count(key.kind, raw)
    authority = extract_authority(key, 1, raw)
    candidate = project(key, raw)
    result = validate_projected_page(authority, body, candidate)
    assert result == candidate and result is not candidate
    assert count == len(result.records) == len(case["expected_records"])
    for record, expected in zip(result.records, case["expected_records"], strict=True):
        assert record.source_ordinal == expected["source_ordinal"]
        assert record.source_identity == expected["source_identity"]
        assert encode(record.fields) == encode(expected["fields"])
        assert record.field_coverage == expected["field_coverage"]
        assert record.native_scope == SCOPE[key.kind]
    if key.kind == "vault-holds":
        expected_token = raw.get("nextPageToken")
        assert authority.continuation.value == expected_token
        assert authority.continuation.presence == (
            "absent" if expected_token is None else "value" if expected_token else "empty"
        )
    if key.kind == "elastic-explain":
        source = raw["indices"][key.source_id]
        relation = authority.explain_relation
        assert relation is not None and relation.managed is source["managed"]
        assert relation.index == key.source_id
        assert relation.policy.value == source.get("policy")
        assert relation.policy.presence == (
            "absent"
            if "policy" not in source
            else "null"
            if source["policy"] is None
            else "empty"
            if source["policy"] == ""
            else "value"
        )
    assert encode(raw) == body


@pytest.mark.parametrize("recipe", NEGATIVES, ids=[case["id"] for case in NEGATIVES])
def test_all_adopted_negative_recipes(recipe: dict[str, Any]) -> None:
    case = BY_ID[recipe["base_case"]]
    key = key_for(case)
    raw = copy.deepcopy(case["raw_response"])
    base = project(key, raw)
    records = copy.deepcopy(case["expected_records"])
    old = earlier_witness()
    old_bytes = witness_bytes(old)
    mutation = recipe["mutation"]
    change(raw if mutation["target"] == "raw_response" else records, mutation)
    with pytest.raises(AuthorityError) as exc:
        authority = extract_authority(key, 1, raw)
        projected = []
        for index, item in enumerate(records):
            projected.append(
                ProjectedRecord(
                    item["source_ordinal"],
                    item["source_identity"],
                    SCOPE[key.kind],
                    item["fields"],
                    item["field_coverage"],
                    base.records[index].diagnostics,
                )
            )
        validate_projected_page(authority, encode(raw), ProjectedPage(tuple(projected)))
    assert exc.value.code in recipe["expected"]["allowed_fixed_codes"]
    assert str(exc.value) == exc.value.code
    assert witness_bytes(old) == old_bytes
    # Actual next-request prevention requires the controller's session tests.
    assert recipe["expected"]["zero_unauthorized_followup"] is True


@pytest.mark.parametrize(
    "kind,data,count",
    [
        ("vault-matter", {}, 1),
        ("vault-matter", [], 0),
        ("vault-holds", {}, 0),
        ("vault-holds", {"holds": []}, 0),
        ("vault-holds", {"holds": [None, {}]}, 2),
        ("splunk-index", {"entry": [None, {}]}, 2),
        ("elastic-status", {}, 1),
        ("elastic-explain", {"indices": {"i": {}}}, 1),
        ("elastic-policy", {"p": {}}, 1),
        ("vault-holds", {"holds": None}, 0),
        ("splunk-index", {"entry": {}}, 0),
        ("elastic-explain", {"indices": {"wrong": {}}}, 1),
        ("elastic-policy", {"wrong": {}}, 1),
        ("elastic-policy", {"p": {}, "extra": {}}, 0),
        ("elastic-explain", {"indices": {"i": None}}, 0),
        ("elastic-status", None, 0),
    ],
)
def test_received_counts_before_identity_or_member_refusal(kind: str, data: object, count: int) -> None:
    assert received_record_count(kind, data) == count


@pytest.mark.parametrize(
    "key,data", [(None, {}), ("forged", {}), ({"kind": "vault-matter", "source_id": "m"}, {"matterId": "m"})]
)
def test_forged_keys_are_refused(key: Any, data: Any) -> None:
    with pytest.raises(AuthorityError):
        extract_authority(key, 1, data)


def test_forged_authority_and_page_refused() -> None:
    with pytest.raises(AuthorityError):
        validate_projected_page(cast(Any, {}), b"{}", cast(Any, {}))


@pytest.mark.parametrize(
    "kind,identity",
    [
        ("vault-matter", "a/b"),
        ("vault-holds", "a%2fb"),
        ("splunk-index", "_ALL"),
        ("splunk-index", "_new"),
        ("splunk-index", "_Reload"),
        ("elastic-explain", "Upper"),
        ("elastic-explain", ".."),
        ("elastic-policy", "_All"),
        ("elastic-policy", "x?query"),
        ("elastic-status", "different"),
        ("future", "m"),
        (True, "m"),
        ("vault-matter", 1),
    ],
)
def test_finite_read_identity_grammar(kind: Any, identity: Any) -> None:
    with pytest.raises(ValidationError):
        ReadKey(kind=kind, source_id=identity)
    with pytest.raises(AuthorityError):
        ReadSubject(kind, identity)


@pytest.mark.parametrize("sequence", [True, False, 0, -1, 1.0, "1", COUNTER_MAX + 1])
def test_page_sequence_is_strict_positive_uint128(sequence: Any) -> None:
    with pytest.raises(AuthorityError):
        extract_authority(ReadKey(kind="vault-matter", source_id="m"), sequence, {"matterId": "m"})


@pytest.mark.parametrize(
    "raw", [{"holds": [None, {"holdId": "h"}]}, {"holds": [{"holdId": "h"}, 0]}, {"holds": [{"holdId": " "}]}]
)
def test_raw_invalid_members_count_before_refusal(raw: JsonObject) -> None:
    assert received_record_count("vault-holds", raw) == len(cast(list[Any], raw["holds"]))
    with pytest.raises(AuthorityError):
        extract_authority(ReadKey(kind="vault-holds", source_id="m"), 1, raw)


@pytest.mark.parametrize("mutation", ["drop", "duplicate", "reverse", "collapse", "ordinal", "identity"])
def test_whole_page_ordinal_membership_and_repeated_ids(mutation: str) -> None:
    key = ReadKey(kind="vault-holds", source_id="m")
    raw: JsonObject = {
        "holds": [{"holdId": "a", "corpus": "MAIL"}, {"holdId": "b"}, {"holdId": "a", "corpus": "DRIVE"}]
    }
    authority = extract_authority(key, 1, raw)
    page = project(key, raw)
    valid = validate_projected_page(authority, encode(raw), page)
    assert [r.source_identity for r in valid.records] == ["a", "b", "a"]
    items = list(page.records)
    if mutation == "drop":
        items.pop()
    elif mutation == "duplicate":
        items[1] = ProjectedRecord(1, "a", "hold", items[0].fields, items[0].field_coverage, items[0].diagnostics)
    elif mutation == "reverse":
        items.reverse()
    elif mutation == "collapse":
        items = items[:2]
    elif mutation == "ordinal":
        item = items[1]
        items[1] = ProjectedRecord(0, item.source_identity, "hold", item.fields, item.field_coverage, item.diagnostics)
    else:
        item = items[1]
        items[1] = ProjectedRecord(1, "other", "hold", item.fields, item.field_coverage, item.diagnostics)
    old = witness_bytes(valid)
    with pytest.raises(AuthorityError):
        validate_projected_page(authority, encode(raw), ProjectedPage(tuple(items)))
    assert witness_bytes(valid) == old


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_ordinal", True),
        ("source_ordinal", 1.0),
        ("source_identity", 1),
        ("native_scope", "policy"),
        ("diagnostics", ()),
        ("_fields", b'{"holdId":"changed"}'),
    ],
)
def test_forged_record_revalidates_before_comparison(field: str, value: object) -> None:
    key = ReadKey(kind="vault-holds", source_id="m")
    raw: JsonObject = {"holds": [{"holdId": "h"}]}
    authority = extract_authority(key, 1, raw)
    page = project(key, raw)
    object.__setattr__(page.records[0], field, value)
    with pytest.raises(AuthorityError):
        validate_projected_page(authority, encode(raw), page)


@pytest.mark.parametrize(
    "raw", [{}, {"holds": []}, {"holds": [], "nextPageToken": ""}, {"nextPageToken": "opaque+/%3F"}]
)
def test_only_real_empty_holds_pages_are_empty(raw: JsonObject) -> None:
    key = ReadKey(kind="vault-holds", source_id="m")
    authority = extract_authority(key, 1, raw)
    assert validate_projected_page(authority, encode(raw), ProjectedPage(())).records == ()
    assert authority.continuation.value == raw.get("nextPageToken")


@pytest.mark.parametrize(
    "kind,identity,raw",
    [
        ("vault-matter", "m", {"matterId": "m"}),
        ("splunk-index", "i", {"entry": [{"name": "i", "content": {}}]}),
        ("elastic-explain", "i", {"indices": {"i": {"index": "i", "managed": False}}}),
        ("elastic-policy", "p", {"p": {}}),
        ("elastic-status", "service", {}),
    ],
)
def test_non_holds_source_object_cannot_be_filtered(kind: ReadKind, identity: str, raw: JsonObject) -> None:
    authority = extract_authority(ReadKey(kind=kind, source_id=identity), 1, raw)
    with pytest.raises(AuthorityError):
        validate_projected_page(authority, encode(raw), ProjectedPage(()))


@pytest.mark.parametrize("token", [None, True, 1, [], {}, "\u00e9" * 2049, "x" * 4097])
def test_invalid_tokens_never_reach_authority(token: Any) -> None:
    with pytest.raises(AuthorityError, match=r"^token_invalid$"):
        extract_authority(ReadKey(kind="vault-holds", source_id="m"), 1, {"nextPageToken": token})


@pytest.mark.parametrize("token", ["x" * 4096, "\u00e9" * 2048, "opaque+/%3F", " \t"])
def test_valid_tokens_remain_exact_opaque_strings(token: str) -> None:
    raw: JsonObject = {"nextPageToken": token}
    authority = extract_authority(ReadKey(kind="vault-holds", source_id="m"), 1, raw)
    assert authority.continuation == SourceOptionalText("value", token)
    assert validate_projected_page(authority, encode(raw), ProjectedPage(())).records == ()


@pytest.mark.parametrize(
    "presence,policy",
    [("absent", None), ("null", None), ("empty", ""), ("value", "p"), ("value", "unsupported/raw?policy")],
)
@pytest.mark.parametrize("managed", [True, False])
def test_raw_policy_presence_and_boolean_are_independent(presence: str, policy: str | None, managed: bool) -> None:
    leaf: JsonObject = {"index": "i", "managed": managed, "phase_execution": {"policy": "cached-is-not-current"}}
    if presence != "absent":
        leaf["policy"] = policy
    raw: JsonObject = {"indices": {"i": leaf}}
    key = ReadKey(kind="elastic-explain", source_id="i")
    authority = extract_authority(key, 1, raw)
    assert authority.explain_relation is not None
    assert authority.explain_relation.managed is managed
    assert authority.explain_relation.policy.presence == presence
    assert authority.explain_relation.policy.value == policy
    validate_projected_page(authority, encode(raw), project(key, raw))
    for wrong in (None, "", "substitute"):
        if presence != "absent" and wrong == policy:
            continue
        changed = copy.deepcopy(raw)
        cast(dict[str, JsonObject], changed["indices"])["i"]["policy"] = wrong
        with pytest.raises(AuthorityError):
            validate_projected_page(authority, encode(raw), project(key, changed))


@pytest.mark.parametrize("managed", [0, 1, 1.0, None, "true"])
def test_explain_requires_raw_boolean_before_callback(managed: Any) -> None:
    with pytest.raises(AuthorityError):
        extract_authority(
            ReadKey(kind="elastic-explain", source_id="i"), 1, {"indices": {"i": {"index": "i", "managed": managed}}}
        )


@pytest.mark.parametrize("replacement", [True, False, 1])
def test_changed_managed_never_authorizes_projection(replacement: Any) -> None:
    key = ReadKey(kind="elastic-explain", source_id="i")
    raw: JsonObject = {"indices": {"i": {"index": "i", "managed": not bool(replacement), "policy": "p"}}}
    authority = extract_authority(key, 1, raw)
    page = project(key, raw)
    fields = page.records[0].fields
    fields["managed"] = replacement
    changed = ProjectedRecord(0, "i", "index", fields, page.records[0].field_coverage, page.records[0].diagnostics)
    with pytest.raises(AuthorityError):
        validate_projected_page(authority, encode(raw), ProjectedPage((changed,)))


def test_detached_callback_input_cannot_replace_token_or_relation() -> None:
    raw: JsonObject = {"holds": [{"holdId": "h"}], "nextPageToken": "original-token"}
    key = ReadKey(kind="vault-holds", source_id="m")
    body = encode(raw)
    authority = extract_authority(key, 1, raw)
    response, subject = ParsedResponse(raw, 200), ReadSubject(key.kind, key.source_id)
    view = response.data
    view["nextPageToken"] = "substituted-token"
    cast(list[JsonObject], view["holds"])[0]["holdId"] = "changed"
    raw.clear()
    object.__setattr__(subject, "source_id", "changed")
    assert response.data["nextPageToken"] == authority.continuation.value == "original-token"
    original = project(key, response.data)
    validate_projected_page(authority, body, original)
    with pytest.raises(AuthorityError):
        validate_projected_page(authority, body, project(key, view))
    assert key.source_id == "m"


@pytest.mark.parametrize(
    "token", [SourceOptionalText("absent"), SourceOptionalText("empty", ""), SourceOptionalText("value", "substitute")]
)
def test_authority_token_cannot_be_stripped_or_substituted(token: SourceOptionalText) -> None:
    raw: JsonObject = {"nextPageToken": "original"}
    authority = extract_authority(ReadKey(kind="vault-holds", source_id="m"), 1, raw)
    forged = replace(authority, continuation=token)
    with pytest.raises(AuthorityError):
        validate_projected_page(forged, encode(raw), ProjectedPage(()))


@pytest.mark.parametrize(
    "messages,code",
    [
        (None, "invalid_response"),
        ({}, "invalid_response"),
        ([None], "invalid_response"),
        ([{}], "invalid_response"),
        ([{"type": True}], "invalid_response"),
        ([{"type": "ERROR", "text": "sensitive synthetic text"}], "upstream_error"),
        ([{"type": "WARN"}, {"type": "ERROR"}], "upstream_error"),
    ],
)
def test_splunk_invalid_or_error_envelopes_refuse_before_callback(messages: Any, code: str) -> None:
    raw: JsonObject = {"entry": [{"name": "i", "content": {}}], "messages": messages}
    callback_calls: list[str] = []
    with pytest.raises(AuthorityError) as exc:
        authority = extract_authority(ReadKey(kind="splunk-index", source_id="i"), 1, raw)
        callback_calls.append("called")
        validate_projected_page(authority, encode(raw), project(ReadKey(kind="splunk-index", source_id="i"), raw))
    assert exc.value.code == code and callback_calls == []
    assert "sensitive synthetic" not in str(exc.value)


@pytest.mark.parametrize(
    "types,expected",
    [
        (["INFO", "DEBUG"], ()),
        (["WARN", "WARN"], ("upstream_warning",)),
        (["future"], ("unsupported_source_value",)),
        (["future", "WARN", "INFO"], ("upstream_warning", "unsupported_source_value")),
    ],
)
def test_splunk_warnings_are_retained_independently_of_callback(types: list[str], expected: tuple[str, ...]) -> None:
    raw: JsonObject = {
        "entry": [{"name": "i", "content": {}}],
        "messages": [{"type": t, "text": "excluded synthetic text"} for t in types],
    }
    key = ReadKey(kind="splunk-index", source_id="i")
    authority = extract_authority(key, 1, raw)
    page = project(key, raw)
    result = validate_projected_page(authority, encode(raw), page)
    assert authority.diagnostics == expected and result.diagnostics == ()
    assert "excluded synthetic text" not in repr(authority)
    assert "excluded synthetic text" not in repr(result)


def test_callback_cannot_fabricate_read_warning() -> None:
    key = ReadKey(kind="elastic-status", source_id="service")
    raw: JsonObject = {"operation_mode": "RUNNING"}
    page = project(key, raw)
    with pytest.raises(AuthorityError):
        validate_projected_page(
            extract_authority(key, 1, raw), encode(raw), ProjectedPage(page.records, ("upstream_warning",))
        )


def test_returned_page_is_independent_of_callback_owned_state_and_views() -> None:
    key = ReadKey(kind="vault-holds", source_id="m")
    raw: JsonObject = {"holds": [{"holdId": "h", "accounts": [{"accountId": "a"}]}]}
    candidate = project(key, raw)
    result = validate_projected_page(extract_authority(key, 1, raw), encode(raw), candidate)
    snapshot = witness_bytes(result)
    assert result.records[0] is not candidate.records[0]
    fields = result.records[0].fields
    fields["accounts"] = []
    coverage = result.records[0].field_coverage
    coverage["accounts"] = "absent"
    object.__setattr__(candidate.records[0], "_fields", b"{}")
    object.__setattr__(candidate, "records", ())
    assert witness_bytes(result) == snapshot
    with pytest.raises(FrozenInstanceError):
        cast(Any, result).records = ()


@pytest.mark.parametrize(
    "body", [b'{"holds":[],"holds":[]}', b'{"holds":NaN}', b"\xef\xbb\xbf{}", b'{"holds":', b'{"holds":[]}', b"[]"]
)
def test_wrong_or_invalid_source_bytes_do_not_validate_old_authority(body: bytes) -> None:
    raw: JsonObject = {"holds": [{"holdId": "h"}]}
    key = ReadKey(kind="vault-holds", source_id="m")
    with pytest.raises(AuthorityError):
        validate_projected_page(extract_authority(key, 1, raw), body, project(key, raw))


@pytest.mark.parametrize("status", [True, 199, 201, 204, 206, 500, "200"])
def test_callback_response_status_is_only_successful_source_200(status: Any) -> None:
    with pytest.raises(AuthorityError):
        ParsedResponse({}, status)


def test_sensitive_data_are_excluded_from_internal_repr() -> None:
    raw: JsonObject = {"holds": [{"holdId": "sensitive-hold"}], "nextPageToken": "sensitive-token"}
    key = ReadKey(kind="vault-holds", source_id="sensitive-matter")
    authority = extract_authority(key, 1, raw)
    for value in (
        key,
        authority,
        authority.continuation,
        authority.occurrences[0],
        ParsedResponse(raw, 200),
        project(key, raw),
        ReadSubject(key.kind, key.source_id),
    ):
        assert "sensitive-" not in repr(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("page_sequence", True),
        ("diagnostics", ("upstream_warning",)),
        ("read_key", {"kind": "elastic-status", "source_id": "service"}),
    ],
)
def test_forged_authority_revalidation(field: str, value: object) -> None:
    raw: JsonObject = {"operation_mode": "RUNNING"}
    key = ReadKey(kind="elastic-status", source_id="service")
    authority = extract_authority(key, 1, raw)
    object.__setattr__(authority, field, value)
    with pytest.raises(AuthorityError):
        validate_projected_page(authority, encode(raw), project(key, raw))


def test_forged_protected_native_scalar_rejects_even_when_python_equality_matches() -> None:
    raw: JsonObject = {"indices": {"i": {"index": "i", "managed": True, "policy": "p"}}}
    key = ReadKey(kind="elastic-explain", source_id="i")
    authority = extract_authority(key, 1, raw)
    protected = SourceOccurrence(0, "i", encode({"index": "i", "managed": 1, "policy": "p"}))
    with pytest.raises(AuthorityError):
        validate_projected_page(replace(authority, occurrences=(protected,)), encode(raw), project(key, raw))
    relation = RawExplainRelation("i", True, SourceOptionalText("value", "p"))
    object.__setattr__(relation, "managed", 1)
    with pytest.raises(AuthorityError):
        replace(authority, explain_relation=relation)


def test_document_bounds_stay_at_parser_boundary() -> None:
    raw: dict[str, Any] = {}
    raw["cycle"] = raw
    with pytest.raises(AuthorityError, match=r"^invalid_json$"):
        received_record_count("elastic-status", raw)
    with pytest.raises(AuthorityError):
        ParsedResponse(cast(JsonObject, raw), 200)
    nested: Any = 1
    for _ in range(17):
        nested = [nested]
    with pytest.raises(AuthorityError, match=r"^invalid_json$"):
        received_record_count("elastic-status", nested)
    with pytest.raises(AuthorityError):
        extract_authority(ReadKey(kind="elastic-status", source_id="service"), 1, {"bad": 1 << 500})


def test_exact_native_numbers_survive_callback_and_returned_snapshot() -> None:
    key = ReadKey(kind="elastic-policy", source_id="p")
    raw: JsonObject = {
        "p": {"policy": {"phases": {"hot": {"actions": {"custom": {"zero": -0.0, "huge": 10**127, "fraction": 0.1}}}}}}
    }
    page = validate_projected_page(extract_authority(key, 1, raw), encode(raw), project(key, raw))
    fields = encode(page.records[0].fields)
    assert b'"zero":-0.0' in fields and b'"huge":1' + b"0" * 127 in fields and b'"fraction":0.1' in fields


@pytest.mark.parametrize(
    "kind,identity,raw,code",
    [
        ("vault-matter", "m", {"matterId": "other"}, "identity_mismatch"),
        ("splunk-index", "i", {"entry": [{"name": "other", "content": {}}]}, "identity_mismatch"),
        (
            "splunk-index",
            "i",
            {"entry": [{"name": "i", "content": {}}, {"name": "i", "content": {}}]},
            "invalid_response",
        ),
        ("splunk-index", "i", {"entry": [{"name": "i", "content": None}]}, "invalid_response"),
        ("elastic-explain", "i", {"indices": {"other": {"index": "i", "managed": True}}}, "identity_mismatch"),
        ("elastic-explain", "i", {"indices": {"i": {"index": "other", "managed": True}}}, "identity_mismatch"),
        ("elastic-explain", "i", {"indices": {"i": {"index": "i", "managed": True}, "other": {}}}, "identity_mismatch"),
        ("elastic-policy", "p", {"other": {}}, "identity_mismatch"),
        ("elastic-policy", "p", {"p": {}, "other": {}}, "identity_mismatch"),
        ("elastic-policy", "p", {"p": None}, "invalid_response"),
    ],
)
def test_exact_selected_envelope_identity_before_projection(
    kind: ReadKind, identity: str, raw: JsonObject, code: str
) -> None:
    with pytest.raises(AuthorityError) as exc:
        extract_authority(ReadKey(kind=kind, source_id=identity), 1, raw)
    assert exc.value.code == code


@pytest.mark.parametrize(
    "hold_id,accepted",
    [("h" * 1024, True), ("\u00e9" * 512, True), ("\u00e9" * 513, False), (" h ", True), (" \t", False)],
)
def test_hold_identity_uses_literal_nonblank_utf8_bound(hold_id: str, accepted: bool) -> None:
    key = ReadKey(kind="vault-holds", source_id="m")
    raw: JsonObject = {"holds": [{"holdId": hold_id}]}
    if accepted:
        authority = extract_authority(key, 1, raw)
        assert authority.occurrences[0].source_identity == hold_id
        assert validate_projected_page(authority, encode(raw), project(key, raw)).records[0].source_identity == hold_id
    else:
        with pytest.raises(AuthorityError):
            extract_authority(key, 1, raw)


@pytest.mark.parametrize("action", ["delete", "replace"])
def test_token_only_callback_mutation_cannot_stop_or_extend_raw_continuation(action: str) -> None:
    key = ReadKey(kind="vault-holds", source_id="m")
    raw: JsonObject = {"holds": [{"holdId": "h"}], "nextPageToken": "raw-token"}
    body = encode(raw)
    authority = extract_authority(key, 1, raw)
    callback_view = ParsedResponse(raw, 200).data
    if action == "delete":
        del callback_view["nextPageToken"]
    else:
        callback_view["nextPageToken"] = "callback-token"
    page = validate_projected_page(authority, body, project(key, callback_view))
    assert len(page.records) == 1
    assert authority.continuation == SourceOptionalText("value", "raw-token")
    assert not hasattr(page, "continuation")


def test_relationship_and_key_inputs_are_detached_before_callback() -> None:
    key = ReadKey(kind="elastic-explain", source_id="i")
    raw: JsonObject = {"indices": {"i": {"index": "i", "managed": False, "policy": "original"}}}
    body = encode(raw)
    authority = extract_authority(key, 1, raw)
    response = ParsedResponse(raw, 200)
    view = response.data
    cast(dict[str, JsonObject], view["indices"])["i"]["managed"] = True
    cast(dict[str, JsonObject], view["indices"])["i"]["policy"] = "replacement"
    cast(dict[str, JsonObject], raw["indices"])["i"]["policy"] = "caller-change"
    object.__setattr__(key, "source_id", "caller-change")
    assert authority.read_key.source_id == "i"
    assert authority.explain_relation is not None
    assert authority.explain_relation.managed is False
    assert authority.explain_relation.policy.value == "original"
    validate_projected_page(authority, body, project(authority.read_key, response.data))
    with pytest.raises(AuthorityError):
        validate_projected_page(authority, body, project(authority.read_key, view))


@pytest.mark.parametrize(
    "diagnostics",
    [
        [],
        ("missing_source_detail", "unsupported_source_value"),
        ("missing_source_detail", "missing_source_detail"),
        ("arbitrary-message",),
        (True,),
    ],
)
def test_record_diagnostics_require_fixed_distinct_order(diagnostics: Any) -> None:
    with pytest.raises(AuthorityError):
        ProjectedRecord(0, "h", "hold", {"holdId": "h"}, {}, diagnostics)


@pytest.mark.parametrize(
    "diagnostics",
    [
        [],
        ("unsupported_source_value", "upstream_warning"),
        ("upstream_warning", "upstream_warning"),
        ("arbitrary-message",),
        (True,),
    ],
)
def test_page_diagnostics_require_fixed_distinct_order(diagnostics: Any) -> None:
    with pytest.raises(AuthorityError):
        ProjectedPage((), diagnostics)


@pytest.mark.parametrize(
    "presence,value",
    [("absent", "x"), ("null", ""), ("empty", None), ("empty", "x"), ("value", ""), ("value", True), ("future", "x")],
)
def test_optional_text_has_no_presence_coercion(presence: Any, value: Any) -> None:
    with pytest.raises(AuthorityError):
        SourceOptionalText(presence, value)
