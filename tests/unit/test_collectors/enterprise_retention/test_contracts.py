"""Strict selected-resource request admission and schema agreement."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, cast

import pytest
from evidentia_collectors.enterprise_retention import _contracts as c
from evidentia_collectors.enterprise_retention._contracts import (
    CorrespondenceError,
    ReadKind,
    expected_fields,
    validate_correspondence,
    validate_selected_fields,
)
from evidentia_collectors.enterprise_retention._parsing import canonical_json, checked_json
from pydantic import ValidationError

PROVIDERS = ("google-vault", "splunk-enterprise", "elastic-ilm")


def request(provider: str = "google-vault", identity: object = "selected-1") -> dict[str, Any]:
    key = "matter_id" if provider == "google-vault" else "index"
    return {"provider": provider, "profile_alias": "Profile.1", "scope_label": "Scope_1", "targets": [{key: identity}]}


@pytest.mark.parametrize("provider", PROVIDERS)
def test_request_round_trips_without_root_wrapper(provider: str) -> None:
    data = request(provider)
    parsed = c.validated_request(data)
    wire = parsed.model_dump_json().encode()
    assert json.loads(wire) == data
    assert c.parse_request(wire) == parsed
    assert c.EnterpriseRetentionCollectRequest.model_validate_json(wire) == parsed
    for mode in ("validation", "serialization"):
        schema = parsed.model_json_schema(mode=mode)
        assert schema["discriminator"]["propertyName"] == "provider"
        branch = schema["$defs"][type(parsed.root).__name__]
        assert set(branch["required"]) == {"provider", "profile_alias", "scope_label", "targets"}
        assert branch["additionalProperties"] is False
        assert branch["properties"]["targets"]["maxItems"] == 20


@pytest.mark.parametrize(
    "provider,identity",
    [(p, v) for p in PROVIDERS for v in ("", "x\n", "x/y", "x?y", "%2f", True, 1, None)]
    + [("splunk-enterprise", v) for v in ("_all", "_ALL", "_nEw", "_Reload", "x" * 81)]
    + [("elastic-ilm", v) for v in (".", "..", "Upper", "_all", "a,b", "-first", "x" * 256)]
    + [("google-vault", "x" * 129)],
)
def test_invalid_selected_identity_refused(provider: str, identity: object) -> None:
    with pytest.raises(c.EnterpriseRetentionInputError, match=r"^invalid_request$"):
        c.validated_request(request(provider, identity))
    with pytest.raises(c.EnterpriseRetentionInputError, match=r"^invalid_request$"):
        c.parse_request(json.dumps(request(provider, identity)).encode())


@pytest.mark.parametrize("provider", PROVIDERS)
def test_target_order_duplicate_and_count_guards(provider: str) -> None:
    data = request(provider)
    key = "matter_id" if provider == "google-vault" else "index"
    data["targets"] = [{key: f"selected-{i}"} for i in range(20)]
    parsed = c.validated_request(data)
    assert [c.target_identity(item) for item in parsed.root.targets] == [f"selected-{i}" for i in range(20)]
    for targets in ([], data["targets"] * 2, [data["targets"][0]] * 2, tuple(data["targets"])):
        with pytest.raises(c.EnterpriseRetentionInputError):
            c.validated_request({**data, "targets": targets})


@pytest.mark.parametrize("field", ["profile_alias", "scope_label"])
@pytest.mark.parametrize("value", ["", " space", "x\n", "x/y", "x" * 65, 1, False])
def test_alias_grammar_and_types(field: str, value: object) -> None:
    with pytest.raises(c.EnterpriseRetentionInputError):
        c.validated_request({**request(), field: value})


@pytest.mark.parametrize("provider", PROVIDERS)
def test_selected_identity_schema_agrees_with_runtime(provider: str) -> None:
    models: dict[str, type[c.VaultMatterTarget] | type[c.SplunkIndexTarget] | type[c.ElasticIndexTarget]] = {
        "google-vault": c.VaultMatterTarget,
        "splunk-enterprise": c.SplunkIndexTarget,
        "elastic-ilm": c.ElasticIndexTarget,
    }
    model = models[provider]
    key = "matter_id" if provider == "google-vault" else "index"
    schema = model.model_json_schema()["properties"][key]
    for value in ("good-1", "a\n", "_all", "_ALL", "_new", "_reload", ".", "..", ".ds-index-001", "a/b", "x" * 255):
        schema_accepts = schema["minLength"] <= len(value) <= schema["maxLength"] and all(
            re.search(item["pattern"], value) for item in schema["allOf"]
        )
        try:
            model.model_validate({key: value})
        except ValidationError:
            runtime_accepts = False
        else:
            runtime_accepts = True
        assert bool(schema_accepts) is runtime_accepts, (provider, value)


def test_requests_reject_extra_fields_and_provider_confusion() -> None:
    for changes in ({"origin": "https://example.invalid"}, {"provider": "unknown"}, {"credential_ref": "not-allowed"}):
        with pytest.raises(c.EnterpriseRetentionInputError):
            c.validated_request({**request(), **changes})
    with pytest.raises(c.EnterpriseRetentionInputError):
        c.validated_request({**request(), "targets": [{"index": "selected-1"}]})


def test_mutated_constructed_and_copied_requests_revalidate() -> None:
    parsed = c.validated_request(request())
    with pytest.raises(ValueError):
        parsed.model_copy(update={"root": parsed.root.model_copy(update={"targets": []})})
    invalid = c.VaultMatterTarget.model_construct(matter_id="other/path")
    with pytest.raises(c.EnterpriseRetentionInputError):
        c.validated_request({**request(), "targets": [invalid]})
    object.__setattr__(parsed.root.targets[0], "matter_id", "other/path")
    with pytest.raises(c.EnterpriseRetentionInputError):
        c.validated_request(parsed)
    with pytest.raises(ValueError):
        parsed.model_dump_json()


def test_revalidated_requests_detach_from_caller_lists() -> None:
    data = request()
    parsed = c.validated_request(data)
    detached = c.validated_request(parsed)
    data["targets"].clear()
    parsed.root.targets.clear()
    assert len(detached.root.targets) == 1
    assert c.target_identity(detached.root.targets[0]) == "selected-1"


@pytest.mark.parametrize("wire", [b'{"provider":1,"provider":2}', b'"\xff"', b"\xef\xbb\xbf{}", b'{"targets":NaN}'])
def test_wire_lexical_refusals_are_fixed(wire: bytes) -> None:
    with pytest.raises(c.EnterpriseRetentionInputError, match=r"^invalid_request$"):
        c.parse_request(wire)


def test_request_byte_ceiling() -> None:
    wire = json.dumps(request()).encode()
    assert c.parse_request(wire + b" " * (65_536 - len(wire)))
    with pytest.raises(c.EnterpriseRetentionInputError, match=r"^request_limit$"):
        c.parse_request(wire + b" " * (65_537 - len(wire)))


@pytest.mark.parametrize(
    "value,allowed",
    [
        ("policy-1", True),
        ("A.B_2", True),
        ("x" * 255, True),
        ("_all", False),
        ("_AlL", False),
        (".", False),
        ("..", False),
        ("a/b", False),
        ("x\n", False),
        (True, False),
        ("x" * 256, False),
    ],
)
def test_policy_reference_grammar(value: object, allowed: bool) -> None:
    assert c.supported_policy(value) is allowed


@pytest.mark.parametrize("representation", ["bytes", "text", "bytearray"])
def test_direct_json_entry_rejects_duplicate_keys(representation: str) -> None:
    wire = json.dumps(request()).encode().replace(b"{", b'{"provider":"wrong",', 1)
    value: bytes | str | bytearray = (
        wire if representation == "bytes" else wire.decode() if representation == "text" else bytearray(wire)
    )
    with pytest.raises(ValueError):
        c.EnterpriseRetentionCollectRequest.model_validate_json(value)


def test_direct_json_entry_enforces_request_byte_limit() -> None:
    small = json.dumps(request()).encode()
    wire = small + b" " * (65_537 - len(small))
    with pytest.raises(ValueError):
        c.EnterpriseRetentionCollectRequest.model_validate_json(wire)


def test_direct_json_entry_cannot_weaken_extra_field_admission() -> None:
    wire = json.dumps({**request(), "unexpected": True})
    with pytest.raises(ValueError):
        c.EnterpriseRetentionCollectRequest.model_validate_json(wire, extra="ignore")


@pytest.mark.parametrize("option", [{"strict": False}, {"extra": "ignore"}, {"extra": "allow"}])
@pytest.mark.parametrize("entry", ["json", "native"])
def test_explicit_options_cannot_weaken_request_contract(option: dict[str, Any], entry: str) -> None:
    with pytest.raises(c.EnterpriseRetentionInputError):
        if entry == "json":
            c.EnterpriseRetentionCollectRequest.model_validate_json(json.dumps(request()), **option)
        else:
            c.EnterpriseRetentionCollectRequest.model_validate(request(), **option)


def test_request_does_not_admit_arbitrary_attributes() -> None:
    with pytest.raises(c.EnterpriseRetentionInputError):
        c.EnterpriseRetentionCollectRequest.model_validate(request(), from_attributes=True)


@pytest.mark.parametrize("char,width", [("x", 1), ("\u00e9", 2), ("\u20ac", 3), ("\U0001f600", 4)])
def test_wire_text_budget_counts_utf8_before_encoding(char: str, width: int) -> None:
    value = char * (c.REQUEST_BYTE_LIMIT // width)
    value += "x" * (c.REQUEST_BYTE_LIMIT % width)
    assert c._request_wire_bytes(value) == value.encode("utf-8")
    with pytest.raises(c.EnterpriseRetentionInputError, match=r"^request_limit$"):
        c._request_wire_bytes(value + "x")


@pytest.mark.parametrize("value", ["\ud800", "\udfff", 1, None, memoryview(b"{}")])
def test_wire_bytes_reject_invalid_native_input(value: object) -> None:
    with pytest.raises(c.EnterpriseRetentionInputError, match=r"^invalid_request$"):
        c._request_wire_bytes(value)


def test_mutable_wire_is_detached_before_parse() -> None:
    original = bytearray(json.dumps(request()).encode())
    copied = c._request_wire_bytes(original)
    original.clear()
    assert c.parse_request(copied).root.profile_alias == "Profile.1"


@pytest.mark.parametrize("representation", ["bytes", "text", "bytearray"])
def test_oversized_direct_wire_refuses_before_lexical_parser(
    monkeypatch: pytest.MonkeyPatch,
    representation: str,
) -> None:
    def unexpected_parse(*args: object, **kwargs: object) -> None:
        raise AssertionError("oversized input reached parser")

    monkeypatch.setattr(c, "parse_strict_json", unexpected_parse)
    value: bytes | str | bytearray = b" " * (c.REQUEST_BYTE_LIMIT + 1)
    assert isinstance(value, bytes)
    if representation == "text":
        value = value.decode()
    elif representation == "bytearray":
        value = bytearray(value)
    with pytest.raises(c.EnterpriseRetentionInputError, match=r"^request_limit$"):
        c.EnterpriseRetentionCollectRequest.model_validate_json(value)


def test_wire_subclass_callbacks_never_run() -> None:
    class HostileText(str):
        def __len__(self) -> int:
            raise AssertionError("source callback ran")

        def encode(self, *args: object, **kwargs: object) -> bytes:
            raise AssertionError("source callback ran")

    with pytest.raises(c.EnterpriseRetentionInputError):
        c.EnterpriseRetentionCollectRequest.model_validate_json(HostileText("{}"))


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_schema_preserves_uniqueness_and_nonblank_gate(mode: Any) -> None:
    from evidentia_core.models.common import NON_BLANK_PATTERN
    from jsonschema import Draft202012Validator

    schema = c.EnterpriseRetentionCollectRequest.model_json_schema(mode=mode)
    validator = Draft202012Validator(schema)
    strings = 0
    for definition in schema["$defs"].values():
        for prop in definition.get("properties", {}).values():
            if prop.get("type") == "string" and prop.get("minLength", 0) >= 1:
                assert prop["pattern"] == NON_BLANK_PATTERN
                strings += 1
    assert strings == 9
    for provider in PROVIDERS:
        data = request(provider)
        data["targets"] *= 2
        assert list(validator.iter_errors(data))


@pytest.mark.parametrize("location", ["root", "constructed_root", "provider", "constructed_branch", "wrapped_branch"])
@pytest.mark.parametrize("raising", [False, True])
def test_untrusted_native_discriminators_never_run_callbacks(
    location: str, raising: bool, capsys: pytest.CaptureFixture[str]
) -> None:
    callbacks = []

    class Hostile:
        @property
        def provider(self) -> str:
            callbacks.append("property")
            if raising:
                raise RuntimeError("synthetic-marker")
            return "google-vault"

        def __str__(self) -> str:
            callbacks.append("str")
            if raising:
                raise RuntimeError("synthetic-marker")
            return "google-vault"

    value: object
    if location == "root":
        value = Hostile()
    elif location == "constructed_root":
        value = c.EnterpriseRetentionCollectRequest.model_construct(root=cast(c.VaultRetentionRequest, Hostile()))
    elif location == "provider":
        value = {**request(), "provider": Hostile()}
    else:
        branch = c.VaultRetentionRequest.model_construct(**{**request(), "provider": Hostile()})
        value = (
            branch
            if location == "constructed_branch"
            else c.EnterpriseRetentionCollectRequest.model_construct(root=branch)
        )
    with pytest.raises(c.EnterpriseRetentionInputError, match=r"^invalid_request$"):
        c.validated_request(value)
    assert not callbacks
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("raising", [False, True])
def test_model_copy_refuses_hostile_keys_before_dictionary_merge(raising: bool) -> None:
    callbacks = []

    class HostileKey:
        def __hash__(self) -> int:
            return hash("root")

        def __eq__(self, other: object) -> bool:
            callbacks.append("equality")
            if raising:
                raise RuntimeError("synthetic-marker")
            return True

    parsed = c.validated_request(request())
    update: Any = {HostileKey(): parsed.root}
    with pytest.raises(c.EnterpriseRetentionInputError, match=r"^invalid_request$"):
        parsed.model_copy(update=update)
    assert not callbacks
    assert parsed.model_copy(update={}) == parsed
    assert parsed.model_copy(update={"root": request("splunk-enterprise")}).root.provider == "splunk-enterprise"


# Authored synthetic source cases; no tenant recording or live acceptance is implied.
CASE_DIR = Path(__file__).resolve().parents[3] / "fixtures" / "enterprise_retention"
POSITIVES: list[dict[str, Any]] = json.loads((CASE_DIR / "source-field-cases.json").read_text(encoding="utf-8"))[
    "cases"
]
NEGATIVES: list[dict[str, Any]] = json.loads(
    (CASE_DIR / "source-field-negative-cases.json").read_text(encoding="utf-8")
)["cases"]
BY_ID = {case["id"]: case for case in POSITIVES}
SESSION_ONLY = {
    "matter_changed_id",
    "holds_null_is_not_empty",
    "token_null_is_not_terminal",
    "splunk_error_cannot_be_omitted",
    "splunk_message_type_wrong_scalar",
    "callback_drops_record",
}


def occurrences(case: dict[str, Any], raw: dict[str, Any]) -> list[dict[str, Any]]:
    kind = case["read_kind"]
    if kind == "vault-holds":
        return cast(list[dict[str, Any]], raw.get("holds", []))
    if kind == "splunk-index":
        return cast(list[dict[str, Any]], raw["entry"])
    if kind == "elastic-explain":
        return [raw["indices"][case["subject"]["source_id"]]]
    if kind == "elastic-policy":
        return [raw[case["subject"]["source_id"]]]
    return [raw]


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
        value[key] = json.loads(recipe["value_json"])


@pytest.mark.parametrize("case", POSITIVES, ids=[case["id"] for case in POSITIVES])
def test_adopted_positive_recipe(case: dict[str, Any]) -> None:
    raw = copy.deepcopy(case["raw_response"])
    before = canonical_json(checked_json(raw))
    sources = occurrences(case, raw)
    expected = case["expected_records"]
    assert len(sources) == len(expected)
    observed_codes: set[str] = set()
    for source, record in zip(sources, expected, strict=True):
        result = expected_fields(case["read_kind"], source)
        assert canonical_json(result.fields) == canonical_json(checked_json(record["fields"]))
        assert result.coverage == record["field_coverage"]
        assert tuple(dict.fromkeys(result.diagnostics)) == result.diagnostics
        assert set(result.diagnostics) <= {"unsupported_source_value", "missing_source_detail"}
        validate_correspondence(case["read_kind"], source, result.fields, result.coverage)
        observed_codes.update(result.diagnostics)
    assert set(case["required_interpretation_codes"]) <= observed_codes
    assert canonical_json(checked_json(raw)) == before


@pytest.mark.parametrize(
    "recipe",
    [r for r in NEGATIVES if r["id"] not in SESSION_ONLY],
    ids=[r["id"] for r in NEGATIVES if r["id"] not in SESSION_ONLY],
)
def test_adopted_field_refusal(recipe: dict[str, Any]) -> None:
    case = BY_ID[recipe["base_case"]]
    raw = copy.deepcopy(case["raw_response"])
    records = copy.deepcopy(case["expected_records"])
    mutation = recipe["mutation"]
    change(raw if mutation["target"] == "raw_response" else records, mutation)
    with pytest.raises(CorrespondenceError, match=r"^invalid_response$"):
        for source, record in zip(occurrences(case, raw), records, strict=True):
            if mutation["target"] == "raw_response":
                expected_fields(case["read_kind"], source)
            else:
                validate_correspondence(case["read_kind"], source, record["fields"], record["field_coverage"])


@pytest.mark.parametrize(
    "recipe",
    [r for r in NEGATIVES if r["id"] in SESSION_ONLY],
    ids=[r["id"] for r in NEGATIVES if r["id"] in SESSION_ONLY],
)
def test_session_recipe_is_preserved_without_field_acceptance_claim(recipe: dict[str, Any]) -> None:
    case = BY_ID[recipe["base_case"]]
    target = copy.deepcopy(
        case["raw_response"] if recipe["mutation"]["target"] == "raw_response" else case["expected_records"]
    )
    before = copy.deepcopy(target)
    change(target, recipe["mutation"])
    assert target != before
    assert recipe["expected"]["refused"] is True
    assert recipe["expected"]["zero_unauthorized_followup"] is True
    assert recipe["expected"]["prior_admitted_evidence_unchanged"] is True
    # The session must execute the retained original refusal oracle separately.
    assert recipe["id"] in SESSION_ONLY


@pytest.mark.parametrize("replacement", [False, True, 0, 0.0, -0.0, 1.0, "0", None])
def test_native_value_tampering(replacement: object) -> None:
    source = {"name": "i", "content": {"maxTotalDataSizeMB": 1}}
    result = expected_fields("splunk-index", source)
    result.fields["maxTotalDataSizeMB"] = cast(Any, replacement)
    with pytest.raises(CorrespondenceError, match=r"^invalid_response$"):
        validate_correspondence("splunk-index", source, result.fields, result.coverage)


def test_negative_zero_sign_is_not_normalized() -> None:
    source = {"name": "i", "content": {"disabled": -0.0}}
    result = expected_fields("splunk-index", source)
    assert b"-0.0" in canonical_json(result.fields)
    result.fields["disabled"] = 0.0
    with pytest.raises(CorrespondenceError):
        validate_correspondence("splunk-index", source, result.fields, result.coverage)


@pytest.mark.parametrize(
    "timestamp,known",
    [
        ("2026-01-02T03:04:05.123456789+05:30", True),
        ("2016-12-31T23:59:60Z", False),
        ("2025-02-29T00:00:00Z", False),
        ("2024-02-29t00:00:00.000000001z", True),
        ("2026-01-01T00:00:00+24:00", False),
    ],
)
def test_timestamp_literal_and_supported_subset(timestamp: str, known: bool) -> None:
    result = expected_fields("vault-holds", {"holdId": "h", "updateTime": timestamp})
    assert result.fields["updateTime"] == timestamp
    assert result.coverage["updateTime"] == ("known" if known else "unknown")


def test_input_and_returned_views_are_detached() -> None:
    source = {"holdId": "h", "accounts": [{"accountId": "a"}], "query": {"future": [1, 2]}}
    expected = expected_fields("vault-holds", source)
    cast(dict[str, Any], source["query"])["future"].append(3)
    assert expected.fields["query"] == {"future": [1, 2]}
    expected.fields["accounts"] = []
    assert expected_fields("vault-holds", source).fields["accounts"] == [{"accountId": "a"}]


@pytest.mark.parametrize("left,right", [("first", "second"), (" \t", "script")])
def test_raw_archive_nonempty_values_have_identical_selected_output(left: str, right: str) -> None:
    first = expected_fields("splunk-index", {"name": "i", "content": {"coldToFrozenDir": left}})
    second = expected_fields("splunk-index", {"name": "i", "content": {"coldToFrozenDir": right}})
    assert first == second


def test_fixed_correspondence_error_contains_no_values() -> None:
    source = {"operation_mode": "RUNNING"}
    with pytest.raises(CorrespondenceError) as exc:
        validate_correspondence("elastic-status", source, {"private-synthetic-key": "private-synthetic-value"}, {})
    assert str(exc.value) == "invalid_response"


@pytest.mark.parametrize("kind", ["", "future", 1, True, None])
def test_unknown_kind_refused(kind: object) -> None:
    with pytest.raises(CorrespondenceError):
        expected_fields(cast(ReadKind, kind), {})


@pytest.mark.parametrize("case", POSITIVES, ids=[case["id"] for case in POSITIVES])
def test_adopted_selected_fields_are_intrinsically_valid(case: dict[str, Any]) -> None:
    for record in case["expected_records"]:
        validate_selected_fields(case["read_kind"], record["fields"], record["field_coverage"])


@pytest.mark.parametrize(
    "recipe",
    [
        r
        for r in NEGATIVES
        if r["mutation"]["target"] == "callback_records"
        and r["id"]
        not in {
            "callback_changes_policy",
            "callback_changes_managed",
            "callback_reorders_account_list",
            "callback_strips_explicit_action_value",
            "callback_drops_record",
        }
    ],
    ids=[
        r["id"]
        for r in NEGATIVES
        if r["mutation"]["target"] == "callback_records"
        and r["id"]
        not in {
            "callback_changes_policy",
            "callback_changes_managed",
            "callback_reorders_account_list",
            "callback_strips_explicit_action_value",
            "callback_drops_record",
        }
    ],
)
def test_intrinsic_schema_refusals(recipe: dict[str, Any]) -> None:
    case = BY_ID[recipe["base_case"]]
    records = copy.deepcopy(case["expected_records"])
    change(records, recipe["mutation"])
    with pytest.raises(CorrespondenceError):
        validate_selected_fields(case["read_kind"], records[0]["fields"], records[0]["field_coverage"])


def test_intrinsic_validation_does_not_attest_original_source() -> None:
    source = {"index": "i", "managed": True, "policy": "policy-a"}
    result = expected_fields("elastic-explain", source)
    result.fields["policy"] = "policy-b"
    validate_selected_fields("elastic-explain", result.fields, result.coverage)
    with pytest.raises(CorrespondenceError):
        validate_correspondence("elastic-explain", source, result.fields, result.coverage)


@pytest.mark.parametrize(
    "state,coverage", [("absent", "absent"), ("null", "null"), ("empty", "known"), ("nonempty", "known")]
)
def test_intrinsic_archive_states(state: str, coverage: str) -> None:
    fields = {"name": "i", "coldToFrozenDirState": state, "coldToFrozenScriptState": "absent"}
    counts = {
        "name": "known",
        "datatype": "absent",
        "disabled": "absent",
        "frozenTimePeriodInSecs": "absent",
        "maxTotalDataSizeMB": "absent",
        "coldToFrozenDir": coverage,
        "coldToFrozenScript": "absent",
    }
    validate_selected_fields("splunk-index", fields, counts)
    counts["coldToFrozenDir"] = "unknown"
    with pytest.raises(CorrespondenceError):
        validate_selected_fields("splunk-index", fields, counts)


@pytest.mark.parametrize("value", [None, [], "source", 1, True])
def test_non_object_source_refused(value: object) -> None:
    with pytest.raises(CorrespondenceError):
        expected_fields("elastic-status", value)


@pytest.mark.parametrize(
    "coverage",
    [{}, {"operation_mode": "unknown"}, {"operation_mode": True}, {"operation_mode": "known", "extra": "absent"}],
)
def test_coverage_membership_and_state_are_exact(coverage: object) -> None:
    with pytest.raises(CorrespondenceError):
        validate_correspondence(
            "elastic-status", {"operation_mode": "RUNNING"}, {"operation_mode": "RUNNING"}, coverage
        )


@pytest.mark.parametrize(
    "hold_id,accepted",
    [("x" * 1024, True), ("x" * 1025, False), ("\u00e9" * 512, True), ("\u00e9" * 513, False), (" \t\n", False)],
)
def test_hold_id_exact_utf8_bound(hold_id: str, accepted: bool) -> None:
    if accepted:
        assert expected_fields("vault-holds", {"holdId": hold_id}).fields["holdId"] == hold_id
    else:
        with pytest.raises(CorrespondenceError):
            expected_fields("vault-holds", {"holdId": hold_id})


@pytest.mark.parametrize(
    "accounts,contradiction",
    [([], False), (None, False), ([{"accountId": "a", "holdTime": "2026-01-01T00:00:00Z"}], True)],
)
def test_vault_scope_contradiction_does_not_change_root_presence(accounts: object, contradiction: bool) -> None:
    source = {"holdId": "h", "accounts": accounts, "orgUnit": {"orgUnitId": "o", "holdTime": "2026-01-01T00:00:00Z"}}
    result = expected_fields("vault-holds", source)
    assert ("unsupported_source_value" in result.diagnostics) is contradiction
    assert result.coverage["accounts"] == ("null" if accounts is None else "known")
    assert result.coverage["orgUnit"] == "known"


def test_open_configuration_preserves_mapping_and_array_order() -> None:
    config = {"z": [0, -0.0, False, None], "error": "literal", "_meta": {"email": "synthetic@example.invalid"}}
    result = expected_fields("vault-holds", {"holdId": "h", "query": config})
    assert list(cast(dict[str, Any], result.fields["query"])) == list(config)
    assert canonical_json(result.fields["query"]) == canonical_json(checked_json(config))


def test_aliases_are_detached_and_do_not_create_internal_shared_views() -> None:
    shared = {"values": [1]}
    source = {"holdId": "h", "query": {"one": shared, "two": shared}}
    result = expected_fields("vault-holds", source)
    query = cast(dict[str, Any], result.fields["query"])
    query["one"]["values"].append(2)
    assert query["two"] == {"values": [1]}
    assert shared == {"values": [1]}


def test_non_json_native_types_and_cycles_are_refused() -> None:
    class UntrustedInt(int):
        pass

    cyclic: dict[str, Any] = {"holdId": "h"}
    cyclic["query"] = cyclic
    for source in [
        cyclic,
        {"name": "i", "content": {"disabled": UntrustedInt(1)}},
        {"holdId": "h", "query": {"x": (1, 2)}},
    ]:
        with pytest.raises(CorrespondenceError):
            expected_fields("vault-holds" if "holdId" in source else "splunk-index", source)


def test_existing_parser_depth_is_not_widened() -> None:
    nested: Any = 0
    for _ in range(14):
        nested = {"x": nested}
    expected_fields("vault-holds", {"holdId": "h", "query": {"future": nested}})
    nested = {"x": nested}
    with pytest.raises(CorrespondenceError):
        expected_fields("vault-holds", {"holdId": "h", "query": {"future": nested}})


@pytest.mark.parametrize(
    "changed", [{"min_age": "1d", "actions": {}}, {"min_age": "0ms", "actions": {"z": None, "a": 1}}]
)
def test_legal_selected_configuration_change_is_not_source_attestation(changed: dict[str, Any]) -> None:
    source = {"policy": {"phases": {"hot": {"min_age": "0ms", "actions": {}}}}}
    result = expected_fields("elastic-policy", source)
    cast(dict[str, Any], result.fields["policy"])["phases"]["hot"] = changed
    validate_selected_fields("elastic-policy", result.fields, result.coverage)
    with pytest.raises(CorrespondenceError):
        validate_correspondence("elastic-policy", source, result.fields, result.coverage)
