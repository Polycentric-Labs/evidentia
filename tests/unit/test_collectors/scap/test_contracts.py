"""Exact scalar admission and closed model shape across direct native inputs."""

from datetime import UTC, datetime, timedelta, tzinfo

import pytest
from evidentia_collectors.scap._contracts import (
    ActorLabel,
    AssessmentIndex,
    Boolean,
    ClaimUtcText,
    CompletionAssertionInput,
    ExpandedName,
    LocalName,
    NamespacePrefix,
    NativeDocument,
    NativeValueRef,
    PIName,
    RunMetadata,
    ScapImportRequest,
    SourceText,
    UtcRuntime,
    UtcText,
    XmlElement,
    XmlPI,
)
from evidentia_collectors.scap._limits import ScapFailure
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError


@pytest.mark.parametrize(
    "scalar,value",
    [
        (Boolean, 1),
        (AssessmentIndex, True),
        (AssessmentIndex, 1.0),
        (AssessmentIndex, "1"),
        (AssessmentIndex, -1),
        (AssessmentIndex, 256),
        (SourceText, b"text"),
        (ActorLabel, " "),
        (ActorLabel, "name\u200b"),
        (SourceText, "\ud800"),
        (SourceText, "\U0001f642" * 65537),
    ],
    ids=[
        "bool-int",
        "index-bool",
        "index-float",
        "index-text",
        "index-negative",
        "index-high",
        "text-bytes",
        "actor-blank",
        "actor-control",
        "source-surrogate",
        "source-utf8-size",
    ],
)
def test_exact_scalar_refusals(scalar, value: object) -> None:
    with pytest.raises((ScapFailure, ValidationError)):
        TypeAdapter(scalar).validate_python(value)


def test_native_strings_preserve_whitespace_and_unicode() -> None:
    text = "  e\u0301\t\u00a0 "
    assert TypeAdapter(SourceText).validate_python(text) == text
    assert TypeAdapter(SourceText).validate_python("") == ""
    assert TypeAdapter(SourceText).validate_python("\U0001f642" * 65536) == "\U0001f642" * 65536


@pytest.mark.parametrize(
    "value",
    [
        "2026-09-13T00:00:00+00:00",
        "2026-09-13T00:00:00z",
        "2026-09-13T00:00:60Z",
        "2026-02-29T00:00:00Z",
        "0000-01-01T00:00:00Z",
    ],
)
def test_utc_text_admits_only_exact_supported_calendar_form(value: str) -> None:
    with pytest.raises((ScapFailure, ValidationError)):
        TypeAdapter(UtcText).validate_python(value)


def test_claim_preserves_trailing_fraction_while_output_is_canonical() -> None:
    claim = "2026-09-13T01:02:03.120000Z"
    assert TypeAdapter(ClaimUtcText).validate_python(claim) == claim
    with pytest.raises((ScapFailure, ValidationError)):
        TypeAdapter(UtcText).validate_python(claim)
    assert TypeAdapter(UtcText).validate_python("2026-09-13T01:02:03.12Z").endswith(".12Z")


def test_private_datetime_never_calls_custom_timezone() -> None:
    calls = []

    class TrapZone(tzinfo):
        def utcoffset(self, value):
            calls.append("offset")
            return timedelta(0)

    class TrapDateTime(datetime):
        pass

    adapter = TypeAdapter(UtcRuntime)
    exact = datetime(2026, 9, 13, tzinfo=UTC)
    assert adapter.validate_python(exact) is exact
    for value in [
        datetime(2026, 9, 13),
        datetime(2026, 9, 13, tzinfo=TrapZone()),
        TrapDateTime(2026, 9, 13, tzinfo=UTC),
        "2026-09-13T00:00:00Z",
    ]:
        with pytest.raises((ScapFailure, ValidationError)):
            adapter.validate_python(value)
    assert calls == []


@pytest.mark.parametrize(
    "scalar,valid,invalid",
    [(LocalName, "rule-result", "a:b"), (NamespacePrefix, "", "9prefix"), (PIName, "source:detail", "XmL")],
)
def test_xml_names_have_their_declared_native_grammar(scalar, valid: str, invalid: str) -> None:
    assert TypeAdapter(scalar).validate_python(valid) == valid
    with pytest.raises((ScapFailure, ValidationError)):
        TypeAdapter(scalar).validate_python(invalid)


@pytest.mark.parametrize("model,field", [(ExpandedName, "local_name"), (XmlPI, "target")])
def test_xml_name_schema_preserves_nonempty_strings_without_a_nonblank_rule(model, field: str) -> None:
    schema = model.model_json_schema()["properties"][field]
    current = Draft202012Validator(schema)
    prior = Draft202012Validator({"type": "string", "minLength": 1, "maxLength": 256})
    for value in ["", " ", "\t\r\n", "\u1680", "\U00010000", "x\n", "x" * 256, "x" * 257, None, 1]:
        assert current.is_valid(value) == prior.is_valid(value)
    assert current.is_valid("\u1680")
    native = (
        {"namespace_uri": "", "local_name": "\u1680"}
        if model is ExpandedName
        else {"kind": "processing_instruction", "target": "\u1680", "data": "", "tail": None}
    )
    assert model.model_validate(native).model_dump(mode="json") == native
    for invalid in ["", " ", "\t\r\n", "9name", "x" * 257]:
        with pytest.raises((ScapFailure, ValidationError)):
            model.model_validate({**native, field: invalid})


def test_request_requires_every_key_and_has_no_extra_or_coercing_fields() -> None:
    value = {
        "source_profile": "xccdf-1.2-results",
        "assessment_index": 0,
        "cadence_slug": None,
        "completion_assertion": None,
    }
    assert ScapImportRequest.model_validate(value).assessment_index == 0
    for name in value:
        missing = dict(value)
        del missing[name]
        with pytest.raises(ValidationError):
            ScapImportRequest.model_validate(missing)
    for malformed in [dict(value, unknown=True), dict(value, assessment_index=False), dict(value, cadence_slug=7)]:
        with pytest.raises((ScapFailure, ValidationError)):
            ScapImportRequest.model_validate(malformed)


def test_native_model_subclasses_and_foreign_mapping_callbacks_are_refused() -> None:
    calls = []

    class TrapDict(dict):
        def items(self):
            calls.append("items")
            raise AssertionError("Source callback must not run")

    class TrapString(str):
        def __str__(self):
            calls.append("str")
            raise AssertionError("Source callback must not run")

    values = [
        TrapDict(namespace_uri="", local_name="root"),
        {"namespace_uri": "", "local_name": TrapString("root")},
        {TrapString("namespace_uri"): "", "local_name": "root"},
    ]
    for value in values:
        with pytest.raises((ScapFailure, ValidationError)):
            ExpandedName.model_validate(value)
    assert calls == []


def test_required_nulls_are_present_in_wire_schema() -> None:
    for model, nullable in [
        (NativeValueRef, "attribute_index"),
        (XmlElement, "tail"),
        (ScapImportRequest, "completion_assertion"),
    ]:
        schema = model.model_json_schema()
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])
        assert nullable in schema["required"]
        assert {item.get("type") for item in schema["properties"][nullable]["anyOf"]} >= {"null"}
    assert "source_profile" in CompletionAssertionInput.model_json_schema()["required"]
    assert "finished_at" in RunMetadata.model_json_schema()["required"]
    schema = NativeDocument.model_json_schema()
    assert schema["properties"]["nodes"]["items"]["discriminator"]["propertyName"] == "kind"


@pytest.mark.parametrize("extra", ["ignore", "allow", "forbid"])
def test_runtime_extra_policy_cannot_weaken_declared_shape(extra: str) -> None:
    with pytest.raises((ScapFailure, ValidationError)):
        ExpandedName.model_validate({"namespace_uri": "", "local_name": "root", "unknown": True}, extra=extra)
    with pytest.raises((ScapFailure, ValidationError)):
        ExpandedName.model_validate({"local_name": "root"}, extra=extra)


def test_supported_model_json_method_rejects_duplicate_keys_before_native_validation() -> None:
    assert ExpandedName.model_validate_json(b'{"namespace_uri":"","local_name":"root"}').local_name == "root"
    for raw in [
        b'{"namespace_uri":"","local_name":"first","local_name":"last"}',
        b'{"namespace_uri":"","local_name":"first","local_name":"first"}',
        b'{"namespace_uri":"","local_name":"root","unknown":true}',
    ]:
        with pytest.raises((ScapFailure, ValidationError)):
            ExpandedName.model_validate_json(raw, extra="ignore")


def test_raw_losing_pydantic_json_routes_cannot_admit_duplicate_keys() -> None:
    from pydantic import BaseModel

    class Outer(BaseModel):
        value: ExpandedName

    raw = b'{"namespace_uri":"","local_name":"first","local_name":"last"}'
    with pytest.raises((ScapFailure, ValidationError)):
        TypeAdapter(ExpandedName).validate_json(raw)
    with pytest.raises((ScapFailure, ValidationError)):
        Outer.model_validate_json(b'{"value":' + raw + b"}")
    native = {"namespace_uri": "", "local_name": "root"}
    assert TypeAdapter(ExpandedName).validate_python(native).local_name == "root"
    assert Outer.model_validate({"value": native}).value.local_name == "root"
