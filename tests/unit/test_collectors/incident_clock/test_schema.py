"""Keep published incident text constraints aligned with their native grammars."""

from __future__ import annotations

from typing import Any

import pytest
from evidentia_collectors.incident_clock import _contracts as contract
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError

from .test_contracts import request


@pytest.mark.parametrize("provider", ["servicenow", "jira", "pagerduty"])
def test_request_schema_keeps_provider_identifiers(provider: str) -> None:
    raw = request(provider)
    model = type(contract.validated_request(raw))
    validator = Draft202012Validator(model.model_json_schema())
    validator.validate(raw)
    for invalid in (" ", "bad/id", "x" * 129):
        candidate = {**raw, "record_id": invalid}
        assert not validator.is_valid(candidate)
        with pytest.raises(contract.IncidentInputError):
            contract.validated_request(candidate)


@pytest.mark.parametrize(
    "annotation,valid,invalid",
    [
        (contract.Alias, ["profile-one", "A_1.2"], [" ", "bad/profile", "x" * 65]),
        (contract.VersionText, ["0.13.0", "1.0+local"], [" ", "version-one", "1/2"]),
    ],
)
def test_nonblank_schema_retains_alias_and_version_grammar(
    annotation: Any, valid: list[str], invalid: list[str]
) -> None:
    adapter: TypeAdapter[Any] = TypeAdapter(annotation)
    validator = Draft202012Validator(adapter.json_schema())
    for value in valid:
        validator.validate(value)
        assert adapter.validate_python(value) == value
    for value in invalid:
        assert not validator.is_valid(value)
        with pytest.raises(ValidationError):
            adapter.validate_python(value)


@pytest.mark.parametrize("blank", [" ", "\t\n", "\u0085", "\u00a0", "\u2000", "\u3000"])
def test_mapping_schema_rejects_blank_without_stripping_visible_text(blank: str) -> None:
    validator = Draft202012Validator(contract.ServiceNowMapping.model_json_schema())
    raw = {"label": blank, "meaning": "Recorded transition", "field": "u_start"}
    assert not validator.is_valid(raw)
    with pytest.raises(ValidationError):
        contract.ServiceNowMapping.model_validate(raw)
    preserved = {**raw, "label": "  Recorded transition  "}
    validator.validate(preserved)
    assert contract.ServiceNowMapping.model_validate(preserved).label == preserved["label"]


@pytest.mark.parametrize("text", [" ", "\t\n", "\u0085", "\u3000"])
def test_native_source_whitespace_remains_a_value(text: str) -> None:
    raw = {"state": "value", "value": text}
    Draft202012Validator(contract.NativeTextCell.model_json_schema()).validate(raw)
    cell = contract.NativeTextCell.model_validate(raw)
    assert cell.state == "value" and cell.value == text
