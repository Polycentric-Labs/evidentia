"""Recursive native JSON remains declared in both input and output schemas."""

from __future__ import annotations

from typing import Literal

import pytest
from evidentia_collectors.retention import StorageRetentionCollectResult
from jsonschema import Draft202012Validator


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_recursive_json_schema_preserves_native_value_types(mode: Literal["validation", "serialization"]) -> None:
    schema = StorageRetentionCollectResult.model_json_schema(mode=mode)
    reference = "#/$defs/StorageRetentionJsonValue"
    definition = schema["$defs"].get("StorageRetentionJsonValue")
    assert definition == {
        "anyOf": [
            {"type": "boolean"},
            {"type": "integer"},
            {"type": "number"},
            {"type": "string"},
            {"type": "array", "items": {"$ref": reference}},
            {"type": "object", "additionalProperties": {"$ref": reference}},
            {"type": "null"},
        ]
    }
    selected = {"$defs": schema["$defs"], "$ref": reference}
    Draft202012Validator.check_schema(selected)
    validator = Draft202012Validator(selected)
    values: list[object] = [None, True, 0, 1.25, "literal", [], {}, {"nested": [False, {"value": "9007199254740993"}]}]
    for value in values:
        validator.validate(value)
    assert not validator.is_valid(object())
