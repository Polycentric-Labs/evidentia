"""Source and result JSON retain their distinct admission limits."""

from __future__ import annotations

import pytest
from evidentia_collectors.registries._parsing import (
    ParsingError,
    canonical_json,
    parse_result_json,
    parse_strict_json,
    result_json_bytes,
)


def test_exact_native_number_and_string_identity() -> None:
    values = parse_strict_json(b'{"large":9007199254740993,"decimal":0.1,"float":1.0,"string":"1"}')
    assert isinstance(values, dict)
    assert type(values["large"]) is int and values["large"] == 9007199254740993
    assert type(values["float"]) is float
    assert values["string"] == "1"
    assert b'"float":1.0' in canonical_json(values)


@pytest.mark.parametrize(
    "raw",
    [b'{"x":1,"\\u0078":2}', b'{"x":1e-999}', b'{"x":1.00000000000000001}', b'{"x":Infinity}'],
)
def test_lossy_or_ambiguous_json_refused(raw: bytes) -> None:
    with pytest.raises(ParsingError):
        parse_strict_json(raw)


def test_aggregate_does_not_expand_source_parser_limits() -> None:
    raw = result_json_bytes({"first": "a" * 700000, "second": "b" * 700000})
    assert len(raw) > 1048576
    assert parse_result_json(raw)["first"] == "a" * 700000
    with pytest.raises(ParsingError):
        parse_strict_json(raw)
