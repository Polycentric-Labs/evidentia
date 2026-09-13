"""Exercise wire and native boundaries before incident source admission."""

from __future__ import annotations

import json
import math
from decimal import getcontext
from typing import cast

import pytest
from evidentia_collectors.incident_clock import _parsing as parsing


def _nested(depth: int) -> object:
    value: object = 0
    for _ in range(depth):
        value = [value]
    return value


@pytest.mark.parametrize("depth", [1, 16, 31, 32])
def test_supported_container_depth(depth: int) -> None:
    wire = b"[" * depth + b"0" + b"]" * depth
    assert parsing.parse_strict_json(wire) == _nested(depth)
    assert parsing.canonical_json(_nested(depth)) == wire


@pytest.mark.parametrize(
    "wire",
    [
        b"[" * 33 + b"0" + b"]" * 33,
        b"[" + b",".join([b"0"] * 100000) + b"]",
        b'"' + b"x" * 65537 + b'"',
        b'"' + rb"\u0061" * 65537 + b'"',
        b"9" * 129,
    ],
    ids=["depth", "nodes", "ascii-string", "escaped-string", "integer"],
)
def test_limits_reject_before_json_decoder(wire: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Decoder reached after structural refusal")

    monkeypatch.setattr(parsing.json, "loads", forbidden)
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(wire)


@pytest.mark.parametrize(
    "wire",
    [
        b'{"x":1,"\\u0078":2}',
        b'"\\ud800"',
        b'"\\udfff"',
        b'"\\ud800x"',
        b'"\\ud800\\u0041"',
        b"\xef\xbb\xbf{}",
        b'"\xff"',
        b"NaN",
        b"Infinity",
        b"-Infinity",
        b"1e10000",
        b"1e-10000",
        b"1.0000000000000001",
        b"01",
        b"+1",
        b"1.",
        b"[}",
        b"[",
        b"]",
        b'"unterminated',
        b'{"k" 0}',
        b"[0,]",
        b"{}{}",
        b"truex",
    ],
)
def test_strict_grammar_and_precision_refusals(wire: bytes) -> None:
    with pytest.raises(parsing.ParsingError, match=r"^invalid_json$"):
        parsing.parse_strict_json(wire)


def test_escaped_brackets_and_surrogate_pair() -> None:
    wire = rb'{"brackets":"[[[{]}]", "escaped":"quote\"[", "slash":"\\", "pair":"\ud83d\ude00"}'
    assert parsing.parse_strict_json(wire) == {
        "brackets": "[[[{]}]",
        "escaped": 'quote"[',
        "slash": "\\",
        "pair": chr(0x1F600),
    }


def test_native_scalar_precision_and_signed_zero() -> None:
    context = getcontext().copy()
    result = parsing.parse_strict_json(b'[0,false,0.1,-0.0,9007199254740993,"9007199254740993"]')
    assert type(result) is list
    assert [type(item) for item in result] == [int, bool, float, float, int, str]
    assert result[2] == 0.1 and result[4] == 9007199254740993
    assert type(result[3]) is float and math.copysign(1, result[3]) == -1
    assert getcontext().flags == context.flags and getcontext().prec == context.prec


@pytest.mark.parametrize("unit,count", [("a", 65536), (chr(0xE9), 32768), (chr(0x1F600), 16384)])
def test_utf8_string_bound_in_native_and_escaped_wire(unit: str, count: int) -> None:
    value = unit * count
    assert parsing.checked_json(value) == value
    assert parsing.parse_strict_json(json.dumps(value).encode("ascii")) == value
    with pytest.raises(parsing.ParsingError):
        parsing.checked_json(value + unit)
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(json.dumps(value + unit).encode("ascii"))


def test_nodes_count_containers_and_keys() -> None:
    assert len(cast(list[object], parsing.checked_json([None] * 99999))) == 99999
    with pytest.raises(parsing.ParsingError):
        parsing.checked_json([None] * 100000)
    with pytest.raises(parsing.ParsingError):
        parsing.checked_json({str(index): None for index in range(50000)})
    assert len(cast(list[object], parsing.parse_strict_json(b"[" + b"0," * 99998 + b"0]"))) == 99999


@pytest.mark.parametrize("bound", [True, 0, -1, 16777217, "4"])
def test_native_byte_bound(bound: object) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(b"null", max_bytes=cast(int, bound))


def test_wire_and_canonical_byte_limits_are_separate() -> None:
    assert parsing.parse_strict_json(b"null", max_bytes=4) is None
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(b"null ", max_bytes=4)
    assert parsing.canonical_json(chr(0), max_bytes=8) == b'"\\u0000"'
    with pytest.raises(parsing.ParsingError):
        parsing.checked_json(chr(0), max_bytes=7)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 10**128, -(10**128), chr(0xD800), (1, 2), {1: "value"}])
def test_unsupported_native_values(value: object) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.checked_json(value)


def test_cycle_depth_and_detachment() -> None:
    cycle: list[object] = []
    cycle.append(cycle)
    for value in (cycle, _nested(33)):
        with pytest.raises(parsing.ParsingError):
            parsing.checked_json(value)
    original = {"value": [0, False, None]}
    detached = parsing.checked_json(original)
    assert detached == original and detached is not original
    assert type(detached) is dict and detached["value"] is not original["value"]


def test_custom_objects_do_not_execute_callbacks() -> None:
    def forbidden(*_args: object) -> None:
        raise AssertionError("Untrusted callback reached")

    meta = type("HostileMeta", (type,), {"__hash__": forbidden, "__eq__": forbidden})
    foreign = meta("Foreign", (), {"__iter__": forbidden, "__str__": forbidden})()
    for value in (foreign, type("StringChild", (str,), {})("value"), type("ListChild", (list,), {})([0])):
        with pytest.raises(parsing.ParsingError):
            parsing.checked_json(value)


def test_late_native_mutation_is_checked_at_clone(monkeypatch: pytest.MonkeyPatch) -> None:
    original: list[object] = [0]
    clone = parsing._Budget.clone

    def replaced(budget: parsing._Budget, value: object, depth: int = 0) -> object:
        if value is original:
            original[0] = object()
        return clone(budget, value, depth)

    monkeypatch.setattr(parsing._Budget, "clone", replaced)
    with pytest.raises(parsing.ParsingError):
        parsing.checked_json(original)


def test_aggregate_allows_more_nodes_than_one_source_body() -> None:
    value = {"events": [0] * 100000}
    with pytest.raises(parsing.ParsingError):
        parsing.checked_json(value)
    encoded = parsing.result_json_bytes(value)
    assert parsing.parse_result_json(encoded) == value


def test_complete_result_byte_boundary_includes_json_escaping() -> None:
    prefix = b'{"parts":['
    suffix = b"]}"
    part = b'"' + b"a" * 65536 + b'",'
    count = 255
    remaining = 16777216 - len(prefix) - len(suffix) - len(part) * count - 2
    wire = prefix + part * count + b'"' + b"b" * remaining + b'"' + suffix
    assert len(wire) == 16777216
    value = parsing.parse_result_json(wire)
    assert parsing.result_json_bytes(value) == wire
    with pytest.raises(parsing.ParsingError):
        parsing.parse_result_json(wire + b" ")
    parts = value["parts"]
    assert type(parts) is list and type(parts[-1]) is str
    parts[-1] += "b"
    with pytest.raises(parsing.ParsingError):
        parsing.result_json_bytes(value)


@pytest.mark.parametrize("value", [None, [], "text"])
def test_result_requires_object(value: object) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.checked_result_json(value)
    with pytest.raises(parsing.ParsingError):
        parsing.parse_result_json(json.dumps(value).encode("utf-8"))


def test_native_string_byte_accounting_matches_independent_reviewed_escaping() -> None:
    from evidentia_collectors.retention._parsing import _string_size as reviewed_size

    samples = [chr(code) for code in range(160)] + [
        chr(0xE9) * 32768,
        chr(0x20AC) * 21845,
        chr(0x1F642) * 16384,
        "x" * 65536,
        chr(0) * 65536,
        "\\" * 65536,
        '"' * 65536,
        "\b\t\n\f\r" * 13107,
    ]
    for value in samples:
        assert parsing._string_size(value) == reviewed_size(value, json_string=True)
        assert parsing._string_size(value) <= 6 * 65536 + 2


@pytest.mark.parametrize("escaped", [True, False])
def test_plain_string_spans_keep_utf8_and_escaped_surrogate_boundaries(escaped: bool) -> None:
    samples = [
        "x" * 65536,
        chr(0xE9) * 32768,
        chr(0x20AC) * 21845,
        chr(0x1F642) * 16384,
        "x" * 32768 + "\\" + "y" * 32767,
        "x" * 32768 + '"' + "y" * 32767,
        "x" * 32768 + chr(0) + "y" * 32767,
    ]
    for value in samples:
        content = json.dumps({"value": value}, ensure_ascii=escaped).encode("utf-8")
        assert parsing.parse_strict_json(content) == {"value": value}
        overflow = json.dumps({"value": value + "xxxx"}, ensure_ascii=escaped).encode("utf-8")
        with pytest.raises(parsing.ParsingError):
            parsing.parse_strict_json(overflow)
