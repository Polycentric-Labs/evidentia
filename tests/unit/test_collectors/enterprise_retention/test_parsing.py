"""Private candidate checks for inherited value fidelity and the tighter depth bound."""

from __future__ import annotations

import json
import math
from decimal import getcontext
from typing import cast

import pytest
from evidentia_collectors.enterprise_retention import _parsing as candidate
from evidentia_collectors.retention import _parsing as storage
from pydantic import JsonValue


def nested(depth: int) -> JsonValue:
    value: JsonValue = 0
    for _ in range(depth):
        value = [value]
    return value


@pytest.mark.parametrize("depth", [1, 15, 16])
def test_supported_depths(depth: int) -> None:
    value = nested(depth)
    wire = b"[" * depth + b"0" + b"]" * depth
    assert candidate.parse_strict_json(wire) == value
    assert candidate.checked_json(value) == value
    assert candidate.canonical_json(value) == wire


@pytest.mark.parametrize("depth", [17, 32, 100])
def test_depth_refused_before_inherited_parser(depth: int, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Inherited allocation must not be reached")

    monkeypatch.setattr(storage, "parse_strict_json", forbidden)
    monkeypatch.setattr(storage, "checked_json", forbidden)
    monkeypatch.setattr(storage, "canonical_json", forbidden)
    for action in (
        lambda: candidate.parse_strict_json(b"[" * depth + b"0" + b"]" * depth),
        lambda: candidate.checked_json(nested(depth)),
        lambda: candidate.canonical_json(nested(depth)),
    ):
        with pytest.raises(candidate.ParsingError, match=r"^invalid_json$"):
            action()


def test_structural_characters_in_strings() -> None:
    wire = rb'{"brackets":"[[[{]}]", "escaped":"quote\"[", "slash":"\\"}'
    value = candidate.parse_strict_json(wire)
    assert value == {"brackets": "[[[{]}]", "escaped": 'quote"[', "slash": "\\"}


@pytest.mark.parametrize(
    "wire",
    [
        b'{"x":1,"\\u0078":2}',
        b'"\\ud800"',
        b"\xef\xbb\xbf{}",
        b'"\xff"',
        b"NaN",
        b"Infinity",
        b"1e10000",
        b"1e-10000",
        b"1.0000000000000001",
        b"[}",
        b"[",
        b"]",
        b'"unterminated',
        b"9" * 129,
    ],
)
def test_inherited_strict_rejections(wire: bytes) -> None:
    with pytest.raises(candidate.ParsingError, match=r"^invalid_json$"):
        candidate.parse_strict_json(wire)


def test_native_values_keep_type_and_precision() -> None:
    context = getcontext().copy()
    result = candidate.parse_strict_json(b'[0,false,0.1,-0.0,9007199254740993,"9007199254740993"]')
    assert isinstance(result, list)
    assert [type(item) for item in result] == [int, bool, float, float, int, str]
    assert result[2] == 0.1 and result[4] == 9007199254740993
    assert type(result[3]) is float and math.copysign(1, result[3]) == -1
    assert getcontext().flags == context.flags and getcontext().prec == context.prec


def test_node_limit_includes_keys() -> None:
    assert candidate.checked_json([None] * 9999) == [None] * 9999
    with pytest.raises(candidate.ParsingError):
        candidate.checked_json([None] * 10000)
    with pytest.raises(candidate.ParsingError):
        candidate.checked_json({str(i): None for i in range(5000)})


def test_input_and_output_are_detached() -> None:
    original: dict[str, JsonValue] = {"values": [False, None, 0]}
    result = candidate.checked_json(original)
    assert isinstance(result, dict) and result == original
    result["values"] = "changed"
    assert original == {"values": [False, None, 0]}


def test_byte_limits() -> None:
    assert candidate.parse_strict_json(b"null", max_bytes=4) is None
    with pytest.raises(candidate.ParsingError):
        candidate.parse_strict_json(b"null ", max_bytes=4)
    with pytest.raises(candidate.ParsingError):
        candidate.parse_strict_json(b"null", max_bytes=True)


def test_native_cycles_and_non_json_objects() -> None:
    cycle: list[object] = []
    cycle.append(cycle)
    for value in (cycle, (1, 2), {1: "value"}, object(), float("inf"), 10**128):
        with pytest.raises(candidate.ParsingError, match=r"^invalid_json$"):
            candidate.checked_json(value)


@pytest.mark.parametrize("serialize", [False, True])
def test_unsupported_metaclass_never_participates_in_admission(serialize: bool) -> None:
    def forbidden(*_args: object) -> None:
        raise AssertionError("Native type admission must use identity")

    for attributes in ({"__hash__": None}, {"__hash__": forbidden, "__eq__": forbidden}):
        meta = type("NonJSONMeta", (type,), attributes)
        unsupported = meta("NonJSON", (), {})()
        with pytest.raises(candidate.ParsingError, match=r"^invalid_json$"):
            if serialize:
                candidate.canonical_json(cast(JsonValue, unsupported))
            else:
                candidate.checked_json(unsupported)


@pytest.mark.parametrize("serialize", [False, True])
def test_detached_clone_rechecked_after_caller_mutation(serialize: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    original: list[JsonValue] = [None]
    inherited = candidate._EnterpriseBudget.clone
    reached = False

    def change_before_clone(budget: candidate._EnterpriseBudget, value: object, depth: int) -> JsonValue:
        nonlocal reached
        if value is original:
            reached = True
            original[0] = nested(16)
        return inherited(budget, value, depth)

    monkeypatch.setattr(candidate._EnterpriseBudget, "clone", change_before_clone)
    with pytest.raises(candidate.ParsingError, match=r"^invalid_json$"):
        if serialize:
            candidate.canonical_json(original)
        else:
            candidate.checked_json(original)
    assert reached


@pytest.mark.parametrize("serialize", [False, True])
def test_mutation_cannot_invoke_unsupported_metaclass(serialize: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    original: list[JsonValue] = [None]
    called: list[str] = []
    inherited = candidate._EnterpriseBudget.clone

    def forbidden(*_args: object) -> None:
        called.append("metaclass")
        raise AssertionError("Unsupported metaclass callback")

    meta = type("ChangingMeta", (type,), {"__hash__": forbidden, "__eq__": forbidden})
    unsupported = meta("NonJSON", (), {})()

    def change_before_clone(budget: candidate._EnterpriseBudget, value: object, depth: int) -> JsonValue:
        if value is original:
            original[0] = cast(JsonValue, unsupported)
        return inherited(budget, value, depth)

    monkeypatch.setattr(candidate._EnterpriseBudget, "clone", change_before_clone)
    with pytest.raises(candidate.ParsingError, match=r"^invalid_json$"):
        if serialize:
            candidate.canonical_json(original)
        else:
            candidate.checked_json(original)
    assert not called


def test_result_parser_exceeds_document_limits_without_raising_them() -> None:
    value: dict[str, JsonValue] = {"items": ["x" * 65_000 for _ in range(18)]}
    wire = candidate.result_json_bytes(value)
    assert 1_048_576 < len(wire) < candidate.MAX_RESULT_BYTES
    assert candidate.parse_result_json(wire) == value
    with pytest.raises(candidate.ParsingError):
        candidate.parse_strict_json(wire)
    with pytest.raises(storage.ParsingError):
        storage.parse_strict_json(wire)
    dense: dict[str, JsonValue] = {"items": [[0] * 6000, [0] * 6000]}
    assert candidate.checked_result_json(dense) == dense
    with pytest.raises(candidate.ParsingError):
        candidate.checked_json(dense)


def test_result_parser_depth_is_independent_from_document_depth(monkeypatch: pytest.MonkeyPatch) -> None:
    value: dict[str, JsonValue] = {"items": nested(19)}
    wire = candidate.result_json_bytes(value)
    assert candidate.parse_result_json(wire) == value
    with pytest.raises(candidate.ParsingError):
        candidate.checked_json(value)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Aggregate decoder must not be reached")

    monkeypatch.setattr(json, "loads", forbidden)
    with pytest.raises(candidate.ParsingError):
        candidate.parse_result_json(b'{"items":' + b"[" * 20 + b"0" + b"]" * 20 + b"}")
    with pytest.raises(candidate.ParsingError):
        candidate.checked_result_json({"items": nested(20)})


@pytest.mark.parametrize(
    "wire",
    [
        b'{"v":1,"\\u0076":2}',
        b'{"v":{"x":1,"x":2}}',
        b'{"v":NaN}',
        b'{"v":1e10000}',
        b'{"v":1e-10000}',
        b'{"v":1.0000000000000001}',
        b'{"v":' + b"9" * 129 + b"}",
        b'{"v":"\\ud800"}',
        b"\xef\xbb\xbf{}",
        b'{"v":"\xff"}',
        b"[]",
        b"false",
    ],
)
def test_aggregate_wire_lexical_refusals(wire: bytes) -> None:
    with pytest.raises(candidate.ParsingError, match=r"^invalid_json$"):
        candidate.parse_result_json(wire)


def test_aggregate_exact_scalars_and_context() -> None:
    context = getcontext().copy()
    wire = b'{"v":[9007199254740993,1.0,-0.0,false,"9007199254740993",' + b"9" * 128 + b"]}"
    value = candidate.parse_result_json(wire)
    values = value["v"]
    assert isinstance(values, list)
    assert [type(v) for v in values] == [int, float, float, bool, str, int]
    assert values[0] == 9007199254740993 and values[5] == 10**128 - 1
    assert type(values[2]) is float and math.copysign(1, values[2]) == -1
    assert candidate.parse_result_json(candidate.result_json_bytes(value)) == value
    assert getcontext().flags == context.flags and getcontext().prec == context.prec


def test_aggregate_raw_byte_limit_precedes_decoder(monkeypatch: pytest.MonkeyPatch) -> None:
    small = b'{"v":null}'
    wire = small + b" " * (candidate.MAX_RESULT_BYTES - len(small))
    assert candidate.parse_result_json(wire) == {"v": None}

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Oversized input must not reach a decoder")

    monkeypatch.setattr(json, "loads", forbidden)
    with pytest.raises(candidate.ParsingError):
        candidate.parse_result_json(wire + b" ")


def test_aggregate_native_bytes_and_detachment() -> None:
    value: dict[str, JsonValue] = {"items": ["x" * 65_534] * 64}
    with pytest.raises(candidate.ParsingError):
        candidate.checked_result_json(value)
    caller: dict[str, JsonValue] = {"items": [False, 0, None]}
    detached = candidate.checked_result_json(caller)
    caller["items"] = None
    assert detached == {"items": [False, 0, None]}


def test_aggregate_node_guard_with_explicit_internal_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    # The production node ceiling follows from the byte limit; use a smaller internal control.
    monkeypatch.setattr(candidate, "MAX_RESULT_NODES", 5)
    assert candidate.parse_result_json(b'{"v":[0,0]}') == {"v": [0, 0]}

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Node overflow must not reach allocation")

    monkeypatch.setattr(json, "loads", forbidden)
    monkeypatch.setattr(storage._JSONBudget, "clone", forbidden)
    with pytest.raises(candidate.ParsingError):
        candidate.parse_result_json(b'{"v":[0,0,0]}')
    with pytest.raises(candidate.ParsingError):
        candidate.checked_result_json({"v": [0, 0, 0]})


def test_aggregate_native_cycles_and_unsupported_types() -> None:
    calls: list[str] = []

    def forbidden(*_args: object) -> None:
        calls.append("metaclass")
        raise AssertionError("Unsupported native callback")

    meta = type("NonJSONMeta", (type,), {"__hash__": forbidden, "__eq__": forbidden})
    unsupported = meta("NonJSON", (), {})()
    cycle: list[object] = []
    cycle.append(cycle)
    for value in ({"v": cycle}, {"v": unsupported}, {"v": (1, 2)}, {1: None}, {"v": float("inf")}):
        with pytest.raises(candidate.ParsingError, match=r"^invalid_json$"):
            candidate.checked_result_json(value)
    assert not calls
