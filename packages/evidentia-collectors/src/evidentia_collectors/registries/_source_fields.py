"""Check selected fields against a finite, source-bound correspondence table."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from types import MappingProxyType
from typing import Any, Literal, cast

from ._contracts import CoverageState, SourceTime, normalized_source_time
from ._parsing import canonical_json, checked_json, parse_result_json

_TABLE_SHA256 = "ba26d1edf0d2172ea4701012b0051adc9645138325a2bddb9a7e1a98314bcd7b"
TimeRepresentation = Literal["rfc3339", "unix_milliseconds", "source_text"]


class SourceFieldError(ValueError):
    def __init__(self, code: str = "invalid_response") -> None:
        self.code = "projection_mismatch" if type(code) is str and code == "projection_mismatch" else "invalid_response"
        super().__init__(self.code)


@dataclass(frozen=True)
class FieldRule:
    path: str
    kind: str
    nullable: bool
    children: tuple[str, ...]
    positions: tuple[int, ...]
    minimum: int | None
    time: TimeRepresentation | None


def _segment(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _parts(path: str) -> tuple[str, ...]:
    return tuple(part.replace("~1", "/").replace("~0", "~") for part in path.split("/")[1:])


@lru_cache(maxsize=1)
def _shapes() -> Mapping[tuple[str, str], Mapping[str, FieldRule]]:
    resource = resources.files("evidentia_collectors.registries").joinpath("data/source-index.json")
    try:
        with resource.open("rb") as stream:
            raw = stream.read(1_048_577)
        if len(raw) > 1_048_576:
            raise SourceFieldError()
        manifest = parse_result_json(raw)
        shapes = manifest["field_shapes"]
        if hashlib.sha256(canonical_json(checked_json(shapes))).hexdigest() != _TABLE_SHA256:
            raise SourceFieldError()
        result: dict[tuple[str, str], Mapping[str, FieldRule]] = {}
        for shape in cast(list[dict[str, Any]], shapes):
            rules = {
                row["path"]: FieldRule(
                    row["path"],
                    row["kind"],
                    row["nullable"],
                    tuple(row["children"]),
                    tuple(row["positions"]),
                    row["minimum"],
                    row["time"],
                )
                for row in shape["rules"]
            }
            result[(shape["selector"], shape["shape_id"])] = MappingProxyType(rules)
        return MappingProxyType(result)
    except (OSError, KeyError, ValueError, TypeError):
        raise SourceFieldError() from None


def _schema(selector: str, shape_id: str) -> Mapping[str, FieldRule]:
    if type(selector) is not str or type(shape_id) is not str:
        raise SourceFieldError()
    rules = _shapes().get((selector, shape_id))
    if rules is None:
        raise SourceFieldError()
    return rules


def _select(value: Any, rules: Mapping[str, FieldRule], path: str, *, projected: bool) -> Any:
    rule = rules[path]
    if value is None:
        if rule.nullable:
            return None
        raise SourceFieldError()
    expected = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool}[rule.kind]
    if type(value) is not expected:
        raise SourceFieldError()
    if rule.kind == "object":
        mapping = cast(dict[str, Any], value)
        if projected and not set(mapping).issubset(rule.children):
            raise SourceFieldError()
        return {
            key: _select(mapping[key], rules, path + "/" + _segment(key), projected=projected)
            for key in rule.children
            if key in mapping
        }
    if rule.kind == "array":
        items = cast(list[Any], value)
        if rule.positions:
            if len(items) != len(rule.positions):
                raise SourceFieldError()
            return [
                _select(item, rules, path + "/" + str(index), projected=projected) for index, item in enumerate(items)
            ]
        return [_select(item, rules, path + "/*", projected=projected) for item in items]
    if rule.minimum is not None and cast(int, value) < rule.minimum:
        raise SourceFieldError()
    return value


def _fields(selector: str, shape_id: str, value: object, *, projected: bool) -> dict[str, Any]:
    rules = _schema(selector, shape_id)
    try:
        source = checked_json(value)
        selected = _select(source, rules, "", projected=projected)
        if type(selected) is not dict or len(canonical_json(selected)) > 65_536:
            raise SourceFieldError()
        return selected
    except (KeyError, ValueError, TypeError, RecursionError):
        raise SourceFieldError() from None


def expected_fields(selector: str, shape_id: str, source: object) -> dict[str, Any]:
    """Controller oracle only; domain projectors must use their own extraction."""
    return _fields(selector, shape_id, source, projected=False)


def validate_fields(selector: str, shape_id: str, projected: object) -> dict[str, Any]:
    return _fields(selector, shape_id, projected, projected=True)


def assert_correspondence(selector: str, shape_id: str, source: object, projected: object) -> None:
    try:
        expected = expected_fields(selector, shape_id, source)
        actual = validate_fields(selector, shape_id, projected)
        if canonical_json(expected) != canonical_json(actual):
            raise SourceFieldError()
    except ValueError:
        raise SourceFieldError("projection_mismatch") from None


def _states(value: Any, parts: tuple[str, ...]) -> list[CoverageState]:
    if not parts:
        return ["null" if value is None else "present"]
    if value is None:
        return ["unknown"]
    first, rest = parts[0], parts[1:]
    if type(value) is dict:
        return _states(value[first], rest) if first in value else ["absent"]
    if type(value) is list:
        if first == "*":
            return [state for item in value for state in _states(item, rest)] or ["absent"]
        index = int(first)
        return _states(value[index], rest) if index < len(value) else ["absent"]
    return ["unknown"]


def field_coverage(selector: str, shape_id: str, fields: object) -> dict[str, CoverageState]:
    value = validate_fields(selector, shape_id, fields)
    result: dict[str, CoverageState] = {}
    for path in _schema(selector, shape_id):
        if path:
            states = set(_states(value, _parts(path)))
            result[path] = next(iter(states)) if len(states) == 1 else "unknown"
    return result


def _located(value: Any, parts: tuple[str, ...], path: str = "") -> Iterator[tuple[str, Any]]:
    if not parts:
        yield path, value
        return
    first, rest = parts[0], parts[1:]
    if type(value) is dict and first in value:
        yield from _located(value[first], rest, path + "/" + _segment(first))
    elif type(value) is list:
        if first == "*":
            for index, item in enumerate(value):
                yield from _located(item, rest, path + "/" + str(index))
        elif int(first) < len(value):
            yield from _located(value[int(first)], rest, path + "/" + first)


def source_times(selector: str, shape_id: str, fields: object) -> list[SourceTime]:
    value = validate_fields(selector, shape_id, fields)
    result: list[SourceTime] = []
    for path, rule in _schema(selector, shape_id).items():
        if rule.time is not None:
            for actual_path, literal in _located(value, _parts(path)):
                result.append(
                    SourceTime.model_validate(
                        {
                            "path": actual_path,
                            "literal": literal,
                            "representation": rule.time,
                            "normalized_utc": normalized_source_time(literal, rule.time),
                        }
                    )
                )
    return result
