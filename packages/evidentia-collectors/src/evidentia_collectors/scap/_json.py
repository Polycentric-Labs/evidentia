"""Count and serialize exact native JSON without coercion or skipped aliases."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass
from typing import cast

from ._limits import RESULT_LIMIT, Budget, ScapFailure

type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None
type _Container = list[JsonValue] | dict[str, JsonValue]

_ESCAPED = re.compile(r'[\x00-\x1f"\\\x7f-\U0010ffff]')
_MAX_INTEGER = 9_007_199_254_740_991
_MAX_DEPTH = 128


@dataclass(slots=True)
class _Frame:
    items: Iterator[tuple[object, object]]
    source_id: int
    output: _Container | None
    mapping: bool
    entries: int = 0


def _string_size(value: str, remaining: int, budget: Budget | None, publication: bool) -> int:
    total = len(value) + 2
    if total > remaining:
        raise ScapFailure("result_limit_exceeded")
    for index, match in enumerate(_ESCAPED.finditer(value)):
        if budget is not None and index % 1024 == 0:
            budget.check(publication=publication)
        character = match.group()
        point = ord(character)
        if 0xD800 <= point <= 0xDFFF:
            raise ScapFailure()
        if point <= 0x7F and character in '\b\t\n\f\r"\\':
            total += 1
        elif point <= 0xFFFF:
            total += 5
        else:
            total += 11
        if total > remaining:
            raise ScapFailure("result_limit_exceeded")
    return total


def _walk(
    value: object, maximum: int, budget: Budget | None, *, publication: bool, snapshot: bool
) -> tuple[int, JsonValue]:
    """Validate and optionally detach in one iterative occurrence-charged pass."""
    if type(maximum) is not int or maximum < 0:
        raise ScapFailure()
    active: set[int] = set()
    frames: list[_Frame] = []
    total = 0
    visited = 0
    current = value
    parent: _Container | None = None
    parent_key: str | None = None
    result: JsonValue = None

    def add(size: int) -> None:
        nonlocal total
        total += size
        if total > maximum:
            raise ScapFailure("result_limit_exceeded")

    try:
        while True:
            visited += 1
            if budget is not None and visited % 256 == 1:
                budget.check(publication=publication)
            if len(frames) > _MAX_DEPTH:
                raise ScapFailure()
            item_type = type(current)
            output: JsonValue
            new_frame: _Frame | None = None
            if current is None:
                add(4)
                output = None
            elif item_type is bool:
                add(4 if current else 5)
                output = cast(bool, current)
            elif item_type is str:
                output = cast(str, current)
                add(_string_size(output, maximum - total, budget, publication))
            elif item_type is int:
                number = cast(int, current)
                if not -_MAX_INTEGER <= number <= _MAX_INTEGER:
                    raise ScapFailure()
                add(len(str(number)))
                output = number
            elif item_type is float:
                decimal = cast(float, current)
                if not math.isfinite(decimal):
                    raise ScapFailure()
                add(len(json.dumps(decimal, allow_nan=False)))
                output = decimal
            elif item_type is dict or item_type is list:
                identity = id(current)
                if identity in active:
                    raise ScapFailure()
                add(2)
                active.add(identity)
                target: _Container | None = None
                items: Iterator[tuple[object, object]]
                if item_type is dict:
                    items = iter(cast(dict[object, object], current).items())
                    if snapshot:
                        target = {}
                else:
                    items = iter(enumerate(cast(list[object], current)))
                    if snapshot:
                        target = []
                output = target
                new_frame = _Frame(items, identity, target, item_type is dict)
            else:
                raise ScapFailure()
            if snapshot:
                if parent is None:
                    result = output
                elif type(parent) is list:
                    cast(list[JsonValue], parent).append(output)
                else:
                    if parent_key is None:
                        raise ScapFailure()
                    cast(dict[str, JsonValue], parent)[parent_key] = output
            if new_frame is not None:
                frames.append(new_frame)
            while frames:
                frame = frames[-1]
                try:
                    key, child = next(frame.items)
                except StopIteration:
                    active.remove(frame.source_id)
                    frames.pop()
                    continue
                except RuntimeError:
                    raise ScapFailure() from None
                if frame.entries:
                    add(1)
                frame.entries += 1
                if frame.mapping:
                    if type(key) is not str:
                        raise ScapFailure()
                    parent_key = cast(str, key)
                    add(_string_size(parent_key, maximum - total, budget, publication))
                    add(1)
                else:
                    parent_key = None
                parent = frame.output
                current = child
                break
            else:
                if budget is not None:
                    budget.check(publication=publication)
                return total, result
    except BaseException as error:
        _discard_snapshot(result, error)
        frames.clear()
        active.clear()
        raise


def _discard_snapshot(value: JsonValue, primary: BaseException | None) -> None:
    """Clear only containers allocated by the native snapshot walk."""
    pending = [value]
    try:
        while pending:
            item = pending.pop()
            if type(item) is dict:
                mapping = cast(dict[str, JsonValue], item)
                pending.extend(child for child in mapping.values() if type(child) is dict or type(child) is list)
                mapping.clear()
            elif type(item) is list:
                sequence = cast(list[JsonValue], item)
                pending.extend(child for child in sequence if type(child) is dict or type(child) is list)
                sequence.clear()
    except BaseException:
        if primary is None:
            raise
        with suppress(BaseException):
            primary.add_note("SCAP native snapshot cleanup also failed.")
    finally:
        pending.clear()


def canonical_size(value: object, maximum: int, budget: Budget | None = None, *, publication: bool = False) -> int:
    return _walk(value, maximum, budget, publication=publication, snapshot=False)[0]


def canonical_bytes(
    value: object, maximum: int = RESULT_LIMIT, budget: Budget | None = None, *, publication: bool = False
) -> bytes:
    snapshot: JsonValue = None
    encoded = b""
    primary: BaseException | None = None
    try:
        measured, snapshot = _walk(value, maximum, budget, publication=publication, snapshot=True)
        encoded = json.dumps(
            snapshot, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        if len(encoded) != measured:
            raise ScapFailure()
        if budget is not None:
            budget.check(publication=publication)
        return encoded
    except BaseException as error:
        primary = error
        raise
    finally:
        _discard_snapshot(snapshot, primary)
        snapshot = None
        encoded = b""


def detached(value: object, maximum: int, budget: Budget | None = None) -> JsonValue:
    """Copy each acyclic occurrence while validating and charging its contents."""
    return _walk(value, maximum, budget, publication=False, snapshot=True)[1]


def load_json(raw: bytes, maximum: int) -> JsonValue:
    """Read one bounded UTF-8 JSON value, refusing duplicate object keys."""
    if type(raw) is not bytes or not 0 < len(raw) <= maximum or raw.startswith(b"\xef\xbb\xbf"):
        raise ScapFailure()
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                in_string = False
        elif byte == 34:
            in_string = True
        elif byte in (91, 123):
            depth += 1
            if depth > _MAX_DEPTH:
                raise ScapFailure()
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise ScapFailure()
    if depth or in_string:
        raise ScapFailure()

    def pairs(items: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for key, value in items:
            if key in result:
                raise ScapFailure()
            result[key] = value
        return result

    def integer(text: str) -> int:
        if len(text) > 17:
            raise ScapFailure()
        number = int(text)
        if not -_MAX_INTEGER <= number <= _MAX_INTEGER:
            raise ScapFailure()
        return number

    def forbidden_constant(text: str) -> float:
        raise ScapFailure()

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_int=integer, parse_constant=forbidden_constant
        )
    except (UnicodeError, ValueError, RecursionError):
        raise ScapFailure() from None
    canonical_size(value, RESULT_LIMIT)
    return cast(JsonValue, value)
