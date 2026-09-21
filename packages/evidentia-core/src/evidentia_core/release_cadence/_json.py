"""Strict bounded JSON parsing and canonical bytes from owned native snapshots."""

from __future__ import annotations

import json
import math
import re
from contextlib import suppress
from dataclasses import dataclass
from typing import cast

from ._limits import (
    JSON_DEPTH,
    JSON_KEY_BYTES,
    JSON_NUMBER_BYTES,
    JSON_VALUES,
    PAGE_BYTES,
    Budget,
    ReleaseFailure,
    check_budget,
    text_value,
)

_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")


@dataclass(frozen=True, slots=True)
class JsonStats:
    values: int
    depth: int


def _discard(value: object) -> None:
    pending = [value]
    try:
        while pending:
            current = pending.pop()
            if type(current) is dict:
                mapping = cast(dict[str, object], current)
                pending.extend(mapping.values())
                mapping.clear()
            elif type(current) is list:
                sequence = cast(list[object], current)
                pending.extend(sequence)
                sequence.clear()
    finally:
        pending.clear()


def _string_size(text: str, maximum: int, budget: Budget | None) -> int:
    # Each temporary is bounded by 4,096 code points, regardless of source size.
    if len(text) > maximum:
        raise ReleaseFailure("json_scalar")
    total = 2
    utf8 = 0
    for offset in range(0, len(text), 4096):
        check_budget(budget)
        chunk = text[offset : offset + 4096]
        try:
            utf8 += len(chunk.encode("utf-8"))
        except UnicodeError:
            raise ReleaseFailure("json_scalar") from None
        if utf8 > maximum:
            raise ReleaseFailure("json_scalar")
        # The standard encoder allocates at most 49,154 characters here.
        total += len(json.encoder.encode_basestring_ascii(chunk)) - 2
    return total


def _snapshot(
    value: object,
    maximum: int,
    *,
    budget: Budget | None,
    allow_aliases: bool,
    max_values: int,
    max_depth: int,
    max_string_bytes: int,
    spaced: bool,
) -> tuple[object, int]:
    """Detach each occurrence, rejecting callbacks before iteration or hashing."""
    check_budget(budget)
    seen: set[int] = set()
    active: set[int] = set()
    cache: dict[str, int] = {}
    holder: list[object] = []
    frames: list[tuple[object, object, object, int, bool]] = [(value, holder, None, 1, False)]
    total = 0
    count = 0
    try:
        while frames:
            source, parent, key, depth, leaving = frames.pop()
            if leaving:
                active.remove(cast(int, source))
                continue
            count += 1
            if count > max_values:
                raise ReleaseFailure("json_count")
            if depth > max_depth:
                raise ReleaseFailure("json_depth")
            if count & 255 == 1:
                check_budget(budget)
            native_type = type(source)
            if native_type is dict or native_type is list:
                identity = id(source)
                if identity in active or (not allow_aliases and identity in seen):
                    raise ReleaseFailure("invalid_request")
                active.add(identity)
                seen.add(identity)
                # Refuse impossible fan-out before allocating the shallow work list.
                length = len(cast(dict[str, object] | list[object], source))
                if count + length * (2 if native_type is dict else 1) > max_values:
                    raise ReleaseFailure("json_count")
                destination: object = {} if native_type is dict else []
                total += 2 + max(0, length - 1) * (2 if spaced else 1)
                frames.append((identity, None, None, depth, True))
                if native_type is dict:
                    items = list(cast(dict[object, object], source).items())
                    try:
                        for item_key, item in reversed(items):
                            if type(item_key) is not str:
                                raise ReleaseFailure("json_scalar")
                            # Keys are occurrences at child depth, not containers.
                            count += 1
                            if count > max_values:
                                raise ReleaseFailure("json_count")
                            if depth + 1 > max_depth:
                                raise ReleaseFailure("json_depth")
                            if count & 255 == 1:
                                check_budget(budget)
                            if len(item_key) <= 64 and item_key.isascii():
                                key_size = cache.get(item_key)
                                if key_size is None:
                                    key_size = _string_size(item_key, JSON_KEY_BYTES, budget)
                                    if len(cache) < 512:
                                        cache[item_key] = key_size
                                elif item_key:
                                    check_budget(budget)
                            else:
                                key_size = _string_size(item_key, JSON_KEY_BYTES, budget)
                            total += key_size + (2 if spaced else 1)
                            if total > maximum:
                                raise ReleaseFailure("result_limit_exceeded")
                            frames.append((item, destination, item_key, depth + 1, False))
                    finally:
                        items.clear()
                else:
                    items_list = list(cast(list[object], source))
                    try:
                        for item in reversed(items_list):
                            frames.append((item, destination, None, depth + 1, False))
                    finally:
                        items_list.clear()
            elif native_type is str:
                string = cast(str, source)
                if len(string) <= 64 and string.isascii():
                    size = cache.get(string)
                    if size is None:
                        size = _string_size(string, max_string_bytes, budget)
                        if len(cache) < 512:
                            cache[string] = size
                    elif len(string) > max_string_bytes:
                        raise ReleaseFailure("json_scalar")
                else:
                    size = _string_size(string, max_string_bytes, budget)
                total += size
                destination = source
            elif native_type is bool:
                total += 4 if source else 5
                destination = source
            elif source is None:
                total += 4
                destination = None
            elif native_type is int:
                number = cast(int, source)
                if number.bit_length() > 426:
                    raise ReleaseFailure("json_scalar")
                spelling = str(number)
                if len(spelling) > JSON_NUMBER_BYTES:
                    raise ReleaseFailure("json_scalar")
                total += len(spelling)
                destination = source
            elif native_type is float:
                floating = cast(float, source)
                if not math.isfinite(floating):
                    raise ReleaseFailure("json_scalar")
                spelling = json.dumps(floating, allow_nan=False)
                if len(spelling) > JSON_NUMBER_BYTES:
                    raise ReleaseFailure("json_scalar")
                total += len(spelling)
                destination = source
            else:
                raise ReleaseFailure("json_scalar")
            if total > maximum:
                raise ReleaseFailure("result_limit_exceeded")
            if type(parent) is list:
                cast(list[object], parent).append(destination)
            else:
                cast(dict[str, object], parent)[cast(str, key)] = destination
        check_budget(budget)
        result = holder.pop()
        return result, total
    except BaseException:
        with suppress(BaseException):
            _discard(holder)
        raise
    finally:
        holder.clear()
        frames.clear()
        active.clear()
        seen.clear()
        cache.clear()
        source = parent = key = destination = item = item_key = None


def detach(
    value: object,
    maximum: int,
    *,
    budget: Budget | None = None,
    allow_aliases: bool = False,
    max_values: int = JSON_VALUES,
    max_depth: int = JSON_DEPTH,
    max_string_bytes: int = PAGE_BYTES,
) -> object:
    return _snapshot(
        value,
        maximum,
        budget=budget,
        allow_aliases=allow_aliases,
        max_values=max_values,
        max_depth=max_depth,
        max_string_bytes=max_string_bytes,
        spaced=False,
    )[0]


def canonical_bytes(
    value: object,
    maximum: int,
    *,
    budget: Budget | None = None,
    allow_aliases: bool = False,
    max_values: int = JSON_VALUES,
    max_depth: int = JSON_DEPTH,
    spaced: bool = False,
) -> bytes:
    snapshot, length = _snapshot(
        value,
        maximum,
        budget=budget,
        allow_aliases=allow_aliases,
        max_values=max_values,
        max_depth=max_depth,
        max_string_bytes=PAGE_BYTES,
        spaced=spaced,
    )
    raw: bytes | None = None
    try:
        check_budget(budget)
        raw = json.dumps(
            snapshot,
            sort_keys=True,
            separators=(", ", ": ") if spaced else (",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        if len(raw) != length or len(raw) > maximum:
            raise ReleaseFailure("result_limit_exceeded")
        check_budget(budget)
    except BaseException:
        with suppress(BaseException):
            _discard(snapshot)
        raise
    else:
        _discard(snapshot)
        return raw
    finally:
        snapshot = None
        raw = None


def preflight(
    raw: bytes,
    maximum: int,
    *,
    budget: Budget | None = None,
    max_values: int = JSON_VALUES,
    max_depth: int = JSON_DEPTH,
    max_string_bytes: int = PAGE_BYTES,
) -> JsonStats:
    """Count the complete grammar before general object construction."""
    check_budget(budget)
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise ReleaseFailure("json_scalar")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise ReleaseFailure("json_syntax") from None
    if text.startswith("\ufeff"):
        raise ReleaseFailure("json_syntax")
    position = 0
    occurrences = 0
    deepest = 0
    size = len(text)

    def space() -> None:
        nonlocal position
        while position < size and text[position] in " \t\r\n":
            if position & 4095 == 0:
                check_budget(budget)
            position += 1

    def charge(depth: int) -> None:
        nonlocal occurrences, deepest
        occurrences += 1
        deepest = max(deepest, depth)
        if occurrences > max_values:
            raise ReleaseFailure("json_count")
        if depth > max_depth:
            raise ReleaseFailure("json_depth")
        if occurrences & 255 == 1:
            check_budget(budget)

    def string(*, key: bool = False) -> str:
        nonlocal position
        begin = position
        position += 1
        escaped = False
        while position < size:
            if position & 4095 == 0:
                check_budget(budget)
            character = text[position]
            position += 1
            if not escaped and character == '"':
                break
            escaped = not escaped and character == "\\"
            if key and position - begin > 6 * JSON_KEY_BYTES + 2:
                raise ReleaseFailure("json_scalar")
        else:
            raise ReleaseFailure("json_syntax")
        try:
            decoded = json.loads(text[begin:position])
        except (ValueError, UnicodeError):
            raise ReleaseFailure("json_syntax") from None
        return text_value(decoded, JSON_KEY_BYTES if key else max_string_bytes)

    def value(depth: int) -> None:
        nonlocal position
        space()
        charge(depth)
        if position >= size:
            raise ReleaseFailure("json_syntax")
        character = text[position]
        if character == "{":
            position += 1
            keys: set[str] = set()
            try:
                space()
                if position < size and text[position] == "}":
                    position += 1
                    return
                while True:
                    space()
                    if position >= size or text[position] != '"':
                        raise ReleaseFailure("json_syntax")
                    charge(depth + 1)
                    name = string(key=True)
                    if name in keys:
                        raise ReleaseFailure("json_syntax")
                    keys.add(name)
                    space()
                    if position >= size or text[position] != ":":
                        raise ReleaseFailure("json_syntax")
                    position += 1
                    value(depth + 1)
                    space()
                    if position < size and text[position] == "}":
                        position += 1
                        return
                    if position >= size or text[position] != ",":
                        raise ReleaseFailure("json_syntax")
                    position += 1
            finally:
                keys.clear()
        elif character == "[":
            position += 1
            space()
            if position < size and text[position] == "]":
                position += 1
                return
            while True:
                value(depth + 1)
                space()
                if position < size and text[position] == "]":
                    position += 1
                    return
                if position >= size or text[position] != ",":
                    raise ReleaseFailure("json_syntax")
                position += 1
        elif character == '"':
            string()
        elif character in "-0123456789":
            begin = position
            while position < size and text[position] in "-+0123456789.eE":
                position += 1
                if position - begin > JSON_NUMBER_BYTES:
                    raise ReleaseFailure("json_scalar")
            spelling = text[begin:position]
            if _NUMBER.fullmatch(spelling) is None:
                raise ReleaseFailure("json_syntax")
            if ("." in spelling or "e" in spelling or "E" in spelling) and not math.isfinite(float(spelling)):
                raise ReleaseFailure("json_scalar")
        else:
            for literal in ("true", "false", "null"):
                if text.startswith(literal, position):
                    position += len(literal)
                    return
            raise ReleaseFailure("json_syntax")

    value(1)
    space()
    if position != size:
        raise ReleaseFailure("json_syntax")
    check_budget(budget)
    return JsonStats(occurrences, deepest)


def load_json(
    raw: bytes,
    maximum: int,
    *,
    budget: Budget | None = None,
    max_values: int = JSON_VALUES,
    max_depth: int = JSON_DEPTH,
    max_string_bytes: int = PAGE_BYTES,
) -> object:
    preflight(
        raw,
        maximum,
        budget=budget,
        max_values=max_values,
        max_depth=max_depth,
        max_string_bytes=max_string_bytes,
    )
    check_budget(budget)
    result: object = None
    try:
        result = json.loads(raw)
        check_budget(budget)
        return result
    except BaseException:
        with suppress(BaseException):
            _discard(result)
        result = None
        raise
