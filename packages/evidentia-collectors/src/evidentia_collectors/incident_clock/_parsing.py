"""Bound source JSON before decoding and preserve exact native values."""

from __future__ import annotations

import json
import math
import re
from decimal import DecimalException
from typing import cast

from pydantic import JsonValue

from evidentia_collectors.retention import _parsing as storage

JsonObject = dict[str, JsonValue]
REQUEST_BYTE_LIMIT = 16_384
PROFILE_BYTE_LIMIT = 65_536
SOURCE_BYTE_LIMIT = 1_048_576
RESULT_BYTE_LIMIT = 16_777_216
PROJECTION_BYTE_LIMIT = 12_582_912
TERMINAL_RESERVE_BYTES = 4_194_304
MAX_DEPTH = 32
MAX_NODES = 100_000
MAX_STRING_BYTES = 65_536
MAX_INTEGER_DIGITS = 128
_RESULT_NODES = (RESULT_BYTE_LIMIT + 1) // 2
_INTEGER_BOUND = 10**MAX_INTEGER_DIGITS


class ParsingError(ValueError):
    """Report a fixed diagnostic without including the rejected source."""

    def __init__(self) -> None:
        super().__init__("invalid_json")


def _limits(max_bytes: int, max_nodes: int) -> None:
    if type(max_bytes) is not int or not 0 < max_bytes <= RESULT_BYTE_LIMIT:
        raise ParsingError()
    if type(max_nodes) is not int or not 0 < max_nodes <= _RESULT_NODES:
        raise ParsingError()


_PLAIN_STRING = re.compile(r'[^"\\\x00-\x1f\ud800-\udfff]+')


class _Scanner(storage._JSONScanner):
    """Reuse the strict grammar while enforcing the incident node and string caps."""

    def __init__(self, text: str, max_nodes: int) -> None:
        super().__init__(text)
        self.max_nodes = max_nodes

    def _node(self) -> None:
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise ParsingError()

    def _string(self) -> None:
        self._required('"')
        size = 0
        while self.position < len(self.text):
            run = _PLAIN_STRING.match(
                self.text, self.position, min(len(self.text), self.position + MAX_STRING_BYTES + 1)
            )
            if run is not None:
                size += len(run.group().encode("utf-8"))
                if size > MAX_STRING_BYTES:
                    raise ParsingError()
                self.position = run.end()
                continue
            char = self.text[self.position]
            self.position += 1
            if char == '"':
                return
            code = ord(char)
            if code < 32 or 0xD800 <= code <= 0xDFFF:
                raise ParsingError()
            if char == "\\":
                if self.position >= len(self.text):
                    raise ParsingError()
                escaped = self.text[self.position]
                self.position += 1
                if escaped in '\\"/bfnrt':
                    code = 0
                elif escaped == "u":
                    code = self._hex_quad()
                    if 0xDC00 <= code <= 0xDFFF:
                        raise ParsingError()
                    if 0xD800 <= code <= 0xDBFF:
                        self._required("\\")
                        self._required("u")
                        low = self._hex_quad()
                        if not 0xDC00 <= low <= 0xDFFF:
                            raise ParsingError()
                        code = 0x10000 + ((code - 0xD800) << 10) + low - 0xDC00
                else:
                    raise ParsingError()
            size += 1 if code <= 0x7F else 2 if code <= 0x7FF else 3 if code <= 0xFFFF else 4
            if size > MAX_STRING_BYTES:
                raise ParsingError()
        raise ParsingError()


def _string_size(value: str) -> int:
    if type(value) is not str or len(value) > MAX_STRING_BYTES:
        raise ParsingError()
    if len(value.encode("utf-8", errors="strict")) > MAX_STRING_BYTES:
        raise ParsingError()
    # Native encoding bounds the allocation to six bytes per admitted byte.
    return len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))


class _Budget:
    def __init__(self, max_bytes: int, max_nodes: int) -> None:
        self.max_bytes = max_bytes
        self.max_nodes = max_nodes
        self.nodes = 0
        self.size = 0
        self.active: set[int] = set()

    def _node(self) -> None:
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise ParsingError()

    def _add(self, size: int) -> None:
        self.size += size
        if self.size > self.max_bytes:
            raise ParsingError()

    def clone(self, value: object, depth: int = 0) -> JsonValue:
        self._node()
        native_type = type(value)
        if value is None:
            self._add(4)
            return None
        if type(value) is bool:
            self._add(4 if value else 5)
            return value
        if type(value) is int:
            if not -_INTEGER_BOUND < value < _INTEGER_BOUND:
                raise ParsingError()
            self._add(len(str(value)))
            return value
        if type(value) is float:
            if not math.isfinite(value):
                raise ParsingError()
            self._add(len(str(value)))
            return value
        if type(value) is str:
            self._add(_string_size(value))
            return value
        if native_type is not list and native_type is not dict:
            raise ParsingError()
        if depth >= MAX_DEPTH or id(value) in self.active:
            raise ParsingError()
        self.active.add(id(value))
        self._add(2)
        try:
            if native_type is list:
                result: list[JsonValue] = []
                for index, item in enumerate(cast(list[object], value)):
                    if index:
                        self._add(1)
                    result.append(self.clone(item, depth + 1))
                return result
            mapping: JsonObject = {}
            for index, (key, item) in enumerate(cast(dict[object, object], value).items()):
                self._node()
                if type(key) is not str:
                    raise ParsingError()
                self._add(_string_size(key) + 1 + bool(index))
                mapping[key] = self.clone(item, depth + 1)
            return mapping
        finally:
            self.active.remove(id(value))


def checked_json(value: object, *, max_bytes: int = SOURCE_BYTE_LIMIT, max_nodes: int = MAX_NODES) -> JsonValue:
    """Detach only native JSON, checking each visited value within finite budgets."""
    try:
        _limits(max_bytes, max_nodes)
        return _Budget(max_bytes, max_nodes).clone(value)
    except (TypeError, ValueError, OverflowError, RecursionError, RuntimeError):
        raise ParsingError() from None


def parse_strict_json(data: bytes, *, max_bytes: int = SOURCE_BYTE_LIMIT, max_nodes: int = MAX_NODES) -> JsonValue:
    """Count grammar nodes and decoded string bytes before allocating a JSON tree."""
    try:
        _limits(max_bytes, max_nodes)
        if type(data) is not bytes or len(data) > max_bytes:
            raise ParsingError()
        text = data.decode("utf-8", errors="strict")
        _Scanner(text, max_nodes).scan()
        value = json.loads(
            text,
            parse_int=storage._integer,
            parse_float=storage._finite_float,
            parse_constant=storage._constant,
            object_pairs_hook=storage._object,
        )
        return checked_json(value, max_bytes=max_bytes, max_nodes=max_nodes)
    except (TypeError, ValueError, OverflowError, RecursionError, RuntimeError, DecimalException):
        raise ParsingError() from None


def canonical_json(value: object, *, max_bytes: int = SOURCE_BYTE_LIMIT, max_nodes: int = MAX_NODES) -> bytes:
    """Serialize a detached native value as sorted, compact, literal UTF-8."""
    detached = checked_json(value, max_bytes=max_bytes, max_nodes=max_nodes)
    data = json.dumps(detached, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(data) > max_bytes:
        raise ParsingError()
    return data


def checked_result_json(value: object) -> JsonObject:
    """Apply aggregate result bounds; the result model closes the schema."""
    result = checked_json(value, max_bytes=RESULT_BYTE_LIMIT, max_nodes=_RESULT_NODES)
    if type(result) is not dict:
        raise ParsingError()
    return result


def parse_result_json(data: bytes) -> JsonObject:
    result = parse_strict_json(data, max_bytes=RESULT_BYTE_LIMIT, max_nodes=_RESULT_NODES)
    if type(result) is not dict:
        raise ParsingError()
    return result


def result_json_bytes(value: object) -> bytes:
    return canonical_json(checked_result_json(value), max_bytes=RESULT_BYTE_LIMIT, max_nodes=_RESULT_NODES)
