"""Bounded enterprise JSON documents and complete-result representations."""

from __future__ import annotations

import json
from decimal import DecimalException
from typing import cast

from pydantic import JsonValue

from evidentia_collectors.retention import _parsing as storage

JsonObject = dict[str, JsonValue]
MAX_BYTES = 1_048_576
MAX_DEPTH = 16
MAX_NODES = 10_000


class ParsingError(ValueError):
    """Report an invalid JSON value without including source content."""

    def __init__(self) -> None:
        super().__init__("invalid_json")


def _wire_depth(text: str, *, max_depth: int = MAX_DEPTH) -> None:
    depth = 0
    quoted = False
    escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > max_depth:
                raise ParsingError()
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise ParsingError()
    if depth or quoted:
        raise ParsingError()


class _NativeDepth:
    def __init__(self, *, max_depth: int = MAX_DEPTH, max_nodes: int = MAX_NODES) -> None:
        self.nodes = 0
        self.max_depth = max_depth
        self.max_nodes = max_nodes

    def node(self) -> None:
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise ParsingError()

    def check(self, value: object, depth: int = 0) -> None:
        self.node()
        native_type = type(value)
        if value is None or native_type is str or native_type is bool or native_type is int or native_type is float:
            return
        if native_type is not list and native_type is not dict:
            raise ParsingError()
        depth += 1
        if depth > self.max_depth:
            raise ParsingError()
        if native_type is list:
            for item in cast(list[object], value):
                self.check(item, depth)
        else:
            for key, item in cast(dict[object, object], value).items():
                self.node()
                if type(key) is not str:
                    raise ParsingError()
                self.check(item, depth)


class _EnterpriseBudget(storage._JSONBudget):
    """Apply enterprise admission to each actual item visited by the bounded clone."""

    def clone(self, value: object, depth: int) -> JsonValue:
        native_type = type(value)
        if value is None or native_type is str or native_type is bool or native_type is int or native_type is float:
            return super().clone(value, depth)
        if native_type is not list and native_type is not dict:
            raise ParsingError()
        if depth >= MAX_DEPTH:
            raise ParsingError()
        return super().clone(value, depth)


def parse_strict_json(data: bytes, *, max_bytes: int = MAX_BYTES) -> JsonValue:
    """Enforce the enterprise depth bound before the existing JSON allocation."""
    try:
        if type(max_bytes) is not int or not 0 < max_bytes <= MAX_BYTES:
            raise ParsingError()
        if type(data) is not bytes or len(data) > max_bytes:
            raise ParsingError()
        _wire_depth(data.decode("utf-8", errors="strict"))
        return storage.parse_strict_json(data, max_bytes=max_bytes)
    except (ValueError, UnicodeError, OverflowError, RecursionError):
        raise ParsingError() from None


def checked_json(value: object) -> JsonValue:
    """Preflight native input and validate the detached bounded clone before return."""
    try:
        _NativeDepth().check(value)
        detached = _EnterpriseBudget().clone(value, 0)
        _NativeDepth().check(detached)
        return detached
    except (TypeError, ValueError, OverflowError, RecursionError, RuntimeError):
        raise ParsingError() from None


def canonical_json(value: JsonValue) -> bytes:
    """Serialize a private validated snapshot with the existing logical representation."""
    try:
        detached = checked_json(value)
        return storage.canonical_json(detached)
    except (TypeError, ValueError, OverflowError, RecursionError, RuntimeError):
        raise ParsingError() from None


# Four result containers surround an observation whose complete local depth is at most 16.
MAX_RESULT_DEPTH = 20
MAX_RESULT_BYTES = 4_194_304
# A valid JSON tree with N key/value nodes needs at least 2*N-1 encoded bytes.
MAX_RESULT_NODES = (MAX_RESULT_BYTES + 1) // 2


class _AggregateScanner(storage._JSONScanner):
    def _node(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_RESULT_NODES:
            raise ParsingError()


class _AggregateBudget(storage._JSONBudget):
    def node(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_RESULT_NODES:
            raise ParsingError()

    def add(self, size: int) -> None:
        self.size += size
        if self.size > MAX_RESULT_BYTES:
            raise ParsingError()

    def clone(self, value: object, depth: int) -> JsonValue:
        native_type = type(value)
        if value is None or native_type is str or native_type is bool or native_type is int or native_type is float:
            return super().clone(value, depth)
        if native_type is not list and native_type is not dict:
            raise ParsingError()
        if depth >= MAX_RESULT_DEPTH:
            raise ParsingError()
        return super().clone(value, depth)


def checked_result_json(value: object) -> JsonObject:
    """Detach a bounded JSON result; the contracts layer validates its closed schema."""
    try:
        if type(value) is not dict:
            raise ParsingError()
        _NativeDepth(max_depth=MAX_RESULT_DEPTH, max_nodes=MAX_RESULT_NODES).check(value)
        detached = _AggregateBudget().clone(value, 0)
        if type(detached) is not dict:
            raise ParsingError()
        _NativeDepth(max_depth=MAX_RESULT_DEPTH, max_nodes=MAX_RESULT_NODES).check(detached)
        return detached
    except (TypeError, ValueError, OverflowError, RecursionError, RuntimeError):
        raise ParsingError() from None


def parse_result_json(data: bytes) -> JsonObject:
    """Preflight complete-result JSON before decoding with exact scalar checks."""
    try:
        if type(data) is not bytes or len(data) > MAX_RESULT_BYTES:
            raise ParsingError()
        text = data.decode("utf-8", errors="strict")
        if text.startswith("\ufeff"):
            raise ParsingError()
        _wire_depth(text, max_depth=MAX_RESULT_DEPTH)
        _AggregateScanner(text).scan()
        value = json.loads(
            text,
            parse_int=storage._integer,
            parse_float=storage._finite_float,
            parse_constant=storage._constant,
            object_pairs_hook=storage._object,
        )
        return checked_result_json(value)
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError, RuntimeError, DecimalException):
        raise ParsingError() from None


def result_json_bytes(value: object) -> bytes:
    """Serialize only a detached bounded result using compact literal UTF-8."""
    try:
        detached = checked_result_json(value)
        data = json.dumps(detached, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
            "utf-8"
        )
        if len(data) > MAX_RESULT_BYTES:
            raise ParsingError()
        return data
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError, RuntimeError):
        raise ParsingError() from None
