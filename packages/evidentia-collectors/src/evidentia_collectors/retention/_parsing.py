"""Bounded JSON and UTF-8 XML parsing for selected storage configuration."""

from __future__ import annotations

import json
import math
import re
import xml.etree.ElementTree as ET
from decimal import Context, Decimal, DecimalException, InvalidOperation
from typing import cast
from xml.sax import SAXException
from xml.sax.handler import ContentHandler
from xml.sax.xmlreader import AttributesImpl

from pydantic import JsonValue

__all__ = [
    "JsonObject",
    "JsonValue",
    "ParsingError",
    "canonical_json",
    "checked_json",
    "parse_strict_json",
    "parse_strict_xml",
]

JsonObject = dict[str, JsonValue]
_MAX_BYTES = 1048576
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 10000
_MAX_INTEGER_DIGITS = 128
_INTEGER_BOUND = 10**_MAX_INTEGER_DIGITS
_MAX_XML_DEPTH = 16
_MAX_XML_ELEMENTS = 10000
_HEX = frozenset("0123456789abcdefABCDEF")
_XML_ENCODING = re.compile(r"\bencoding[ \t\r\n]*=[ \t\r\n]*(['\"])([^'\"]*)\1", re.ASCII)


class ParsingError(ValueError):
    """Expose a fixed diagnostic without source content."""

    def __init__(self) -> None:
        super().__init__("Invalid structured data.")


def _check_bytes(data: bytes, max_bytes: int = _MAX_BYTES) -> None:
    if type(max_bytes) is not int or not 0 < max_bytes <= _MAX_BYTES:
        raise ParsingError()
    if type(data) is not bytes or len(data) > max_bytes:
        raise ParsingError()


class _JSONScanner:
    """Count grammar nodes and depth before the decoder allocates a tree."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.position = 0
        self.nodes = 0

    def scan(self) -> None:
        self._value(0)
        self._space()
        if self.position != len(self.text):
            raise ParsingError()

    def _space(self) -> None:
        while self.position < len(self.text) and self.text[self.position] in " \t\r\n":
            self.position += 1

    def _node(self) -> None:
        self.nodes += 1
        if self.nodes > _MAX_JSON_NODES:
            raise ParsingError()

    def _take(self, char: str) -> bool:
        if self.position < len(self.text) and self.text[self.position] == char:
            self.position += 1
            return True
        return False

    def _required(self, char: str) -> None:
        if not self._take(char):
            raise ParsingError()

    def _value(self, depth: int) -> None:
        self._node()
        self._space()
        if self.position >= len(self.text):
            raise ParsingError()
        char = self.text[self.position]
        if char in "[{":
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                raise ParsingError()
            self.position += 1
            self._space()
            if char == "[":
                if self._take("]"):
                    return
                while True:
                    self._value(depth)
                    self._space()
                    if self._take("]"):
                        return
                    self._required(",")
            else:
                if self._take("}"):
                    return
                while True:
                    self._space()
                    self._node()
                    self._string()
                    self._space()
                    self._required(":")
                    self._value(depth)
                    self._space()
                    if self._take("}"):
                        return
                    self._required(",")
        elif char == '"':
            self._string()
        elif char == "-" or "0" <= char <= "9":
            self._number()
        else:
            for literal in ("true", "false", "null"):
                if self.text.startswith(literal, self.position):
                    self.position += len(literal)
                    return
            raise ParsingError()

    def _hex_quad(self) -> int:
        end = self.position + 4
        token = self.text[self.position : end]
        if len(token) != 4 or any(char not in _HEX for char in token):
            raise ParsingError()
        self.position = end
        return int(token, 16)

    def _string(self) -> None:
        self._required('"')
        while self.position < len(self.text):
            char = self.text[self.position]
            self.position += 1
            if char == '"':
                return
            if ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF:
                raise ParsingError()
            if char != "\\":
                continue
            if self.position >= len(self.text):
                raise ParsingError()
            escaped = self.text[self.position]
            self.position += 1
            if escaped in '\\"/bfnrt':
                continue
            if escaped != "u":
                raise ParsingError()
            code = self._hex_quad()
            if 0xDC00 <= code <= 0xDFFF:
                raise ParsingError()
            if 0xD800 <= code <= 0xDBFF:
                self._required("\\")
                self._required("u")
                if not 0xDC00 <= self._hex_quad() <= 0xDFFF:
                    raise ParsingError()
        raise ParsingError()

    def _digits(self) -> None:
        start = self.position
        while self.position < len(self.text) and "0" <= self.text[self.position] <= "9":
            self.position += 1
        if self.position == start:
            raise ParsingError()

    def _number(self) -> None:
        self._take("-")
        start = self.position
        if not self._take("0"):
            self._digits()
        integer_digits = self.position - start
        floating = False
        if self._take("."):
            floating = True
            self._digits()
        if self.position < len(self.text) and self.text[self.position] in "eE":
            floating = True
            self.position += 1
            if self.position < len(self.text) and self.text[self.position] in "+-":
                self.position += 1
            self._digits()
        if not floating and integer_digits > _MAX_INTEGER_DIGITS:
            raise ParsingError()


def _integer(token: str) -> int:
    if len(token.removeprefix("-")) > _MAX_INTEGER_DIGITS:
        raise ParsingError()
    return int(token)


def _finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise ParsingError()
    # An isolated constructor context contains invalid-exponent flags.
    context = Context(traps=[InvalidOperation])
    if Decimal(token, context=context) != Decimal(str(value), context=context):
        raise ParsingError()
    return value


def _constant(_token: str) -> JsonValue:
    raise ParsingError()


def _object(pairs: list[tuple[str, JsonValue]]) -> JsonObject:
    value: JsonObject = {}
    for key, item in pairs:
        if key in value:
            raise ParsingError()
        value[key] = item
    return value


def parse_strict_json(data: bytes, *, max_bytes: int = _MAX_BYTES) -> JsonValue:
    """Parse UTF-8 JSON without a BOM, preserving exact supported native scalars."""
    try:
        _check_bytes(data, max_bytes)
        text = data.decode("utf-8", errors="strict")
        if text.startswith("\ufeff"):
            raise ParsingError()
        _JSONScanner(text).scan()
        value = json.loads(
            text, parse_int=_integer, parse_float=_finite_float, parse_constant=_constant, object_pairs_hook=_object
        )
        return checked_json(value)
    except (UnicodeError, ValueError, OverflowError, RecursionError, DecimalException):
        raise ParsingError() from None


def _string_size(value: str, *, json_string: bool) -> int:
    if len(value) > _MAX_BYTES:
        raise ParsingError()
    size = 2 if json_string else 0
    for char in value:
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            raise ParsingError()
        if json_string and char in '\\"':
            size += 2
        elif json_string and code < 32:
            size += 2 if code in {8, 9, 10, 12, 13} else 6
        elif code <= 0x7F:
            size += 1
        elif code <= 0x7FF:
            size += 2
        elif code <= 0xFFFF:
            size += 3
        else:
            size += 4
        if size > _MAX_BYTES:
            raise ParsingError()
    return size


class _JSONBudget:
    def __init__(self) -> None:
        self.nodes = 0
        self.size = 0
        self.active: set[int] = set()

    def add(self, size: int) -> None:
        self.size += size
        if self.size > _MAX_BYTES:
            raise ParsingError()

    def node(self) -> None:
        self.nodes += 1
        if self.nodes > _MAX_JSON_NODES:
            raise ParsingError()

    def clone(self, value: object, depth: int) -> JsonValue:
        self.node()
        if value is None:
            self.add(4)
            return None
        if type(value) is bool:
            self.add(4 if value else 5)
            return value
        if type(value) is int:
            if not -_INTEGER_BOUND < value < _INTEGER_BOUND:
                raise ParsingError()
            self.add(len(str(value)))
            return value
        if type(value) is float:
            if not math.isfinite(value):
                raise ParsingError()
            self.add(len(str(value)))
            return value
        if type(value) is str:
            self.add(_string_size(value, json_string=True))
            return value
        if type(value) not in {dict, list}:
            raise ParsingError()
        depth += 1
        if depth > _MAX_JSON_DEPTH or id(value) in self.active:
            raise ParsingError()
        self.active.add(id(value))
        self.add(2)
        try:
            if type(value) is list:
                result_list: list[JsonValue] = []
                for index, item in enumerate(cast(list[object], value)):
                    if index:
                        self.add(1)
                    result_list.append(self.clone(item, depth))
                return result_list
            result_dict: JsonObject = {}
            for index, (key, item) in enumerate(cast(dict[object, object], value).items()):
                self.node()
                if type(key) is not str:
                    raise ParsingError()
                self.add(_string_size(key, json_string=True) + 1 + bool(index))
                result_dict[key] = self.clone(item, depth)
            return result_dict
        finally:
            self.active.remove(id(value))


def checked_json(value: object) -> JsonValue:
    """Detach strict native JSON within the shared depth, node and encoded-byte bounds."""
    try:
        return _JSONBudget().clone(value, 0)
    except (ValueError, OverflowError, RecursionError, RuntimeError):
        raise ParsingError() from None


def canonical_json(value: JsonValue) -> bytes:
    """Serialize the bounded logical value as sorted compact UTF-8 JSON."""
    checked = checked_json(value)
    try:
        return json.dumps(checked, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
            "utf-8"
        )
    except (ValueError, UnicodeError, OverflowError, RecursionError):
        raise ParsingError() from None


class _XMLPreflight(ContentHandler):
    """Count expanded names without allocating namespace-expanded attributes."""

    def __init__(self) -> None:
        super().__init__()
        self.scopes: list[dict[str, int]] = []
        self.elements = 0
        self.text_bytes = 0

    def _add(self, size: int) -> None:
        self.text_bytes += size
        if self.text_bytes > _MAX_BYTES:
            raise ParsingError()

    def _uri_size(self, prefix: str) -> int:
        for scope in reversed(self.scopes):
            if prefix in scope:
                return scope[prefix]
        if prefix == "xml":
            return len("http://www.w3.org/XML/1998/namespace")
        if prefix == "":
            return 0
        raise ParsingError()

    def _name_size(self, name: str, *, attribute: bool) -> int:
        prefix, separator, local = name.partition(":")
        if not separator:
            local = prefix
            if attribute:
                return _string_size(local, json_string=False)
            prefix = ""
        elif not prefix or not local or ":" in local:
            raise ParsingError()
        uri_size = self._uri_size(prefix)
        return _string_size(local, json_string=False) + (uri_size + 2 if uri_size else 0)

    def startElement(self, name: str, attrs: AttributesImpl) -> None:
        self.elements += 1
        if self.elements > _MAX_XML_ELEMENTS or len(self.scopes) >= _MAX_XML_DEPTH:
            raise ParsingError()
        scope: dict[str, int] = {}
        for key, value in attrs.items():
            if key == "xmlns":
                scope[""] = _string_size(value, json_string=False)
            elif key.startswith("xmlns:"):
                scope[key[6:]] = _string_size(value, json_string=False)
        self.scopes.append(scope)
        self._add(self._name_size(name, attribute=False))
        for key, value in attrs.items():
            if key != "xmlns" and not key.startswith("xmlns:"):
                self._add(self._name_size(key, attribute=True))
                self._add(_string_size(value, json_string=False))

    def endElement(self, name: str) -> None:
        self.scopes.pop()

    def characters(self, content: str) -> None:
        self._add(_string_size(content, json_string=False))


class _BoundedXMLTarget:
    """Reject excess tree content before TreeBuilder retains each event."""

    def __init__(self) -> None:
        self.tree = ET.TreeBuilder()
        self.depth = 0
        self.elements = 0
        self.text_bytes = 0

    def _text(self, text: str) -> None:
        self.text_bytes += _string_size(text, json_string=False)
        if self.text_bytes > _MAX_BYTES:
            raise ParsingError()

    def start(self, tag: str, attributes: dict[str, str]) -> ET.Element:
        self.depth += 1
        self.elements += 1
        if self.depth > _MAX_XML_DEPTH or self.elements > _MAX_XML_ELEMENTS:
            raise ParsingError()
        self._text(tag)
        for key, value in attributes.items():
            self._text(key)
            self._text(value)
        return self.tree.start(tag, attributes)

    def end(self, tag: str) -> ET.Element:
        result = self.tree.end(tag)
        self.depth -= 1
        return result

    def data(self, data: str) -> None:
        self._text(data)
        self.tree.data(data)

    def close(self) -> ET.Element:
        if self.depth != 0 or not self.elements:
            raise ParsingError()
        return self.tree.close()


def _validate_xml_utf8(data: bytes) -> None:
    _check_bytes(data)
    text = data.decode("utf-8", errors="strict")
    if "\x00" in text:
        raise ParsingError()
    offset = int(text.startswith("\ufeff"))
    if text.startswith("<?xml", offset) and len(text) > offset + 5 and text[offset + 5] in " \t\r\n":
        end = text.find("?>", offset)
        if end < 0:
            raise ParsingError()
        encoding = _XML_ENCODING.search(text, offset, end)
        if encoding is not None and encoding.group(2).lower() != "utf-8":
            raise ParsingError()


def parse_strict_xml(data: bytes) -> ET.Element:
    """Parse bounded UTF-8 XML, loading its optional dependency only on this path."""
    try:
        _validate_xml_utf8(data)
    except (UnicodeError, ValueError):
        raise ParsingError() from None
    from defusedxml.common import DefusedXmlException
    from defusedxml.ElementTree import DefusedXMLParser
    from defusedxml.expatreader import DefusedExpatParser

    try:
        preflight = DefusedExpatParser(namespaceHandling=0, forbid_dtd=True, forbid_entities=True, forbid_external=True)
        preflight.setContentHandler(_XMLPreflight())
        preflight.feed(data)
        preflight.close()
        parser = DefusedXMLParser(
            target=_BoundedXMLTarget(), forbid_dtd=True, forbid_entities=True, forbid_external=True
        )
        parser.feed(data)
        root = parser.close()
        if not isinstance(root, ET.Element):
            raise ParsingError()
        return root
    except (DefusedXmlException, SAXException, ET.ParseError, UnicodeError, ValueError, LookupError):
        raise ParsingError() from None
