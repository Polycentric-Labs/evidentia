"""Bounded UTF-8 XML preflight and one defused parser for the complete source."""

from __future__ import annotations

import codecs
import importlib
import importlib.util
from collections.abc import Callable
from typing import Protocol, cast
from xml.etree.ElementTree import ParseError

from ._limits import (
    ATTRIBUTE_LIMIT,
    CALLBACK_LIMIT,
    DEPTH_LIMIT,
    FEED_LIMIT,
    NAMESPACE_LIMIT,
    NODE_LIMIT,
    RAW_LIMIT,
    REFERENCE_LIMIT,
    SOURCE_TEXT_LIMIT,
    TOKEN_COUNT_LIMIT,
    TOKEN_LIMIT,
    TOTAL_ATTRIBUTE_LIMIT,
    TOTAL_NAMESPACE_LIMIT,
    VALUE_LIMIT,
    Budget,
    ScapFailure,
    text_value,
)
from ._native import NativeView, validate_native

_SPACE = b" \t\r\n"
_PREDEFINED = {b"&amp;", b"&lt;", b"&gt;", b"&apos;", b"&quot;"}


def _malformed() -> ScapFailure:
    return ScapFailure("malformed_xml")


def _reference(raw: bytes, index: int, end: int) -> int:
    stop = raw.find(b";", index + 1, min(end, index + REFERENCE_LIMIT))
    if stop == -1:
        if end - index >= REFERENCE_LIMIT:
            raise ScapFailure("source_limit_exceeded")
        raise _malformed()
    token = raw[index : stop + 1]
    if token in _PREDEFINED:
        return stop + 1
    if not token.startswith(b"&#"):
        raise ScapFailure("unsafe_xml")
    hexadecimal = token.startswith(b"&#x")
    digits = token[3:-1] if hexadecimal else token[2:-1]
    if not digits:
        raise _malformed()
    value = 0
    for digit in digits:
        if 48 <= digit <= 57:
            part = digit - 48
        elif hexadecimal and 65 <= digit <= 70:
            part = digit - 55
        elif hexadecimal and 97 <= digit <= 102:
            part = digit - 87
        else:
            raise _malformed()
        value = value * (16 if hexadecimal else 10) + part
        if value > 0x10FFFF:
            raise _malformed()
    if not (
        value in (9, 10, 13) or 0x20 <= value <= 0xD7FF or 0xE000 <= value <= 0xFFFD or 0x10000 <= value <= 0x10FFFF
    ):
        raise _malformed()
    return stop + 1


def lexical_preflight(raw: bytes, budget: Budget) -> None:
    """Finish whole-source token and encoding admission before parser input."""
    if type(raw) is not bytes:
        raise ScapFailure("invalid_request")
    if not raw:
        raise _malformed()
    if len(raw) > RAW_LIMIT:
        raise ScapFailure("source_limit_exceeded")
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    try:
        for offset in range(0, len(raw), FEED_LIMIT):
            budget.check()
            text = decoder.decode(raw[offset : offset + FEED_LIMIT], final=False)
            if "\x00" in text:
                raise ScapFailure("unsafe_xml")
        decoder.decode(b"", final=True)
    except UnicodeError:
        raise ScapFailure("unsafe_xml") from None
    index = 3 if raw.startswith(b"\xef\xbb\xbf") else 0
    tokens = 0
    nodes = 0
    total_attributes = 0
    total_namespaces = 0

    def token() -> None:
        nonlocal tokens
        tokens += 1
        if tokens > TOKEN_COUNT_LIMIT:
            raise ScapFailure("source_limit_exceeded")
        if tokens % 128 == 1:
            budget.check()

    def node() -> None:
        nonlocal nodes
        nodes += 1
        if nodes > NODE_LIMIT:
            raise ScapFailure("source_limit_exceeded")

    def terminated(start: int, delimiter: bytes, prefix: int) -> int:
        found = raw.find(delimiter, start + prefix, min(len(raw), start + TOKEN_LIMIT))
        if found == -1:
            if len(raw) - start >= TOKEN_LIMIT:
                raise ScapFailure("source_limit_exceeded")
            raise _malformed()
        return found + len(delimiter)

    def tag(start: int) -> int:
        nonlocal total_attributes, total_namespaces
        cursor = start + 1
        closing = cursor < len(raw) and raw[cursor] == 47
        if closing:
            cursor += 1
        while cursor < len(raw) and raw[cursor] not in _SPACE + b"/>":
            cursor += 1
            if cursor - start >= TOKEN_LIMIT:
                raise ScapFailure("source_limit_exceeded")
        if cursor == start + (2 if closing else 1):
            raise _malformed()
        attributes = 0
        namespaces = 0
        while cursor < len(raw):
            if cursor - start >= TOKEN_LIMIT:
                raise ScapFailure("source_limit_exceeded")
            if raw[cursor] in _SPACE:
                cursor += 1
                continue
            if raw[cursor] == 62:
                return cursor + 1
            if raw[cursor : cursor + 2] == b"/>":
                if cursor + 2 - start > TOKEN_LIMIT:
                    raise ScapFailure("source_limit_exceeded")
                return cursor + 2
            if closing:
                raise _malformed()
            attribute_start = cursor
            while cursor < len(raw) and raw[cursor] not in _SPACE + b"=/>":
                cursor += 1
                if cursor - start >= TOKEN_LIMIT:
                    raise ScapFailure("source_limit_exceeded")
            if cursor == attribute_start:
                raise _malformed()
            attribute_name = raw[attribute_start:cursor]
            namespace = attribute_name == b"xmlns" or attribute_name.startswith(b"xmlns:")
            attributes += not namespace
            namespaces += namespace
            total_attributes += not namespace
            total_namespaces += namespace
            if (
                attributes > ATTRIBUTE_LIMIT
                or namespaces > NAMESPACE_LIMIT
                or total_attributes > TOTAL_ATTRIBUTE_LIMIT
                or total_namespaces > TOTAL_NAMESPACE_LIMIT
            ):
                raise ScapFailure("source_limit_exceeded")
            while cursor < len(raw) and raw[cursor] in _SPACE:
                cursor += 1
                if cursor - start >= TOKEN_LIMIT:
                    raise ScapFailure("source_limit_exceeded")
            if cursor >= len(raw) or raw[cursor] != 61:
                raise _malformed()
            cursor += 1
            while cursor < len(raw) and raw[cursor] in _SPACE:
                cursor += 1
                if cursor - start >= TOKEN_LIMIT:
                    raise ScapFailure("source_limit_exceeded")
            if cursor >= len(raw) or raw[cursor] not in (34, 39):
                raise _malformed()
            quote = raw[cursor]
            cursor += 1
            while cursor < len(raw) and raw[cursor] != quote:
                if cursor - start >= TOKEN_LIMIT:
                    raise ScapFailure("source_limit_exceeded")
                if raw[cursor] == 38:
                    token()
                    cursor = _reference(raw, cursor, len(raw))
                elif raw[cursor] == 60:
                    raise _malformed()
                else:
                    cursor += 1
            if cursor >= len(raw):
                raise _malformed()
            cursor += 1
        raise _malformed()

    while index < len(raw):
        budget.check()
        token()
        if raw[index] == 38:
            index = _reference(raw, index, len(raw))
        elif raw[index] != 60:
            end = index
            while end < len(raw) and raw[end] not in (38, 60):
                end += 1
                if end - index > TOKEN_LIMIT:
                    raise ScapFailure("source_limit_exceeded")
            index = end
        elif raw.startswith(b"<!--", index):
            node()
            index = terminated(index, b"-->", 4)
        elif raw.startswith(b"<![CDATA[", index):
            index = terminated(index, b"]]>", 9)
        elif raw.startswith(b"<?", index):
            end = terminated(index, b"?>", 2)
            target_end = index + 2
            while target_end < end - 2 and raw[target_end] not in _SPACE:
                target_end += 1
            target = raw[index + 2 : target_end]
            if target == b"xml":
                declaration = raw[index:end]
                if b"encoding" in declaration:
                    encoded_start = declaration.find(b"encoding") + 8
                    while encoded_start < len(declaration) and declaration[encoded_start] in _SPACE:
                        encoded_start += 1
                    if encoded_start >= len(declaration) or declaration[encoded_start] != 61:
                        raise _malformed()
                    encoded_start += 1
                    while encoded_start < len(declaration) and declaration[encoded_start] in _SPACE:
                        encoded_start += 1
                    if encoded_start >= len(declaration) or declaration[encoded_start] not in (34, 39):
                        raise _malformed()
                    quote = declaration[encoded_start]
                    encoded_end = declaration.find(bytes([quote]), encoded_start + 1)
                    if encoded_end == -1:
                        raise _malformed()
                    if declaration[encoded_start + 1 : encoded_end].lower() != b"utf-8":
                        raise ScapFailure("unsafe_xml")
            else:
                node()
            index = end
        elif raw.startswith(b"<!", index):
            raise ScapFailure("unsafe_xml")
        else:
            if not raw.startswith(b"</", index):
                node()
            index = tag(index)
    budget.check()


def _clear_entries(entries: list[dict[str, object]]) -> None:
    for entry in entries:
        name = entry.get("name")
        if type(name) is dict:
            name.clear()
        entry.clear()
    entries.clear()


def _clear_record(record: dict[str, object]) -> None:
    for field in ("name", "declaration"):
        value = record.get(field)
        if type(value) is dict:
            value.clear()
    for field in ("attributes", "namespace_declarations"):
        value = record.get(field)
        if type(value) is list:
            _clear_entries(value)
    children = record.get("children")
    if type(children) is list:
        children.clear()
    record.clear()


class _Target:
    """Retain counted source occurrences without an intermediate element tree."""

    def __init__(self, budget: Budget) -> None:
        self.budget = budget
        self.nodes: list[dict[str, object]] = []
        self.document: dict[str, object] = {"declaration": None, "text": None, "children": [], "nodes": self.nodes}
        self.stack: list[int] = []
        self.namespaces: list[dict[str, str]] = []
        self.callbacks = 0
        self.source_bytes = 0
        self.attribute_count = 0
        self.namespace_count = 0
        self.fragments: list[str] = []
        self.fragment_bytes = 0
        self.default_cr = False

    def event(self, *, default: bool = False) -> None:
        self.callbacks += 1
        if self.callbacks > CALLBACK_LIMIT:
            raise ScapFailure("source_limit_exceeded")
        if self.callbacks % 128 == 1:
            self.budget.check()
        if not default:
            self.default_cr = False

    def source(self, value: str, maximum: int = VALUE_LIMIT) -> str:
        try:
            checked = text_value(value, 0, maximum)
        except ScapFailure:
            raise ScapFailure("source_limit_exceeded") from None
        self.source_bytes += len(checked.encode("utf-8"))
        if self.source_bytes > SOURCE_TEXT_LIMIT:
            raise ScapFailure("source_limit_exceeded")
        return checked

    def name(self, value: str) -> dict[str, str]:
        if value.startswith("{"):
            namespace, separator, local = value[1:].rpartition("}")
            if not separator:
                raise _malformed()
        else:
            namespace, local = "", value
        return {"namespace_uri": self.source(namespace, 2048), "local_name": self.source(local, 256)}

    def flush(self) -> None:
        if not self.fragments:
            return
        self.budget.check()
        parent = self.nodes[self.stack[-1]] if self.stack else self.document
        children = cast(list[int], parent["children"])
        holder, slot = (self.nodes[children[-1]], "tail") if children else (parent, "text")
        if holder[slot] is not None:
            raise ScapFailure("invalid_internal_result")
        holder[slot] = "".join(self.fragments)
        self.fragments.clear()
        self.fragment_bytes = 0
        self.budget.check()

    def fragment(self, value: str) -> None:
        if not value:
            return
        size = len(value.encode("utf-8"))
        if self.fragment_bytes + size > VALUE_LIMIT:
            raise ScapFailure("source_limit_exceeded")
        self.source(value)
        self.fragment_bytes += size
        self.fragments.append(value)

    def append(self, node: dict[str, object]) -> int:
        try:
            self.flush()
            if len(self.nodes) >= NODE_LIMIT:
                raise ScapFailure("source_limit_exceeded")
            parent = self.nodes[self.stack[-1]] if self.stack else self.document
            children = cast(list[int], parent["children"])
            index = len(self.nodes)
            children.append(index)
            self.nodes.append(node)
            return index
        except BaseException as primary:
            try:
                _clear_record(node)
            except BaseException:
                _cleanup_note(primary)
            raise

    def start(self, name: str, attributes: dict[str, str]) -> None:
        self.event()
        if len(self.stack) >= DEPTH_LIMIT or len(attributes) > ATTRIBUTE_LIMIT:
            raise ScapFailure("source_limit_exceeded")
        self.attribute_count += len(attributes)
        if self.attribute_count > TOTAL_ATTRIBUTE_LIMIT:
            raise ScapFailure("source_limit_exceeded")
        retained_attributes: list[dict[str, object]] = []
        node: dict[str, object] | None = None
        try:
            for attribute_name, value in attributes.items():
                retained_attributes.append({"name": self.name(attribute_name), "value": self.source(value)})
            node = {
                "kind": "element",
                "name": self.name(name),
                "namespace_declarations": self.namespaces,
                "attributes": retained_attributes,
                "text": None,
                "tail": None,
                "children": [],
            }
            self.namespaces = []
            self.stack.append(self.append(node))
        except BaseException as primary:
            try:
                _clear_entries(retained_attributes)
                if node is not None:
                    _clear_record(node)
            except BaseException:
                _cleanup_note(primary)
            raise

    def end(self, name: str) -> None:
        self.event()
        self.flush()
        if not self.stack:
            raise _malformed()
        self.stack.pop()

    def start_ns(self, prefix: str, uri: str) -> None:
        self.event()
        self.flush()
        self.namespace_count += 1
        if len(self.namespaces) >= NAMESPACE_LIMIT or self.namespace_count > TOTAL_NAMESPACE_LIMIT:
            raise ScapFailure("source_limit_exceeded")
        self.namespaces.append({"prefix": self.source(prefix, 128), "namespace_uri": self.source(uri, 2048)})

    def end_ns(self, prefix: str) -> None:
        self.event()

    def data(self, value: str) -> None:
        self.event()
        self.fragment(value)

    def comment(self, value: str) -> None:
        self.event()
        self.append({"kind": "comment", "data": self.source(value), "tail": None})

    def pi(self, target: str, value: str) -> None:
        self.event()
        self.append(
            {
                "kind": "processing_instruction",
                "target": self.source(target, 256),
                "data": self.source(value),
                "tail": None,
            }
        )

    def declaration(self, version: str, encoding: str | None, standalone: int) -> None:
        self.event()
        if version != "1.0" or (encoding is not None and encoding.lower() != "utf-8"):
            raise ScapFailure("unsafe_xml")
        if self.document["declaration"] is not None or standalone not in (-1, 0, 1):
            raise _malformed()
        declared_standalone = None if standalone == -1 else "yes" if standalone == 1 else "no"
        self.document["declaration"] = {
            "version": self.source(version, 3),
            "encoding": None if encoding is None else self.source(encoding, 64),
            "standalone": None if declared_standalone is None else self.source(declared_standalone, 3),
        }

    def default(self, value: str) -> None:
        self.event(default=True)
        if value and all(character in " \t\r\n" for character in value):
            starts_lf = self.default_cr and value.startswith("\n")
            self.default_cr = value.endswith("\r")
            self.fragment((value[1:] if starts_lf else value).replace("\r\n", "\n").replace("\r", "\n"))
        else:
            self.default_cr = False

    def close(self) -> dict[str, object]:
        self.flush()
        self.budget.check()
        if self.stack or self.namespaces:
            raise _malformed()
        return self.document


class _Expat(Protocol):
    buffer_text: bool
    XmlDeclHandler: Callable[[str, str | None, int], None] | None
    DefaultHandlerExpand: Callable[[str], None] | None


class _Parser(Protocol):
    parser: _Expat

    def feed(self, data: bytes) -> None: ...
    def close(self) -> dict[str, object]: ...


class _ParserFactory(Protocol):
    def __call__(
        self, *, target: _Target, forbid_dtd: bool, forbid_entities: bool, forbid_external: bool
    ) -> _Parser: ...


def _dependency() -> tuple[_ParserFactory, type[Exception]]:
    """Resolve optional support only when an admitted entry point needs XML."""
    try:
        spec = importlib.util.find_spec("defusedxml")
    except Exception:
        raise ScapFailure("internal_dependency_failure") from None
    if spec is None:
        raise ScapFailure("scan_extra_unavailable")
    try:
        element_tree = importlib.import_module("defusedxml.ElementTree")
        common = importlib.import_module("defusedxml.common")
        factory = element_tree.DefusedXMLParser
        forbidden = common.DefusedXmlException
        if not callable(factory) or not isinstance(forbidden, type) or not issubclass(forbidden, Exception):
            raise TypeError
    except Exception:
        raise ScapFailure("internal_dependency_failure") from None
    return cast(_ParserFactory, factory), forbidden


def _cleanup_note(primary: BaseException) -> None:
    try:
        BaseException.add_note(primary, "SCAP parser cleanup did not complete.")
    except BaseException:
        return


def _release(parser: _Parser | None, backend: _Expat | None, target: _Target) -> None:
    """Release parser-owned source data without feeding or closing the parser."""
    try:
        if parser is not None:
            state = vars(parser)
            for field in ("_names", "entity"):
                cache = state.get(field)
                if type(cache) is dict:
                    cache.clear()
            for field in ("parser", "_parser", "target", "_target", "_doctype"):
                state.pop(field, None)
        if backend is not None:
            for field in (
                "StartElementHandler",
                "EndElementHandler",
                "StartNamespaceDeclHandler",
                "EndNamespaceDeclHandler",
                "CharacterDataHandler",
                "CommentHandler",
                "ProcessingInstructionHandler",
                "XmlDeclHandler",
                "DefaultHandlerExpand",
                "StartDoctypeDeclHandler",
                "EntityDeclHandler",
                "UnparsedEntityDeclHandler",
                "ExternalEntityRefHandler",
            ):
                setattr(backend, field, None)
    finally:
        for node in target.nodes:
            _clear_record(node)
        _clear_record(target.document)
        target.nodes.clear()
        target.stack.clear()
        _clear_entries(cast(list[dict[str, object]], target.namespaces))
        target.fragments.clear()
        target.fragment_bytes = 0
        target.default_cr = False


def parse_xml(raw: bytes, budget: Budget) -> NativeView:
    """Parse one complete admitted source through preserved defusing handlers."""
    budget.check()
    lexical_preflight(raw, budget)
    factory, forbidden = _dependency()
    target = _Target(budget)
    parser: _Parser | None = None
    expat: _Expat | None = None
    primary: BaseException | None = None
    try:
        try:
            parser = factory(target=target, forbid_dtd=True, forbid_entities=True, forbid_external=True)
            expat = parser.parser
            expat.buffer_text = False
            expat.XmlDeclHandler = target.declaration
            previous_default = expat.DefaultHandlerExpand

            def default(value: str) -> None:
                target.default(value)
                if previous_default is not None:
                    previous_default(value)

            expat.DefaultHandlerExpand = default
            for offset in range(0, len(raw), FEED_LIMIT):
                budget.check()
                parser.feed(raw[offset : offset + FEED_LIMIT])
            value = parser.close()
            budget.check()
            return validate_native(value, budget)
        except ScapFailure:
            raise
        except forbidden:
            raise ScapFailure("unsafe_xml") from None
        except ParseError:
            raise _malformed() from None
        except Exception:
            raise ScapFailure("internal_dependency_failure") from None
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            _release(parser, expat, target)
        except BaseException as cleanup_error:
            if primary is not None:
                _cleanup_note(primary)
            elif isinstance(cleanup_error, Exception):
                raise ScapFailure("internal_dependency_failure") from None
            else:
                raise
        finally:
            parser = None
            expat = None
            raw = b""
