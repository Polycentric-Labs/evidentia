"""Complete native graph validation and source-local occurrence references."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from pydantic import ValidationError

from ._contracts import NativeDocument, NativeValueRef, XmlComment, XmlElement, XmlPI
from ._json import canonical_size, detached
from ._limits import (
    DEPTH_LIMIT,
    NATIVE_LIMIT,
    SOURCE_TEXT_LIMIT,
    TOTAL_ATTRIBUTE_LIMIT,
    TOTAL_NAMESPACE_LIMIT,
    VALUE_LIMIT,
    Budget,
    ScapFailure,
)

XML_NAMESPACE = "http://www.w3.org/XML/1998/namespace"
XMLNS_NAMESPACE = "http://www.w3.org/2000/xmlns/"


def _invalid() -> ScapFailure:
    return ScapFailure("source_contract_invalid")


def _xml_characters(value: str) -> None:
    for character in value:
        point = ord(character)
        if not (
            point in (9, 10, 13) or 0x20 <= point <= 0xD7FF or 0xE000 <= point <= 0xFFFD or 0x10000 <= point <= 0x10FFFF
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class NativeView:
    """One checked graph with bounded parent and subtree index tables."""

    document: NativeDocument
    parents: tuple[int | None, ...]
    subtree_ends: tuple[int, ...]
    root_index: int
    source_string_bytes: int
    budget: Budget

    def element(self, index: int) -> XmlElement:
        if type(index) is not int or not 0 <= index < len(self.document.nodes):
            raise _invalid()
        node = self.document.nodes[index]
        if type(node) is not XmlElement:
            raise _invalid()
        return node

    def is_element(self, index: int, namespace_uri: str, local_name: str) -> bool:
        if not 0 <= index < len(self.document.nodes):
            raise _invalid()
        node = self.document.nodes[index]
        return (
            type(node) is XmlElement and node.name.namespace_uri == namespace_uri and node.name.local_name == local_name
        )

    def child_elements(self, index: int) -> list[int]:
        result = []
        for offset, child in enumerate(self.element(index).children):
            if offset % 256 == 0:
                self.budget.check()
            if type(self.document.nodes[child]) is XmlElement:
                result.append(child)
        return result

    def children_named(self, index: int, namespace_uri: str, local_name: str) -> list[int]:
        return [child for child in self.child_elements(index) if self.is_element(child, namespace_uri, local_name)]

    def descendants(self, index: int) -> Iterator[int]:
        self.element(index)
        for child in range(index + 1, self.subtree_ends[index]):
            if child % 256 == 0:
                self.budget.check()
            yield child

    def attribute_ref(self, index: int, local_name: str, namespace_uri: str = "") -> NativeValueRef | None:
        for offset, attribute in enumerate(self.element(index).attributes):
            if attribute.name.namespace_uri == namespace_uri and attribute.name.local_name == local_name:
                return NativeValueRef(node_index=index, slot="attribute_value", attribute_index=offset)
        return None

    def attribute(self, index: int, local_name: str, namespace_uri: str = "", *, required: bool = False) -> str | None:
        reference = self.attribute_ref(index, local_name, namespace_uri)
        if reference is None:
            if required:
                raise _invalid()
            return None
        return self.resolve(reference)

    def simple_content(self, index: int) -> str:
        node = self.element(index)
        fragments: list[str] = []
        total = 0

        def retain(text: str | None) -> None:
            nonlocal total
            if text is not None:
                total += len(text.encode("utf-8"))
                if total > VALUE_LIMIT:
                    raise ScapFailure("source_limit_exceeded")
                fragments.append(text)

        retain(node.text)
        for offset, child_index in enumerate(node.children):
            if offset % 256 == 0:
                self.budget.check()
            child = self.document.nodes[child_index]
            if type(child) is XmlElement:
                raise _invalid()
            retain(child.tail)
        self.budget.check()
        result = "".join(fragments)
        self.budget.check()
        return result

    def resolve(self, reference: NativeValueRef) -> str:
        node = self.element(reference.node_index)
        if reference.slot == "attribute_value":
            index = reference.attribute_index
            if index is None or not 0 <= index < len(node.attributes):
                raise _invalid()
            return node.attributes[index].value
        if reference.attribute_index is not None:
            raise _invalid()
        if reference.slot == "element_simple_content":
            return self.simple_content(reference.node_index)
        if reference.slot == "text" and node.text is not None:
            return node.text
        raise _invalid()


def validate_native(value: object, budget: Budget) -> NativeView:
    """Detach and validate every node, namespace scope and source occurrence."""
    budget.check()
    native = detached(value, NATIVE_LIMIT, budget)
    try:
        document = NativeDocument.model_validate(native)
    except (ScapFailure, ValidationError):
        raise _invalid() from None
    nodes = document.nodes
    parents: list[int | None] = [None] * len(nodes)
    ends = [0] * len(nodes)
    source_bytes = 0
    attribute_count = 0
    namespace_count = 0

    def source_string(text: str | None) -> None:
        nonlocal source_bytes
        if text is not None:
            _xml_characters(text)
            source_bytes += len(text.encode("utf-8"))
            if source_bytes > SOURCE_TEXT_LIMIT:
                raise ScapFailure("source_limit_exceeded")

    def document_whitespace(text: str | None) -> None:
        if text is not None and any(character not in " \t\r\n" for character in text):
            raise _invalid()

    source_string(document.text)
    document_whitespace(document.text)
    if document.declaration is not None:
        source_string(document.declaration.version)
        source_string(document.declaration.encoding)
        source_string(document.declaration.standalone)
    namespaces = {"xml": XML_NAMESPACE, "": ""}
    changes: list[list[tuple[str, str | None]]] = []
    stack: list[tuple[int, int, int | None, bool]] = [(index, 1, None, False) for index in reversed(document.children)]
    next_index = 0
    root_index = -1
    while stack:
        index, depth, parent, leaving = stack.pop()
        if leaving:
            ends[index] = next_index
            for prefix, previous in reversed(changes.pop()):
                if previous is None:
                    del namespaces[prefix]
                else:
                    namespaces[prefix] = previous
            continue
        if index != next_index or not 0 <= index < len(nodes):
            raise _invalid()
        if index % 128 == 0:
            budget.check()
        parents[index] = parent
        next_index += 1
        node = nodes[index]
        source_string(node.tail)
        if parent is None:
            document_whitespace(node.tail)
        if type(node) is XmlElement:
            if depth > DEPTH_LIMIT:
                raise ScapFailure("source_limit_exceeded")
            if parent is None:
                if root_index != -1:
                    raise _invalid()
                root_index = index
            local_changes: list[tuple[str, str | None]] = []
            prefixes: set[str] = set()
            namespace_count += len(node.namespace_declarations)
            attribute_count += len(node.attributes)
            if namespace_count > TOTAL_NAMESPACE_LIMIT or attribute_count > TOTAL_ATTRIBUTE_LIMIT:
                raise ScapFailure("source_limit_exceeded")
            for declaration in node.namespace_declarations:
                prefix, uri = declaration.prefix, declaration.namespace_uri
                source_string(prefix)
                source_string(uri)
                if prefix in prefixes or prefix == "xmlns" or uri == XMLNS_NAMESPACE:
                    raise _invalid()
                if (prefix == "xml") != (uri == XML_NAMESPACE) or (prefix and not uri):
                    raise _invalid()
                prefixes.add(prefix)
                local_changes.append((prefix, namespaces.get(prefix)))
                namespaces[prefix] = uri
            changes.append(local_changes)
            source_string(node.name.namespace_uri)
            source_string(node.name.local_name)
            uri = node.name.namespace_uri
            if uri == XMLNS_NAMESPACE or (not uri and namespaces[""] != "") or (uri and uri not in namespaces.values()):
                raise _invalid()
            attribute_names: set[tuple[str, str]] = set()
            for attribute in node.attributes:
                key = (attribute.name.namespace_uri, attribute.name.local_name)
                if key in attribute_names or key == ("", "xmlns") or key[0] == XMLNS_NAMESPACE:
                    raise _invalid()
                if key[0] and not any(prefix and binding == key[0] for prefix, binding in namespaces.items()):
                    raise _invalid()
                attribute_names.add(key)
                source_string(key[0])
                source_string(key[1])
                source_string(attribute.value)
            source_string(node.text)
            stack.append((index, depth, parent, True))
            stack.extend((child, depth + 1, index, False) for child in reversed(node.children))
        elif type(node) is XmlComment:
            source_string(node.data)
            if "--" in node.data or node.data.endswith("-"):
                raise _invalid()
            ends[index] = next_index
        elif type(node) is XmlPI:
            source_string(node.target)
            source_string(node.data)
            if "?>" in node.data:
                raise _invalid()
            ends[index] = next_index
        else:
            raise _invalid()
    if next_index != len(nodes) or root_index == -1:
        raise _invalid()
    canonical_size(native, NATIVE_LIMIT, budget)
    return NativeView(document, tuple(parents), tuple(ends), root_index, source_bytes, budget)
