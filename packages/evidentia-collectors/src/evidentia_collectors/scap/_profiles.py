"""Shared finite source rules and source-correspondent assessment projection."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast

from evidentia_core.models.common import deterministic_finding_id

from ._contracts import AssessmentProjection, NativeValueRef, SourceBinding, XmlElement, _xml_name
from ._json import canonical_bytes, canonical_size
from ._limits import (
    ASSESSMENT_LIMIT,
    NODE_LIMIT,
    OUTCOME_LIMIT,
    REMAINDER_LIMIT,
    TIME_LIMIT,
    UNIT_LIMIT,
    VALUE_LIMIT,
    Budget,
    ScapFailure,
    text_value,
)
from ._native import XML_NAMESPACE, NativeView
from ._time import normalize_source_time

XCCDF = "http://checklists.nist.gov/xccdf/1.2"
OVAL_RESULTS = "http://oval.mitre.org/XMLSchema/oval-results-5"
OVAL_COMMON = "http://oval.mitre.org/XMLSchema/oval-common-5"
OVAL_DEFINITIONS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
OVAL_CHARACTERISTICS = "http://oval.mitre.org/XMLSchema/oval-system-characteristics-5"
SIGNATURE = "http://www.w3.org/2000/09/xmldsig#"
SCHEMA_INSTANCE = "http://www.w3.org/2001/XMLSchema-instance"
XCCDF_OUTCOMES = (
    "pass",
    "fail",
    "error",
    "unknown",
    "notapplicable",
    "informational",
    "fixed",
    "notchecked",
    "notselected",
)
OVAL_OUTCOMES = ("true", "false", "unknown", "error", "not evaluated", "not applicable")
OVAL_LEVELS = (
    "oval_definition",
    "oval_criteria",
    "oval_criterion",
    "oval_extend_definition",
    "oval_test",
    "oval_tested_item",
)
TOP_LEVELS = ("xccdf_rule_result", "oval_definition", "oval_test")


def invalid_source() -> ScapFailure:
    return ScapFailure("source_contract_invalid")


def collapse(value: str) -> str:
    """Apply only the XML Schema whitespace facet to a separate semantic view."""
    return re.sub(r"[ \t\r\n]+", " ", value).strip(" ")


def source_boolean(value: str) -> bool:
    lexical = collapse(value)
    if lexical not in ("true", "false", "1", "0"):
        raise invalid_source()
    return lexical in ("true", "1")


def source_integer(value: str, *, nonnegative: bool = False) -> str:
    """Return a bounded canonical integer key without allocating a large integer."""
    lexical = collapse(value)
    if re.fullmatch(r"[+-]?[0-9]+", lexical) is None:
        raise invalid_source()
    digits = lexical.lstrip("+-").lstrip("0") or "0"
    negative = lexical.startswith("-") and digits != "0"
    if nonnegative and negative:
        raise invalid_source()
    return ("-" if negative else "") + digits


def source_decimal(value: str, *, nonnegative: bool = False) -> str:
    """Return an exact lexical decimal key without float or unbounded conversion."""
    lexical = collapse(value)
    if re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)", lexical) is None:
        raise invalid_source()
    whole, _, fraction = lexical.lstrip("+-").partition(".")
    whole = whole.lstrip("0") or "0"
    fraction = fraction.rstrip("0")
    negative = lexical.startswith("-") and (whole != "0" or bool(fraction))
    if nonnegative and negative:
        raise invalid_source()
    return ("-" if negative else "") + whole + ("." + fraction if fraction else "")


def source_type(value: str, kind: str, budget: Budget | None = None) -> str:
    """Validate a declared scalar while leaving its native slot unchanged."""
    if kind == "string":
        return value
    if kind == "uri":
        if budget is None:
            raise ScapFailure("invalid_internal_result")
        return source_uri(value, budget)
    if kind == "boolean":
        return "true" if source_boolean(value) else "false"
    if kind in ("integer", "nonnegative"):
        return source_integer(value, nonnegative=kind == "nonnegative")
    if kind in ("decimal", "weight"):
        return source_decimal(value, nonnegative=kind == "weight")
    if kind == "ncname":
        try:
            return _xml_name(collapse(value), maximum=VALUE_LIMIT)
        except ScapFailure:
            raise invalid_source() from None
    if kind.startswith("enum:"):
        if value not in kind[5:].split("|"):
            raise invalid_source()
        return value
    raise ScapFailure("invalid_internal_result")


_URI_UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()")
_URI_HEX = frozenset(b"0123456789abcdefABCDEF")
_URI_ESCAPED_ASCII = frozenset(b' <>"{}|\\^' + bytes([96]))
_URI_RESERVED = b";/?:@&=+$,"


def _uri_tokens(value: bytes, start: int, end: int, extra: bytes, budget: Budget) -> None:
    allowed = _URI_UNRESERVED | frozenset(extra)
    cursor = start
    while cursor < end:
        if cursor % 4096 < 3:
            budget.check()
        octet = value[cursor]
        if octet == 37:
            if cursor + 2 >= end or value[cursor + 1] not in _URI_HEX or value[cursor + 2] not in _URI_HEX:
                raise invalid_source()
            cursor += 3
        elif octet in allowed:
            cursor += 1
        else:
            raise invalid_source()


def _uri_ipv6(address: bytes) -> None:
    if not 2 <= len(address) <= 45 or address.count(b"::") > 1:
        raise invalid_source()
    left, compressed, right = address.partition(b"::")
    fields = ([] if not left else left.split(b":")) + ([] if not right else right.split(b":"))
    if any(not field for field in fields):
        raise invalid_source()
    count = 0
    for position, field in enumerate(fields):
        if b"." in field:
            octets = field.split(b".")
            if position != len(fields) - 1 or not address.endswith(field) or len(octets) != 4:
                raise invalid_source()
            if any(not 1 <= len(octet) <= 3 or not octet.isdigit() or int(octet) > 255 for octet in octets):
                raise invalid_source()
            count += 2
        elif 1 <= len(field) <= 4 and all(octet in _URI_HEX for octet in field):
            count += 1
        else:
            raise invalid_source()
    if (compressed and count >= 8) or (not compressed and count != 8):
        raise invalid_source()


def _uri_authority(value: bytes, budget: Budget) -> None:
    if b"[" not in value and b"]" not in value:
        _uri_tokens(value, 0, len(value), b"$,;:@&=+", budget)
        return
    if value.count(b"[") != 1 or value.count(b"]") != 1:
        raise invalid_source()
    opening, closing = value.index(b"["), value.index(b"]")
    if opening >= closing:
        raise invalid_source()
    prefix, suffix = value[:opening], value[closing + 1 :]
    if prefix:
        if not prefix.endswith(b"@"):
            raise invalid_source()
        _uri_tokens(prefix, 0, len(prefix) - 1, b";:&=+$,", budget)
    if suffix and (not suffix.startswith(b":") or any(not 48 <= octet <= 57 for octet in suffix[1:])):
        raise invalid_source()
    _uri_ipv6(value[opening + 1 : closing])


def source_uri(value: str, budget: Budget) -> str:
    """Apply the finite legacy URI-reference policy to a temporary semantic view."""
    budget.check()
    try:
        text_value(value, 0, VALUE_LIMIT)
    except ScapFailure:
        raise ScapFailure("source_limit_exceeded") from None
    semantic = collapse(value)
    source = semantic.encode("utf-8")
    escaped = bytearray()
    try:
        for offset, octet in enumerate(source):
            if offset % 4096 == 0:
                budget.check()
            if octet < 32 or octet >= 127 or octet in _URI_ESCAPED_ASCII:
                escaped.extend(f"%{octet:02X}".encode("ascii"))
            else:
                escaped.append(octet)
        encoded = bytes(escaped)
    finally:
        escaped.clear()
    budget.check()
    body, fragment_mark, fragment = encoded.partition(b"#")
    if fragment_mark:
        _uri_tokens(fragment, 0, len(fragment), _URI_RESERVED, budget)
    absolute = False
    colon = body.find(b":")
    slash, query = body.find(b"/"), body.find(b"?")
    boundary = min(position for position in (slash, query, len(body)) if position >= 0)
    if 0 <= colon < boundary:
        scheme = body[:colon]
        if not scheme or not (65 <= scheme[0] <= 90 or 97 <= scheme[0] <= 122):
            raise invalid_source()
        if any(octet not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-." for octet in scheme):
            raise invalid_source()
        body = body[colon + 1 :]
        if not body:
            raise invalid_source()
        absolute = True
        if not body.startswith(b"/"):
            _uri_tokens(body, 0, len(body), _URI_RESERVED, budget)
            budget.check()
            return semantic
    path, query_mark, query_value = body.partition(b"?")
    if query_mark:
        _uri_tokens(query_value, 0, len(query_value), _URI_RESERVED, budget)
    if path.startswith(b"//"):
        authority, slash_mark, remaining = path[2:].partition(b"/")
        _uri_authority(authority, budget)
        path = slash_mark + remaining
    elif path and not path.startswith(b"/"):
        if absolute:
            raise invalid_source()
        first = path.find(b"/")
        _uri_tokens(path, 0, len(path) if first < 0 else first, b";@&=+$,", budget)
    _uri_tokens(path, 0, len(path), b"/:@&=+$,;", budget)
    budget.check()
    return semantic


@dataclass(frozen=True, slots=True)
class ChildRule:
    namespace: str
    names: tuple[str, ...]
    minimum: int = 0
    maximum: int = NODE_LIMIT
    foreign: bool = False

    def matches(self, node: XmlElement) -> bool:
        if self.foreign:
            return node.name.namespace_uri not in ("", self.namespace)
        return node.name.namespace_uri == self.namespace and node.name.local_name in self.names


class ProfileContext:
    """Accumulate only validated observations and count the complete input scope."""

    def __init__(self, view: NativeView, source: SourceBinding, assessment_index: int, units: list[int]) -> None:
        self.view = view
        self.source = source
        self.assessment_index = assessment_index
        if not units:
            raise invalid_source()
        if len(units) > UNIT_LIMIT:
            raise ScapFailure("source_limit_exceeded")
        if type(assessment_index) is not int or not 0 <= assessment_index < len(units):
            raise ScapFailure("assessment_not_found")
        self.units = units
        self.selected = units[assessment_index]
        self.interpreted: set[int] = set()
        self.outcomes: list[dict[str, object]] = []
        self.times: list[dict[str, object]] = []
        self.visible_outcomes = 0
        self.visible_times = 0
        self.directives: dict[str, object] | None = None
        self.export_detail = "not_applicable"
        self.flags: list[dict[str, object]] = []
        self.statuses: list[dict[str, object]] = []
        self.core_status: list[dict[str, object]] = []

    def mark(self, index: int) -> XmlElement:
        self.view.budget.check()
        self.interpreted.add(index)
        return self.view.element(index)

    def sequence(self, index: int, rules: Sequence[ChildRule]) -> list[int]:
        node = self.mark(index)
        if node.text is not None and any(ch not in " \t\r\n" for ch in node.text):
            raise invalid_source()
        children = self.view.child_elements(index)
        position = 0
        for rule in rules:
            count = 0
            while position < len(children) and rule.matches(self.view.element(children[position])):
                count += 1
                position += 1
                if count > rule.maximum:
                    raise invalid_source()
            if count < rule.minimum:
                raise invalid_source()
        if position != len(children):
            raise invalid_source()
        for child in node.children:
            tail = self.view.document.nodes[child].tail
            if tail is not None and any(ch not in " \t\r\n" for ch in tail):
                raise invalid_source()
        return children

    def attributes(
        self,
        index: int,
        required: dict[str, str],
        optional: dict[str, str] | None = None,
        *,
        xml: tuple[str, ...] = (),
        foreign: bool = False,
    ) -> dict[str, str]:
        node = self.mark(index)
        optional = {} if optional is None else optional
        present: dict[str, str] = {}
        for attribute in node.attributes:
            name = attribute.name
            if name.namespace_uri:
                if name.namespace_uri == SCHEMA_INSTANCE:
                    if name.local_name in ("schemaLocation", "noNamespaceSchemaLocation"):
                        continue
                    raise invalid_source()
                if name.namespace_uri == XML_NAMESPACE and name.local_name in xml:
                    if name.local_name == "base":
                        source_uri(attribute.value, self.view.budget)
                    continue
                if foreign and name.namespace_uri != node.name.namespace_uri:
                    continue
                raise invalid_source()
            kind = required.get(name.local_name, optional.get(name.local_name))
            if kind is None:
                raise invalid_source()
            present[name.local_name] = source_type(attribute.value, kind, self.view.budget)
        if not required.keys() <= present.keys():
            raise invalid_source()
        return present

    def simple(self, index: int, kind: str = "string") -> str:
        self.mark(index)
        return source_type(self.view.simple_content(index), kind, self.view.budget)

    def reference(self, index: int, attribute: str | None = None) -> NativeValueRef:
        if attribute is None:
            return NativeValueRef(node_index=index, slot="element_simple_content", attribute_index=None)
        ref = self.view.attribute_ref(index, attribute)
        if ref is None:
            raise invalid_source()
        return ref

    def outcome(self, unit: int, index: int, level: str, reference: NativeValueRef) -> None:
        self.visible_outcomes += 1
        if self.visible_outcomes > OUTCOME_LIMIT:
            raise ScapFailure("source_limit_exceeded")
        value = self.view.resolve(reference)
        vocabulary = XCCDF_OUTCOMES if level == "xccdf_rule_result" else OVAL_OUTCOMES
        if value not in vocabulary:
            raise invalid_source()
        if unit == self.selected:
            self.outcomes.append(
                {
                    "unit_node_index": unit,
                    "node_index": index,
                    "level": level,
                    "value_ref": reference.model_dump(),
                    "native_result": value,
                }
            )

    def time(
        self, index: int, attribute: str | None, scope_index: int, scope: str, role: str, *, retain: bool = True
    ) -> None:
        self.visible_times += retain
        if self.visible_times > TIME_LIMIT:
            raise ScapFailure("source_limit_exceeded")
        reference = self.reference(index, attribute)
        normalized = normalize_source_time(self.view.resolve(reference), self.view.budget)
        if retain:
            self.times.append(
                {
                    "scope_node_index": scope_index,
                    "scope": scope,
                    "role": role,
                    "value_ref": reference.model_dump(),
                    "normalization": normalized.model_dump(),
                }
            )

    def finish(self) -> AssessmentProjection:
        self.view.budget.check()
        is_xccdf = self.source.profile == "xccdf-1.2-results"
        kind = "xccdf_test_result" if is_xccdf else "oval_system"
        units = [
            {"assessment_index": offset, "unit_kind": kind, "node_index": index}
            for offset, index in enumerate(self.units)
        ]
        self.outcomes.sort(key=lambda item: cast(int, item["node_index"]))
        self.times.sort(
            key=lambda item: (
                cast(dict[str, int], item["value_ref"])["node_index"],
                cast(dict[str, int], item["value_ref"])["attribute_index"] or 0,
            )
        )
        counts = Counter((item["level"], item["native_result"]) for item in self.outcomes)
        levels = ("xccdf_rule_result",) if is_xccdf else OVAL_LEVELS
        outcomes = XCCDF_OUTCOMES if is_xccdf else OVAL_OUTCOMES
        top = [item for item in self.outcomes if item["level"] in TOP_LEVELS]
        countable = sum(item["native_result"] not in ("notchecked", "notselected", "not evaluated") for item in top)
        roots: list[int] = []
        signatures: list[int] = []
        uninterpreted_count = 0
        skip_until = -1
        for index, node in enumerate(self.view.document.nodes):
            if index % 256 == 0:
                self.view.budget.check()
            if (
                type(node) is XmlElement
                and node.name.namespace_uri == SIGNATURE
                and node.name.local_name == "Signature"
            ):
                signatures.append(index)
            if index >= skip_until and index not in self.interpreted:
                roots.append(index)
                skip_until = self.view.subtree_ends[index]
                uninterpreted_count += skip_until - index
        frame = {
            "schema_version": "scap-finding-identity-v1",
            "source_sha256": self.source.sha256,
            "source_profile": self.source.profile,
            "assessment_index": self.assessment_index,
            "unit_node_index": self.selected,
            "mapping_rule_id": "scap-assessment-summary-v1",
        }
        digest = hashlib.sha256(canonical_bytes(frame, REMAINDER_LIMIT, self.view.budget)).hexdigest()
        finding = {
            "node_index": self.selected,
            "mapping_rule_id": "scap-assessment-summary-v1",
            "source_key_sha256": digest,
            "finding_id": deterministic_finding_id("scap-xccdf" if is_xccdf else "scap-oval", digest),
        }
        coverage = {
            "scope": "selected_assessment_native_projection",
            "selected_node_index": self.selected,
            "visible_unit_count": len(units),
            "selected_unit_count": 1,
            "unselected_unit_count": len(units) - 1,
            "visible_outcome_count": self.visible_outcomes,
            "selected_outcome_count": len(self.outcomes),
            "top_level_outcome_count": len(top),
            "countable_top_level_outcome_count": countable,
            "outcome_counts": [
                {"level": level, "native_result": value, "count": counts[(level, value)]}
                for level in levels
                for value in outcomes
            ],
            "native_export_detail": self.export_detail,
            "oval_directives": self.directives,
            "collection_flags": self.flags,
            "uninterpreted_node_count": uninterpreted_count,
            "signature_node_indices": signatures,
            "source_population_complete": "not_established",
            "schema_validation": "bounded_core_profile_rules",
            "complete_schema_validation": "not_performed",
            "platform_validation": "not_performed",
            "signature_verification": "not_performed",
            "producer_interoperability": "not_established",
            "cadence_evidence": "countable" if countable else "not_evaluated" if top else "empty",
            "status_observations": self.statuses,
            "core_status_defaults": self.core_status,
        }
        result = {
            "selection": units[self.assessment_index],
            "units": units,
            "outcomes": self.outcomes,
            "times": self.times,
            "coverage": coverage,
            "uninterpreted_roots": roots,
            "finding_refs": [finding],
        }
        canonical_size(result, ASSESSMENT_LIMIT, self.view.budget)
        projection = AssessmentProjection.model_validate(result)
        self.view.budget.check()
        return projection
