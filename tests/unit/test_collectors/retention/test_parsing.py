"""Boundary and fidelity tests for the bounded structured-data parser."""

from __future__ import annotations

import builtins
import importlib.util
import json
import math
import xml.etree.ElementTree as ET
from decimal import Decimal, getcontext, localcontext
from pathlib import Path
from unittest.mock import Mock

import pytest
from evidentia_collectors.retention import _parsing as parsing

LIMIT = 1048576


@pytest.mark.parametrize(
    "raw,expected",
    [
        (b"null", None),
        (b"true", True),
        (b"false", False),
        (b"0", 0),
        (b"-7", -7),
        (b"0.1", 0.1),
        (b"1.0", 1.0),
        (b"1e0", 1.0),
        (b'"text"', "text"),
        (b"[]", []),
        (b"{}", {}),
        (b'{"s":"[{}],:\\"\\\\","t":[1,true,null]}', {"s": '[{}],:"\\', "t": [1, True, None]}),
        (b'"\\uD83D\\uDE00"', chr(0x1F600)),
        (b'"\\b\\f\\n\\r\\t\\/"', "\b\f\n\r\t/"),
    ],
)
def test_json_preserves_native_types_and_escaped_structure(raw: bytes, expected: object) -> None:
    value = parsing.parse_strict_json(raw)
    assert value == expected
    assert type(value) is type(expected)


@pytest.mark.parametrize("value", [2**53 + 1, -(2**100), 10**128 - 1, -(10**128 - 1)])
def test_large_supported_integers_remain_exact(value: int) -> None:
    raw = str(value).encode("ascii")
    parsed = parsing.parse_strict_json(raw)
    assert type(parsed) is int and parsed == value
    assert parsing.canonical_json(parsed) == raw


@pytest.mark.parametrize("value", [10**128, -(10**128)])
def test_integer_digit_ceiling_rejects_raw_and_native(value: int) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(str(value).encode("ascii"))
    with pytest.raises(parsing.ParsingError):
        parsing.checked_json(value)
    with pytest.raises(parsing.ParsingError):
        parsing.canonical_json(value)


@pytest.mark.parametrize(
    "raw",
    [b"NaN", b"Infinity", b"-Infinity", b"1e309", b"1e-400", b"1.0000000000000001", b"1e-99999999999999999999999999"],
)
def test_nonfinite_or_lossy_float_tokens_reject(raw: bytes) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(raw)


@pytest.mark.parametrize("raw", [b"0.1", b"-0.0", b"0.0", b"1.7976931348623157e308", b"5e-324"])
def test_finite_float_extremes_preserve_type_and_signed_zero(raw: bytes) -> None:
    value = parsing.parse_strict_json(raw)
    assert type(value) is float
    assert value == float(raw)
    assert math.copysign(1, value) == math.copysign(1, float(raw))
    assert Decimal(raw.decode()) == Decimal(str(value))


def test_decimal_context_is_untouched_for_valid_and_invalid_numbers() -> None:
    with localcontext() as context:
        context.prec = 1
        before = context.copy()
        assert parsing.parse_strict_json(b"0.1") == 0.1
        with pytest.raises(parsing.ParsingError):
            parsing.parse_strict_json(b"1e-99999999999999999999999999")
        assert getcontext().prec == before.prec
        assert getcontext().flags == before.flags
        assert getcontext().traps == before.traps


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":1,"\\u0061":2}', b'{"outer":{"x":1,"x":2}}'])
def test_duplicate_decoded_keys_reject(raw: bytes) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(raw)


@pytest.mark.parametrize(
    "raw", [b'"\\ud800"', b'"\\udc00"', b'"\\ud800\\u0041"', b'{"\\ud800":1}', bytes.fromhex("22eda08022")]
)
def test_json_surrogates_reject(raw: bytes) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b" ",
        b"01",
        b"+1",
        b"1.",
        b".1",
        b"1e",
        b"1e+",
        b"true false",
        b"[1,]",
        b'{"a":1,}',
        b'{"a" 1}',
        b'"\\x20"',
        b'"\\uQQQQ"',
        b'"unterminated',
        b'"raw\nline"',
        b"[[}",
    ],
)
def test_invalid_json_grammar_rejects_with_fixed_message(raw: bytes) -> None:
    with pytest.raises(parsing.ParsingError, match=r"^Invalid structured data\.$") as captured:
        parsing.parse_strict_json(raw)
    assert str(captured.value) == "Invalid structured data."


@pytest.mark.parametrize(
    "raw", [bytes.fromhex("efbbbf") + b"{}", "{}".encode("utf-16"), "{}".encode("utf-32"), b'"\xff"']
)
def test_json_requires_utf8_without_bom(raw: bytes) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(raw)


@pytest.mark.parametrize("limit", [0, -1, True, 1.0, LIMIT + 1])
def test_max_bytes_configuration_is_strict(limit: object) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(b"0", max_bytes=limit)


@pytest.mark.parametrize("raw", ["{}", bytearray(b"{}"), memoryview(b"{}"), None])
def test_json_accepts_only_native_bytes(raw: object) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(raw)


def test_json_byte_limit_precedes_decoder(monkeypatch: pytest.MonkeyPatch) -> None:
    assert parsing.parse_strict_json(b"0" + b" " * (LIMIT - 1)) == 0
    loads = Mock(side_effect=AssertionError("decoder must not run"))
    monkeypatch.setattr(parsing.json, "loads", loads)
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(b"0" + b" " * LIMIT)
    assert loads.call_count == 0


def test_request_limit_boundary() -> None:
    assert parsing.parse_strict_json(b"0" + b" " * 65535, max_bytes=65536) == 0
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(b"0" + b" " * 65536, max_bytes=65536)


def test_depth_boundary_and_preallocation_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    assert parsing.parse_strict_json(b"[" * 32 + b"0" + b"]" * 32)
    loads = Mock(side_effect=AssertionError("tree allocation must not run"))
    monkeypatch.setattr(parsing.json, "loads", loads)
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(b"[" * 33 + b"0" + b"]" * 33)
    assert loads.call_count == 0


def test_node_boundary_counts_object_keys_and_values(monkeypatch: pytest.MonkeyPatch) -> None:
    exact = b"[" + b",".join([b"0"] * 9999) + b"]"
    assert len(parsing.parse_strict_json(exact)) == 9999
    valid_object = {str(i): 0 for i in range(4999)}
    assert parsing.parse_strict_json(json.dumps(valid_object).encode()) == valid_object
    too_many = b"[" + b",".join([b"0"] * 10000) + b"]"
    object_too_many = json.dumps({str(i): 0 for i in range(5000)}).encode()
    loads = Mock(side_effect=AssertionError("tree allocation must not run"))
    monkeypatch.setattr(parsing.json, "loads", loads)
    for raw in (too_many, object_too_many):
        with pytest.raises(parsing.ParsingError):
            parsing.parse_strict_json(raw)
    assert loads.call_count == 0


def test_canonical_json_order_encoding_and_detachment() -> None:
    original = {"z": [{"name": chr(0xE9), "null": None}], "a": 1.0}
    copied = parsing.checked_json(original)
    assert copied == original and copied is not original
    assert copied["z"] is not original["z"]
    original["z"][0]["name"] = "changed"
    assert parsing.canonical_json(copied) == b'{"a":1.0,"z":[{"name":"\xc3\xa9","null":null}]}'


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        chr(0xD800),
        {chr(0xDFFF): 1},
        {1: "x"},
        (1, 2),
        b"x",
        Decimal("0.1"),
        {1, 2},
        object(),
    ],
)
def test_checked_json_rejects_unsupported_or_lossy_native_types(value: object) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.checked_json(value)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: type("Text", (str,), {})("x"),
        lambda: type("Number", (int,), {})(1),
        lambda: type("Real", (float,), {})(1.0),
        lambda: type("Items", (list,), {})([]),
        lambda: type("Object", (dict,), {})({}),
    ],
)
def test_checked_json_rejects_subclasses(factory) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.checked_json(factory())


def test_native_cycles_and_depth_reject_without_recursion_error() -> None:
    cyclic = []
    cyclic.append(cyclic)
    with pytest.raises(parsing.ParsingError):
        parsing.checked_json(cyclic)
    nested = 0
    for _ in range(32):
        nested = [nested]
    assert parsing.checked_json(nested)
    with pytest.raises(parsing.ParsingError):
        parsing.checked_json([nested])


def test_shared_native_children_become_independent_copies() -> None:
    child = [1]
    copied = parsing.checked_json([child, child])
    assert copied == [[1], [1]]
    assert copied[0] is not copied[1]


def test_canonical_byte_budget_counts_utf8_and_escapes() -> None:
    assert len(parsing.canonical_json("a" * (LIMIT - 2))) == LIMIT
    for value in ("a" * (LIMIT - 1), chr(0x1F600) * (LIMIT // 4), "\x00" * (LIMIT // 6 + 1)):
        with pytest.raises(parsing.ParsingError):
            parsing.checked_json(value)
        with pytest.raises(parsing.ParsingError):
            parsing.canonical_json(value)


@pytest.mark.parametrize(
    "raw",
    [
        b"<root/>",
        b'<?xml version="1.0" encoding="UTF-8"?><root><n>001</n><b>false</b></root>',
        bytes.fromhex("efbbbf") + b"<root/>",
        "<root><s>caf\u00e9</s></root>".encode("utf-8"),
    ],
)
def test_xml_utf8_subset_preserves_string_fields(raw: bytes) -> None:
    root = parsing.parse_strict_xml(raw)
    assert root.tag == "root"
    if root.find("n") is not None:
        assert root.findtext("n") == "001"
        assert root.findtext("b") == "false"


@pytest.mark.parametrize(
    "raw",
    [
        "<root/>".encode("utf-16"),
        "<root/>".encode("utf-32"),
        b'<?xml version="1.0" encoding="ISO-8859-1"?><root/>',
        b"<root>\x00</root>",
        b"<root>\xff</root>",
        b"<root>",
    ],
)
def test_xml_encoding_or_syntax_refusal_is_fixed(raw: bytes) -> None:
    with pytest.raises(parsing.ParsingError, match=r"^Invalid structured data\.$"):
        parsing.parse_strict_xml(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b"<!DOCTYPE root><root/>",
        b'<!DOCTYPE root [<!ENTITY x "synthetic">]><root>&x;</root>',
        b'<!DOCTYPE root SYSTEM "https://example.invalid/external.dtd"><root/>',
        b'<!DOCTYPE root [<!ENTITY x SYSTEM "file:///synthetic.xml">]><root>&x;</root>',
        b'<!DOCTYPE root [<!ENTITY % x SYSTEM "https://example.invalid/parameter.dtd">%x;]><root/>',
    ],
)
def test_xml_dtd_entity_external_refusal(raw: bytes) -> None:
    with pytest.raises(parsing.ParsingError, match=r"^Invalid structured data\.$"):
        parsing.parse_strict_xml(raw)


def test_xml_byte_depth_and_element_boundaries() -> None:
    exact_bytes = b"<r>" + b"a" * (LIMIT - 7) + b"</r>"
    assert parsing.parse_strict_xml(exact_bytes).tag == "r"
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_xml(exact_bytes + b" ")
    assert parsing.parse_strict_xml(b"<r>" * 16 + b"</r>" * 16).tag == "r"
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_xml(b"<r>" * 17 + b"</r>" * 17)
    assert len(parsing.parse_strict_xml(b"<r>" + b"<n/>" * 9999 + b"</r>")) == 9999
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_xml(b"<r>" + b"<n/>" * 10000 + b"</r>")


def test_xml_namespace_expansion_is_bounded() -> None:
    uri = "u" * 600000
    raw = f'<r xmlns="{uri}"><n/></r>'.encode()
    assert len(raw) < LIMIT
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_xml(raw)


@pytest.mark.parametrize(
    "missing", ["defusedxml", "defusedxml.ElementTree", "defusedxml.common", "synthetic_transitive_dependency"]
)
def test_lazy_xml_dependency_failures_remain_precise(monkeypatch: pytest.MonkeyPatch, missing: str) -> None:
    original = builtins.__import__
    sentinel = ModuleNotFoundError("synthetic dependency absent", name=missing)

    def blocked(name, *args, **kwargs):
        if name.startswith("defusedxml"):
            raise sentinel
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    assert parsing.parse_strict_json(b"{}") == {}
    with pytest.raises(ModuleNotFoundError) as captured:
        parsing.parse_strict_xml(b"<root/>")
    assert captured.value is sentinel and captured.value.name == missing


def test_module_import_does_not_require_defusedxml(monkeypatch: pytest.MonkeyPatch) -> None:
    original = builtins.__import__
    calls = []

    def blocked(name, *args, **kwargs):
        if name.startswith("defusedxml"):
            calls.append(name)
            raise ModuleNotFoundError("synthetic optional absence", name="defusedxml")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    spec = importlib.util.spec_from_file_location("isolated_parsing_base", Path(parsing.__file__))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.parse_strict_json(b"[]") == []
    assert calls == []


@pytest.mark.parametrize("raw", [b'{"\\u00e9":1,"\xc3\xa9":2}', b'{"\\ud83d\\ude00":1,"\xf0\x9f\x98\x80":2}'])
def test_duplicate_keys_use_decoded_unicode_identity(raw: bytes) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(raw)


def test_utf8_content_bom_and_multibyte_byte_boundary() -> None:
    assert parsing.parse_strict_json(b'"\xef\xbb\xbf"') == chr(0xFEFF)
    assert parsing.parse_strict_json(b'"\xc3\xa9"', max_bytes=4) == chr(0xE9)
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_json(b'"\xc3\xa9"', max_bytes=3)


def test_native_node_budget_matches_scanner() -> None:
    assert parsing.checked_json([0] * 9999) == [0] * 9999
    with pytest.raises(parsing.ParsingError):
        parsing.checked_json([0] * 10000)
    assert parsing.checked_json({str(i): 0 for i in range(4999)})
    with pytest.raises(parsing.ParsingError):
        parsing.checked_json({str(i): 0 for i in range(5000)})


def test_canonical_refusal_precedes_dump_allocation(monkeypatch: pytest.MonkeyPatch) -> None:
    dumps = Mock(side_effect=AssertionError("canonical allocation must not run"))
    monkeypatch.setattr(parsing.json, "dumps", dumps)
    for value in ("a" * LIMIT, [0] * 10000, 10**128):
        with pytest.raises(parsing.ParsingError):
            parsing.canonical_json(value)
    assert dumps.call_count == 0


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
def test_xml_no_bom_utf16_utf32_still_rejects(encoding: str) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_xml("<root/>".encode(encoding))


def test_xml_large_bytes_refuse_before_optional_import(monkeypatch: pytest.MonkeyPatch) -> None:
    original = builtins.__import__
    calls = []

    def forbidden(name, *args, **kwargs):
        if name.startswith("defusedxml"):
            calls.append(name)
            raise AssertionError("parser import must not run")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", forbidden)
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_xml(b"x" * (LIMIT + 1))
    assert calls == []


@pytest.mark.parametrize("kind", ["depth", "elements", "expanded_namespace"])
def test_xml_rejects_before_excess_treebuilder_start(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    importlib.import_module("defusedxml.ElementTree")
    actual_builder = ET.TreeBuilder
    starts = []

    class RecordingBuilder:
        def __init__(self) -> None:
            self.inner = actual_builder()

        def start(self, tag: str, attributes: dict[str, str]) -> ET.Element:
            starts.append(tag)
            return self.inner.start(tag, attributes)

        def end(self, tag: str) -> ET.Element:
            return self.inner.end(tag)

        def data(self, data: str) -> None:
            self.inner.data(data)

        def close(self) -> ET.Element:
            return self.inner.close()

    monkeypatch.setattr(parsing.ET, "TreeBuilder", RecordingBuilder)
    if kind == "depth":
        raw = b"<r>" * 17 + b"</r>" * 17
    elif kind == "elements":
        raw = b"<r>" + b"<n/>" * 10000 + b"</r>"
    else:
        uri = "u" * 600000
        raw = f'<r xmlns="{uri}"><n/></r>'.encode()
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_xml(raw)
    assert starts == []


def test_error_representation_contains_no_input() -> None:
    marker = "synthetic-source-value"
    for parse, raw in (
        (parsing.parse_strict_json, f'{{"{marker}":'.encode()),
        (parsing.parse_strict_xml, f"<{marker}>".encode()),
    ):
        with pytest.raises(parsing.ParsingError) as captured:
            parse(raw)
        assert captured.value.args == ("Invalid structured data.",)
        assert marker not in str(captured.value)
        assert marker not in repr(captured.value)
        assert captured.value.__cause__ is None


def test_namespace_attribute_expansion_refuses_before_tree_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    defused = importlib.import_module("defusedxml.ElementTree")
    tree_parser = Mock(side_effect=AssertionError("namespace-aware allocation must not run"))
    monkeypatch.setattr(defused, "DefusedXMLParser", tree_parser)
    uri = "u" * 100000
    attributes = " ".join(f'p:a{i}="v"' for i in range(20))
    raw = f'<r xmlns:p="{uri}" {attributes}/>'.encode()
    assert len(raw) < LIMIT
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_xml(raw)
    assert tree_parser.call_count == 0


def test_unused_large_namespace_does_not_expand_logical_tree() -> None:
    uri = "u" * 600000
    raw = f'<r xmlns:unused="{uri}"><n plain="value"/></r>'.encode()
    root = parsing.parse_strict_xml(raw)
    assert root.tag == "r" and root[0].tag == "n"
    assert root[0].attrib == {"plain": "value"}


def test_namespace_scope_shadowing_default_reset_and_xml_prefix() -> None:
    raw = (
        b'<r xmlns="urn:default" xmlns:p="urn:first" xml:lang="en">'
        b'<p:n p:x="1"/><x xmlns:p="urn:second" xmlns=""><p:n/></x><p:n/>'
        b"</r>"
    )
    root = parsing.parse_strict_xml(raw)
    assert root.tag == "{urn:default}r"
    assert root.attrib == {"{http://www.w3.org/XML/1998/namespace}lang": "en"}
    assert root[0].tag == "{urn:first}n" and root[0].attrib == {"{urn:first}x": "1"}
    assert root[1].tag == "x" and root[1][0].tag == "{urn:second}n"
    assert root[2].tag == "{urn:first}n"


@pytest.mark.parametrize(
    "raw", [b'<r a="1" a="2"/>', b"<p:r/>", b'<r xmlns:p="urn:same" xmlns:q="urn:same" p:a="1" q:a="2"/>']
)
def test_xml_duplicate_expanded_attributes_and_unbound_prefix_reject(raw: bytes) -> None:
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_xml(raw)


def test_both_xml_passes_explicitly_forbid_dtd_entities_and_external(monkeypatch: pytest.MonkeyPatch) -> None:
    sax_module = importlib.import_module("defusedxml.expatreader")
    tree_module = importlib.import_module("defusedxml.ElementTree")
    actual_sax = sax_module.DefusedExpatParser
    actual_tree = tree_module.DefusedXMLParser
    calls = []

    def sax_factory(**kwargs):
        calls.append(("sax", kwargs))
        return actual_sax(**kwargs)

    def tree_factory(**kwargs):
        calls.append(("tree", kwargs))
        return actual_tree(**kwargs)

    monkeypatch.setattr(sax_module, "DefusedExpatParser", sax_factory)
    monkeypatch.setattr(tree_module, "DefusedXMLParser", tree_factory)
    assert parsing.parse_strict_xml(b"<r/>").tag == "r"
    assert [name for name, _ in calls] == ["sax", "tree"]
    assert calls[0][1]["namespaceHandling"] == 0
    for _, kwargs in calls:
        assert kwargs["forbid_dtd"] is True
        assert kwargs["forbid_entities"] is True
        assert kwargs["forbid_external"] is True


def test_tree_pass_independently_refuses_dtd(monkeypatch: pytest.MonkeyPatch) -> None:
    sax_module = importlib.import_module("defusedxml.expatreader")
    skipped_preflight = Mock()
    monkeypatch.setattr(sax_module, "DefusedExpatParser", lambda **kwargs: skipped_preflight)
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_xml(b'<!DOCTYPE r [<!ENTITY x "synthetic">]><r>&x;</r>')
    assert skipped_preflight.feed.call_count == 1


def test_preflight_refuses_dtd_before_tree_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    tree_module = importlib.import_module("defusedxml.ElementTree")
    tree_parser = Mock(side_effect=AssertionError("tree must not run"))
    monkeypatch.setattr(tree_module, "DefusedXMLParser", tree_parser)
    with pytest.raises(parsing.ParsingError):
        parsing.parse_strict_xml(b'<!DOCTYPE r SYSTEM "https://example.invalid/source"><r/>')
    assert tree_parser.call_count == 0
