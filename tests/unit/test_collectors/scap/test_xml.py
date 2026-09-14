"""Complete XML admission, retained source structure and bounded parser events."""

from __future__ import annotations

import hashlib
from unittest.mock import Mock

import pytest
from evidentia_collectors.scap import _xml
from evidentia_collectors.scap._limits import ScapFailure, start_budget


@pytest.mark.parametrize("chunk", [1, 2, 7, 8192])
def test_fragmentation_preserves_complete_native_order_and_xml_normalization(monkeypatch, chunk) -> None:
    raw = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
        b"<!--before-->\r\n<?audit pre?>\r\n"
        b'<r xmlns="urn:r" xmlns:p="urn:p" xml:lang="en" p:a="A&#xD;&#xA;&#x9;B"> lead\r\n'
        b'<!--mid-->tail<?go data?>more<p:c xmlns:p="urn:q" a="x\t y\r\nz">C&amp;&lt;&#13;&#x9;</p:c>'
        b"end<![CDATA[<raw>]]></r>\r\n<!--after-->\r\n"
    )
    monkeypatch.setattr(_xml, "FEED_LIMIT", chunk)
    view = _xml.parse_xml(raw, start_budget())
    doc = view.document
    assert doc.declaration.model_dump() == {"version": "1.0", "encoding": "UTF-8", "standalone": "yes"}
    assert doc.children == [0, 1, 2, 6]
    assert doc.text == "\n"
    assert view.parents == (None, None, None, 2, 2, 2, None)
    assert [node.kind for node in doc.nodes] == [
        "comment",
        "processing_instruction",
        "element",
        "comment",
        "processing_instruction",
        "element",
        "comment",
    ]
    assert [node.tail for node in doc.nodes] == ["\n", "\n", "\n", "tail", "more", "end<raw>", "\n"]
    root = view.element(2)
    assert root.name.model_dump() == {"namespace_uri": "urn:r", "local_name": "r"}
    assert [item.model_dump() for item in root.namespace_declarations] == [
        {"prefix": "", "namespace_uri": "urn:r"},
        {"prefix": "p", "namespace_uri": "urn:p"},
    ]
    assert root.text == " lead\n" and root.children == [3, 4, 5]
    assert root.attributes[0].name.namespace_uri == "http://www.w3.org/XML/1998/namespace"
    assert root.attributes[0].value == "en"
    assert root.attributes[1].value == "A\r\n\tB"
    child = view.element(5)
    assert child.name.namespace_uri == "urn:q"
    assert child.attributes[0].value == "x  y z"
    assert child.text == "C&<\r\t"
    assert view.simple_content(5) == "C&<\r\t"
    assert doc.nodes[1].target == "audit" and doc.nodes[1].data == "pre"
    assert doc.nodes[4].target == "go" and doc.nodes[4].data == "data"
    assert [doc.nodes[index].data for index in (0, 3, 6)] == ["before", "mid", "after"]


@pytest.mark.parametrize("raw", [b"<r/>", b"<r></r>", b"<r><![CDATA[]]></r>"])
def test_absent_slots_remain_null(raw) -> None:
    doc = _xml.parse_xml(raw, start_budget()).document
    assert doc.declaration is None and doc.text is None
    assert doc.nodes[0].text is None and doc.nodes[0].tail is None


def test_different_raw_bytes_can_have_equal_native_values() -> None:
    values = [b"<r a='x'>&#65;</r>", b'<r a="x">A</r>', b'\xef\xbb\xbf<r a="x">A</r>']
    docs = [_xml.parse_xml(raw, start_budget()).document.model_dump() for raw in values]
    assert docs[0] == docs[1] == docs[2]
    assert len({hashlib.sha256(raw).hexdigest() for raw in values}) == 3


@pytest.mark.parametrize(
    "raw,code",
    [
        (b"", "malformed_xml"),
        (b"<r>", "malformed_xml"),
        (b"<r/><r/>", "malformed_xml"),
        (b"<r>\x00</r>", "unsafe_xml"),
        (b"<r>\xff</r>", "unsafe_xml"),
        (b"\xff\xfe<\x00r\x00/\x00>\x00", "unsafe_xml"),
        (b'<?xml version="1.1"?><r/>', "unsafe_xml"),
        (b'<?xml version="1.0" encoding="ISO-8859-1"?><r/>', "unsafe_xml"),
        (b"<!DOCTYPE r><r/>", "unsafe_xml"),
        (b'<!DOCTYPE r SYSTEM "file:///unavailable"><r/>', "unsafe_xml"),
        (b"<r>" + b"<x/>" * 4000 + b"&undeclared;</r>", "unsafe_xml"),
        (b"<r>&#0;</r>", "malformed_xml"),
        (b"<r>&#xD800;</r>", "malformed_xml"),
        (b"<r>&#x110000;</r>", "malformed_xml"),
        (b"<r>&#;</r>", "malformed_xml"),
        (b"<r>&#X41;</r>", "malformed_xml"),
        (b"<r>&#xG;</r>", "malformed_xml"),
        (b"<r a='<'/>", "malformed_xml"),
        (b"<r a='1' a='2'/>", "malformed_xml"),
    ],
    ids=lambda value: hashlib.sha256(value).hexdigest()[:12] if isinstance(value, bytes) else value,
)
def test_fixed_value_free_source_refusals(raw, code) -> None:
    with pytest.raises(ScapFailure) as raised:
        _xml.parse_xml(raw, start_budget())
    assert raised.value.code == code
    assert "unavailable" not in str(raised.value) and "undeclared" not in str(raised.value)


@pytest.mark.parametrize("suffix", [b"<!DOCTYPE r>", b"&late;", b"\xff", b"\x00"])
def test_whole_source_preflight_refuses_before_dependency_or_feed(monkeypatch, suffix) -> None:
    resolver = Mock(side_effect=AssertionError("dependency resolved too early"))
    monkeypatch.setattr(_xml, "_dependency", resolver)
    with pytest.raises(ScapFailure):
        _xml.parse_xml(b"<r>" + b"<x/>" * 4000 + suffix + b"</r>", start_budget())
    resolver.assert_not_called()


@pytest.mark.parametrize("source", ["<r/>", bytearray(b"<r/>"), memoryview(b"<r/>")])
def test_raw_source_requires_exact_bytes(source) -> None:
    with pytest.raises(ScapFailure, match="Invalid SCAP import options"):
        _xml.parse_xml(source, start_budget())


@pytest.mark.parametrize("kind", ["literal", "comment", "cdata", "pi", "tag", "attribute-space"])
def test_complete_lexical_token_boundary(kind) -> None:
    limit = _xml.TOKEN_LIMIT

    def make(size: int) -> bytes:
        if kind == "literal":
            return b"<r>" + b"a" * size + b"</r>"
        if kind == "comment":
            return b"<r><!--" + b"a" * (size - 7) + b"--></r>"
        if kind == "cdata":
            return b"<r><![CDATA[" + b"a" * (size - 12) + b"]]></r>"
        if kind == "pi":
            return b"<r><?p " + b"a" * (size - 6) + b"?></r>"
        if kind == "tag":
            return b"<r" + b" " * (size - 4) + b"/>"
        return b"<r a" + b" " * (size - 11) + b"= 'x'/>"

    exact = make(limit)
    _xml.lexical_preflight(exact, start_budget())
    with pytest.raises(ScapFailure) as raised:
        _xml.lexical_preflight(make(limit + 1), start_budget())
    assert raised.value.code == "source_limit_exceeded"


def test_character_reference_boundary_and_cumulative_decoded_value() -> None:
    exact = b"&#0000000000065;"
    assert len(exact) == 16
    _xml.lexical_preflight(b"<r>" + exact + b"</r>", start_budget())
    with pytest.raises(ScapFailure) as raised:
        _xml.lexical_preflight(b"<r>&#00000000000065;</r>", start_budget())
    assert raised.value.code == "source_limit_exceeded"
    exact_value = b"<r>" + b"a" * (_xml.VALUE_LIMIT - 1) + b"&#65;</r>"
    assert len(_xml.parse_xml(exact_value, start_budget()).element(0).text) == _xml.VALUE_LIMIT
    with pytest.raises(ScapFailure) as raised:
        _xml.parse_xml(exact_value.replace(b"&#65;", b"&#65;&#65;"), start_budget())
    assert raised.value.code == "source_limit_exceeded"


def test_exact_depth_and_attribute_namespace_limits() -> None:
    _xml.parse_xml(b"<r>" * 64 + b"</r>" * 64, start_budget())
    with pytest.raises(ScapFailure) as raised:
        _xml.parse_xml(b"<r>" * 65 + b"</r>" * 65, start_budget())
    assert raised.value.code == "source_limit_exceeded"
    attributes = b" ".join(f'a{i}="x"'.encode() for i in range(64))
    namespaces = b" ".join(f'xmlns:p{i}="urn:{i}"'.encode() for i in range(64))
    root = _xml.parse_xml(b"<r " + attributes + b" " + namespaces + b"/>", start_budget()).element(0)
    assert len(root.attributes) == len(root.namespace_declarations) == 64
    for extra in (b' a64="x"', b' xmlns:p64="urn:64"'):
        with pytest.raises(ScapFailure) as raised:
            _xml.parse_xml(b"<r " + attributes + b" " + namespaces + extra + b"/>", start_budget())
        assert raised.value.code == "source_limit_exceeded"


@pytest.mark.parametrize("fragment", [b"\r", b"\r\n", b"\n", b"\r\r\n"])
def test_document_whitespace_normalizes_across_single_byte_feeds(monkeypatch, fragment) -> None:
    monkeypatch.setattr(_xml, "FEED_LIMIT", 1)
    doc = _xml.parse_xml(fragment + b"<r/>" + fragment, start_budget()).document
    expected = fragment.decode().replace("\r\n", "\n").replace("\r", "\n")
    assert doc.text == expected and doc.nodes[0].tail == expected


def test_default_callback_does_not_erase_line_feed_across_markup(monkeypatch) -> None:
    monkeypatch.setattr(_xml, "FEED_LIMIT", 1)
    doc = _xml.parse_xml(b"\r<r/>\n", start_budget()).document
    assert doc.text == "\n" and doc.nodes[0].tail == "\n"


def test_optional_dependency_absence_broken_discovery_and_import(monkeypatch) -> None:
    monkeypatch.setattr(_xml.importlib.util, "find_spec", lambda _: None)
    with pytest.raises(ScapFailure) as raised:
        _xml.parse_xml(b"<r/>", start_budget())
    assert raised.value.code == "scan_extra_unavailable"
    monkeypatch.setattr(_xml.importlib.util, "find_spec", Mock(side_effect=RuntimeError("private detail")))
    with pytest.raises(ScapFailure) as raised:
        _xml.parse_xml(b"<r/>", start_budget())
    assert raised.value.code == "internal_dependency_failure"
    monkeypatch.setattr(_xml.importlib.util, "find_spec", lambda _: object())
    monkeypatch.setattr(_xml.importlib, "import_module", Mock(side_effect=ImportError("private detail")))
    with pytest.raises(ScapFailure) as raised:
        _xml.parse_xml(b"<r/>", start_budget())
    assert raised.value.code == "internal_dependency_failure"
    assert "private detail" not in str(raised.value)


def test_single_defused_parser_keeps_forbidden_handlers_and_counts_callbacks(monkeypatch) -> None:
    real_factory, forbidden = _xml._dependency()
    observations = []

    def factory(**kwargs):
        assert kwargs["forbid_dtd"] is kwargs["forbid_entities"] is kwargs["forbid_external"] is True
        parser = real_factory(**kwargs)
        backend = parser.parser
        saved = (
            backend.StartDoctypeDeclHandler,
            backend.EntityDeclHandler,
            backend.UnparsedEntityDeclHandler,
            backend.ExternalEntityRefHandler,
        )
        original_feed = parser.feed

        def feed(data):
            assert len(data) <= 8192 and backend.buffer_text is False
            assert saved == (
                backend.StartDoctypeDeclHandler,
                backend.EntityDeclHandler,
                backend.UnparsedEntityDeclHandler,
                backend.ExternalEntityRefHandler,
            )
            assert all(handler is not None for handler in saved)
            original_feed(data)

        parser.feed = feed
        observations.append(kwargs["target"])
        return parser

    monkeypatch.setattr(_xml, "_dependency", lambda: (factory, forbidden))
    _xml.parse_xml(b'<?xml version="1.0"?>\n<r xmlns:p="urn:p"><!--a--><?p b?>x</r>\n', start_budget())
    assert len(observations) == 1
    assert observations[0].callbacks == 10


def test_callback_cap_is_checked_before_retaining_another_event(monkeypatch) -> None:
    monkeypatch.setattr(_xml, "CALLBACK_LIMIT", 3)
    with pytest.raises(ScapFailure) as raised:
        _xml.parse_xml(b"<r><!--one--><!--two--></r>", start_budget())
    assert raised.value.code == "source_limit_exceeded"


def test_cancellation_propagates_without_partial_native_return(monkeypatch) -> None:
    class Cancelled(BaseException):
        pass

    cancellation = Cancelled()
    monkeypatch.setattr(_xml, "_dependency", Mock(side_effect=cancellation))
    with pytest.raises(Cancelled) as raised:
        _xml.parse_xml(b"<r/>", start_budget())
    assert raised.value is cancellation


@pytest.mark.parametrize("failure", ["malformed", "cancelled", "deadline", "success"])
def test_parser_owned_buffers_are_released_after_every_exit(monkeypatch, failure) -> None:
    class Cancelled(BaseException):
        pass

    primary = Cancelled() if failure == "cancelled" else ScapFailure("processing_deadline_exceeded")
    factory, forbidden = _xml._dependency()
    observations = []
    feed_count = 0
    close_count = 0

    def capture(**kwargs):
        parser = factory(**kwargs)
        backend = parser.parser
        original_feed, original_close = parser.feed, parser.close
        target = kwargs["target"]
        observations.append((parser, backend, target))

        def feed(data):
            nonlocal feed_count
            feed_count += 1
            if failure in ("cancelled", "deadline") and feed_count == 4:
                raise primary
            original_feed(data)

        def close():
            nonlocal close_count
            close_count += 1
            return original_close()

        parser.feed, parser.close = feed, close
        return parser

    monkeypatch.setattr(_xml, "_dependency", lambda: (capture, forbidden))
    raw = b"<root>" + b"<child>fragment</child>" * 4000 + (b"</wrong>" if failure == "malformed" else b"</root>")
    if failure == "success":
        view = _xml.parse_xml(raw, start_budget())
        assert len(view.document.nodes) == 4001
        assert view.element(1).text == "fragment"
        assert close_count == 1
    else:
        with pytest.raises(BaseException) as raised:
            _xml.parse_xml(raw, start_budget())
        if failure != "malformed":
            assert raised.value is primary
        else:
            assert type(raised.value) is ScapFailure and raised.value.code == "malformed_xml"
        assert close_count == 0
        frame = raised.value.__traceback__
        while frame is not None:
            if frame.tb_frame.f_code.co_name == "parse_xml":
                assert frame.tb_frame.f_locals["raw"] == b""
                assert frame.tb_frame.f_locals["parser"] is None
                assert frame.tb_frame.f_locals["expat"] is None
            frame = frame.tb_next
    parser, backend, target = observations[0]
    assert target.nodes == [] and target.document == {}
    assert target.stack == [] and target.namespaces == [] and target.fragments == []
    assert target.fragment_bytes == 0
    assert parser._names == {} and parser.entity == {}
    assert all(name not in vars(parser) for name in ("parser", "_parser", "target", "_target", "_doctype"))
    assert all(
        getattr(backend, name) is None
        for name in (
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
        )
    )


@pytest.mark.parametrize("damaged_notes", [False, True])
def test_secondary_cleanup_failure_preserves_primary_cancellation(monkeypatch, damaged_notes) -> None:
    class Cancelled(BaseException):
        pass

    cancellation = Cancelled()
    if damaged_notes:
        cancellation.__notes__ = ()
    original_release = _xml._release
    original_factory, forbidden = _xml._dependency()

    def factory(**kwargs):
        parser = original_factory(**kwargs)
        parser.feed = Mock(side_effect=cancellation)
        return parser

    def release(*args):
        original_release(*args)
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(_xml, "_dependency", lambda: (factory, forbidden))
    monkeypatch.setattr(_xml, "_release", release)
    with pytest.raises(Cancelled) as raised:
        _xml.parse_xml(b"<r/>", start_budget())
    assert raised.value is cancellation


def test_cleanup_error_on_success_is_not_hidden_by_callers_active_exception(monkeypatch) -> None:
    original = _xml._release

    def release(*args):
        original(*args)
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(_xml, "_release", release)
    try:
        raise ValueError("caller context")
    except ValueError:
        with pytest.raises(ScapFailure) as raised:
            _xml.parse_xml(b"<r/>", start_budget())
        assert raised.value.code == "internal_dependency_failure"


@pytest.mark.parametrize("kind", ["element", "comment", "pi"])
def test_callback_traceback_aliases_are_cleared_in_place(monkeypatch, kind) -> None:
    import sys

    original = _xml.Budget.check

    def check(self, **kwargs):
        frame = sys._getframe(1)
        if frame.f_code is _xml._Target.flush.__code__ and "holder" in frame.f_locals:
            raise ScapFailure("processing_deadline_exceeded")
        return original(self, **kwargs)

    suffix = {"element": b"<child/>", "comment": b"<!--marker-->", "pi": b"<?marker value?>"}[kind]
    monkeypatch.setattr(_xml.Budget, "check", check)
    with pytest.raises(ScapFailure) as raised:
        _xml.parse_xml(b"<r>synthetic" + suffix + b"</r>", start_budget())
    assert raised.value.code == "processing_deadline_exceeded"
    traceback = raised.value.__traceback__
    checked = 0
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code is _xml._Target.flush.__code__ and "holder" in frame.f_locals:
            assert frame.f_locals["holder"] == {}
            checked += 1
        if frame.f_code is _xml._Target.append.__code__:
            assert frame.f_locals["node"] == {}
        traceback = traceback.tb_next
    assert checked == 1


def test_partially_built_attribute_list_is_cleared_after_natural_source_refusal() -> None:
    with pytest.raises(ScapFailure) as raised:
        _xml.parse_xml(b'<r a="synthetic" ' + b"z" * 257 + b'=""/>', start_budget())
    assert raised.value.code == "source_limit_exceeded"
    traceback = raised.value.__traceback__
    checked = 0
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code is _xml._Target.start.__code__:
            assert frame.f_locals["retained_attributes"] == []
            checked += 1
        traceback = traceback.tb_next
    assert checked == 1


def test_actual_detached_walk_failure_clears_original_owned_containers(monkeypatch) -> None:
    import sys

    from evidentia_collectors.scap import _json

    original_check = _xml.Budget.check
    original_native = _xml.validate_native
    records = []
    walk_checks = 0

    def validate(value, budget):
        records.extend(value["nodes"])
        records.extend(node["name"] for node in value["nodes"] if node["kind"] == "element")
        return original_native(value, budget)

    def check(self, **kwargs):
        nonlocal walk_checks
        if sys._getframe(1).f_code is _json._walk.__code__:
            walk_checks += 1
            if walk_checks == 2:
                raise ScapFailure("processing_deadline_exceeded")
        return original_check(self, **kwargs)

    monkeypatch.setattr(_xml, "validate_native", validate)
    monkeypatch.setattr(_xml.Budget, "check", check)
    with pytest.raises(ScapFailure) as raised:
        _xml.parse_xml(b"<r>" + b"<child>synthetic</child>" * 160 + b"</r>", start_budget())
    assert raised.value.code == "processing_deadline_exceeded" and walk_checks == 2
    assert len(records) == 322 and all(record == {} for record in records)
