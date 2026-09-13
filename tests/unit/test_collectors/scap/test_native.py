"""Whole-graph topology, namespace scope and bounded simple-content tests."""

from copy import deepcopy

import pytest
from evidentia_collectors.scap._contracts import NativeValueRef
from evidentia_collectors.scap._limits import ScapFailure, start_budget
from evidentia_collectors.scap._native import validate_native


def element(name: str = "root", *, uri: str = "", children: list[int] | None = None) -> dict:
    return {
        "kind": "element",
        "name": {"namespace_uri": uri, "local_name": name},
        "namespace_declarations": [],
        "attributes": [],
        "text": None,
        "tail": None,
        "children": [] if children is None else children,
    }


def document(nodes: list[dict], children: list[int] | None = None) -> dict:
    return {"declaration": None, "text": None, "children": [0] if children is None else children, "nodes": nodes}


def test_complete_order_parent_tables_and_logical_value_preserve_marker_tails() -> None:
    root = element(children=[1, 2])
    root.update(text="a", tail="\n")
    raw = document(
        [
            root,
            {"kind": "comment", "data": "hidden", "tail": "b"},
            {"kind": "processing_instruction", "target": "test", "data": "skip", "tail": "c"},
        ]
    )
    raw["text"] = "\n"
    original = deepcopy(raw)
    view = validate_native(raw, start_budget())
    assert view.document.model_dump() == original
    assert view.parents == (None, 0, 0)
    assert view.subtree_ends == (3, 2, 3)
    assert view.source_string_bytes == 23
    assert view.simple_content(0) == "abc"
    assert view.resolve(NativeValueRef(node_index=0, slot="text", attribute_index=None)) == "a"
    assert list(view.descendants(0)) == [1, 2]
    raw["nodes"][0]["text"] = "caller change"
    assert view.simple_content(0) == "abc"
    assert original["nodes"][0]["text"] == "a"


def test_absent_and_empty_slots_remain_distinct_with_empty_simple_value() -> None:
    absent = validate_native(document([element()]), start_budget())
    empty_element = element()
    empty_element["text"] = ""
    empty = validate_native(document([empty_element]), start_budget())
    assert absent.document.nodes[0].text is None
    assert empty.document.nodes[0].text == ""
    assert absent.simple_content(0) == empty.simple_content(0) == ""


def test_element_children_refuse_simple_content_instead_of_flattening_descendants() -> None:
    root, child = element(children=[1]), element("child")
    root["text"], child["text"] = "before", "nested"
    view = validate_native(document([root, child]), start_budget())
    with pytest.raises(ScapFailure) as caught:
        view.simple_content(0)
    assert caught.value.code == "source_contract_invalid"


def test_simple_content_cumulative_limit_is_checked_across_markers() -> None:
    root = element(children=[1])
    root["text"] = "x" * 131_072
    comment = {"kind": "comment", "data": "", "tail": "y" * 131_072}
    exact = validate_native(document([root, comment]), start_budget())
    assert len(exact.simple_content(0)) == 262_144
    comment["tail"] += "y"
    above = validate_native(document([root, comment]), start_budget())
    with pytest.raises(ScapFailure) as caught:
        above.simple_content(0)
    assert caught.value.code == "source_limit_exceeded"


@pytest.mark.parametrize(
    "case",
    [
        "cycle",
        "duplicate-edge",
        "orphan",
        "wrong-preorder",
        "out-of-range",
        "two-roots",
        "no-root",
        "root-text",
        "root-tail",
    ],
)
def test_invalid_document_topology_refuses(case: str) -> None:
    raw = document([element(children=[1]), element("child")])
    if case == "cycle":
        raw["nodes"][1]["children"] = [0]
    elif case == "duplicate-edge":
        raw["nodes"][0]["children"] = [1, 1]
    elif case == "orphan":
        raw["nodes"][0]["children"] = []
    elif case == "wrong-preorder":
        raw["nodes"].append(element("third"))
        raw["nodes"][0]["children"] = [2, 1]
    elif case == "out-of-range":
        raw["nodes"][0]["children"] = [2]
    elif case == "two-roots":
        raw["nodes"][0]["children"] = []
        raw["children"] = [0, 1]
    elif case == "no-root":
        raw = document([{"kind": "comment", "data": "only", "tail": None}])
    elif case == "root-text":
        raw["text"] = "outside"
    else:
        raw["nodes"][0]["tail"] = "outside"
    with pytest.raises(ScapFailure):
        validate_native(raw, start_budget())


def test_namespaces_restore_at_sibling_boundaries_without_copied_scope_maps() -> None:
    root = element(uri="urn:root", children=[1, 2])
    root["namespace_declarations"] = [
        {"prefix": "", "namespace_uri": "urn:root"},
        {"prefix": "p", "namespace_uri": "urn:p"},
    ]
    first = element("first")
    first["namespace_declarations"] = [{"prefix": "", "namespace_uri": ""}, {"prefix": "p", "namespace_uri": "urn:q"}]
    first["attributes"] = [{"name": {"namespace_uri": "urn:q", "local_name": "id"}, "value": "literal"}]
    second = element("second", uri="urn:p")
    view = validate_native(document([root, first, second]), start_budget())
    assert view.parents == (None, 0, 0)
    assert view.attribute(1, "id", "urn:q", required=True) == "literal"
    assert view.children_named(0, "urn:p", "second") == [2]
    assert view.document.nodes[1].namespace_declarations[0].namespace_uri == ""


@pytest.mark.parametrize(
    "case",
    [
        "duplicate-prefix",
        "unbound-element",
        "unbound-attribute",
        "default-only-attribute",
        "wrong-xml",
        "xmlns-prefix",
        "xmlns-uri",
        "undeclare-prefix",
        "duplicate-attribute",
        "wrong-default",
    ],
)
def test_invalid_namespace_or_attribute_binding_refuses(case: str) -> None:
    node = element()
    if case == "duplicate-prefix":
        node["namespace_declarations"] = [{"prefix": "p", "namespace_uri": "urn:p"}] * 2
    elif case == "unbound-element":
        node["name"]["namespace_uri"] = "urn:absent"
    elif case in ("unbound-attribute", "default-only-attribute"):
        node["attributes"] = [{"name": {"namespace_uri": "urn:a", "local_name": "id"}, "value": "1"}]
        if case == "default-only-attribute":
            node["name"]["namespace_uri"] = "urn:a"
            node["namespace_declarations"] = [{"prefix": "", "namespace_uri": "urn:a"}]
    elif case == "wrong-xml":
        node["namespace_declarations"] = [{"prefix": "xml", "namespace_uri": "urn:wrong"}]
    elif case == "xmlns-prefix":
        node["namespace_declarations"] = [{"prefix": "xmlns", "namespace_uri": "urn:wrong"}]
    elif case == "xmlns-uri":
        node["namespace_declarations"] = [{"prefix": "p", "namespace_uri": "http://www.w3.org/2000/xmlns/"}]
    elif case == "undeclare-prefix":
        node["namespace_declarations"] = [{"prefix": "p", "namespace_uri": ""}]
    elif case == "duplicate-attribute":
        node["attributes"] = [{"name": {"namespace_uri": "", "local_name": "id"}, "value": "1"}] * 2
    else:
        node["namespace_declarations"] = [{"prefix": "", "namespace_uri": "urn:default"}]
    with pytest.raises(ScapFailure):
        validate_native(document([node]), start_budget())


@pytest.mark.parametrize("invalid", ["\x00", "\x0b", "\ufffe"])
def test_xml_illegal_source_characters_refuse(invalid: str) -> None:
    node = element()
    node["text"] = invalid
    with pytest.raises(ScapFailure):
        validate_native(document([node]), start_budget())


def test_all_source_occurrences_are_charged_including_repeated_values() -> None:
    nodes = [element(children=list(range(1, 18)))]
    for _ in range(17):
        child = element("child")
        child["text"] = "x" * 262_144
        nodes.append(child)
    with pytest.raises(ScapFailure) as caught:
        validate_native(document(nodes), start_budget())
    assert caught.value.code == "source_limit_exceeded"


def test_depth_counts_elements_not_comment_or_pi_markers() -> None:
    nodes = [element("level", children=[i + 1]) for i in range(64)]
    nodes.append({"kind": "comment", "data": "allowed leaf", "tail": None})
    assert validate_native(document(nodes), start_budget()).subtree_ends[0] == 65
    nodes[-1] = element("level65")
    with pytest.raises(ScapFailure) as caught:
        validate_native(document(nodes), start_budget())
    assert caught.value.code == "source_limit_exceeded"


def test_refs_do_not_resolve_missing_attributes_or_unrelated_text() -> None:
    node = element()
    node["attributes"] = [{"name": {"namespace_uri": "", "local_name": "id"}, "value": "  same literal  "}]
    view = validate_native(document([node]), start_budget())
    assert view.attribute(0, "id", required=True) == "  same literal  "
    for reference in [
        NativeValueRef(node_index=0, slot="attribute_value", attribute_index=1),
        NativeValueRef(node_index=0, slot="text", attribute_index=None),
        NativeValueRef(node_index=0, slot="element_simple_content", attribute_index=0),
    ]:
        with pytest.raises(ScapFailure):
            view.resolve(reference)
