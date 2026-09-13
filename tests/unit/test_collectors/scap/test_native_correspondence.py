"""Complete retained source correspondence without a production expected-value oracle."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any
from uuid import UUID, uuid5
from xml.etree import ElementTree as ET

import pytest

from .test_source_conformance import PROFILES, expected_fixture, import_source, source_fixture, xccdf_document


def resolve_ref(document: dict[str, Any], reference: dict[str, Any]) -> str:
    node = document["nodes"][reference["node_index"]]
    if reference["slot"] == "attribute_value":
        return str(node["attributes"][reference["attribute_index"]]["value"])
    assert reference["slot"] == "element_simple_content"
    parts = [node["text"] or ""]
    for index in node["children"]:
        child = document["nodes"][index]
        assert child["kind"] in ("comment", "processing_instruction")
        parts.append(child["tail"] or "")
    return "".join(parts)


def source_finding(raw: bytes, profile: str, index: int, node: int) -> tuple[str, str]:
    frame = {
        "schema_version": "scap-finding-identity-v1",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_profile": profile,
        "assessment_index": index,
        "unit_node_index": node,
        "mapping_rule_id": "scap-assessment-summary-v1",
    }
    digest = hashlib.sha256(
        json.dumps(frame, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    ).hexdigest()
    namespace = UUID("c81bcb44-9b41-5b18-9f10-72b3b9b4d3d6")
    system = "scap-xccdf" if profile == PROFILES[0] else "scap-oval"
    return digest, str(uuid5(namespace, system + "\0" + digest))


@pytest.mark.parametrize("profile", PROFILES)
def test_every_outcome_reference_resolves_to_independent_native_source(profile: str) -> None:
    raw, expected = source_fixture(profile), expected_fixture(profile)
    native = expected["native_document"]
    result = import_source(raw, profile)
    for outcome in result.assessment.outcomes:
        reference = outcome.value_ref.model_dump()
        assert resolve_ref(native, reference) == outcome.native_result
        assert reference["node_index"] < len(native["nodes"])
    for row, written in zip(result.assessment.times, expected["assessment"]["times"], strict=True):
        assert row.value_ref.model_dump() == written["value_ref"]
        assert resolve_ref(native, written["value_ref"])
        assert row.normalization.model_dump() == written["normalization"]
    selected = expected["assessment"]["selection"]["node_index"]
    key, identity = source_finding(raw, profile, 0, selected)
    assert result.assessment.finding_refs[0].source_key_sha256 == key
    assert result.assessment.finding_refs[0].finding_id == result.findings[0].id == identity


@pytest.mark.parametrize("profile", PROFILES)
def test_independent_element_parser_agrees_with_every_fixture_element_slot(profile: str) -> None:
    raw = source_fixture(profile)
    expected = expected_fixture(profile)["native_document"]
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True, insert_pis=True))
    source = ET.fromstring(raw, parser=parser)
    nodes = expected["nodes"]
    visited: list[int] = []

    def compare(element: ET.Element, index: int) -> None:
        visited.append(index)
        node = nodes[index]
        tag: object = element.tag
        if tag is ET.Comment:
            assert node["kind"] == "comment" and node["data"] == element.text
        elif tag is ET.ProcessingInstruction:
            target, separator, data = (element.text or "").partition(" ")
            assert node["kind"] == "processing_instruction"
            assert node["target"] == target and node["data"] == (data if separator else "")
        else:
            assert node["kind"] == "element"
            name = node["name"]
            assert element.tag == "{" + name["namespace_uri"] + "}" + name["local_name"]
            attributes = []
            for attribute in node["attributes"]:
                name = attribute["name"]
                key = ("{" + name["namespace_uri"] + "}" if name["namespace_uri"] else "") + name["local_name"]
                attributes.append((key, attribute["value"]))
            assert list(element.attrib.items()) == attributes
            assert element.text == node["text"]
            assert len(element) == len(node["children"])
            for child, child_index in zip(element, node["children"], strict=True):
                compare(child, child_index)
        if index != expected["children"][0]:
            assert element.tail == node["tail"]

    compare(source, expected["children"][0])
    assert visited == list(range(len(nodes)))
    assert import_source(raw, profile).native_document.model_dump() == expected


def test_top_level_markers_and_raw_newlines_have_hand_derived_locations() -> None:
    original = source_fixture(PROFILES[0])
    expected = copy.deepcopy(expected_fixture(PROFILES[0])["native_document"])
    raw = original.replace(b"?>\n", b"?>\n<!--leading-->\n<?outside value?>\n", 1).replace(b"\n", b"\r\n")
    for node in expected["nodes"]:
        if node["kind"] == "element":
            node["children"] = [index + 2 for index in node["children"]]
    expected["children"] = [0, 1, 2]
    expected["nodes"][:0] = [
        {"kind": "comment", "data": "leading", "tail": "\n"},
        {"kind": "processing_instruction", "target": "outside", "data": "value", "tail": "\n"},
    ]
    result = import_source(raw)
    assert result.native_document.model_dump() == expected
    assert result.source.sha256 == hashlib.sha256(raw).hexdigest()
    assert result.assessment.selection.node_index == 2
    assert result.assessment.uninterpreted_roots == [0, 1, 7, 11]
    assert result.assessment.coverage.uninterpreted_node_count == 4


def test_entity_and_cdata_spelling_affects_raw_identity_without_invented_nodes() -> None:
    plain = xccdf_document()
    lexical = plain.replace(b"synthetic-independent-target", b"syn&#x74;hetic-<![CDATA[independent]]>-target")
    first, second = import_source(plain), import_source(lexical)
    assert first.native_document.model_dump() == second.native_document.model_dump()
    assert first.source.sha256 != second.source.sha256
    assert first.findings[0].id != second.findings[0].id
    assert first.evidence_artifact is not None and second.evidence_artifact is not None
    assert first.evidence_artifact.id != second.evidence_artifact.id
    assert len(first.native_document.nodes) == len(second.native_document.nodes) == 6


def test_opaque_checks_keep_namespace_rebinding_signature_and_instruction_text() -> None:
    raw = xccdf_document().replace(
        b"</rule-result>",
        b'<check system="urn:synthetic:inert"><check-content>'
        b'<p:payload xmlns:p="urn:synthetic:outer" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" p:order="first">'
        b"alpha<!--opaque-->tail<?instruction never-execute?>more"
        b'<p:result xmlns:p="urn:synthetic:inner" p:order="second">fail</p:result>'
        b"<ds:Signature><ds:SignedInfo>unverified</ds:SignedInfo></ds:Signature>"
        b"</p:payload></check-content></check></rule-result>",
    )
    result = import_source(raw)
    nodes = result.native_document.model_dump()["nodes"]
    payload = next(node for node in nodes if node.get("name", {}).get("local_name") == "payload")
    inner = next(node for node in nodes if node.get("name", {}).get("namespace_uri") == "urn:synthetic:inner")
    assert payload["name"]["namespace_uri"] == "urn:synthetic:outer"
    assert payload["attributes"][0]["value"] == "first"
    assert inner["attributes"][0]["name"]["namespace_uri"] == "urn:synthetic:inner"
    assert inner["attributes"][0]["value"] == "second"
    assert inner["text"] == "fail"
    assert [row.native_result for row in result.assessment.outcomes] == ["pass"]
    assert result.assessment.coverage.visible_outcome_count == 1
    assert len(result.assessment.coverage.signature_node_indices) == 1
    assert result.assessment.coverage.signature_verification == "not_performed"
    assert "signature_unverified" in [row.code for row in result.diagnostics]
    assert result.evidence_artifact is not None
    assert result.evidence_artifact.content.native_document.model_dump() == result.native_document.model_dump()
