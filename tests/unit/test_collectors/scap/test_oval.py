"""Hand-derived OVAL source rules, occurrences and native evidence boundaries."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from evidentia_collectors.scap._contracts import SourceBinding, XmlElement
from evidentia_collectors.scap._limits import ScapFailure, start_budget
from evidentia_collectors.scap._xml import parse_xml
from evidentia_collectors.scap.oval import project_oval

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "scap"
_VERSIONS = ("5.8", "5.11.2", "5.12.3")
_OUTCOMES = ("true", "false", "unknown", "error", "not evaluated", "not applicable")
_CRITERION = '<criterion test_ref="oval:synthetic:tst:1" version="0" result="true"/>'
_TEST = '<test test_id="oval:synthetic:tst:1" version="0" check="all" result="unknown"/>'


def fixture(version: str) -> bytes:
    # Checkout normalization is confined to these checked-in synthetic fixtures.
    return (_FIXTURES / f"oval-{version}-native.xml").read_bytes().replace(b"\r\n", b"\n")


def project(raw: bytes | str, version: str = "5.12.3", index: int = 0):
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    budget = start_budget()
    source = SourceBinding(
        sha256=hashlib.sha256(raw).hexdigest(),
        bytes=len(raw),
        profile=f"oval-{version}-core-results",
        projection_version="scap-native-document-v1",
    )
    view = parse_xml(raw, budget)
    return project_oval(view, source, index), view


def refused(raw: str | bytes, version: str = "5.12.3", index: int = 0) -> None:
    with pytest.raises(ScapFailure) as raised:
        project(raw, version, index)
    assert raised.value.code == "source_contract_invalid"


def generator(version: str, prefix: str = "", extra: str = "", timestamp: str = "2024-03-01T00:00:00Z") -> str:
    return (
        f"<{prefix}generator><c:schema_version>{version}</c:schema_version>"
        f"<c:timestamp>{timestamp}</c:timestamp>{extra}</{prefix}generator>"
    )


def rules(reported: str = "true", content: str | None = None) -> str:
    detail = "" if content is None else f' content="{content}"'
    return "".join(f'<definition_{name.replace(" ", "_")} reported="{reported}"{detail}/>' for name in _OUTCOMES)


def definition(criteria: str | None = _CRITERION, extra: str = "", result: str = "true") -> str:
    body = "" if criteria is None else f'<criteria operator="AND" result="{result}">{criteria}</criteria>'
    return f'<definition definition_id="oval:synthetic:def:1" version="0" result="{result}"{extra}>{body}</definition>'


def system(
    version: str = "5.12.3",
    definitions: str | None = None,
    tests: str | None = _TEST,
    extra_sc: str = "",
    interface: str | None = None,
) -> str:
    definitions = definition() if definitions is None else definitions
    defs = f"<definitions>{definitions}</definitions>" if definitions else ""
    test_container = "" if tests is None else f"<tests>{tests}</tests>"
    if interface is None:
        interface = "<s:interface_name>synthetic0</s:interface_name>"
        if version != "5.12.3":
            interface += "<s:ip_address>192.0.2.1</s:ip_address><s:mac_address>02-00-00-00-00-01</s:mac_address>"
    return (
        f"<system>{defs}{test_container}<s:oval_system_characteristics>{generator(version, 's:')}"
        "<s:system_info><s:os_name>SyntheticOS</s:os_name><s:os_version>0</s:os_version>"
        "<s:architecture>synthetic</s:architecture><s:primary_host_name>synthetic-host</s:primary_host_name>"
        f"<s:interfaces><s:interface>{interface}</s:interface></s:interfaces></s:system_info>"
        f"{extra_sc}</s:oval_system_characteristics></system>"
    )


def document(
    version: str = "5.12.3",
    systems: str | None = None,
    directive_rules: str | None = None,
    class_rules: str = "",
    embedded: str = "",
    include: str = ' include_source_definitions="false"',
) -> str:
    systems = system(version) if systems is None else systems
    directive_rules = rules() if directive_rules is None else directive_rules
    return (
        '<oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5" '
        'xmlns:c="http://oval.mitre.org/XMLSchema/oval-common-5" '
        'xmlns:s="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5" '
        'xmlns:d="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:p="urn:synthetic:platform">'
        f"{generator(version)}<directives{include}>{directive_rules}</directives>{class_rules}{embedded}"
        f"<results>{systems}</results></oval_results>"
    )


def embedded(version: str, content: str = "") -> str:
    return f"<d:oval_definitions>{generator(version, 'd:')}{content}</d:oval_definitions>"


def collected(content: str = "", extra: str = "") -> str:
    return (
        '<s:collected_objects><s:object id="oval:synthetic:obj:1" version="0" flag="incomplete"'
        f">{content}</s:object>{extra}</s:collected_objects>"
    )


def data(content: str) -> str:
    return f"<s:system_data>{content}</s:system_data>"


@pytest.mark.parametrize("version", _VERSIONS)
def test_independently_authored_complete_h8_projection(version) -> None:
    expected = json.loads((_FIXTURES / f"oval-{version}-native.expected.json").read_text(encoding="utf-8"))
    raw = fixture(version)
    assert hashlib.sha256(raw).hexdigest() == expected["source_sha256"]
    projection, view = project(raw, version)
    assert len(view.document.nodes) == expected["native_node_count"]
    assert projection.model_dump() == expected["assessment"]
    assert len(projection.times) == 2
    assert all(row.role == "document_compilation" for row in projection.times)
    assert len(projection.finding_refs) == 1


@pytest.mark.parametrize("version", _VERSIONS)
def test_duplicate_systems_remain_distinct_assessment_occurrences(version) -> None:
    raw = document(version, system(version) * 2)
    first, _ = project(raw, version, 0)
    second, _ = project(raw, version, 1)
    assert len(first.units) == len(second.units) == 2
    assert first.selection.node_index != second.selection.node_index
    assert first.finding_refs[0].finding_id != second.finding_refs[0].finding_id
    assert second.coverage.visible_outcome_count == 8
    assert len(second.outcomes) == 4 and len(second.times) == 3
    assert {row.scope for row in second.times} == {"document", "system_characteristics"}
    invalid = raw.replace("<s:os_version>0</s:os_version>", "<s:os_version><bad/></s:os_version>", 1)
    refused(invalid, version, 1)


@pytest.mark.parametrize("index", [-1, 1, True, 0.0])
def test_selection_is_an_existing_direct_system_index(index) -> None:
    with pytest.raises(ScapFailure) as raised:
        project(document(), index=index)
    assert raised.value.code == "assessment_not_found"


def test_direct_systems_required_and_empty_containers_are_distinct() -> None:
    refused(document(systems=f"<p:wrapper>{system()}</p:wrapper>"))
    raw = document(systems=system(definitions="", tests=None), directive_rules=rules("false"))
    projection, _ = project(raw)
    assert projection.outcomes == [] and projection.coverage.cadence_evidence == "empty"
    assert projection.coverage.native_export_detail == "no_reported_rules"
    refused(raw.replace("<system>", "<system><definitions/>"))
    refused(raw.replace("<system>", "<system><tests/>"))
    refused(raw.replace("</s:system_info>", "</s:system_info><s:collected_objects/>"))
    project(raw.replace("</s:system_info>", "</s:system_info><s:system_data/>"))


def test_legacy_decimal_spellings_all_generators_and_compilation_scopes() -> None:
    raw = document("5.8", embedded=embedded("5.800"), include="")
    raw = raw.replace("<c:schema_version>5.8</", "<c:schema_version>+05.80</", 1)
    raw = raw.replace("<c:schema_version>5.8</", "<c:schema_version>005.8</", 1)
    projection, view = project(raw, "5.8")
    assert [row.scope for row in projection.times] == ["document", "embedded_definitions", "system_characteristics"]
    assert all(row.role == "document_compilation" for row in projection.times)
    values = [
        view.simple_content(i)
        for i, node in enumerate(view.document.nodes)
        if type(node) is XmlElement and node.name.local_name == "schema_version"
    ]
    assert values == ["+05.80", "5.800", "005.8"]


@pytest.mark.parametrize("value,attrs", [("5.8e0", ""), ("5.8:1.0", ""), ("5.8", ' platform=""')])
def test_legacy_generator_rejects_undeclared_decimal_or_platform(value, attrs) -> None:
    raw = document("5.8").replace("<c:schema_version>5.8</", f"<c:schema_version{attrs}>{value}</", 1)
    refused(raw, "5.8")


@pytest.mark.parametrize("version", ["5.11.2", "5.12.3"])
def test_later_core_component_exactness_and_platform_presence(version) -> None:
    raw = document(version)
    platform = f'<c:schema_version platform="">{version}:1.2</c:schema_version>'
    raw = raw.replace("<c:timestamp>", platform + "<c:timestamp>", 1)
    project(raw, version)
    refused(raw.replace(f">{version}:1.2<", f">{version}0:1.2<"), version)
    refused(raw.replace(' platform=""', ""), version)
    refused(raw.replace(f"<c:schema_version>{version}</c:schema_version>", "", 1), version)
    refused(
        raw.replace(
            f"<c:schema_version>{version}</c:schema_version>", "<c:schema_version> 5.12.3 </c:schema_version>", 1
        ),
        version,
    )


@pytest.mark.parametrize(
    "extra", ["<c:schema_version>5.12.3</c:schema_version>", "<c:timestamp>2024-03-01T00:00:00Z</c:timestamp>"]
)
def test_known_generator_duplicates_in_wildcard_tail_refuse(extra) -> None:
    raw = document().replace("</generator>", extra + "</generator>", 1)
    refused(raw)


def test_unknown_generator_and_system_info_extensions_stay_opaque() -> None:
    raw = document().replace("</generator>", '<p:extension a="literal"><p:child/></p:extension></generator>', 1)
    raw = raw.replace("</s:system_info>", "<s:extension><p:child/></s:extension></s:system_info>")
    projection, view = project(raw)
    names = [view.element(i).name.local_name for i in projection.uninterpreted_roots]
    assert names == ["extension", "extension"]
    refused(raw.replace("</s:system_info>", "<s:os_name>duplicate</s:os_name></s:system_info>"))


@pytest.mark.parametrize("broken", ["<c:timestamp/>", "", "<c:timestamp>2024-02-30T00:00:00Z</c:timestamp>"])
def test_unselected_generator_time_refuses_whole_file(broken) -> None:
    second = system().replace("<c:timestamp>2024-03-01T00:00:00Z</c:timestamp>", broken)
    refused(document(systems=system() + second), index=0)
    refused(document(systems=system() + second), index=1)


def test_unselected_core_version_must_agree() -> None:
    refused(document(systems=system() + system("5.11.2")), index=0)


@pytest.mark.parametrize("lexical", ["TRUE", "yes", ""])
def test_reported_boolean_is_required_and_source_typed(lexical) -> None:
    replacement = "" if lexical == "" else f' reported="{lexical}"'
    refused(document().replace(' reported="true"', replacement, 1))


def test_false_directive_keeps_absent_content_full_without_reporting() -> None:
    projection, view = project(document(systems=system(definitions="", tests=None), directive_rules=rules("0")))
    directive = projection.coverage.oval_directives.default_rules[0]
    assert directive.reported.effective_value is False
    assert view.resolve(directive.reported.value_ref) == "0"
    assert directive.content.present is False and directive.content.effective_value == "full"
    assert projection.coverage.native_export_detail == "no_reported_rules"


def test_directive_order_and_duplicate_class_refuse() -> None:
    raw = document()
    unknown, error = '<definition_unknown reported="true"/>', '<definition_error reported="true"/>'
    refused(raw.replace(unknown + error, error + unknown))
    block = f'<class_directives class="inventory">{rules()}</class_directives>'
    refused(document(class_rules=block * 2))


@pytest.mark.parametrize("include", ["", ' include_source_definitions="true"', ' include_source_definitions="1"'])
def test_effective_include_true_requires_embedded_source(include) -> None:
    refused(document(include=include))
    project(document(include=include, embedded=embedded("5.12.3")))


@pytest.mark.parametrize("include", [' include_source_definitions="false"', ' include_source_definitions="0"'])
def test_include_false_forbids_embedded_source(include) -> None:
    refused(document(include=include, embedded=embedded("5.12.3")))


def test_matching_class_only_and_no_embedded_class_backfill() -> None:
    block = f'<class_directives class="inventory">{rules("false")}</class_directives>'
    project(document(class_rules=block, systems=system(definitions=definition(extra=' class="compliance"'))))
    refused(document(class_rules=block, systems=system(definitions=definition(extra=' class="inventory"'))))
    source = embedded(
        "5.12.3", '<d:definitions><d:definition id="oval:synthetic:def:1" class="inventory"/></d:definitions>'
    )
    projection, view = project(document(class_rules=block, embedded=source, include=""))
    outcome = projection.outcomes[0]
    assert view.attribute_ref(outcome.node_index, "class") is None
    assert any(
        type(n) is XmlElement
        and n.name.namespace_uri.endswith("oval-definitions-5")
        and n.name.local_name == "definitions"
        for n in view.document.nodes
    )


def test_error_directive_is_not_unknown_and_full_thin_are_exact() -> None:
    thin = rules(content="thin")
    block = (
        '<class_directives class="inventory">'
        + thin.replace(
            '<definition_error reported="true" content="thin"/>', '<definition_error reported="false" content="thin"/>'
        )
        + "</class_directives>"
    )
    refused(
        document(
            systems=system(definitions=definition(None, ' class="inventory"', "error"), tests=None),
            directive_rules=thin,
            class_rules=block,
        )
    )
    refused(document(systems=system(definitions=definition(None))))
    refused(document(directive_rules=thin))
    project(document(systems=system(definitions=definition(None), tests=None), directive_rules=thin))


def test_document_wide_tests_rule_is_independent_of_observed_class() -> None:
    thin = rules(content="thin")
    raw = document(systems=system(definitions=definition(None), tests=None), directive_rules=thin)
    project(raw)
    block = f'<class_directives class="inventory">{rules()}</class_directives>'
    refused(document(systems=system(definitions=definition(None), tests=None), directive_rules=thin, class_rules=block))
    refused(document(systems=system(definitions=definition(None)), directive_rules=thin))


@pytest.mark.parametrize("outcome", _OUTCOMES)
def test_all_native_results_are_preserved_without_evaluation(outcome) -> None:
    raw = document().replace('result="unknown"', f'result="{outcome}"')
    projection, _ = project(raw)
    assert [row.native_result for row in projection.outcomes] == ["true", "true", "true", outcome]
    assert projection.coverage.top_level_outcome_count == 2
    assert projection.coverage.countable_top_level_outcome_count == (1 if outcome == "not evaluated" else 2)


@pytest.mark.parametrize(
    "duplicate", [definition(extra=' variable_instance="01"'), definition().replace('version="0"', 'version="-0"')]
)
def test_canonical_duplicate_definition_keys_refuse(duplicate) -> None:
    refused(document(systems=system(definitions=definition() + duplicate)))


def test_distinct_zero_version_and_instance_keys_admit_but_native_lexemes_remain() -> None:
    second = definition().replace('version="0"', 'version="1"', 1)
    third = definition(extra=' variable_instance="0"')
    projection, _ = project(document(systems=system(definitions=definition() + second + third)))
    assert sum(row.level == "oval_definition" for row in projection.outcomes) == 3
    raw = (
        document()
        .replace('version="0"', 'version="+00"')
        .replace('result="true"/>', 'variable_instance="01" result="true"/>')
    )
    project(raw)


def test_same_system_test_full_keys_and_reverse_membership() -> None:
    refused(document(systems=system(tests=_TEST.replace('version="0"', 'version="1"'))))
    refused(document(systems=system(tests=_TEST + _TEST.replace('version="0"', 'version="1"'))))
    refused(document(systems=system(tests=_TEST * 2)))
    projection, _ = project(document(systems=system(definitions=definition(_CRITERION * 2))))
    assert sum(row.level == "oval_criterion" for row in projection.outcomes) == 2
    first = system().replace('test_ref="oval:synthetic:tst:1"', 'test_ref="oval:synthetic:tst:2"')
    second = system().replace("oval:synthetic:tst:1", "oval:synthetic:tst:2")
    refused(document(systems=first + second))


def test_extend_definition_uses_same_system_full_key() -> None:
    extended = '<extend_definition definition_ref="oval:synthetic:def:1" version="+00" result="true"/>'
    second = definition(extended).replace(
        'definition_id="oval:synthetic:def:1"', 'definition_id="oval:synthetic:def:2"'
    )
    projection, _ = project(document(systems=system(definitions=definition() + second)))
    assert sum(row.level == "oval_extend_definition" for row in projection.outcomes) == 1
    refused(document(systems=system(definitions=definition() + second.replace('version="+00"', 'version="1"'))))


def test_object_keys_and_signed_item_links_are_local_and_literal() -> None:
    reference = '<s:reference item_ref="-1"/>'
    sc = collected(reference) + data(
        '<p:any_record id="-01" status="vendor-literal"><p:entity status="other"/></p:any_record>'
    )
    test = _TEST.replace("/>", '><tested_item item_id="-1" result="unknown"/></test>')
    projection, view = project(document(systems=system(tests=test, extra_sc=sc)))
    assert [row.native_flag for row in projection.coverage.collection_flags] == ["incomplete"]
    assert [view.resolve(row.value_ref) for row in projection.coverage.status_observations] == [
        "vendor-literal",
        "other",
    ]
    assert all(row.effective_status is None for row in projection.coverage.status_observations)
    assert [row.scope for row in projection.coverage.status_observations] == [
        "direct_system_data_child",
        "nested_platform_position",
    ]
    assert any(row.level == "oval_tested_item" and row.native_result == "unknown" for row in projection.outcomes)
    refused(document(systems=system(tests=test, extra_sc=collected(reference))))
    duplicate = '<s:object id="oval:synthetic:obj:1" version="-0" variable_instance="01" flag="complete"/>'
    refused(document(systems=system(extra_sc=collected("", duplicate))))
    project(document(systems=system(extra_sc=data('<p:unused id="99"/>'))))


@pytest.mark.parametrize(
    "items", ['<p:item id="+00"/><p:item id="-0"/>', "<p:item/>", '<p:item p:id="1"/>', '<p:item id="1.0"/>']
)
def test_opaque_item_index_has_explicit_required_unique_signed_integer_guard(items) -> None:
    refused(document(systems=system(extra_sc=data(items))))


def test_item_references_cannot_resolve_in_another_system() -> None:
    first = system(extra_sc=collected('<s:reference item_ref="1"/>'))
    second = system(extra_sc=data('<p:record id="1"/>'))
    refused(document(systems=first + second))


def test_repeated_variable_values_preserve_occurrences_without_unique_key_inference() -> None:
    variables = '<tested_variable variable_id="oval:synthetic:var:1">a</tested_variable><tested_variable variable_id="oval:synthetic:var:1">b</tested_variable>'
    values = '<s:variable_value variable_id="oval:synthetic:var:1">a</s:variable_value><s:variable_value variable_id="oval:synthetic:var:1">a</s:variable_value>'
    raw = document(systems=system(tests=_TEST.replace("/>", f">{variables}</test>"), extra_sc=collected(values)))
    _, view = project(raw)
    found = [
        view.simple_content(i)
        for i, node in enumerate(view.document.nodes)
        if type(node) is XmlElement and node.name.local_name in ("tested_variable", "variable_value")
    ]
    assert found == ["a", "b", "a", "a"]


@pytest.mark.parametrize("version", _VERSIONS)
def test_applicability_is_version_specific_and_absence_is_native(version) -> None:
    raw = document(version).replace(_CRITERION, _CRITERION.replace("/>", ' applicability_check="false"/>'))
    if version == "5.8":
        refused(raw, version)
    else:
        _, absent = project(document(version), version)
        _, present = project(raw, version)
        absent_node = next(
            i
            for i, node in enumerate(absent.document.nodes)
            if type(node) is XmlElement and node.name.local_name == "criterion"
        )
        present_node = next(
            i
            for i, node in enumerate(present.document.nodes)
            if type(node) is XmlElement and node.name.local_name == "criterion"
        )
        assert absent.attribute_ref(absent_node, "applicability_check") is None
        assert present.attribute(present_node, "applicability_check") == "false"


@pytest.mark.parametrize("version", ["5.8", "5.11.2"])
@pytest.mark.parametrize(
    "before,after",
    [
        ("<s:ip_address>192.0.2.1</s:ip_address>", ""),
        ("<s:mac_address>02-00-00-00-00-01</s:mac_address>", ""),
        ("s:ip_address", "s:ipv6_address"),
    ],
)
def test_old_interface_required_sequence(version, before, after) -> None:
    refused(document(version).replace(before, after), version)


def test_new_interface_allows_repeated_addresses_and_optional_mac_in_source_order() -> None:
    name = "<s:interface_name>synthetic0</s:interface_name>"
    ip = "<s:ip_address>192.0.2.1</s:ip_address>"
    ipv6 = "<s:ipv6_address>2001:db8::1</s:ipv6_address>"
    project(document(systems=system(interface=name)))
    project(document(systems=system(interface=name + ip * 2 + ipv6 * 2)))
    refused(document(systems=system(interface=name + ipv6 + ip)))
    refused(document(systems=system(interface=name + "<s:mac_address>x</s:mac_address>" * 2)))


@pytest.mark.parametrize(
    "attrs", [' datatype="integer"', ' status="vendor-literal"', ' mask="yes"', ' status=" exists "']
)
def test_legacy_ip_known_attributes_are_exact_source_types(attrs) -> None:
    refused(document("5.8").replace("<s:ip_address>", f"<s:ip_address{attrs}>"), "5.8")


def test_legacy_ip_derives_only_reviewed_status_default() -> None:
    projection, view = project(document("5.8"), "5.8")
    row = projection.coverage.core_status_defaults[0]
    assert row.effective_status == "exists" and row.present is False and row.value_ref is None
    assert view.element(row.node_index).attributes == []
    raw = document("5.8").replace(
        "<s:ip_address>", '<s:ip_address datatype="ipv4_address" mask=" 1 " status="not collected">'
    )
    projection, view = project(raw, "5.8")
    row = projection.coverage.core_status_defaults[0]
    assert row.present and row.effective_status == "not collected"
    assert view.attribute(row.node_index, "mask") == " 1 "


@pytest.mark.parametrize("version", ["5.11.2", "5.12.3"])
@pytest.mark.parametrize("attrs", [' status="exists"', ' mask="false"', ' datatype="string"'])
def test_later_ip_string_does_not_inherit_old_attributes(version, attrs) -> None:
    name = "<s:interface_name>synthetic0</s:interface_name>"
    interface = name + f"<s:ip_address{attrs}>192.0.2.1</s:ip_address><s:mac_address>x</s:mac_address>"
    refused(document(version, systems=system(version, interface=interface)), version)


def test_embedded_legacy_applicability_refusal_is_exact_reached_tree_only() -> None:
    criterion = '<d:criterion applicability_check="true"/>'
    reached = f"<d:definitions><d:definition><d:criteria><d:criteria>{criterion}</d:criteria></d:criteria></d:definition></d:definitions>"
    refused(document("5.8", embedded=embedded("5.8", reached), include=""), "5.8")
    for opaque in (
        f"<d:definitions><d:definition><d:metadata>{criterion}</d:metadata></d:definition></d:definitions>",
        f"<p:wrapper>{criterion}</p:wrapper>",
        reached.replace(" applicability_check=", " p:applicability_check="),
    ):
        projection, _ = project(document("5.8", embedded=embedded("5.8", opaque), include=""), "5.8")
        assert projection.coverage.complete_schema_validation == "not_performed"
        assert projection.coverage.platform_validation == "not_performed"


@pytest.mark.parametrize("field", ["result", "flag", "class"])
def test_source_string_enums_do_not_gain_token_whitespace_semantics(field) -> None:
    if field == "flag":
        raw = document(systems=system(extra_sc=collected())).replace('flag="incomplete"', 'flag=" incomplete "')
    elif field == "class":
        raw = document(systems=system(definitions=definition(extra=' class=" inventory "')))
    else:
        raw = document().replace('result="true"', 'result=" true "', 1)
    refused(raw)
