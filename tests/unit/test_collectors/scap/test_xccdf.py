"""Source-derived XCCDF projections, complete-file validation and native retention."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from evidentia_collectors.scap._contracts import SourceBinding
from evidentia_collectors.scap._limits import ScapFailure, start_budget
from evidentia_collectors.scap._profiles import XCCDF, source_decimal, source_integer
from evidentia_collectors.scap._xml import parse_xml
from evidentia_collectors.scap.xccdf import project_xccdf

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "scap"


def fixture() -> bytes:
    # Only the checked-in synthetic fixture has checkout line endings normalized.
    return (_FIXTURES / "xccdf-1.2-native.xml").read_bytes().replace(b"\r\n", b"\n")


def project(raw: bytes, index: int = 0):
    budget = start_budget()
    source = SourceBinding(
        sha256=hashlib.sha256(raw).hexdigest(),
        bytes=len(raw),
        profile="xccdf-1.2-results",
        projection_version="scap-native-document-v1",
    )
    view = parse_xml(raw, budget)
    return project_xccdf(view, source, index), view


def benchmark(*results: bytes) -> bytes:
    return (
        f'<Benchmark xmlns="{XCCDF}" id="xccdf_org.example.synthetic_benchmark_one">'.encode()
        + b'<status>draft</status><version>1</version><Rule id="xccdf_org.example.synthetic_rule_one"/>'
        + b"".join(raw.split(b"\n", 1)[1] if raw.startswith(b"<?xml") else raw for raw in results)
        + b"</Benchmark>"
    )


def test_independently_authored_complete_projection() -> None:
    expected = json.loads((_FIXTURES / "xccdf-1.2-native.expected.json").read_text(encoding="utf-8"))
    raw = fixture()
    assert hashlib.sha256(raw).hexdigest() == expected["source_sha256"]
    projection, view = project(raw)
    assert len(view.document.nodes) == expected["native_node_count"]
    assert projection.model_dump() == expected["assessment"]
    assert [outcome.native_result for outcome in projection.outcomes] == ["pass", "notchecked"]
    assert view.simple_content(4) == "pass" and view.document.nodes[5].data == "split"
    assert view.simple_content(8) == "notchecked" and view.document.nodes[9].target == "split"


@pytest.mark.parametrize(
    "outcome,countable",
    [
        ("pass", 1),
        ("fail", 1),
        ("error", 1),
        ("unknown", 1),
        ("notapplicable", 1),
        ("informational", 1),
        ("fixed", 1),
        ("notchecked", 0),
        ("notselected", 0),
    ],
)
def test_all_native_outcomes_and_summary_independent_counts(outcome, countable) -> None:
    raw = fixture().replace(b"pa<!--split-->ss", outcome.encode())
    projection, _ = project(raw)
    assert projection.outcomes[0].native_result == outcome
    assert projection.coverage.top_level_outcome_count == 2
    assert projection.coverage.countable_top_level_outcome_count == countable
    assert len(projection.finding_refs) == 1
    assert sum(row.count for row in projection.coverage.outcome_counts) == 2


def test_zero_rule_results_are_valid_empty_native_evidence() -> None:
    raw = fixture()
    start, end = raw.index(b"  <rule-result"), raw.index(b"  <score")
    projection, _ = project(raw[:start] + raw[end:])
    assert projection.outcomes == []
    assert projection.coverage.cadence_evidence == "empty"
    assert projection.coverage.top_level_outcome_count == 0
    assert len(projection.finding_refs) == 1


def test_complete_source_units_unselected_validation_and_occurrence_selection() -> None:
    first = fixture()
    second = first.replace(b"testresult_one", b"testresult_two").replace(b"not<?split value?>checked", b"fail")
    raw = benchmark(first, second)
    projection, view = project(raw, 1)
    assert len(projection.units) == 2 and projection.selection.model_dump() == projection.units[1].model_dump()
    assert projection.coverage.visible_outcome_count == 4
    assert [item.native_result for item in projection.outcomes] == ["pass", "fail"]
    assert all(time.scope_node_index == projection.selection.node_index for time in projection.times)
    assert view.document.nodes[projection.units[0].node_index].attributes[0].value.endswith("testresult_one")
    for selected in (0, 1):
        with pytest.raises(ScapFailure) as raised:
            project(raw.replace(b"not<?split value?>checked", b"unrecognized"), selected)
        assert raised.value.code == "source_contract_invalid"


@pytest.mark.parametrize("index", [-1, 1, True, 0.0])
def test_explicit_occurrence_requires_an_existing_integer(index) -> None:
    with pytest.raises(ScapFailure) as raised:
        project(fixture(), index)
    assert raised.value.code == "assessment_not_found"


@pytest.mark.parametrize(
    "before,after",
    [
        (b' id="xccdf_org.example.synthetic_testresult_one"', b""),
        (b' end-time="2024-02-29T24:00:00-00:00"', b""),
        (b'<benchmark href="urn:synthetic:benchmark:one"/>', b""),
        (b"<target>synthetic-target-one</target>", b""),
        (b'<score maximum="100">50</score>', b""),
        (b"24:00:00-00:00", b"24:00:01Z"),
        (b"pa<!--split-->ss", b" pass "),
        (b"pa<!--split-->ss", b"pa<value/>ss"),
        (b'<score maximum="100">50</score>', b'<score maximum="NaN">50</score>'),
        (b'<score maximum="100">50</score>', b'<score maximum="100">5e1</score>'),
        (b"<target>synthetic-target-one</target>", b"<score>1</score><target>synthetic-target-one</target>"),
    ],
)
def test_whole_file_refusal_for_required_fields_sequence_and_datatypes(before, after) -> None:
    raw = fixture()
    assert before in raw
    with pytest.raises(ScapFailure) as raised:
        project(raw.replace(before, after))
    assert raised.value.code == "source_contract_invalid"


def test_repeated_rule_refs_preserve_instances_but_duplicate_contexts_refuse() -> None:
    raw = fixture()
    projection, _ = project(raw)
    assert len(projection.outcomes) == 2
    extra = b"<instance>first</instance><instance>second</instance>"
    with pytest.raises(ScapFailure) as raised:
        project(raw.replace(b'<instance context="component">alpha</instance>', extra))
    assert raised.value.code == "source_contract_invalid"
    parent = b'<instance context="one" parentContext="missing">first</instance>'
    with pytest.raises(ScapFailure):
        project(raw.replace(b'<instance context="component">alpha</instance>', parent))
    valid = b'<instance context="one" parentContext="two">first</instance><instance context="two">second</instance>'
    project(raw.replace(b'<instance context="component">alpha</instance>', valid))


def test_duplicate_result_ids_and_missing_benchmark_rule_refuse() -> None:
    with pytest.raises(ScapFailure):
        project(benchmark(fixture(), fixture()))
    with pytest.raises(ScapFailure):
        project(benchmark(fixture()).replace(b'<Rule id="xccdf_org.example.synthetic_rule_one"/>', b""))


@pytest.mark.parametrize(
    "weight,allowed",
    [
        ("0", True),
        ("-0.000", True),
        ("+000999.000", True),
        ("0.001", True),
        (".0001", False),
        ("1000", False),
        ("100.1", False),
        ("-1", False),
        ("1e1", False),
    ],
)
def test_weight_value_and_total_digits(weight, allowed) -> None:
    raw = fixture().replace(b"<rule-result idref=", b'<rule-result weight="' + weight.encode() + b'" idref=', 1)
    if allowed:
        project(raw)
    else:
        with pytest.raises(ScapFailure) as raised:
            project(raw)
        assert raised.value.code == "source_contract_invalid"


def test_external_profile_and_inert_target_choice_are_preserved() -> None:
    raw = fixture().replace(b"<target>", b'<profile idref="external_tailoring_profile"/><target>', 1)
    raw = raw.replace(
        b"  <rule-result",
        b'<target-id-ref system="urn:one" href="local-description"/>'
        b'<foreign xmlns="urn:foreign"><opaque/></foreign>'
        b'<target-id-ref system="urn:two" href="another-description"/>\n  <rule-result',
        1,
    )
    projection, view = project(raw)
    assert projection.coverage.uninterpreted_node_count == 4
    assert any(
        view.element(index).name.namespace_uri == "urn:foreign"
        for index in projection.uninterpreted_roots
        if view.document.nodes[index].kind == "element"
    )


def test_selected_time_roles_owner_and_source_attribute_order() -> None:
    raw = fixture().replace(
        b"  <target>", b'<tailoring-file href="urn:t" id="t" version="1" time="2024-02-01T00:00:00Z"/>\n  <target>'
    )
    raw = raw.replace(b"<rule-result idref=", b'<rule-result time="2024-02-29T23:55:00Z" idref=', 1)
    raw = raw.replace(
        b'    <instance context="component">alpha</instance>',
        b'<override time="2024-03-01T00:00:00Z" authority="synthetic"><old-result>fail</old-result>'
        b"<new-result>pass</new-result><remark>source context</remark></override>"
        b'<instance context="component">alpha</instance>',
    )
    projection, view = project(raw)
    assert [item.role for item in projection.times] == [
        "assessment_start",
        "assessment_completion",
        "tailoring_version_time",
        "rule_completion",
        "override_time",
    ]
    for item in projection.times:
        assert item.scope_node_index == item.value_ref.node_index
        assert view.resolve(item.value_ref)


def test_decimal_and_integer_views_do_not_use_large_python_numeric_conversion() -> None:
    digits = "7" * 6000
    assert source_integer(" +" + "0" * 6000 + digits + "\t", nonnegative=True) == digits
    assert source_decimal("\n+000" + digits + ".000\r") == digits
    assert source_decimal("-0.000") == "0"
    with pytest.raises(ScapFailure):
        source_integer("1\u00a02", nonnegative=True)


def test_benchmark_reference_targets_distinguish_values_clusters_and_plain_text() -> None:
    raw = benchmark(fixture()).replace(
        b"<version>1</version>",
        b'<plain-text id="synthetic_text">inert</plain-text><version>1</version>'
        b'<Value id="xccdf_org.example.synthetic_value_one" cluster-id="synthetic_cluster"/>',
    )
    raw = raw.replace(b"  <rule-result", b'<set-value idref="synthetic_cluster">chosen</set-value>\n  <rule-result', 1)
    check = (
        b'<check system="urn:synthetic"><check-export '
        b'value-id="xccdf_org.example.synthetic_value_one" export-name="input"/></check>'
    )
    raw = raw.replace(b"  </rule-result>", b'<fix><sub idref="synthetic_text"/></fix>' + check + b"</rule-result>", 1)
    projection, _ = project(raw)
    assert projection.coverage.selected_outcome_count == 2
    with pytest.raises(ScapFailure):
        project(raw.replace(b'value-id="xccdf_org.example.synthetic_value_one"', b'value-id="synthetic_text"'))
    with pytest.raises(ScapFailure):
        project(raw.replace(b'idref="synthetic_cluster"', b'idref="missing_cluster"'))
    with pytest.raises(ScapFailure):
        project(raw.replace(b'idref="synthetic_text"', b'idref="missing_text"'))


def test_schema_hints_are_inert_and_cannot_select_dynamic_types() -> None:
    raw = fixture().replace(
        b"<TestResult ",
        b'<TestResult xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        b'xsi:schemaLocation="urn:source urn:unavailable-schema" ',
        1,
    )
    projection, view = project(raw)
    assert projection.coverage.selected_outcome_count == 2
    assert view.element(0).attributes[0].value == "urn:source urn:unavailable-schema"
    for override in (b'xsi:type="alternate"', b'xsi:nil="true"', b'xsi:nil="false"'):
        with pytest.raises(ScapFailure) as raised:
            project(raw.replace(b'xsi:schemaLocation="urn:source urn:unavailable-schema"', override))
        assert raised.value.code == "source_contract_invalid"


def test_required_source_name_patterns_and_text_type_are_exact() -> None:
    raw = fixture()
    for name in (
        b"short_name",
        b"prefix_xccdf_org.example_testresult_one",
        b"xccdf__testresult_one",
        b"xccdf_org_testresult_",
    ):
        with pytest.raises(ScapFailure):
            project(raw.replace(b"xccdf_org.example.synthetic_testresult_one", name))
    with pytest.raises(ScapFailure):
        project(raw.replace(b"<target>", b"<title>text<emphasis/>text</title><target>", 1))
    project(raw.replace(b"<target>", b"<title>text<!--inert-->tail</title><target>", 1))


@pytest.mark.parametrize("old,new,allowed", [("fail", "pass", True), ("pass", "fail", False), ("fail", "fail", True)])
def test_override_agreement_preserves_unchanged_annotations(old, new, allowed) -> None:
    override = (
        '<override time="2024-03-01T00:00:00Z" authority="synthetic">'
        f"<old-result>{old}</old-result><new-result>{new}</new-result><remark>context</remark></override>"
    ).encode()
    raw = fixture().replace(b'    <instance context="component">', override + b'    <instance context="component">', 1)
    if allowed:
        projection, _ = project(raw)
        assert projection.outcomes[0].native_result == "pass"
    else:
        with pytest.raises(ScapFailure) as raised:
            project(raw)
        assert raised.value.code == "source_contract_invalid"


@pytest.mark.parametrize(
    "body,allowed", [(b"", False), (b"<!--marker--><?marker value?>", False), (b"<check-content/>", True)]
)
def test_present_check_requires_an_admitted_element(body, allowed) -> None:
    check = b'<check system="urn:synthetic">' + body + b"</check>"
    raw = fixture().replace(b"  </rule-result>", check + b"  </rule-result>", 1)
    if allowed:
        project(raw)
    else:
        with pytest.raises(ScapFailure) as raised:
            project(raw)
        assert raised.value.code == "source_contract_invalid"


@pytest.mark.parametrize("field", ["check", "Id"])
def test_interpreted_unique_ids_span_unselected_units(field) -> None:
    first = fixture()
    if field == "check":
        first = first.replace(
            b"  </rule-result>",
            b'<check id="unique_source_id" system="urn:synthetic"><check-content/></check></rule-result>',
            1,
        )
    else:
        first = first.replace(b"<TestResult ", b'<TestResult Id="unique_source_id" ', 1)
    second = first.replace(b"testresult_one", b"testresult_two")
    for selected in (0, 1):
        with pytest.raises(ScapFailure) as raised:
            project(benchmark(first, second), selected)
        assert raised.value.code == "source_contract_invalid"
    second = second.replace(b"unique_source_id", b"distinct_source_id")
    project(benchmark(first, second))


def test_interpreted_xml_id_includes_benchmark_and_uses_token_semantics() -> None:
    raw = benchmark(fixture().replace(b"<TestResult ", b'<TestResult Id="shared" ', 1))
    raw = raw.replace(b"<Benchmark ", b'<Benchmark Id="  shared  " ', 1)
    with pytest.raises(ScapFailure) as raised:
        project(raw)
    assert raised.value.code == "source_contract_invalid"
    project(raw.replace(b'Id="  shared  "', b'Id="different"'))


def test_repeat_fix_ids_are_not_interpreted_as_unique_check_ids() -> None:
    fix = b'<fix id="repeated_source_fix">inert</fix>'
    raw = fixture().replace(b"  </rule-result>", fix + b"  </rule-result>")
    project(raw)


def test_unselected_times_validate_without_consuming_selected_observation_cap(monkeypatch) -> None:
    from evidentia_collectors.scap import _profiles

    monkeypatch.setattr(_profiles, "TIME_LIMIT", 2)
    first = fixture()
    second = first.replace(b"testresult_one", b"testresult_two")
    for selected in (0, 1):
        projection, _ = project(benchmark(first, second), selected)
        assert len(projection.times) == 2
    with pytest.raises(ScapFailure) as raised:
        project(benchmark(first.replace(b"24:00:00-00:00", b"24:00:01Z"), second), 1)
    assert raised.value.code == "source_contract_invalid"
    with pytest.raises(ScapFailure) as raised:
        project(first.replace(b"<rule-result ", b'<rule-result time="2024-03-01T00:00:00Z" ', 1))
    assert raised.value.code == "source_limit_exceeded"


# These finite URI cases were specified from the pinned source policy before implementation.
_URI_SOURCE_CASES = json.loads(r"""
[{"id":"empty","literal":"","collapsed":"","allowed":true},{"id":"empty_after_xml_collapse","literal":" \t\r\n ","collapsed":"","allowed":true},{"id":"fragment_only","literal":"#part","collapsed":"#part","allowed":true},{"id":"empty_fragment","literal":"#","collapsed":"#","allowed":true},{"id":"relative_file","literal":"synthetic.xml","collapsed":"synthetic.xml","allowed":true},{"id":"relative_parent","literal":"../synthetic.xml","collapsed":"../synthetic.xml","allowed":true},{"id":"absolute_path","literal":"/synthetic/path","collapsed":"/synthetic/path","allowed":true},{"id":"empty_path_segments","literal":"a//b/","collapsed":"a//b/","allowed":true},{"id":"path_parameters","literal":"a;b=1/c;d=2","collapsed":"a;b=1/c;d=2","allowed":true},{"id":"query_only","literal":"?y","collapsed":"?y","allowed":true},{"id":"empty_query_only","literal":"?","collapsed":"?","allowed":true},{"id":"query_fragment","literal":"?y#part","collapsed":"?y#part","allowed":true},{"id":"repeated_question","literal":"a?b?c","collapsed":"a?b?c","allowed":true},{"id":"fragment_question","literal":"a#b?c","collapsed":"a#b?c","allowed":true},{"id":"fragment_double_hash","literal":"a#b#c","collapsed":"a#b#c","allowed":false},{"id":"opaque_urn","literal":"urn:synthetic:one","collapsed":"urn:synthetic:one","allowed":true},{"id":"opaque_colons","literal":"a:b:c","collapsed":"a:b:c","allowed":true},{"id":"opaque_question","literal":"a:?value","collapsed":"a:?value","allowed":true},{"id":"scheme_case","literal":"A+B.2-z:thing","collapsed":"A+B.2-z:thing","allowed":true},{"id":"empty_absolute","literal":"a:","collapsed":"a:","allowed":false},{"id":"empty_absolute_before_fragment","literal":"a:#part","collapsed":"a:#part","allowed":false},{"id":"digit_scheme","literal":"1:a","collapsed":"1:a","allowed":false},{"id":"empty_scheme","literal":":a","collapsed":":a","allowed":false},{"id":"relative_colon_after_slash","literal":"./a:b","collapsed":"./a:b","allowed":true},{"id":"encoded_first_colon","literal":"1%3Aa","collapsed":"1%3Aa","allowed":true},{"id":"escaped_octet","literal":"%ff","collapsed":"%ff","allowed":true},{"id":"escaped_non_utf8","literal":"%C3%28","collapsed":"%C3%28","allowed":true},{"id":"escaped_hash","literal":"a%23b","collapsed":"a%23b","allowed":true},{"id":"percent_alone","literal":"%","collapsed":"%","allowed":false},{"id":"percent_short","literal":"%A","collapsed":"%A","allowed":false},{"id":"percent_nonhex","literal":"%G0","collapsed":"%G0","allowed":false},{"id":"percent_zero","literal":"%00","collapsed":"%00","allowed":true},{"id":"space_mapping","literal":"a b","collapsed":"a b","allowed":true},{"id":"xml_whitespace_mapping","literal":" a\n\t b ","collapsed":"a b","allowed":true},{"id":"unicode_mapping","literal":"urn:synthetic:\u00e9","collapsed":"urn:synthetic:\u00e9","allowed":true},{"id":"unicode_not_normalized","literal":"urn:synthetic:e\u0301","collapsed":"urn:synthetic:e\u0301","allowed":true},{"id":"nbsp_not_trimmed","literal":"\u00a0a\u00a0","collapsed":"\u00a0a\u00a0","allowed":true},{"id":"del_mapping","literal":"a\u007fb","collapsed":"a\u007fb","allowed":true},{"id":"c1_mapping","literal":"a\u0080b","collapsed":"a\u0080b","allowed":true},{"id":"excluded_ascii_mapping","literal":"<>\"{}|\\^`","collapsed":"<>\"{}|\\^`","allowed":true},{"id":"empty_authority","literal":"//","collapsed":"//","allowed":true},{"id":"scheme_empty_authority","literal":"http://","collapsed":"http://","allowed":true},{"id":"file_empty_authority","literal":"file:///synthetic/path","collapsed":"file:///synthetic/path","allowed":true},{"id":"registry_authority","literal":"scheme://_catalog;v=one/path","collapsed":"scheme://_catalog;v=one/path","allowed":true},{"id":"generic_nondigit_port_text","literal":"http://synthetic.example:abc/path","collapsed":"http://synthetic.example:abc/path","allowed":true},{"id":"generic_multiple_at","literal":"scheme://a@b@c/path","collapsed":"scheme://a@b@c/path","allowed":true},{"id":"authority_space","literal":"scheme://synthetic name/path","collapsed":"scheme://synthetic name/path","allowed":true},{"id":"authority_query","literal":"//?q","collapsed":"//?q","allowed":true},{"id":"ipv6_loopback","literal":"http://[::1]/","collapsed":"http://[::1]/","allowed":true},{"id":"ipv6_all_zero","literal":"//[::]","collapsed":"//[::]","allowed":true},{"id":"ipv6_full","literal":"//[1:2:3:4:5:6:7:8]","collapsed":"//[1:2:3:4:5:6:7:8]","allowed":true},{"id":"ipv6_empty_port","literal":"//[::1]:","collapsed":"//[::1]:","allowed":true},{"id":"ipv6_large_port","literal":"//[::1]:999999999999","collapsed":"//[::1]:999999999999","allowed":true},{"id":"ipv6_userinfo","literal":"//operator@[::1]/","collapsed":"//operator@[::1]/","allowed":true},{"id":"ipv6_bad_port","literal":"//[::1]:abc","collapsed":"//[::1]:abc","allowed":false},{"id":"ipv6_suffix","literal":"//[::1]extra","collapsed":"//[::1]extra","allowed":false},{"id":"ipv6_missing_close","literal":"//[::1","collapsed":"//[::1","allowed":false},{"id":"ipv6_empty","literal":"//[]","collapsed":"//[]","allowed":false},{"id":"ipv6_seven_fields","literal":"//[1:2:3:4:5:6:7]","collapsed":"//[1:2:3:4:5:6:7]","allowed":false},{"id":"ipv6_nine_fields","literal":"//[1:2:3:4:5:6:7:8:9]","collapsed":"//[1:2:3:4:5:6:7:8:9]","allowed":false},{"id":"ipv6_zero_compression","literal":"//[1:2:3:4:5:6:7::8]","collapsed":"//[1:2:3:4:5:6:7::8]","allowed":false},{"id":"ipv6_two_compressions","literal":"//[1::2::3]","collapsed":"//[1::2::3]","allowed":false},{"id":"ipv6_long_hextet","literal":"//[12345::]","collapsed":"//[12345::]","allowed":false},{"id":"ipv6_nonhex","literal":"//[gg::]","collapsed":"//[gg::]","allowed":false},{"id":"ipv6_dotted_tail","literal":"//[::ffff:192.0.2.128]","collapsed":"//[::ffff:192.0.2.128]","allowed":true},{"id":"ipv6_dotted_leading_zero","literal":"//[::ffff:192.000.002.128]","collapsed":"//[::ffff:192.000.002.128]","allowed":true},{"id":"ipv6_octet_overflow","literal":"//[::ffff:256.1.2.3]","collapsed":"//[::ffff:256.1.2.3]","allowed":false},{"id":"ipv6_octet_four_digits","literal":"//[::ffff:0000.1.2.3]","collapsed":"//[::ffff:0000.1.2.3]","allowed":false},{"id":"ipv6_uncompressed_dotted","literal":"//[0:0:0:0:0:ffff:192.0.2.1]","collapsed":"//[0:0:0:0:0:ffff:192.0.2.1]","allowed":true},{"id":"ipv6_zone","literal":"//[fe80::1%25synthetic]","collapsed":"//[fe80::1%25synthetic]","allowed":false},{"id":"ipv6_future","literal":"//[v1.synthetic]","collapsed":"//[v1.synthetic]","allowed":false},{"id":"ipv6_encoded_hextet","literal":"//[%31::]","collapsed":"//[%31::]","allowed":false},{"id":"ipv6_prefix","literal":"//[2001:db8::1/64]","collapsed":"//[2001:db8::1/64]","allowed":false},{"id":"raw_bracket_query","literal":"?q=[0]","collapsed":"?q=[0]","allowed":false},{"id":"raw_bracket_fragment","literal":"#part[0]","collapsed":"#part[0]","allowed":false},{"id":"raw_bracket_opaque","literal":"urn:synthetic[0]","collapsed":"urn:synthetic[0]","allowed":false},{"id":"raw_bracket_path","literal":"/part[0]","collapsed":"/part[0]","allowed":false},{"id":"encoded_bracket_query","literal":"?q=%5B0%5D","collapsed":"?q=%5B0%5D","allowed":true},{"id":"encoded_bracket_fragment","literal":"#part%5b0%5d","collapsed":"#part%5b0%5d","allowed":true},{"id":"encoded_bracket_path","literal":"/part%5B0%5D","collapsed":"/part%5B0%5D","allowed":true},{"id":"brackets_bare","literal":"[::1]","collapsed":"[::1]","allowed":false},{"id":"unwise_backslash","literal":"a\\b","collapsed":"a\\b","allowed":true}]
""")


@pytest.mark.parametrize("case", _URI_SOURCE_CASES, ids=lambda case: case["id"])
def test_source_derived_finite_uri_policy(case) -> None:
    from evidentia_collectors.scap._profiles import source_uri

    if case["allowed"]:
        assert source_uri(case["literal"], start_budget()) == case["collapsed"]
    else:
        with pytest.raises(ScapFailure) as raised:
            source_uri(case["literal"], start_budget())
        assert raised.value.code == "source_contract_invalid"


def test_uri_temporary_view_has_exact_existing_source_bound(monkeypatch) -> None:
    from evidentia_collectors.scap import _profiles

    original = _profiles._uri_tokens
    sizes = []

    def tokens(value, start, end, extra, budget):
        sizes.append(len(value))
        return original(value, start, end, extra, budget)

    monkeypatch.setattr(_profiles, "_uri_tokens", tokens)
    literal = '"' * 262144
    assert _profiles.source_uri(literal, start_budget()) == literal
    assert max(sizes) == 786432
    before = len(sizes)
    with pytest.raises(ScapFailure) as raised:
        _profiles.source_uri(literal + '"', start_budget())
    assert raised.value.code == "source_limit_exceeded" and len(sizes) == before


def test_uri_deadline_releases_temporary_mutable_escape_buffer(monkeypatch) -> None:
    import sys

    from evidentia_collectors.scap import _profiles

    original = _profiles.Budget.check
    primary = ScapFailure("processing_deadline_exceeded")

    def check(self, **kwargs):
        frame = sys._getframe(1)
        if frame.f_code is _profiles.source_uri.__code__ and len(frame.f_locals.get("escaped", ())) > 3000:
            raise primary
        return original(self, **kwargs)

    monkeypatch.setattr(_profiles.Budget, "check", check)
    with pytest.raises(ScapFailure) as raised:
        _profiles.source_uri('"' * 10000, start_budget())
    assert raised.value is primary
    traceback = primary.__traceback__
    while traceback is not None:
        if traceback.tb_frame.f_code is _profiles.source_uri.__code__:
            assert traceback.tb_frame.f_locals["escaped"] == bytearray()
        traceback = traceback.tb_next


def test_uri_source_slots_and_interpreted_xml_base_remain_exact() -> None:
    raw = fixture().replace(b"urn:synthetic:benchmark:one", b"  ?query=%2f  ")
    projection, view = project(raw)
    assert view.attribute(1, "href", required=True) == "  ?query=%2f  "
    assert projection.coverage.selected_outcome_count == 2
    check = b'<check system="urn:synthetic" xml:base="%invalid"><check-content/></check>'
    with pytest.raises(ScapFailure) as raised:
        project(raw.replace(b"  </rule-result>", check + b"  </rule-result>", 1))
    assert raised.value.code == "source_contract_invalid"
