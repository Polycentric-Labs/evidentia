"""Independent source facts exercised through the complete offline import."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest
from evidentia_collectors.scap._contracts import ScapCollectionResult
from evidentia_collectors.scap.collector import ScapSourceProfile, collect_scap_bytes

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "scap"
PROFILES = ("xccdf-1.2-results", "oval-5.8-core-results", "oval-5.11.2-core-results", "oval-5.12.3-core-results")
OVAL_PROFILES = PROFILES[1:]
SLUG = "nist-800-53-rev5-ca7"
OVAL_RESULTS = ("true", "false", "unknown", "error", "not evaluated", "not applicable")


def source_fixture(profile: str) -> bytes:
    name = profile.removesuffix("-core-results").removesuffix("-results")
    # Only checked-in synthetic XML receives checkout line-ending normalization.
    return (FIXTURES / f"{name}-native.xml").read_bytes().replace(b"\r\n", b"\n")


def expected_fixture(profile: str) -> dict[str, Any]:
    name = profile.removesuffix("-core-results").removesuffix("-results")
    return cast(dict[str, Any], json.loads((FIXTURES / f"{name}-native.expected.json").read_text(encoding="utf-8")))


def import_source(raw: bytes, profile: str = PROFILES[0], index: int = 0, **options: Any) -> ScapCollectionResult:
    return collect_scap_bytes(raw, source_profile=cast(ScapSourceProfile, profile), assessment_index=index, **options)


def completion_claim(raw: bytes, profile: str, index: int = 0, **changes: Any) -> dict[str, Any]:
    return {
        "schema_version": "scap-completion-assertion-v1",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_profile": profile,
        "assessment_index": index,
        "completed_at": "2024-03-01T00:00:00.000000Z",
        "reference": "Synthetic independent observation",
        **changes,
    }


def xccdf_document(*, result: str = "pass", end: str = "2024-03-01T00:00:00Z", start: str | None = None) -> bytes:
    start_attribute = "" if start is None else f' start-time="{start}"'
    return (
        '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2" '
        'id="xccdf_org.example.acceptance_testresult_one"'
        f'{start_attribute} end-time="{end}"><benchmark href="urn:synthetic:acceptance"/>'
        "<target>synthetic-independent-target</target>"
        '<rule-result idref="xccdf_org.example.acceptance_rule_one">'
        f'<result>{result}</result></rule-result><score maximum="1">0</score></TestResult>'
    ).encode()


def oval_outcome_document(profile: str, outcome: str) -> bytes:
    raw = source_fixture(profile)
    old = {OVAL_PROFILES[0]: "false", OVAL_PROFILES[1]: "unknown", OVAL_PROFILES[2]: "not evaluated"}[profile]
    assert raw.count(f'result="{old}"'.encode()) == 4
    raw = raw.replace(f'result="{old}"'.encode(), f'result="{outcome}"'.encode())
    raw = raw.replace(b' reported="1"', b' reported="true"')
    before = f'<definition_{old.replace(" ", "_")} reported="true"/>'.encode()
    raw = raw.replace(before, before.replace(b'"true"', b'"false"'))
    after = f'<definition_{outcome.replace(" ", "_")} reported="false"/>'.encode()
    assert after in raw
    return raw.replace(after, after.replace(b'"false"', b'"true"'))


@pytest.mark.parametrize("profile", PROFILES)
def test_full_result_has_handwritten_native_and_assessment_facts(profile: str) -> None:
    raw, expected = source_fixture(profile), expected_fixture(profile)
    result = import_source(raw, profile)
    assert result.source.sha256 == hashlib.sha256(raw).hexdigest() == expected["source_sha256"]
    assert result.source.bytes == len(raw)
    assert result.native_document.model_dump() == expected["native_document"]
    assert result.assessment.model_dump() == expected["assessment"]
    assert len(result.findings) == result.manifest.total_findings == 1
    assert result.findings[0].id == expected["assessment"]["finding_refs"][0]["finding_id"]
    assert result.findings[0].severity == "informational"
    assert result.findings[0].compliance_status == "unknown"
    assert result.manifest.source_system_ids == ["scap-source:" + expected["source_sha256"]]
    assert result.findings[0].raw_data.source.model_dump() == result.source.model_dump()
    if profile.startswith("oval"):
        assert result.evidence_artifact is None
        assert result.completion.qualification_reasons == ["native_completion_absent"]
    else:
        assert result.evidence_artifact is not None
        assert result.evidence_artifact.content.native_document.model_dump() == expected["native_document"]
        assert result.evidence_artifact.content.assessment.model_dump() == expected["assessment"]


@pytest.mark.parametrize(
    "outcome",
    ("pass", "fail", "error", "unknown", "notapplicable", "informational", "fixed", "notchecked", "notselected"),
)
def test_xccdf_native_outcome_is_not_a_compliance_decision(outcome: str) -> None:
    result = import_source(xccdf_document(result=outcome), cadence_slug=SLUG)
    countable = outcome not in ("notchecked", "notselected")
    assert [row.native_result for row in result.assessment.outcomes] == [outcome]
    assert result.assessment.coverage.countable_top_level_outcome_count == int(countable)
    assert result.cadence.state == ("linked" if countable else "ineligible")
    assert result.findings[0].compliance_status == "unknown"
    assert result.evidence_artifact is not None
    assert result.evidence_artifact.control_mappings == []
    assert result.evidence_artifact.sufficiency == "unknown"


@pytest.mark.parametrize("profile", OVAL_PROFILES)
@pytest.mark.parametrize("outcome", OVAL_RESULTS)
def test_oval_every_result_level_survives_without_boolean_reinterpretation(profile: str, outcome: str) -> None:
    raw = oval_outcome_document(profile, outcome)
    result = import_source(
        raw,
        profile,
        cadence_slug=SLUG,
        completion_assertion=completion_claim(raw, profile),
        asserted_by="Synthetic independent operator",
    )
    assert [row.level for row in result.assessment.outcomes] == [
        "oval_definition",
        "oval_criteria",
        "oval_criterion",
        "oval_test",
    ]
    assert [row.native_result for row in result.assessment.outcomes] == [outcome] * 4
    coverage = result.assessment.coverage
    assert coverage.visible_outcome_count == coverage.selected_outcome_count == 4
    assert coverage.top_level_outcome_count == 2
    assert coverage.countable_top_level_outcome_count == (0 if outcome == "not evaluated" else 2)
    assert result.cadence.state == ("ineligible" if outcome == "not evaluated" else "linked")
    assert result.findings[0].compliance_status == "unknown"
    assert result.evidence_artifact is not None
    assert result.evidence_artifact.content.assessment.outcomes == result.assessment.outcomes


@pytest.mark.parametrize("profile", OVAL_PROFILES)
def test_thin_class_directive_is_retained_without_manufacturing_missing_results(profile: str) -> None:
    raw = oval_outcome_document(profile, "true")
    begin, end = (
        raw.index(b"          <criteria"),
        raw.index(b"          </criteria>") + len(b"          </criteria>\n"),
    )
    raw = raw[:begin] + raw[end:]
    begin, end = raw.index(b"      <tests>"), raw.index(b"      </tests>") + len(b"      </tests>\n")
    raw = raw[:begin] + raw[end:]
    raw = raw.replace(b' reported="', b' content="thin" reported="')
    class_name = {OVAL_PROFILES[0]: "inventory", OVAL_PROFILES[1]: "compliance", OVAL_PROFILES[2]: "vulnerability"}[
        profile
    ]
    if profile == OVAL_PROFILES[1]:
        raw = raw.replace(b"<definition definition_id=", b'<definition class="compliance" definition_id=')
    rules = b"".join(
        f'<definition_{item.replace(" ", "_")} reported="true" content="thin"/>'.encode() for item in OVAL_RESULTS
    )
    extra = f'<class_directives class="{class_name}">'.encode() + rules + b"</class_directives>"
    raw = raw.replace(b"</directives>", b"</directives>" + extra)
    result = import_source(raw, profile)
    coverage = result.assessment.coverage
    assert [row.level for row in result.assessment.outcomes] == ["oval_definition"]
    assert coverage.selected_outcome_count == coverage.top_level_outcome_count == 1
    assert coverage.native_export_detail == "thin"
    assert coverage.oval_directives is not None
    assert len(coverage.oval_directives.class_rules) == 1
    assert [row.outcome for row in coverage.oval_directives.default_rules] == list(OVAL_RESULTS)
    assert "partial_export_detail" in [item.code for item in result.diagnostics]
    assert result.evidence_artifact is None


@pytest.mark.parametrize("profile", OVAL_PROFILES)
def test_duplicate_hostnames_are_distinct_selected_source_occurrences(profile: str) -> None:
    raw = source_fixture(profile)
    begin, end = raw.index(b"    <system>"), raw.index(b"    </system>") + len(b"    </system>")
    unit = raw[begin:end]
    raw = raw[:end] + unit + raw[end:]
    first, second = import_source(raw, profile, 0), import_source(raw, profile, 1)
    assert first.source.model_dump() == second.source.model_dump()
    assert first.native_document.model_dump() == second.native_document.model_dump()
    assert first.assessment.coverage.visible_unit_count == second.assessment.coverage.visible_unit_count == 2
    assert first.assessment.coverage.visible_outcome_count == second.assessment.coverage.visible_outcome_count == 8
    assert [row.native_result for row in first.assessment.outcomes] == [
        row.native_result for row in second.assessment.outcomes
    ]
    assert first.assessment.selection.node_index != second.assessment.selection.node_index
    assert first.findings[0].id != second.findings[0].id
    assert first.evidence_artifact is second.evidence_artifact is None
