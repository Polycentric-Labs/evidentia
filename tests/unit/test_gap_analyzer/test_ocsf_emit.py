"""Tests for the v0.10.4 A2 OCSF gap-report export.

Symmetric counterpart to test_sarif.py — same fixture shapes, same
assertion style, validates that ``evidentia gap analyze --format
ocsf`` produces a well-formed OCSF Compliance Finding array.

OCSF Compliance Finding spec: class_uid 2003.
https://schema.ocsf.io/2.0.0/classes/compliance_finding
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from evidentia_core.gap_analyzer import export_report
from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    ImplementationEffort,
)

# Skip the whole module if the [ocsf] extra is not installed.
pytest.importorskip(
    "py_ocsf_models",
    reason="py-ocsf-models not installed; run `uv sync --all-extras` or install the [ocsf] extra",
)


def _gap(
    control_id: str,
    severity: GapSeverity,
    implementation_status: str = "missing",
    **kw: Any,
) -> ControlGap:
    return ControlGap(
        framework="nist-800-53-rev5",
        control_id=control_id,
        control_title=f"{control_id} title",
        control_description=f"{control_id} description",
        gap_severity=severity,
        implementation_status=implementation_status,
        gap_description=f"{control_id} is not implemented.",
        remediation_guidance=f"Implement {control_id}.",
        implementation_effort=ImplementationEffort.MEDIUM,
        **kw,
    )


def _report(gaps: list[ControlGap]) -> GapAnalysisReport:
    sev = [g.gap_severity for g in gaps]
    return GapAnalysisReport(
        organization="Acme",
        frameworks_analyzed=["nist-800-53-rev5"],
        total_controls_required=100,
        total_controls_in_inventory=80,
        total_gaps=len(gaps),
        critical_gaps=sum(1 for s in sev if s == GapSeverity.CRITICAL),
        high_gaps=sum(1 for s in sev if s == GapSeverity.HIGH),
        medium_gaps=sum(1 for s in sev if s == GapSeverity.MEDIUM),
        low_gaps=sum(1 for s in sev if s == GapSeverity.LOW),
        coverage_percentage=80.0,
        gaps=gaps,
        inventory_source="inventory.yaml",
    )


def test_each_gap_becomes_one_ocsf_compliance_finding() -> None:
    from evidentia_core.gap_analyzer.ocsf import gap_report_to_ocsf_array

    report = _report([_gap("AC-2", GapSeverity.HIGH), _gap("AC-3", GapSeverity.MEDIUM)])
    ocsf_array = gap_report_to_ocsf_array(report)

    assert len(ocsf_array) == 2
    for entry in ocsf_array:
        assert entry["class_uid"] == 2003
        assert entry["class_name"] == "Compliance Finding"
        assert entry["category_uid"] == 2
        assert entry["category_name"] == "Findings"


def test_ocsf_severity_id_maps_from_gap_severity() -> None:
    from evidentia_core.gap_analyzer.ocsf import gap_report_to_ocsf_array

    report = _report(
        [
            _gap("C", GapSeverity.CRITICAL),
            _gap("H", GapSeverity.HIGH),
            _gap("M", GapSeverity.MEDIUM),
            _gap("L", GapSeverity.LOW),
            _gap("I", GapSeverity.INFORMATIONAL),
        ]
    )
    by_control = {
        entry["compliance"]["requirements"][0]: entry["severity_id"] for entry in gap_report_to_ocsf_array(report)
    }
    # OCSF SeverityID: 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical
    assert by_control == {"C": 5, "H": 4, "M": 3, "L": 2, "I": 1}


def test_compliance_status_id_maps_from_implementation_status() -> None:
    from evidentia_core.gap_analyzer.ocsf import gap_report_to_ocsf_array

    report = _report(
        [
            _gap("M1", GapSeverity.HIGH, implementation_status="missing"),
            _gap("M2", GapSeverity.HIGH, implementation_status="partial"),
            _gap("M3", GapSeverity.HIGH, implementation_status="planned"),
            _gap("M4", GapSeverity.HIGH, implementation_status="implemented"),
            _gap("M5", GapSeverity.HIGH, implementation_status="not_applicable"),
        ]
    )
    # OCSF ComplianceStatusID: 1=Pass, 2=Warning, 3=Fail, 99=Other
    by_control = {
        entry["compliance"]["requirements"][0]: entry["compliance"]["status_id"]
        for entry in gap_report_to_ocsf_array(report)
    }
    assert by_control == {
        "M1": 3,  # missing -> Fail
        "M2": 2,  # partial -> Warning
        "M3": 3,  # planned -> Fail
        "M4": 1,  # implemented -> Pass
        "M5": 99,  # not_applicable -> Other
    }


def test_remediation_guidance_flows_to_ocsf_remediation_desc() -> None:
    from evidentia_core.gap_analyzer.ocsf import gap_report_to_ocsf_array

    gap = _gap("AC-2", GapSeverity.HIGH)
    gap.remediation_guidance = "Wire IAM federation to corporate SSO."
    report = _report([gap])
    [entry] = gap_report_to_ocsf_array(report)
    assert entry["remediation"]["desc"] == "Wire IAM federation to corporate SSO."


def test_unmapped_carries_full_gap_for_round_trip() -> None:
    """v0.10.4 A2 round-trip fidelity invariant: the full ControlGap
    JSON round-trips through the OCSF emit, matching the v0.10.0
    SecurityFinding pattern."""
    from evidentia_core.gap_analyzer.ocsf import gap_report_to_ocsf_array

    gap = _gap("AC-2", GapSeverity.HIGH)
    gap.priority_score = 42.5
    gap.cross_framework_value = ["soc2-tsc:CC6.1", "iso-27001:A.9.1.1"]
    report = _report([gap])

    [entry] = gap_report_to_ocsf_array(report)
    embedded = entry["unmapped"]["evidentia"]["gap"]
    assert embedded["id"] == gap.id
    assert embedded["priority_score"] == 42.5
    assert embedded["cross_framework_value"] == [
        "soc2-tsc:CC6.1",
        "iso-27001:A.9.1.1",
    ]


def test_export_report_format_ocsf_writes_array_to_path(tmp_path: Path) -> None:
    """End-to-end via the public export_report dispatch: --format ocsf
    writes a JSON array to disk that round-trips into a list of dicts
    with the expected OCSF shape."""
    report = _report([_gap("AC-2", GapSeverity.CRITICAL), _gap("AC-3", GapSeverity.LOW)])
    output_path = tmp_path / "gaps.ocsf.json"

    returned_path = export_report(report, output_path, format="ocsf")

    assert returned_path == output_path
    parsed = json.loads(output_path.read_text(encoding="utf-8"))
    assert isinstance(parsed, list)
    assert len(parsed) == 2
    assert all(entry["class_uid"] == 2003 for entry in parsed)
    by_control = {entry["compliance"]["requirements"][0]: entry for entry in parsed}
    assert by_control["AC-2"]["severity_id"] == 5
    assert by_control["AC-3"]["severity_id"] == 2


def test_standards_includes_cross_framework_values() -> None:
    from evidentia_core.gap_analyzer.ocsf import gap_report_to_ocsf_array

    gap = _gap("AC-2", GapSeverity.HIGH)
    gap.cross_framework_value = ["soc2-tsc:CC6.1", "iso-27001:A.9.1.1"]
    report = _report([gap])
    [entry] = gap_report_to_ocsf_array(report)
    assert "nist-800-53-rev5" in entry["compliance"]["standards"]
    assert "soc2-tsc" in entry["compliance"]["standards"]
    assert "iso-27001" in entry["compliance"]["standards"]
