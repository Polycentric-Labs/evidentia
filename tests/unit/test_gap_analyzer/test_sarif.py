"""Tests for the v0.10.0 SARIF gap-report export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evidentia_core.gap_analyzer import export_report
from evidentia_core.gap_analyzer.sarif import gap_report_to_sarif
from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    ImplementationEffort,
)


def _gap(control_id: str, severity: GapSeverity, **kw: Any) -> ControlGap:
    return ControlGap(
        framework="nist-800-53-rev5",
        control_id=control_id,
        control_title=f"{control_id} title",
        control_description=f"{control_id} description",
        gap_severity=severity,
        implementation_status="missing",
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


def test_sarif_has_version_schema_and_driver() -> None:
    sarif = gap_report_to_sarif(_report([_gap("AC-2", GapSeverity.HIGH)]))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Evidentia"
    assert sarif["runs"][0]["tool"]["driver"]["version"]


def test_each_gap_becomes_a_result() -> None:
    report = _report([_gap("AC-2", GapSeverity.HIGH), _gap("AC-3", GapSeverity.MEDIUM)])
    results = gap_report_to_sarif(report)["runs"][0]["results"]
    assert len(results) == 2
    assert {r["ruleId"] for r in results} == {
        "nist-800-53-rev5/AC-2",
        "nist-800-53-rev5/AC-3",
    }


def test_gap_severity_maps_to_sarif_level() -> None:
    report = _report(
        [
            _gap("C", GapSeverity.CRITICAL),
            _gap("H", GapSeverity.HIGH),
            _gap("M", GapSeverity.MEDIUM),
            _gap("L", GapSeverity.LOW),
            _gap("I", GapSeverity.INFORMATIONAL),
        ]
    )
    levels = {r["ruleId"].split("/")[1]: r["level"] for r in gap_report_to_sarif(report)["runs"][0]["results"]}
    assert levels == {
        "C": "error",
        "H": "error",
        "M": "warning",
        "L": "note",
        "I": "note",
    }


def test_rules_are_deduplicated_per_control() -> None:
    # The same control twice -> one rule, two results.
    report = _report([_gap("AC-2", GapSeverity.HIGH), _gap("AC-2", GapSeverity.LOW)])
    sarif = gap_report_to_sarif(report)
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(sarif["runs"][0]["results"]) == 2


def test_results_carry_stable_partial_fingerprints() -> None:
    report = _report([_gap("AC-2", GapSeverity.HIGH)])
    r1 = gap_report_to_sarif(report)["runs"][0]["results"][0]
    r2 = gap_report_to_sarif(report)["runs"][0]["results"][0]
    assert r1["partialFingerprints"]
    assert r1["partialFingerprints"] == r2["partialFingerprints"]


def test_remediation_guidance_in_result_message() -> None:
    report = _report([_gap("AC-2", GapSeverity.HIGH)])
    message = gap_report_to_sarif(report)["runs"][0]["results"][0]["message"]
    assert "Implement AC-2." in message["text"]


def test_result_has_physical_and_logical_location() -> None:
    report = _report([_gap("AC-2", GapSeverity.HIGH)])
    location = gap_report_to_sarif(report)["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == ("inventory.yaml")
    assert location["logicalLocations"][0]["kind"] == "control"


def test_empty_report_produces_valid_sarif() -> None:
    sarif = gap_report_to_sarif(_report([]))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_export_report_writes_sarif_file(tmp_path: Path) -> None:
    report = _report([_gap("AC-2", GapSeverity.HIGH)])
    out = tmp_path / "gaps.sarif"
    export_report(report, out, format="sarif")
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["version"] == "2.1.0"
    assert len(loaded["runs"][0]["results"]) == 1
