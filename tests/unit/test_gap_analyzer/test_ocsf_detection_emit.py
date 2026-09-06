"""Tests for the v0.10.5 Phase 7 OCSF Detection Finding gap-report export.

Symmetric counterpart to test_ocsf_emit.py — same fixture shapes, same
assertion style, validates that ``evidentia gap analyze --format
ocsf-detection`` produces a well-formed OCSF Detection Finding array.

OCSF Detection Finding spec: ``class_uid`` 2004.
https://schema.ocsf.io/2.0.0/classes/detection_finding

The Detection Finding emit is the SIEM-target counterpart to the
Compliance Finding emit (``class_uid`` 2003) shipped in v0.10.4 —
major SIEMs (Splunk, Elastic, Microsoft Sentinel, Datadog) consume
Detection Finding as production traffic.

Adversarial-probe taxonomy (mirroring the v0.10.4 capability-matrix
shape, Vectors 1 / 2 / 4 / 7): minimal positive (each gap becomes one
finding); empty inventory (zero-gap report → empty array); malformed
YAML / mid-emit failure (round-trip via ``export_report`` to disk);
round-trip JSON validity (``json.loads`` on the output).
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
    GapStatus,
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


# ---------------------------------------------------------------------------
# Vector 1 — Minimal positive
# ---------------------------------------------------------------------------


def test_each_gap_becomes_one_ocsf_detection_finding() -> None:
    from evidentia_core.gap_analyzer.ocsf_detection import (
        gap_report_to_ocsf_detection_array,
    )

    report = _report([_gap("AC-2", GapSeverity.HIGH), _gap("AC-3", GapSeverity.MEDIUM)])
    detection_array = gap_report_to_ocsf_detection_array(report)

    assert len(detection_array) == 2
    for entry in detection_array:
        assert entry["class_uid"] == 2004
        assert entry["class_name"] == "Detection Finding"
        assert entry["category_uid"] == 2
        assert entry["category_name"] == "Findings"


def test_severity_id_maps_from_gap_severity() -> None:
    from evidentia_core.gap_analyzer.ocsf_detection import (
        gap_report_to_ocsf_detection_array,
    )

    report = _report(
        [
            _gap("C", GapSeverity.CRITICAL),
            _gap("H", GapSeverity.HIGH),
            _gap("M", GapSeverity.MEDIUM),
            _gap("L", GapSeverity.LOW),
            _gap("I", GapSeverity.INFORMATIONAL),
        ]
    )
    by_finding = {
        entry["finding_info"]["uid"]: entry["severity_id"] for entry in gap_report_to_ocsf_detection_array(report)
    }
    # OCSF SeverityID: 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical
    gap_id_to_severity = {
        gap.id: {
            GapSeverity.CRITICAL: 5,
            GapSeverity.HIGH: 4,
            GapSeverity.MEDIUM: 3,
            GapSeverity.LOW: 2,
            GapSeverity.INFORMATIONAL: 1,
        }[gap.gap_severity]
        for gap in report.gaps
    }
    assert by_finding == gap_id_to_severity


def test_status_id_maps_from_gap_status() -> None:
    """GapStatus -> OCSF StatusID. OPEN/IN_PROGRESS → New (1);
    REMEDIATED → Resolved (4); ACCEPTED → Suppressed (3); default → Other (99)."""
    from evidentia_core.gap_analyzer.ocsf_detection import (
        gap_report_to_ocsf_detection_array,
    )

    open_gap = _gap("S1", GapSeverity.HIGH)
    open_gap.status = GapStatus.OPEN
    inprog_gap = _gap("S2", GapSeverity.HIGH)
    inprog_gap.status = GapStatus.IN_PROGRESS
    remediated_gap = _gap("S3", GapSeverity.HIGH)
    remediated_gap.status = GapStatus.REMEDIATED
    accepted_gap = _gap("S4", GapSeverity.HIGH)
    accepted_gap.status = GapStatus.ACCEPTED
    na_gap = _gap("S5", GapSeverity.HIGH)
    na_gap.status = GapStatus.NOT_APPLICABLE

    report = _report([open_gap, inprog_gap, remediated_gap, accepted_gap, na_gap])
    by_uid = {entry["finding_info"]["uid"]: entry["status_id"] for entry in gap_report_to_ocsf_detection_array(report)}
    assert by_uid[open_gap.id] == 1
    assert by_uid[inprog_gap.id] == 1
    assert by_uid[remediated_gap.id] == 4
    assert by_uid[accepted_gap.id] == 3
    assert by_uid[na_gap.id] == 99


def test_remediation_guidance_flows_to_ocsf_remediation_desc() -> None:
    from evidentia_core.gap_analyzer.ocsf_detection import (
        gap_report_to_ocsf_detection_array,
    )

    gap = _gap("AC-2", GapSeverity.HIGH)
    gap.remediation_guidance = "Wire IAM federation to corporate SSO."
    report = _report([gap])
    [entry] = gap_report_to_ocsf_detection_array(report)
    assert entry["remediation"]["desc"] == "Wire IAM federation to corporate SSO."


def test_finding_info_carries_framework_qualified_type() -> None:
    """Detection Finding has no native compliance object, so the
    framework + control id lands in finding_info.types[] as a stable
    per-control identifier the SIEM can filter on."""
    from evidentia_core.gap_analyzer.ocsf_detection import (
        gap_report_to_ocsf_detection_array,
    )

    report = _report([_gap("AC-2", GapSeverity.HIGH)])
    [entry] = gap_report_to_ocsf_detection_array(report)
    assert "nist-800-53-rev5/AC-2" in entry["finding_info"]["types"]


def test_message_carries_gap_description() -> None:
    from evidentia_core.gap_analyzer.ocsf_detection import (
        gap_report_to_ocsf_detection_array,
    )

    report = _report([_gap("AC-2", GapSeverity.HIGH)])
    [entry] = gap_report_to_ocsf_detection_array(report)
    assert entry["message"] == "AC-2 is not implemented."


# ---------------------------------------------------------------------------
# Vector 2 — Empty inventory / zero-gap report
# ---------------------------------------------------------------------------


def test_empty_report_produces_empty_detection_array() -> None:
    from evidentia_core.gap_analyzer.ocsf_detection import (
        gap_report_to_ocsf_detection_array,
    )

    detection_array = gap_report_to_ocsf_detection_array(_report([]))
    assert detection_array == []


# ---------------------------------------------------------------------------
# Vector 4 — Round-trip on the unmapped block (lossless fidelity)
# ---------------------------------------------------------------------------


def test_unmapped_carries_full_gap_for_round_trip() -> None:
    """v0.10.5 Phase 7 round-trip fidelity invariant: the full
    ControlGap JSON round-trips through the OCSF Detection emit,
    matching the v0.10.0 SecurityFinding + v0.10.4 Compliance Finding
    patterns."""
    from evidentia_core.gap_analyzer.ocsf_detection import (
        gap_report_to_ocsf_detection_array,
    )

    gap = _gap("AC-2", GapSeverity.HIGH)
    gap.priority_score = 42.5
    gap.cross_framework_value = ["soc2-tsc:CC6.1", "iso-27001:A.9.1.1"]
    report = _report([gap])

    [entry] = gap_report_to_ocsf_detection_array(report)
    embedded = entry["unmapped"]["evidentia"]["gap"]
    assert embedded["id"] == gap.id
    assert embedded["priority_score"] == 42.5
    assert embedded["cross_framework_value"] == [
        "soc2-tsc:CC6.1",
        "iso-27001:A.9.1.1",
    ]
    # Detection Finding has no native compliance object, so the
    # implementation_status must round-trip via the unmapped block.
    assert embedded["implementation_status"] == "missing"
    assert embedded["framework"] == "nist-800-53-rev5"
    assert embedded["control_id"] == "AC-2"


# ---------------------------------------------------------------------------
# Vector 7 — Round-trip JSON validity via the public dispatch
# ---------------------------------------------------------------------------


def test_export_report_format_ocsf_detection_writes_array_to_path(
    tmp_path: Path,
) -> None:
    """End-to-end via the public export_report dispatch: --format
    ocsf-detection writes a JSON array to disk that round-trips into
    a list of dicts with the expected OCSF Detection Finding shape."""
    report = _report([_gap("AC-2", GapSeverity.CRITICAL), _gap("AC-3", GapSeverity.LOW)])
    output_path = tmp_path / "gaps.ocsf-detection.json"

    returned_path = export_report(report, output_path, format="ocsf-detection")

    assert returned_path == output_path
    parsed = json.loads(output_path.read_text(encoding="utf-8"))
    assert isinstance(parsed, list)
    assert len(parsed) == 2
    assert all(entry["class_uid"] == 2004 for entry in parsed)

    # Severity round-trip via the disk artifact.
    by_uid_severity = {entry["finding_info"]["uid"]: entry["severity_id"] for entry in parsed}
    ids = {gap.control_id: gap.id for gap in report.gaps}
    assert by_uid_severity[ids["AC-2"]] == 5
    assert by_uid_severity[ids["AC-3"]] == 2


def test_metadata_product_is_evidentia() -> None:
    from evidentia_core.gap_analyzer.ocsf_detection import (
        gap_report_to_ocsf_detection_array,
    )

    report = _report([_gap("AC-2", GapSeverity.HIGH)])
    [entry] = gap_report_to_ocsf_detection_array(report)
    assert entry["metadata"]["product"]["name"] == "Evidentia"
    assert entry["metadata"]["product"]["vendor_name"] == "Polycentric Labs"
    assert entry["metadata"]["product"]["version"]
