"""Tests for the v0.10.5 Phase 8 CycloneDX 1.6 VEX gap-report export.

Validates that ``evidentia gap analyze --format cyclonedx-vex`` produces
a well-formed CycloneDX 1.6 VEX document — the supply-chain VEX surface
complementing the existing CycloneDX SBOM emit at release time.

CycloneDX 1.6 VEX spec: https://cyclonedx.org/docs/1.6/json/ (the
``vulnerabilities[].analysis.state`` enum: ``resolved`` /
``resolved_with_pedigree`` / ``exploitable`` / ``in_triage`` /
``false_positive`` / ``not_affected``).

Adversarial-probe taxonomy (mirroring the v0.10.4 capability-matrix
shape, Vectors 1 / 2 / 4 / 7): minimal positive (each gap becomes one
vulnerability); empty inventory (zero-gap report → empty array);
malformed YAML / mid-emit failure handled by upstream; round-trip JSON
validity (``json.loads`` on the output, schema sanity).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evidentia_core.gap_analyzer import export_report
from evidentia_core.gap_analyzer.vex import gap_report_to_cyclonedx_vex
from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    GapStatus,
    ImplementationEffort,
)


def _gap(
    control_id: str,
    severity: GapSeverity,
    implementation_status: str = "missing",
    status: GapStatus = GapStatus.OPEN,
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
        status=status,
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
# Vector 1 — Minimal positive: envelope + per-gap vulnerability
# ---------------------------------------------------------------------------


def test_cyclonedx_vex_envelope_has_bom_format_and_spec_version() -> None:
    vex = gap_report_to_cyclonedx_vex(_report([_gap("AC-2", GapSeverity.HIGH)]))
    assert vex["bomFormat"] == "CycloneDX"
    assert vex["specVersion"] == "1.6"
    assert vex["version"] == 1
    assert vex["serialNumber"].startswith("urn:uuid:evidentia-vex-")


def test_metadata_tool_is_evidentia() -> None:
    vex = gap_report_to_cyclonedx_vex(_report([_gap("AC-2", GapSeverity.HIGH)]))
    tool = vex["metadata"]["tools"]["components"][0]
    assert tool["name"] == "Evidentia"
    assert tool["vendor"] == "Polycentric Labs"
    assert tool["type"] == "application"
    assert tool["version"]


def test_each_gap_becomes_one_vulnerability_entry() -> None:
    report = _report([_gap("AC-2", GapSeverity.HIGH), _gap("AC-3", GapSeverity.MEDIUM)])
    vex = gap_report_to_cyclonedx_vex(report)
    assert len(vex["vulnerabilities"]) == 2
    ids = {v["id"] for v in vex["vulnerabilities"]}
    assert ids == {report.gaps[0].id, report.gaps[1].id}


def test_severity_maps_to_cyclonedx_rating() -> None:
    report = _report(
        [
            _gap("C", GapSeverity.CRITICAL),
            _gap("H", GapSeverity.HIGH),
            _gap("M", GapSeverity.MEDIUM),
            _gap("L", GapSeverity.LOW),
            _gap("I", GapSeverity.INFORMATIONAL),
        ]
    )
    vex = gap_report_to_cyclonedx_vex(report)

    # EvidentiaModel uses use_enum_values=True so gap_severity comes
    # back as a plain str; unwrap defensively for the cross-key build.
    def _sev(g: ControlGap) -> str:
        return g.gap_severity.value if hasattr(g.gap_severity, "value") else str(g.gap_severity)

    by_gap_severity = {
        _sev(gap): vex["vulnerabilities"][i]["ratings"][0]["severity"] for i, gap in enumerate(report.gaps)
    }
    assert by_gap_severity == {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "info",
    }


def test_recommendation_carries_remediation_guidance() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH)
    gap.remediation_guidance = "Wire IAM federation to corporate SSO."
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["recommendation"] == "Wire IAM federation to corporate SSO."


def test_description_carries_framework_and_control() -> None:
    vex = gap_report_to_cyclonedx_vex(_report([_gap("AC-2", GapSeverity.HIGH)]))
    description = vex["vulnerabilities"][0]["description"]
    assert "nist-800-53-rev5" in description
    assert "AC-2" in description


def test_properties_carry_evidentia_metadata() -> None:
    """CycloneDX `properties` carries framework + control_id +
    implementation_status as name/value pairs for downstream consumers
    that re-key per control."""
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="partial")
    gap.cross_framework_value = ["soc2-tsc:CC6.1"]
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    props = {p["name"]: p["value"] for p in vex["vulnerabilities"][0]["properties"]}
    assert props["evidentia:framework"] == "nist-800-53-rev5"
    assert props["evidentia:control_id"] == "AC-2"
    assert props["evidentia:implementation_status"] == "partial"
    assert "evidentia:cross_framework_value" in props


# ---------------------------------------------------------------------------
# VEX state mapping — the canonical Phase 8 state-derivation table
# ---------------------------------------------------------------------------


def test_state_implemented_is_resolved() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="implemented")
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"]["state"] == "resolved"


def test_state_missing_open_is_exploitable() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="missing")
    gap.status = GapStatus.OPEN
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"]["state"] == "exploitable"


def test_state_missing_in_progress_is_in_triage() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="missing")
    gap.status = GapStatus.IN_PROGRESS
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"]["state"] == "in_triage"


def test_state_missing_remediated_is_resolved() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="missing")
    gap.status = GapStatus.REMEDIATED
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"]["state"] == "resolved"


def test_state_missing_accepted_is_not_affected_with_justification() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="missing")
    gap.status = GapStatus.ACCEPTED
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    analysis = vex["vulnerabilities"][0]["analysis"]
    assert analysis["state"] == "not_affected"
    assert analysis["justification"] == "code_not_reachable"


def test_state_partial_is_in_triage() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="partial")
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"]["state"] == "in_triage"


def test_state_planned_is_in_triage() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="planned")
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"]["state"] == "in_triage"


def test_state_not_applicable_is_not_affected() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="not_applicable")
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    analysis = vex["vulnerabilities"][0]["analysis"]
    assert analysis["state"] == "not_affected"
    assert analysis["justification"] == "code_not_present"


def test_justification_absent_when_state_is_not_not_affected() -> None:
    """CycloneDX 1.6 VEX schema rejects `analysis.justification` on
    non-`not_affected` states. The emit must not emit it."""
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="missing")
    gap.status = GapStatus.OPEN  # → exploitable
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert "justification" not in vex["vulnerabilities"][0]["analysis"]


def test_analysis_detail_carries_rationale() -> None:
    """The `analysis.detail` field surfaces the state-decision rationale
    so a VEX reviewer can audit the classification."""
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="partial")
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    detail = vex["vulnerabilities"][0]["analysis"]["detail"]
    assert "partial" in detail
    assert "in_triage" in detail


# ---------------------------------------------------------------------------
# Vector 2 — Empty inventory / zero-gap report
# ---------------------------------------------------------------------------


def test_empty_report_produces_empty_vulnerabilities_array() -> None:
    vex = gap_report_to_cyclonedx_vex(_report([]))
    assert vex["bomFormat"] == "CycloneDX"
    assert vex["vulnerabilities"] == []


# ---------------------------------------------------------------------------
# Vector 4 — Round-trip via the `export_report` dispatch
# ---------------------------------------------------------------------------


def test_export_report_writes_cyclonedx_vex_file(tmp_path: Path) -> None:
    """End-to-end via the public export_report dispatch: --format
    cyclonedx-vex writes a JSON document to disk that round-trips into
    a dict with the expected CycloneDX 1.6 VEX shape."""
    report = _report([_gap("AC-2", GapSeverity.CRITICAL), _gap("AC-3", GapSeverity.LOW)])
    output_path = tmp_path / "gaps.vex.json"

    returned_path = export_report(report, output_path, format="cyclonedx-vex")

    assert returned_path == output_path
    loaded = json.loads(output_path.read_text(encoding="utf-8"))
    assert loaded["bomFormat"] == "CycloneDX"
    assert loaded["specVersion"] == "1.6"
    assert len(loaded["vulnerabilities"]) == 2


# ---------------------------------------------------------------------------
# Vector 7 — Round-trip JSON validity + serial-number determinism
# ---------------------------------------------------------------------------


def test_serial_number_is_deterministic_for_same_report() -> None:
    """A re-emit of the same report produces the same `serialNumber`
    so VEX consumers can detect idempotent re-publishes."""
    report = _report([_gap("AC-2", GapSeverity.HIGH)])
    a = gap_report_to_cyclonedx_vex(report)
    b = gap_report_to_cyclonedx_vex(report)
    assert a["serialNumber"] == b["serialNumber"]


def test_all_vulnerabilities_have_required_cyclonedx_fields() -> None:
    """Schema sanity: every vulnerability entry carries the
    CycloneDX-required `id`, `source`, `ratings`, and `analysis.state`
    keys."""
    report = _report(
        [
            _gap("C", GapSeverity.CRITICAL),
            _gap("H", GapSeverity.HIGH, implementation_status="partial"),
            _gap("M", GapSeverity.MEDIUM, implementation_status="implemented"),
        ]
    )
    vex = gap_report_to_cyclonedx_vex(report)
    for vuln in vex["vulnerabilities"]:
        assert "id" in vuln
        assert "source" in vuln
        assert vuln["source"]["name"] == "Evidentia"
        assert "ratings" in vuln
        assert len(vuln["ratings"]) == 1
        assert "analysis" in vuln
        assert vuln["analysis"]["state"] in {
            "resolved",
            "exploitable",
            "in_triage",
            "not_affected",
            "false_positive",
        }
