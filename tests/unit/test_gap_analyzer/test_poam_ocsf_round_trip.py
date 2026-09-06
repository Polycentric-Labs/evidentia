"""POA&M ↔ OCSF remediation round-trip regression test (v0.10.4 B4).

The v0.9.0 POA&M exporter (`gap_report_to_oscal_poam`) populates OSCAL
`risk.remediations[0].description` from `ControlGap.remediation_guidance`.

The v0.10.4 A2 OCSF emit (`gap_report_to_ocsf_array`) populates OCSF
`compliance_finding.remediation.desc` from the same field.

The v0.10.0 SecurityFinding → OCSF mapper (`finding_to_ocsf`) populates
OCSF `compliance_finding.remediation.desc` from `SecurityFinding.remediation`.

The three exporters MUST agree on remediation-text propagation. Drift
between them would break operators who rely on the OCSF/POA&M outputs
agreeing about the same gap's remediation. These tests pin the
invariant so a future refactor of any one exporter cannot silently
break the others.
"""

from __future__ import annotations

from datetime import UTC

import pytest
from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    ImplementationEffort,
)
from evidentia_core.oscal.poam_exporter import gap_report_to_oscal_poam

# Skip the whole module if [ocsf] extra is not installed.
pytest.importorskip(
    "py_ocsf_models",
    reason="py-ocsf-models not installed; install the [ocsf] extra",
)


_REMEDIATION_TEXT = (
    "Wire IAM federation to corporate SSO; document the integration in "
    "the operator runbook; tag the integration test for CI gating."
)


def _gap(
    control_id: str = "AC-2",
    severity: GapSeverity = GapSeverity.HIGH,
) -> ControlGap:
    return ControlGap(
        framework="nist-800-53-rev5",
        control_id=control_id,
        control_title=f"{control_id} title",
        control_description=f"{control_id} description",
        gap_severity=severity,
        implementation_status="missing",
        gap_description=f"{control_id} is not implemented.",
        remediation_guidance=_REMEDIATION_TEXT,
        implementation_effort=ImplementationEffort.MEDIUM,
    )


def _report(gaps: list[ControlGap]) -> GapAnalysisReport:
    sev = [g.gap_severity for g in gaps]
    return GapAnalysisReport(
        organization="Acme",
        frameworks_analyzed=["nist-800-53-rev5"],
        total_controls_required=10,
        total_controls_in_inventory=5,
        total_gaps=len(gaps),
        critical_gaps=sum(1 for s in sev if s == GapSeverity.CRITICAL),
        high_gaps=sum(1 for s in sev if s == GapSeverity.HIGH),
        medium_gaps=sum(1 for s in sev if s == GapSeverity.MEDIUM),
        low_gaps=sum(1 for s in sev if s == GapSeverity.LOW),
        coverage_percentage=50.0,
        gaps=gaps,
        inventory_source="inventory.yaml",
    )


def test_remediation_text_lands_in_both_oscal_poam_and_ocsf_compliance_finding() -> None:
    """The same `gap.remediation_guidance` MUST surface in both the
    OSCAL POA&M `risk.remediations[0].description` AND the OCSF
    Compliance Finding `remediation.desc`. Drift here would mean
    operators see different remediation text in different downstream
    consumers for the same gap."""
    from evidentia_core.gap_analyzer.ocsf import gap_report_to_ocsf_array

    report = _report([_gap("AC-2", GapSeverity.HIGH)])

    # POA&M path
    poam_doc = gap_report_to_oscal_poam(report)
    risks = poam_doc["plan-of-action-and-milestones"]["risks"]
    assert len(risks) == 1
    poam_remediation = risks[0]["remediations"][0]["description"]
    assert poam_remediation == _REMEDIATION_TEXT

    # OCSF path (v0.10.4 A2)
    [ocsf_finding] = gap_report_to_ocsf_array(report)
    ocsf_remediation = ocsf_finding["remediation"]["desc"]
    assert ocsf_remediation == _REMEDIATION_TEXT

    # The two MUST agree exactly.
    assert poam_remediation == ocsf_remediation


def test_security_finding_to_ocsf_remediation_round_trip() -> None:
    """A v0.10.0 SecurityFinding with `remediation` set MUST round-
    trip through `finding_to_ocsf` and back via `finding_from_ocsf`
    preserving the remediation text. Validates the third leg of the
    POA&M ↔ OCSF remediation invariant."""
    from datetime import datetime

    from evidentia_core.models.finding import (
        ComplianceStatus,
        SecurityFinding,
    )
    from evidentia_core.ocsf import finding_from_ocsf, finding_to_ocsf

    original = SecurityFinding(
        title="Test finding",
        description="An IAM federation gap reported by a CSPM scanner.",
        severity="high",
        status="active",
        source_system="prowler",
        first_observed=datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC),
        last_observed=datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC),
        compliance_status=ComplianceStatus.FAIL,
        remediation=_REMEDIATION_TEXT,
    )

    ocsf_dict = finding_to_ocsf(original)
    assert ocsf_dict["remediation"]["desc"] == _REMEDIATION_TEXT

    round_trip = finding_from_ocsf(ocsf_dict)
    assert round_trip.remediation == _REMEDIATION_TEXT
    assert round_trip.remediation == original.remediation


def test_empty_remediation_does_not_emit_ocsf_remediation_block() -> None:
    """Negative case: a gap with an empty remediation_guidance string
    is impossible to construct (Pydantic validation requires the
    field) — but if a future refactor relaxed that, the OCSF emit
    MUST NOT emit an empty `remediation` block (OCSF treats absent
    remediation as "no recommendation yet" — better than an empty
    string)."""
    from evidentia_core.gap_analyzer.ocsf import gap_report_to_ocsf_array

    gap = _gap("AC-2", GapSeverity.HIGH)
    # Pydantic-enforced today; this is forward-cover insurance.
    object.__setattr__(gap, "remediation_guidance", "")
    report = _report([gap])

    [ocsf_finding] = gap_report_to_ocsf_array(report)
    assert "remediation" not in ocsf_finding or ocsf_finding.get("remediation") is None
