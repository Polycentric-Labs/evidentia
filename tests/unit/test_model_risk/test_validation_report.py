"""Unit tests for evidentia_core.model_risk.validation_report (v0.7.10 P0.6.3)."""

from __future__ import annotations

from datetime import date

from evidentia_core.model_risk import generate_validation_report
from evidentia_core.models.model_risk import (
    Methodology,
    ModelInventory,
    Provenance,
    Tier,
    ValidationFinding,
    ValidationSeverity,
    ValidationStatus,
)


def _model_with_findings(
    findings: list[ValidationFinding] | None = None,
) -> ModelInventory:
    return ModelInventory(
        name="Test Model",
        purpose="Test purpose",
        methodology=Methodology.ML,
        vendor_or_internal=Provenance.INTERNAL,
        tier=Tier.TIER_2,
        owner="ml-team@example.com",
        last_validation_date=date(2025, 6, 15),
        validation_findings=findings or [],
    )


class TestGenerateValidationReport:
    def test_no_findings_renders_minimal_report(self) -> None:
        m = _model_with_findings([])
        out = generate_validation_report(m)
        # All major sections present even with no findings
        for section in (
            "## Executive summary",
            "## Finding disposition",
            "## Findings detail",
            "## Validation cycle context",
        ):
            assert section in out
        # Minimal report doesn't render the per-finding narrative
        assert "## Remediation narrative" not in out
        # Disposition table degrades to an empty-state row
        assert "| (no findings) | 0 | 0 | 0 | 0 | 0 |" in out

    def test_findings_disposition_counts(self) -> None:
        m = _model_with_findings([
            ValidationFinding(
                title="HIGH-1",
                description="x",
                severity=ValidationSeverity.HIGH,
                status=ValidationStatus.OPEN,
                detected_at=date(2025, 12, 1),
            ),
            ValidationFinding(
                title="HIGH-2",
                description="x",
                severity=ValidationSeverity.HIGH,
                status=ValidationStatus.REMEDIATED,
                detected_at=date(2025, 11, 1),
            ),
            ValidationFinding(
                title="MED-1",
                description="x",
                severity=ValidationSeverity.MEDIUM,
                status=ValidationStatus.OPEN,
                detected_at=date(2025, 12, 5),
            ),
            ValidationFinding(
                title="LOW-1",
                description="x",
                severity=ValidationSeverity.LOW,
                status=ValidationStatus.ACCEPTED,
                detected_at=date(2025, 10, 1),
            ),
        ])
        out = generate_validation_report(m)
        # HIGH row: 1 open / 1 remediated / 0 / 0 / 2 total
        assert "| high | 1 | 1 | 0 | 0 | 2 |" in out
        # MEDIUM row: 1 / 0 / 0 / 0 / 1
        assert "| medium | 1 | 0 | 0 | 0 | 1 |" in out
        # LOW row: 0 / 0 / 1 / 0 / 1
        assert "| low | 0 | 0 | 1 | 0 | 1 |" in out
        # Grand totals: 2 open / 1 rem / 1 acc / 0 / 4
        assert "| **All** | **2** | 1 | 1 | 0 | **4** |" in out

    def test_high_open_warning_callout_renders_when_high_open(self) -> None:
        m = _model_with_findings([
            ValidationFinding(
                title="HIGH bias",
                description="x",
                severity=ValidationSeverity.HIGH,
                status=ValidationStatus.OPEN,
                detected_at=date(2025, 12, 1),
            ),
        ])
        out = generate_validation_report(m)
        assert "⚠️" in out
        assert "HIGH-severity findings open" in out

    def test_no_high_open_no_warning_callout(self) -> None:
        m = _model_with_findings([
            ValidationFinding(
                title="HIGH but remediated",
                description="x",
                severity=ValidationSeverity.HIGH,
                status=ValidationStatus.REMEDIATED,
                detected_at=date(2025, 11, 1),
            ),
            ValidationFinding(
                title="MED open",
                description="x",
                severity=ValidationSeverity.MEDIUM,
                status=ValidationStatus.OPEN,
                detected_at=date(2025, 12, 1),
            ),
        ])
        out = generate_validation_report(m)
        # Specifically the HIGH-open callout text should NOT appear
        assert "HIGH-severity findings open" not in out

    def test_remediation_narrative_renders_per_finding(self) -> None:
        m = _model_with_findings([
            ValidationFinding(
                title="Bias on protected class",
                description="Disparate impact on age >65 detected.",
                severity=ValidationSeverity.HIGH,
                status=ValidationStatus.OPEN,
                detected_at=date(2025, 12, 1),
                remediation_plan="Retrain with re-weighted samples by 2026-Q2",
            ),
        ])
        out = generate_validation_report(m)
        assert "## Remediation narrative" in out
        assert "Bias on protected class" in out
        assert "Disparate impact on age >65 detected." in out
        assert "Retrain with re-weighted samples" in out

    def test_no_remediation_plan_renders_placeholder(self) -> None:
        m = _model_with_findings([
            ValidationFinding(
                title="x",
                description="y",
                severity=ValidationSeverity.MEDIUM,
                detected_at=date(2025, 12, 1),
                # No remediation_plan
            ),
        ])
        out = generate_validation_report(m)
        assert "_None recorded_" in out

    def test_cadence_text_for_each_tier(self) -> None:
        for tier, expected in [
            (Tier.TIER_1, "annual"),
            (Tier.TIER_2, "biennial"),
            (Tier.TIER_3, "triennial"),
        ]:
            m = ModelInventory(
                name="x",
                purpose="x",
                methodology=Methodology.ML,
                vendor_or_internal=Provenance.INTERNAL,
                tier=tier,
                owner="a@b.com",
            )
            out = generate_validation_report(m)
            assert expected in out

    def test_render_is_deterministic_for_same_input(self) -> None:
        m = _model_with_findings([
            ValidationFinding(
                title="X",
                description="Y",
                severity=ValidationSeverity.MEDIUM,
                status=ValidationStatus.OPEN,
                detected_at=date(2025, 12, 1),
            ),
        ])
        a = generate_validation_report(m)
        b = generate_validation_report(m)
        assert a == b

    def test_model_id_appears_in_executive_summary(self) -> None:
        m = _model_with_findings([])
        out = generate_validation_report(m)
        assert m.id in out
