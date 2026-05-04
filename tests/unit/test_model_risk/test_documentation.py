"""Unit tests for evidentia_core.model_risk.documentation (v0.7.10 P0.6.2)."""

from __future__ import annotations

from datetime import date

from evidentia_core.model_risk import generate_model_documentation
from evidentia_core.models.model_risk import (
    Methodology,
    ModelInput,
    ModelInventory,
    ModelOutput,
    Provenance,
    Tier,
    ValidationFinding,
    ValidationSeverity,
    ValidationStatus,
)


def _minimal() -> ModelInventory:
    return ModelInventory(
        name="Test Model",
        purpose="Test model purpose for unit tests",
        methodology=Methodology.ML,
        vendor_or_internal=Provenance.INTERNAL,
        tier=Tier.TIER_2,
        owner="ml-team@example.com",
    )


class TestGenerateModelDocumentation:
    def test_minimal_model_renders_all_sections(self) -> None:
        m = _minimal()
        out = generate_model_documentation(m)
        # All 9 numbered sections present
        for section in (
            "## 1. Identification",
            "## 2. Purpose and intended use",
            "## 3. Methodology and design",
            "## 4. Inputs",
            "## 5. Outputs",
            "## 6. Assumptions and limitations",
            "## 7. Validation history",
            "## 8. Monitoring and retirement plan",
            "## 9. Audit trail",
        ):
            assert section in out, f"missing section: {section}"

    def test_renders_model_id_in_audit_trail(self) -> None:
        m = _minimal()
        out = generate_model_documentation(m)
        assert m.id in out
        # The ID must appear specifically in the audit-trail section
        # so the SR 11-7 / SR 26-02 trace-back narrative is concrete.
        audit_section = out.split("## 9. Audit trail")[1]
        assert m.id in audit_section

    def test_tier_narrative_for_tier_1(self) -> None:
        m = ModelInventory(
            name="Tier 1 model",
            purpose="x",
            methodology=Methodology.ML,
            vendor_or_internal=Provenance.INTERNAL,
            tier=Tier.TIER_1,
            owner="a@b.com",
        )
        out = generate_model_documentation(m)
        # Tier 1 narrative mentions "HIGH materiality" + "annual"
        assert "HIGH materiality" in out
        assert "annual" in out

    def test_tier_narrative_for_tier_3(self) -> None:
        m = ModelInventory(
            name="Tier 3 model",
            purpose="x",
            methodology=Methodology.RULES_BASED,
            vendor_or_internal=Provenance.INTERNAL,
            tier=Tier.TIER_3,
            owner="a@b.com",
        )
        out = generate_model_documentation(m)
        assert "LOW materiality" in out
        assert "triennial" in out

    def test_inputs_table_renders_all_inputs(self) -> None:
        m = ModelInventory(
            name="With inputs",
            purpose="x",
            methodology=Methodology.ML,
            vendor_or_internal=Provenance.INTERNAL,
            tier=Tier.TIER_2,
            owner="a@b.com",
            inputs=[
                ModelInput(name="FICO", source_system="experian"),
                ModelInput(
                    name="History", source_system="snowflake",
                    transformation="log-normalized",
                ),
            ],
        )
        out = generate_model_documentation(m)
        assert "| FICO | experian" in out
        assert "| History | snowflake | log-normalized" in out

    def test_no_inputs_renders_placeholder_text(self) -> None:
        m = _minimal()
        out = generate_model_documentation(m)
        assert "No inputs recorded" in out

    def test_outputs_with_consumers(self) -> None:
        m = ModelInventory(
            name="With outputs",
            purpose="x",
            methodology=Methodology.ML,
            vendor_or_internal=Provenance.INTERNAL,
            tier=Tier.TIER_2,
            owner="a@b.com",
            outputs=[
                ModelOutput(
                    name="approval prob",
                    decision_type="binary classification",
                    downstream_consumers=["loan-origination", "fraud-queue"],
                ),
            ],
        )
        out = generate_model_documentation(m)
        assert "loan-origination, fraud-queue" in out

    def test_findings_table_renders_findings(self) -> None:
        m = ModelInventory(
            name="With findings",
            purpose="x",
            methodology=Methodology.ML,
            vendor_or_internal=Provenance.INTERNAL,
            tier=Tier.TIER_2,
            owner="a@b.com",
            last_validation_date=date(2025, 6, 15),
            validation_findings=[
                ValidationFinding(
                    title="Fairness bias finding",
                    description="x",
                    severity=ValidationSeverity.HIGH,
                    status=ValidationStatus.OPEN,
                    detected_at=date(2025, 7, 1),
                ),
            ],
        )
        out = generate_model_documentation(m)
        assert "Fairness bias finding" in out
        assert "high" in out  # severity rendered

    def test_no_findings_renders_cadence_narrative(self) -> None:
        m = _minimal()
        out = generate_model_documentation(m)
        # SR 11-7-aligned narrative when no findings yet
        assert "No validation findings recorded yet" in out

    def test_render_is_deterministic_for_same_input(self) -> None:
        m = _minimal()
        a = generate_model_documentation(m)
        b = generate_model_documentation(m)
        assert a == b

    def test_evidentia_version_appears_in_header(self) -> None:
        m = _minimal()
        out = generate_model_documentation(m)
        assert m.evidentia_version in out
