"""Unit tests for evidentia_core.models.model_risk (v0.7.10 P0.6.1)."""

from __future__ import annotations

from datetime import date

import pytest
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
from pydantic import ValidationError

# ── Helpers ────────────────────────────────────────────────────────


def _make_internal_model(
    *,
    name: str = "Test Internal Model",
    methodology: Methodology = Methodology.ML,
    tier: Tier = Tier.TIER_2,
    last_validation_date: date | None = None,
) -> ModelInventory:
    return ModelInventory(
        name=name,
        purpose="Test model purpose for unit tests",
        methodology=methodology,
        vendor_or_internal=Provenance.INTERNAL,
        tier=tier,
        owner="ml-team@example.com",
        last_validation_date=last_validation_date,
    )


# ── Enum sanity ─────────────────────────────────────────────────────


class TestEnums:
    def test_methodology_values(self) -> None:
        # Spot-check that the 6 documented methodology values are present
        values = {m.value for m in Methodology}
        assert "statistical" in values
        assert "ml" in values
        assert "rules_based" in values
        assert "llm" in values
        assert "expert_judgment" in values
        assert "hybrid" in values

    def test_tier_values(self) -> None:
        values = {t.value for t in Tier}
        assert values == {"tier_1", "tier_2", "tier_3"}

    def test_provenance_values(self) -> None:
        values = {p.value for p in Provenance}
        assert values == {"internal", "vendor"}

    def test_validation_severity_values(self) -> None:
        values = {s.value for s in ValidationSeverity}
        assert values == {"high", "medium", "low"}

    def test_validation_status_values(self) -> None:
        values = {s.value for s in ValidationStatus}
        assert values == {"open", "remediated", "accepted", "deferred"}


# ── Sub-model construction ─────────────────────────────────────────


class TestModelInput:
    def test_minimal_construction(self) -> None:
        i = ModelInput(name="x", source_system="snowflake")
        assert i.name == "x"
        assert i.source_system == "snowflake"
        assert i.transformation is None

    def test_full_construction(self) -> None:
        i = ModelInput(
            name="FICO score",
            source_system="experian-api",
            transformation="log-normalized",
            data_classification="PII",
            refresh_cadence="daily",
        )
        assert i.transformation == "log-normalized"
        assert i.data_classification == "PII"


class TestModelOutput:
    def test_minimal_construction(self) -> None:
        o = ModelOutput(name="approval", decision_type="binary classification")
        assert o.downstream_consumers == []

    def test_with_consumers(self) -> None:
        o = ModelOutput(
            name="risk score",
            decision_type="continuous",
            downstream_consumers=["loan-origination", "fraud-queue"],
        )
        assert len(o.downstream_consumers) == 2


class TestValidationFinding:
    def test_minimal(self) -> None:
        f = ValidationFinding(
            title="Bias on protected class",
            description="Model exhibited disparate impact on age >65",
            severity=ValidationSeverity.HIGH,
            detected_at=date(2026, 1, 15),
        )
        assert f.status == ValidationStatus.OPEN  # default
        assert f.id  # auto-generated UUID
        assert f.remediation_plan is None


# ── ModelInventory construction ────────────────────────────────────


class TestModelInventoryConstruction:
    def test_internal_model_minimal(self) -> None:
        m = _make_internal_model()
        assert m.id  # UUID v4 generated
        assert m.created_at is not None
        assert m.evidentia_version  # populated
        assert m.vendor_id is None
        assert m.next_validation_due is None  # no last_validation yet

    def test_vendor_model_requires_vendor_id(self) -> None:
        with pytest.raises(
            ValidationError,
            match="vendor-provenance models must set `vendor_id`",
        ):
            ModelInventory(
                name="Vendor model",
                purpose="x",
                methodology=Methodology.LLM,
                vendor_or_internal=Provenance.VENDOR,
                tier=Tier.TIER_2,
                owner="a@b.com",
            )

    def test_internal_model_rejects_vendor_id(self) -> None:
        with pytest.raises(
            ValidationError,
            match="internal-provenance models must not set `vendor_id`",
        ):
            ModelInventory(
                name="Internal model",
                purpose="x",
                methodology=Methodology.ML,
                vendor_or_internal=Provenance.INTERNAL,
                vendor_id="aaaa1111-2222-3333-4444-555566667777",
                tier=Tier.TIER_2,
                owner="a@b.com",
            )

    def test_vendor_model_with_vendor_id_succeeds(self) -> None:
        m = ModelInventory(
            name="Vendor LLM",
            purpose="LLM-driven control narratives",
            methodology=Methodology.LLM,
            vendor_or_internal=Provenance.VENDOR,
            vendor_id="aaaa1111-2222-3333-4444-555566667777",
            tier=Tier.TIER_2,
            owner="ai-team@example.com",
        )
        assert m.vendor_id == "aaaa1111-2222-3333-4444-555566667777"

    def test_extra_fields_rejected(self) -> None:
        # Pydantic extra="forbid" inherited from EvidentiaModel
        with pytest.raises(
            ValidationError, match="extra"
        ):
            ModelInventory(
                name="x",
                purpose="x",
                methodology=Methodology.ML,
                vendor_or_internal=Provenance.INTERNAL,
                tier=Tier.TIER_2,
                owner="a@b.com",
                bogus_field="should be rejected",  # type: ignore[call-arg]
            )


# ── compute_next_validation_due cadence ─────────────────────────────


class TestComputeNextValidationDue:
    def test_returns_none_when_no_last_validation(self) -> None:
        m = _make_internal_model()
        assert m.compute_next_validation_due() is None

    def test_tier_1_annual(self) -> None:
        m = _make_internal_model(
            tier=Tier.TIER_1,
            last_validation_date=date(2025, 6, 15),
        )
        assert m.compute_next_validation_due() == date(2026, 6, 15)

    def test_tier_2_biennial(self) -> None:
        m = _make_internal_model(
            tier=Tier.TIER_2,
            last_validation_date=date(2025, 6, 15),
        )
        assert m.compute_next_validation_due() == date(2027, 6, 15)

    def test_tier_3_triennial(self) -> None:
        m = _make_internal_model(
            tier=Tier.TIER_3,
            last_validation_date=date(2025, 6, 15),
        )
        assert m.compute_next_validation_due() == date(2028, 6, 15)

    def test_leap_year_clamp(self) -> None:
        # Tier 1 = 12 months. Anchor on Feb 29, 2024 (leap year).
        # Next validation should clamp to Feb 28, 2025 (non-leap).
        m = _make_internal_model(
            tier=Tier.TIER_1,
            last_validation_date=date(2024, 2, 29),
        )
        assert m.compute_next_validation_due() == date(2025, 2, 28)

    def test_leap_year_to_leap_year(self) -> None:
        # Tier 2 = 24 months = 2 years. Anchor Feb 29, 2024 (leap)
        # → Feb 29, 2026 (NOT leap; clamp to Feb 28).
        m = _make_internal_model(
            tier=Tier.TIER_2,
            last_validation_date=date(2024, 2, 29),
        )
        # 2026 is not a leap year — clamp to Feb 28
        assert m.compute_next_validation_due() == date(2026, 2, 28)


# ── Integration: full ModelInventory with all sub-models ───────────


class TestFullModelInventory:
    def test_with_inputs_outputs_findings(self) -> None:
        m = ModelInventory(
            name="FICO scorer v3",
            purpose="Score consumer credit applications",
            methodology=Methodology.ML,
            vendor_or_internal=Provenance.INTERNAL,
            tier=Tier.TIER_1,
            owner="ml-team@example.com",
            inputs=[
                ModelInput(name="FICO", source_system="experian"),
                ModelInput(name="History", source_system="snowflake"),
            ],
            outputs=[
                ModelOutput(
                    name="approval probability",
                    decision_type="binary classification",
                    downstream_consumers=["loan-origination"],
                ),
            ],
            validation_findings=[
                ValidationFinding(
                    title="Open finding",
                    description="x",
                    severity=ValidationSeverity.MEDIUM,
                    detected_at=date(2025, 12, 1),
                ),
            ],
            last_validation_date=date(2025, 12, 1),
            retirement_plan="Replace with v4 by 2027 Q1",
            notes="High-stakes Tier-1 model under continuous monitoring",
        )
        assert len(m.inputs) == 2
        assert len(m.outputs) == 1
        assert len(m.validation_findings) == 1
        # Tier 1 + last 2025-12-01 → annual cadence → 2026-12-01
        assert m.compute_next_validation_due() == date(2026, 12, 1)
