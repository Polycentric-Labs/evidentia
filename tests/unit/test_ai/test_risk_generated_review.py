"""Generated risk drafts cannot carry model-authored human decisions."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from evidentia_ai.risk_statements import generator as generator_module
from evidentia_ai.risk_statements.templates import SystemContext
from evidentia_core.audit import GenerationContext
from evidentia_core.models.gap import ControlGap, GapSeverity, ImplementationEffort
from evidentia_core.models.risk import (
    ImpactRating,
    LikelihoodRating,
    RiskLevel,
    RiskRegister,
    RiskStatement,
    RiskTreatment,
)


def model_authored_risk(treatment: RiskTreatment) -> RiskStatement:
    # These fields are schema-valid but do not prove a human took any action.
    return RiskStatement(
        id="synthetic-risk-id",
        asset="Synthetic service",
        threat_source="External attacker",
        threat_event="Use an inactive account",
        vulnerability="Inactive accounts remain enabled",
        likelihood=LikelihoodRating.HIGH,
        likelihood_rationale="An inactive account still has access",
        impact=ImpactRating.HIGH,
        impact_rationale="The account can read sensitive records",
        risk_level=RiskLevel.HIGH,
        risk_description="Inactive accounts could expose sensitive records",
        recommended_controls=["AC-2"],
        remediation_steps=["Disable inactive accounts"],
        remediation_priority=2,
        treatment=treatment,
        treatment_rationale="The model claims this decision was authorized",
        accepted=True,
        reviewed_by="synthetic-reviewer",
        reviewed_at=datetime(2000, 1, 1, tzinfo=UTC),
        generated_by="synthetic-human-author",
        generated_at=datetime(2000, 1, 1, tzinfo=UTC),
        model_inventory_ref="synthetic-model-invented-binding",
        tags=["preserve-analytic-tag"],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("treatment", list(RiskTreatment))
@pytest.mark.parametrize("inventory", [None, "operator-selected-model-inventory"])
async def test_generation_returns_unreviewed_draft_and_preserves_analysis(
    mode: str, treatment: RiskTreatment, inventory: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    risk = model_authored_risk(treatment)
    authority_fields = {
        "accepted",
        "reviewed_by",
        "reviewed_at",
        "treatment",
        "treatment_rationale",
        "generated_by",
        "generated_at",
        "model_inventory_ref",
        "source_gap_id",
        "model_used",
        "framework_mappings",
        "generation_context",
    }
    original_content = risk.model_dump(mode="json", exclude=authority_fields)
    gap = ControlGap(
        id="trusted-gap",
        framework="nist-800-53-rev5",
        control_id="AC-2",
        control_title="Account Management",
        control_description="Manage account access",
        gap_severity=GapSeverity.HIGH,
        gap_description="Inactive accounts remain enabled",
        implementation_status="missing",
        cross_framework_value=["soc2-tsc:CC6.1"],
        remediation_guidance="Disable inactive accounts",
        implementation_effort=ImplementationEffort.MEDIUM,
    )
    context = SystemContext(
        organization="Synthetic organization",
        system_name="Synthetic service",
        system_description="Synthetic test system",
        hosting="Local test environment",
    )
    provenance = GenerationContext(
        model="ollama_chat/llama3.3",
        temperature=0.1,
        prompt_hash="0" * 64,
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        credential_identity="synthetic-operator",
    )
    monkeypatch.setattr(generator_module, "get_instructor_client", MagicMock())
    generator = generator_module.RiskStatementGenerator(model=provenance.model, model_inventory_id=inventory)
    sync, asynchronous = MagicMock(return_value=(risk, 1)), AsyncMock(return_value=(risk, 1))
    monkeypatch.setattr(generator, "_invoke_llm_sync", sync)
    monkeypatch.setattr(generator, "_invoke_llm_async", asynchronous)
    monkeypatch.setattr(generator, "_build_generation_context", MagicMock(return_value=provenance))
    monkeypatch.setattr(generator, "_emit_success", MagicMock())
    if mode == "sync":
        result = generator.generate(gap, context)
        sync.assert_called_once()
        asynchronous.assert_not_called()
    else:
        result = await generator.generate_async(gap, context)
        asynchronous.assert_awaited_once()
        sync.assert_not_called()

    assert result.accepted is False
    assert result.reviewed_by is None
    assert result.reviewed_at is None
    assert result.treatment == RiskTreatment.PENDING
    assert result.treatment_rationale is None
    assert result.generated_by == "evidentia-ai"
    assert result.generated_at == provenance.generated_at
    assert result.model_inventory_ref == inventory
    assert result.source_gap_id == gap.id
    assert result.model_used == provenance.model
    assert result.generation_context == provenance
    assert result.framework_mappings == ["nist-800-53-rev5:AC-2", "soc2-tsc:CC6.1"]
    assert result.model_dump(mode="json", exclude=authority_fields) == original_content
    # API and CLI serialization must keep the reset state, and register
    # counters must see a pending draft instead of a completed human review.
    roundtrip = RiskStatement.model_validate_json(result.model_dump_json())
    register = RiskRegister(organization="Synthetic organization", system_name="Synthetic service", risks=[roundtrip])
    assert register.accepted_count == 0
    assert register.pending_review_count == 1


def test_existing_human_reviewed_records_still_deserialize() -> None:
    risk = model_authored_risk(RiskTreatment.ACCEPT)
    restored = RiskStatement.model_validate_json(risk.model_dump_json())
    assert restored.accepted is True
    assert restored.reviewed_by == risk.reviewed_by
    assert restored.reviewed_at == risk.reviewed_at
    assert restored.treatment == RiskTreatment.ACCEPT
