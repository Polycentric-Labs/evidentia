"""Unit tests for evidentia_core.ai_governance.classification (v0.9.3 P2.3)."""

from __future__ import annotations

from evidentia_core.ai_governance import (
    AISystemDescriptor,
    AnnexIIIDomain,
    EUAIActTier,
    NISTAIRMFFunction,
    classify,
)


class TestEUAIActTier:
    def test_prohibited_practice_returns_unacceptable(self) -> None:
        d = AISystemDescriptor(
            name="social-credit-score",
            purpose="Score citizens by behavior",
            is_prohibited_practice=True,
        )
        result = classify(d)
        assert result.eu_ai_act_tier == EUAIActTier.UNACCEPTABLE
        assert any("Article 5" in r for r in result.rationale)

    def test_annex_iii_domain_returns_high(self) -> None:
        d = AISystemDescriptor(
            name="resume-screener",
            purpose="Score job applicants for HR review",
            annex_iii_domain=AnnexIIIDomain.EMPLOYMENT,
        )
        result = classify(d)
        assert result.eu_ai_act_tier == EUAIActTier.HIGH
        assert any("employment" in r.lower() for r in result.rationale)

    def test_interacts_returns_limited(self) -> None:
        d = AISystemDescriptor(
            name="customer-chatbot",
            purpose="Answer FAQ-style customer questions",
            interacts_with_natural_persons=True,
        )
        result = classify(d)
        assert result.eu_ai_act_tier == EUAIActTier.LIMITED
        assert any("Article 50" in r for r in result.rationale)

    def test_generates_synthetic_returns_limited(self) -> None:
        d = AISystemDescriptor(
            name="image-generator",
            purpose="Generate marketing images from text prompts",
            generates_synthetic_content=True,
        )
        result = classify(d)
        assert result.eu_ai_act_tier == EUAIActTier.LIMITED
        assert any("synthetic" in r.lower() for r in result.rationale)

    def test_default_descriptor_returns_minimal(self) -> None:
        d = AISystemDescriptor(
            name="spam-filter",
            purpose="Internal email spam classification",
        )
        result = classify(d)
        assert result.eu_ai_act_tier == EUAIActTier.MINIMAL
        assert any("MINIMAL" in r for r in result.rationale)

    def test_prohibited_overrides_annex_iii(self) -> None:
        # If both prohibited + annex III are set, UNACCEPTABLE wins.
        d = AISystemDescriptor(
            name="banned-biometric",
            purpose="Real-time facial recognition in public spaces",
            is_prohibited_practice=True,
            annex_iii_domain=AnnexIIIDomain.BIOMETRICS,
        )
        result = classify(d)
        assert result.eu_ai_act_tier == EUAIActTier.UNACCEPTABLE


class TestNISTAIRMFOrdering:
    def test_high_tier_prioritizes_govern_then_map(self) -> None:
        d = AISystemDescriptor(
            name="credit-scorer",
            purpose="Decide consumer credit applications",
            annex_iii_domain=AnnexIIIDomain.ESSENTIAL_SERVICES,
        )
        result = classify(d)
        assert result.applicable_nist_ai_rmf_functions[0] == (
            NISTAIRMFFunction.GOVERN
        )
        assert result.applicable_nist_ai_rmf_functions[1] == (
            NISTAIRMFFunction.MAP
        )

    def test_automated_role_prioritizes_measure(self) -> None:
        d = AISystemDescriptor(
            name="auto-refund",
            purpose="Auto-approve customer refunds under $100",
            decision_role="automated",  # type: ignore[arg-type]
        )
        result = classify(d)
        assert result.applicable_nist_ai_rmf_functions[0] == (
            NISTAIRMFFunction.MEASURE
        )

    def test_advisory_role_prioritizes_map(self) -> None:
        d = AISystemDescriptor(
            name="advisor",
            purpose="Suggest treatment options for clinician review",
        )
        result = classify(d)
        assert result.applicable_nist_ai_rmf_functions[0] == (
            NISTAIRMFFunction.MAP
        )

    def test_all_four_functions_always_present(self) -> None:
        d = AISystemDescriptor(name="x", purpose="y")
        result = classify(d)
        assert set(result.applicable_nist_ai_rmf_functions) == {
            NISTAIRMFFunction.GOVERN,
            NISTAIRMFFunction.MAP,
            NISTAIRMFFunction.MEASURE,
            NISTAIRMFFunction.MANAGE,
        }


class TestClassificationOutput:
    def test_disclaimer_present(self) -> None:
        d = AISystemDescriptor(name="x", purpose="y")
        result = classify(d)
        assert "informational starting point" in result.disclaimer
        assert "legal compliance determination" in result.disclaimer

    def test_descriptor_name_echoed(self) -> None:
        d = AISystemDescriptor(name="my-system", purpose="y")
        result = classify(d)
        assert result.descriptor_name == "my-system"

    def test_rationale_nonempty(self) -> None:
        d = AISystemDescriptor(name="x", purpose="y")
        result = classify(d)
        assert len(result.rationale) >= 1
