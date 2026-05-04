"""Unit tests for evidentia_core.risk_quant.open_fair (v0.7.11 P1.5 G4)."""

from __future__ import annotations

import pytest
from evidentia_core.risk_quant import (
    OpenFAIRScenario,
    PERTRange,
    compute_ale,
    compute_loss_magnitude,
    generate_risk_quantification_report,
)
from evidentia_core.risk_quant.open_fair import (
    RiskCategory,
    categorize_risk,
    compute_lef,
)
from pydantic import ValidationError

# ── PERTRange ──────────────────────────────────────────────────────


class TestPERTRange:
    def test_construct_valid_ordering(self) -> None:
        r = PERTRange(low=10, most_likely=50, high=200)
        assert r.low == 10
        assert r.most_likely == 50
        assert r.high == 200

    def test_construct_rejects_inverted_ordering(self) -> None:
        with pytest.raises(ValidationError):
            PERTRange(low=200, most_likely=50, high=10)

    def test_construct_rejects_negative_low(self) -> None:
        with pytest.raises(ValidationError):
            PERTRange(low=-1, most_likely=50, high=100)

    def test_construct_accepts_equal_values(self) -> None:
        # Degenerate but valid — operator hasn't yet refined
        r = PERTRange(low=100, most_likely=100, high=100)
        assert r.mean() == 100

    def test_mean_pert_formula(self) -> None:
        # E[X] = (low + 4*most_likely + high) / 6
        r = PERTRange(low=10, most_likely=50, high=200)
        assert abs(r.mean() - (10 + 200 + 50 * 4) / 6) < 1e-9


# ── OpenFAIRScenario construction ──────────────────────────────────


def _scalar_scenario(**overrides: object) -> OpenFAIRScenario:
    base: dict[str, object] = {
        "name": "Credential stuffing",
        "description": "External attackers reuse leaked credentials.",
        "tef": 365.0,
        "vulnerability": 0.001,
        "primary_loss": 5000.0,
        "secondary_loss": 50000.0,
    }
    base.update(overrides)
    return OpenFAIRScenario.model_validate(base)


class TestOpenFAIRScenario:
    def test_minimal_scalar_construction(self) -> None:
        s = _scalar_scenario()
        assert s.id  # auto-UUID

    def test_pert_range_for_factor(self) -> None:
        s = _scalar_scenario(
            tef=PERTRange(low=100, most_likely=300, high=1000)
        )
        # Actually loaded as PERTRange via Pydantic discrimination
        assert isinstance(s.tef, PERTRange | dict)


# ── compute_lef / compute_loss_magnitude / compute_ale ─────────────


class TestComputeFAIRFactors:
    def test_scalar_lef(self) -> None:
        s = _scalar_scenario(tef=100, vulnerability=0.05)
        assert compute_lef(s) == 5.0

    def test_scalar_loss_magnitude(self) -> None:
        s = _scalar_scenario(primary_loss=5000, secondary_loss=50000)
        assert compute_loss_magnitude(s) == 55000.0

    def test_scalar_ale(self) -> None:
        s = _scalar_scenario(
            tef=100,
            vulnerability=0.05,
            primary_loss=5000,
            secondary_loss=50000,
        )
        # LEF=5, LM=55000 → ALE=275000
        assert compute_ale(s) == 275_000.0

    def test_pert_factors_resolve_to_mean(self) -> None:
        s = _scalar_scenario(
            tef=PERTRange(low=10, most_likely=20, high=30),
            vulnerability=0.1,
            primary_loss=PERTRange(low=1000, most_likely=2000, high=3000),
            secondary_loss=0,
        )
        # TEF mean = (10 + 80 + 30)/6 = 20
        # PrimLoss mean = (1000 + 8000 + 3000)/6 = 2000
        # LEF = 20 * 0.1 = 2.0
        # LM = 2000
        # ALE = 4000
        assert compute_ale(s) == pytest.approx(4000.0)


# ── categorize_risk ────────────────────────────────────────────────


class TestCategorizeRisk:
    @pytest.mark.parametrize("ale,expected", [
        (15_000_000, RiskCategory.SEVERE),
        (5_000_000, RiskCategory.HIGH),
        (500_000, RiskCategory.SIGNIFICANT),
        (50_000, RiskCategory.MODERATE),
        (5_000, RiskCategory.LOW),
        (0, RiskCategory.LOW),
    ])
    def test_band_boundaries(self, ale: float, expected: RiskCategory) -> None:
        assert categorize_risk(ale) == expected


# ── generate_risk_quantification_report ───────────────────────────


class TestGenerateReport:
    def test_empty_scenarios_renders_minimal(self) -> None:
        out = generate_risk_quantification_report([])
        assert "No scenarios defined" in out

    def test_single_scenario_report(self) -> None:
        s = _scalar_scenario()
        out = generate_risk_quantification_report([s])
        assert "FAIR Risk Quantification Report" in out
        assert "Credential stuffing" in out
        assert "TEF" in out
        assert "Vulnerability" in out
        assert "ALE" in out

    def test_total_ale_in_summary(self) -> None:
        # Two scenarios: ALE = (1000 * 0.1 * 1000) + (10 * 0.5 * 5000)
        #              = 100,000 + 25,000 = 125,000
        s1 = _scalar_scenario(
            name="S1", tef=1000, vulnerability=0.1,
            primary_loss=1000, secondary_loss=0,
        )
        s2 = _scalar_scenario(
            name="S2", tef=10, vulnerability=0.5,
            primary_loss=5000, secondary_loss=0,
        )
        out = generate_risk_quantification_report([s1, s2])
        assert "$125.0k" in out

    def test_category_distribution_table(self) -> None:
        out = generate_risk_quantification_report([_scalar_scenario()])
        assert "| severe | 0 |" in out
        assert "| moderate | 1 |" in out  # ALE = 365 * 0.001 * 55000 = ~20k

    def test_render_is_deterministic(self) -> None:
        s = _scalar_scenario()
        a = generate_risk_quantification_report([s])
        b = generate_risk_quantification_report([s])
        # Same scenario instance — output must be identical
        assert a == b

    def test_per_scenario_sorted_by_ale_descending(self) -> None:
        # high-ALE first
        big = _scalar_scenario(
            name="BIG", tef=1000, vulnerability=1.0,
            primary_loss=1_000_000, secondary_loss=0,
        )
        small = _scalar_scenario(
            name="SMALL", tef=1, vulnerability=0.001,
            primary_loss=1, secondary_loss=0,
        )
        out = generate_risk_quantification_report([small, big])
        # BIG should appear before SMALL in the output
        assert out.index("BIG") < out.index("SMALL")
