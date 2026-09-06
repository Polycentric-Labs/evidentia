"""Tests for priority-score math in GapAnalyzer._compute_priority (v0.2.1 D7).

Covers every severity × effort × cross-fw-count combination so future
changes to the weighting table or cross-fw bonus multiplier get caught
in CI rather than silently shifting every report's ranking.
"""

from __future__ import annotations

import pytest
from evidentia_core.gap_analyzer.analyzer import (
    EFFORT_WEIGHT,
    SEVERITY_WEIGHT,
    GapAnalyzer,
)
from evidentia_core.models.gap import ControlGap, GapSeverity, ImplementationEffort


def _gap(
    sev: GapSeverity,
    effort: ImplementationEffort,
    cross_fw_count: int = 0,
) -> ControlGap:
    """Build a minimal ControlGap fixture."""
    return ControlGap(
        framework="fw",
        control_id="AC-2",
        control_title="Test Control",
        control_description="Test description.",
        gap_severity=sev,
        implementation_status="missing",
        gap_description="Control is missing.",
        remediation_guidance="Implement it.",
        implementation_effort=effort,
        cross_framework_value=[f"other:ctrl-{i}" for i in range(cross_fw_count)],
    )


@pytest.mark.parametrize("severity", list(GapSeverity))
@pytest.mark.parametrize("effort", list(ImplementationEffort))
@pytest.mark.parametrize("cross_fw", [0, 1, 3, 5])
def test_priority_matches_formula(severity: GapSeverity, effort: ImplementationEffort, cross_fw: int) -> None:
    """Priority score matches the documented formula exactly.

    Formula: severity_weight × (1 + 0.2 × cross_fw_count) × (1 / effort_weight)
    """
    analyzer = GapAnalyzer()
    gap = _gap(severity, effort, cross_fw_count=cross_fw)
    actual = analyzer._compute_priority(gap)

    expected = round(
        SEVERITY_WEIGHT[severity] * (1 + 0.2 * cross_fw) * (1 / EFFORT_WEIGHT[effort]),
        3,
    )
    assert actual == pytest.approx(expected, rel=1e-9), (
        f"Formula mismatch for sev={severity} effort={effort} cross_fw={cross_fw}"
    )


def test_critical_severity_wins_over_high() -> None:
    """Critical gap with same effort should outrank a High gap."""
    a = GapAnalyzer()
    crit = _gap(GapSeverity.CRITICAL, ImplementationEffort.MEDIUM)
    high = _gap(GapSeverity.HIGH, ImplementationEffort.MEDIUM)
    assert a._compute_priority(crit) > a._compute_priority(high)


def test_easy_win_ranks_above_hard_with_same_severity() -> None:
    """Given equal severity & cross-fw, LOW effort outranks VERY_HIGH."""
    a = GapAnalyzer()
    easy = _gap(GapSeverity.HIGH, ImplementationEffort.LOW)
    hard = _gap(GapSeverity.HIGH, ImplementationEffort.VERY_HIGH)
    assert a._compute_priority(easy) > a._compute_priority(hard)


def test_cross_framework_bonus_is_20_percent_per_framework() -> None:
    """Each cross_framework_value entry adds 20% to the base severity × effort product."""
    a = GapAnalyzer()
    base = _gap(GapSeverity.HIGH, ImplementationEffort.MEDIUM, cross_fw_count=0)
    bonus_1 = _gap(GapSeverity.HIGH, ImplementationEffort.MEDIUM, cross_fw_count=1)
    bonus_5 = _gap(GapSeverity.HIGH, ImplementationEffort.MEDIUM, cross_fw_count=5)

    # Base: 3.0 * (1 + 0) * (1/2) = 1.5
    # bonus_1: 3.0 * (1 + 0.2) * (1/2) = 1.8
    # bonus_5: 3.0 * (1 + 1.0) * (1/2) = 3.0
    assert a._compute_priority(base) == pytest.approx(1.5)
    assert a._compute_priority(bonus_1) == pytest.approx(1.8)
    assert a._compute_priority(bonus_5) == pytest.approx(3.0)


def test_informational_gaps_rank_lowest() -> None:
    """GapSeverity.INFORMATIONAL should produce the smallest priority value
    for equal effort + cross-fw."""
    a = GapAnalyzer()
    info = _gap(GapSeverity.INFORMATIONAL, ImplementationEffort.MEDIUM)
    low = _gap(GapSeverity.LOW, ImplementationEffort.MEDIUM)
    assert a._compute_priority(info) < a._compute_priority(low)


def test_priority_is_rounded_to_three_decimals() -> None:
    """Display layer assumes 3-decimal priority — regression guard."""
    a = GapAnalyzer()
    # Construct a combination that doesn't cleanly round: severity=3.0
    # * (1 + 0.2 * 1) * (1/4) = 0.9 exactly — pick one that DOES round.
    # 3.0 * 1.4 * (1/8) = 0.525 exactly. Test with cross_fw=2: 3.0 * 1.4 * 1/8 = 0.525
    gap = _gap(GapSeverity.HIGH, ImplementationEffort.VERY_HIGH, cross_fw_count=2)
    score = a._compute_priority(gap)
    # Must be representable in 3 decimal places
    assert abs(score - round(score, 3)) < 1e-9
