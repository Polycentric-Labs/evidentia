"""Tests for the hybrid effort estimator (v0.2.1 D1)."""

from __future__ import annotations

import pytest
from evidentia_core.gap_analyzer.analyzer import (
    _HIGH_EFFORT_KEYWORDS,
    _MEDIUM_EFFORT_KEYWORDS,
    GapAnalyzer,
)
from evidentia_core.models.catalog import CatalogControl
from evidentia_core.models.gap import ImplementationEffort

# -----------------------------------------------------------------------------
# Layer 1: structural complexity score still dominates when present
# -----------------------------------------------------------------------------


def _ctrl(id_: str, description: str = "", n_enhancements: int = 0, n_objectives: int = 0) -> CatalogControl:
    """Build a minimal control with configurable structural complexity."""
    enhancements = [
        CatalogControl(id=f"{id_}({i + 1})", title=f"Enh {i + 1}", description="enh") for i in range(n_enhancements)
    ]
    return CatalogControl(
        id=id_,
        title=f"Title for {id_}",
        description=description,
        enhancements=enhancements,
        assessment_objectives=[f"obj-{i}" for i in range(n_objectives)],
    )


@pytest.mark.parametrize(
    "n_enh,n_obj,expected",
    [
        (10, 0, ImplementationEffort.VERY_HIGH),
        (0, 10, ImplementationEffort.VERY_HIGH),
        (5, 5, ImplementationEffort.VERY_HIGH),
        (5, 0, ImplementationEffort.HIGH),
        (0, 5, ImplementationEffort.HIGH),
        (3, 2, ImplementationEffort.HIGH),
        (2, 0, ImplementationEffort.MEDIUM),
        (0, 2, ImplementationEffort.MEDIUM),
        (1, 1, ImplementationEffort.MEDIUM),
        # Falls through to layer-2 / layer-3 when < 2
        (1, 0, ImplementationEffort.LOW),
        (0, 0, ImplementationEffort.LOW),
    ],
)
def test_structural_score_dominates(n_enh: int, n_obj: int, expected: ImplementationEffort) -> None:
    """When enhancements + assessment_objectives >= 2 the structural layer wins."""
    analyzer = GapAnalyzer()
    ctrl = _ctrl("AC-2", description="", n_enhancements=n_enh, n_objectives=n_obj)
    assert analyzer._estimate_effort(ctrl) == expected


# -----------------------------------------------------------------------------
# Layer 2: keyword fallback when structural score is zero
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("keyword", _HIGH_EFFORT_KEYWORDS)
def test_every_high_effort_keyword_resolves_to_high(keyword: str) -> None:
    """Every high-effort keyword in its own control description triggers HIGH."""
    analyzer = GapAnalyzer()
    ctrl = _ctrl("X", description=f"Implement {keyword} for all production systems.")
    assert analyzer._estimate_effort(ctrl) == ImplementationEffort.HIGH


@pytest.mark.parametrize("keyword", _MEDIUM_EFFORT_KEYWORDS)
def test_every_medium_effort_keyword_resolves_to_medium(keyword: str) -> None:
    """Every medium-effort keyword (not overshadowed by a high one) triggers MEDIUM."""
    analyzer = GapAnalyzer()
    # Ensure no high keyword accidentally present in the sentence
    ctrl = _ctrl("X", description=f"Establish a formal {keyword} for handling requests.")
    result = analyzer._estimate_effort(ctrl)
    # HIGH keywords get priority. The test is valid only when this control's
    # description doesn't contain a HIGH keyword.
    if any(kw in ctrl.description.lower() for kw in _HIGH_EFFORT_KEYWORDS):
        assert result == ImplementationEffort.HIGH
    else:
        assert result == ImplementationEffort.MEDIUM


def test_high_keyword_takes_precedence_over_medium() -> None:
    """A description with both kinds of keywords resolves to HIGH."""
    analyzer = GapAnalyzer()
    ctrl = _ctrl(
        "AC-2",
        description="Review policy for cryptographic controls monthly.",
    )
    assert analyzer._estimate_effort(ctrl) == ImplementationEffort.HIGH


# -----------------------------------------------------------------------------
# Layer 3: description-length fallback
# -----------------------------------------------------------------------------


def test_long_bare_description_resolves_to_medium() -> None:
    """A description > 400 chars without any keywords falls back to MEDIUM."""
    analyzer = GapAnalyzer()
    # ~450 char description with no effort-indicating keywords. Using simple
    # filler words that don't hit HIGH or MEDIUM keyword lists.
    long_text = (
        "The organization shall establish mechanisms that ensure continued "
        "availability across all tiers of the system. This includes redundant "
        "infrastructure, failover testing, geographic distribution across "
        "multiple data centers, regular verification of disaster recovery "
        "capabilities, and comprehensive service-level agreements with "
        "downstream providers. Each component shall be individually verified "
        "annually as part of the broader business continuity program."
    )
    assert len(long_text) > 400
    # Guard: none of our HIGH/MEDIUM keywords present
    for kw in (*_HIGH_EFFORT_KEYWORDS, *_MEDIUM_EFFORT_KEYWORDS):
        assert kw not in long_text.lower(), f"Test fixture accidentally contains effort keyword {kw!r}"
    ctrl = _ctrl("X", description=long_text)
    assert analyzer._estimate_effort(ctrl) == ImplementationEffort.MEDIUM


def test_short_bare_description_resolves_to_low() -> None:
    """Short description, zero structural signals, no keywords → LOW."""
    analyzer = GapAnalyzer()
    ctrl = _ctrl("X", description="Maintain signage at facility entrances.")
    assert analyzer._estimate_effort(ctrl) == ImplementationEffort.LOW


def test_empty_description_resolves_to_low() -> None:
    """Defensive: None or empty description never crashes."""
    analyzer = GapAnalyzer()
    ctrl = _ctrl("X", description="")
    assert analyzer._estimate_effort(ctrl) == ImplementationEffort.LOW


# -----------------------------------------------------------------------------
# Real-control sanity checks against canonical NIST controls
# -----------------------------------------------------------------------------


def test_known_high_effort_nist_control() -> None:
    """AC-3 Access Enforcement — description mentions 'authentication' (HIGH keyword)."""
    analyzer = GapAnalyzer()
    ctrl = _ctrl(
        "AC-3",
        description=(
            "Enforce approved authorizations for logical access to information "
            "and system resources in accordance with applicable access control "
            "policies and authentication requirements."
        ),
    )
    assert analyzer._estimate_effort(ctrl) == ImplementationEffort.HIGH


def test_known_medium_effort_policy_control() -> None:
    """AT-1 Policy and Procedures — description emphasizes 'policy' and 'procedure'."""
    analyzer = GapAnalyzer()
    ctrl = _ctrl(
        "AT-1",
        description=(
            "Develop, document, and disseminate to designated personnel an "
            "awareness and training policy and procedure for implementation."
        ),
    )
    assert analyzer._estimate_effort(ctrl) == ImplementationEffort.MEDIUM


def test_never_returns_all_low_on_varied_descriptions() -> None:
    """Regression guard: the v0.2.0 bug was every gap scoring LOW.

    With varied-content descriptions, at least 3 distinct effort tiers
    should be reachable.
    """
    analyzer = GapAnalyzer()
    descriptions = [
        "Maintain a list of authorized personnel.",  # LOW
        "Establish a policy for incident handling procedures.",  # MEDIUM
        "Implement multi-factor authentication for all privileged accounts.",  # HIGH
    ]
    results = {analyzer._estimate_effort(_ctrl(f"X{i}", description=d)) for i, d in enumerate(descriptions)}
    assert len(results) >= 3, f"Expected 3+ distinct effort tiers, got {results}"
