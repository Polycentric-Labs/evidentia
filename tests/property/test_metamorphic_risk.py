"""Metamorphic / invariant property tests for the GRC risk + scoring engines.

Hypothesis + mutation testing hit the *oracle problem* on quantitative risk
math: there is no independent "expected" ALE to assert against for an arbitrary
input. Metamorphic testing sidesteps the oracle by asserting *relations between
outputs* that must hold by construction — e.g. "raising any non-negative FAIR
factor must never lower the ALE", or "re-ordering a vendor inventory must not
change its concentration report". These target the engines' *judgment* logic
(``evidentia_core.risk_quant.open_fair`` + ``evidentia_core.tprm.concentration``),
which the existing example/round-trip tests exercise only at single points.

Every relation below is sound from the engines' own definitions:

  Open FAIR:  ALE = (TEF x Vulnerability) x (PrimaryLoss + SecondaryLoss),
              all factors >= 0, so ALE is non-decreasing and homogeneous
              degree-1 in each factor; ``categorize_risk`` is a monotone band
              function of ALE; the quantification report is deterministic and
              (for distinct ALEs) order-invariant.

  Concentration: per-value counts are *distinct-vendor-set* cardinalities and
              the distribution is deterministically sorted, so the report is
              invariant to vendor input order; counts are bounded by the vendor
              total; threshold flagging is monotone in the threshold.

A failure here is either a real semantic regression in the engine or a wrong
invariant — both are worth catching, and each relation is annotated with why it
holds so a failure is diagnosable.
"""

from __future__ import annotations

import math
from datetime import date

from evidentia_core.models.tprm import CriticalityTier, Vendor, VendorType
from evidentia_core.risk_quant.open_fair import (
    OpenFAIRScenario,
    PERTRange,
    RiskCategory,
    categorize_risk,
    compute_ale,
    generate_risk_quantification_report,
)
from evidentia_core.tprm.concentration import compute_concentration
from hypothesis import given
from hypothesis import strategies as st

# ── strategies ─────────────────────────────────────────────────────────────
# Bounded, finite, non-negative magnitudes: large enough to span FAIR's risk
# bands, small enough that products stay in float64's exact-ish range.
_NONNEG = st.floats(min_value=0.0, max_value=1.0e6, allow_nan=False, allow_infinity=False)
_PROB = st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)
_SCALE = st.floats(min_value=0.0, max_value=1.0e3, allow_nan=False, allow_infinity=False)
_ALE = st.floats(min_value=0.0, max_value=5.0e7, allow_nan=False, allow_infinity=False)

_RISK_ORDER = [
    RiskCategory.LOW,
    RiskCategory.MODERATE,
    RiskCategory.SIGNIFICANT,
    RiskCategory.HIGH,
    RiskCategory.SEVERE,
]
_RISK_RANK = {c: i for i, c in enumerate(_RISK_ORDER)}


def _ge(a: float, b: float) -> bool:
    """``a >= b`` tolerating benign float rounding (no wall-clock; pure math)."""
    return a >= b or math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-6)


def _scenario(
    tef: float | PERTRange,
    vuln: float | PERTRange,
    primary: float | PERTRange,
    secondary: float | PERTRange = 0.0,
) -> OpenFAIRScenario:
    return OpenFAIRScenario(
        name="scenario",
        description="metamorphic test scenario",
        tef=tef,
        vulnerability=vuln,
        primary_loss=primary,
        secondary_loss=secondary,
    )


# ── Open FAIR: monotonicity (raising any factor never lowers ALE) ───────────


@given(tef=_NONNEG, vuln=_PROB, primary=_NONNEG, secondary=_NONNEG, delta=_NONNEG)
def test_ale_monotonic_in_tef(tef, vuln, primary, secondary, delta):
    base = compute_ale(_scenario(tef, vuln, primary, secondary))
    bumped = compute_ale(_scenario(tef + delta, vuln, primary, secondary))
    assert _ge(bumped, base)


@given(tef=_NONNEG, vuln=_PROB, primary=_NONNEG, secondary=_NONNEG, delta=_NONNEG)
def test_ale_monotonic_in_vulnerability(tef, vuln, primary, secondary, delta):
    base = compute_ale(_scenario(tef, vuln, primary, secondary))
    bumped = compute_ale(_scenario(tef, vuln + delta, primary, secondary))
    assert _ge(bumped, base)


@given(tef=_NONNEG, vuln=_PROB, primary=_NONNEG, secondary=_NONNEG, delta=_NONNEG)
def test_ale_monotonic_in_primary_loss(tef, vuln, primary, secondary, delta):
    base = compute_ale(_scenario(tef, vuln, primary, secondary))
    bumped = compute_ale(_scenario(tef, vuln, primary + delta, secondary))
    assert _ge(bumped, base)


@given(tef=_NONNEG, vuln=_PROB, primary=_NONNEG, secondary=_NONNEG, delta=_NONNEG)
def test_ale_monotonic_in_secondary_loss(tef, vuln, primary, secondary, delta):
    """Adding non-negative secondary loss never lowers ALE (LM additivity)."""
    base = compute_ale(_scenario(tef, vuln, primary, secondary))
    bumped = compute_ale(_scenario(tef, vuln, primary, secondary + delta))
    assert _ge(bumped, base)


# ── Open FAIR: homogeneity (degree-1 scaling) ───────────────────────────────


@given(tef=_NONNEG, vuln=_PROB, primary=_NONNEG, secondary=_NONNEG, k=_SCALE)
def test_ale_scales_linearly_in_frequency(tef, vuln, primary, secondary, k):
    base = compute_ale(_scenario(tef, vuln, primary, secondary))
    scaled = compute_ale(_scenario(tef * k, vuln, primary, secondary))
    assert math.isclose(scaled, k * base, rel_tol=1e-9, abs_tol=1e-6)


@given(tef=_NONNEG, vuln=_PROB, primary=_NONNEG, secondary=_NONNEG, k=_SCALE)
def test_ale_scales_linearly_in_loss_magnitude(tef, vuln, primary, secondary, k):
    base = compute_ale(_scenario(tef, vuln, primary, secondary))
    scaled = compute_ale(_scenario(tef, vuln, primary * k, secondary * k))
    assert math.isclose(scaled, k * base, rel_tol=1e-9, abs_tol=1e-6)


# ── Open FAIR: PERT encoding ────────────────────────────────────────────────


@given(x=_NONNEG)
def test_pert_degenerate_equals_scalar(x):
    """A zero-width PERT range (low==most_likely==high) equals the scalar."""
    degenerate = PERTRange(low=x, most_likely=x, high=x)
    assert math.isclose(degenerate.mean(), x, rel_tol=1e-9, abs_tol=1e-9)
    scalar_ale = compute_ale(_scenario(2.0, 0.5, x))
    pert_ale = compute_ale(_scenario(2.0, 0.5, degenerate))
    assert math.isclose(scalar_ale, pert_ale, rel_tol=1e-9, abs_tol=1e-6)


@given(a=_NONNEG, b=_NONNEG, c=_NONNEG)
def test_pert_mean_within_bounds(a, b, c):
    """The PERT mean always lies within [low, high]."""
    low, most_likely, high = sorted([a, b, c])
    mean = PERTRange(low=low, most_likely=most_likely, high=high).mean()
    assert low - 1e-9 <= mean <= high + 1e-9


# ── Open FAIR: band classification monotonicity ─────────────────────────────


@given(a=_ALE, b=_ALE)
def test_categorize_risk_monotonic_in_ale(a, b):
    lo, hi = sorted([a, b])
    assert _RISK_RANK[categorize_risk(lo)] <= _RISK_RANK[categorize_risk(hi)]


# ── Open FAIR: report determinism + permutation invariance ──────────────────


def test_report_deterministic_and_order_invariant():
    """Same scenarios -> identical report; distinct ALEs -> order-invariant."""
    scenarios = [
        _scenario(1.0, 1.0, 100.0),  # ALE 100
        _scenario(2.0, 1.0, 1_000.0),  # ALE 2,000
        _scenario(1.0, 0.5, 1_000_000.0),  # ALE 500,000
        _scenario(10.0, 1.0, 1_000_000.0),  # ALE 10,000,000
    ]
    report = generate_risk_quantification_report(scenarios)
    assert report == generate_risk_quantification_report(scenarios)  # determinism
    assert report == generate_risk_quantification_report(list(reversed(scenarios)))


# ── Concentration: construction helper + strategies ─────────────────────────

_REGIONS = ["us-east-1", "eu-west-1", "ap-south-1", "us-west-2", None]
_VENDOR_SPEC = st.tuples(st.sampled_from(_REGIONS), st.sampled_from(list(VendorType)))
_DIMENSIONS = ["region", "service-category", "criticality-tier"]


def _vendor(name: str, region: str | None, vtype: VendorType) -> Vendor:
    return Vendor(
        name=name,
        type=vtype,
        criticality_tier=CriticalityTier.MEDIUM,
        relationship_owner="x@x.com",
        contract_start_date=date(2025, 1, 1),
        region=region,
        fourth_parties=[],
        regulatory_classification=[],
    )


def _build(specs: list[tuple[str | None, VendorType]]) -> list[Vendor]:
    return [_vendor(f"vendor-{i}", region, vtype) for i, (region, vtype) in enumerate(specs)]


# ── Concentration: permutation invariance ───────────────────────────────────


@given(specs=st.lists(_VENDOR_SPEC, min_size=1, max_size=12))
def test_concentration_invariant_to_vendor_order(specs):
    """Set-based aggregation + deterministic sort => order cannot change output."""
    vendors = _build(specs)
    forward = compute_concentration(vendors, _DIMENSIONS)
    reverse = compute_concentration(list(reversed(vendors)), _DIMENSIONS)
    # generated_at differs (utc_now); the analysed distribution must not.
    assert forward.dimensions == reverse.dimensions


# ── Concentration: count / percentage bounds ────────────────────────────────


@given(specs=st.lists(_VENDOR_SPEC, min_size=1, max_size=12))
def test_concentration_counts_bounded_by_total(specs):
    vendors = _build(specs)
    report = compute_concentration(vendors, _DIMENSIONS)
    total = report.total_vendors
    assert total == len(vendors)
    for dim in report.dimensions:
        assert 0 <= dim.vendors_with_value <= total
        for vc in dim.distribution:
            assert 0 <= vc.count <= total
            assert 0.0 <= vc.percentage <= 100.0
            assert vc.percentage == round(vc.count / total * 100.0, 1)


# ── Concentration: threshold-flagging monotonicity ──────────────────────────


@given(specs=st.lists(_VENDOR_SPEC, min_size=1, max_size=12))
def test_threshold_flagging_monotonic(specs):
    """A higher threshold flags a subset of what a lower threshold flags."""
    vendors = _build(specs)

    def flagged(threshold: float) -> set[tuple[str, str]]:
        report = compute_concentration(vendors, _DIMENSIONS, threshold=threshold)
        return {
            (dim.dimension, vc.value)
            for dim in report.dimensions
            for vc in dim.distribution
            if vc.exceeds_threshold
        }

    assert flagged(50.0) <= flagged(10.0)


# ── Concentration: requested dimension order is preserved ────────────────────


@given(specs=st.lists(_VENDOR_SPEC, min_size=1, max_size=8))
def test_concentration_preserves_dimension_order(specs):
    vendors = _build(specs)
    order = ["service-category", "criticality-tier", "region"]
    report = compute_concentration(vendors, order)
    assert [dim.dimension for dim in report.dimensions] == order
