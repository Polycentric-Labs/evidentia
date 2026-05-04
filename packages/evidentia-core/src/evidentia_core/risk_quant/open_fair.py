"""Open FAIR risk quantification primitives (v0.7.11 P1.5 G4).

Implements the Open Group's Open FAIR (Factor Analysis of
Information Risk) taxonomy for dollarized risk quantification.
Reference: <https://www.opengroup.org/open-fair> + ISO/IEC 27005
Annex E.

The FAIR model decomposes risk into:

    Risk = LEF × LM
         = (TEF × Vulnerability) × (PrimaryLoss + SecondaryLoss)

where:

  - **TEF** (Threat Event Frequency): events/year that threat
    actors attempt the attack
  - **Vulnerability**: probability (0-1) the attempt succeeds
    given existing controls
  - **LEF** (Loss Event Frequency) = TEF × Vulnerability
  - **PrimaryLoss**: direct response + replacement costs ($)
  - **SecondaryLoss**: downstream costs — fines, reputation,
    customer churn, legal ($)
  - **LM** (Loss Magnitude) = PrimaryLoss + SecondaryLoss
  - **ALE** (Annualized Loss Expectancy) = LEF × LM

Operators can supply single-point estimates OR PERT ranges
(low / most-likely / high). The PERT distribution is the FAIR
canonical encoding of estimator uncertainty; this module
computes the PERT mean
``E[X] = (low + 4×most_likely + high) / 6`` deterministically.
Full Monte Carlo simulation is deferred to v0.7.12.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import Field, model_validator

from evidentia_core.models.common import (
    EvidentiaModel,
    current_version,
    new_id,
    utc_now,
)


class RiskCategory(str, Enum):
    """FAIR risk-category bands from the published Open Group guide."""

    SEVERE = "severe"  # ALE > $10M
    HIGH = "high"  # $1M < ALE <= $10M
    SIGNIFICANT = "significant"  # $100k < ALE <= $1M
    MODERATE = "moderate"  # $10k < ALE <= $100k
    LOW = "low"  # ALE <= $10k


class PERTRange(EvidentiaModel):
    """A 3-point PERT estimate (low / most_likely / high).

    PERT mean: ``E[X] = (low + 4*most_likely + high) / 6``.
    Operators capturing range-of-estimate uncertainty use this
    rather than single-point values.

    Constraint: ``low <= most_likely <= high``.
    """

    low: float = Field(
        ge=0.0,
        description="Lowest plausible value (5th percentile-ish).",
    )
    most_likely: float = Field(
        ge=0.0,
        description="Most-likely value (mode).",
    )
    high: float = Field(
        ge=0.0,
        description="Highest plausible value (95th percentile-ish).",
    )

    @model_validator(mode="after")
    def _enforce_ordering(self) -> PERTRange:
        if not (self.low <= self.most_likely <= self.high):
            raise ValueError(
                f"PERTRange must satisfy low <= most_likely <= high; "
                f"got low={self.low}, most_likely={self.most_likely}, "
                f"high={self.high}"
            )
        return self

    def mean(self) -> float:
        """Return the PERT-distribution mean (Beta-PERT default lambda=4)."""
        return (self.low + 4.0 * self.most_likely + self.high) / 6.0


class OpenFAIRScenario(EvidentiaModel):
    """A risk scenario expressed in Open FAIR terms.

    Operators supply each FAIR factor as either a scalar (single-
    point estimate) or a :class:`PERTRange` (range estimate).
    The :func:`compute_ale` helper resolves both to a deterministic
    expected value.
    """

    id: str = Field(default_factory=new_id)
    name: str = Field(
        description="Short scenario name (e.g., 'Credential stuffing on customer login')."
    )
    description: str = Field(
        description="Full scenario narrative covering threat, asset, + impact."
    )

    # FAIR loss-event frequency (LEF) factors
    tef: float | PERTRange = Field(
        description=(
            "Threat Event Frequency: events/year that threat actors "
            "attempt this attack. Scalar OR PERTRange."
        )
    )
    vulnerability: float | PERTRange = Field(
        description=(
            "Vulnerability: probability (0-1) the attempt succeeds "
            "given controls. Scalar OR PERTRange."
        )
    )

    # FAIR loss-magnitude (LM) factors
    primary_loss: float | PERTRange = Field(
        description=(
            "Primary Loss ($): direct response + replacement costs "
            "from one event. Scalar OR PERTRange."
        )
    )
    secondary_loss: float | PERTRange = Field(
        default=0.0,
        description=(
            "Secondary Loss ($): downstream costs — fines, "
            "reputation, customer churn, legal — from one event. "
            "Scalar OR PERTRange. Default 0."
        ),
    )

    # Optional cross-links
    asset: str | None = Field(
        default=None,
        description="Asset under risk (free-text or ID).",
    )
    threat_actor: str | None = Field(
        default=None,
        description="Threat-actor archetype (e.g., 'opportunistic external')",
    )
    notes: str | None = Field(
        default=None,
        description="Free-text notes about methodology, source data, etc.",
    )

    # Auto-populated metadata
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    evidentia_version: str = Field(default_factory=current_version)


def _resolve(value: float | PERTRange) -> float:
    """Collapse a scalar-or-PERTRange field to its expected value."""
    if isinstance(value, PERTRange):
        return value.mean()
    return float(value)


def compute_loss_magnitude(scenario: OpenFAIRScenario) -> float:
    """Return the expected loss magnitude per event ($)."""
    return _resolve(scenario.primary_loss) + _resolve(scenario.secondary_loss)


def compute_lef(scenario: OpenFAIRScenario) -> float:
    """Return the expected loss-event frequency (events/year).

    LEF = TEF × Vulnerability. Caller is responsible for ensuring
    Vulnerability ∈ [0, 1]; we don't clamp because operators may
    legitimately model multi-stage attacks where the per-stage
    success-probability product exceeds 1 (rare but legal).
    """
    return _resolve(scenario.tef) * _resolve(scenario.vulnerability)


def compute_ale(scenario: OpenFAIRScenario) -> float:
    """Return the Annualized Loss Expectancy ($)."""
    return compute_lef(scenario) * compute_loss_magnitude(scenario)


def categorize_risk(ale: float) -> RiskCategory:
    """Classify an ALE into the FAIR risk bands."""
    if ale > 10_000_000:
        return RiskCategory.SEVERE
    if ale > 1_000_000:
        return RiskCategory.HIGH
    if ale > 100_000:
        return RiskCategory.SIGNIFICANT
    if ale > 10_000:
        return RiskCategory.MODERATE
    return RiskCategory.LOW


def _format_currency(amount: float) -> str:
    """US-format currency with sensible precision."""
    if amount >= 1_000_000:
        return f"${amount / 1_000_000:.2f}M"
    if amount >= 1_000:
        return f"${amount / 1_000:.1f}k"
    return f"${amount:.2f}"


def _format_factor(value: float | PERTRange, unit: str) -> str:
    """Render a scalar-or-range factor in a single human-readable line."""
    if isinstance(value, PERTRange):
        return (
            f"PERT(low={value.low}, most_likely={value.most_likely}, "
            f"high={value.high}) → {value.mean():.4f} {unit}"
        )
    return f"{value} {unit}"


def generate_risk_quantification_report(
    scenarios: list[OpenFAIRScenario],
) -> str:
    """Generate a Markdown FAIR quantification report.

    Sections:

      1. Executive summary — total ALE across all scenarios +
         category distribution (SEVERE / HIGH / SIGNIFICANT /
         MODERATE / LOW)
      2. Per-scenario detail — name + ALE + LEF + LM breakdown
         + each factor's resolved-mean

    Output is deterministic — same input produces the same output
    character-for-character.
    """
    sections: list[str] = []
    if not scenarios:
        return (
            "# FAIR Risk Quantification Report\n\n"
            "_No scenarios defined. Use `evidentia risk quantify "
            "--method open-fair` with a YAML/JSON scenario file to "
            "produce a quantification._\n"
        )

    # Compute everything once
    rows = []
    cat_counts: dict[str, int] = {c.value: 0 for c in RiskCategory}
    total_ale = 0.0
    for s in scenarios:
        ale = compute_ale(s)
        cat = categorize_risk(ale).value
        cat_counts[cat] += 1
        total_ale += ale
        rows.append((s, ale, cat))

    # ── §1 Executive summary ─────────────────────────────────────
    cat_rows = "\n".join(
        f"| {cat} | {cat_counts[cat]} |"
        for cat in (
            RiskCategory.SEVERE.value,
            RiskCategory.HIGH.value,
            RiskCategory.SIGNIFICANT.value,
            RiskCategory.MODERATE.value,
            RiskCategory.LOW.value,
        )
    )
    sections.append(
        "# FAIR Risk Quantification Report\n\n"
        f"_Open FAIR (Factor Analysis of Information Risk) "
        f"quantification across {len(scenarios)} scenario(s) per "
        "the Open Group's Open Risk Taxonomy Standard._\n\n"
        f"**Total Annualized Loss Expectancy (ALE)**: "
        f"{_format_currency(total_ale)}\n\n"
        "| Risk category | Scenario count |\n"
        "| --- | --- |\n"
        + cat_rows
        + f"\n| **Total** | **{len(scenarios)}** |\n"
    )

    # ── §2 Per-scenario detail ───────────────────────────────────
    sections.append("## Per-scenario detail\n")
    for s, ale, cat in sorted(rows, key=lambda r: -r[1]):
        lef = compute_lef(s)
        lm = compute_loss_magnitude(s)
        sections.append(
            f"### {s.name} — {_format_currency(ale)} ALE ({cat})\n\n"
            f"**Description**: {s.description}\n\n"
            f"| Factor | Value |\n"
            f"| --- | --- |\n"
            f"| TEF | {_format_factor(s.tef, 'events/yr')} |\n"
            f"| Vulnerability | {_format_factor(s.vulnerability, '')} |\n"
            f"| LEF (computed) | {lef:.4f} events/yr |\n"
            f"| Primary loss | {_format_factor(s.primary_loss, 'USD')} |\n"
            f"| Secondary loss | {_format_factor(s.secondary_loss, 'USD')} |\n"
            f"| LM (computed) | {_format_currency(lm)} |\n"
            f"| **ALE** | **{_format_currency(ale)}** |\n"
        )

    return "\n".join(sections)
