"""FIPS 199 categorization for federal AI systems (v0.9.6 P3).

`FIPS PUB 199 <https://csrc.nist.gov/pubs/fips/199/final>`_ defines
the standardized impact categorization scheme for federal information
+ federal information systems along three security objectives:

  - **Confidentiality**: unauthorized disclosure impact
  - **Integrity**: unauthorized modification impact
  - **Availability**: disruption-of-access impact

Each objective is rated LOW / MODERATE / HIGH per FIPS 199 §3 +
the worked examples in NIST SP 800-60 Vol 1 + Vol 2. The
**overall categorization** follows the "high-water-mark" rule per
FIPS 199 §3: ``overall = max(confidentiality, integrity, availability)``.

This module ships as a v0.9.6 federal-compliance carry-over from the
v0.9.5 walk-through validation queue. The categorization fields slot
into :class:`evidentia_core.ai_governance.registry.AISystemRegistryEntry`
as an Optional sub-model (backward-compat with v0.9.3–v0.9.5 entries
that pre-date federal-tier inventory expectations).

Operators populating FIPS 199 fields typically have an upstream
NIST SP 800-60 reference (the published worked-examples mapping
information-type → impact level). Evidentia does not maintain that
mapping itself — operators supply the per-objective rating based
on their SSP / authorization documentation.

**Threat-model boundary**: FIPS 199 ratings are operator-supplied
metadata, not a control surface. Misclassification is an operator
risk (under-rated systems may bypass required controls); Evidentia
surfaces the field for downstream OSCAL emit + reporting but does
NOT validate the rating against the information-types the system
processes (that's the operator's NIST SP 800-60 review).
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field, model_validator

from evidentia_core.models.common import EvidentiaModel


class FIPS199Impact(str, Enum):
    """Impact level per FIPS 199 §3.

    Ordered ``LOW < MODERATE < HIGH`` for the high-water-mark
    aggregation. String values match FIPS 199 + NIST SP 800-60
    spelling conventions.
    """

    LOW = "low"
    """Limited adverse effect on org operations, assets, individuals."""

    MODERATE = "moderate"
    """Serious adverse effect. Major degradation, significant
    financial loss, or significant harm to individuals."""

    HIGH = "high"
    """Severe / catastrophic adverse effect. Severe degradation,
    major financial loss, severe / catastrophic harm including
    loss of life."""

    def rank(self) -> int:
        """Numeric rank for high-water-mark comparison (LOW=1 / MODERATE=2 / HIGH=3)."""
        return {
            FIPS199Impact.LOW: 1,
            FIPS199Impact.MODERATE: 2,
            FIPS199Impact.HIGH: 3,
        }[self]


def _high_water_mark(a: FIPS199Impact, b: FIPS199Impact, c: FIPS199Impact) -> FIPS199Impact:
    """Return the highest of three FIPS 199 impact levels.

    Implements the FIPS 199 §3 high-water-mark aggregation:
    overall = max(confidentiality, integrity, availability).
    """
    return max((a, b, c), key=lambda i: i.rank())


class FIPS199Categorization(EvidentiaModel):
    """FIPS 199 impact categorization for an AI system or component.

    Carries the three per-objective ratings + the high-water-mark
    overall. The :meth:`compute_overall` validator enforces the
    invariant: if ``overall`` is supplied explicitly, it MUST equal
    the high-water-mark of the per-objective ratings. If omitted,
    it is computed automatically. This prevents operators from
    accidentally publishing an entry where ``overall=LOW`` while
    one of the objectives is HIGH (an obvious paperwork error that
    would otherwise pass schema validation).

    Example::

        cat = FIPS199Categorization(
            confidentiality_impact=FIPS199Impact.MODERATE,
            integrity_impact=FIPS199Impact.HIGH,
            availability_impact=FIPS199Impact.LOW,
        )
        # overall computed automatically:
        assert cat.overall == FIPS199Impact.HIGH
    """

    confidentiality_impact: FIPS199Impact = Field(
        description=(
            "Impact of unauthorized DISCLOSURE per FIPS 199. Operators rate per NIST SP 800-60 worked-examples."
        ),
    )
    integrity_impact: FIPS199Impact = Field(
        description=("Impact of unauthorized MODIFICATION per FIPS 199."),
    )
    availability_impact: FIPS199Impact = Field(
        description=("Impact of DISRUPTION OF ACCESS per FIPS 199."),
    )
    overall: FIPS199Impact | None = Field(
        default=None,
        description=(
            "FIPS 199 §3 high-water-mark: max of the three per-"
            "objective ratings. Auto-computed when omitted; if "
            "supplied explicitly, MUST equal the high-water-mark "
            "(validator rejects mismatches as paperwork errors)."
        ),
    )
    rationale: str | None = Field(
        default=None,
        max_length=4000,
        description=(
            "Free-text justification linking the impact ratings to the underlying information types per NIST SP 800-60."
        ),
    )

    @model_validator(mode="after")
    def _enforce_high_water_mark(self) -> FIPS199Categorization:
        """Compute or validate the ``overall`` high-water-mark.

        Pydantic invariant: ``overall`` MUST equal the high-water-
        mark of the three per-objective ratings. We compute it if
        omitted, otherwise verify it matches.
        """
        # ``use_enum_values=True`` on EvidentiaModel means the three
        # objective fields may arrive as strings post-serialization.
        # Coerce back to FIPS199Impact for the rank comparison.
        c = (
            self.confidentiality_impact
            if isinstance(self.confidentiality_impact, FIPS199Impact)
            else FIPS199Impact(self.confidentiality_impact)
        )
        i = (
            self.integrity_impact
            if isinstance(self.integrity_impact, FIPS199Impact)
            else FIPS199Impact(self.integrity_impact)
        )
        a = (
            self.availability_impact
            if isinstance(self.availability_impact, FIPS199Impact)
            else FIPS199Impact(self.availability_impact)
        )
        computed = _high_water_mark(c, i, a)
        if self.overall is None:
            # mypy-friendly: assign via __dict__ to bypass model
            # frozen-ness (EvidentiaModel is not frozen, but the
            # __setattr__ path triggers re-validation by default).
            self.__dict__["overall"] = computed.value
            return self
        supplied = self.overall if isinstance(self.overall, FIPS199Impact) else FIPS199Impact(self.overall)
        if supplied != computed:
            raise ValueError(
                f"FIPS 199 high-water-mark mismatch: overall="
                f"{supplied.value} but max(C={c.value}, I={i.value}, "
                f"A={a.value})={computed.value}. Omit 'overall' to "
                f"auto-compute, or correct the per-objective ratings."
            )
        return self


__all__ = [
    "FIPS199Categorization",
    "FIPS199Impact",
]
