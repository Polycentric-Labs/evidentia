"""OMB M-25-21 "high-impact AI" categorization (v0.10.12).

`OMB Memorandum M-25-21 <https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-21-Accelerating-Federal-Use-of-AI-through-Innovation-Governance-and-Public-Trust.pdf>`_
("Accelerating Federal Use of AI through Innovation, Governance, and
Public Trust", April 3, 2025) **rescinds and replaces** the prior
:mod:`~evidentia_core.ai_governance.omb_m_24_10` memo (M-24-10,
March 28, 2024). The companion procurement memo, M-25-22 ("Driving
Efficient Acquisition of Artificial Intelligence in Government"),
rescinds M-24-18; Evidentia models no M-24-18 surface, so M-25-22 is
out of scope here (tracked for a future cycle).

The defining change for an AI-system inventory: M-25-21 **collapses
the old "rights-impacting" / "safety-impacting" split into a single
"high-impact AI" category.** An AI use is *high-impact* when its
output serves as a *principal basis* for decisions or actions with a
legal, material, binding, or significant effect on at least one of these
consequence areas (:class:`HighImpactBasis`):

  - civil rights, civil liberties, or privacy;
  - access to essential services / programs (education, housing,
    insurance, credit, employment, and similar);
  - access to critical government resources or services;
  - human health and safety;
  - critical infrastructure or public safety;
  - strategic assets or resources.

A high-impact designation triggers M-25-21's **minimum risk-management
practices**. The memo enumerates seven: (1) pre-deployment testing;
(2) an AI impact assessment; (3) ongoing monitoring with adverse-impact
detection; (4) adequate human training and competency; (5) enhanced
human oversight and intervention; (6) consistent remedies and appeals
processes; (7) end-user and public feedback incorporation. **Evidentia
records the high-impact determination + its consequence bases here;
structured per-practice tracking of the seven is a future-cycle
extension point on** :class:`OMBHighImpactAssessment` **(reserved for
v0.11).**

**Threat-model boundary**: as with the legacy memo, this is
operator-supplied metadata, not a control surface. Misclassification is
an operator risk; Evidentia surfaces the determination for inventory +
reporting but does NOT validate it against the system's actual use
case. Agencies have a designated review path (typically the Chief AI
Officer per M-25-21's governance structure) that makes the call.

**Inventory schema reference**: there is no upstream-published
machine-readable schema for M-25-21 inventory entries (agencies publish
prose compliance plans). Evidentia defines the canonical JSON / Pydantic
representation here so cross-agency tooling has a shared schema to
target — the same role the legacy module played for M-24-10.

**Backward compatibility**: the legacy
:class:`~evidentia_core.ai_governance.omb_m_24_10.OMBImpactCategory`
field is retained on the registry and keeps working; persisted
inventories that carry it still load. :func:`crosswalk_from_legacy`
provides an explicit, operator-invoked old → new mapping. Evidentia
does NOT silently auto-derive the new determination from a persisted
legacy value (that would fabricate a federal determination without
operator review).
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from evidentia_core.ai_governance.omb_m_24_10 import OMBImpactCategory
from evidentia_core.models.common import EvidentiaModel


class HighImpactDetermination(str, Enum):
    """OMB M-25-21 high-impact AI determination.

    Replaces the legacy four-value rights/safety taxonomy with the
    single consolidated category M-25-21 defines. String values are
    stable across releases so persisted YAML / JSON inventories survive
    minor / major version bumps (same contract the legacy enum carries).
    """

    HIGH_IMPACT = "high_impact"
    """The AI use is high-impact per M-25-21: its output is a principal
    basis for decisions/actions with a legal, material, binding, or
    significant effect on one or more :class:`HighImpactBasis` areas.
    Triggers the seven minimum risk-management practices."""

    NOT_HIGH_IMPACT = "not_high_impact"
    """The AI use is not high-impact. Subject to baseline governance but
    exempt from the M-25-21 minimum risk-management practices."""

    NOT_ASSESSED = "not_assessed"
    """The operator has not yet made a high-impact determination. Carries
    no exemption — it signals an open inventory action, distinct from an
    affirmative NOT_HIGH_IMPACT finding."""


class HighImpactBasis(str, Enum):
    """An M-25-21 consequence area that can make an AI use high-impact.

    The memo defines high-impact AI by the effect of the system's output
    on these areas. An :class:`OMBHighImpactAssessment` carries the
    subset that applies (a system can be high-impact on multiple
    grounds). String values are stable (persisted in inventories).
    """

    CIVIL_RIGHTS_LIBERTIES_PRIVACY = "civil_rights_liberties_privacy"
    """Civil rights, civil liberties, or privacy."""

    ESSENTIAL_SERVICES_ACCESS = "essential_services_access"
    """Access to, or the ability to apply for, essential services and
    programs — education, housing, insurance, credit, employment, and
    similar benefits."""

    CRITICAL_GOVERNMENT_RESOURCES = "critical_government_resources"
    """Access to critical government resources or services."""

    HEALTH_AND_SAFETY = "health_and_safety"
    """Human health and safety."""

    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"
    """Critical infrastructure or public safety."""

    STRATEGIC_ASSETS = "strategic_assets"
    """Strategic assets or resources (incl. national-security,
    defense, and intelligence interests)."""


class OMBHighImpactAssessment(EvidentiaModel):
    """OMB M-25-21 high-impact AI assessment for one registered system.

    Carries the operator's high-impact determination plus the
    consequence bases supporting it. Mirrors the
    :class:`~evidentia_core.ai_governance.fips199.FIPS199Categorization`
    sub-model pattern (a small, self-describing record attached to a
    registry entry).

    The seven M-25-21 minimum risk-management practices are NOT modelled
    as structured fields this cycle — this class is the reserved
    extension point for per-practice tracking in a future federal cycle
    (v0.11). Operators capture the determination + bases now and document
    practice status out of band.
    """

    determination: HighImpactDetermination = Field(
        description=(
            "The M-25-21 high-impact determination. HIGH_IMPACT triggers "
            "the minimum risk-management practices."
        ),
    )
    bases: list[HighImpactBasis] = Field(
        default_factory=list,
        description=(
            "The consequence areas that make the system high-impact. "
            "Meaningful only when determination is HIGH_IMPACT; left "
            "empty otherwise. Advisory, not enforced — an operator may "
            "record a HIGH_IMPACT determination before pinning every "
            "basis."
        ),
    )
    rationale: str | None = Field(
        default=None,
        max_length=4000,
        description=(
            "Optional free-text justification linking the determination "
            "to the system's use case (or noting a legacy-crosswalk "
            "origin per :func:`crosswalk_from_legacy`)."
        ),
    )


def triggers_minimum_practices(determination: HighImpactDetermination) -> bool:
    """Return True iff the determination triggers M-25-21 minimum practices.

    Only :attr:`HighImpactDetermination.HIGH_IMPACT` triggers the seven
    minimum risk-management practices. NOT_HIGH_IMPACT is exempt;
    NOT_ASSESSED is an open inventory action (no exemption, but no
    affirmative practice obligation until assessed).

    Accepts either the enum member or its string value (registry entries
    persist enums as their string values under the model's
    ``use_enum_values`` config), coercing defensively.
    """
    coerced = (
        determination
        if isinstance(determination, HighImpactDetermination)
        else HighImpactDetermination(determination)
    )
    return coerced == HighImpactDetermination.HIGH_IMPACT


# Coarse legacy basis mapping — see crosswalk_from_legacy. These are the
# consequence areas most directly implied by each legacy category; the
# crosswalk flags them as legacy-derived so the operator reviews against
# the M-25-21 definitions rather than treating them as authoritative.
_LEGACY_BASES: dict[OMBImpactCategory, list[HighImpactBasis]] = {
    OMBImpactCategory.RIGHTS_IMPACTING: [
        HighImpactBasis.CIVIL_RIGHTS_LIBERTIES_PRIVACY,
        HighImpactBasis.ESSENTIAL_SERVICES_ACCESS,
    ],
    OMBImpactCategory.SAFETY_IMPACTING: [
        HighImpactBasis.HEALTH_AND_SAFETY,
        HighImpactBasis.CRITICAL_INFRASTRUCTURE,
    ],
    OMBImpactCategory.RIGHTS_AND_SAFETY_IMPACTING: [
        HighImpactBasis.CIVIL_RIGHTS_LIBERTIES_PRIVACY,
        HighImpactBasis.ESSENTIAL_SERVICES_ACCESS,
        HighImpactBasis.HEALTH_AND_SAFETY,
        HighImpactBasis.CRITICAL_INFRASTRUCTURE,
    ],
}


def crosswalk_from_legacy(category: OMBImpactCategory) -> OMBHighImpactAssessment:
    """Map a legacy OMB M-24-10 category to an M-25-21 assessment.

    Determination mapping (deterministic):

      - RIGHTS_IMPACTING / SAFETY_IMPACTING / RIGHTS_AND_SAFETY_IMPACTING
        → :attr:`HighImpactDetermination.HIGH_IMPACT` (all three legacy
        "impacting" categories fold into the single high-impact class).
      - NEITHER → :attr:`HighImpactDetermination.NOT_HIGH_IMPACT`.

    The ``bases`` are a **coarse** mapping of the legacy category to the
    most directly implied M-25-21 consequence areas, and the returned
    ``rationale`` flags the assessment as legacy-derived. The mapping is
    a migration aid, not an authoritative re-determination — operators
    should review the result against the M-25-21 definitions. This helper
    is explicit/operator-invoked; Evidentia never applies it silently.

    Args:
        category: A legacy
            :class:`~evidentia_core.ai_governance.omb_m_24_10.OMBImpactCategory`
            value (enum member or its string value).

    Returns:
        An :class:`OMBHighImpactAssessment` with the mapped determination,
        coarse bases, and a legacy-derived rationale.
    """
    coerced = (
        category
        if isinstance(category, OMBImpactCategory)
        else OMBImpactCategory(category)
    )
    if coerced == OMBImpactCategory.NEITHER:
        return OMBHighImpactAssessment(
            determination=HighImpactDetermination.NOT_HIGH_IMPACT,
            bases=[],
            rationale=(
                "Derived from legacy OMB M-24-10 category 'neither' "
                "(memo rescinded 2025-04-03 by M-25-21). Review against "
                "the M-25-21 high-impact definition."
            ),
        )
    return OMBHighImpactAssessment(
        determination=HighImpactDetermination.HIGH_IMPACT,
        bases=list(_LEGACY_BASES.get(coerced, [])),
        rationale=(
            f"Derived from legacy OMB M-24-10 category "
            f"'{coerced.value}' (memo rescinded 2025-04-03 by M-25-21). "
            f"Bases are a coarse legacy mapping — review against the "
            f"M-25-21 high-impact consequence areas."
        ),
    )


__all__ = [
    "HighImpactBasis",
    "HighImpactDetermination",
    "OMBHighImpactAssessment",
    "crosswalk_from_legacy",
    "triggers_minimum_practices",
]
