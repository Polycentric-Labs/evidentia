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
practices** (§4(b), verified against the memo text 2026-07-14). The memo
enumerates seven: (i) Conduct Pre-Deployment Testing; (ii) Complete AI
Impact Assessment; (iii) Conduct Ongoing Monitoring for Performance and
Potential Adverse Impacts; (iv) Ensure Adequate Human Training and
Assessment; (v) Provide Additional Human Oversight, Intervention, and
Accountability; (vi) Offer Consistent Remedies or Appeals; (vii) Consult
and Incorporate Feedback from End Users and the Public. Agencies had
365 days from issuance (i.e. to 2026-04-03) to implement them for
existing high-impact AI.

**v0.11 fills the extension point reserved at v0.10.12**: structured
per-practice status lives in :attr:`OMBHighImpactAssessment.practices`
(a :class:`MinimumPractice` → :class:`MinimumPracticeRecord` mapping),
including the §4(a)(ii) **CAIO waiver** record — a written,
system/context-specific determination that the CAIO must re-certify
annually, may revoke at any time, must report to OMB within 30 days of
granting or revoking, and may not delegate. :func:`practice_compliance`
rolls the mapping up (recorded / missing / satisfied) without ever
inventing a status for an unrecorded practice.

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

from datetime import date
from enum import Enum

from pydantic import Field, model_validator

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


class MinimumPractice(str, Enum):
    """One of M-25-21 §4(b)'s seven minimum risk-management practices.

    Member docstrings carry the memo's practice headings verbatim
    (verified against the memo text 2026-07-14). String values are
    stable across releases (persisted in inventories).
    """

    PRE_DEPLOYMENT_TESTING = "pre_deployment_testing"
    """§4(b)(i) — Conduct Pre-Deployment Testing."""

    IMPACT_ASSESSMENT = "impact_assessment"
    """§4(b)(ii) — Complete AI Impact Assessment."""

    ONGOING_MONITORING = "ongoing_monitoring"
    """§4(b)(iii) — Conduct Ongoing Monitoring for Performance and
    Potential Adverse Impacts."""

    HUMAN_TRAINING = "human_training"
    """§4(b)(iv) — Ensure Adequate Human Training and Assessment."""

    HUMAN_OVERSIGHT = "human_oversight"
    """§4(b)(v) — Provide Additional Human Oversight, Intervention,
    and Accountability."""

    REMEDIES_AND_APPEALS = "remedies_and_appeals"
    """§4(b)(vi) — Offer Consistent Remedies or Appeals."""

    PUBLIC_FEEDBACK = "public_feedback"
    """§4(b)(vii) — Consult and Incorporate Feedback from End Users
    and the Public."""


class PracticeStatus(str, Enum):
    """Implementation status of one minimum practice for one system.

    ``WAIVED`` is a distinct compliance state, not an absence: it
    requires a CAIO waiver record (:class:`PracticeWaiver`) per
    §4(a)(ii). There is deliberately no "not applicable" — under
    M-25-21 the only sanctioned way a high-impact system does not
    apply a minimum practice is a CAIO waiver.
    """

    IMPLEMENTED = "implemented"
    """The practice is implemented and operating for this system."""

    IN_PROGRESS = "in_progress"
    """Implementation underway; not yet operating."""

    NOT_STARTED = "not_started"
    """Recorded as an open obligation; no implementation work yet."""

    WAIVED = "waived"
    """A CAIO waiver per §4(a)(ii) is in force for this practice
    (the record must carry a :class:`PracticeWaiver`)."""


class PracticeWaiver(EvidentiaModel):
    """A CAIO waiver of one minimum practice for one system (§4(a)(ii)).

    The memo's constraints, modelled as data + advisory helpers rather
    than hard validation (Evidentia records the operator's state; the
    CAIO owns the determination):

    - a **written determination** based on a system-specific and
      context-specific risk assessment (``justification``);
    - the CAIO must **certify ongoing validity annually**
      (``last_certified_on``; :func:`waiver_certification_due`);
    - grants/revocations must be **reported to OMB within 30 days**
      (``reported_to_omb_on``; :func:`waiver_omb_report_overdue`);
    - the authority is the CAIO's and may not be delegated — recorded
      here only as provenance (``issued_by``).
    """

    issued_on: date = Field(
        description="Date the CAIO granted the waiver.",
    )
    issued_by: str = Field(
        max_length=256,
        description=(
            "The granting official (the agency CAIO — §4(a)(ii) makes "
            "this authority non-delegable). Recorded as provenance."
        ),
    )
    justification: str = Field(
        max_length=8000,
        description=(
            "The written determination: why fulfilling the practice "
            "would increase risks to safety or rights overall, or would "
            "create an unacceptable impediment to critical agency "
            "operations (the memo's two sanctioned grounds)."
        ),
    )
    last_certified_on: date | None = Field(
        default=None,
        description=(
            "Most recent annual re-certification of ongoing validity. "
            "None until the first re-certification (the anchor for the "
            "annual clock is then issued_on)."
        ),
    )
    reported_to_omb_on: date | None = Field(
        default=None,
        description=(
            "Date the grant was reported to OMB (due within 30 days of "
            "granting per §4(a)(iii)). None = not yet reported."
        ),
    )


class MinimumPracticeRecord(EvidentiaModel):
    """Status of one minimum practice for one registered system.

    Operator-supplied metadata, same threat-model boundary as the
    high-impact determination itself: Evidentia surfaces it for
    inventory and reporting but does not validate it against the
    system's actual behavior.
    """

    status: PracticeStatus = Field(
        description="Implementation status of this practice.",
    )
    notes: str | None = Field(
        default=None,
        max_length=4000,
        description=(
            "Optional free-text detail — evidence pointers, plan "
            "references, scope notes."
        ),
    )
    last_reviewed: date | None = Field(
        default=None,
        description="When the operator last reviewed this status.",
    )
    waiver: PracticeWaiver | None = Field(
        default=None,
        description=(
            "The CAIO waiver in force — required iff status is WAIVED."
        ),
    )

    @model_validator(mode="after")
    def _waiver_iff_waived(self) -> MinimumPracticeRecord:
        """WAIVED requires a waiver record; a waiver record requires WAIVED."""
        waived = self.status == PracticeStatus.WAIVED
        if waived and self.waiver is None:
            raise ValueError(
                "status 'waived' requires a waiver record (the CAIO's "
                "written determination per M-25-21 §4(a)(ii))"
            )
        if not waived and self.waiver is not None:
            raise ValueError(
                "a waiver record is only valid with status 'waived' "
                f"(got status {self.status!r})"
            )
        return self


class OMBHighImpactAssessment(EvidentiaModel):
    """OMB M-25-21 high-impact AI assessment for one registered system.

    Carries the operator's high-impact determination plus the
    consequence bases supporting it. Mirrors the
    :class:`~evidentia_core.ai_governance.fips199.FIPS199Categorization`
    sub-model pattern (a small, self-describing record attached to a
    registry entry).

    v0.11 fills the per-practice extension point reserved at v0.10.12:
    :attr:`practices` carries structured status for the seven §4(b)
    minimum practices, including §4(a)(ii) CAIO waivers. Persisted
    v0.10.12-era assessments without the field still load (it defaults
    to empty — "nothing recorded yet", which
    :func:`practice_compliance` reports as missing, never as satisfied).
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
    practices: dict[MinimumPractice, MinimumPracticeRecord] = Field(
        default_factory=dict,
        description=(
            "Structured per-practice status for the seven M-25-21 §4(b) "
            "minimum practices (v0.11). Keyed by practice; an absent key "
            "means 'not recorded' — distinct from an affirmative "
            "NOT_STARTED. Meaningful when determination is HIGH_IMPACT; "
            "recording against other determinations is permitted (e.g. "
            "practices retained after a re-determination) but reported "
            "as advisory only."
        ),
    )


class PracticeComplianceSummary(EvidentiaModel):
    """Roll-up of one assessment's per-practice state (advisory).

    ``satisfied`` is deliberately strict: every one of the seven
    practices must be recorded AND be either IMPLEMENTED or WAIVED.
    Unrecorded practices are ``missing`` — Evidentia never fabricates a
    status for them.
    """

    total: int = Field(description="Total minimum practices (always 7).")
    implemented: int = Field(description="Practices recorded IMPLEMENTED.")
    in_progress: int = Field(description="Practices recorded IN_PROGRESS.")
    not_started: int = Field(description="Practices recorded NOT_STARTED.")
    waived: int = Field(description="Practices recorded WAIVED.")
    missing: list[MinimumPractice] = Field(
        description="Practices with no recorded status.",
    )
    satisfied: bool = Field(
        description=(
            "True iff all seven practices are recorded and each is "
            "IMPLEMENTED or WAIVED."
        ),
    )


def practice_compliance(
    assessment: OMBHighImpactAssessment,
) -> PracticeComplianceSummary:
    """Summarize an assessment's per-practice compliance state.

    Pure roll-up over :attr:`OMBHighImpactAssessment.practices` — no
    dates are evaluated here (waiver-clock checks are the separate
    :func:`waiver_certification_due` / :func:`waiver_omb_report_overdue`
    helpers, which need a "today").
    """
    counts = dict.fromkeys(PracticeStatus, 0)
    for record in assessment.practices.values():
        status = (
            record.status
            if isinstance(record.status, PracticeStatus)
            else PracticeStatus(record.status)
        )
        counts[status] += 1
    recorded = {
        practice
        if isinstance(practice, MinimumPractice)
        else MinimumPractice(practice)
        for practice in assessment.practices
    }
    missing = sorted(set(MinimumPractice) - recorded, key=lambda p: p.value)
    satisfied = not missing and all(
        (
            record.status
            if isinstance(record.status, PracticeStatus)
            else PracticeStatus(record.status)
        )
        in (PracticeStatus.IMPLEMENTED, PracticeStatus.WAIVED)
        for record in assessment.practices.values()
    )
    return PracticeComplianceSummary(
        total=len(MinimumPractice),
        implemented=counts[PracticeStatus.IMPLEMENTED],
        in_progress=counts[PracticeStatus.IN_PROGRESS],
        not_started=counts[PracticeStatus.NOT_STARTED],
        waived=counts[PracticeStatus.WAIVED],
        missing=missing,
        satisfied=satisfied,
    )


def waiver_certification_due(waiver: PracticeWaiver, today: date) -> bool:
    """True when the §4(a)(ii) annual re-certification is overdue.

    The clock anchors on the most recent certification
    (``last_certified_on``), or on ``issued_on`` when the waiver has
    never been re-certified.
    """
    anchor = waiver.last_certified_on or waiver.issued_on
    return (today - anchor).days > 365


def waiver_omb_report_overdue(waiver: PracticeWaiver, today: date) -> bool:
    """True when the §4(a)(iii) 30-day OMB report is overdue.

    False once ``reported_to_omb_on`` is set (regardless of whether the
    report itself was late — that is history, not an open action).
    """
    if waiver.reported_to_omb_on is not None:
        return False
    return (today - waiver.issued_on).days > 30


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
    "MinimumPractice",
    "MinimumPracticeRecord",
    "OMBHighImpactAssessment",
    "PracticeComplianceSummary",
    "PracticeStatus",
    "PracticeWaiver",
    "crosswalk_from_legacy",
    "practice_compliance",
    "triggers_minimum_practices",
    "waiver_certification_due",
    "waiver_omb_report_overdue",
]
