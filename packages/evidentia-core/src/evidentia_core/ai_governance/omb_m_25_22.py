"""OMB M-25-22 AI acquisition-lifecycle tracking (v0.11).

`OMB Memorandum M-25-22 <https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-22-Driving-Efficient-Acquisition-of-Artificial-Intelligence-in-Government.pdf>`_
("Driving Efficient Acquisition of Artificial Intelligence in
Government", April 3, 2025) **rescinds and replaces** OMB M-24-18 and is
the procurement companion to
:mod:`~evidentia_core.ai_governance.omb_m_25_21`. Evidentia modelled no
M-24-18 surface, so this module is the first procurement surface
(v0.11 Wave 2; lifecycle phases verified against the memo text
2026-07-14).

**Scope** (memo §1): AI systems or services acquired by or on behalf of
covered agencies (44 U.S.C. §3502(1)); some requirements are CFO-Act-
agency-only; the Intelligence Community and national-security systems
are excluded. Whether a given procurement is covered is the operator's
call — Evidentia records the determination, same threat-model boundary
as the rest of ai-gov (operator-supplied metadata, not a control
surface).

**The §4 AI Acquisition Lifecycle — six phases, headings verbatim**:
(a) Identification of Requirements; (b) Market Research & Planning;
(c) Solicitation Development; (d) Selection and Award; (e) Contract
Administration; (f) Contract Closeout.

Two M-25-21 tie-ins the model carries:

- §4(a) requires agencies, during Identification of Requirements, to
  make an *initial determination of whether a system is likely to host
  high-impact AI use cases, as defined by OMB Memorandum M-25-21* —
  :attr:`AIAcquisition.likely_high_impact` reuses
  :class:`~evidentia_core.ai_governance.omb_m_25_21.HighImpactDetermination`
  (including its ``not_assessed`` open-action semantics).
- An acquisition may precede system registration, so
  :attr:`AIAcquisition.linked_system_id` is optional; link it once the
  acquired system lands in the AI registry.

Unlike M-25-21's minimum practices, M-25-22 defines **no waiver
mechanism** for the lifecycle guidance — phase tracking is
status-only. This cycle deliberately models phase STATUS, not the
per-phase MUST/SHOULD checklists (ratified 2026-07-14: smaller drift
surface against a memo with no machine-readable upstream).
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum

from pydantic import Field

from evidentia_core.ai_governance.omb_m_25_21 import HighImpactDetermination
from evidentia_core.models.common import EvidentiaModel, new_id, utc_now


class AcquisitionPhase(str, Enum):
    """One of M-25-22 §4's six AI-acquisition lifecycle phases.

    Member docstrings carry the memo's phase headings verbatim
    (verified 2026-07-14). String values are stable across releases
    (persisted in acquisition records).
    """

    IDENTIFICATION_OF_REQUIREMENTS = "identification_of_requirements"
    """§4(a) — Identification of Requirements."""

    MARKET_RESEARCH_AND_PLANNING = "market_research_and_planning"
    """§4(b) — Market Research & Planning."""

    SOLICITATION_DEVELOPMENT = "solicitation_development"
    """§4(c) — Solicitation Development."""

    SELECTION_AND_AWARD = "selection_and_award"
    """§4(d) — Selection and Award."""

    CONTRACT_ADMINISTRATION = "contract_administration"
    """§4(e) — Contract Administration."""

    CONTRACT_CLOSEOUT = "contract_closeout"
    """§4(f) — Contract Closeout."""


class AcquisitionPhaseStatus(str, Enum):
    """Progress state of one lifecycle phase for one acquisition."""

    NOT_STARTED = "not_started"
    """Recorded as upcoming; no work in this phase yet."""

    IN_PROGRESS = "in_progress"
    """The phase is underway."""

    COMPLETE = "complete"
    """The phase's activities are done for this acquisition."""


class AcquisitionPhaseRecord(EvidentiaModel):
    """Status of one lifecycle phase for one acquisition.

    Mirrors the M-25-21
    :class:`~evidentia_core.ai_governance.omb_m_25_21.MinimumPracticeRecord`
    pattern, minus waivers (M-25-22 has no waiver mechanism).
    """

    status: AcquisitionPhaseStatus = Field(
        description="Progress state of this phase.",
    )
    notes: str | None = Field(
        default=None,
        max_length=4000,
        description=(
            "Optional detail — cross-functional-team notes, artifact "
            "pointers, solicitation references."
        ),
    )
    last_reviewed: date | None = Field(
        default=None,
        description="When the operator last reviewed this status.",
    )


class AIAcquisition(EvidentiaModel):
    """One AI procurement tracked through the M-25-22 lifecycle."""

    acquisition_id: str = Field(
        default_factory=new_id,
        description="Stable UUID v4 string; assigned at registration time.",
    )
    name: str = Field(
        min_length=1,
        max_length=256,
        description="Operator-facing name for the procurement.",
    )
    solicitation_reference: str | None = Field(
        default=None,
        max_length=256,
        description=(
            "Solicitation / contract vehicle reference (RFP number, "
            "task-order ID, or similar), once one exists."
        ),
    )
    description: str | None = Field(
        default=None,
        max_length=4000,
        description="What is being acquired and why (free text).",
    )
    linked_system_id: str | None = Field(
        default=None,
        description=(
            "AI-registry system_id this acquisition delivered or will "
            "deliver. Optional — an acquisition may precede "
            "registration; link it once the system is registered."
        ),
    )
    likely_high_impact: HighImpactDetermination = Field(
        default=HighImpactDetermination.NOT_ASSESSED,
        description=(
            "The §4(a) initial determination of whether the system is "
            "likely to host high-impact AI use cases, as defined by "
            "M-25-21. not_assessed marks the open inventory action."
        ),
    )
    covered_note: str | None = Field(
        default=None,
        max_length=2000,
        description=(
            "Operator note on M-25-22 coverage/exclusions for this "
            "procurement (e.g. CFO-Act applicability, IC/NSS "
            "exclusion rationale)."
        ),
    )
    phases: dict[AcquisitionPhase, AcquisitionPhaseRecord] = Field(
        default_factory=dict,
        description=(
            "Per-phase lifecycle status keyed by §4 phase. An absent "
            "key means 'not recorded' — distinct from an affirmative "
            "NOT_STARTED."
        ),
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        description="Registration timestamp; never mutated.",
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        description="Last persistence timestamp; bumped on save.",
    )


class AcquisitionProgressSummary(EvidentiaModel):
    """Roll-up of one acquisition's lifecycle state (advisory).

    Mirrors the M-25-21 ``PracticeComplianceSummary`` posture:
    unrecorded phases are ``missing`` — Evidentia never fabricates a
    status for them; ``complete`` requires all six phases recorded AND
    complete.
    """

    total: int = Field(description="Total lifecycle phases (always 6).")
    complete: int = Field(description="Phases recorded COMPLETE.")
    in_progress: int = Field(description="Phases recorded IN_PROGRESS.")
    not_started: int = Field(description="Phases recorded NOT_STARTED.")
    missing: list[AcquisitionPhase] = Field(
        description="Phases with no recorded status.",
    )
    lifecycle_complete: bool = Field(
        description=(
            "True iff all six phases are recorded and each is COMPLETE."
        ),
    )


def acquisition_progress(acquisition: AIAcquisition) -> AcquisitionProgressSummary:
    """Summarize an acquisition's lifecycle progress.

    Pure roll-up over :attr:`AIAcquisition.phases`; no dates are
    evaluated.
    """
    counts = dict.fromkeys(AcquisitionPhaseStatus, 0)
    for record in acquisition.phases.values():
        status = (
            record.status
            if isinstance(record.status, AcquisitionPhaseStatus)
            else AcquisitionPhaseStatus(record.status)
        )
        counts[status] += 1
    recorded = {
        phase if isinstance(phase, AcquisitionPhase) else AcquisitionPhase(phase)
        for phase in acquisition.phases
    }
    missing = sorted(set(AcquisitionPhase) - recorded, key=lambda p: p.value)
    lifecycle_complete = not missing and all(
        (
            record.status
            if isinstance(record.status, AcquisitionPhaseStatus)
            else AcquisitionPhaseStatus(record.status)
        )
        == AcquisitionPhaseStatus.COMPLETE
        for record in acquisition.phases.values()
    )
    return AcquisitionProgressSummary(
        total=len(AcquisitionPhase),
        complete=counts[AcquisitionPhaseStatus.COMPLETE],
        in_progress=counts[AcquisitionPhaseStatus.IN_PROGRESS],
        not_started=counts[AcquisitionPhaseStatus.NOT_STARTED],
        missing=missing,
        lifecycle_complete=lifecycle_complete,
    )


__all__ = [
    "AIAcquisition",
    "AcquisitionPhase",
    "AcquisitionPhaseRecord",
    "AcquisitionPhaseStatus",
    "AcquisitionProgressSummary",
    "acquisition_progress",
]
