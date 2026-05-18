"""Control gap analysis models.

Represents the difference between what a framework requires and what
an organization has implemented. The gap analyzer produces these models
as its primary output.

v0.9.0 P1 extension: ``ControlGap`` gains an optional ``poam_milestones``
field carrying a list of :class:`Milestone` records that track the
remediation lifecycle for a Plan-of-Action-and-Milestones entry. The
field defaults to an empty list, so v0.7.x + v0.8.x serialized gap
reports re-parse cleanly under v0.9.0 (Pydantic adds the empty list on
parse). The :class:`POAMState` enum carries the canonical lifecycle
states an auditor sees in OSCAL POA&M emit (NIST SP 800-53A Rev 5
Appendix F + FedRAMP POA&M Template Completion Guide v3.0).
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum

from pydantic import Field

from evidentia_core.models.common import (
    EvidentiaModel,
    current_version,
    new_id,
    utc_now,
)


class GapSeverity(str, Enum):
    """Severity of a control gap based on framework requirement and implementation state."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ImplementationEffort(str, Enum):
    """Estimated effort to remediate a gap."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class GapStatus(str, Enum):
    """Current status of gap remediation."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"
    NOT_APPLICABLE = "not_applicable"


class POAMState(str, Enum):
    """Plan-of-Action-and-Milestones lifecycle state (v0.9.0 P1).

    Aligned to the FedRAMP POA&M Template Completion Guide v3.0 + NIST
    SP 800-53A Rev 5 Appendix F vocabulary an auditor sees in OSCAL
    POA&M emit. The five states are time-ordered (planned → in-progress
    → completed → verified) plus the off-axis ``OVERDUE`` state that
    fires when a planned/in-progress milestone's date is in the past
    relative to the system clock.

    State transition rules (enforced by
    :func:`evidentia_core.poam.state.is_valid_transition`):

    - ``PLANNED`` → ``IN_PROGRESS`` | ``OVERDUE`` | ``COMPLETED``
    - ``IN_PROGRESS`` → ``COMPLETED`` | ``OVERDUE``
    - ``OVERDUE`` → ``IN_PROGRESS`` | ``COMPLETED`` (operator catches up)
    - ``COMPLETED`` → ``VERIFIED`` (auditor sign-off; closes the loop)
    - ``VERIFIED`` is terminal — re-opening a verified milestone
      requires creating a new milestone, never mutating the verified
      record (audit-trail integrity).

    Backward transitions (e.g., ``COMPLETED`` → ``IN_PROGRESS``) are
    explicitly forbidden by the state machine. An auditor-defensible
    POA&M must show forward progress only; a "we changed our mind"
    rewind is captured as a NEW milestone with a fresh planned date,
    not an edit to the prior record.
    """

    PLANNED = "planned"
    """Milestone is scheduled but work hasn't started."""

    IN_PROGRESS = "in_progress"
    """Operator is actively working the milestone."""

    OVERDUE = "overdue"
    """Milestone date is in the past + status is not yet COMPLETED.

    Computed at query time by :func:`evidentia_core.poam.state.derive_overdue`
    against a reference date; the persisted ``status`` field records
    operator-set state, while ``OVERDUE`` is a derived attention signal
    that the auditing harness surfaces at report-emit time.
    """

    COMPLETED = "completed"
    """Operator-claimed completion; pending auditor verification."""

    VERIFIED = "verified"
    """Auditor confirmed the milestone is closed. Terminal state."""


class Milestone(EvidentiaModel):
    """A single Plan-of-Action-and-Milestones milestone (v0.9.0 P1).

    Each ``ControlGap`` carries a (possibly empty) list of milestones
    tracking the remediation timeline. The OSCAL POA&M emit
    (v0.9.0 P2) materializes the milestone list into the OSCAL
    ``observation`` + ``risk`` + ``poam-item`` element graph; until
    P2 lands, milestones are persisted on the gap record + surfaced
    via the v0.9.0 P2 CLI/REST surfaces.

    The model is intentionally minimal — date + description + status +
    optional evidence ref — so the v0.9.0 walk-through (Phase 4) can
    surface federal-SI customer scenarios without rework. Additional
    fields (assigned_to, milestone_id cross-references, dependency
    graph) defer to v0.9.1 or v1.0 unless the walk-through demands them.
    """

    id: str = Field(
        default_factory=new_id,
        description=(
            "UUID v4 stamp for cross-referencing in OSCAL POA&M emit. "
            "Stable across edits to other fields; never re-stamped."
        ),
    )
    target_date: date = Field(
        description=(
            "Target completion date. Naive ``date`` (no timezone); the "
            "POA&M cycle calendar treats this as the operator's local "
            "fiscal date for ``OVERDUE`` derivation."
        ),
    )
    description: str = Field(
        min_length=1,
        max_length=2048,
        description=(
            "Human-readable milestone description. What the operator "
            "is committing to deliver. Auditors read this verbatim "
            "from the OSCAL POA&M emit; it should stand alone without "
            "the surrounding gap context."
        ),
    )
    status: POAMState = Field(
        default=POAMState.PLANNED,
        description=(
            "Operator-set lifecycle state. ``OVERDUE`` is set "
            "explicitly by the operator OR derived at query time "
            "from ``target_date < today AND status in {PLANNED, "
            "IN_PROGRESS}`` via "
            ":func:`evidentia_core.poam.state.derive_overdue`."
        ),
    )
    evidence_ref: str | None = Field(
        default=None,
        max_length=512,
        description=(
            "Optional reference to the evidence artifact that closes "
            "the milestone (Sigstore-signed JSON, OSCAL Assessment "
            "Result UUID, Jira ticket key, ServiceNow change record, "
            "S3 object URI, etc.). Free-form string; the OSCAL "
            "POA&M exporter (v0.9.0 P2) maps this into a "
            "``back-matter`` ``resource`` if it parses as a URL or "
            "URI; otherwise emits as ``prop[name=evidentia.evidence_ref]``."
        ),
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        description="UTC timestamp when the milestone was first added.",
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        description=(
            "UTC timestamp of the last status transition or field "
            "edit. Refreshed by :func:`evidentia_core.poam_store.save_poam` "
            "on every persist call."
        ),
    )
    # ── Collaboration primitives (v0.9.5 P3.1) ───────────────────────
    # All Optional + backward-compat with v0.9.4-shipped milestones
    # (deserializing a v0.9.4 milestone JSON / OSCAL POA&M emit with
    # no owner/reviewer fields populates them as None).
    owner: str | None = Field(
        default=None,
        max_length=256,
        description=(
            "v0.9.5 P3.1: optional owner identifier — the person or "
            "team responsible for driving this milestone to closure. "
            "Free-form string; conventions vary (email, Slack handle, "
            "Jira username, AD group name). The CLI ``poam list "
            "--owner X`` + REST ``GET /api/poam?owner=X`` filters on "
            "exact-match equality. Federal-SI deployments typically "
            "use the same identifier as the FedRAMP POA&M Template "
            "'Point of Contact' column."
        ),
    )
    reviewer: str | None = Field(
        default=None,
        max_length=256,
        description=(
            "v0.9.5 P3.1: optional reviewer identifier — the person "
            "or team responsible for validating that the milestone is "
            "genuinely closed before the status transitions to "
            "``VERIFIED``. Separate from ``owner`` so the two-eyes "
            "principle is enforceable at the data-model layer."
        ),
    )


class ControlGap(EvidentiaModel):
    """A single control gap identified by the gap analyzer.

    Represents a framework requirement that the organization has not
    fully implemented.
    """

    id: str = Field(default_factory=new_id)
    # ── Framework requirement ──────────────────────────────────────────
    framework: str = Field(
        description="Framework ID, e.g. 'nist-800-53-mod', 'soc2-tsc'",
    )
    control_id: str = Field(
        description="Control ID within the framework, e.g. 'AC-2', 'CC6.1'",
    )
    control_title: str = Field(
        description="Human-readable control title from the catalog",
    )
    control_description: str = Field(
        description="Full control description from the catalog",
    )
    control_family: str | None = Field(
        default=None,
        description="Control family or category",
    )
    # ── Gap details ────────────────────────────────────────────────────
    gap_severity: GapSeverity = Field(
        description="Severity based on requirement level and implementation state",
    )
    implementation_status: str = Field(
        description=(
            "Current state: 'missing', 'partial', 'planned', 'not_applicable'"
        ),
    )
    gap_description: str = Field(
        description="Specific description of what is missing or incomplete",
    )
    status: GapStatus = Field(
        default=GapStatus.OPEN,
        description="Current remediation status",
    )
    # ── Cross-framework analysis ───────────────────────────────────────
    equivalent_controls_in_inventory: list[str] = Field(
        default_factory=list,
        description="Organization control IDs that partially satisfy this requirement",
    )
    cross_framework_value: list[str] = Field(
        default_factory=list,
        description="Other framework:control_id pairs that this gap also satisfies",
    )
    # ── Remediation ────────────────────────────────────────────────────
    remediation_guidance: str = Field(
        description="Actionable remediation guidance for this gap",
    )
    implementation_effort: ImplementationEffort = Field(
        description="Estimated engineering effort to close this gap",
    )
    priority_score: float = Field(
        default=0.0,
        description="Computed priority score (higher = more urgent)",
    )
    # ── Ticket tracking ────────────────────────────────────────────────
    jira_issue_key: str | None = Field(default=None)
    servicenow_ticket_id: str | None = Field(default=None)
    # ── POA&M milestones (v0.9.0 P1) ───────────────────────────────────
    # Optional list of remediation milestones. Default-empty preserves
    # backward-compat with v0.7.x + v0.8.x serialized gap reports. The
    # OSCAL POA&M exporter (v0.9.0 P2) materializes this list into the
    # ``poam-item`` element graph; gaps with an empty list are still
    # valid POA&M items but emit without milestones (representing
    # accepted-risk or not-yet-planned remediation).
    poam_milestones: list[Milestone] = Field(
        default_factory=list,
        description=(
            "Plan-of-Action-and-Milestones milestones for this gap. "
            "Order is preserved across save+load round-trips. "
            "Sorting by ``target_date`` happens at query time, not "
            "at persistence time."
        ),
    )
    # ── Lifecycle ──────────────────────────────────────────────────────
    created_at: datetime = Field(default_factory=utc_now)
    remediated_at: datetime | None = Field(default=None)
    assigned_to: str | None = Field(default=None)
    tags: list[str] = Field(default_factory=list)


class EfficiencyOpportunity(EvidentiaModel):
    """A control that satisfies multiple framework requirements simultaneously.

    These are high-value implementation targets — implementing one control
    closes gaps across multiple frameworks.
    """

    control_id: str = Field(
        description="The NIST 800-53 control ID (canonical reference)",
    )
    control_title: str = Field(description="Human-readable control title")
    frameworks_satisfied: list[str] = Field(
        description="List of framework:control_id pairs this satisfies",
    )
    framework_count: int = Field(description="Number of distinct frameworks satisfied")
    total_gaps_closed: int = Field(
        description="Total number of gap entries that would be closed",
    )
    implementation_effort: ImplementationEffort = Field(
        description="Estimated effort to implement",
    )
    value_score: float = Field(
        description="Efficiency value score = total_gaps_closed / effort_weight",
    )


class GapAnalysisReport(EvidentiaModel):
    """Complete gap analysis report.

    The primary output of the gap analyzer. Contains all identified gaps,
    efficiency opportunities, and a prioritized remediation roadmap.
    """

    id: str = Field(default_factory=new_id)
    organization: str = Field(
        description="Organization name from the control inventory",
    )
    frameworks_analyzed: list[str] = Field(
        description="Framework IDs that were analyzed",
    )
    analyzed_at: datetime = Field(default_factory=utc_now)
    # ── Summary statistics ─────────────────────────────────────────────
    total_controls_required: int = Field(
        description="Total unique controls required across all analyzed frameworks",
    )
    total_controls_in_inventory: int = Field(
        description="Total controls in the organization's inventory",
    )
    total_gaps: int
    critical_gaps: int
    high_gaps: int
    medium_gaps: int
    low_gaps: int
    informational_gaps: int = Field(default=0)
    coverage_percentage: float = Field(
        description="Percentage of required controls that are fully implemented",
    )
    # ── Detail ─────────────────────────────────────────────────────────
    gaps: list[ControlGap] = Field(
        description="All identified gaps, sorted by priority_score descending",
    )
    efficiency_opportunities: list[EfficiencyOpportunity] = Field(
        default_factory=list,
        description="Controls that satisfy 3+ framework requirements",
    )
    prioritized_roadmap: list[str] = Field(
        default_factory=list,
        description="Ordered list of gap IDs by descending priority_score",
    )
    # ── Metadata ───────────────────────────────────────────────────────
    inventory_source: str | None = Field(
        default=None,
        description="Path to the inventory file used",
    )
    evidentia_version: str = Field(
        default_factory=current_version,
        description="Version of evidentia-core that produced this report",
    )
    notes: str | None = Field(default=None)
