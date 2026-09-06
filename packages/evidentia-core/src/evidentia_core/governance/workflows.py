"""Process-as-code governance workflows (v0.7.11 P1.5 G5).

Operators declare governance processes in YAML (or Pydantic
directly) — change-approval workflows, quarterly-review workflows,
validation-cycle workflows, etc. — then execute + track them via
the ``evidentia governance workflow {run, status, log}`` CLI.

The core abstraction is a sequenced list of :class:`WorkflowStep`
items, each with a name + role (cross-references the v0.7.10 P1.5
G1 :class:`Owner.line_of_defense`), required-status, and optional
SLA in days. As a workflow runs, each step transitions through
states (PENDING → IN_PROGRESS → APPROVED / REJECTED / SKIPPED)
with timestamped + actor-tagged events.

Use cases:

  - **Change-approval**: 1st-line submitter → 2nd-line risk
    review → 3rd-line audit (for material changes) → CAB approval
  - **Quarterly review**: business owner → MRM (for model
    changes) → CISO sign-off → board reporting
  - **Validation cycle**: model owner submits → independent
    validator reviews → MRM director approves → finding tracking

Public surface:

  - :class:`WorkflowStepStatus` enum (5 states)
  - :class:`WorkflowStatus` enum (5 states)
  - :class:`WorkflowStepEvent` — one timestamped state-transition
  - :class:`WorkflowStep` — a step definition + history
  - :class:`Workflow` — a workflow definition + step list
  - :func:`advance_workflow_step` — transition a step's status
  - :func:`current_step_index` — find the active step in a workflow
  - :func:`evaluate_workflow` — overall workflow status from steps
  - :func:`generate_workflow_log` — Markdown audit-log report
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import Field

from evidentia_core.models.common import (
    EvidentiaModel,
    current_version,
    new_id,
    utc_now,
)


class WorkflowStepStatus(str, Enum):
    """Step lifecycle states."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    APPROVED = "approved"
    REJECTED = "rejected"
    SKIPPED = "skipped"


class WorkflowStatus(str, Enum):
    """Overall workflow lifecycle states."""

    DRAFT = "draft"
    IN_PROGRESS = "in_progress"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELED = "canceled"


# Terminal step states — once reached, the step doesn't transition
# further (a new submission requires a new workflow instance).
_TERMINAL_STEP_STATES = {
    WorkflowStepStatus.APPROVED.value,
    WorkflowStepStatus.REJECTED.value,
    WorkflowStepStatus.SKIPPED.value,
}


class WorkflowStepEvent(EvidentiaModel):
    """One timestamped state-transition on a workflow step."""

    occurred_at: datetime = Field(default_factory=utc_now)
    actor: str = Field(description=("Identity who performed the transition (typically email)."))
    from_status: WorkflowStepStatus
    to_status: WorkflowStepStatus
    note: str | None = Field(
        default=None,
        description="Optional rationale / approval note.",
    )


class WorkflowStep(EvidentiaModel):
    """One step in a governance workflow.

    Each step has:

      - a name + sequence number (zero-indexed; populated by
        ``Workflow``)
      - a ``required_role`` label that should match the actor's
        line of defense or domain (free-text — the workflow does
        NOT enforce role-actor binding; that's the operator's
        organizational discipline)
      - a current ``status``
      - an optional SLA in days
      - a history of state-transition events
    """

    name: str = Field(description="Step name (e.g., 'MRM 2nd-line review').")
    description: str | None = Field(
        default=None,
        description="What this step requires + what counts as approval.",
    )
    required_role: str = Field(
        description=(
            "Role label of the actor expected to perform this step "
            "(e.g., 'MRM Director', '3LOD-second', 'CAB chair'). "
            "Free-text; not enforced by the engine."
        )
    )
    status: WorkflowStepStatus = Field(
        default=WorkflowStepStatus.PENDING,
        description="Current state.",
    )
    sla_days: int | None = Field(
        default=None,
        ge=1,
        description="Optional SLA in calendar days from in-progress.",
    )
    history: list[WorkflowStepEvent] = Field(
        default_factory=list,
        description="Timestamped state-transition events.",
    )


class Workflow(EvidentiaModel):
    """A governance workflow definition + execution state.

    Stepwise execution: callers transition steps in order via
    :func:`advance_workflow_step`. The first step is auto-promoted
    from PENDING → IN_PROGRESS when the workflow is created (if
    operators want a strictly draft-then-start flow, they can
    explicitly mark the workflow DRAFT until the first transition).
    """

    id: str = Field(default_factory=new_id)
    name: str = Field(description="Workflow instance name (e.g., 'Credit-model-v3 quarterly review 2026-Q1').")
    template: str | None = Field(
        default=None,
        description=(
            "Optional reference to a workflow template name. "
            "Templates are external — operators can maintain a "
            "template library + use this field for traceability."
        ),
    )
    description: str = Field(description="Workflow purpose narrative.")
    subject: str | None = Field(
        default=None,
        description=(
            "What/who is the workflow about (e.g., 'Model X', 'Vendor Y', 'Change request CR-1234'). Free-text."
        ),
    )
    steps: list[WorkflowStep] = Field(
        default_factory=list,
        description="Ordered list of workflow steps.",
    )
    status: WorkflowStatus = Field(
        default=WorkflowStatus.DRAFT,
        description="Overall workflow status (derived from step states).",
    )
    initiator: str = Field(description="Identity (typically email) that initiated the workflow.")

    # Auto-populated metadata
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    evidentia_version: str = Field(default_factory=current_version)


def current_step_index(workflow: Workflow) -> int | None:
    """Return the index of the first step that is not in a terminal state.

    None if all steps are terminal (workflow finished) or the step
    list is empty.
    """
    for i, step in enumerate(workflow.steps):
        if step.status not in _TERMINAL_STEP_STATES:
            return i
    return None


def evaluate_workflow(workflow: Workflow) -> WorkflowStatus:
    """Compute the overall :class:`WorkflowStatus` from its step states.

    Logic:

      - Any REJECTED step → REJECTED (rejection short-circuits)
      - All steps APPROVED or SKIPPED → APPROVED
      - Any IN_PROGRESS or PENDING step (and no rejection) →
        IN_PROGRESS (or DRAFT if the FIRST step is still PENDING)
    """
    if not workflow.steps:
        return WorkflowStatus.DRAFT
    statuses = [s.status for s in workflow.steps]
    if any(s == WorkflowStepStatus.REJECTED.value for s in statuses):
        return WorkflowStatus.REJECTED
    terminal_or_skipped = {
        WorkflowStepStatus.APPROVED.value,
        WorkflowStepStatus.SKIPPED.value,
    }
    if all(s in terminal_or_skipped for s in statuses):
        return WorkflowStatus.APPROVED
    # Some non-terminal step exists. If we've made any progress
    # past the first step, we're IN_PROGRESS; otherwise DRAFT.
    if (
        statuses[0] == WorkflowStepStatus.PENDING.value
        and len([s for s in statuses if s != WorkflowStepStatus.PENDING.value]) == 0
    ):
        return WorkflowStatus.DRAFT
    return WorkflowStatus.IN_PROGRESS


class WorkflowAdvanceError(ValueError):
    """Raised when an attempted step transition violates workflow rules."""


def advance_workflow_step(
    workflow: Workflow,
    *,
    step_index: int,
    new_status: WorkflowStepStatus,
    actor: str,
    note: str | None = None,
) -> Workflow:
    """Transition a step to a new status + return an updated workflow.

    Rules:

      - ``step_index`` must be valid + must reference the
        currently-active step (no skipping ahead; SKIP a step
        explicitly via this function with new_status=SKIPPED if
        the operator wants to bypass it)
      - The current step's existing status must NOT already be
        terminal (APPROVED / REJECTED / SKIPPED)
      - Only PENDING / IN_PROGRESS steps can transition to
        APPROVED / REJECTED / SKIPPED / IN_PROGRESS

    Raises :class:`WorkflowAdvanceError` on any rule violation.

    Returns a NEW ``Workflow`` instance (input is not mutated)
    with:
      - the targeted step's history appended
      - the targeted step's status updated
      - the next step's status auto-promoted to IN_PROGRESS if
        this was a forward transition
      - the workflow's overall status re-evaluated
      - ``updated_at`` refreshed
    """
    if step_index < 0 or step_index >= len(workflow.steps):
        raise WorkflowAdvanceError(f"Step index {step_index} out of range (workflow has {len(workflow.steps)} step(s))")
    target_step = workflow.steps[step_index]
    if target_step.status in _TERMINAL_STEP_STATES:
        raise WorkflowAdvanceError(
            f"Step {step_index} ({target_step.name!r}) is already terminal ({target_step.status}); cannot transition."
        )
    active_idx = current_step_index(workflow)
    if active_idx is not None and step_index != active_idx:
        raise WorkflowAdvanceError(
            f"Step {step_index} is not the active step (active is index {active_idx}); steps must execute in order."
        )

    # Build the new step with appended event + new status
    event = WorkflowStepEvent(
        actor=actor,
        from_status=WorkflowStepStatus(target_step.status),
        to_status=new_status,
        note=note,
    )
    new_step = target_step.model_copy(
        update={
            "status": new_status,
            "history": [*target_step.history, event],
        }
    )

    # Build the new step list; auto-promote next step if this was a
    # forward transition (APPROVED / SKIPPED) and a next step exists
    # that's still PENDING.
    new_steps = list(workflow.steps)
    new_steps[step_index] = new_step
    if (
        new_status
        in {
            WorkflowStepStatus.APPROVED,
            WorkflowStepStatus.SKIPPED,
        }
        and step_index + 1 < len(new_steps)
        and new_steps[step_index + 1].status == WorkflowStepStatus.PENDING.value
    ):
        promoted = new_steps[step_index + 1].model_copy(update={"status": WorkflowStepStatus.IN_PROGRESS.value})
        new_steps[step_index + 1] = promoted

    new_workflow = workflow.model_copy(
        update={
            "steps": new_steps,
            "updated_at": utc_now(),
        }
    )
    # Re-evaluate workflow-level status from the updated step states
    new_workflow = new_workflow.model_copy(update={"status": evaluate_workflow(new_workflow)})
    return new_workflow


def _format_event(e: WorkflowStepEvent) -> str:
    note = f" — {e.note}" if e.note else ""
    return f"`{e.occurred_at.isoformat()}` **{e.actor}**: {e.from_status} → {e.to_status}{note}"


def generate_workflow_log(workflow: Workflow) -> str:
    """Generate a Markdown audit-log of a workflow's full lifecycle.

    Sections:

      1. Header (name + subject + status + initiator + timestamps)
      2. Per-step status table
      3. Per-step event narrative (timestamped + actor-tagged)

    Output is deterministic — same input produces the same output
    character-for-character.
    """
    sections: list[str] = []
    overall = evaluate_workflow(workflow).value
    breach_callout = ""
    if overall == WorkflowStatus.REJECTED.value:
        breach_callout = (
            "> ⚠️ **Workflow REJECTED.** A step rejection short-"
            "circuited the flow; review the step that produced the "
            "REJECTED status below.\n\n"
        )

    sections.append(
        f"# Workflow Audit Log — {workflow.name}\n\n"
        f"_Process-as-code governance workflow log per v0.7.11 P1.5 G5._\n\n"
        f"{breach_callout}"
        f"**ID**: `{workflow.id}`  \n"
        f"**Subject**: {workflow.subject or '_not specified_'}  \n"
        f"**Initiator**: {workflow.initiator}  \n"
        f"**Status**: `{overall}`  \n"
        f"**Description**: {workflow.description}  \n"
        f"**Created**: {workflow.created_at.isoformat()}  \n"
        f"**Updated**: {workflow.updated_at.isoformat()}  \n"
    )

    if not workflow.steps:
        sections.append("## Steps\n\n_No steps defined._\n")
        return "\n".join(sections)

    # ── §2 Per-step status table ────────────────────────────────
    rows = []
    for i, step in enumerate(workflow.steps):
        sla = f"{step.sla_days}d" if step.sla_days else "—"
        rows.append(f"| {i} | {step.name} | {step.required_role} | {step.status} | {sla} | {len(step.history)} |")
    sections.append(
        "## Steps\n\n"
        "| # | Name | Required role | Status | SLA | Events |\n"
        "| --- | --- | --- | --- | --- | --- |\n" + "\n".join(rows) + "\n"
    )

    # ── §3 Per-step event narrative ─────────────────────────────
    sections.append("## Event narrative\n")
    for i, step in enumerate(workflow.steps):
        sections.append(f"### Step {i} — {step.name} (`{step.status}`)\n\n**Required role**: {step.required_role}\n")
        if step.description:
            sections.append(f"**Description**: {step.description}\n")
        if not step.history:
            sections.append("_No events yet._\n")
        else:
            sections.append("Events:\n\n" + "\n".join(f"- {_format_event(e)}" for e in step.history) + "\n")

    return "\n".join(sections)
