"""Governance primitives — Three Lines of Defense + Effective Challenge.

Introduced in v0.7.10 P1.5 per `docs/releases/plans/v0.7.10-plan.md`. Brings
Evidentia into alignment with the IIA "Three Lines Model" (2020
revision) and SR 11-7 / SR 26-02 §III.D effective-challenge
expectations regulators apply across financial-services
risk-management programs.

Public surface:

  - :class:`LineOfDefense` enum (first / second / third)
  - :class:`Owner` Pydantic model — email + line-of-defense
    classification + optional team / title metadata
  - :func:`generate_lines_report` — aggregates classified owners
    across the vendor + model-risk inventories into a Markdown
    distribution report

Shipped surfaces in this module:

- :class:`EffectiveChallenge` + :class:`ChallengeOutcome` (v0.7.10 P1.5 G2)
- :class:`Metric` + :class:`MetricKind` + :class:`MetricObservation`
  + :class:`MetricStatus` (v0.7.10 P1.5 G3)
- :class:`Workflow` + workflow_store primitives (v0.7.11)
"""

from __future__ import annotations

from evidentia_core.governance.effective_challenge import (
    ChallengeOutcome,
    EffectiveChallenge,
)
from evidentia_core.governance.lines_of_defense import (
    LineOfDefense,
    Owner,
    generate_lines_report,
)
from evidentia_core.governance.metrics import (
    Metric,
    MetricDirection,
    MetricKind,
    MetricObservation,
    MetricStatus,
    evaluate_metric,
    generate_metrics_report,
)
from evidentia_core.governance.workflows import (
    Workflow,
    WorkflowAdvanceError,
    WorkflowStatus,
    WorkflowStep,
    WorkflowStepEvent,
    WorkflowStepStatus,
    advance_workflow_step,
    current_step_index,
    evaluate_workflow,
    generate_workflow_log,
)

__all__ = [
    "ChallengeOutcome",
    "EffectiveChallenge",
    "LineOfDefense",
    "Metric",
    "MetricDirection",
    "MetricKind",
    "MetricObservation",
    "MetricStatus",
    "Owner",
    "Workflow",
    "WorkflowAdvanceError",
    "WorkflowStatus",
    "WorkflowStep",
    "WorkflowStepEvent",
    "WorkflowStepStatus",
    "advance_workflow_step",
    "current_step_index",
    "evaluate_metric",
    "evaluate_workflow",
    "generate_lines_report",
    "generate_metrics_report",
    "generate_workflow_log",
]
