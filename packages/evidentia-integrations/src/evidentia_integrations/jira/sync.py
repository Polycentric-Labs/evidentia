"""Gap-to-Jira push + sync helpers.

Composes :class:`JiraClient` with the pure-functional mapper in
:mod:`.mapper` so callers (CLI, API) get a single function that takes
a gap and does the right thing:

- :func:`push_gap_to_jira` — create a Jira issue for a gap and stamp
  the returned key onto ``gap.jira_issue_key``.
- :func:`sync_gap_from_jira` — read the linked Jira issue and update
  ``gap.status`` if the Jira status maps to a known GapStatus.
- :func:`push_open_gaps` / :func:`sync_report` — batch wrappers that
  iterate a :class:`GapAnalysisReport`.

All functions return structured :class:`JiraSyncOutcome` entries so
CLI / API callers can render per-gap results without a second pass.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from enum import Enum

from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapStatus,
)
from pydantic import BaseModel, ConfigDict, Field

from evidentia_integrations.jira.client import (
    JiraApiError,
    JiraClient,
    JiraIssue,
)
from evidentia_integrations.jira.mapper import (
    JiraMappingError,
    gap_to_create_request,
    jira_status_to_gap_status,
)

logger = logging.getLogger(__name__)


class JiraSyncAction(str, Enum):
    """What happened to a single gap during a batch push/sync operation."""

    CREATED = "created"
    UPDATED = "updated"
    SKIPPED = "skipped"
    ERRORED = "errored"


class JiraSyncOutcome(BaseModel):
    """One row of a batch push/sync result — one per gap processed."""

    model_config = ConfigDict(extra="forbid")

    gap_id: str
    control_id: str
    framework: str
    action: JiraSyncAction
    issue_key: str | None = Field(
        default=None,
        description=("Jira issue key after push/sync — populated on CREATED/UPDATED."),
    )
    issue_url: str | None = Field(default=None)
    detail: str = Field(
        description=("Human-readable one-line explanation — rendered verbatim in CLI output and GUI toast messages."),
    )
    new_status: GapStatus | None = Field(
        default=None,
        description=(
            "If the gap's status changed during sync, this is the new value. "
            "Not mirrored for CREATED actions (those don't change status)."
        ),
    )


class JiraSyncResult(BaseModel):
    """Aggregate result of a batch push or sync operation."""

    model_config = ConfigDict(extra="forbid")

    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    outcomes: list[JiraSyncOutcome] = Field(default_factory=list)

    @property
    def created(self) -> int:
        return sum(1 for o in self.outcomes if o.action == JiraSyncAction.CREATED)

    @property
    def updated(self) -> int:
        return sum(1 for o in self.outcomes if o.action == JiraSyncAction.UPDATED)

    @property
    def skipped(self) -> int:
        return sum(1 for o in self.outcomes if o.action == JiraSyncAction.SKIPPED)

    @property
    def errored(self) -> int:
        return sum(1 for o in self.outcomes if o.action == JiraSyncAction.ERRORED)


# ── Single-gap ────────────────────────────────────────────────────────────


def push_gap_to_jira(
    gap: ControlGap,
    client: JiraClient,
    *,
    force: bool = False,
) -> JiraSyncOutcome:
    """Create a Jira issue for a gap.

    If ``gap.jira_issue_key`` is already populated, the function is a
    no-op (SKIPPED) — unless ``force=True``, in which case a new issue
    is created regardless. The previous key isn't deleted from Jira;
    only the Evidentia linkage is overwritten.

    The function mutates ``gap.jira_issue_key`` on success so callers
    can persist the updated ``GapAnalysisReport`` back to the gap
    store.
    """
    if gap.jira_issue_key and not force:
        return JiraSyncOutcome(
            gap_id=gap.id,
            control_id=gap.control_id,
            framework=gap.framework,
            action=JiraSyncAction.SKIPPED,
            issue_key=gap.jira_issue_key,
            detail=(f"Already linked to {gap.jira_issue_key}; pass force=True to create a new issue anyway."),
        )

    try:
        payload = gap_to_create_request(gap)
    except JiraMappingError as e:
        return JiraSyncOutcome(
            gap_id=gap.id,
            control_id=gap.control_id,
            framework=gap.framework,
            action=JiraSyncAction.ERRORED,
            detail=f"Mapping error: {e}",
        )

    try:
        # gap_to_create_request returns dict[str, object] because the
        # nested values mix strings + lists + nested dicts. Narrow to the
        # concrete shapes JiraClient.create_issue expects; the mapper's
        # unit tests assert these slots hold their expected types.
        labels_raw = payload["labels"]
        extras_raw = payload["extra_fields"]
        labels: list[str] = list(labels_raw) if isinstance(labels_raw, list) else []
        extras: dict[str, object] = dict(extras_raw) if isinstance(extras_raw, dict) else {}
        issue: JiraIssue = client.create_issue(
            summary=str(payload["summary"]),
            description=str(payload["description"]),
            labels=labels,
            extra_fields=extras,
        )
    except JiraApiError as e:
        return JiraSyncOutcome(
            gap_id=gap.id,
            control_id=gap.control_id,
            framework=gap.framework,
            action=JiraSyncAction.ERRORED,
            detail=f"Jira API error: {e}",
        )

    gap.jira_issue_key = issue.key
    return JiraSyncOutcome(
        gap_id=gap.id,
        control_id=gap.control_id,
        framework=gap.framework,
        action=JiraSyncAction.CREATED,
        issue_key=issue.key,
        issue_url=issue.url,
        detail=f"Created {issue.key}",
    )


def sync_gap_from_jira(
    gap: ControlGap,
    client: JiraClient,
) -> JiraSyncOutcome:
    """Read ``gap.jira_issue_key``'s status + update the gap if it changed.

    - No-op SKIPPED when ``gap.jira_issue_key`` is blank.
    - UPDATED when the Jira status maps to a different GapStatus than
      the gap currently holds.
    - SKIPPED ("status unchanged") when the mapping matches.
    - SKIPPED ("unknown Jira status") when Jira's status name isn't in
      :data:`JIRA_STATUS_TO_GAP_STATUS`.
    - ERRORED on HTTP / API failures.
    """
    if not gap.jira_issue_key:
        return JiraSyncOutcome(
            gap_id=gap.id,
            control_id=gap.control_id,
            framework=gap.framework,
            action=JiraSyncAction.SKIPPED,
            detail="Gap is not linked to a Jira issue yet.",
        )

    try:
        issue = client.get_issue(gap.jira_issue_key)
    except JiraApiError as e:
        return JiraSyncOutcome(
            gap_id=gap.id,
            control_id=gap.control_id,
            framework=gap.framework,
            action=JiraSyncAction.ERRORED,
            issue_key=gap.jira_issue_key,
            detail=f"Jira API error: {e}",
        )

    mapped = jira_status_to_gap_status(issue.status_name)
    if mapped is None:
        return JiraSyncOutcome(
            gap_id=gap.id,
            control_id=gap.control_id,
            framework=gap.framework,
            action=JiraSyncAction.SKIPPED,
            issue_key=issue.key,
            issue_url=issue.url,
            detail=(
                f"Jira status {issue.status_name!r} isn't in the default "
                "mapping; leaving gap.status unchanged. Add to "
                "JIRA_STATUS_TO_GAP_STATUS to honor custom workflow names."
            ),
        )

    current = _coerce_gap_status(gap.status)
    if current == mapped:
        return JiraSyncOutcome(
            gap_id=gap.id,
            control_id=gap.control_id,
            framework=gap.framework,
            action=JiraSyncAction.SKIPPED,
            issue_key=issue.key,
            issue_url=issue.url,
            detail=f"Status unchanged ({mapped.value}).",
        )

    gap.status = mapped
    if mapped == GapStatus.REMEDIATED and gap.remediated_at is None:
        gap.remediated_at = datetime.now(UTC)

    return JiraSyncOutcome(
        gap_id=gap.id,
        control_id=gap.control_id,
        framework=gap.framework,
        action=JiraSyncAction.UPDATED,
        issue_key=issue.key,
        issue_url=issue.url,
        new_status=mapped,
        detail=(
            f"Updated gap status: {current.value if current else '?'} -> {mapped.value} (Jira: {issue.status_name})"
        ),
    )


def _coerce_gap_status(value: object) -> GapStatus | None:
    """Accept enum or string forms. Returns None for unknown strings."""
    if isinstance(value, GapStatus):
        return value
    if isinstance(value, str):
        try:
            return GapStatus(value)
        except ValueError:
            return None
    return None


# ── Batch ────────────────────────────────────────────────────────────────


def push_open_gaps(
    report: GapAnalysisReport,
    client: JiraClient,
    *,
    severity_filter: set[str] | None = None,
    max_issues: int | None = None,
) -> JiraSyncResult:
    """Push every OPEN gap in a report as a Jira issue.

    Already-linked gaps are skipped. Use ``severity_filter`` to restrict
    to e.g. ``{"critical", "high"}``; ``max_issues`` caps total creations
    (safety rail for first-time setup against a big report).
    """
    result = JiraSyncResult()
    created = 0

    for gap in report.gaps:
        current_status = _coerce_gap_status(gap.status)
        if current_status not in (GapStatus.OPEN, GapStatus.IN_PROGRESS):
            continue
        if severity_filter is not None:
            severity_str = gap.gap_severity.value if hasattr(gap.gap_severity, "value") else str(gap.gap_severity)
            if severity_str not in severity_filter:
                continue
        if max_issues is not None and created >= max_issues:
            result.outcomes.append(
                JiraSyncOutcome(
                    gap_id=gap.id,
                    control_id=gap.control_id,
                    framework=gap.framework,
                    action=JiraSyncAction.SKIPPED,
                    detail=f"max_issues={max_issues} reached; skipping remaining gaps.",
                )
            )
            continue

        outcome = push_gap_to_jira(gap, client)
        result.outcomes.append(outcome)
        if outcome.action == JiraSyncAction.CREATED:
            created += 1

    return result


def sync_report(
    report: GapAnalysisReport,
    client: JiraClient,
) -> JiraSyncResult:
    """Sync every linked gap's status from Jira."""
    result = JiraSyncResult()
    for gap in report.gaps:
        if not gap.jira_issue_key:
            continue
        result.outcomes.append(sync_gap_from_jira(gap, client))
    return result


__all__ = [
    "JiraSyncAction",
    "JiraSyncOutcome",
    "JiraSyncResult",
    "push_gap_to_jira",
    "push_open_gaps",
    "sync_gap_from_jira",
    "sync_report",
]
