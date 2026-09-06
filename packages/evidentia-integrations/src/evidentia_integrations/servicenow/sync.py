"""Gap-to-ServiceNow push helpers.

Composes :class:`ServiceNowClient` with the pure-functional mapper
in :mod:`.mapper` so callers (CLI, API) get a single function that
takes a gap and creates / updates a ServiceNow record.

Unlike the Jira integration, ServiceNow push is one-way: it does
not pull statuses back into the gap report. Bidirectional sync is
out of scope for v0.7.7 — many ServiceNow deployments use closed-
loop workflows that the Jira-style status mapping doesn't fit.

Idempotency: each ServiceNow record carries a deterministic
``correlation_id = "evidentia-gap-<gap.id>"`` set by the mapper.
On re-push, :meth:`ServiceNowClient.find_existing_by_correlation`
deduplicates so a previously-created record is reused rather than
duplicated. Without idempotency, a second `push --gaps` run would
create N parallel records per gap.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from enum import Enum

from evidentia_core.models.gap import ControlGap, GapAnalysisReport
from pydantic import BaseModel, ConfigDict, Field

from evidentia_integrations.servicenow.client import (
    ServiceNowApiError,
    ServiceNowClient,
    ServiceNowRecord,
)
from evidentia_integrations.servicenow.mapper import (
    ServiceNowMappingError,
    gap_to_record_request,
)

logger = logging.getLogger(__name__)


class ServiceNowSyncAction(str, Enum):
    """What happened to a single gap during a batch push operation."""

    CREATED = "created"
    EXISTING = "existing"
    SKIPPED = "skipped"
    ERRORED = "errored"


class ServiceNowSyncOutcome(BaseModel):
    """One row of a batch push result — one per gap processed."""

    model_config = ConfigDict(extra="forbid")

    gap_id: str
    control_id: str
    framework: str
    action: ServiceNowSyncAction
    sys_id: str | None = Field(default=None)
    record_number: str | None = Field(default=None)
    record_url: str | None = Field(default=None)
    detail: str = Field(
        description=("Human-readable one-line explanation — rendered verbatim in CLI output and GUI toast messages."),
    )


class ServiceNowSyncResult(BaseModel):
    """Aggregate result of a batch push operation."""

    model_config = ConfigDict(extra="forbid")

    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    outcomes: list[ServiceNowSyncOutcome] = Field(default_factory=list)

    @property
    def created(self) -> int:
        return sum(1 for o in self.outcomes if o.action == ServiceNowSyncAction.CREATED)

    @property
    def existing(self) -> int:
        return sum(1 for o in self.outcomes if o.action == ServiceNowSyncAction.EXISTING)

    @property
    def skipped(self) -> int:
        return sum(1 for o in self.outcomes if o.action == ServiceNowSyncAction.SKIPPED)

    @property
    def errored(self) -> int:
        return sum(1 for o in self.outcomes if o.action == ServiceNowSyncAction.ERRORED)


# ── Single-gap ────────────────────────────────────────────────────────────


def push_gap_to_servicenow(
    gap: ControlGap,
    client: ServiceNowClient,
    *,
    force: bool = False,
) -> ServiceNowSyncOutcome:
    """Create or reuse a ServiceNow record for a gap.

    Idempotent — looks up by ``correlation_id`` first; only creates
    a new record if no existing one matches. Pass ``force=True`` to
    create regardless (rarely needed; mostly for testing).
    """
    try:
        fields = gap_to_record_request(gap)
    except ServiceNowMappingError as e:
        return ServiceNowSyncOutcome(
            gap_id=gap.id,
            control_id=gap.control_id,
            framework=gap.framework,
            action=ServiceNowSyncAction.ERRORED,
            detail=f"Mapping error: {e}",
        )

    correlation_id = str(fields.get("correlation_id") or "")

    if correlation_id and not force:
        try:
            existing: ServiceNowRecord | None = client.find_existing_by_correlation(correlation_id=correlation_id)
        except ServiceNowApiError as e:
            return ServiceNowSyncOutcome(
                gap_id=gap.id,
                control_id=gap.control_id,
                framework=gap.framework,
                action=ServiceNowSyncAction.ERRORED,
                detail=f"ServiceNow lookup failed: {e}",
            )
        if existing is not None:
            return ServiceNowSyncOutcome(
                gap_id=gap.id,
                control_id=gap.control_id,
                framework=gap.framework,
                action=ServiceNowSyncAction.EXISTING,
                sys_id=existing.sys_id,
                record_number=existing.number,
                record_url=existing.url,
                detail=(f"Existing record {existing.number}; pass force=True to create a new one."),
            )

    try:
        record = client.create_record(fields=fields)
    except ServiceNowApiError as e:
        return ServiceNowSyncOutcome(
            gap_id=gap.id,
            control_id=gap.control_id,
            framework=gap.framework,
            action=ServiceNowSyncAction.ERRORED,
            detail=f"ServiceNow create failed: {e}",
        )

    return ServiceNowSyncOutcome(
        gap_id=gap.id,
        control_id=gap.control_id,
        framework=gap.framework,
        action=ServiceNowSyncAction.CREATED,
        sys_id=record.sys_id,
        record_number=record.number,
        record_url=record.url,
        detail=f"Created {record.number}",
    )


# ── Batch ────────────────────────────────────────────────────────────────


def push_open_gaps(
    report: GapAnalysisReport,
    client: ServiceNowClient,
    *,
    force: bool = False,
) -> ServiceNowSyncResult:
    """Push every OPEN / IN_PROGRESS gap in the report to ServiceNow.

    Skipped:
    - REMEDIATED / ACCEPTED / NOT_APPLICABLE — closed gaps don't
      need a tracking record
    """
    result = ServiceNowSyncResult()
    for gap in report.gaps:
        status_value = gap.status.value if hasattr(gap.status, "value") else str(gap.status)
        if status_value not in {"open", "in_progress"}:
            result.outcomes.append(
                ServiceNowSyncOutcome(
                    gap_id=gap.id,
                    control_id=gap.control_id,
                    framework=gap.framework,
                    action=ServiceNowSyncAction.SKIPPED,
                    detail=f"Gap status is {status_value}; skipping.",
                )
            )
            continue
        result.outcomes.append(push_gap_to_servicenow(gap, client, force=force))
    return result
