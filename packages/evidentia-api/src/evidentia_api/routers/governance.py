"""Governance router — 3LOD + Effective Challenge + KRI/KPI/KGI + workflows (v0.10.12).

Surfaces the ``evidentia governance`` CLI verb tree over HTTP. Mirrors
the poam / model-risk / evidence routers one-for-one: an
``APIRouter()`` with no prefix (the app applies ``/api`` at registration
time), bare-segment paths, ``evidentia_core.audit`` emits, the
``{total, skip, limit, items}`` list envelope, ``Invalid*IdError`` →
404 normalization, and 400 for domain / body-content errors. Markdown
report endpoints return :class:`PlainTextResponse` (matching the
model-risk router's ``/documentation`` + ``/validation-report``).

Endpoints (16 CLI verbs → REST):

  Effective Challenge log (``governance challenge {add,list,show}``)
    - ``POST /governance/challenges``                — create  (write)
    - ``GET  /governance/challenges``                — list+filter (open)
    - ``GET  /governance/challenges/{challenge_id}`` — show    (open)

  KRI/KPI/KGI metrics (``governance metrics {add,observe,list,show,delete,report}``)
    - ``POST   /governance/metrics``                          — create  (write)
    - ``POST   /governance/metrics/{metric_id}/observations`` — observe (write)
    - ``GET    /governance/metrics``                          — list+filter (open)
    - ``GET    /governance/metrics/report``                   — report  (open)
    - ``GET    /governance/metrics/{metric_id}``              — show    (open)
    - ``DELETE /governance/metrics/{metric_id}``              — delete  (admin)

  Process-as-code workflows (``governance workflow {run,advance,status,list,log,delete}``)
    - ``POST   /governance/workflows``                    — run     (write)
    - ``POST   /governance/workflows/{workflow_id}/advance`` — advance (write)
    - ``GET    /governance/workflows/{workflow_id}``      — status  (open)
    - ``GET    /governance/workflows``                    — list    (open)
    - ``GET    /governance/workflows/{workflow_id}/log``  — log     (open)
    - ``DELETE /governance/workflows/{workflow_id}``      — delete  (admin)

  Three Lines of Defense (``governance lines-report``)
    - ``POST /governance/lines-report``  — render from posted owners (open)

Naming guard: this router deliberately mounts metrics under
``/governance/metrics`` — the existing ``routers/metrics.py`` already
serves the Prometheus ``GET /api/metrics`` surface, so the namespace
prefix avoids a collision.

RBAC posture (v0.10.12 threat-model): the governance CLI has no RBAC
today, but the REST mutations gate on ``write`` (create / observe /
run / advance) and ``admin`` (delete) via
:func:`evidentia_api.rbac_dependency.require_role`. Reads + report
renders are open. Under the default permissive policy (no
``EVIDENTIA_RBAC_POLICY_FILE``) every request passes — the gates only
bite when an operator opts into RBAC.

Computed status: metric ``status`` (:func:`evaluate_metric`) and the
workflow ``status`` field (:func:`evaluate_workflow`, persisted on the
model) are derived, not stored on the metric. Metric responses splice
``status`` alongside ``model_dump(mode="json")`` — mirroring how the
CLI surfaces ``evaluate_metric(metric).value``. Workflow ``status`` is
already a model field (the run + advance flows persist the computed
value), so it round-trips natively.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.effective_challenge_store import (
    InvalidChallengeIdError,
    list_challenges,
    load_challenge_by_id,
    save_challenge,
)
from evidentia_core.governance import (
    ChallengeOutcome,
    EffectiveChallenge,
    Metric,
    MetricKind,
    MetricObservation,
    Owner,
    Workflow,
    WorkflowAdvanceError,
    WorkflowStepStatus,
    advance_workflow_step,
    evaluate_metric,
    evaluate_workflow,
    generate_lines_report,
    generate_metrics_report,
    generate_workflow_log,
)
from evidentia_core.metric_store import (
    InvalidMetricIdError,
    delete_metric,
    list_metrics,
    load_metric_by_id,
    save_metric,
)
from evidentia_core.models.common import NonBlankStr
from evidentia_core.models.common import enum_value as _enum_value
from evidentia_core.workflow_store import (
    InvalidWorkflowIdError,
    delete_workflow,
    list_workflows,
    load_workflow_by_id,
    save_workflow,
)
from fastapi import APIRouter, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from evidentia_api.errors import (
    RBAC_DENIED_403,
    api_error,
    error_responses,
)
from evidentia_api.rbac_dependency import require_role

router = APIRouter()
_log = get_logger("evidentia.api.governance")


def _metric_with_status(metric: Metric) -> dict[str, Any]:
    """Serialize a metric with its computed (non-stored) status spliced in.

    Mirrors how the CLI surfaces ``evaluate_metric(metric).value`` —
    ``status`` is derived from the latest observation against the
    thresholds, never persisted, so we recompute on every read/write.
    """
    return {
        **metric.model_dump(mode="json"),
        "status": evaluate_metric(metric).value,
    }


# ════════════════════════════════════════════════════════════════════
# Effective Challenge log
# ════════════════════════════════════════════════════════════════════


@router.post(
    "/governance/challenges",
    response_model=EffectiveChallenge,
    status_code=201,
    dependencies=[require_role("write")],
    responses=error_responses(
        {
            403: RBAC_DENIED_403,
            422: (
                "Client-supplied empty/malformed ``id`` "
                "(``error: invalid_body``)."
            ),
        }
    ),
)
async def create_challenge(payload: EffectiveChallenge) -> EffectiveChallenge:
    """Log a new effective-challenge record.

    Body shape is the full :class:`EffectiveChallenge` model. Server
    fills ``id`` / ``created_at`` / ``updated_at`` / ``evidentia_version``
    via Pydantic ``default_factory`` when the client omits them.
    """
    challenge = payload.model_copy()
    try:
        save_challenge(challenge)
    except (InvalidChallengeIdError, ValueError) as exc:
        # A client-supplied empty/malformed ``id`` (Pydantic accepts ``""`` as a
        # valid str, so the UUID default_factory only fires on an OMITTED id)
        # reaches the store's id-shape validation. Return 422 rather than letting
        # it propagate as an unhandled 500 — a response-contract fix mirroring
        # the GET/PUT paths in this router (F-V1012-S4-1).
        raise api_error(422, "invalid_body", str(exc)) from exc
    _log.info(
        action=EventAction.GOVERNANCE_CHALLENGE_CREATED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Effective challenge logged via API: "
            f"{challenge.challenge_topic}"
        ),
        evidentia={
            "challenge_id": challenge.id,
            "subject_model_id": challenge.subject_model_id,
            "outcome": _enum_value(challenge.outcome),
        },
    )
    return challenge


@router.get(
    "/governance/challenges",
    responses=error_responses(
        {
            400: (
                "Unknown ``outcome`` filter value (``error: "
                "unknown_outcome``); ``detail`` carries ``outcome`` "
                "+ ``valid``."
            ),
        }
    ),
)
async def list_challenge_records(
    skip: int = Query(0, ge=0, description="Pagination offset."),
    limit: int = Query(
        100, ge=1, le=1000, description="Max records (1-1000)."
    ),
    subject_model_id: str | None = Query(
        None,
        description="Filter by subject ModelInventory.id (exact-equality).",
    ),
    outcome: str | None = Query(
        None,
        description="Filter by outcome: accepted / rejected / modify / pending.",
    ),
) -> dict[str, object]:
    """List effective-challenge records (newest-first by challenge_date).

    Filter + paginate semantics match the poam router (pagination
    applies AFTER filtering so ``total`` reflects the filter-matched
    count).
    """
    if outcome and outcome not in {o.value for o in ChallengeOutcome}:
        raise api_error(
            400,
            "unknown_outcome",
            (
                f"Unknown outcome {outcome!r}; valid: "
                f"{sorted(o.value for o in ChallengeOutcome)}"
            ),
            outcome=outcome,
            valid=sorted(o.value for o in ChallengeOutcome),
        )
    challenges = list_challenges()
    if subject_model_id:
        challenges = [
            c for c in challenges if c.subject_model_id == subject_model_id
        ]
    if outcome:
        challenges = [
            c for c in challenges if _enum_value(c.outcome) == outcome
        ]
    total = len(challenges)
    page = challenges[skip : skip + limit]
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": [c.model_dump(mode="json") for c in page],
    }


@router.get(
    "/governance/challenges/{challenge_id}",
    response_model=EffectiveChallenge,
    responses=error_responses(
        {
            404: (
                "Unknown or malformed ``challenge_id`` "
                "(``error: not_found``)."
            ),
        }
    ),
)
async def get_challenge(challenge_id: str) -> EffectiveChallenge:
    """Fetch a single challenge by ID. 404 on unknown OR malformed ID."""
    try:
        challenge = load_challenge_by_id(challenge_id)
    except InvalidChallengeIdError as exc:
        raise api_error(
            404,
            "not_found",
            f"Challenge {challenge_id!r} not found.",
            resource="challenge",
            resource_id=challenge_id,
        ) from exc
    if challenge is None:
        raise api_error(
            404,
            "not_found",
            f"Challenge {challenge_id!r} not found.",
            resource="challenge",
            resource_id=challenge_id,
        )
    return challenge


# ════════════════════════════════════════════════════════════════════
# KRI / KPI / KGI metrics
# ════════════════════════════════════════════════════════════════════


class MetricObservationPayload(BaseModel):
    """Body shape for POST /governance/metrics/{id}/observations."""

    value: float = Field(description="Observation value.")
    observed_at: date = Field(
        description="ISO-8601 date (YYYY-MM-DD) the observation was recorded."
    )
    note: str | None = Field(
        default=None, description="Optional contextual note."
    )


@router.post(
    "/governance/metrics",
    status_code=201,
    dependencies=[require_role("write")],
    responses=error_responses(
        {
            403: RBAC_DENIED_403,
            422: (
                "Client-supplied empty/malformed ``id`` "
                "(``error: invalid_body``)."
            ),
        }
    ),
)
async def create_metric(payload: Metric) -> dict[str, Any]:
    """Define a new KRI / KPI / KGI metric.

    Body shape is the full :class:`Metric` model. Server fills
    ``id`` / timestamps / ``evidentia_version`` via Pydantic
    ``default_factory`` when omitted.

    Returns the created metric with its computed ``status`` spliced in
    (via :func:`_metric_with_status`) — consistent with the list / show
    / observe endpoints. A freshly-created metric has no observations,
    so ``status`` is ``"no_data"``. ``response_model=Metric`` is
    deliberately omitted: it would strip the non-model ``status`` key
    and re-impose the bare-model shape this fix removes.
    """
    metric = payload.model_copy()
    try:
        save_metric(metric)
    except (InvalidMetricIdError, ValueError) as exc:
        # See create_challenge — a client-supplied empty/malformed id must be a
        # 422, not an unhandled 500 (F-V1012-S4-1).
        raise api_error(422, "invalid_body", str(exc)) from exc
    _log.info(
        action=EventAction.GOVERNANCE_METRIC_CREATED,
        outcome=EventOutcome.SUCCESS,
        message=f"Metric defined via API: {metric.name}",
        evidentia={
            "metric_id": metric.id,
            "kind": _enum_value(metric.kind),
        },
    )
    return _metric_with_status(metric)


@router.post(
    "/governance/metrics/{metric_id}/observations",
    dependencies=[require_role("write")],
    responses=error_responses(
        {
            403: RBAC_DENIED_403,
            404: (
                "Unknown or malformed ``metric_id`` "
                "(``error: not_found``)."
            ),
        }
    ),
)
async def observe_metric(
    metric_id: str, payload: MetricObservationPayload
) -> dict[str, Any]:
    """Append an observation + return the updated metric with computed status.

    Loads the metric (404 on unknown / malformed ID), appends a new
    :class:`MetricObservation`, persists, then returns the full metric
    with the recomputed ``status`` field spliced in (mirroring the
    CLI's ``current status: <evaluate_metric>`` surface).
    """
    try:
        metric = load_metric_by_id(metric_id)
    except InvalidMetricIdError as exc:
        raise api_error(
            404,
            "not_found",
            f"Metric {metric_id!r} not found.",
            resource="metric",
            resource_id=metric_id,
        ) from exc
    if metric is None:
        raise api_error(
            404,
            "not_found",
            f"Metric {metric_id!r} not found.",
            resource="metric",
            resource_id=metric_id,
        )
    new_obs = MetricObservation(
        observed_at=payload.observed_at,
        value=payload.value,
        note=payload.note,
    )
    metric = metric.model_copy(
        update={"observations": [*metric.observations, new_obs]}
    )
    save_metric(metric)
    _log.info(
        action=EventAction.GOVERNANCE_METRIC_OBSERVED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Observation {payload.value} recorded via API for "
            f"{metric.name}; status={evaluate_metric(metric).value}"
        ),
        evidentia={
            "metric_id": metric.id,
            "value": payload.value,
            "status": evaluate_metric(metric).value,
        },
    )
    return _metric_with_status(metric)


@router.get(
    "/governance/metrics",
    responses=error_responses(
        {
            400: (
                "Unknown ``kind`` filter value (``error: "
                "unknown_kind``); ``detail`` carries ``kind`` + "
                "``valid``."
            ),
        }
    ),
)
async def list_metric_records(
    skip: int = Query(0, ge=0, description="Pagination offset."),
    limit: int = Query(
        100, ge=1, le=1000, description="Max records (1-1000)."
    ),
    kind: str | None = Query(
        None, description="Filter by kind: kri / kpi / kgi."
    ),
) -> dict[str, object]:
    """List metrics, each with its computed status.

    Filter + paginate semantics match the poam router. Each item
    carries a computed ``status`` (:func:`evaluate_metric`) spliced
    alongside the persisted fields.
    """
    if kind and kind not in {k.value for k in MetricKind}:
        raise api_error(
            400,
            "unknown_kind",
            (
                f"Unknown kind {kind!r}; valid: "
                f"{sorted(k.value for k in MetricKind)}"
            ),
            kind=kind,
            valid=sorted(k.value for k in MetricKind),
        )
    metrics = list_metrics()
    if kind:
        metrics = [m for m in metrics if _enum_value(m.kind) == kind]
    total = len(metrics)
    page = metrics[skip : skip + limit]
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": [_metric_with_status(m) for m in page],
    }


@router.get("/governance/metrics/report", response_class=PlainTextResponse)
async def metrics_report() -> str:
    """Return the Markdown KRI/KPI/KGI dashboard report as plain text.

    Declared BEFORE ``/governance/metrics/{metric_id}`` so the static
    ``report`` segment is not captured by the path-parameter route (a
    test asserts the ordering — ``report`` must not be parsed as an ID).
    Same content as ``evidentia governance metrics report``.
    """
    return generate_metrics_report(list_metrics())


@router.get(
    "/governance/metrics/{metric_id}",
    responses=error_responses(
        {
            404: (
                "Unknown or malformed ``metric_id`` "
                "(``error: not_found``)."
            ),
        }
    ),
)
async def get_metric(metric_id: str) -> dict[str, Any]:
    """Fetch a single metric with computed status. 404 on unknown/malformed."""
    try:
        metric = load_metric_by_id(metric_id)
    except InvalidMetricIdError as exc:
        raise api_error(
            404,
            "not_found",
            f"Metric {metric_id!r} not found.",
            resource="metric",
            resource_id=metric_id,
        ) from exc
    if metric is None:
        raise api_error(
            404,
            "not_found",
            f"Metric {metric_id!r} not found.",
            resource="metric",
            resource_id=metric_id,
        )
    return _metric_with_status(metric)


@router.delete(
    "/governance/metrics/{metric_id}",
    status_code=204,
    dependencies=[require_role("admin")],
    responses=error_responses(
        {
            403: RBAC_DENIED_403,
            404: (
                "Unknown or malformed ``metric_id`` "
                "(``error: not_found``)."
            ),
        }
    ),
)
async def delete_metric_record(metric_id: str) -> None:
    """Delete a metric by ID. 204 on success, 404 on unknown/malformed."""
    try:
        removed = delete_metric(metric_id)
    except InvalidMetricIdError as exc:
        raise api_error(
            404,
            "not_found",
            f"Metric {metric_id!r} not found.",
            resource="metric",
            resource_id=metric_id,
        ) from exc
    if not removed:
        raise api_error(
            404,
            "not_found",
            f"Metric {metric_id!r} not found.",
            resource="metric",
            resource_id=metric_id,
        )
    _log.info(
        action=EventAction.GOVERNANCE_METRIC_DELETED,
        outcome=EventOutcome.SUCCESS,
        message=f"Metric {metric_id[:8]} deleted via API",
        evidentia={"metric_id": metric_id},
    )


# ════════════════════════════════════════════════════════════════════
# Process-as-code workflows
# ════════════════════════════════════════════════════════════════════


class WorkflowAdvancePayload(BaseModel):
    """Body shape for POST /governance/workflows/{id}/advance."""

    step_index: int = Field(
        ge=0, description="Step index (0-based) to transition."
    )
    new_status: WorkflowStepStatus = Field(
        description="approved / rejected / skipped / in_progress."
    )
    actor: NonBlankStr = Field(
        description="Actor identity (typically email)."
    )
    note: str | None = Field(
        default=None, description="Optional rationale / approval note."
    )


@router.post(
    "/governance/workflows",
    response_model=Workflow,
    status_code=201,
    dependencies=[require_role("write")],
    responses=error_responses(
        {
            403: RBAC_DENIED_403,
            422: (
                "Client-supplied empty/malformed ``id`` "
                "(``error: invalid_body``)."
            ),
        }
    ),
)
async def run_workflow(payload: Workflow) -> Workflow:
    """Instantiate + persist a workflow run.

    Unlike the CLI (which takes a YAML *file path*), this endpoint takes
    the already-parsed :class:`Workflow` model as the JSON body. The
    post-parse lifecycle steps replicate the CLI's
    ``_load_workflow_template`` (cli/governance.py): auto-promote step 0
    from PENDING → IN_PROGRESS, then set ``status =
    evaluate_workflow(wf)``.

    NOTE: this auto-promote + evaluate block is duplicated inline from
    the CLI. Lifting it into a shared core helper
    (e.g. ``evidentia_core.governance.workflows.instantiate_workflow``)
    is a future CLI/API-parity refactor.
    """
    wf = payload.model_copy()
    # Auto-promote the first step from PENDING → IN_PROGRESS so the
    # workflow is "active" immediately after run.
    if wf.steps and wf.steps[0].status == WorkflowStepStatus.PENDING.value:
        first = wf.steps[0].model_copy(
            update={"status": WorkflowStepStatus.IN_PROGRESS.value}
        )
        new_steps = [first, *wf.steps[1:]]
        wf = wf.model_copy(update={"steps": new_steps})
    # Re-evaluate workflow status from the (now in-progress) step list.
    wf = wf.model_copy(update={"status": evaluate_workflow(wf)})
    try:
        save_workflow(wf)
    except (InvalidWorkflowIdError, ValueError) as exc:
        # See create_challenge — a client-supplied empty/malformed id must be a
        # 422, not an unhandled 500 (F-V1012-S4-1).
        raise api_error(422, "invalid_body", str(exc)) from exc
    _log.info(
        action=EventAction.GOVERNANCE_WORKFLOW_RUN,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Workflow started via API: {wf.name}; "
            f"status={_enum_value(wf.status)}"
        ),
        evidentia={
            "workflow_id": wf.id,
            "status": _enum_value(wf.status),
            "step_count": len(wf.steps),
        },
    )
    return wf


@router.post(
    "/governance/workflows/{workflow_id}/advance",
    response_model=Workflow,
    dependencies=[require_role("write")],
    responses=error_responses(
        {
            400: (
                "Workflow-rule violation on the step transition "
                "(``error: invalid_body``)."
            ),
            403: RBAC_DENIED_403,
            404: (
                "Unknown or malformed ``workflow_id`` "
                "(``error: not_found``)."
            ),
        }
    ),
)
async def advance_workflow(
    workflow_id: str, payload: WorkflowAdvancePayload
) -> Workflow:
    """Transition a workflow step to a new status.

    Loads (404 on unknown / malformed ID), calls
    :func:`advance_workflow_step`, normalizes
    :class:`WorkflowAdvanceError` → 400 (rule violation), persists the
    new workflow, and returns it with the re-evaluated ``status``.
    """
    try:
        wf = load_workflow_by_id(workflow_id)
    except InvalidWorkflowIdError as exc:
        raise api_error(
            404,
            "not_found",
            f"Workflow {workflow_id!r} not found.",
            resource="workflow",
            resource_id=workflow_id,
        ) from exc
    if wf is None:
        raise api_error(
            404,
            "not_found",
            f"Workflow {workflow_id!r} not found.",
            resource="workflow",
            resource_id=workflow_id,
        )
    try:
        new_wf = advance_workflow_step(
            wf,
            step_index=payload.step_index,
            new_status=payload.new_status,
            actor=payload.actor,
            note=payload.note,
        )
    except WorkflowAdvanceError as exc:
        raise api_error(400, "invalid_body", str(exc)) from exc
    save_workflow(new_wf)
    _log.info(
        action=EventAction.GOVERNANCE_WORKFLOW_ADVANCED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Workflow {workflow_id[:8]} step {payload.step_index} "
            f"→ {_enum_value(payload.new_status)} via API; "
            f"status={_enum_value(new_wf.status)}"
        ),
        evidentia={
            "workflow_id": new_wf.id,
            "step_index": payload.step_index,
            "new_status": _enum_value(payload.new_status),
            "workflow_status": _enum_value(new_wf.status),
        },
    )
    return new_wf


@router.get("/governance/workflows")
async def list_workflow_records(
    skip: int = Query(0, ge=0, description="Pagination offset."),
    limit: int = Query(
        100, ge=1, le=1000, description="Max records (1-1000)."
    ),
) -> dict[str, object]:
    """List workflows (newest-first). Standard envelope + pagination."""
    workflows = list_workflows()
    total = len(workflows)
    page = workflows[skip : skip + limit]
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": [w.model_dump(mode="json") for w in page],
    }


@router.get(
    "/governance/workflows/{workflow_id}",
    response_model=Workflow,
    responses=error_responses(
        {
            404: (
                "Unknown or malformed ``workflow_id`` "
                "(``error: not_found``)."
            ),
        }
    ),
)
async def get_workflow(workflow_id: str) -> Workflow:
    """Fetch a single workflow by ID. 404 on unknown OR malformed ID."""
    try:
        wf = load_workflow_by_id(workflow_id)
    except InvalidWorkflowIdError as exc:
        raise api_error(
            404,
            "not_found",
            f"Workflow {workflow_id!r} not found.",
            resource="workflow",
            resource_id=workflow_id,
        ) from exc
    if wf is None:
        raise api_error(
            404,
            "not_found",
            f"Workflow {workflow_id!r} not found.",
            resource="workflow",
            resource_id=workflow_id,
        )
    return wf


@router.get(
    "/governance/workflows/{workflow_id}/log",
    response_class=PlainTextResponse,
    responses=error_responses(
        {
            404: (
                "Unknown or malformed ``workflow_id`` "
                "(``error: not_found``)."
            ),
        }
    ),
)
async def workflow_log(workflow_id: str) -> str:
    """Return the Markdown workflow audit-log as plain text.

    404 on unknown / malformed ID. Same content as
    ``evidentia governance workflow log``.
    """
    try:
        wf = load_workflow_by_id(workflow_id)
    except InvalidWorkflowIdError as exc:
        raise api_error(
            404,
            "not_found",
            f"Workflow {workflow_id!r} not found.",
            resource="workflow",
            resource_id=workflow_id,
        ) from exc
    if wf is None:
        raise api_error(
            404,
            "not_found",
            f"Workflow {workflow_id!r} not found.",
            resource="workflow",
            resource_id=workflow_id,
        )
    return generate_workflow_log(wf)


@router.delete(
    "/governance/workflows/{workflow_id}",
    status_code=204,
    dependencies=[require_role("admin")],
    responses=error_responses(
        {
            403: RBAC_DENIED_403,
            404: (
                "Unknown or malformed ``workflow_id`` "
                "(``error: not_found``)."
            ),
        }
    ),
)
async def delete_workflow_record(workflow_id: str) -> None:
    """Delete a workflow by ID. 204 on success, 404 on unknown/malformed."""
    try:
        removed = delete_workflow(workflow_id)
    except InvalidWorkflowIdError as exc:
        raise api_error(
            404,
            "not_found",
            f"Workflow {workflow_id!r} not found.",
            resource="workflow",
            resource_id=workflow_id,
        ) from exc
    if not removed:
        raise api_error(
            404,
            "not_found",
            f"Workflow {workflow_id!r} not found.",
            resource="workflow",
            resource_id=workflow_id,
        )
    _log.info(
        action=EventAction.GOVERNANCE_WORKFLOW_DELETED,
        outcome=EventOutcome.SUCCESS,
        message=f"Workflow {workflow_id[:8]} deleted via API",
        evidentia={"workflow_id": workflow_id},
    )


# ════════════════════════════════════════════════════════════════════
# Three Lines of Defense report
# ════════════════════════════════════════════════════════════════════


@router.post("/governance/lines-report", response_class=PlainTextResponse)
async def lines_report(owners: list[Owner]) -> str:
    """Render a 3LOD distribution report from a posted owner list.

    Stateless: the CLI reads owners from a YAML overlay file, but the
    API takes the parsed ``list[Owner]`` directly as the JSON body.
    Returns the deterministic Markdown report as plain text. Same
    content as ``evidentia governance lines-report``.
    """
    return generate_lines_report(owners)
