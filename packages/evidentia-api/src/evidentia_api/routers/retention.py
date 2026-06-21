"""Retention router — audit chain-of-custody retention metadata over HTTP.

Surfaces the v0.7.11 retention data layer + lifecycle primitives
(:mod:`evidentia_core.retention.metadata` +
:mod:`evidentia_core.retention_metadata_store`) over HTTP under the
``/api/retention`` prefix. Mirrors the v0.9.0 P2 POA&M router shape +
inherits the same error-normalization conventions (400 for runtime
body / domain errors per v0.7.8 F-V08-DAST-3; 404 for shape-violation
+ not-found IDs per v0.7.9 P0.1 H-3 widening).

Endpoints (7 CLI verbs → REST):

  - ``POST   /api/retention`` — set (create) a retention record;
    computes the default retention period + lock_until when omitted
  - ``GET    /api/retention`` — list records with optional
    classification + lifecycle filters
  - ``GET    /api/retention/report`` — Markdown retention-posture
    audit report (declared BEFORE the ``{retention_id}`` param route
    so ``report`` is not captured as an ID)
  - ``GET    /api/retention/{retention_id}`` — fetch a single record
  - ``POST   /api/retention/{retention_id}/extend`` — extend the
    lock_until date (WORM-style: extend-only, never shorten)
  - ``POST   /api/retention/{retention_id}/transition`` — transition
    the lifecycle stage (state-machine enforced)
  - ``DELETE /api/retention/{retention_id}`` — remove the metadata
    record (metadata only; not an evidence purge)

RBAC posture (v0.10.12 threat-model): mutations carry opt-in
``require_role`` gates (write on set / extend / transition; admin on
delete) which are NO-OPs under the default permissive policy
(anonymous passes) — they only bite when an operator wires
``EVIDENTIA_RBAC_POLICY_FILE``. The retention CLI has no RBAC today;
the API surface adds the gates without changing default behavior.
"""

from __future__ import annotations

from datetime import date

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.models.common import enum_value as _enum_value
from evidentia_core.models.common import utc_now
from evidentia_core.retention.metadata import (
    RetentionClassification,
    RetentionLifecycleStage,
    RetentionMetadata,
    RetentionTransitionError,
    default_retention_days,
    generate_retention_report,
    transition_lifecycle,
)
from evidentia_core.retention_metadata_store import (
    InvalidRetentionIdError,
    delete_retention,
    list_retention,
    load_retention_by_id,
    save_retention,
)
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from evidentia_api.rbac_dependency import require_role

router = APIRouter()
_log = get_logger("evidentia.api.retention")


# ── request DTOs ───────────────────────────────────────────────────


class RetentionCreatePayload(BaseModel):
    """Body shape for POST /api/retention (the `retention set` verb)."""

    classification: RetentionClassification = Field(
        description="Regulator-aligned classification (required)."
    )
    retention_period_days: int | None = Field(
        default=None,
        description=(
            "Retention period in calendar days. Defaults to the "
            "regulator-stated minimum for the classification."
        ),
    )
    record_pointer: str | None = Field(
        default=None,
        description="Pointer to the underlying record (file/S3/Azure URL).",
    )
    legal_hold: bool = Field(
        default=False,
        description="Mark this record as under legal hold from the start.",
    )
    policy_name: str | None = Field(
        default=None,
        description="Optional cross-reference to a RetentionPolicy.",
    )
    notes: str | None = Field(
        default=None, description="Free-text operator notes."
    )


class RetentionExtendPayload(BaseModel):
    """Body shape for POST /api/retention/{id}/extend."""

    new_lock_until: date = Field(
        description="ISO-8601 date the new lock-until should be (YYYY-MM-DD)."
    )


class RetentionTransitionPayload(BaseModel):
    """Body shape for POST /api/retention/{id}/transition."""

    new_stage: RetentionLifecycleStage = Field(
        description="Target lifecycle stage: active/preserved/expired/purged."
    )


# ── set / list ─────────────────────────────────────────────────────


@router.post(
    "/retention",
    response_model=RetentionMetadata,
    status_code=201,
    dependencies=[require_role("write")],
)
async def set_retention(payload: RetentionCreatePayload) -> RetentionMetadata:
    """Create a retention metadata record.

    When ``retention_period_days`` is omitted, the per-classification
    regulator default is used. The model's ``_populate_lock_until``
    validator computes ``lock_until`` from
    ``created_at + retention_period_days`` at construction.
    """
    days = (
        payload.retention_period_days
        if payload.retention_period_days is not None
        else default_retention_days(payload.classification)
    )
    metadata = RetentionMetadata(
        classification=payload.classification,
        retention_period_days=days,
        legal_hold=payload.legal_hold,
        record_pointer=payload.record_pointer,
        policy_name=payload.policy_name,
        notes=payload.notes,
    )
    save_retention(metadata)
    _log.info(
        action=EventAction.RETENTION_RECORD_PUT,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Retention record created via API: "
            f"{_enum_value(metadata.classification)}"
        ),
        evidentia={
            "retention_id": metadata.id,
            "classification": _enum_value(metadata.classification),
            "lock_until": (
                metadata.lock_until.isoformat()
                if metadata.lock_until
                else None
            ),
        },
    )
    return metadata


@router.get("/retention")
async def list_retention_records(
    skip: int = Query(0, ge=0, description="Pagination offset."),
    limit: int = Query(
        100,
        ge=1,
        le=1000,
        description="Max records (1-1000).",
    ),
    classification: str | None = Query(
        None,
        description=(
            "Filter by classification: sec-17a-4 / finra-3110 / "
            "irs-tax / sox-404 / hipaa / glba / pci-dss / model-risk "
            "/ gdpr / generic."
        ),
    ),
    lifecycle: str | None = Query(
        None,
        description=(
            "Filter by lifecycle stage: active / preserved / expired "
            "/ purged."
        ),
    ),
) -> dict[str, object]:
    """List retention records in canonical sort order.

    Filtering applies BEFORE pagination so ``total`` reflects the
    filter-matched count.
    """
    if classification and classification not in {
        c.value for c in RetentionClassification
    }:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown classification {classification!r}; valid: "
                f"{sorted(c.value for c in RetentionClassification)}"
            ),
        )
    if lifecycle and lifecycle not in {
        s.value for s in RetentionLifecycleStage
    }:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown lifecycle {lifecycle!r}; valid: "
                f"{sorted(s.value for s in RetentionLifecycleStage)}"
            ),
        )

    items = list_retention()
    if classification:
        items = [m for m in items if m.classification == classification]
    if lifecycle:
        items = [m for m in items if m.lifecycle_stage == lifecycle]
    total = len(items)
    page = items[skip : skip + limit]
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": [m.model_dump(mode="json") for m in page],
    }


# ── report (declared BEFORE the {retention_id} param route) ─────────


@router.get("/retention/report", response_class=PlainTextResponse)
async def retention_report() -> str:
    """Return the retention-posture audit report as Markdown text.

    Response Content-Type is ``text/plain; charset=utf-8`` so the
    Markdown body lands raw in the client. Same content as
    ``evidentia retention report``. Declared before the
    ``/retention/{retention_id}`` route so the static ``report``
    segment is not captured as an ID.
    """
    return generate_retention_report(list_retention())


# ── show / extend / transition / delete ────────────────────────────


@router.get("/retention/{retention_id}", response_model=RetentionMetadata)
async def get_retention(retention_id: str) -> RetentionMetadata:
    """Fetch a single retention record by ID."""
    try:
        metadata = load_retention_by_id(retention_id)
    except InvalidRetentionIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Retention record {retention_id!r} not found.",
        ) from exc
    if metadata is None:
        raise HTTPException(
            status_code=404,
            detail=f"Retention record {retention_id!r} not found.",
        )
    return metadata


@router.post(
    "/retention/{retention_id}/extend",
    response_model=RetentionMetadata,
    dependencies=[require_role("write")],
)
async def extend_retention(
    retention_id: str, payload: RetentionExtendPayload
) -> RetentionMetadata:
    """Extend a record's lock-until date.

    WORM-style retention only allows extending — never shortening.
    Replicates the CLI's inline extend logic (does not route through
    the WORM backend).
    """
    try:
        metadata = load_retention_by_id(retention_id)
    except InvalidRetentionIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Retention record {retention_id!r} not found.",
        ) from exc
    if metadata is None:
        raise HTTPException(
            status_code=404,
            detail=f"Retention record {retention_id!r} not found.",
        )
    if (
        metadata.lock_until is not None
        and payload.new_lock_until < metadata.lock_until
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                f"WORM forbids shortening retention (current "
                f"lock_until={metadata.lock_until}; "
                f"requested={payload.new_lock_until})."
            ),
        )
    updated = metadata.model_copy(
        update={"lock_until": payload.new_lock_until, "updated_at": utc_now()}
    )
    save_retention(updated)
    _log.info(
        action=EventAction.RETENTION_RECORD_EXTENDED,
        outcome=EventOutcome.SUCCESS,
        message=f"Retention record {retention_id[:8]} extended via API",
        evidentia={
            "retention_id": updated.id,
            "prior_lock_until": (
                metadata.lock_until.isoformat()
                if metadata.lock_until
                else None
            ),
            "new_lock_until": payload.new_lock_until.isoformat(),
        },
    )
    return updated


@router.post(
    "/retention/{retention_id}/transition",
    response_model=RetentionMetadata,
    dependencies=[require_role("write")],
)
async def transition_retention(
    retention_id: str, payload: RetentionTransitionPayload
) -> RetentionMetadata:
    """Transition a record's lifecycle stage (state-machine enforced)."""
    try:
        metadata = load_retention_by_id(retention_id)
    except InvalidRetentionIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Retention record {retention_id!r} not found.",
        ) from exc
    if metadata is None:
        raise HTTPException(
            status_code=404,
            detail=f"Retention record {retention_id!r} not found.",
        )
    prior_stage = _enum_value(metadata.lifecycle_stage)
    try:
        updated = transition_lifecycle(metadata, payload.new_stage)
    except RetentionTransitionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    save_retention(updated)
    _log.info(
        action=EventAction.RETENTION_LIFECYCLE_TRANSITIONED,
        outcome=EventOutcome.SUCCESS,
        message=f"Retention record {retention_id[:8]} transitioned via API",
        evidentia={
            "retention_id": updated.id,
            "prior_state": prior_stage,
            "new_state": _enum_value(updated.lifecycle_stage),
        },
    )
    return updated


@router.delete(
    "/retention/{retention_id}",
    status_code=204,
    dependencies=[require_role("admin")],
)
async def delete_retention_record(retention_id: str) -> None:
    """Delete a retention metadata record.

    204 on success, 404 on shape-violation OR unknown. This removes
    only the metadata record, not the underlying evidence.
    """
    try:
        removed = delete_retention(retention_id)
    except InvalidRetentionIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Retention record {retention_id!r} not found.",
        ) from exc
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"Retention record {retention_id!r} not found.",
        )
    # NOTE: this DELETE removes only the retention METADATA record — it
    # is NOT a WORM/secure evidence purge. The audit vocabulary has no
    # metadata-delete EventAction member (the closest is
    # RETENTION_RECORD_PURGED, which connotes a secure purge), and this
    # router may not add one (events.py is out of scope). To avoid
    # misleading an audit reviewer into reading this as a secure purge,
    # the message string says so unambiguously.
    _log.info(
        action=EventAction.RETENTION_RECORD_PURGED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Retention metadata record {retention_id[:8]} deleted via "
            f"API (metadata record deleted, not a WORM/secure purge)"
        ),
        evidentia={"retention_id": retention_id},
    )
