"""POA&M router — Plan-of-Action-and-Milestones CRUD endpoints (v0.9.0 P2).

Surfaces the v0.9.0 P1 POA&M data layer over HTTP under the
``/api/poam`` prefix. Mirrors the v0.7.9 P0.1.4 TPRM router shape +
inherits the same error-normalization conventions (400 for runtime
body-content errors per v0.7.8 F-V08-DAST-3; 404 for shape-violation
+ not-found IDs per v0.7.9 P0.1 H-3 widening).

Endpoints:

  - ``GET    /api/poam/items`` — list POA&M items with optional
    skip/limit pagination + severity/status filters
  - ``POST   /api/poam/items`` — create (or replace) a POA&M item;
    body shape is the full ControlGap model
  - ``GET    /api/poam/items/{poam_id}`` — fetch single POA&M
  - ``PUT    /api/poam/items/{poam_id}`` — full-replace (preserves
    id + created_at; refreshes updated milestone timestamps)
  - ``DELETE /api/poam/items/{poam_id}`` — remove from store
  - ``POST   /api/poam/items/{poam_id}/milestones`` — append a new
    milestone (returns the updated POA&M)
  - ``PATCH  /api/poam/items/{poam_id}/milestones/{milestone_id}`` —
    update an existing milestone (state-machine enforced)
  - ``GET    /api/poam/calendar`` — read-only attention-state surface
    (overdue + due-soon milestones across all POA&Ms)

Auth posture: open like existing endpoints (matches v0.7.9 P0.1.4
B1 + v0.8.0 P0.5 FastAPI AuthProvider middleware applies the
optional token-file auth at the app layer, not per-router).
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.models.common import enum_value as _enum_value
from evidentia_core.models.gap import (
    ControlGap,
    GapSeverity,
    GapStatus,
    Milestone,
    POAMState,
)
from evidentia_core.poam.milestone import derive_attention_state
from evidentia_core.poam.state import is_valid_transition
from evidentia_core.poam_store import (
    InvalidPoamIdError,
    delete_poam,
    list_poams,
    load_poam_by_id,
    save_poam,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter()
_log = get_logger("evidentia.api.poam")


# ── helpers ────────────────────────────────────────────────────────


def _filter_poams(
    poams: list[ControlGap],
    severity: str | None,
    status: str | None,
    owner: str | None = None,
    reviewer: str | None = None,
) -> list[ControlGap]:
    if severity:
        poams = [p for p in poams if p.gap_severity == severity]
    if status:
        poams = [p for p in poams if p.status == status]
    # v0.9.5 P3.1: owner / reviewer filtering — match against any
    # milestone on the POA&M item. The "any-match" semantics mirror
    # the CLI poam list --owner X behavior.
    if owner is not None:
        poams = [
            p for p in poams
            if any(m.owner == owner for m in p.poam_milestones)
        ]
    if reviewer is not None:
        poams = [
            p for p in poams
            if any(m.reviewer == reviewer for m in p.poam_milestones)
        ]
    return poams


# ── POA&M item CRUD ────────────────────────────────────────────────


@router.get("/poam/items")
async def list_poam_items(
    skip: int = Query(0, ge=0, description="Pagination offset."),
    limit: int = Query(
        100,
        ge=1,
        le=1000,
        description="Max records (1-1000).",
    ),
    severity: str | None = Query(
        None,
        description=(
            "Filter by gap severity: critical / high / medium / low / "
            "informational."
        ),
    ),
    status: str | None = Query(
        None,
        description=(
            "Filter by gap status: open / in_progress / remediated / "
            "accepted / not_applicable."
        ),
    ),
    owner: str | None = Query(
        None,
        description=(
            "v0.9.5 P3.1: filter to POA&M items with at least one "
            "milestone where owner == this value (exact-equality)."
        ),
    ),
    reviewer: str | None = Query(
        None,
        description=(
            "v0.9.5 P3.1: filter to POA&M items with at least one "
            "milestone where reviewer == this value (exact-equality)."
        ),
    ),
) -> dict[str, object]:
    """List POA&M items in canonical sort order.

    Filter + paginate semantics match the TPRM router (pagination
    applies AFTER filtering so ``total`` reflects filter-matched
    count).
    """
    if severity and severity not in {e.value for e in GapSeverity}:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown severity {severity!r}; valid: "
                f"{sorted(e.value for e in GapSeverity)}"
            ),
        )
    if status and status not in {e.value for e in GapStatus}:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown status {status!r}; valid: "
                f"{sorted(e.value for e in GapStatus)}"
            ),
        )

    all_poams = list_poams()
    filtered = _filter_poams(
        all_poams, severity, status, owner=owner, reviewer=reviewer
    )
    total = len(filtered)
    page = filtered[skip : skip + limit]
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": [p.model_dump(mode="json") for p in page],
    }


@router.post("/poam/items", response_model=ControlGap, status_code=201)
async def create_poam_item(payload: ControlGap) -> ControlGap:
    """Create a POA&M item.

    Body shape is the full ControlGap model. Server fills id /
    created_at / evidentia_version via Pydantic default_factory
    when the client omits them. Idempotent: re-POSTing a body with
    the same id overwrites (use PUT for explicit replace semantics).
    """
    poam = payload.model_copy()
    save_poam(poam)
    _log.info(
        action=EventAction.POAM_CREATED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"POA&M item created via API: {poam.framework}:"
            f"{poam.control_id}"
        ),
        evidentia={
            "poam_id": poam.id,
            "control_id": f"{poam.framework}:{poam.control_id}",
        },
    )
    return poam


@router.get("/poam/items/{poam_id}", response_model=ControlGap)
async def get_poam_item(poam_id: str) -> ControlGap:
    """Fetch a single POA&M by ID."""
    try:
        poam = load_poam_by_id(poam_id)
    except InvalidPoamIdError as exc:
        # Match the TPRM widening pattern: shape violation
        # normalizes to 404 from the client's perspective.
        raise HTTPException(
            status_code=404,
            detail=f"POA&M {poam_id!r} not found.",
        ) from exc
    if poam is None:
        raise HTTPException(
            status_code=404,
            detail=f"POA&M {poam_id!r} not found.",
        )
    return poam


@router.put("/poam/items/{poam_id}", response_model=ControlGap)
async def replace_poam_item(poam_id: str, payload: ControlGap) -> ControlGap:
    """Full-replace a POA&M item.

    Preserves the original ``id`` + ``created_at`` even if the
    client supplies different values (path param is authoritative
    for identity; created_at is immutable once the record exists).
    Milestone timestamps refresh via poam_store.save_poam's
    state-change-detection path.
    """
    try:
        existing = load_poam_by_id(poam_id)
    except InvalidPoamIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"POA&M {poam_id!r} not found.",
        ) from exc
    if existing is None:
        raise HTTPException(
            status_code=404,
            detail=f"POA&M {poam_id!r} not found.",
        )
    prior_status = existing.status
    poam = payload.model_copy(
        update={"id": existing.id, "created_at": existing.created_at}
    )
    save_poam(poam)
    _log.info(
        action=EventAction.POAM_UPDATED,
        outcome=EventOutcome.SUCCESS,
        message=f"POA&M {poam_id[:8]} replaced via API",
        evidentia={
            "poam_id": poam.id,
            "control_id": f"{poam.framework}:{poam.control_id}",
            "prior_state": _enum_value(prior_status),
            "new_state": _enum_value(poam.status),
        },
    )
    if (
        _enum_value(prior_status) != GapStatus.REMEDIATED.value
        and _enum_value(poam.status) == GapStatus.REMEDIATED.value
    ):
        _log.info(
            action=EventAction.POAM_CLOSED,
            outcome=EventOutcome.SUCCESS,
            message=(
                f"POA&M {poam_id[:8]} closed via API (status=remediated)"
            ),
            evidentia={
                "poam_id": poam.id,
                "control_id": f"{poam.framework}:{poam.control_id}",
                "prior_state": _enum_value(prior_status),
                "new_state": GapStatus.REMEDIATED.value,
            },
        )
    return poam


@router.delete("/poam/items/{poam_id}", status_code=204)
async def delete_poam_item(poam_id: str) -> None:
    """Delete a POA&M item. 204 on success, 404 on shape-violation OR unknown."""
    try:
        removed = delete_poam(poam_id)
    except InvalidPoamIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"POA&M {poam_id!r} not found.",
        ) from exc
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"POA&M {poam_id!r} not found.",
        )


# ── milestone management ───────────────────────────────────────────


class MilestoneCreatePayload(BaseModel):
    """Body shape for POST /api/poam/items/{id}/milestones."""

    target_date: date = Field(description="ISO-8601 target completion date.")
    description: str = Field(
        min_length=1,
        max_length=2048,
        description="Milestone description.",
    )
    status: POAMState = Field(
        default=POAMState.PLANNED,
        description="Initial state.",
    )
    evidence_ref: str | None = Field(
        default=None,
        max_length=512,
        description="Optional evidence reference.",
    )


class MilestoneUpdatePayload(BaseModel):
    """Body shape for PATCH /api/poam/items/{id}/milestones/{ms_id}."""

    target_date: date | None = None
    description: str | None = Field(default=None, max_length=2048)
    status: POAMState | None = None
    evidence_ref: str | None = Field(default=None, max_length=512)


@router.post(
    "/poam/items/{poam_id}/milestones",
    response_model=ControlGap,
)
async def add_milestone(
    poam_id: str,
    payload: MilestoneCreatePayload,
) -> ControlGap:
    """Append a new milestone to an existing POA&M."""
    try:
        poam = load_poam_by_id(poam_id)
    except InvalidPoamIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"POA&M {poam_id!r} not found.",
        ) from exc
    if poam is None:
        raise HTTPException(
            status_code=404,
            detail=f"POA&M {poam_id!r} not found.",
        )
    ms = Milestone(
        target_date=payload.target_date,
        description=payload.description,
        status=payload.status,
        evidence_ref=payload.evidence_ref,
    )
    poam.poam_milestones.append(ms)
    save_poam(poam)
    _log.info(
        action=EventAction.POAM_UPDATED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Milestone {ms.id[:8]} added to POA&M {poam_id[:8]} "
            f"via API"
        ),
        evidentia={
            "poam_id": poam.id,
            "control_id": f"{poam.framework}:{poam.control_id}",
            "milestone_id": ms.id,
            "new_state": _enum_value(ms.status),
        },
    )
    return poam


@router.patch(
    "/poam/items/{poam_id}/milestones/{milestone_id}",
    response_model=ControlGap,
)
async def update_milestone(
    poam_id: str,
    milestone_id: str,
    payload: MilestoneUpdatePayload,
) -> ControlGap:
    """Update an existing milestone. Backward state transitions blocked."""
    try:
        poam = load_poam_by_id(poam_id)
    except InvalidPoamIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"POA&M {poam_id!r} not found.",
        ) from exc
    if poam is None:
        raise HTTPException(
            status_code=404,
            detail=f"POA&M {poam_id!r} not found.",
        )
    target_ms: Milestone | None = next(
        (m for m in poam.poam_milestones if m.id == milestone_id),
        None,
    )
    if target_ms is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Milestone {milestone_id!r} not found on POA&M "
                f"{poam_id!r}."
            ),
        )
    prior_state = POAMState(target_ms.status)

    if payload.status is not None and payload.status != prior_state:
        if not is_valid_transition(prior_state, payload.status):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Invalid state transition "
                    f"{prior_state.value} → {payload.status.value}; "
                    f"backward transitions blocked. File a new "
                    f"milestone with a fresh target_date to re-open work."
                ),
            )
        target_ms.status = payload.status

    if payload.target_date is not None:
        target_ms.target_date = payload.target_date
    if payload.description is not None:
        target_ms.description = payload.description
    if payload.evidence_ref is not None:
        # Explicit empty string treated as "clear"; None passed in the
        # body means "no change" by the Pydantic-optional convention.
        target_ms.evidence_ref = payload.evidence_ref or None

    save_poam(poam)

    new_state = POAMState(target_ms.status)
    if (
        payload.status is not None
        and new_state == POAMState.COMPLETED
        and prior_state != POAMState.COMPLETED
    ):
        _log.info(
            action=EventAction.POAM_MILESTONE_REACHED,
            outcome=EventOutcome.SUCCESS,
            message=(
                f"Milestone {milestone_id[:8]} on POA&M "
                f"{poam_id[:8]} completed via API"
            ),
            evidentia={
                "poam_id": poam.id,
                "control_id": f"{poam.framework}:{poam.control_id}",
                "milestone_id": target_ms.id,
                "prior_state": prior_state.value,
                "new_state": new_state.value,
            },
        )
    elif (
        payload.status is not None
        and new_state == POAMState.VERIFIED
    ):
        _log.info(
            action=EventAction.POAM_VERIFIED,
            outcome=EventOutcome.SUCCESS,
            message=(
                f"Milestone {milestone_id[:8]} on POA&M "
                f"{poam_id[:8]} verified via API"
            ),
            evidentia={
                "poam_id": poam.id,
                "control_id": f"{poam.framework}:{poam.control_id}",
                "milestone_id": target_ms.id,
                "prior_state": prior_state.value,
                "new_state": new_state.value,
            },
        )
    elif (
        payload.status is not None
        and new_state == POAMState.OVERDUE
    ):
        _log.info(
            action=EventAction.POAM_OVERDUE,
            outcome=EventOutcome.SUCCESS,
            message=(
                f"Milestone {milestone_id[:8]} on POA&M "
                f"{poam_id[:8]} marked overdue via API"
            ),
            evidentia={
                "poam_id": poam.id,
                "control_id": f"{poam.framework}:{poam.control_id}",
                "milestone_id": target_ms.id,
                "prior_state": prior_state.value,
                "new_state": new_state.value,
            },
        )
    else:
        _log.info(
            action=EventAction.POAM_UPDATED,
            outcome=EventOutcome.SUCCESS,
            message=(
                f"Milestone {milestone_id[:8]} on POA&M "
                f"{poam_id[:8]} edited via API"
            ),
            evidentia={
                "poam_id": poam.id,
                "control_id": f"{poam.framework}:{poam.control_id}",
                "milestone_id": target_ms.id,
            },
        )

    return poam


# ── calendar (read-only attention surface) ─────────────────────────


@router.get("/poam/calendar")
async def get_calendar(
    today_override: str | None = Query(
        None,
        alias="today",
        description=(
            "Override 'today' for deterministic snapshots "
            "(YYYY-MM-DD). Omit for the server's current date."
        ),
    ),
) -> dict[str, Any]:
    """Read-only attention surface: overdue + due-soon milestones."""
    if today_override:
        try:
            today_val = date.fromisoformat(today_override)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"--today must be ISO-8601 YYYY-MM-DD; got "
                    f"{today_override!r}: {exc}"
                ),
            ) from exc
    else:
        today_val = datetime.now(tz=UTC).date()

    all_milestones: list[tuple[ControlGap, Milestone]] = []
    for poam in list_poams():
        for ms in poam.poam_milestones:
            all_milestones.append((poam, ms))
    buckets = derive_attention_state(
        [ms for _, ms in all_milestones], today=today_val
    )
    poam_by_milestone_id = {
        ms.id: poam for poam, ms in all_milestones
    }

    return {
        "today": today_val.isoformat(),
        "overdue": [
            {
                "milestone_id": ms.id,
                "poam_id": poam_by_milestone_id[ms.id].id,
                "control_id": (
                    f"{poam_by_milestone_id[ms.id].framework}:"
                    f"{poam_by_milestone_id[ms.id].control_id}"
                ),
                "target_date": ms.target_date.isoformat(),
                "status": ms.status,
                "description": ms.description,
            }
            for ms in buckets["overdue"]
        ],
        "due_soon": [
            {
                "milestone_id": ms.id,
                "poam_id": poam_by_milestone_id[ms.id].id,
                "control_id": (
                    f"{poam_by_milestone_id[ms.id].framework}:"
                    f"{poam_by_milestone_id[ms.id].control_id}"
                ),
                "target_date": ms.target_date.isoformat(),
                "status": ms.status,
                "description": ms.description,
            }
            for ms in buckets["due_soon"]
        ],
    }
