"""CONMON router — Continuous Monitoring cycle-calendar endpoints (v0.9.1 P1).

REST parity with the ``evidentia conmon`` CLI (v0.9.0 P3).
Surfaces the :mod:`evidentia_core.conmon` read-only library over
HTTP under the ``/api/conmon`` prefix. Mirrors the v0.9.0
POA&M router shape + inherits the same error-normalization
conventions.

Endpoints:

  - ``GET    /api/conmon/cadences`` — list cadences with optional
    ``?framework=`` filter
  - ``GET    /api/conmon/cadences/{slug}`` — get single cadence
  - ``POST   /api/conmon/next`` — compute next-due date from
    slug + last_completed payload
  - ``POST   /api/conmon/check`` — batch attention-state check;
    returns overdue + due-soon arrays
  - ``POST   /api/conmon/health`` — aggregate framework health
    scoring from a slug→last-completed payload (v0.9.3 P1.3)

Auth posture: open (matches v0.9.0 POA&M router; transport auth
applied at the app layer via AuthProviderMiddleware).
"""

from __future__ import annotations

from datetime import date
from typing import Any

from evidentia_core.conmon import (
    CycleAttentionState,
    compute_health,
    derive_status,
    get_cadence,
    list_cadences,
    next_due,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter()


# ── request / response models ─────────────────────────────────────


class NextDueRequest(BaseModel):
    slug: str = Field(
        min_length=1,
        description="Cadence slug (e.g., 'nist-800-53-rev5-ca7').",
    )
    last_completed: date = Field(
        description="ISO-8601 date of the last completed cycle.",
    )


class NextDueResponse(BaseModel):
    slug: str
    framework: str
    activity: str
    frequency: str
    last_completed: date
    next_due: date


class CheckEntry(BaseModel):
    slug: str
    last_completed: date


class CheckRequest(BaseModel):
    entries: list[CheckEntry] = Field(
        min_length=1,
        max_length=100,
        description="Cadence slug → last-completed-date pairs to check.",
    )
    today: date | None = Field(
        default=None,
        description=(
            "Override 'today' for deterministic snapshots. "
            "Omit for real-time checks."
        ),
    )
    window_days: int = Field(
        default=14,
        ge=0,
        description="Due-soon window in days (default: 14).",
    )


class CheckCycleRow(BaseModel):
    slug: str
    framework: str
    activity: str
    frequency: str
    last_completed: date
    next_due: date
    days_until_due: int
    state: str


class CheckResponse(BaseModel):
    today: date
    window_days: int
    overdue: list[CheckCycleRow]
    due_soon: list[CheckCycleRow]
    current: list[CheckCycleRow]
    unknown_slugs: list[str]


# ── cadence listing ───────────────────────────────────────────────


@router.get("/conmon/cadences")
async def list_conmon_cadences(
    framework: str | None = Query(
        default=None,
        description="Filter to a specific framework identifier.",
    ),
) -> list[dict[str, str | None]]:
    """List bundled + registered CONMON cadences."""
    cadences = list_cadences(framework=framework)
    return [
        {
            "slug": c.slug,
            "framework": c.framework,
            "activity": c.activity,
            "frequency": str(c.frequency),
            "description": c.description,
            "citation": c.citation,
        }
        for c in cadences
    ]


@router.get("/conmon/cadences/{slug}")
async def get_conmon_cadence(slug: str) -> dict[str, str | None]:
    """Get a single cadence by slug."""
    cadence = get_cadence(slug)
    if cadence is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown cadence slug: {slug!r}",
        )
    return {
        "slug": cadence.slug,
        "framework": cadence.framework,
        "activity": cadence.activity,
        "frequency": str(cadence.frequency),
        "description": cadence.description,
        "citation": cadence.citation,
    }


# ── next-due computation ──────────────────────────────────────────


@router.post("/conmon/next")
async def compute_next_due(body: NextDueRequest) -> NextDueResponse:
    """Compute the next-due date for a registered cadence."""
    cadence = get_cadence(body.slug)
    if cadence is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown cadence slug: {body.slug!r}",
        )
    due = next_due(body.slug, body.last_completed)
    return NextDueResponse(
        slug=cadence.slug,
        framework=cadence.framework,
        activity=cadence.activity,
        frequency=str(cadence.frequency),
        last_completed=body.last_completed,
        next_due=due,
    )


# ── batch check ───────────────────────────────────────────────────


@router.post("/conmon/check")
async def check_conmon_cycles(body: CheckRequest) -> CheckResponse:
    """Batch attention-state check across multiple cadences.

    Returns cycles bucketed into overdue / due_soon / current.
    Unknown slugs are collected separately (not errored).
    """
    today = body.today if body.today is not None else date.today()

    overdue: list[CheckCycleRow] = []
    due_soon: list[CheckCycleRow] = []
    current: list[CheckCycleRow] = []
    unknown_slugs: list[str] = []

    for entry in body.entries:
        cadence = get_cadence(entry.slug)
        if cadence is None:
            unknown_slugs.append(entry.slug)
            continue
        due = next_due(entry.slug, entry.last_completed)
        state = derive_status(due, today, window_days=body.window_days)
        days_until_due = (due - today).days
        row = CheckCycleRow(
            slug=entry.slug,
            framework=cadence.framework,
            activity=cadence.activity,
            frequency=str(cadence.frequency),
            last_completed=entry.last_completed,
            next_due=due,
            days_until_due=days_until_due,
            state=state.value,
        )
        if state == CycleAttentionState.OVERDUE:
            overdue.append(row)
        elif state == CycleAttentionState.DUE_SOON:
            due_soon.append(row)
        else:
            current.append(row)

    return CheckResponse(
        today=today,
        window_days=body.window_days,
        overdue=overdue,
        due_soon=due_soon,
        current=current,
        unknown_slugs=unknown_slugs,
    )


# ── health (v0.9.3 P1.3) ──────────────────────────────────────────


class HealthRequest(BaseModel):
    state: dict[str, date] = Field(
        max_length=10000,
        description=(
            "Slug→last-completed-date mapping. Capped at 10,000 "
            "entries per request."
        ),
    )
    today: date | None = Field(
        default=None,
        description=(
            "Override 'today' for deterministic snapshots. Omit "
            "for real-time reports."
        ),
    )
    window_days: int = Field(
        default=14,
        ge=0,
        description="Due-soon window in days (default 14).",
    )
    framework: str | None = Field(
        default=None,
        description=(
            "Optional framework identifier to restrict the report."
        ),
    )


@router.post("/conmon/health")
async def conmon_health_endpoint(body: HealthRequest) -> dict[str, Any]:
    """Aggregate CONMON framework health from a state payload.

    Mirrors the v0.9.3 P1.3 ``evidentia conmon health`` CLI output
    shape via :meth:`HealthReport.to_dict`.
    """
    today = body.today if body.today is not None else date.today()
    report = compute_health(
        state=body.state,
        today=today,
        window_days=body.window_days,
        framework_filter=body.framework,
    )
    return report.to_dict()
