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
  - ``GET    /api/conmon/daemon-status`` — daemon health-check
    snapshot read from a sidecar JSON file (v0.9.4 P2.1)

Auth posture: open (matches v0.9.0 POA&M router; transport auth
applied at the app layer via AuthProviderMiddleware).
"""

from __future__ import annotations

import os
from datetime import date
from pathlib import Path
from typing import Any

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.conmon import (
    CycleAttentionState,
    compute_health,
    derive_status,
    get_cadence,
    list_cadences,
    next_due,
)
from evidentia_core.conmon.daemon import read_daemon_status
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter()
_log = get_logger("evidentia_api.routers.conmon")


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


# ── daemon-status (v0.9.4 P2.1) ───────────────────────────────────


@router.get("/conmon/daemon-status")
async def conmon_daemon_status_endpoint() -> dict[str, Any]:
    """Return the running daemon's last-poll status snapshot.

    Reads a JSON sidecar file the daemon writes after every poll
    cycle. Operator configures both processes to share the path via
    the ``EVIDENTIA_CONMON_DAEMON_STATUS_FILE`` env var (daemon
    writes; this endpoint reads).

    Returns:
        200 with the status payload when the file is present + parseable.
        404 when the env var is unset OR the file doesn't exist
        (daemon not yet started, status-file not configured).
        500 reserved for unexpected I/O errors only — corrupt-file
        reads return 404 + a graceful "no status available" message.

    Audit emit: :attr:`EventAction.CONMON_DAEMON_STATUS_QUERIED`.
    Pairs with the v0.9.3 P1.1 :attr:`EventAction.CONMON_DAEMON_STARTED`
    + :attr:`EventAction.CONMON_DAEMON_POLL_FAILED` events for
    end-to-end auditor visibility into daemon health.
    """
    status_file_env = os.environ.get(
        "EVIDENTIA_CONMON_DAEMON_STATUS_FILE", ""
    ).strip()
    if not status_file_env:
        raise HTTPException(
            status_code=404,
            detail=(
                "No daemon-status file configured. Set "
                "EVIDENTIA_CONMON_DAEMON_STATUS_FILE on the server + "
                "pass --status-file=<same path> to evidentia conmon "
                "watch on the daemon side."
            ),
        )

    status_file = Path(status_file_env)
    payload = read_daemon_status(status_file)
    if payload is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Daemon status not available: {status_file} missing "
                "or unparseable. Daemon may not have started yet, or "
                "the file is mid-write — retry after one poll cycle."
            ),
        )

    _log.info(
        action=EventAction.CONMON_DAEMON_STATUS_QUERIED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Daemon status queried (last_poll_at="
            f"{payload.get('last_poll_at')}, outcome="
            f"{payload.get('last_poll_outcome')})"
        ),
        evidentia={
            "status_file": str(status_file),
            "last_poll_outcome": payload.get("last_poll_outcome"),
        },
    )
    return payload
