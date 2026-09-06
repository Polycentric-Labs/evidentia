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
  - ``GET    /api/conmon/daemon-history`` — last N status
    snapshots from a rolling JSONL history file. Lets operators
    detect flapping daemons that the point-in-time status
    sidecar can't reveal (v0.9.5 P2.3)
  - ``POST   /api/conmon/mark-completed`` — record a cycle
    completion into the server's YAML state file (mutating;
    require_role("write")). Mirrors the ``evidentia conmon
    mark-completed`` CLI verb. The state-file path is resolved
    server-side from the ``EVIDENTIA_CONMON_STATE_FILE`` env var
    (clients never pass a filesystem path). (v0.10.12)
  - ``GET    /api/conmon/dedup-list`` — list the daemon's
    alert-dedup entries (open read). Mirrors the ``evidentia
    conmon dedup-list`` CLI verb. The dedup-file path is resolved
    server-side from the ``EVIDENTIA_CONMON_ALERT_DEDUP_FILE``
    env var. (v0.10.12)

Auth posture: open for reads (matches v0.9.0 POA&M router;
transport auth applied at the app layer via
AuthProviderMiddleware). The v0.10.12 mark-completed write is
gated on ``require_role("write")``; the long-running ``conmon
watch`` daemon stays CLI-only (the API exposes read-only
daemon-status / daemon-history instead).
"""

from __future__ import annotations

import os
from datetime import UTC, date, datetime, time
from pathlib import Path
from typing import Any

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.conmon import (
    DEFAULT_SUPPRESSION_HOURS,
    AlertDeduper,
    CadenceSeries,
    CycleAttentionState,
    assert_series,
    compute_health,
    default_window,
    derive_status,
    get_cadence,
    list_cadences,
    mark_completed,
    next_due,
)
from evidentia_core.conmon.daemon import (
    read_daemon_history,
    read_daemon_status,
)
from evidentia_core.conmon.series import CADENCE_SLUG_METADATA_KEY
from evidentia_core.evidence_store import get_evidence_store_dir, iter_artifacts
from evidentia_core.models.common import NonBlankStr
from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from evidentia_api.errors import (
    RBAC_DENIED_403,
    api_error,
    error_responses,
)
from evidentia_api.rbac_dependency import require_role

router = APIRouter()
_log = get_logger("evidentia_api.routers.conmon")


# ── request / response models ─────────────────────────────────────


class NextDueRequest(BaseModel):
    slug: NonBlankStr = Field(
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
        description=("Override 'today' for deterministic snapshots. Omit for real-time checks."),
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


@router.get(
    "/conmon/cadences/{slug}",
    responses=error_responses({404: "Unknown cadence ``slug`` (``error: not_found``)."}),
)
async def get_conmon_cadence(slug: str) -> dict[str, str | None]:
    """Get a single cadence by slug."""
    cadence = get_cadence(slug)
    if cadence is None:
        raise api_error(
            404,
            "not_found",
            f"Unknown cadence slug: {slug!r}",
            resource="cadence",
            resource_id=slug,
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


@router.post(
    "/conmon/next",
    responses=error_responses({404: "Unknown cadence ``slug`` (``error: not_found``)."}),
)
async def compute_next_due(body: NextDueRequest) -> NextDueResponse:
    """Compute the next-due date for a registered cadence."""
    cadence = get_cadence(body.slug)
    if cadence is None:
        raise api_error(
            404,
            "not_found",
            f"Unknown cadence slug: {body.slug!r}",
            resource="cadence",
            resource_id=body.slug,
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


# ── series (v0.13, V13-01: cadence evidence series) ──────────────


class SeriesRequest(BaseModel):
    slug: NonBlankStr = Field(
        max_length=128,
        description="Cadence slug (e.g., 'pci-dss-11-6-1-weekly').",
    )
    since: date | None = Field(
        default=None,
        description=(
            "Window start. When both 'since' and 'until' are omitted, "
            "the window is the last 'lookback_days' days ending today. "
            "When only one of the two is given, the other is filled "
            "from that same default window (not derived from the given "
            "bound)."
        ),
    )
    until: date | None = Field(
        default=None,
        description="Window end. See 'since' for the fill rule.",
    )
    lookback_days: int = Field(
        default=365,
        ge=1,
        le=3660,
        description=("Look-back window in days, used to fill any bound 'since' / 'until' don't supply. Default 365."),
    )
    tolerance_days: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Grace period (days) added to the cadence's interval before "
            "a spacing counts as a gap. Omit for the cadence-appropriate "
            "default."
        ),
    )


class SeriesResponse(BaseModel):
    series: CadenceSeries
    description: str


@router.post(
    "/conmon/series",
    responses=error_responses(
        {
            400: "`until` precedes `since` (``error: invalid_window``).",
            404: "Unknown cadence ``slug`` (``error: not_found``).",
        }
    ),
)
async def assert_conmon_series(body: SeriesRequest) -> SeriesResponse:
    """Assert the cadence evidence series for a slug over a window.

    Reads the server's own configured evidence store
    (:func:`evidentia_core.evidence_store.get_evidence_store_dir`,
    honoring ``EVIDENTIA_EVIDENCE_STORE_DIR``; the request never carries
    a filesystem path, for the same reason no other router here accepts
    a client-supplied path) for artifacts whose ``metadata.cadence_slug``
    matches ``slug`` inside the resolved window, then asserts the dated
    series (:func:`evidentia_core.conmon.series.assert_series`). A
    gap-free series is evidence of cadence and nothing more.
    """
    cadence = get_cadence(body.slug)
    if cadence is None:
        raise api_error(
            404,
            "not_found",
            f"Unknown cadence slug: {body.slug!r}",
            resource="cadence",
            resource_id=body.slug,
        )

    default_start, default_end = default_window(lookback_days=body.lookback_days)
    start_date = body.since if body.since is not None else default_start.date()
    end_date = body.until if body.until is not None else default_end.date()
    if end_date < start_date:
        raise api_error(
            400,
            "invalid_window",
            f"until ({end_date.isoformat()}) is before since ({start_date.isoformat()}).",
            since=start_date.isoformat(),
            until=end_date.isoformat(),
        )
    window_start = datetime.combine(start_date, time.min, tzinfo=UTC)
    window_end = datetime.combine(end_date, time.max, tzinfo=UTC)

    store = get_evidence_store_dir()
    artifacts = iter_artifacts(
        store,
        since=window_start,
        until=window_end,
        metadata={CADENCE_SLUG_METADATA_KEY: body.slug},
    )
    series = assert_series(
        body.slug,
        artifacts,
        window_start=window_start,
        window_end=window_end,
        tolerance_days=body.tolerance_days,
    )
    return SeriesResponse(series=series, description=series.describe())


# ── health (v0.9.3 P1.3) ──────────────────────────────────────────


class HealthRequest(BaseModel):
    state: dict[str, date] = Field(
        max_length=10000,
        description=("Slug→last-completed-date mapping. Capped at 10,000 entries per request."),
    )
    today: date | None = Field(
        default=None,
        description=("Override 'today' for deterministic snapshots. Omit for real-time reports."),
    )
    window_days: int = Field(
        default=14,
        ge=0,
        description="Due-soon window in days (default 14).",
    )
    framework: str | None = Field(
        default=None,
        description=("Optional framework identifier to restrict the report."),
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


@router.get(
    "/conmon/daemon-status",
    responses=error_responses(
        {
            404: ("Status file not configured, missing, or unparseable (``error: not_found``)."),
        }
    ),
)
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
    status_file_env = os.environ.get("EVIDENTIA_CONMON_DAEMON_STATUS_FILE", "").strip()
    if not status_file_env:
        raise api_error(
            404,
            "not_found",
            (
                "No daemon-status file configured. Set "
                "EVIDENTIA_CONMON_DAEMON_STATUS_FILE on the server + "
                "pass --status-file=<same path> to evidentia conmon "
                "watch on the daemon side."
            ),
            resource="daemon_state",
        )

    status_file = Path(status_file_env)
    payload = read_daemon_status(status_file)
    if payload is None:
        raise api_error(
            404,
            "not_found",
            (
                f"Daemon status not available: {status_file} missing "
                "or unparseable. Daemon may not have started yet, or "
                "the file is mid-write — retry after one poll cycle."
            ),
            resource="daemon_state",
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


# ── daemon-history (v0.9.5 P2.3) ──────────────────────────────────


@router.get(
    "/conmon/daemon-history",
    responses=error_responses(
        {
            404: ("History file not configured or missing (``error: not_found``)."),
        }
    ),
)
async def conmon_daemon_history_endpoint(
    limit: int = Query(
        default=50,
        ge=1,
        le=1000,
        description=(
            "Maximum number of recent snapshots to return. Default "
            "50 covers ~2 days at the 1-hour default poll interval. "
            "Capped at 1000."
        ),
    ),
) -> dict[str, Any]:
    """Return recent daemon-status snapshots from the rolling history.

    Returns up to ``limit`` most recent entries from the JSONL
    history file the daemon appends to after each poll. Lets
    operators detect flapping daemons that the point-in-time
    status sidecar can't reveal (rapid success → failure → success
    oscillation).

    Reads ``EVIDENTIA_CONMON_DAEMON_HISTORY_FILE`` env var for the
    file path. Pair with ``--history-file`` on the daemon side so
    both processes share the path.

    Returns:
        200 with ``{"snapshots": [...]}`` (chronological, oldest
        first within the limited window) when the history file
        exists. Empty list if the file exists but no poll cycles
        have completed yet.

        404 when the env var is unset OR the file doesn't exist
        (daemon not yet started, history-file not configured).

    Audit emit: :attr:`EventAction.CONMON_DAEMON_STATUS_QUERIED`
    with ``query_type=history`` to differentiate from point-in-
    time snapshot queries.
    """
    history_file_env = os.environ.get("EVIDENTIA_CONMON_DAEMON_HISTORY_FILE", "").strip()
    if not history_file_env:
        raise api_error(
            404,
            "not_found",
            (
                "No daemon-history file configured. Set "
                "EVIDENTIA_CONMON_DAEMON_HISTORY_FILE on the server + "
                "pass --history-file=<same path> to evidentia conmon "
                "watch on the daemon side."
            ),
            resource="daemon_history",
        )

    history_file = Path(history_file_env)
    if not history_file.is_file():
        raise api_error(
            404,
            "not_found",
            (
                f"Daemon history not available: {history_file} "
                "missing. Daemon may not have completed its first "
                "poll cycle yet."
            ),
            resource="daemon_history",
        )

    snapshots = read_daemon_history(history_file, limit=limit)

    _log.info(
        action=EventAction.CONMON_DAEMON_STATUS_QUERIED,
        outcome=EventOutcome.SUCCESS,
        message=(f"Daemon history queried (returned={len(snapshots)} snapshots, limit={limit})"),
        evidentia={
            "history_file": str(history_file),
            "query_type": "history",
            "returned_count": len(snapshots),
            "limit": limit,
        },
    )
    return {
        "snapshots": snapshots,
        "count": len(snapshots),
        "limit": limit,
    }


# ── mark-completed (v0.10.12) ─────────────────────────────────────


class MarkCompletedRequest(BaseModel):
    slug: NonBlankStr = Field(
        description="Cadence slug (e.g., 'nist-800-53-rev5-ca7').",
    )
    when: date = Field(
        description="ISO-8601 date of cycle completion (YYYY-MM-DD).",
    )


class MarkCompletedResponse(BaseModel):
    slug: str
    framework: str
    activity: str
    previous_last_completed: date | None
    new_last_completed: date


@router.post(
    "/conmon/mark-completed",
    dependencies=[require_role("write")],
    responses=error_responses(
        {
            400: (
                "State file not configured (``error: "
                "feature_unavailable``) or unknown cadence ``slug`` "
                "(``error: invalid_field``)."
            ),
            403: RBAC_DENIED_403,
        }
    ),
)
async def mark_conmon_completed(
    body: MarkCompletedRequest,
) -> MarkCompletedResponse:
    """Record a CONMON cycle completion in the server's state file.

    REST parity with the ``evidentia conmon mark-completed`` CLI
    verb. The verb mutates a YAML ``{slug: last_completed}`` state
    file; over HTTP the server resolves that path from the
    ``EVIDENTIA_CONMON_STATE_FILE`` env var so clients never pass an
    arbitrary filesystem path (the CLI's deprecated
    ``--last-completed-file`` alias is intentionally NOT surfaced —
    only the canonical state-file concept is exposed).

    Persistence + audit: delegates to
    :func:`evidentia_core.conmon.mark_completed`, which atomically
    writes the state file and emits
    :attr:`EventAction.CONMON_CYCLE_MARKED_COMPLETED` with the
    previous + new ``last_completed`` values — the auditor's primary
    evidence that the cycle was performed, not merely scheduled.

    Returns:
        200 with the previous (``None`` on first mark) + new
        completion dates.
        400 when ``EVIDENTIA_CONMON_STATE_FILE`` is unset (the server
        operator has not configured a state file) OR the slug is not a
        registered cadence.
        422 (FastAPI body validation) on a missing/malformed ``when``.

    RBAC: ``require_role("write")`` — denies under a deny-by-default
    policy; inert under the permissive DEFAULT_POLICY.
    """
    state_file_env = os.environ.get("EVIDENTIA_CONMON_STATE_FILE", "").strip()
    if not state_file_env:
        raise api_error(
            400,
            "feature_unavailable",
            (
                "No CONMON state file configured. Set "
                "EVIDENTIA_CONMON_STATE_FILE on the server to the YAML "
                "state-file path the daemon polls."
            ),
            env_var="EVIDENTIA_CONMON_STATE_FILE",
        )

    state_file = Path(state_file_env)
    try:
        previous = mark_completed(state_file, body.slug, body.when)
    except ValueError as exc:
        # Unknown cadence slug — mirrors the CLI's exit-1 user error.
        raise api_error(400, "invalid_field", str(exc), field="slug") from exc

    cadence = get_cadence(body.slug)
    assert cadence is not None  # validated by mark_completed

    return MarkCompletedResponse(
        slug=cadence.slug,
        framework=cadence.framework,
        activity=cadence.activity,
        previous_last_completed=previous,
        new_last_completed=body.when,
    )


# ── dedup-list (v0.10.12) ─────────────────────────────────────────


@router.get(
    "/conmon/dedup-list",
    responses=error_responses(
        {
            400: ("Alert-dedup file not configured (``error: feature_unavailable``)."),
        }
    ),
)
async def list_conmon_dedup(
    slug: str | None = Query(
        default=None,
        description="Optional cadence-slug filter (exact match).",
    ),
    suppression_hours: float = Query(
        default=DEFAULT_SUPPRESSION_HOURS,
        ge=0.0,
        description=(
            "Suppression window used for the "
            "'suppression_remaining_minutes' column. Should match the "
            "daemon's --alert-suppression-hours."
        ),
    ),
) -> dict[str, Any]:
    """List the daemon's alert-dedup entries (read-only).

    REST parity with the ``evidentia conmon dedup-list`` CLI verb.
    Reads the alert-dedup JSON state file the ``conmon watch`` daemon
    writes; the server resolves its path from the
    ``EVIDENTIA_CONMON_ALERT_DEDUP_FILE`` env var. A missing file
    yields an empty result (CLI parity — the verb tolerates a
    not-yet-created file).

    Returns:
        200 with ``{"entries": [...], "count": N}``. Each entry is
        ``{cadence_slug, state, last_dispatched_at,
        suppression_remaining_minutes}``, newest-dispatched first.
        400 when ``EVIDENTIA_CONMON_ALERT_DEDUP_FILE`` is unset.

    Auth posture: open (read). No RBAC gate.
    """
    from datetime import UTC, datetime, timedelta

    dedup_file_env = os.environ.get("EVIDENTIA_CONMON_ALERT_DEDUP_FILE", "").strip()
    if not dedup_file_env:
        raise api_error(
            400,
            "feature_unavailable",
            (
                "No alert-dedup file configured. Set "
                "EVIDENTIA_CONMON_ALERT_DEDUP_FILE on the server to the "
                "JSON dedup-state path the daemon writes (pair with "
                "--alert-dedup-file on the daemon side)."
            ),
            env_var="EVIDENTIA_CONMON_ALERT_DEDUP_FILE",
        )

    deduper = AlertDeduper.from_hours(Path(dedup_file_env), suppression_hours)
    raw_entries = deduper.list_entries(slug_filter=slug)
    now = datetime.now(tz=UTC)
    window = timedelta(hours=suppression_hours)

    entries: list[dict[str, Any]] = []
    for entry_slug, state_name, ts in raw_entries:
        remaining_seconds = max(0.0, (ts + window - now).total_seconds())
        entries.append(
            {
                "cadence_slug": entry_slug,
                "state": state_name,
                "last_dispatched_at": ts.isoformat(),
                "suppression_remaining_minutes": round(remaining_seconds / 60.0, 1),
            }
        )

    return {"entries": entries, "count": len(entries)}
