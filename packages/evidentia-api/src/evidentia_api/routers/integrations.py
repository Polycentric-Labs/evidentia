"""Integrations router — Jira (v0.5.0).

All endpoints return JSON. Jira credentials come from environment
variables the server process sees; no secrets ever flow through
browser-visible state. ``GET /api/integrations/jira/status`` returns
a "configured/not" boolean + the project + the authenticated user's
display name — never the API token value.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from evidentia_core.gap_store import (
    InvalidReportKeyError,
    load_report_by_key,
)
from evidentia_core.models.gap import GapAnalysisReport
from evidentia_core.security.paths import PathTraversalError
from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)
router = APIRouter()


def _new_request_id() -> str:
    """Generate a short opaque ID to correlate a client error with the
    server-side log entry that contains the full exception detail.

    Returned to the client in error responses; the server-side log
    line uses the same ID so an operator can grep the application log
    for the specifics without exposing exception messages over the
    wire.
    """
    return uuid.uuid4().hex[:12]


def _load_report(key: str) -> GapAnalysisReport:
    try:
        report = load_report_by_key(key)
    except InvalidReportKeyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except PathTraversalError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if report is None:
        raise HTTPException(
            status_code=404, detail=f"Report {key} not found."
        )
    return report


def _save_report(report: GapAnalysisReport) -> None:
    from evidentia_core.gap_store import save_report

    save_report(report)


# ── Jira status ──────────────────────────────────────────────────────────


@router.get("/integrations/jira/status")
async def jira_status() -> dict[str, Any]:
    """Return whether Jira is configured + basic connection info.

    Never includes the API token value. Calls ``JiraClient.test_connection``
    which does two cheap REST probes (``/myself`` + project lookup); if
    either fails, ``configured=False`` + ``error=<short reason>``.
    """
    try:
        from evidentia_integrations.jira import (
            JiraApiError,
            JiraClient,
            JiraConfig,
        )
    except ImportError as e:  # pragma: no cover — integrations package ships with CLI
        rid = _new_request_id()
        logger.warning("jira_status import failure [%s]: %r", rid, e)
        return {
            "configured": False,
            "error": "evidentia-integrations package is not installed.",
            "request_id": rid,
        }

    try:
        cfg = JiraConfig.from_env()
    except ValueError as e:
        rid = _new_request_id()
        logger.warning("jira_status config failure [%s]: %r", rid, e)
        return {
            "configured": False,
            "error": "Jira configuration is incomplete or invalid.",
            "request_id": rid,
        }

    try:
        with JiraClient(cfg) as client:
            info = client.test_connection()
    except JiraApiError as e:
        rid = _new_request_id()
        logger.warning("jira_status api failure [%s]: %r", rid, e)
        return {
            "configured": False,
            "base_url": cfg.base_url,
            "project_key": cfg.project_key,
            "error": "Jira API call failed; check server logs with the request_id.",
            "request_id": rid,
        }

    return {
        "configured": True,
        "base_url": info["base_url"],
        "project_key": info["project_key"],
        "project_name": info["project_name"],
        "user": info["user"],
    }


# ── Push ────────────────────────────────────────────────────────────────


@router.post("/integrations/jira/push/{report_key}")
async def jira_push(
    report_key: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Push open gaps from a saved report as Jira issues.

    Request body is optional; recognized keys:

    - ``severity_filter``: list of severity strings
      (e.g. ``["critical", "high"]``)
    - ``max_issues``: int cap for total creations
    """
    from evidentia_integrations.jira import (
        JiraClient,
        JiraConfig,
        push_open_gaps,
    )

    report = _load_report(report_key)

    try:
        cfg = JiraConfig.from_env()
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e

    body = payload or {}
    severity_filter: set[str] | None = None
    if isinstance(body.get("severity_filter"), list):
        severity_filter = {
            str(s).lower() for s in body["severity_filter"] if isinstance(s, str)
        }
    max_issues = None
    if isinstance(body.get("max_issues"), int):
        max_issues = int(body["max_issues"])

    with JiraClient(cfg) as client:
        result = push_open_gaps(
            report,
            client,
            severity_filter=severity_filter,
            max_issues=max_issues,
        )

    # Persist the updated report — push_open_gaps stamps jira_issue_key
    # onto gaps it created issues for.
    _save_report(report)

    return {
        "created": result.created,
        "updated": result.updated,
        "skipped": result.skipped,
        "errored": result.errored,
        "outcomes": [o.model_dump(mode="json") for o in result.outcomes],
    }


# ── Sync ────────────────────────────────────────────────────────────────


@router.post("/integrations/jira/sync/{report_key}")
async def jira_sync(report_key: str) -> dict[str, Any]:
    """Pull status from Jira for every linked gap in the report.

    Mutates the in-memory report and persists it back to the gap store
    so subsequent reads (Dashboard, Gap Analyze) reflect the new
    statuses.
    """
    from evidentia_integrations.jira import (
        JiraClient,
        JiraConfig,
        sync_report,
    )

    report = _load_report(report_key)

    try:
        cfg = JiraConfig.from_env()
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e

    with JiraClient(cfg) as client:
        result = sync_report(report, client)

    _save_report(report)

    return {
        "updated": result.updated,
        "skipped": result.skipped,
        "errored": result.errored,
        "outcomes": [o.model_dump(mode="json") for o in result.outcomes],
    }


@router.get("/integrations/jira/status-map")
async def jira_status_map() -> dict[str, dict[str, str]]:
    """Return the current GapStatus ↔ Jira-status mapping for UI rendering."""
    from evidentia_integrations.jira import (
        GAP_STATUS_TO_JIRA_STATUS,
        JIRA_STATUS_TO_GAP_STATUS,
    )

    return {
        "gap_status_to_jira": {
            k.value: v for k, v in GAP_STATUS_TO_JIRA_STATUS.items()
        },
        "jira_status_to_gap": {
            k: v.value for k, v in JIRA_STATUS_TO_GAP_STATUS.items()
        },
    }
