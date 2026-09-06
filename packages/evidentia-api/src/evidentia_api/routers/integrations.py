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
from urllib.parse import urlparse

from evidentia_core import network_guard
from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.gap_store import (
    InvalidReportKeyError,
    load_report_by_key,
)
from evidentia_core.models.gap import GapAnalysisReport
from evidentia_core.network_guard import OfflineViolationError, SSRFBlockedError
from evidentia_core.security.paths import PathTraversalError
from fastapi import APIRouter
from pydantic import ValidationError

from evidentia_api.errors import api_error, error_responses

logger = logging.getLogger(__name__)
router = APIRouter()

# Structured audit logger for credentialed external writes.
_audit = get_logger("evidentia.api.integrations")


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
    except (InvalidReportKeyError, PathTraversalError) as exc:
        # Both errors reflect client-supplied bad keys; normalize to
        # 400 (the F-V08-DAST-3 status normalization is unchanged)
        # with the structured detail object from
        # :mod:`evidentia_api.errors`.
        raise api_error(400, "invalid_id", str(exc), resource="gap_report") from exc
    if report is None:
        raise api_error(
            404,
            "not_found",
            f"Report {key} not found.",
            resource="gap_report",
            resource_id=key,
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


@router.post(
    "/integrations/jira/push/{report_key}",
    responses=error_responses(
        {
            400: "Malformed ``report_key`` (``error: invalid_id``).",
            404: "No such stored report (``error: not_found``).",
            503: ("Jira env configuration incomplete (``error: credentials_missing``)."),
        }
    ),
)
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
        raise api_error(503, "credentials_missing", str(e)) from e

    body = payload or {}
    severity_filter: set[str] | None = None
    if isinstance(body.get("severity_filter"), list):
        severity_filter = {str(s).lower() for s in body["severity_filter"] if isinstance(s, str)}
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


@router.post(
    "/integrations/jira/sync/{report_key}",
    responses=error_responses(
        {
            400: "Malformed ``report_key`` (``error: invalid_id``).",
            404: "No such stored report (``error: not_found``).",
            503: ("Jira env configuration incomplete (``error: credentials_missing``)."),
        }
    ),
)
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
        raise api_error(503, "credentials_missing", str(e)) from e

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
        "gap_status_to_jira": {k.value: v for k, v in GAP_STATUS_TO_JIRA_STATUS.items()},
        "jira_status_to_gap": {k: v.value for k, v in JIRA_STATUS_TO_GAP_STATUS.items()},
    }


# ── Tableau publish (v0.7.8 P1.1) ─────────────────────────────────


@router.post(
    "/integrations/tableau/publish/{report_key}",
    responses=error_responses(
        {
            400: (
                "Malformed ``report_key`` (``error: invalid_id``); "
                "missing ``server_url`` (``error: missing_field``); "
                "SSRF/offline-refused ``server_url`` or bad ``risks`` "
                "(``error: invalid_field``); invalid Tableau "
                "configuration (``error: invalid_body``)."
            ),
            404: "No such stored report (``error: not_found``).",
            500: ("Unexpected publish failure (``error: internal_error``); ``detail`` carries ``request_id``."),
            503: (
                "Tableau integration not installed "
                "(``error: feature_unavailable``) or upstream "
                "Tableau API failure (``error: upstream_error``)."
            ),
        }
    ),
)
async def tableau_publish(
    report_key: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Publish a stored gap report to Tableau as data sources.

    Path:
      - ``report_key``: the gap-store key for a previously saved
        :class:`GapAnalysisReport`.

    Required body:
      - ``server_url``: Tableau Server / Cloud base URL.

    Optional body:
      - ``site_id``: Tableau site slug (default empty for default
        site).
      - ``project_name``: project on the site to publish into
        (default ``"default"``).
      - ``pat_name_env`` / ``pat_secret_env``: env-var names for
        the PAT (defaults ``TABLEAU_PAT_NAME`` /
        ``TABLEAU_PAT_SECRET``).
      - ``risks``: optional list of pre-computed RiskStatement
        dicts to publish alongside the gaps.
      - ``overwrite``: bool (default true) — overwrite existing
        datasets vs. fail on conflict.

    Per ``~/.claude/CLAUDE.md`` secret-handling protocol, the PAT
    name + secret values NEVER flow through the request body —
    only the env-var names do.
    """
    request_id = _new_request_id()
    try:
        from evidentia_integrations.tableau import (
            TableauApiError,
            TableauConfig,
            publish_report,
        )
    except ImportError as e:
        raise api_error(
            503,
            "feature_unavailable",
            ("Tableau integration not installed. Run `pip install 'evidentia-integrations[tableau]'`."),
        ) from e

    server_url = str(payload.get("server_url") or "").strip()
    if not server_url:
        raise api_error(
            400,
            "missing_field",
            "Request body must include 'server_url'.",
            field="server_url",
        )

    # SSRF + offline guard on the body-controlled Tableau host. Tableau is
    # the one integration whose outbound host comes from the request body
    # (Jira / ServiceNow base URLs are env-sourced; Power BI is the fixed
    # api.powerbi.com), so without this a caller — any anonymous caller on
    # an unsecured deployment, or an authenticated low-privilege user —
    # could point server_url at a private / loopback / cloud-metadata
    # (169.254.169.254) address and exfiltrate the Tableau PAT. Same
    # chokepoint every collector uses; block_private_ips defaults True (an
    # explicit `false` opts out for a trusted internal Tableau Server).
    block_private = payload.get("block_private_ips", True) is not False
    try:
        network_guard.check_url(
            server_url,
            subsystem="tableau",
            remediation=("Publish to a reachable public Tableau Server / Cloud URL, or disable offline mode."),
        )
        validated_ips = network_guard.enforce_public_host(server_url, subsystem="tableau", block_private=block_private)
    except (SSRFBlockedError, OfflineViolationError) as exc:
        raise api_error(400, "invalid_field", str(exc), field="server_url") from exc

    # Validate body shape (risks list) BEFORE report lookup so 400
    # is returned for malformed bodies instead of 404 for missing
    # reports.
    risks_input = payload.get("risks")
    risks: Any | None = None
    if risks_input is not None:
        from evidentia_core.models.risk import RiskStatement

        if not isinstance(risks_input, list):
            raise api_error(
                400,
                "invalid_field",
                "'risks' must be a JSON array.",
                field="risks",
            )
        try:
            risks = [RiskStatement.model_validate(item) for item in risks_input]
        except Exception as exc:
            raise api_error(
                400,
                "invalid_field",
                f"Invalid risk payload: {exc}",
                field="risks",
            ) from exc

    try:
        cfg = TableauConfig(
            server_url=server_url,
            site_id=str(payload.get("site_id") or ""),
            project_name=str(payload.get("project_name") or "default"),
            pat_name_env=str(payload.get("pat_name_env") or "TABLEAU_PAT_NAME"),
            pat_secret_env=str(payload.get("pat_secret_env") or "TABLEAU_PAT_SECRET"),
        )
    except ValidationError as exc:
        # e.g. the server_url https-scheme field_validator rejects a
        # non-TLS URL — refuse rather than send a PAT over plaintext.
        # Validated BEFORE the report lookup so a bad URL returns 400, not
        # a 404 for a missing report.
        raise api_error(
            400,
            "invalid_body",
            f"Invalid Tableau configuration: {exc}",
        ) from exc

    report = _load_report(report_key)

    overwrite = bool(payload.get("overwrite", True))

    host = urlparse(server_url).hostname or ""
    try:
        # Pin the validated public IPs through the Tableau SDK's own
        # re-resolution (anti-DNS-rebind), mirroring the collectors. The
        # pin is a no-op when block_private_ips=false (validated_ips empty).
        if validated_ips:
            with network_guard.pin_resolved_host(host, validated_ips):
                result = publish_report(
                    config=cfg,
                    report=report,
                    risks=risks,
                    overwrite=overwrite,
                )
        else:
            result = publish_report(
                config=cfg,
                report=report,
                risks=risks,
                overwrite=overwrite,
            )
    except TableauApiError as exc:
        logger.exception("Tableau publish failed (request_id=%s)", request_id)
        raise api_error(503, "upstream_error", str(exc)) from exc
    except Exception as exc:
        logger.exception(
            "Tableau publish unexpected error (request_id=%s)",
            request_id,
        )
        raise api_error(
            500,
            "internal_error",
            f"Tableau publish failed; request_id={request_id}",
            request_id=request_id,
        ) from exc

    return result.model_dump()


# ── Power BI publish (v0.7.8 P1.2) ────────────────────────────────


@router.post(
    "/integrations/powerbi/publish/{report_key}",
    responses=error_responses(
        {
            400: (
                "Malformed ``report_key`` (``error: invalid_id``); "
                "missing ``workspace_id`` / ``tenant_id`` / "
                "``client_id`` (``error: missing_field``); bad "
                "``risks`` (``error: invalid_field``)."
            ),
            404: "No such stored report (``error: not_found``).",
            500: ("Unexpected publish failure (``error: internal_error``); ``detail`` carries ``request_id``."),
            503: (
                "Power BI integration not installed "
                "(``error: feature_unavailable``) or upstream "
                "Power BI API failure (``error: upstream_error``)."
            ),
        }
    ),
)
async def powerbi_publish(
    report_key: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Push a stored gap report to Power BI as Push Datasets.

    Path:
      - ``report_key``: the gap-store key for a previously saved
        :class:`GapAnalysisReport`.

    Required body:
      - ``workspace_id``: Power BI workspace ID (UUID).
      - ``tenant_id``: Azure AD tenant ID (UUID).
      - ``client_id``: Azure AD service-principal application ID.

    Optional body:
      - ``client_secret_env``: env-var name for the client secret
        (default ``POWERBI_CLIENT_SECRET``).
      - ``risks``: optional list of pre-computed RiskStatement
        dicts.
      - ``clear_before_push``: bool (default true) — full-refresh
        semantics; clear datasets before pushing new rows.

    Per CLAUDE.md secret-handling protocol, the client secret value
    NEVER flows through the request body — only the env-var name.
    """
    request_id = _new_request_id()
    try:
        from evidentia_integrations.powerbi import (
            PowerBIApiError,
            PowerBIConfig,
            publish_report,
        )
    except ImportError as e:
        raise api_error(
            503,
            "feature_unavailable",
            ("Power BI integration not installed. Run `pip install 'evidentia-integrations[powerbi]'`."),
        ) from e

    workspace_id = str(payload.get("workspace_id") or "").strip()
    tenant_id = str(payload.get("tenant_id") or "").strip()
    client_id = str(payload.get("client_id") or "").strip()
    if not workspace_id:
        raise api_error(
            400,
            "missing_field",
            "Request body must include 'workspace_id'.",
            field="workspace_id",
        )
    if not tenant_id:
        raise api_error(
            400,
            "missing_field",
            "Request body must include 'tenant_id'.",
            field="tenant_id",
        )
    if not client_id:
        raise api_error(
            400,
            "missing_field",
            "Request body must include 'client_id'.",
            field="client_id",
        )

    # Validate body shape BEFORE report lookup.
    risks_input = payload.get("risks")
    risks: Any | None = None
    if risks_input is not None:
        from evidentia_core.models.risk import RiskStatement

        if not isinstance(risks_input, list):
            raise api_error(
                400,
                "invalid_field",
                "'risks' must be a JSON array.",
                field="risks",
            )
        try:
            risks = [RiskStatement.model_validate(item) for item in risks_input]
        except Exception as exc:
            raise api_error(
                400,
                "invalid_field",
                f"Invalid risk payload: {exc}",
                field="risks",
            ) from exc

    report = _load_report(report_key)

    cfg = PowerBIConfig(
        workspace_id=workspace_id,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret_env=str(payload.get("client_secret_env") or "POWERBI_CLIENT_SECRET"),
    )
    clear_before_push = bool(payload.get("clear_before_push", True))

    try:
        result = publish_report(
            config=cfg,
            report=report,
            risks=risks,
            clear_before_push=clear_before_push,
        )
    except PowerBIApiError as exc:
        logger.exception("Power BI publish failed (request_id=%s)", request_id)
        raise api_error(503, "upstream_error", str(exc)) from exc
    except Exception as exc:
        logger.exception(
            "Power BI publish unexpected error (request_id=%s)",
            request_id,
        )
        raise api_error(
            500,
            "internal_error",
            f"Power BI publish failed; request_id={request_id}",
            request_id=request_id,
        ) from exc

    return result.model_dump()


# ── ServiceNow status ─────────────────────────────────────────────


@router.get("/integrations/servicenow/status")
async def servicenow_status() -> dict[str, Any]:
    """Return whether ServiceNow is configured + a connectivity probe.

    Connectivity/config probe only — does NOT create any records.
    Calls ``ServiceNowClient.test_connection`` which issues a single
    1-row read against the configured table, confirming both that the
    credentials work and that the principal has read access.

    Credentials are sourced SERVER-SIDE from environment variables
    (``EVIDENTIA_SERVICENOW_*``), exactly like the Jira ``status``
    endpoint — never from the request. The basic-auth password value
    is never included in the response; on any failure a sanitized
    message + a correlatable ``request_id`` is returned and the
    specifics are written to the server log only.
    """
    try:
        from evidentia_integrations.servicenow import (
            ServiceNowApiError,
            ServiceNowClient,
            ServiceNowConfig,
        )
    except ImportError as e:  # pragma: no cover — integrations ships with CLI
        rid = _new_request_id()
        logger.warning("servicenow_status import failure [%s]: %r", rid, e)
        return {
            "configured": False,
            "error": "evidentia-integrations package is not installed.",
            "request_id": rid,
        }

    try:
        cfg = ServiceNowConfig.from_env()
    except ValueError as e:
        rid = _new_request_id()
        logger.warning("servicenow_status config failure [%s]: %r", rid, e)
        return {
            "configured": False,
            "error": "ServiceNow configuration is incomplete or invalid.",
            "request_id": rid,
        }

    try:
        with ServiceNowClient(cfg) as client:
            info = client.test_connection()
    except ServiceNowApiError as e:
        rid = _new_request_id()
        logger.warning("servicenow_status api failure [%s]: %r", rid, e)
        return {
            "configured": False,
            "instance_url": cfg.instance_url,
            "table_name": cfg.table_name,
            "error": ("ServiceNow API call failed; check server logs with the request_id."),
            "request_id": rid,
        }

    return {
        "configured": True,
        "instance_url": info["instance_url"],
        "table_name": info["table_name"],
        "user": info["user"],
        "result_count": info["result_count"],
    }


# ── ServiceNow push ───────────────────────────────────────────────


@router.post(
    "/integrations/servicenow/push/{report_key}",
    responses=error_responses(
        {
            400: "Malformed ``report_key`` (``error: invalid_id``).",
            404: "No such stored report (``error: not_found``).",
            503: (
                "ServiceNow integration not installed "
                "(``error: feature_unavailable``) or env "
                "configuration incomplete "
                "(``error: credentials_missing``)."
            ),
        }
    ),
)
async def servicenow_push(
    report_key: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Push open gaps from a saved report as ServiceNow records.

    Credentialed EXTERNAL write — creates an incident / GRC-issue /
    custom-table record per OPEN / IN_PROGRESS gap. Idempotent: a gap
    that already has a matching record (by ``correlation_id``) is
    reported as ``existing`` rather than duplicated.

    Path:
      - ``report_key``: the gap-store key for a previously saved
        :class:`GapAnalysisReport`.

    Request body is optional and carries ONLY non-secret params:

      - ``force``: bool (default false) — create new records even when
        a matching ``correlation_id`` already exists. Rarely needed.

    Credentials (instance URL / user / password) are sourced
    SERVER-SIDE from ``EVIDENTIA_SERVICENOW_*`` environment variables,
    exactly like the Jira ``push`` endpoint. Secret values NEVER flow
    through the request body; any ``instance_url`` / ``user`` /
    ``password`` keys in the body are ignored.

    Returns ``503`` when the integration is unconfigured, ``400`` on a
    malformed report key, and ``404`` when the report does not exist.
    """
    try:
        from evidentia_integrations.servicenow import (
            ServiceNowClient,
            ServiceNowConfig,
        )
        from evidentia_integrations.servicenow import (
            push_open_gaps as sn_push_open_gaps,
        )
    except ImportError as e:
        raise api_error(
            503,
            "feature_unavailable",
            ("ServiceNow integration not installed. Run `pip install 'evidentia-integrations[servicenow]'`."),
        ) from e

    report = _load_report(report_key)

    try:
        cfg = ServiceNowConfig.from_env()
    except ValueError as e:
        raise api_error(503, "credentials_missing", str(e)) from e

    body = payload or {}
    force = bool(body.get("force", False))

    with ServiceNowClient(cfg) as client:
        result = sn_push_open_gaps(report, client, force=force)

    # Audit the credentialed external write. No secret values are
    # included — only the report key, target table, and outcome counts.
    _audit.info(
        action=EventAction.INTEGRATIONS_SERVICENOW_PUSH,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Pushed gap report {report_key} to ServiceNow table "
            f"{cfg.table_name} via API: created={result.created} "
            f"existing={result.existing} skipped={result.skipped} "
            f"errored={result.errored}"
        ),
        evidentia={
            "report_key": report_key,
            "table_name": cfg.table_name,
            "created": result.created,
            "existing": result.existing,
            "skipped": result.skipped,
            "errored": result.errored,
        },
    )

    return {
        "created": result.created,
        "existing": result.existing,
        "skipped": result.skipped,
        "errored": result.errored,
        "outcomes": [o.model_dump(mode="json") for o in result.outcomes],
    }
