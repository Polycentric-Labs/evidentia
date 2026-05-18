"""``GET /api/metrics`` — Prometheus text-format exposition (v0.8.0 P1 G3).

Lightweight stdlib-only implementation of a Prometheus-
compatible metrics endpoint. Exposes:

- ``evidentia_app_info{version="..."}`` — single-sample gauge
  carrying the running version (label-encoded; standard
  Prometheus convention).
- ``evidentia_audit_events_total{action="..."}`` — counter
  tracking the cumulative count of audit events per
  EventAction since process start.
- ``evidentia_audit_events_failures_total`` — counter for
  audit events with EventOutcome.FAILURE.
- ``evidentia_uptime_seconds`` — gauge showing how long the
  process has been running.

The counters tap into the existing
:mod:`evidentia_core.audit` event-firing path via a lightweight
in-process counter dict. The metrics are PROCESS-LOCAL — a
multi-process deployment will need an external aggregator
(Prometheus Pushgateway, statsd, etc.). For v0.8.0 single-
process operation, this gives operators visibility into AI
call rates, retention transitions, eval runs, and any other
audit-tracked action without a heavyweight client library.

The endpoint emits ``Content-Type: text/plain; version=0.0.4;
charset=utf-8`` per the official Prometheus exposition format
spec (https://prometheus.io/docs/instrumenting/exposition_formats/).
Operators can scrape this with ``prometheus.io`` directly OR
ingest into Grafana Agent / OpenTelemetry Collector for
metric forwarding.

OPERATIONAL POSTURE (v0.8.0 review F-V08-S3): the endpoint is
NOT auth-gated. Acceptable for the default localhost-bound
deployment (`uvicorn --host 127.0.0.1`) where the same trust
boundary already applies to ``/api/docs`` + ``/api/health``.
For non-loopback bind (`--host 0.0.0.0`), operators MUST
front the endpoint with reverse-proxy basic auth, mTLS, or a
network-segregated scrape network — Prometheus exposition
output reveals server fingerprint + operational telemetry
that an attacker can use to time auth-spray attacks. v0.8.1
will wire :class:`AuthProvider` plugin contract into the
FastAPI dependency stack so this endpoint inherits the same
auth requirement as ``/api/risks`` and other gated routers.
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from pathlib import Path

from evidentia_core.audit.metrics import (
    PROMETHEUS_CONTENT_TYPE,
    render_metrics,
)
from evidentia_core.conmon.daemon import read_daemon_status
from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from evidentia_api import __version__ as api_version

router = APIRouter()

_PROCESS_START_TIME = time.monotonic()


def _render_conmon_daemon_gauges() -> str:
    """v0.9.5 P2.3: append conmon-daemon health gauges if the
    operator has configured ``EVIDENTIA_CONMON_DAEMON_STATUS_FILE``
    + the daemon has produced at least one status snapshot.

    Returns an empty string when the env var is unset or the file
    can't be read — Prometheus scrapers tolerate sparse metric
    sets gracefully (gauges absent in one scrape simply gap in
    the time series).

    Emitted gauges:

    - ``evidentia_conmon_daemon_last_poll_age_seconds`` — how
      long since the last poll fired. Operators alert on this
      exceeding ``poll_interval_seconds * 2`` (daemon stalled).
    - ``evidentia_conmon_daemon_last_poll_success`` — 1.0 when
      the last poll succeeded; 0.0 on failure.
    - ``evidentia_conmon_daemon_recognized_cadence_count`` —
      how many state-file slugs have a matching registered
      cadence. Pair with the unknown_cadence_count gauge to
      detect operator-misconfigured state files.
    - ``evidentia_conmon_daemon_unknown_cadence_count``
    - ``evidentia_conmon_daemon_uptime_seconds``
    """
    status_file_env = os.environ.get(
        "EVIDENTIA_CONMON_DAEMON_STATUS_FILE", ""
    ).strip()
    if not status_file_env:
        return ""
    payload = read_daemon_status(Path(status_file_env))
    if payload is None:
        return ""

    lines: list[str] = []
    last_poll_at_raw = payload.get("last_poll_at")
    if isinstance(last_poll_at_raw, str):
        try:
            last_poll_at = datetime.fromisoformat(last_poll_at_raw)
            age_seconds = (
                datetime.now(tz=UTC) - last_poll_at
            ).total_seconds()
            lines.extend(
                [
                    "# HELP evidentia_conmon_daemon_last_poll_age_seconds "
                    "Seconds since the daemon's last poll cycle completed.",
                    "# TYPE evidentia_conmon_daemon_last_poll_age_seconds "
                    "gauge",
                    f"evidentia_conmon_daemon_last_poll_age_seconds "
                    f"{age_seconds:.6f}",
                ]
            )
        except ValueError:
            # Mid-write or corrupted timestamp — skip the age gauge.
            pass

    outcome = payload.get("last_poll_outcome")
    if outcome in ("success", "failed"):
        lines.extend(
            [
                "# HELP evidentia_conmon_daemon_last_poll_success "
                "1.0 if the last poll succeeded, 0.0 if it failed.",
                "# TYPE evidentia_conmon_daemon_last_poll_success gauge",
                f"evidentia_conmon_daemon_last_poll_success "
                f"{1.0 if outcome == 'success' else 0.0}",
            ]
        )

    recognized = payload.get("recognized_cadence_count")
    if isinstance(recognized, int):
        lines.extend(
            [
                "# HELP evidentia_conmon_daemon_recognized_cadence_count "
                "Number of state-file slugs with a registered cadence.",
                "# TYPE evidentia_conmon_daemon_recognized_cadence_count "
                "gauge",
                f"evidentia_conmon_daemon_recognized_cadence_count "
                f"{recognized}",
            ]
        )

    unknown = payload.get("unknown_cadence_count")
    if isinstance(unknown, int):
        lines.extend(
            [
                "# HELP evidentia_conmon_daemon_unknown_cadence_count "
                "Number of state-file slugs without a registered cadence.",
                "# TYPE evidentia_conmon_daemon_unknown_cadence_count gauge",
                f"evidentia_conmon_daemon_unknown_cadence_count {unknown}",
            ]
        )

    uptime = payload.get("daemon_uptime_seconds")
    if isinstance(uptime, int | float):
        lines.extend(
            [
                "# HELP evidentia_conmon_daemon_uptime_seconds "
                "Seconds since the conmon daemon process started.",
                "# TYPE evidentia_conmon_daemon_uptime_seconds gauge",
                f"evidentia_conmon_daemon_uptime_seconds {float(uptime):.6f}",
            ]
        )

    return "\n".join(lines) + "\n" if lines else ""


@router.get("/metrics", response_class=PlainTextResponse)
async def metrics() -> PlainTextResponse:
    """Render Prometheus text-format metrics for scraping.

    Returns:
        ``200 OK`` with ``Content-Type: text/plain; version=0.0.4;
        charset=utf-8`` carrying the current metric values.

    v0.9.5 P2.3: when ``EVIDENTIA_CONMON_DAEMON_STATUS_FILE`` is
    set, appends conmon-daemon health gauges (last_poll_age_seconds,
    recognized_cadence_count, etc.) so operators can wire Prometheus
    alerting on daemon staleness + flapping. See module docstring
    for the gauge inventory.
    """
    uptime = time.monotonic() - _PROCESS_START_TIME
    body = render_metrics(api_version=api_version, uptime_seconds=uptime)
    body += _render_conmon_daemon_gauges()
    return PlainTextResponse(
        content=body,
        media_type=PROMETHEUS_CONTENT_TYPE,
    )
