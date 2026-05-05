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
"""

from __future__ import annotations

import time

from evidentia_core.audit.metrics import (
    PROMETHEUS_CONTENT_TYPE,
    render_metrics,
)
from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from evidentia_api import __version__ as api_version

router = APIRouter()

_PROCESS_START_TIME = time.monotonic()


@router.get("/metrics", response_class=PlainTextResponse)
async def metrics() -> PlainTextResponse:
    """Render Prometheus text-format metrics for scraping.

    Returns:
        ``200 OK`` with ``Content-Type: text/plain; version=0.0.4;
        charset=utf-8`` carrying the current metric values.
    """
    uptime = time.monotonic() - _PROCESS_START_TIME
    body = render_metrics(api_version=api_version, uptime_seconds=uptime)
    return PlainTextResponse(
        content=body,
        media_type=PROMETHEUS_CONTENT_TYPE,
    )
