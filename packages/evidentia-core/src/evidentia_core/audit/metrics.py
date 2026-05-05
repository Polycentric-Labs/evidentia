"""In-process Prometheus metrics aggregation (v0.8.0 P1 G3).

A lightweight stdlib-only counter aggregator that taps into
the audit-event-firing path. The ECS-structured logger
(:func:`evidentia_core.audit.get_logger`) calls
:func:`record_event` on every emit; the counters are exposed
via :mod:`evidentia_api.routers.metrics`.

Process-local: counters reset on process restart and are
NOT shared across worker processes in a multi-worker uvicorn
deployment. Single-process operation is the v0.8.0 target;
multi-process aggregation defers to v0.8.1 (likely via
Prometheus Pushgateway or an OpenTelemetry collector
sidecar).

Thread-safety: counters are Python ints incremented under a
threading lock so concurrent audit events from different
worker threads can't corrupt the counts. The lock contention
is negligible compared to the audit-log I/O the events
already incur.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator

# Prometheus exposition format media type (spec version 0.0.4).
# https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format
PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

_lock = threading.Lock()
_event_counts: dict[str, int] = {}
_failure_count = 0


def record_event(*, action: str, outcome: str) -> None:
    """Increment counters for a single audit-event firing.

    Called by :func:`evidentia_core.audit.get_logger`'s emit
    path on every event. Cheap (dict + int increment under
    lock) so the audit-log I/O dominates the cost.

    Args:
        action: The :class:`EventAction` string value (e.g.
            ``evidentia.ai.risk_generated``).
        outcome: The :class:`EventOutcome` string value
            (``success``, ``failure``, or ``unknown``).
    """
    global _failure_count
    with _lock:
        _event_counts[action] = _event_counts.get(action, 0) + 1
        if outcome == "failure":
            _failure_count += 1


def reset_for_tests() -> None:
    """Test-only — clear the counters between cases."""
    global _failure_count
    with _lock:
        _event_counts.clear()
        _failure_count = 0


def _iter_event_lines() -> Iterator[str]:
    with _lock:
        snapshot = dict(_event_counts)
    for action, count in sorted(snapshot.items()):
        # Escape per Prometheus spec — backslash, double-quote, newline.
        escaped = (
            action.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
        )
        yield f'evidentia_audit_events_total{{action="{escaped}"}} {count}'


def render_metrics(*, api_version: str, uptime_seconds: float) -> str:
    """Render the current counter snapshot in Prometheus text format.

    Args:
        api_version: Running ``evidentia-api`` version string;
            label-encoded into the ``evidentia_app_info`` gauge
            per Prometheus app-version convention.
        uptime_seconds: Seconds since process start. Provided
            by the caller (the FastAPI router records start
            time when the module loads) rather than computed
            here so unit tests can pass deterministic values.

    Returns:
        Prometheus exposition format (text/plain) — newline-
        separated metric lines plus required ``# HELP`` and
        ``# TYPE`` annotations.
    """
    lines: list[str] = []

    # evidentia_app_info — single-sample gauge carrying the
    # version label per Prometheus app-info convention.
    lines.append("# HELP evidentia_app_info Evidentia API server info.")
    lines.append("# TYPE evidentia_app_info gauge")
    escaped_ver = (
        api_version.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )
    lines.append(f'evidentia_app_info{{version="{escaped_ver}"}} 1')

    # evidentia_uptime_seconds — process uptime gauge.
    lines.append(
        "# HELP evidentia_uptime_seconds Seconds since the API process started."
    )
    lines.append("# TYPE evidentia_uptime_seconds gauge")
    # Render with 6-decimal precision; Prometheus expects float text.
    lines.append(f"evidentia_uptime_seconds {uptime_seconds:.6f}")

    # evidentia_audit_events_total — per-action counter.
    lines.append(
        "# HELP evidentia_audit_events_total "
        "Cumulative count of audit events per EventAction."
    )
    lines.append("# TYPE evidentia_audit_events_total counter")
    event_lines = list(_iter_event_lines())
    lines.extend(event_lines)

    # evidentia_audit_events_failures_total — failure counter.
    with _lock:
        failure_snapshot = _failure_count
    lines.append(
        "# HELP evidentia_audit_events_failures_total "
        "Cumulative count of audit events with outcome=failure."
    )
    lines.append("# TYPE evidentia_audit_events_failures_total counter")
    lines.append(f"evidentia_audit_events_failures_total {failure_snapshot}")

    # Trailing newline per Prometheus exposition format.
    return "\n".join(lines) + "\n"
