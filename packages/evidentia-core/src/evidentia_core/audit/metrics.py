"""In-process Prometheus metrics aggregation (v0.8.0 P1 G3 + v0.8.1 F-V08-CR-2).

A lightweight stdlib-only counter aggregator that taps into
the audit-event-firing path. The ECS-structured logger
(:func:`evidentia_core.audit.get_logger`) calls
:func:`record_event` on every emit; the counters are exposed
via :mod:`evidentia_api.routers.metrics`.

Process-local: counters reset on process restart and are
NOT shared across worker processes in a multi-worker uvicorn
deployment. Single-process operation is the v0.8.0 target;
multi-process aggregation defers to v0.8.x (likely via
Prometheus Pushgateway or an OpenTelemetry collector
sidecar).

Thread-safety: counters are encapsulated in a
:class:`MetricsRegistry` instance with a per-registry
threading.Lock so concurrent audit events from different
worker threads can't corrupt the counts. The lock contention
is negligible compared to the audit-log I/O the events
already incur.

v0.8.1 F-V08-CR-2 closure: counters were previously module-
level globals; that exposed implicit-state-management bugs
where any caller could pass an outcome value that didn't
match the literal ``"failure"`` string used by the comparison.
The :class:`MetricsRegistry` class encapsulates state +
asserts the outcome contract via :class:`EventOutcome`'s
canonical values (``success``, ``failure``, ``unknown``).
The module-level :func:`record_event` and
:func:`render_metrics` functions remain as the public API
and delegate to a process-default registry.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator

# Prometheus exposition format media type (spec version 0.0.4).
# https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format
PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

# v0.8.1 F-V08-CR-2: canonical EventOutcome values that
# MetricsRegistry recognizes for the failure-counter
# increment. Mirrors :class:`evidentia_core.audit.events.EventOutcome`
# (avoid circular import; closed enum tracked here).
_VALID_OUTCOMES = frozenset({"success", "failure", "unknown"})


class MetricsRegistry:
    """Thread-safe counter aggregator for audit events.

    Encapsulates the previously module-level globals so:

    1. Tests can construct an isolated registry without a
       module reload.
    2. The outcome contract is enforced at boundary
       (``record_event`` rejects unknown outcome strings
       loudly via ValueError rather than silently miscounting).
    3. Future multi-process aggregation can subclass this
       with a Pushgateway-backed implementation while
       preserving the API.

    A process-default instance lives at :data:`_DEFAULT_REGISTRY`;
    the module-level :func:`record_event` and
    :func:`render_metrics` functions delegate to it.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._event_counts: dict[str, int] = {}
        self._failure_count = 0

    def record_event(self, *, action: str, outcome: str) -> None:
        """Increment counters for a single audit-event firing.

        Args:
            action: The :class:`EventAction` string value (e.g.
                ``evidentia.ai.risk_generated``).
            outcome: One of ``"success"``, ``"failure"``, or
                ``"unknown"`` — the :class:`EventOutcome` string
                values. Other values raise ``ValueError`` (the
                v0.8.1 F-V08-CR-2 enforcement; previously a
                bug-prone implicit string comparison).
        """
        if outcome not in _VALID_OUTCOMES:
            raise ValueError(f"record_event: outcome must be one of {sorted(_VALID_OUTCOMES)}; got {outcome!r}")
        with self._lock:
            self._event_counts[action] = self._event_counts.get(action, 0) + 1
            if outcome == "failure":
                self._failure_count += 1

    def reset(self) -> None:
        """Clear counters; used by ``reset_for_tests``."""
        with self._lock:
            self._event_counts.clear()
            self._failure_count = 0

    def iter_event_lines(self) -> Iterator[str]:
        """Yield Prometheus exposition lines for each action's count."""
        with self._lock:
            snapshot = dict(self._event_counts)
        for action, count in sorted(snapshot.items()):
            # Escape per Prometheus spec — backslash, double-quote,
            # newline.
            escaped = action.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            yield (f'evidentia_audit_events_total{{action="{escaped}"}} {count}')

    @property
    def failure_count(self) -> int:
        """Snapshot of the cumulative failure-event count."""
        with self._lock:
            return self._failure_count


# Process-default registry. The module-level convenience
# functions below delegate to this; tests + multi-tenant
# scenarios can construct dedicated MetricsRegistry instances.
_DEFAULT_REGISTRY = MetricsRegistry()


def record_event(*, action: str, outcome: str) -> None:
    """Increment counters on the process-default registry."""
    _DEFAULT_REGISTRY.record_event(action=action, outcome=outcome)


def reset_for_tests() -> None:
    """Test-only — clear the process-default registry between cases."""
    _DEFAULT_REGISTRY.reset()


def _iter_event_lines() -> Iterator[str]:
    """Process-default registry iter_event_lines (back-compat)."""
    yield from _DEFAULT_REGISTRY.iter_event_lines()


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
    escaped_ver = api_version.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    lines.append(f'evidentia_app_info{{version="{escaped_ver}"}} 1')

    # evidentia_uptime_seconds — process uptime gauge.
    lines.append("# HELP evidentia_uptime_seconds Seconds since the API process started.")
    lines.append("# TYPE evidentia_uptime_seconds gauge")
    # Render with 6-decimal precision; Prometheus expects float text.
    lines.append(f"evidentia_uptime_seconds {uptime_seconds:.6f}")

    # evidentia_audit_events_total — per-action counter.
    lines.append("# HELP evidentia_audit_events_total Cumulative count of audit events per EventAction.")
    lines.append("# TYPE evidentia_audit_events_total counter")
    event_lines = list(_iter_event_lines())
    lines.extend(event_lines)

    # evidentia_audit_events_failures_total — failure counter.
    failure_snapshot = _DEFAULT_REGISTRY.failure_count
    lines.append("# HELP evidentia_audit_events_failures_total Cumulative count of audit events with outcome=failure.")
    lines.append("# TYPE evidentia_audit_events_failures_total counter")
    lines.append(f"evidentia_audit_events_failures_total {failure_snapshot}")

    # Trailing newline per Prometheus exposition format.
    return "\n".join(lines) + "\n"
