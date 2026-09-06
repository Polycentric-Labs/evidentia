"""Unit tests for the v0.8.0 P1 G3 Prometheus metrics endpoint.

Two test classes:

1. :class:`TestRender` — :func:`render_metrics` produces
   well-formed Prometheus text-format output (HELP + TYPE
   annotations, escaped labels, no trailing whitespace).
2. :class:`TestEndpoint` — ``GET /api/metrics`` returns
   200 with the right Content-Type, contains the expected
   metric names, and increments the counter when an audit
   event fires.
"""

from __future__ import annotations

import pytest
from evidentia_api.app import create_app
from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.audit.metrics import (
    PROMETHEUS_CONTENT_TYPE,
    record_event,
    render_metrics,
    reset_for_tests,
)
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _reset_metrics() -> None:
    """Each test starts with empty counters."""
    reset_for_tests()


# ── 1. Render ──────────────────────────────────────────────────────


class TestRender:
    def test_empty_state_emits_app_info_and_uptime(self) -> None:
        body = render_metrics(api_version="0.7.16", uptime_seconds=12.5)
        assert "evidentia_app_info" in body
        assert 'version="0.7.16"' in body
        assert "evidentia_uptime_seconds" in body
        assert "12.500000" in body
        # Counters are present even when zero.
        assert "evidentia_audit_events_total" in body
        assert "evidentia_audit_events_failures_total" in body

    def test_help_and_type_annotations_present(self) -> None:
        body = render_metrics(api_version="0.7.16", uptime_seconds=0.0)
        # HELP + TYPE pair for every metric per Prometheus spec.
        for metric in (
            "evidentia_app_info",
            "evidentia_uptime_seconds",
            "evidentia_audit_events_total",
            "evidentia_audit_events_failures_total",
        ):
            assert f"# HELP {metric}" in body, f"missing HELP for {metric}"
            assert f"# TYPE {metric}" in body, f"missing TYPE for {metric}"

    def test_record_event_increments_counter(self) -> None:
        record_event(action="evidentia.test.event", outcome="success")
        record_event(action="evidentia.test.event", outcome="success")
        record_event(action="evidentia.test.other", outcome="success")
        body = render_metrics(api_version="0.7.16", uptime_seconds=0.0)
        assert ('evidentia_audit_events_total{action="evidentia.test.event"} 2') in body
        assert ('evidentia_audit_events_total{action="evidentia.test.other"} 1') in body

    def test_failure_outcome_bumps_failure_counter(self) -> None:
        record_event(action="evidentia.test.failure", outcome="failure")
        record_event(action="evidentia.test.success", outcome="success")
        body = render_metrics(api_version="0.7.16", uptime_seconds=0.0)
        assert "evidentia_audit_events_failures_total 1" in body

    def test_label_escaping_preserves_special_chars(self) -> None:
        # Prometheus requires escaping of \, ", \n in label values.
        record_event(
            action='evidentia.weird"action\\path',
            outcome="success",
        )
        body = render_metrics(api_version="0.7.16", uptime_seconds=0.0)
        assert ('evidentia.weird\\"action\\\\path') in body

    def test_output_ends_with_newline(self) -> None:
        body = render_metrics(api_version="0.7.16", uptime_seconds=0.0)
        # Prometheus exposition format requires the body end with a
        # newline so scrapers can detect EOF unambiguously.
        assert body.endswith("\n")


# ── 2. /api/metrics endpoint ───────────────────────────────────────


class TestEndpoint:
    def test_get_metrics_returns_200_with_prometheus_content_type(
        self,
    ) -> None:
        app = create_app(dev_mode=False)
        client = TestClient(app)
        response = client.get("/api/metrics")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        # Full content type carries Prometheus version annotation.
        assert "version=0.0.4" in response.headers["content-type"]

    def test_endpoint_carries_app_info(self) -> None:
        app = create_app(dev_mode=False)
        client = TestClient(app)
        response = client.get("/api/metrics")
        assert "evidentia_app_info" in response.text

    def test_audit_events_increment_endpoint_counter(self) -> None:
        import logging

        app = create_app(dev_mode=False)
        client = TestClient(app)
        # Fire a real audit event (using the EventAction enum so the
        # logger -> record_event tap fires too). v0.8.1 F-V08-CR-1
        # gates record_event on the stdlib logger's level filter, so
        # the test must set the level to INFO explicitly to opt
        # into seeing INFO events.
        log = get_logger("evidentia.test.metrics")
        logging.getLogger("evidentia.test.metrics").setLevel(logging.INFO)
        log.info(
            action=EventAction.AI_RISK_GENERATED,
            outcome=EventOutcome.SUCCESS,
            message="test event",
        )
        response = client.get("/api/metrics")
        assert response.status_code == 200
        # The action label is the EventAction string value.
        assert ('evidentia_audit_events_total{action="evidentia.ai.risk_generated"} 1') in response.text

    def test_filtered_log_events_do_not_increment_counter(self) -> None:
        """v0.8.1 F-V08-CR-1: when the stdlib logger filters out
        an event (level=WARNING; INFO event), the counter does
        NOT increment. Counters and log-stream stay in sync.
        """
        import logging

        app = create_app(dev_mode=False)
        client = TestClient(app)
        # Set logger to WARNING — INFO events should be filtered.
        log = get_logger("evidentia.test.filtered")
        logging.getLogger("evidentia.test.filtered").setLevel(logging.WARNING)
        log.info(
            action=EventAction.AI_RISK_GENERATED,
            outcome=EventOutcome.SUCCESS,
            message="filtered INFO event",
        )
        response = client.get("/api/metrics")
        # The event was filtered out; no counter increment.
        assert ('evidentia_audit_events_total{action="evidentia.ai.risk_generated"} 1') not in response.text

    def test_prometheus_content_type_constant_well_formed(self) -> None:
        # Sanity check the constant exposed for downstream tooling.
        assert PROMETHEUS_CONTENT_TYPE.startswith("text/plain")
        assert "version=0.0.4" in PROMETHEUS_CONTENT_TYPE

    def test_record_event_rejects_unknown_outcome(self) -> None:
        """v0.8.1 F-V08-CR-2: record_event raises on unknown
        outcome strings rather than silently miscounting."""
        with pytest.raises(ValueError, match="outcome must be one of"):
            record_event(action="evidentia.test.bad", outcome="bogus")
        with pytest.raises(ValueError):
            record_event(action="evidentia.test.bad", outcome="FAILURE")  # case-sensitive
