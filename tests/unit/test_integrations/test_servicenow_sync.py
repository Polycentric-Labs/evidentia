"""Unit tests for ``evidentia_integrations.servicenow.sync``.

End-to-end gap-to-ServiceNow push, with httpx.MockTransport. Tests
verify idempotency (correlation_id lookup avoids dupes) + the
SKIPPED / EXISTING / CREATED / ERRORED outcome breakdown.
"""

from __future__ import annotations

from typing import Any

import httpx
from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    GapStatus,
    ImplementationEffort,
)
from evidentia_integrations.servicenow.client import ServiceNowClient
from evidentia_integrations.servicenow.config import ServiceNowConfig
from evidentia_integrations.servicenow.sync import (
    ServiceNowSyncAction,
    push_gap_to_servicenow,
    push_open_gaps,
)


def _gap(
    gap_id: str = "g01",
    status: GapStatus = GapStatus.OPEN,
    **overrides: object,
) -> ControlGap:
    defaults = {
        "id": gap_id,
        "framework": "nist-800-53-rev5-moderate",
        "control_id": "AC-2",
        "control_title": "Account Management",
        "control_description": "Manage information system accounts.",
        "gap_severity": GapSeverity.HIGH,
        "implementation_status": "missing",
        "gap_description": "No centralized account-management process.",
        "remediation_guidance": "Deploy Okta with quarterly access reviews.",
        "implementation_effort": ImplementationEffort.MEDIUM,
        "status": status,
    }
    defaults.update(overrides)
    return ControlGap(**defaults)  # type: ignore[arg-type]


def _make_report(*, gaps: list[ControlGap]) -> GapAnalysisReport:
    """Build a minimum-viable GapAnalysisReport for sync tests."""
    crit = sum(1 for g in gaps if g.gap_severity == GapSeverity.CRITICAL)
    high = sum(1 for g in gaps if g.gap_severity == GapSeverity.HIGH)
    med = sum(1 for g in gaps if g.gap_severity == GapSeverity.MEDIUM)
    low = sum(1 for g in gaps if g.gap_severity == GapSeverity.LOW)
    return GapAnalysisReport(
        organization="Test Org",
        frameworks_analyzed=["nist-800-53-rev5-moderate"],
        total_controls_required=len(gaps),
        total_controls_in_inventory=0,
        total_gaps=len(gaps),
        critical_gaps=crit,
        high_gaps=high,
        medium_gaps=med,
        low_gaps=low,
        coverage_percentage=0.0,
        gaps=gaps,
    )


def _client_with_handler(
    handler: Any,
    table_name: str = "incident",
) -> ServiceNowClient:
    cfg = ServiceNowConfig(
        instance_url="https://acme.service-now.com",
        user="evidentia.bot",
        password="hunter2",
        table_name=table_name,
    )
    transport = httpx.MockTransport(handler)
    http = httpx.Client(
        base_url=cfg.instance_url,
        transport=transport,
        headers={"Authorization": "Basic test"},
    )
    return ServiceNowClient(cfg, http=http)


# ── push_gap_to_servicenow ──────────────────────────────────────────


def test_push_creates_new_record_when_no_existing_match() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        if request.method == "GET":
            # Idempotency lookup returns no match
            return httpx.Response(200, json={"result": []})
        return httpx.Response(
            201,
            json={
                "result": {
                    "sys_id": "abc",
                    "number": "INC0010001",
                    "short_description": "...",
                    "state": "1",
                }
            },
        )

    client = _client_with_handler(handler)
    outcome = push_gap_to_servicenow(_gap(), client)
    assert outcome.action == ServiceNowSyncAction.CREATED
    assert outcome.sys_id == "abc"
    assert outcome.record_number == "INC0010001"
    # 1 GET (lookup) + 1 POST (create) = 2 requests
    assert len(captured) == 2


def test_push_returns_existing_when_correlation_id_matches() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # Always return a match — push should detect dupe
        return httpx.Response(
            200,
            json={
                "result": [
                    {
                        "sys_id": "existing-sys-id",
                        "number": "INC0009999",
                        "short_description": "Already exists",
                        "state": "2",
                    }
                ]
            },
        )

    client = _client_with_handler(handler)
    outcome = push_gap_to_servicenow(_gap(), client)
    assert outcome.action == ServiceNowSyncAction.EXISTING
    assert outcome.sys_id == "existing-sys-id"
    assert outcome.record_number == "INC0009999"


def test_push_force_creates_even_when_existing() -> None:
    creates = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal creates
        if request.method == "POST":
            creates += 1
            return httpx.Response(
                201,
                json={"result": {"sys_id": "new", "number": "INC0099999"}},
            )
        # No GET should be made when force=True
        return httpx.Response(500, json={"error": {"message": "GET should not happen"}})

    client = _client_with_handler(handler)
    outcome = push_gap_to_servicenow(_gap(), client, force=True)
    assert outcome.action == ServiceNowSyncAction.CREATED
    assert creates == 1


def test_push_returns_errored_on_api_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": {"message": "Internal Server Error"}})

    client = _client_with_handler(handler)
    outcome = push_gap_to_servicenow(_gap(), client)
    assert outcome.action == ServiceNowSyncAction.ERRORED
    assert "lookup failed" in outcome.detail


def test_push_returns_errored_on_mapping_failure() -> None:
    gap = _gap()
    gap.framework = ""  # break the mapper

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={})

    client = _client_with_handler(handler)
    outcome = push_gap_to_servicenow(gap, client)
    assert outcome.action == ServiceNowSyncAction.ERRORED
    assert "Mapping error" in outcome.detail


# ── push_open_gaps ──────────────────────────────────────────────────


def test_push_open_gaps_skips_remediated() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"result": []})
        return httpx.Response(
            201,
            json={"result": {"sys_id": "x", "number": "INC0001"}},
        )

    client = _client_with_handler(handler)
    report = _make_report(
        gaps=[
            _gap(gap_id="g01", status=GapStatus.OPEN),
            _gap(gap_id="g02", status=GapStatus.REMEDIATED),
            _gap(gap_id="g03", status=GapStatus.IN_PROGRESS),
            _gap(gap_id="g04", status=GapStatus.ACCEPTED),
            _gap(gap_id="g05", status=GapStatus.NOT_APPLICABLE),
        ]
    )
    result = push_open_gaps(report, client)

    assert result.created == 2  # g01 + g03
    assert result.skipped == 3  # g02 + g04 + g05
    assert result.errored == 0


def test_push_open_gaps_aggregate_counts() -> None:
    state = {"created": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"result": []})
        state["created"] += 1
        return httpx.Response(
            201,
            json={
                "result": {
                    "sys_id": f"x{state['created']:03d}",
                    "number": f"INC{state['created']:08d}",
                }
            },
        )

    client = _client_with_handler(handler)
    report = _make_report(gaps=[_gap(gap_id=f"g{i:02d}", status=GapStatus.OPEN) for i in range(5)])
    result = push_open_gaps(report, client)
    assert result.created == 5
    assert state["created"] == 5
