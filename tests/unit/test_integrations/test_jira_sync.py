"""Unit tests for ``evidentia_integrations.jira.sync`` helpers.

Covers push_gap_to_jira / sync_gap_from_jira / push_open_gaps / sync_report
against a fake :class:`JiraClient` with controllable responses. No real
HTTP.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    GapStatus,
    ImplementationEffort,
)
from evidentia_integrations.jira import JiraApiError
from evidentia_integrations.jira.client import JiraIssue
from evidentia_integrations.jira.sync import (
    JiraSyncAction,
    push_gap_to_jira,
    push_open_gaps,
    sync_gap_from_jira,
    sync_report,
)

# ── Fixtures ─────────────────────────────────────────────────────────────


def _gap(**overrides: object) -> ControlGap:
    defaults: dict[str, object] = {
        "framework": "nist-800-53-rev5-moderate",
        "control_id": "AC-2",
        "control_title": "Account Management",
        "control_description": "Manage accounts",
        "gap_severity": GapSeverity.HIGH,
        "implementation_status": "missing",
        "gap_description": "x",
        "remediation_guidance": "y",
        "implementation_effort": ImplementationEffort.MEDIUM,
    }
    defaults.update(overrides)
    return ControlGap(**defaults)  # type: ignore[arg-type]


def _issue(key: str = "SEC-42", status_name: str = "To Do") -> JiraIssue:
    return JiraIssue(
        key=key,
        id=key.split("-")[1] + "000",
        summary="x",
        status_name=status_name,
        status_category="new",
        url=f"https://acme.atlassian.net/browse/{key}",
    )


def _client(**behavior: object) -> MagicMock:
    """Build a MagicMock shaped like JiraClient."""
    client = MagicMock()
    if "create_issue" in behavior:
        client.create_issue.side_effect = behavior["create_issue"]
    if "get_issue" in behavior:
        client.get_issue.side_effect = behavior["get_issue"]
    return client


# ── push_gap_to_jira ─────────────────────────────────────────────────────


class TestPushGapToJira:
    def test_creates_issue_and_stamps_gap(self) -> None:
        gap = _gap()
        assert gap.jira_issue_key is None

        def _create(**_: object) -> JiraIssue:
            return _issue("SEC-42")

        client = _client(create_issue=_create)

        outcome = push_gap_to_jira(gap, client)

        assert outcome.action == JiraSyncAction.CREATED
        assert outcome.issue_key == "SEC-42"
        assert outcome.issue_url == "https://acme.atlassian.net/browse/SEC-42"
        assert gap.jira_issue_key == "SEC-42"
        assert client.create_issue.call_count == 1

    def test_skips_when_already_linked(self) -> None:
        gap = _gap(jira_issue_key="SEC-1")
        client = _client()

        outcome = push_gap_to_jira(gap, client)

        assert outcome.action == JiraSyncAction.SKIPPED
        assert outcome.issue_key == "SEC-1"
        assert "already linked" in outcome.detail.lower()
        assert client.create_issue.call_count == 0

    def test_force_creates_new_issue_even_when_linked(self) -> None:
        gap = _gap(jira_issue_key="SEC-OLD")

        def _create(**_: object) -> JiraIssue:
            return _issue("SEC-99")

        client = _client(create_issue=_create)

        outcome = push_gap_to_jira(gap, client, force=True)

        assert outcome.action == JiraSyncAction.CREATED
        assert outcome.issue_key == "SEC-99"
        assert gap.jira_issue_key == "SEC-99", "force should overwrite link"

    def test_api_error_returns_errored_outcome(self) -> None:
        gap = _gap()

        def _create(**_: object) -> JiraIssue:
            raise JiraApiError("Bad request", status_code=400, errors=["labels: bad"])

        client = _client(create_issue=_create)

        outcome = push_gap_to_jira(gap, client)

        assert outcome.action == JiraSyncAction.ERRORED
        assert "Jira API error" in outcome.detail
        assert gap.jira_issue_key is None, "Failed push must not leave the gap pointing at a bogus key."


# ── sync_gap_from_jira ───────────────────────────────────────────────────


class TestSyncGapFromJira:
    def test_skips_unlinked_gap(self) -> None:
        gap = _gap(status=GapStatus.OPEN)
        client = _client()
        outcome = sync_gap_from_jira(gap, client)

        assert outcome.action == JiraSyncAction.SKIPPED
        assert "not linked" in outcome.detail.lower()
        assert client.get_issue.call_count == 0

    def test_updates_gap_status_from_jira(self) -> None:
        gap = _gap(jira_issue_key="SEC-5", status=GapStatus.OPEN)
        client = _client(get_issue=lambda _: _issue("SEC-5", status_name="In Progress"))

        outcome = sync_gap_from_jira(gap, client)

        assert outcome.action == JiraSyncAction.UPDATED
        assert outcome.new_status == GapStatus.IN_PROGRESS
        assert gap.status == GapStatus.IN_PROGRESS

    def test_marks_remediated_at_when_status_becomes_remediated(self) -> None:
        gap = _gap(jira_issue_key="SEC-5", status=GapStatus.IN_PROGRESS)
        assert gap.remediated_at is None
        client = _client(get_issue=lambda _: _issue("SEC-5", status_name="Done"))

        outcome = sync_gap_from_jira(gap, client)

        assert outcome.action == JiraSyncAction.UPDATED
        assert gap.status == GapStatus.REMEDIATED
        assert gap.remediated_at is not None

    def test_skips_when_status_unchanged(self) -> None:
        gap = _gap(jira_issue_key="SEC-5", status=GapStatus.OPEN)
        client = _client(get_issue=lambda _: _issue("SEC-5", status_name="To Do"))

        outcome = sync_gap_from_jira(gap, client)

        assert outcome.action == JiraSyncAction.SKIPPED
        assert "unchanged" in outcome.detail.lower()
        assert gap.status == GapStatus.OPEN

    def test_skips_when_jira_status_unknown(self) -> None:
        gap = _gap(jira_issue_key="SEC-5", status=GapStatus.OPEN)
        client = _client(get_issue=lambda _: _issue("SEC-5", status_name="Waiting for Customer"))

        outcome = sync_gap_from_jira(gap, client)

        assert outcome.action == JiraSyncAction.SKIPPED
        assert "mapping" in outcome.detail.lower()
        assert gap.status == GapStatus.OPEN

    def test_errors_on_api_failure(self) -> None:
        gap = _gap(jira_issue_key="SEC-5", status=GapStatus.OPEN)

        def _get(_: str) -> JiraIssue:
            raise JiraApiError("gone", status_code=410)

        client = _client(get_issue=_get)

        outcome = sync_gap_from_jira(gap, client)

        assert outcome.action == JiraSyncAction.ERRORED
        assert outcome.issue_key == "SEC-5"


# ── push_open_gaps (batch) ───────────────────────────────────────────────


def _report(gaps: list[ControlGap]) -> GapAnalysisReport:
    return GapAnalysisReport(
        organization="Test Org",
        frameworks_analyzed=["soc2-tsc"],
        total_controls_required=len(gaps),
        total_controls_in_inventory=0,
        total_gaps=len(gaps),
        critical_gaps=sum(1 for g in gaps if _sev_value(g.gap_severity) == "critical"),
        high_gaps=sum(1 for g in gaps if _sev_value(g.gap_severity) == "high"),
        medium_gaps=sum(1 for g in gaps if _sev_value(g.gap_severity) == "medium"),
        low_gaps=sum(1 for g in gaps if _sev_value(g.gap_severity) == "low"),
        informational_gaps=sum(1 for g in gaps if _sev_value(g.gap_severity) == "informational"),
        coverage_percentage=0.0,
        gaps=gaps,
    )


def _sev_value(v: object) -> str:
    return v.value if hasattr(v, "value") else str(v)


class TestPushOpenGaps:
    def test_pushes_only_open_or_in_progress(self) -> None:
        gaps = [
            _gap(control_id="AC-1", status=GapStatus.OPEN),
            _gap(control_id="AC-2", status=GapStatus.REMEDIATED),
            _gap(control_id="AC-3", status=GapStatus.ACCEPTED),
            _gap(control_id="AC-4", status=GapStatus.IN_PROGRESS),
        ]
        report = _report(gaps)

        issued: list[str] = []

        def _create(**kwargs: object) -> JiraIssue:
            summary = str(kwargs["summary"])
            issued.append(summary)
            return _issue(f"SEC-{len(issued)}")

        client = _client(create_issue=_create)

        result = push_open_gaps(report, client)

        assert result.created == 2
        # Skipped statuses produce no outcome entry in push_open_gaps —
        # only the two candidates get processed.
        assert len(result.outcomes) == 2
        assert all(o.action == JiraSyncAction.CREATED for o in result.outcomes)
        assert any("AC-1" in s for s in issued)
        assert any("AC-4" in s for s in issued)

    def test_severity_filter_restricts_to_chosen_severities(self) -> None:
        gaps = [
            _gap(control_id="C1", gap_severity=GapSeverity.CRITICAL, status=GapStatus.OPEN),
            _gap(control_id="C2", gap_severity=GapSeverity.HIGH, status=GapStatus.OPEN),
            _gap(control_id="C3", gap_severity=GapSeverity.MEDIUM, status=GapStatus.OPEN),
        ]
        report = _report(gaps)

        def _create(**_: object) -> JiraIssue:
            return _issue()

        client = _client(create_issue=_create)

        result = push_open_gaps(report, client, severity_filter={"critical", "high"})

        assert result.created == 2

    def test_max_issues_cap_stops_creation_and_marks_rest_skipped(self) -> None:
        gaps = [_gap(control_id=f"C{i}", status=GapStatus.OPEN) for i in range(5)]
        report = _report(gaps)

        def _create(**_: object) -> JiraIssue:
            return _issue()

        client = _client(create_issue=_create)

        result = push_open_gaps(report, client, max_issues=2)

        assert result.created == 2
        assert result.skipped == 3
        assert all("max_issues" in o.detail for o in result.outcomes if o.action == JiraSyncAction.SKIPPED)


# ── sync_report (batch) ──────────────────────────────────────────────────


class TestSyncReport:
    def test_syncs_only_linked_gaps(self) -> None:
        gaps = [
            _gap(control_id="A1", jira_issue_key="SEC-1", status=GapStatus.OPEN),
            _gap(control_id="A2", status=GapStatus.OPEN),  # unlinked
            _gap(control_id="A3", jira_issue_key="SEC-3", status=GapStatus.OPEN),
        ]
        report = _report(gaps)

        status_map = {"SEC-1": "In Progress", "SEC-3": "Done"}

        def _get(key: str) -> JiraIssue:
            return _issue(key, status_name=status_map[key])

        client = _client(get_issue=_get)

        result = sync_report(report, client)

        assert len(result.outcomes) == 2, (
            "sync_report should only emit outcomes for LINKED gaps; unlinked are silently filtered."
        )
        assert result.updated == 2
        assert gaps[0].status == GapStatus.IN_PROGRESS
        assert gaps[2].status == GapStatus.REMEDIATED
