"""Unit tests for ``evidentia_integrations.jira.mapper``.

Pure-functional logic only — no HTTP, no real Jira server. These tests
are the first line of defense against GapStatus <-> Jira workflow drift.
"""

from __future__ import annotations

import pytest
from evidentia_core.models.gap import (
    ControlGap,
    GapSeverity,
    GapStatus,
    ImplementationEffort,
)
from evidentia_integrations.jira.mapper import (
    GAP_STATUS_TO_JIRA_STATUS,
    JIRA_STATUS_TO_GAP_STATUS,
    JiraMappingError,
    gap_to_create_request,
    jira_status_to_gap_status,
)


def _gap(**overrides: object) -> ControlGap:
    """Minimum-viable ControlGap with sane defaults."""
    defaults = {
        "framework": "nist-800-53-rev5-moderate",
        "control_id": "AC-2",
        "control_title": "Account Management",
        "control_description": "Manage information system accounts.",
        "gap_severity": GapSeverity.HIGH,
        "implementation_status": "missing",
        "gap_description": "No centralized account-management process.",
        "remediation_guidance": "Deploy Okta with quarterly access reviews.",
        "implementation_effort": ImplementationEffort.MEDIUM,
    }
    defaults.update(overrides)
    return ControlGap(**defaults)  # type: ignore[arg-type]


# ── jira_status_to_gap_status ────────────────────────────────────────────


class TestJiraStatusMapping:
    @pytest.mark.parametrize(
        "jira_name, expected",
        [
            ("To Do", GapStatus.OPEN),
            ("Backlog", GapStatus.OPEN),
            ("Reopened", GapStatus.OPEN),
            ("In Progress", GapStatus.IN_PROGRESS),
            ("In Review", GapStatus.IN_PROGRESS),
            ("Blocked", GapStatus.IN_PROGRESS),
            ("Done", GapStatus.REMEDIATED),
            ("Resolved", GapStatus.REMEDIATED),
            ("Closed", GapStatus.REMEDIATED),
            ("Complete", GapStatus.REMEDIATED),
            ("Won't Do", GapStatus.ACCEPTED),
            ("Won't Fix", GapStatus.ACCEPTED),
            ("WontFix", GapStatus.ACCEPTED),
            ("declined", GapStatus.ACCEPTED),
        ],
    )
    def test_known_statuses(self, jira_name: str, expected: GapStatus) -> None:
        assert jira_status_to_gap_status(jira_name) is expected

    def test_case_insensitive(self) -> None:
        assert jira_status_to_gap_status("DONE") is GapStatus.REMEDIATED
        assert jira_status_to_gap_status("  in progress  ") is GapStatus.IN_PROGRESS

    def test_unknown_returns_none(self) -> None:
        assert jira_status_to_gap_status("Waiting on Customer") is None
        assert jira_status_to_gap_status("") is None

    def test_every_gap_status_has_forward_mapping(self) -> None:
        """All GapStatus enum values must have a forward mapping entry.

        This catches new GapStatus additions that would otherwise crash
        a Jira push silently.
        """
        for status in GapStatus:
            assert status in GAP_STATUS_TO_JIRA_STATUS, f"Missing forward mapping for GapStatus.{status.name}"

    def test_forward_reverse_roundtrip_for_canonical_statuses(self) -> None:
        """OPEN / IN_PROGRESS / REMEDIATED / ACCEPTED roundtrip correctly.

        NOT_APPLICABLE isn't in the roundtrip set — it collapses to
        ``Won't Do`` on the forward path, which maps back to ACCEPTED
        (the intentional one-way squash).
        """
        roundtrip_statuses = [
            GapStatus.OPEN,
            GapStatus.IN_PROGRESS,
            GapStatus.REMEDIATED,
            GapStatus.ACCEPTED,
        ]
        for status in roundtrip_statuses:
            jira_name = GAP_STATUS_TO_JIRA_STATUS[status]
            returned = JIRA_STATUS_TO_GAP_STATUS[jira_name.lower()]
            assert returned is status


# ── gap_to_create_request ────────────────────────────────────────────────


class TestGapToCreateRequest:
    def test_produces_expected_shape(self) -> None:
        req = gap_to_create_request(_gap())
        assert "summary" in req
        assert "description" in req
        assert "labels" in req
        assert "extra_fields" in req

    def test_summary_includes_framework_and_control_id(self) -> None:
        req = gap_to_create_request(_gap())
        summary = req["summary"]
        assert isinstance(summary, str)
        assert "nist-800-53-rev5-moderate" in summary
        assert "AC-2" in summary
        assert "Account Management" in summary

    def test_summary_truncated_when_long(self) -> None:
        long_title = "X" * 500
        req = gap_to_create_request(_gap(control_title=long_title))
        summary = req["summary"]
        assert isinstance(summary, str)
        assert len(summary) <= 250

    def test_description_contains_all_prose_fields(self) -> None:
        req = gap_to_create_request(_gap())
        desc = req["description"]
        assert isinstance(desc, str)
        assert "No centralized account-management process." in desc
        assert "Deploy Okta with quarterly access reviews." in desc
        assert "Severity:" in desc
        assert "Effort:" in desc
        assert "Priority score:" in desc
        assert "Tracked by Evidentia gap id" in desc

    def test_description_lists_cross_framework_impact(self) -> None:
        req = gap_to_create_request(_gap(cross_framework_value=["soc2-tsc:CC6.1", "iso-27001-2022:A.8.1"]))
        desc = req["description"]
        assert isinstance(desc, str)
        assert "Cross-framework impact" in desc
        assert "soc2-tsc:CC6.1" in desc
        assert "iso-27001-2022:A.8.1" in desc

    def test_description_omits_cross_framework_section_when_empty(self) -> None:
        req = gap_to_create_request(_gap(cross_framework_value=[]))
        desc = req["description"]
        assert isinstance(desc, str)
        assert "Cross-framework impact" not in desc

    def test_labels_include_evidentia_and_framework(self) -> None:
        req = gap_to_create_request(_gap())
        labels = req["labels"]
        assert isinstance(labels, list)
        assert "evidentia" in labels
        assert "nist-800-53-rev5-moderate" in labels
        assert "severity-high" in labels
        assert "effort-medium" in labels

    def test_critical_severity_maps_to_highest_priority(self) -> None:
        req = gap_to_create_request(_gap(gap_severity=GapSeverity.CRITICAL))
        extra = req["extra_fields"]
        assert isinstance(extra, dict)
        assert extra["priority"] == {"name": "Highest"}

    def test_informational_severity_maps_to_lowest_priority(self) -> None:
        req = gap_to_create_request(_gap(gap_severity=GapSeverity.INFORMATIONAL))
        extra = req["extra_fields"]
        assert isinstance(extra, dict)
        assert extra["priority"] == {"name": "Lowest"}

    def test_rejects_gap_missing_framework(self) -> None:
        # framework="" fails at Pydantic validation before reaching the
        # mapper. Construct a valid gap and then blank the field.
        gap = _gap()
        gap.framework = ""
        with pytest.raises(JiraMappingError, match="framework/control_id"):
            gap_to_create_request(gap)

    def test_handles_string_enum_values_from_json_roundtrip(self) -> None:
        """ControlGap round-tripped through JSON carries string enum
        values rather than enum instances (Pydantic use_enum_values=True).
        The mapper must accept both shapes."""
        json_gap = _gap()
        json_gap.gap_severity = "critical"  # type: ignore[assignment]
        json_gap.implementation_effort = "high"  # type: ignore[assignment]
        req = gap_to_create_request(json_gap)
        assert isinstance(req["description"], str)
        assert "critical" in req["description"]
