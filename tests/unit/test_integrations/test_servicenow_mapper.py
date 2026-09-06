"""Unit tests for ``evidentia_integrations.servicenow.mapper``.

Pure-functional logic only — no HTTP, no real ServiceNow instance.
"""

from __future__ import annotations

import pytest
from evidentia_core.models.gap import (
    ControlGap,
    GapSeverity,
    ImplementationEffort,
)
from evidentia_integrations.servicenow.mapper import (
    SEVERITY_TO_SN_PRIORITY,
    ServiceNowMappingError,
    gap_to_record_request,
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


# ── Severity priority mapping ───────────────────────────────────────


@pytest.mark.parametrize(
    "severity, expected_priority",
    [
        (GapSeverity.CRITICAL, "1"),
        (GapSeverity.HIGH, "2"),
        (GapSeverity.MEDIUM, "3"),
        (GapSeverity.LOW, "4"),
        (GapSeverity.INFORMATIONAL, "5"),
    ],
)
def test_severity_priority_mapping(severity: GapSeverity, expected_priority: str) -> None:
    assert SEVERITY_TO_SN_PRIORITY[severity] == expected_priority


# ── gap_to_record_request ───────────────────────────────────────────


def test_basic_gap_request_includes_required_fields() -> None:
    fields = gap_to_record_request(_gap())
    assert "short_description" in fields
    assert "description" in fields
    assert fields["priority"] == "2"  # HIGH
    assert fields["impact"] == "1"
    assert fields["urgency"] == "2"
    assert "correlation_id" in fields
    assert "correlation_display" in fields


def test_short_description_truncated_to_160_chars() -> None:
    long_title = "X" * 300
    gap = _gap(control_title=long_title)
    fields = gap_to_record_request(gap)
    sd = str(fields["short_description"])
    assert len(sd) <= 160


def test_correlation_id_is_deterministic() -> None:
    gap = _gap()
    fields1 = gap_to_record_request(gap)
    fields2 = gap_to_record_request(gap)
    assert fields1["correlation_id"] == fields2["correlation_id"]


def test_correlation_id_uses_gap_id() -> None:
    gap = _gap()
    fields = gap_to_record_request(gap)
    assert str(fields["correlation_id"]).endswith(gap.id)


def test_custom_correlation_prefix() -> None:
    gap = _gap()
    fields = gap_to_record_request(gap, correlation_id_prefix="custom-prefix-")
    assert str(fields["correlation_id"]).startswith("custom-prefix-")


def test_critical_severity_uses_priority_1() -> None:
    gap = _gap(gap_severity=GapSeverity.CRITICAL)
    fields = gap_to_record_request(gap)
    assert fields["priority"] == "1"
    assert fields["impact"] == "1"
    assert fields["urgency"] == "1"


def test_informational_severity_uses_priority_5() -> None:
    gap = _gap(gap_severity=GapSeverity.INFORMATIONAL)
    fields = gap_to_record_request(gap)
    assert fields["priority"] == "5"


def test_description_includes_gap_remediation_and_id() -> None:
    gap = _gap(
        gap_description="custom gap text",
        remediation_guidance="custom guidance",
    )
    fields = gap_to_record_request(gap)
    description = str(fields["description"])
    assert "custom gap text" in description
    assert "custom guidance" in description
    assert gap.id in description
    assert gap.framework in description


def test_description_includes_cross_framework_when_present() -> None:
    gap = _gap(
        cross_framework_value=["iso27001-2022:A.5.16", "soc2-tsc:CC6.1"],
    )
    fields = gap_to_record_request(gap)
    description = str(fields["description"])
    assert "Cross-framework impact" in description
    assert "iso27001-2022:A.5.16" in description


def test_missing_framework_raises() -> None:
    gap = _gap()
    gap.framework = ""  # bypass validators by mutation
    with pytest.raises(ServiceNowMappingError, match="missing framework"):
        gap_to_record_request(gap)


def test_missing_control_id_raises() -> None:
    gap = _gap()
    gap.control_id = ""
    with pytest.raises(ServiceNowMappingError, match="missing framework"):
        gap_to_record_request(gap)
