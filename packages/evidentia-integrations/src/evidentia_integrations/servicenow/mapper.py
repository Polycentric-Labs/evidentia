"""Pure-functional mapping between Evidentia gaps and ServiceNow records.

Extracted from the live client so translations are unit-testable
without HTTP mocking. Mirrors the Jira mapper layout.
"""

from __future__ import annotations

from typing import Final

from evidentia_core.models.gap import ControlGap, GapSeverity


class ServiceNowMappingError(Exception):
    """Raised when a gap -> ServiceNow field translation fails."""


# Severity -> ServiceNow priority value. ServiceNow's incident table
# uses numeric strings 1-5 where 1 = Critical and 5 = Planning.
SEVERITY_TO_SN_PRIORITY: Final[dict[GapSeverity, str]] = {
    GapSeverity.CRITICAL: "1",
    GapSeverity.HIGH: "2",
    GapSeverity.MEDIUM: "3",
    GapSeverity.LOW: "4",
    GapSeverity.INFORMATIONAL: "5",
}


# Severity -> ServiceNow impact + urgency. The default incident
# table uses these as the 2-axis input that produces priority.
# 1 = High, 2 = Medium, 3 = Low.
_SEVERITY_TO_IMPACT_URGENCY: Final[dict[GapSeverity, tuple[str, str]]] = {
    GapSeverity.CRITICAL: ("1", "1"),
    GapSeverity.HIGH: ("1", "2"),
    GapSeverity.MEDIUM: ("2", "2"),
    GapSeverity.LOW: ("3", "2"),
    GapSeverity.INFORMATIONAL: ("3", "3"),
}


def gap_to_record_request(
    gap: ControlGap,
    *,
    correlation_id_prefix: str = "evidentia-gap-",
) -> dict[str, object]:
    """Build the field dict for :meth:`ServiceNowClient.create_record`.

    Returns a dict suitable for the ServiceNow Table API. Field names
    target the default ``incident`` table; operators using
    ``sn_grc_issue`` or a custom table can post-process the dict
    before passing it to ``create_record``.

    Sets ``correlation_id`` to a deterministic Evidentia identifier
    so ``find_existing_by_correlation`` can detect duplicates on
    re-push.
    """
    if not gap.framework or not gap.control_id:
        raise ServiceNowMappingError("Gap is missing framework/control_id; cannot push to ServiceNow.")

    severity_value = gap.gap_severity if isinstance(gap.gap_severity, GapSeverity) else GapSeverity(gap.gap_severity)
    priority = SEVERITY_TO_SN_PRIORITY.get(severity_value, "3")
    impact, urgency = _SEVERITY_TO_IMPACT_URGENCY.get(severity_value, ("2", "2"))

    short_description = f"[{gap.framework}] {gap.control_id}: {gap.control_title}"
    short_description = short_description[:160]  # SN cap

    description_lines: list[str] = [
        f"Control: {gap.framework}:{gap.control_id} — {gap.control_title}",
        f"Severity: {_enum_value(gap.gap_severity)}",
        f"Effort: {_enum_value(gap.implementation_effort).replace('_', ' ')}",
        f"Priority score: {gap.priority_score:.2f}",
        "",
        "Gap:",
        gap.gap_description or "(no description)",
        "",
        "Remediation guidance:",
        gap.remediation_guidance or "(no guidance)",
    ]
    if gap.cross_framework_value:
        description_lines.extend(
            [
                "",
                "Cross-framework impact (closing this gap also satisfies):",
                *(f"  - {cf}" for cf in gap.cross_framework_value),
            ]
        )
    description_lines.extend(["", f"Tracked by Evidentia gap id: {gap.id}"])
    description = "\n".join(description_lines)

    correlation_id = f"{correlation_id_prefix}{gap.id}"

    return {
        "short_description": short_description,
        "description": description,
        "priority": priority,
        "impact": impact,
        "urgency": urgency,
        "correlation_id": correlation_id,
        "correlation_display": f"Evidentia: {gap.framework}:{gap.control_id}",
    }


def _enum_value(value: object) -> str:
    """Return the ``.value`` of an enum, or the string form otherwise."""
    return value.value if hasattr(value, "value") else str(value)
