"""Pure-functional mapping between Evidentia gaps and Jira issues.

Extracted from :mod:`evidentia_integrations.jira.client` so these
translations are easy to unit-test without HTTP mocking. The live
client composes these with REST calls.
"""

from __future__ import annotations

from typing import Final

from evidentia_core.models.gap import ControlGap, GapSeverity, GapStatus


class JiraMappingError(Exception):
    """Raised when a gap <-> Jira field translation fails validation."""


# ── Status mapping ───────────────────────────────────────────────────────

#: GapStatus -> Jira workflow status name (case-insensitive match on sync).
#: Accepted / Not-applicable map to ``Won't Do`` since Jira's default
#: workflow doesn't have a dedicated "accepted" transition — they're both
#: "won't remediate".
GAP_STATUS_TO_JIRA_STATUS: Final[dict[GapStatus, str]] = {
    GapStatus.OPEN: "To Do",
    GapStatus.IN_PROGRESS: "In Progress",
    GapStatus.REMEDIATED: "Done",
    GapStatus.ACCEPTED: "Won't Do",
    GapStatus.NOT_APPLICABLE: "Won't Do",
}

#: Reverse mapping — Jira status (lowercased) -> GapStatus. Covers the
#: default Jira Cloud workflow names + a few common customizations
#: ("Closed", "Resolved") that teams often use.
JIRA_STATUS_TO_GAP_STATUS: Final[dict[str, GapStatus]] = {
    "to do": GapStatus.OPEN,
    "backlog": GapStatus.OPEN,
    "open": GapStatus.OPEN,
    "reopened": GapStatus.OPEN,
    "in progress": GapStatus.IN_PROGRESS,
    "in review": GapStatus.IN_PROGRESS,
    "blocked": GapStatus.IN_PROGRESS,
    "done": GapStatus.REMEDIATED,
    "resolved": GapStatus.REMEDIATED,
    "closed": GapStatus.REMEDIATED,
    "complete": GapStatus.REMEDIATED,
    "completed": GapStatus.REMEDIATED,
    "won't do": GapStatus.ACCEPTED,
    "won't fix": GapStatus.ACCEPTED,
    "wontfix": GapStatus.ACCEPTED,
    "cannot reproduce": GapStatus.ACCEPTED,
    "declined": GapStatus.ACCEPTED,
}


# Severity -> Jira priority name. Jira's default priorities are
# "Highest / High / Medium / Low / Lowest". If a project customizes
# priorities the mapping can be overridden at :class:`JiraConfig`
# level in v0.5.1 — for now, most out-of-box projects accept these.
_SEVERITY_TO_PRIORITY: Final[dict[GapSeverity, str]] = {
    GapSeverity.CRITICAL: "Highest",
    GapSeverity.HIGH: "High",
    GapSeverity.MEDIUM: "Medium",
    GapSeverity.LOW: "Low",
    GapSeverity.INFORMATIONAL: "Lowest",
}


def jira_status_to_gap_status(jira_status_name: str) -> GapStatus | None:
    """Return the :class:`GapStatus` corresponding to a Jira status name.

    Case-insensitive. Returns ``None`` for unknown statuses so callers
    can decide how to handle unfamiliar workflow states (log + skip,
    surface as an error, or prompt the user to extend the mapping).
    """
    return JIRA_STATUS_TO_GAP_STATUS.get(jira_status_name.strip().lower())


# ── Issue-creation payload ───────────────────────────────────────────────


def gap_to_create_request(gap: ControlGap) -> dict[str, object]:
    """Build the kwargs for :meth:`JiraClient.create_issue` from a gap.

    Produces a structured body with:
      - ``summary``: ``"[{framework}] {control_id}: {control_title}"``
      - ``description``: prose summary (severity, effort, gap description,
        remediation guidance, cross-framework impact)
      - ``labels``: the framework id + ``evidentia`` + severity
      - ``extra_fields``: ``priority`` from gap severity.
    """
    if not gap.framework or not gap.control_id:
        raise JiraMappingError(
            "Gap is missing framework/control_id; cannot push to Jira."
        )

    summary = f"[{gap.framework}] {gap.control_id}: {gap.control_title}"
    summary = summary[:250]  # Jira cap is ~255 — stay conservative.

    lines: list[str] = [
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
        lines.extend(
            [
                "",
                "Cross-framework impact (closing this gap also satisfies):",
                *(f"  - {cf}" for cf in gap.cross_framework_value),
            ]
        )
    if gap.equivalent_controls_in_inventory:
        lines.extend(
            [
                "",
                "Related controls in inventory:",
                *(f"  - {c}" for c in gap.equivalent_controls_in_inventory),
            ]
        )
    lines.extend(
        [
            "",
            f"Tracked by Evidentia gap id: {gap.id}",
        ]
    )

    severity_str = _enum_value(gap.gap_severity)
    labels = [
        "evidentia",
        gap.framework,
        f"severity-{severity_str}",
        f"effort-{_enum_value(gap.implementation_effort)}",
    ]

    priority_name = _SEVERITY_TO_PRIORITY.get(
        gap.gap_severity
        if isinstance(gap.gap_severity, GapSeverity)
        else GapSeverity(gap.gap_severity)
    )

    extra_fields: dict[str, object] = {}
    if priority_name:
        extra_fields["priority"] = {"name": priority_name}

    return {
        "summary": summary,
        "description": "\n".join(lines),
        "labels": labels,
        "extra_fields": extra_fields,
    }


def _enum_value(value: object) -> str:
    """Return the ``.value`` of an enum, or the string form otherwise.

    Evidentia's Pydantic models use ``use_enum_values=True`` which
    means loaded-from-JSON instances carry strings, while in-memory
    instances carry the enum itself. Normalizing here lets the mapper
    work identically on both paths.
    """
    return value.value if hasattr(value, "value") else str(value)
