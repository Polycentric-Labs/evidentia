"""CycloneDX 1.6 and 1.7 representations of control-gap observations.

Each source gap retains its identity, rating, description, recommendation and
ordered properties. Its analysis contains a literal lifecycle observation only;
control status does not establish component applicability, vulnerable-code
presence or exploitability. Schema validation does not establish those facts.

CycloneDX recommends a new serial for each BOM. This exporter deliberately uses
one UUID for repeated exports of the same report ID and original timestamp
representation, including across the two supported versions. The serial is not
a content digest or an external-consumer interoperability guarantee.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from evidentia_core.models.common import current_version
from evidentia_core.models.gap import ControlGap, GapAnalysisReport, GapSeverity

_CYCLONEDX_BOM_FORMAT = "CycloneDX"

# Preserve the source severity mapping for the supported CycloneDX subset.
_SEVERITY_TO_CYCLONEDX: dict[GapSeverity, str] = {
    GapSeverity.CRITICAL: "critical",
    GapSeverity.HIGH: "high",
    GapSeverity.MEDIUM: "medium",
    GapSeverity.LOW: "low",
    GapSeverity.INFORMATIONAL: "info",
}


def gap_report_to_cyclonedx_vex(report: GapAnalysisReport, *, spec_version: str = "1.6") -> dict[str, Any]:
    """Render literal control-gap observations with an explicit schema version.

    The default is 1.6; only the exact native strings 1.6 and 1.7 are accepted.
    A source timestamp must have a defined offset and a representable UTC
    instant. Invalid selection or time raises ValueError without altering the
    source report. This output carries no vulnerability-impact verdict.
    """
    if type(spec_version) is not str or spec_version not in ("1.6", "1.7"):
        raise ValueError("Unsupported CycloneDX VEX specification version")
    timestamp = _canonical_timestamp(report.analyzed_at)
    serial = uuid5(
        NAMESPACE_URL,
        f"https://github.com/Polycentric-Labs/evidentia#vex:{report.id}:{report.analyzed_at.isoformat()}",
    ).urn
    vulnerabilities = [_gap_to_vulnerability(gap) for gap in report.gaps]
    return {
        "bomFormat": _CYCLONEDX_BOM_FORMAT,
        "specVersion": spec_version,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Evidentia",
                        "publisher": "Polycentric Labs",
                        "version": current_version(),
                    }
                ]
            },
        },
        "vulnerabilities": vulnerabilities,
    }


def _canonical_timestamp(value: datetime) -> str:
    """Render the same aware instant with a four-digit year and six fractions."""
    message = "VEX requires an aware timestamp representable in UTC"
    try:
        if value.utcoffset() is None:
            raise ValueError(message)
        instant = value.astimezone(UTC)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError(message) from exc
    # A real datetime supplies checked calendar fields. Explicit numeric widths
    # avoid platform-specific strftime behavior for years below 1000.
    return (
        f"{instant.year:04d}-{instant.month:02d}-{instant.day:02d}"
        f"T{instant.hour:02d}:{instant.minute:02d}:{instant.second:02d}"
        f".{instant.microsecond:06d}Z"
    )


def _gap_to_vulnerability(gap: ControlGap) -> dict[str, Any]:
    """Convert a single :class:`ControlGap` to a CycloneDX
    vulnerability entry with a VEX analysis block.
    """
    severity = _SEVERITY_TO_CYCLONEDX.get(gap.gap_severity, "unknown")
    analysis = {"detail": _vex_analysis_detail(gap)}

    vulnerability: dict[str, Any] = {
        "bom-ref": gap.id,
        "id": gap.id,
        "source": {
            "name": "Evidentia",
            "url": "https://github.com/Polycentric-Labs/evidentia",
        },
        "ratings": [
            {
                "source": {"name": "Evidentia"},
                "severity": severity,
                "method": "other",
            }
        ],
        "description": (f"{gap.framework} {gap.control_id} ({gap.control_title}): {gap.gap_description}"),
        "analysis": analysis,
    }

    if gap.remediation_guidance:
        vulnerability["recommendation"] = gap.remediation_guidance

    # Properties carry the framework + control_id + implementation_status
    # so a downstream VEX consumer can re-key per control without
    # parsing the description text. CycloneDX `properties` is a list of
    # name/value pairs.
    properties: list[dict[str, str]] = [
        {"name": "evidentia:framework", "value": gap.framework},
        {"name": "evidentia:control_id", "value": gap.control_id},
        {
            "name": "evidentia:implementation_status",
            "value": gap.implementation_status,
        },
        {
            "name": "evidentia:gap_status",
            "value": (gap.status.value if hasattr(gap.status, "value") else str(gap.status)),
        },
        {
            "name": "evidentia:priority_score",
            "value": str(gap.priority_score),
        },
    ]
    if gap.cross_framework_value:
        properties.append(
            {
                "name": "evidentia:cross_framework_value",
                "value": ", ".join(gap.cross_framework_value),
            }
        )
    vulnerability["properties"] = properties

    return vulnerability


def _vex_analysis_detail(gap: ControlGap) -> str:
    """Preserve literal implementation and lifecycle status without inference."""
    status_value = gap.status.value if hasattr(gap.status, "value") else str(gap.status)
    return (
        "Control-gap lifecycle observation only. "
        f"implementation_status={gap.implementation_status}; gap_status={status_value}. "
        "No component or service applicability, vulnerable-code presence or "
        "exploitability assessment is provided."
    )


__all__ = ["gap_report_to_cyclonedx_vex"]
