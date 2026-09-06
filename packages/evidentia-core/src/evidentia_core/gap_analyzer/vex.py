"""CycloneDX 1.6 VEX export for gap-analysis reports.

v0.10.5 Phase 8. Renders a :class:`GapAnalysisReport` as a CycloneDX 1.6
**VEX** (Vulnerability Exploitability eXchange) document so gap-analysis
output can flow into supply-chain VEX consumers (Dependency-Track and
other CycloneDX-aware tooling) alongside Evidentia's existing CycloneDX
1.6 SBOM emit (the release workflow ships ``evidentia-sbom.cdx.json``).

Federal supply-chain mandates (EO 14028, SEC 2026 supply-chain
enforcement) are driving CycloneDX VEX adoption. CycloneDX is already
part of Evidentia's supply-chain artifact stack (SBOM at release time;
PEP 740 attestations; SLSA provenance), so VEX is an additive surface
that does not require new dependencies.

**Gap-to-vulnerability semantics.** A control gap is conceptually a
"vulnerability" in the operator's compliance posture — a known issue
with a known severity that the operator may or may not have remediated.
Each :class:`ControlGap` becomes one CycloneDX ``vulnerability`` entry:

- ``id`` — the gap ID (UUID v4 stamp; stable across reports).
- ``source.name`` — Evidentia (the analyzer that surfaced the gap).
- ``ratings[].severity`` — the gap severity, mapped to CycloneDX
  severity strings.
- ``description`` — ``gap.gap_description``.
- ``recommendation`` — ``gap.remediation_guidance``.
- ``analysis.state`` — derived from ``gap.implementation_status`` +
  ``gap.status`` (the v0.7.x GapStatus field). See the mapping below.
- ``analysis.detail`` — operator-visible rationale for the state
  classification.

**State mapping** (CycloneDX 1.6 vulnerability state enum):

| ``implementation_status`` | ``status`` (GapStatus) | VEX ``state``              |
|---------------------------|------------------------|----------------------------|
| ``implemented``           | any                    | ``resolved``               |
| ``missing``               | ``open``               | ``exploitable``            |
| ``missing``               | ``in_progress``        | ``in_triage``              |
| ``missing``               | ``remediated``         | ``resolved``               |
| ``missing``               | ``accepted``           | ``not_affected``           |
| ``missing``               | ``not_applicable``     | ``not_affected``           |
| ``partial``               | any (except accepted)  | ``in_triage``              |
| ``partial``               | ``accepted``           | ``not_affected``           |
| ``planned``               | any                    | ``in_triage``              |
| ``not_applicable``        | any                    | ``not_affected``           |

Rationale: a *missing-and-open* gap is the VEX analogue of an
"exploitable" vulnerability — the operator has acknowledged the issue
exists and is choosing not (yet) to fix it. *Missing-but-accepted* is
``not_affected`` with a ``risk_accepted`` justification. *Implemented*
or *remediated* is ``resolved``.

The CycloneDX 1.6 VEX schema is defined at
https://cyclonedx.org/docs/1.6/json/ — this module emits the subset
sufficient for gap reporting; downstream tooling that wants a fully
SBOM-bound VEX merges this output with the Evidentia SBOM via the
standard CycloneDX merge tooling.
"""

from __future__ import annotations

import hashlib
from typing import Any

from evidentia_core.models.common import current_version
from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
)

_CYCLONEDX_SPEC_VERSION = "1.6"
_CYCLONEDX_BOM_FORMAT = "CycloneDX"

# Map GapSeverity -> CycloneDX vulnerability rating severity string.
# CycloneDX 1.6 severity vocabulary: critical / high / medium / low /
# info / none / unknown.
_SEVERITY_TO_CYCLONEDX: dict[GapSeverity, str] = {
    GapSeverity.CRITICAL: "critical",
    GapSeverity.HIGH: "high",
    GapSeverity.MEDIUM: "medium",
    GapSeverity.LOW: "low",
    GapSeverity.INFORMATIONAL: "info",
}

# Internal constants for the VEX state strings (CycloneDX 1.6
# vulnerability state enum).
_STATE_RESOLVED = "resolved"
_STATE_EXPLOITABLE = "exploitable"
_STATE_IN_TRIAGE = "in_triage"
_STATE_NOT_AFFECTED = "not_affected"
_STATE_FALSE_POSITIVE = "false_positive"


def gap_report_to_cyclonedx_vex(report: GapAnalysisReport) -> dict[str, Any]:
    """Render a gap-analysis report as a CycloneDX 1.6 VEX dict.

    Returns a plain JSON-ready ``dict`` conforming to the CycloneDX 1.6
    VEX schema. The output is a standalone artifact; it is also
    composable with the Evidentia release-time SBOM via the standard
    CycloneDX merge tooling.

    Each :class:`ControlGap` becomes one ``vulnerability`` entry with a
    VEX ``analysis.state`` derived from the gap's implementation status
    and lifecycle status. See the module docstring for the full state
    mapping.
    """
    vulnerabilities: list[dict[str, Any]] = [_gap_to_vulnerability(gap) for gap in report.gaps]

    # Stable per-report fingerprint so consumers can detect re-emits of
    # the same report. Computed over the report id + analyzed_at to
    # remain deterministic for identical inputs while shifting on a
    # fresh analyzer run.
    serial = hashlib.sha256(f"{report.id}:{report.analyzed_at.isoformat()}".encode()).hexdigest()[:16]

    return {
        "bomFormat": _CYCLONEDX_BOM_FORMAT,
        "specVersion": _CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:evidentia-vex-{serial}",
        "version": 1,
        "metadata": {
            "timestamp": report.analyzed_at.isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Evidentia",
                        "vendor": "Polycentric Labs",
                        "version": current_version(),
                    }
                ]
            },
        },
        "vulnerabilities": vulnerabilities,
    }


def _gap_to_vulnerability(gap: ControlGap) -> dict[str, Any]:
    """Convert a single :class:`ControlGap` to a CycloneDX
    vulnerability entry with a VEX analysis block.
    """
    severity = _SEVERITY_TO_CYCLONEDX.get(gap.gap_severity, "unknown")
    state, justification = _vex_state_and_justification(gap)

    # Build the analysis block. CycloneDX VEX `analysis.justification`
    # is only valid when `state == not_affected`; the schema rejects it
    # otherwise.
    analysis: dict[str, Any] = {
        "state": state,
        "detail": _vex_analysis_detail(gap, state),
    }
    if state == _STATE_NOT_AFFECTED and justification is not None:
        analysis["justification"] = justification

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


def _vex_state_and_justification(gap: ControlGap) -> tuple[str, str | None]:
    """Derive the CycloneDX VEX state + (when applicable) the
    ``not_affected`` justification from a gap's implementation_status +
    lifecycle status.

    Returns ``(state, justification_or_None)``. The justification is
    non-None only when ``state == "not_affected"`` — the CycloneDX 1.6
    schema rejects it on other states.
    """
    impl = gap.implementation_status
    # EvidentiaModel uses `use_enum_values=True`; gap.status may surface
    # as either the underlying str or the enum instance. Unwrap to str
    # for the comparison.
    status_value = gap.status.value if hasattr(gap.status, "value") else str(gap.status)

    # `implemented`: the control is in place, gap is structurally
    # resolved. VEX `resolved`.
    if impl == "implemented":
        return _STATE_RESOLVED, None

    # `not_applicable` (implementation layer): explicit-NA — the
    # framework requirement doesn't apply to this operator's scope.
    # VEX `not_affected` with `code_not_present` justification.
    if impl == "not_applicable":
        return _STATE_NOT_AFFECTED, "code_not_present"

    # GapStatus is the lifecycle status; can override implementation_status.
    if status_value == "remediated":
        return _STATE_RESOLVED, None
    if status_value == "accepted":
        return _STATE_NOT_AFFECTED, "code_not_reachable"
    if status_value == "not_applicable":
        return _STATE_NOT_AFFECTED, "code_not_present"

    # IN_PROGRESS: operator is actively working the gap → in_triage.
    if status_value == "in_progress":
        return _STATE_IN_TRIAGE, None

    # `partial` / `planned`: in-flight remediation; in_triage.
    if impl in ("partial", "planned"):
        return _STATE_IN_TRIAGE, None

    # Default: implementation_status == "missing" + status == OPEN.
    # The compliance equivalent of an "exploitable" vulnerability.
    return _STATE_EXPLOITABLE, None


def _vex_analysis_detail(gap: ControlGap, state: str) -> str:
    """Operator-visible rationale for the VEX state classification.

    Surfaces the data the state decision was made from (the gap's
    implementation_status + lifecycle status) so a VEX reviewer can
    audit the classification without re-running the gap analyzer.
    """
    # EvidentiaModel uses `use_enum_values=True`, so enum-typed fields
    # may surface as either the underlying str or the enum instance
    # depending on construction path (Python-constructed vs Pydantic-
    # deserialized). Defensively unwrap both shapes.
    status_value = gap.status.value if hasattr(gap.status, "value") else str(gap.status)
    severity_value = gap.gap_severity.value if hasattr(gap.gap_severity, "value") else str(gap.gap_severity)
    return (
        f"Gap classified as VEX state '{state}' from "
        f"implementation_status='{gap.implementation_status}', "
        f"gap_status='{status_value}'. Framework: {gap.framework}; "
        f"control: {gap.control_id}; severity: {severity_value}."
    )


__all__ = ["gap_report_to_cyclonedx_vex"]
