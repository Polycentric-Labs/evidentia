"""OCSF Compliance Finding array export for gap-analysis reports.

v0.10.4 A2. Symmetric counterpart to the v0.10.0 ``sarif.py`` emit:
renders a :class:`GapAnalysisReport` as a JSON array of OCSF
Compliance Finding (class_uid 2003) records so gap analysis output
can flow into SIEMs / data lakes / OCSF-aware tooling alongside
collector-shaped findings ingested via v0.10.1's ``evidentia collect
ocsf`` verb.

Each :class:`ControlGap` becomes one OCSF Compliance Finding:

- ``compliance.status`` is derived from ``implementation_status``
  (missing → NON_COMPLIANT; partial → PARTIAL_COMPLIANCE;
  planned → OTHER; not_applicable → NOT_APPLICABLE; default → OTHER).
- ``compliance.requirements`` carries the gap's control_id; cross-
  framework values land in ``compliance.standards``.
- ``severity_id`` maps from :class:`GapSeverity`
  (CRITICAL+HIGH → High; MEDIUM → Medium; LOW → Low; INFORMATIONAL
  → Informational).
- ``remediation.desc`` carries ``gap.remediation_guidance``.
- ``unmapped["evidentia"]`` carries the full ``ControlGap`` JSON for
  round-trip fidelity (mirrors the v0.10.0 SecurityFinding
  unmapped block on the collector path).
"""

from __future__ import annotations

from typing import Any

from evidentia_core.models.common import current_version
from evidentia_core.models.gap import ControlGap, GapAnalysisReport, GapSeverity
from evidentia_core.ocsf.finding_mapping import (
    OCSFMappingError,
    _load_ocsf,
)

_OCSF_CATEGORY_UID = 2  # Findings
_OCSF_CATEGORY_NAME = "Findings"
_OCSF_CLASS_UID = 2003  # Compliance Finding
_OCSF_CLASS_NAME = "Compliance Finding"

# Map GapSeverity -> OCSF SeverityID enum integer value.
# OCSF SeverityID: 0=Unknown, 1=Informational, 2=Low, 3=Medium,
# 4=High, 5=Critical, 6=Fatal, 99=Other.
_SEVERITY_TO_OCSF_SEVERITY_ID: dict[GapSeverity, int] = {
    GapSeverity.CRITICAL: 5,
    GapSeverity.HIGH: 4,
    GapSeverity.MEDIUM: 3,
    GapSeverity.LOW: 2,
    GapSeverity.INFORMATIONAL: 1,
}

# Map gap.implementation_status (string) -> OCSF ComplianceStatusID
# enum integer value. OCSF ComplianceStatusID:
# 0=Unknown, 1=Pass, 2=Warning, 3=Fail, 99=Other.
# "missing"/"planned" → Fail (3); "partial" → Warning (2);
# "implemented" → Pass (1); anything else → Other (99).
_IMPL_STATUS_TO_COMPLIANCE_STATUS_ID: dict[str, int] = {
    "missing": 3,
    "planned": 3,
    "partial": 2,
    "implemented": 1,
    "not_applicable": 99,
}


def gap_report_to_ocsf_array(report: GapAnalysisReport) -> list[dict[str, Any]]:
    """Render a gap-analysis report as a JSON array of OCSF
    Compliance Finding records.

    Returns a list of plain JSON-ready ``dict`` objects, each one
    valid against the OCSF Compliance Finding (class_uid 2003)
    schema. Suitable for direct ``json.dumps()`` serialization;
    the wrapping ``_export_ocsf()`` helper handles file I/O.

    Raises :class:`OCSFMappingError` if the ``ocsf`` extra is absent
    (mirrors the collector-path ``finding_to_ocsf`` precondition).
    """
    ocsf = _load_ocsf()
    return [_gap_to_ocsf_finding(gap, report, ocsf) for gap in report.gaps]


def _gap_to_ocsf_finding(
    gap: ControlGap,
    report: GapAnalysisReport,
    ocsf: Any,
) -> dict[str, Any]:
    """Convert a single :class:`ControlGap` to an OCSF Compliance
    Finding dict.

    The full ``ControlGap`` JSON lands under ``unmapped["evidentia"]``
    so consumers that understand Evidentia's gap shape can recover
    the unflattened detail (mirrors the v0.10.0
    :func:`finding_to_ocsf` pattern).
    """
    severity_id_int = _SEVERITY_TO_OCSF_SEVERITY_ID.get(gap.gap_severity, 99)
    compliance_status_id_int = _IMPL_STATUS_TO_COMPLIANCE_STATUS_ID.get(gap.implementation_status, 99)

    standards: list[str] = sorted({gap.framework, *(s.split(":")[0] for s in gap.cross_framework_value)})

    compliance = ocsf.Compliance(
        desc=gap.gap_description,
        requirements=[gap.control_id],
        standards=standards,
        status_id=ocsf.ComplianceStatusID(compliance_status_id_int),
    )
    finding_info = ocsf.FindingInformation(
        title=f"Gap: {gap.framework} {gap.control_id} — {gap.control_title}",
        uid=gap.id,
        desc=gap.gap_description,
        first_seen_time_dt=gap.created_at,
        last_seen_time_dt=gap.created_at,
        data_sources=["evidentia_gap_analyzer"],
    )
    metadata = ocsf.Metadata(
        product=ocsf.Product(
            name="Evidentia",
            vendor_name="Polycentric Labs",
            version=current_version(),
        ),
    )
    remediation = ocsf.Remediation(desc=gap.remediation_guidance) if gap.remediation_guidance else None

    # GapStatus -> OCSF StatusID: OPEN/IN_PROGRESS → New (1);
    # REMEDIATED → Closed (4); ACCEPTED → Suppressed (3); default → Other (99).
    finding_status_id = {
        "open": 1,
        "in_progress": 1,
        "remediated": 4,
        "accepted": 3,
    }.get(gap.status.value if hasattr(gap.status, "value") else str(gap.status), 99)

    # OCSF requires `time` (milliseconds since epoch).
    timestamp_ms = int(gap.created_at.timestamp() * 1000)

    compliance_finding = ocsf.ComplianceFinding(
        activity_id=ocsf.ActivityID.Create,
        type_uid=ocsf.ComplianceFindingTypeID.Create,
        category_uid=_OCSF_CATEGORY_UID,
        category_name=_OCSF_CATEGORY_NAME,
        class_uid=_OCSF_CLASS_UID,
        class_name=_OCSF_CLASS_NAME,
        time=timestamp_ms,
        time_dt=gap.created_at,
        severity_id=ocsf.SeverityID(severity_id_int),
        severity=gap.gap_severity.value if hasattr(gap.gap_severity, "value") else str(gap.gap_severity),
        status_id=ocsf.StatusID(finding_status_id),
        message=gap.gap_description,
        metadata=metadata,
        finding_info=finding_info,
        compliance=compliance,
        remediation=remediation,
        # Carry the full ControlGap JSON for lossless round-trip
        # (operators that emit gap reports as OCSF and then ingest
        # them back via a downstream pipeline can recover gap.id,
        # priority_score, cross_framework_value, etc.).
        unmapped={"evidentia": {"gap": gap.model_dump(mode="json")}},
    )

    # `ocsf` is loaded dynamically by `_load_ocsf` so mypy types the
    # returned model as `Any`; the model_dump call is well-typed at
    # runtime to dict[str, Any]. Annotate to satisfy the strict
    # `no-any-return` policy without losing precision.
    result: dict[str, Any] = compliance_finding.model_dump(mode="json", exclude_none=True)
    return result


__all__ = ["OCSFMappingError", "gap_report_to_ocsf_array"]
