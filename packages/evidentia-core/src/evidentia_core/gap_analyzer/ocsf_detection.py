"""OCSF Detection Finding array export for gap-analysis reports.

v0.10.5 Phase 7. SIEM-target counterpart to the v0.10.4 ``ocsf.py``
Compliance Finding emit. Renders a :class:`GapAnalysisReport` as a JSON
array of OCSF **Detection Finding** (``class_uid`` 2004) records so gap
analysis output can flow natively into major SIEMs — Splunk, Elastic,
Microsoft Sentinel, Datadog — which consume Detection Finding as the
production-traffic OCSF class.

The OCSF ecosystem's actual production traffic is on Detection Finding
2004: Prowler emits 2004, AWS Security Hub emits 2004, and SIEM vendors
have wired their ingest pipelines to 2004. Compliance Finding 2003 has
under-adoption — it is the *semantically correct* class for control
pass/fail findings (and remains Evidentia's default OCSF emit), but
operators who need SIEM ingest pick 2004.

Each :class:`ControlGap` becomes one OCSF Detection Finding:

- ``severity_id`` maps from :class:`GapSeverity` identically to the
  Compliance Finding path (CRITICAL → 5, HIGH → 4, MEDIUM → 3, LOW → 2,
  INFORMATIONAL → 1).
- ``finding_info.title`` / ``.desc`` / ``.uid`` mirror the Compliance
  Finding pattern.
- ``message`` carries ``gap.gap_description``.
- ``remediation.desc`` carries ``gap.remediation_guidance``.
- ``status_id`` maps from :class:`GapStatus`
  (OPEN/IN_PROGRESS → New (1); REMEDIATED → Resolved (4);
  ACCEPTED → Suppressed (3); default → Other (99)) — same mapping the
  Compliance Finding emit uses for its ``finding_info`` status.
- Detection Finding has **no native ``compliance`` object** (it pre-dates
  OCSF's compliance class). Framework + control_id therefore land in
  ``finding_info.product_uid`` (the control identifier, framework-
  qualified) plus the ``unmapped["evidentia"]["gap"]`` block. SIEM
  operators who care about the compliance binding read it from the
  unmapped block; SIEM operators who just want findings see the gap
  description in the standard fields.
- ``unmapped["evidentia"]["gap"]`` carries the full ``ControlGap`` JSON
  for round-trip fidelity (mirrors the v0.10.0 SecurityFinding +
  v0.10.4 Compliance Finding patterns).
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
_OCSF_CLASS_UID = 2004  # Detection Finding
_OCSF_CLASS_NAME = "Detection Finding"

# Map GapSeverity -> OCSF SeverityID enum integer value. Identical to
# the Compliance Finding emit so a finding's severity stays consistent
# whichever OCSF class an operator chooses.
_SEVERITY_TO_OCSF_SEVERITY_ID: dict[GapSeverity, int] = {
    GapSeverity.CRITICAL: 5,
    GapSeverity.HIGH: 4,
    GapSeverity.MEDIUM: 3,
    GapSeverity.LOW: 2,
    GapSeverity.INFORMATIONAL: 1,
}


def gap_report_to_ocsf_detection_array(
    report: GapAnalysisReport,
) -> list[dict[str, Any]]:
    """Render a gap-analysis report as a JSON array of OCSF Detection
    Finding records.

    Returns a list of plain JSON-ready ``dict`` objects, each valid
    against the OCSF Detection Finding (``class_uid`` 2004) schema.
    Suitable for direct ``json.dumps()`` serialization; the wrapping
    ``_export_ocsf_detection()`` helper handles file I/O.

    Raises :class:`OCSFMappingError` if the ``ocsf`` extra is absent
    (mirrors the collector-path ``finding_to_ocsf`` precondition).
    """
    ocsf = _load_ocsf()
    return [_gap_to_ocsf_detection_finding(gap, report, ocsf) for gap in report.gaps]


def _gap_to_ocsf_detection_finding(
    gap: ControlGap,
    report: GapAnalysisReport,
    ocsf: Any,
) -> dict[str, Any]:
    """Convert a single :class:`ControlGap` to an OCSF Detection
    Finding dict.

    The full ``ControlGap`` JSON lands under ``unmapped["evidentia"]``
    so consumers that understand Evidentia's gap shape can recover the
    unflattened detail (mirrors the v0.10.0 :func:`finding_to_ocsf`
    pattern).
    """
    severity_id_int = _SEVERITY_TO_OCSF_SEVERITY_ID.get(gap.gap_severity, 99)

    # Frame the control identifier as a framework-qualified type tag in
    # `finding_info.types[]` so SIEM filters that key off the finding
    # type see a stable per-control identifier even when the unmapped
    # block is stripped on ingest. Mirrors the SARIF emit's `rule_id`
    # shape (`<framework>/<control_id>`).
    framework_qualified_control = f"{gap.framework}/{gap.control_id}"

    finding_info = ocsf.FindingInformation(
        title=f"Gap: {gap.framework} {gap.control_id} — {gap.control_title}",
        uid=gap.id,
        desc=gap.gap_description,
        types=[framework_qualified_control],
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
    # REMEDIATED → Resolved (4); ACCEPTED → Suppressed (3); default → Other (99).
    finding_status_id = {
        "open": 1,
        "in_progress": 1,
        "remediated": 4,
        "accepted": 3,
    }.get(gap.status.value if hasattr(gap.status, "value") else str(gap.status), 99)

    # OCSF requires `time` (milliseconds since epoch).
    timestamp_ms = int(gap.created_at.timestamp() * 1000)

    # Look up DetectionFindingTypeID dynamically so the lazy ocsf
    # namespace stays the single source of truth for OCSF class IDs.
    from py_ocsf_models.events.findings.detection_finding_type_id import (
        DetectionFindingTypeID,
    )

    detection_finding = ocsf.DetectionFinding(
        activity_id=ocsf.ActivityID.Create,
        type_uid=DetectionFindingTypeID.Create,
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
        remediation=remediation,
        # Carry the full ControlGap JSON for lossless round-trip.
        # Detection Finding has no native compliance object, so the
        # unmapped block is also where consumers recover framework +
        # control_id + implementation_status + cross_framework_value.
        unmapped={"evidentia": {"gap": gap.model_dump(mode="json")}},
    )

    # `ocsf` is loaded dynamically by `_load_ocsf` so mypy types the
    # returned model as `Any`; the model_dump call is well-typed at
    # runtime to dict[str, Any]. Annotate to satisfy the strict
    # `no-any-return` policy without losing precision.
    result: dict[str, Any] = detection_finding.model_dump(mode="json", exclude_none=True)
    return result


__all__ = ["OCSFMappingError", "gap_report_to_ocsf_detection_array"]
