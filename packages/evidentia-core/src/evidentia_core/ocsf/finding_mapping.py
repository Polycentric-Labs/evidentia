"""OCSF mapping for evidence-collector findings.

v0.10.0 — converts Evidentia :class:`SecurityFinding` objects to and
from OCSF **Compliance Finding** objects (``class_uid`` 2003), so
Evidentia findings interoperate with the OCSF ecosystem (SIEMs,
AWS Security Lake, and other OCSF producers / consumers).

The OCSF representation comes from ``py-ocsf-models`` — installed via
the optional ``ocsf`` extra (``pip install 'evidentia-core[ocsf]'``).
**This module is the only place that imports it**; the core
:mod:`evidentia_core.models.finding` model never does, so the default
install stays slim and the core model is insulated from OCSF schema
churn. ``py-ocsf-models`` 0.9.x models the OCSF 1.5.0 schema; the
Compliance Finding class is stable across OCSF 1.1+ so this is a
version-label detail, not a functional one.

Round-trip fidelity
-------------------
OCSF's ``compliance`` object cannot natively express Evidentia's
OLIR-typed control mappings (relationship + justification) or its
``CollectionContext`` provenance. Rather than lose them, :func:`finding_to_ocsf`
stashes the *complete* Evidentia finding under the OCSF-standard
``unmapped`` field, namespaced as ``unmapped["evidentia"]``. So::

    finding_from_ocsf(finding_to_ocsf(f)) == f

holds exactly for Evidentia-produced findings. Third-party OCSF input
(no ``unmapped["evidentia"]`` block) is reconstructed best-effort from
the native OCSF fields — the v0.10.1 ingestion collector refines that
path.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from evidentia_core.models.common import (
    ControlMapping,
    OLIRRelationship,
    Severity,
    current_version,
)
from evidentia_core.models.finding import (
    ComplianceStatus,
    FindingStatus,
    SecurityFinding,
)

__all__ = ["OCSFMappingError", "finding_from_ocsf", "finding_to_ocsf"]

# OCSF Compliance Finding class identifiers (OCSF Findings category).
_OCSF_CLASS_UID = 2003
_OCSF_CATEGORY_UID = 2
_OCSF_CLASS_NAME = "Compliance Finding"
_OCSF_CATEGORY_NAME = "Findings"

# Evidentia Severity -> OCSF SeverityID value (py-ocsf-models SeverityID:
# Unknown 0 / Informational 1 / Low 2 / Medium 3 / High 4 / Critical 5 /
# Fatal 6 / Other 99).
_SEVERITY_TO_OCSF: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 1,
}
_OCSF_TO_SEVERITY: dict[int, Severity] = {
    value: severity for severity, value in _SEVERITY_TO_OCSF.items()
}

# Evidentia ComplianceStatus -> OCSF compliance StatusID value
# (py-ocsf-models compliance StatusID: Unknown 0 / Pass 1 / Warning 2 /
# Fail 3 / Other 99). OCSF has no "not applicable" value, so
# NOT_APPLICABLE maps to Other; the exact value round-trips losslessly
# via the unmapped block.
_COMPLIANCE_STATUS_TO_OCSF: dict[ComplianceStatus, int] = {
    ComplianceStatus.PASS: 1,
    ComplianceStatus.WARNING: 2,
    ComplianceStatus.FAIL: 3,
    ComplianceStatus.NOT_APPLICABLE: 99,
    ComplianceStatus.UNKNOWN: 0,
}
_OCSF_TO_COMPLIANCE_STATUS: dict[int, ComplianceStatus] = {
    0: ComplianceStatus.UNKNOWN,
    1: ComplianceStatus.PASS,
    2: ComplianceStatus.WARNING,
    3: ComplianceStatus.FAIL,
    99: ComplianceStatus.NOT_APPLICABLE,
}

# Evidentia FindingStatus -> OCSF finding StatusID value (py-ocsf-models
# finding StatusID: Unknown 0 / New 1 / InProgress 2 / Suppressed 3 /
# Resolved 4 / Archived 5 / Other 99).
_FINDING_STATUS_TO_OCSF: dict[FindingStatus, int] = {
    FindingStatus.ACTIVE: 1,
    FindingStatus.RESOLVED: 4,
    FindingStatus.SUPPRESSED: 3,
}


class OCSFMappingError(RuntimeError):
    """Raised when OCSF mapping cannot proceed.

    Most commonly: the optional ``ocsf`` extra (``py-ocsf-models``) is
    not installed. Also raised when OCSF input does not validate as a
    Compliance Finding.
    """


def _load_ocsf() -> Any:
    """Lazy-import ``py-ocsf-models`` and return its classes as a namespace.

    Imported lazily (not at module load) so ``import evidentia_core.ocsf``
    works without the optional ``ocsf`` extra; the error only surfaces
    when a mapping function is actually called.
    """
    try:
        from py_ocsf_models.events.findings.activity_id import ActivityID
        from py_ocsf_models.events.findings.compliance_finding import (
            ComplianceFinding,
        )
        from py_ocsf_models.events.findings.compliance_finding_type_id import (
            ComplianceFindingTypeID,
        )
        from py_ocsf_models.events.findings.severity_id import SeverityID
        from py_ocsf_models.events.findings.status_id import StatusID
        from py_ocsf_models.objects.compliance import Compliance
        from py_ocsf_models.objects.compliance_status import (
            StatusID as ComplianceStatusID,
        )
        from py_ocsf_models.objects.finding_info import FindingInformation
        from py_ocsf_models.objects.metadata import Metadata
        from py_ocsf_models.objects.product import Product
        from py_ocsf_models.objects.remediation import Remediation
        from py_ocsf_models.objects.resource_details import ResourceDetails
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise OCSFMappingError(
            "OCSF mapping needs the optional 'ocsf' extra. Install it with: "
            "pip install 'evidentia-core[ocsf]'."
        ) from exc

    return SimpleNamespace(
        ActivityID=ActivityID,
        ComplianceFinding=ComplianceFinding,
        ComplianceFindingTypeID=ComplianceFindingTypeID,
        SeverityID=SeverityID,
        StatusID=StatusID,
        Compliance=Compliance,
        ComplianceStatusID=ComplianceStatusID,
        FindingInformation=FindingInformation,
        Metadata=Metadata,
        Product=Product,
        Remediation=Remediation,
        ResourceDetails=ResourceDetails,
    )


def finding_to_ocsf(finding: SecurityFinding) -> dict[str, Any]:
    """Convert a :class:`SecurityFinding` to an OCSF Compliance Finding.

    Returns a plain JSON-ready ``dict`` conforming to the OCSF
    Compliance Finding class. The complete Evidentia finding is embedded
    under ``unmapped["evidentia"]`` so :func:`finding_from_ocsf` can
    reconstruct it losslessly.

    Raises :class:`OCSFMappingError` if the ``ocsf`` extra is absent.
    """
    ocsf = _load_ocsf()

    frameworks = sorted({cm.framework for cm in finding.control_mappings})
    requirements = [cm.control_id for cm in finding.control_mappings]

    compliance = ocsf.Compliance(
        desc=finding.description,
        requirements=requirements or None,
        standards=frameworks or None,
        status_id=ocsf.ComplianceStatusID(
            _COMPLIANCE_STATUS_TO_OCSF[finding.compliance_status]
        ),
    )
    finding_info = ocsf.FindingInformation(
        title=finding.title,
        uid=finding.id,
        desc=finding.description,
        first_seen_time_dt=finding.first_observed,
        last_seen_time_dt=finding.last_observed,
        data_sources=[finding.source_system],
    )
    metadata = ocsf.Metadata(
        product=ocsf.Product(
            name="Evidentia",
            vendor_name="Polycentric Labs",
            version=current_version(),
        ),
    )
    remediation = (
        ocsf.Remediation(desc=finding.remediation) if finding.remediation else None
    )
    resources = None
    if finding.resource_id or finding.resource_type:
        resources = [
            ocsf.ResourceDetails(
                type=finding.resource_type,
                uid=finding.resource_id,
                region=finding.resource_region,
            )
        ]

    compliance_finding = ocsf.ComplianceFinding(
        activity_id=ocsf.ActivityID.Create,
        type_uid=ocsf.ComplianceFindingTypeID.Create,
        category_uid=_OCSF_CATEGORY_UID,
        category_name=_OCSF_CATEGORY_NAME,
        class_uid=_OCSF_CLASS_UID,
        class_name=_OCSF_CLASS_NAME,
        time=int(finding.first_observed.timestamp() * 1000),
        time_dt=finding.first_observed,
        severity_id=ocsf.SeverityID(_SEVERITY_TO_OCSF[finding.severity]),
        # EvidentiaModel uses use_enum_values=True, so `finding.severity`
        # is already the plain string value (e.g. "high").
        severity=finding.severity,
        status_id=ocsf.StatusID(_FINDING_STATUS_TO_OCSF[finding.status]),
        message=finding.description,
        metadata=metadata,
        finding_info=finding_info,
        compliance=compliance,
        remediation=remediation,
        resources=resources,
        unmapped={"evidentia": finding.model_dump(mode="json")},
    )
    result: dict[str, Any] = compliance_finding.model_dump(
        mode="json", exclude_none=True
    )
    return result


def finding_from_ocsf(
    ocsf_finding: dict[str, Any],
    *,
    trust_unmapped: bool = True,
) -> SecurityFinding:
    """Convert an OCSF Compliance Finding ``dict`` back to a SecurityFinding.

    Parameters
    ----------
    ocsf_finding:
        The OCSF Compliance Finding ``dict`` to convert. Re-validated via
        ``py_ocsf_models.ComplianceFinding.model_validate`` before any
        field is read; malformed input raises :class:`OCSFMappingError`.
    trust_unmapped:
        Whether to honor an ``unmapped["evidentia"]`` block as
        authoritative. Default ``True`` — for Evidentia-internal call
        paths where the OCSF doc was produced by :func:`finding_to_ocsf`,
        this gives a *lossless* round-trip (the block carries the
        complete original finding, including OLIR control mappings and
        ``CollectionContext`` provenance that have no native OCSF home).

        **Set to ``False`` when ingesting third-party OCSF input whose
        origin you do not cryptographically verify.** The block is then
        ignored entirely and the finding is rebuilt best-effort from
        native OCSF fields only. A *valid but malicious* OCSF producer
        could otherwise inject a forged block to control the
        reconstructed ``SecurityFinding`` — Pydantic still re-validates
        the model so corrupted blocks fail safely, but the residual
        identity / attribution-forgery risk is real.

        Added v0.10.1 to close pre-release-review finding **F-V100-L1**
        (CWE-345 Insufficient Verification of Data Authenticity, proxy).
        The OCSF *ingestion* collector — shipped in v0.10.1 alongside
        this parameter — passes ``trust_unmapped=False``; all internal
        round-trip call sites stay on the default.

    Returns
    -------
    SecurityFinding
        Reconstructed from the unmapped block when present and
        ``trust_unmapped=True``; otherwise rebuilt from native OCSF
        fields.

    Raises
    ------
    OCSFMappingError
        If the ``ocsf`` extra is absent or the input does not validate
        as an OCSF Compliance Finding.
    """
    ocsf = _load_ocsf()

    try:
        compliance_finding = ocsf.ComplianceFinding.model_validate(ocsf_finding)
    except Exception as exc:  # pydantic ValidationError (and any related parse error)
        raise OCSFMappingError(
            f"input does not validate as an OCSF Compliance Finding: {exc}"
        ) from exc

    if trust_unmapped:
        unmapped = compliance_finding.unmapped
        if isinstance(unmapped, dict) and isinstance(unmapped.get("evidentia"), dict):
            return SecurityFinding.model_validate(unmapped["evidentia"])

    return _security_finding_from_native_ocsf(compliance_finding)


def _security_finding_from_native_ocsf(compliance_finding: Any) -> SecurityFinding:
    """Best-effort :class:`SecurityFinding` from a third-party OCSF finding.

    Used when the OCSF input was not produced by Evidentia (no
    ``unmapped["evidentia"]`` block). v0.10.0 keeps this deliberately
    simple; the v0.10.1 OCSF-ingestion collector refines it (including
    Detection Finding support, which is what tools like Prowler emit).
    """
    info = compliance_finding.finding_info
    compliance = compliance_finding.compliance

    severity = _OCSF_TO_SEVERITY.get(
        int(compliance_finding.severity_id), Severity.MEDIUM
    )
    compliance_status = ComplianceStatus.UNKNOWN
    if compliance is not None and compliance.status_id is not None:
        compliance_status = _OCSF_TO_COMPLIANCE_STATUS.get(
            int(compliance.status_id), ComplianceStatus.UNKNOWN
        )

    standards = list(compliance.standards or []) if compliance is not None else []
    requirements = (
        list(compliance.requirements or []) if compliance is not None else []
    )
    framework = standards[0] if standards else "unknown"
    control_mappings = [
        ControlMapping(
            framework=framework,
            control_id=requirement,
            relationship=OLIRRelationship.RELATED_TO,
            justification=(
                "Ingested from OCSF; the source did not specify an OLIR "
                "relationship."
            ),
        )
        for requirement in requirements
    ]

    product = getattr(compliance_finding.metadata, "product", None)
    source_system = getattr(product, "name", None) or "ocsf-import"
    remediation = (
        compliance_finding.remediation.desc
        if compliance_finding.remediation is not None
        else None
    )

    kwargs: dict[str, Any] = {
        "id": info.uid,
        "title": info.title,
        "description": info.desc or compliance_finding.message or info.title,
        "severity": severity,
        "compliance_status": compliance_status,
        "remediation": remediation,
        "source_system": source_system,
        "control_mappings": control_mappings,
    }
    if info.first_seen_time_dt is not None:
        kwargs["first_observed"] = info.first_seen_time_dt
    if info.last_seen_time_dt is not None:
        kwargs["last_observed"] = info.last_seen_time_dt
    return SecurityFinding(**kwargs)
