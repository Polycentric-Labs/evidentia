"""Severity + NIST 800-53 Rev 5 control mappings for Nessus findings.

Mirrors the ``_m()`` helper + constant-list pattern used by
``evidentia_collectors.okta.mapping``. A vulnerability scan is
evidence toward RA-5 (vulnerability monitoring and scanning) and a
feed into SI-2 (flaw remediation), not a pass/fail check of either
control, so every mapping here uses ``SUBSET_OF``.
"""

from __future__ import annotations

from evidentia_core.models.common import ControlMapping, OLIRRelationship, Severity

# Nessus's numeric `severity` ReportItem attribute, ascending: 0 informational,
# 1 low, 2 medium, 3 high, 4 critical. Index-matched against Severity's members
# from least to most severe (the reverse of the enum's own declared order).
_SEVERITY_BY_NESSUS_LEVEL: tuple[Severity, ...] = (
    Severity.INFORMATIONAL,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


def nessus_severity_to_severity(value: int) -> Severity:
    """Map a Nessus ``ReportItem severity`` attribute (0-4) to ``Severity``.

    Values outside ``[0, 4]`` clamp to the nearest end (a plugin feed
    should never emit one, but a clamp is cheaper and safer than a
    raised exception on a value this collector doesn't control).
    """
    index = max(0, min(value, len(_SEVERITY_BY_NESSUS_LEVEL) - 1))
    return _SEVERITY_BY_NESSUS_LEVEL[index]


def _m(control_id: str, justification: str) -> ControlMapping:
    return ControlMapping(
        framework="nist-800-53-rev5",
        control_id=control_id,
        relationship=OLIRRelationship.SUBSET_OF,
        justification=justification,
    )


# Attached to every emitted SecurityFinding and to the scan-report
# EvidenceArtifact itself: a vulnerability scan is evidence toward both
# controls regardless of any single finding's severity.
VULNERABILITY_SCAN_MAPPINGS: list[ControlMapping] = [
    _m("RA-5", "vulnerability scan output"),
    _m("SI-2", "flaw remediation input"),
]

__all__ = [
    "VULNERABILITY_SCAN_MAPPINGS",
    "nessus_severity_to_severity",
]
