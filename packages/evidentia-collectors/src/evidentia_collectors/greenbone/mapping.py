"""Severity mapping for Greenbone findings.

The NIST 800-53 Rev 5 control mappings are NOT redefined here: both the
Nessus and Greenbone ingests support the identical claim, that a
vulnerability scan is evidence toward RA-5 (vulnerability monitoring and
scanning) and a feed into SI-2 (flaw remediation), not a pass/fail check
of either control. Rather than duplicate the two ``ControlMapping``
entries, this module reuses
:data:`evidentia_collectors.nessus.mapping.VULNERABILITY_SCAN_MAPPINGS`
directly; both collectors are gated behind the same ``scan`` extra, so the
import carries no new dependency.
"""

from __future__ import annotations

from evidentia_core.models.common import Severity

from evidentia_collectors.nessus.mapping import VULNERABILITY_SCAN_MAPPINGS

# Greenbone's <threat> element (Log, Low, Medium, High, Critical) is the
# fallback used only when the numeric <severity> is absent/unparseable:
# see greenbone_severity_to_severity. Keyed lower-case; the parser's own
# text is title-case but this mapping is looked up case-insensitively.
_THREAT_TO_SEVERITY: dict[str, Severity] = {
    "log": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def greenbone_severity_to_severity(severity_value: float | None, threat: str) -> Severity:
    """Map a Greenbone ``<result><severity>`` float (CVSS-style, 0.0-10.0) to ``Severity``.

    Thresholds: ``9.0`` and above critical, ``7.0`` and above high, ``4.0``
    and above medium, above ``0`` low, ``0`` informational. When
    ``severity_value`` is ``None`` (the tag was absent or unparseable),
    falls back to the ``<threat>`` text (``Log``/``Low``/``Medium``/
    ``High``/``Critical``, matched case-insensitively); an unrecognized
    threat string defaults to informational.
    """
    if severity_value is None:
        return _THREAT_TO_SEVERITY.get(threat.strip().lower(), Severity.INFORMATIONAL)
    if severity_value >= 9.0:
        return Severity.CRITICAL
    if severity_value >= 7.0:
        return Severity.HIGH
    if severity_value >= 4.0:
        return Severity.MEDIUM
    if severity_value > 0:
        return Severity.LOW
    return Severity.INFORMATIONAL


__all__ = [
    "VULNERABILITY_SCAN_MAPPINGS",
    "greenbone_severity_to_severity",
]
