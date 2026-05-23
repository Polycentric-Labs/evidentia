"""OCSF (Open Cybersecurity Schema Framework) interoperability.

v0.10.0. Converts Evidentia findings to and from OCSF Compliance
Finding objects. See :mod:`evidentia_core.ocsf.finding_mapping`.

v0.10.1. Adds :func:`finding_from_ocsf_detection` for the OCSF
Detection Finding class (``class_uid`` 2004) — what Prowler and AWS
Security Hub emit — and a trust-boundary-aware
``trust_unmapped`` parameter on :func:`finding_from_ocsf` (default
``True`` for the Evidentia-internal round-trip path; the
:mod:`evidentia_collectors.ocsf` ingestion collector passes
``False``).

Importing this package does NOT require the optional ``ocsf`` extra —
``py-ocsf-models`` is imported lazily, only when a mapping function is
actually called.
"""

from evidentia_core.ocsf.finding_mapping import (
    OCSFMappingError,
    finding_from_ocsf,
    finding_from_ocsf_detection,
    finding_to_ocsf,
)

__all__ = [
    "OCSFMappingError",
    "finding_from_ocsf",
    "finding_from_ocsf_detection",
    "finding_to_ocsf",
]
