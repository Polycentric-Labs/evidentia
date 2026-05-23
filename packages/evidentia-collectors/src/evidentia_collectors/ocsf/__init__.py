"""OCSF ingestion collector (v0.10.1).

Reads OCSF Compliance Finding (``class_uid`` 2003) or Detection
Finding (``class_uid`` 2004) JSON from a file or URL and returns a
``list[SecurityFinding]``. Designed to consume output from Prowler,
AWS Security Hub, or any other OCSF-emitting scanner.

Trust-boundary: third-party OCSF input is **never** allowed to control
Evidentia-native fields via the ``unmapped["evidentia"]`` block. The
collector passes ``trust_unmapped=False`` to the underlying mapping
functions. See :mod:`evidentia_core.ocsf.finding_mapping` and
``docs/ocsf-mapping.md`` §5.1.

Requires the optional ``ocsf`` extra:
``pip install 'evidentia-core[ocsf]'``.
"""

from evidentia_collectors.ocsf.collector import (
    OCSFIngestError,
    collect_ocsf_file,
    collect_ocsf_url,
)

__all__ = [
    "OCSFIngestError",
    "collect_ocsf_file",
    "collect_ocsf_url",
]
