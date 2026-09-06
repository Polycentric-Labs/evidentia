"""Nessus v2 XML scan-export ingestion collector (v0.13 V13-05).

Reads a Nessus v2 (``.nessus``) scan-export, the file Nessus
Essentials / Professional / Tenable.sc write on export; from a file
or an in-memory XML string and returns ``(list[SecurityFinding],
CollectionManifest, EvidenceArtifact)``. The artifact feeds
``evidentia conmon series`` via ``metadata["cadence_slug"]``.

No network access: this is a file-ingest collector, not a
credentialed API poller. XML is parsed with ``defusedxml``: entity
expansion and external references are refused before any element is
read.

Requires the optional ``scan`` extra:
``pip install 'evidentia-collectors[scan]'``.

Public surface::

    from evidentia_collectors.nessus import collect_nessus_file

    findings, manifest, artifact = collect_nessus_file("scan.nessus")

Introspect blind spots (documentation, not consumed programmatically)::

    python -c "from evidentia_collectors.nessus import BLIND_SPOTS; \\
        import json; print(json.dumps(BLIND_SPOTS, indent=2))"
"""

from evidentia_collectors.nessus.collector import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    DEFAULT_CADENCE_SLUG,
    NessusHost,
    NessusIngestError,
    NessusReportItem,
    ParsedScan,
    collect_nessus_file,
    collect_nessus_text,
    parse_nessus,
)

__all__ = [
    "BLIND_SPOTS",
    "COLLECTOR_ID",
    "DEFAULT_CADENCE_SLUG",
    "NessusHost",
    "NessusIngestError",
    "NessusReportItem",
    "ParsedScan",
    "collect_nessus_file",
    "collect_nessus_text",
    "parse_nessus",
]
