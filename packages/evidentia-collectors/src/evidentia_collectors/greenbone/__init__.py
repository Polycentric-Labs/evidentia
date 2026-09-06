"""Greenbone GMP report XML ingestion collector (v0.13 V13-05).

Reads a Greenbone Community Edition (OpenVAS) GMP report export (the
``<report>`` XML document ``gvm-cli`` or the Greenbone web UI write on
export) from a file or an in-memory XML string and returns
``(list[SecurityFinding], CollectionManifest, EvidenceArtifact)``. The
artifact feeds ``evidentia conmon series`` via ``metadata["cadence_slug"]``.

No network access: this is a file-ingest collector, not a credentialed
API poller. XML is parsed with ``defusedxml``; entity expansion and
external references are refused before any element is read.

Requires the optional ``scan`` extra:
``pip install 'evidentia-collectors[scan]'``.

Public surface::

    from evidentia_collectors.greenbone import collect_greenbone_file

    findings, manifest, artifact = collect_greenbone_file("report.xml")

Introspect blind spots (documentation, not consumed programmatically)::

    python -c "from evidentia_collectors.greenbone import BLIND_SPOTS; \\
        import json; print(json.dumps(BLIND_SPOTS, indent=2))"
"""

from evidentia_collectors.greenbone.collector import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    DEFAULT_CADENCE_SLUG,
    GreenboneIngestError,
    GreenboneResult,
    ParsedReport,
    collect_greenbone_file,
    collect_greenbone_text,
    parse_greenbone,
)

__all__ = [
    "BLIND_SPOTS",
    "COLLECTOR_ID",
    "DEFAULT_CADENCE_SLUG",
    "GreenboneIngestError",
    "GreenboneResult",
    "ParsedReport",
    "collect_greenbone_file",
    "collect_greenbone_text",
    "parse_greenbone",
]
