"""Nessus v2 XML scan-export ingestion (v0.13 V13-05 first half).

Parses a Nessus v2 (``.nessus``) scan-export XML document — the file
Nessus Essentials / Professional / Tenable.sc write when you export a
scan — into ``SecurityFinding`` records, a ``CollectionManifest``, and
one scan-report ``EvidenceArtifact`` that feeds ``evidentia conmon
series``. No network access: the input is always a local file or an
already-in-memory XML string, matching the design's "free and
self-hostable, no network access in tests" framing for this item
(``docs/designs/cadence-assertion-layer-design.md`` section 2.6).

XML is parsed with ``defusedxml`` so external entities and entity
expansion (XXE / billion-laughs) are refused before any element is
read; input is capped at 50 MB, mirroring the OCSF ingest's own cap
(:mod:`evidentia_collectors.ocsf.collector`). Requires the optional
``scan`` extra: ``pip install 'evidentia-collectors[scan]'``.

Trust boundary: a Nessus export is third-party input (the scanner, not
Evidentia, produced it). Every ``SecurityFinding`` this module emits
gets its ``id`` from :func:`evidentia_core.models.common.
deterministic_finding_id` via ``source_system`` + ``source_finding_id``
— the collector never sets ``id`` directly, so nothing in the XML can
forge a finding identity (see ``docs/collector-idempotency-audit.md``
section 4).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import defusedxml.ElementTree as DefusedET
from defusedxml.common import DefusedXmlException
from evidentia_core.audit import (
    CollectionContext,
    CollectionManifest,
    CoverageCount,
    new_run_id,
)
from evidentia_core.conmon.series import CADENCE_SLUG_METADATA_KEY
from evidentia_core.models.common import current_version, utc_now
from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType
from evidentia_core.models.finding import SecurityFinding

from evidentia_collectors.nessus.mapping import (
    VULNERABILITY_SCAN_MAPPINGS,
    nessus_severity_to_severity,
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

COLLECTOR_ID = "nessus-file"

# The bundled cadence a scan-report artifact is assumed to satisfy when the
# caller doesn't name one. A real, registered cadence (evidentia_core.conmon
# .calendar.BUNDLED_CADENCES) — FedRAMP ConMon monthly vulnerability scans.
DEFAULT_CADENCE_SLUG = "fedramp-conmon-scans"

# Mirrors the OCSF ingest's 50 MB cap (evidentia_collectors.ocsf.collector).
# A Nessus export is untrusted third-party input; the cap bounds both memory
# use and defusedxml parse time before any element is read.
_MAX_INPUT_BYTES = 50 * 1024 * 1024

# Nessus writes HOST_START / HOST_END as ctime()-style strings, e.g.
# "Tue Sep  1 10:22:31 2026" — note the double space before a single-digit
# day. Collapsing repeated whitespace before strptime handles that padding
# without a custom format string per day-of-month width.
_TIMESTAMP_FORMAT = "%a %b %d %H:%M:%S %Y"
_WHITESPACE_RE = re.compile(r"\s+")

BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "EVIDENTIA-NESSUS-UNAUTHENTICATED-SCAN",
        "title": "Unauthenticated scans see less than credentialed ones",
        "description": (
            "A Nessus scan run without host credentials relies on "
            "network-visible banners and responses; it cannot enumerate "
            "installed packages, local patch levels, or configuration "
            "files the way a credentialed (authenticated) scan can. The "
            "export carries no marker distinguishing which mode produced "
            "it — operators should track scan-policy configuration "
            "out of band."
        ),
    },
    {
        "id": "EVIDENTIA-NESSUS-SCOPE-LIMITED-TO-TARGETS",
        "title": "Hosts outside the configured scan targets are absent",
        "description": (
            "The export contains exactly the hosts the scan policy "
            "targeted. A host that exists on the network but was never "
            "in scope produces no ReportHost entry and is silently "
            "absent from both the findings and the coverage counts — "
            "this ingest cannot detect an under-scoped target list."
        ),
    },
    {
        "id": "EVIDENTIA-NESSUS-PLUGIN-FEED-AGE",
        "title": "Plugin-feed staleness is not in the export",
        "description": (
            "Nessus v2 XML does not carry the plugin feed's publish or "
            "sync date. A scan run against a months-stale plugin feed "
            "looks identical, on the wire, to one run the day a plugin "
            "shipped — operators should verify feed currency in the "
            "scanner itself, not from this export."
        ),
    },
    {
        "id": "EVIDENTIA-NESSUS-PARTIAL-SCAN-COMPLETES",
        "title": "A partial scan still produces a report",
        "description": (
            "A scan that times out, loses network connectivity mid-run, "
            "or is manually stopped still exports whatever ReportHost / "
            "ReportItem data it collected before the interruption. The "
            "manifest's is_complete flag reflects only whether every "
            "host in THIS export has a parseable HOST_END timestamp, not "
            "whether the scan covered everything the policy intended."
        ),
    },
]


class NessusIngestError(RuntimeError):
    """Raised when Nessus ingestion cannot proceed.

    Common causes: malformed XML, a forbidden entity / external
    reference construct (XXE / entity-expansion refusal via
    ``defusedxml``), a root element other than
    ``NessusClientData_v2``, an oversized input (over the 50 MB cap),
    or an unreadable file.
    """


@dataclass(frozen=True)
class NessusHost:
    """One ``<ReportHost>`` — its name, resolved IP, and scan timestamps.

    ``host_start`` / ``host_end`` are ``None`` when the ``HOST_START`` /
    ``HOST_END`` tag was absent or failed to parse (see
    :func:`_parse_nessus_timestamp`) — the caller decides the fallback,
    keeping this parse step pure and independently testable.
    """

    name: str
    host_ip: str | None
    host_start: datetime | None
    host_end: datetime | None


@dataclass(frozen=True)
class NessusReportItem:
    """One ``<ReportItem>`` — a single plugin result against one host."""

    host_name: str
    host_ip: str | None
    port: int
    protocol: str
    svc_name: str
    severity: int
    plugin_id: str
    plugin_name: str
    plugin_family: str
    synopsis: str
    description: str
    plugin_output: str
    risk_factor: str
    cve: list[str] = field(default_factory=list)
    cvss3_base_score: float | None = None
    solution: str = ""


@dataclass(frozen=True)
class ParsedScan:
    """The result of parsing a Nessus v2 XML export.

    Deliberately decoupled from ``SecurityFinding`` construction so the
    XML-parsing step is unit-testable on its own (shape, timestamps,
    entity refusal) without touching the finding-mapping rules.
    """

    report_name: str
    hosts: list[NessusHost]
    items: list[NessusReportItem]
    earliest_host_start: datetime | None
    latest_host_end: datetime | None


def _parse_nessus_timestamp(raw: str | None) -> datetime | None:
    """Parse a Nessus ``HOST_START`` / ``HOST_END`` ctime-style string.

    Nessus writes these as ``time.ctime()``-style text, e.g.
    ``"Tue Sep  1 10:22:31 2026"`` (a double space pads a single-digit
    day). Collapsing repeated whitespace before ``strptime`` absorbs
    that padding. Returns ``None`` (never raises) when ``raw`` is
    empty/``None`` or doesn't match — the caller supplies the
    now/warning fallback.
    """
    if raw is None:
        return None
    collapsed = _WHITESPACE_RE.sub(" ", raw.strip())
    if not collapsed:
        return None
    try:
        parsed = datetime.strptime(collapsed, _TIMESTAMP_FORMAT)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC)


def _child_text(element: ET.Element, tag: str) -> str:
    """Return the stripped text of ``element``'s first ``tag`` child, or ``""``."""
    child = element.find(tag)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def parse_nessus(xml_bytes: bytes) -> ParsedScan:
    """Parse Nessus v2 XML bytes into a :class:`ParsedScan`.

    Uses ``defusedxml.ElementTree`` so a DOCTYPE with an ``<!ENTITY``
    declaration or an external (SYSTEM/PUBLIC) reference raises before
    any element is read — refusing XXE and entity-expansion (billion-
    laughs) payloads. Raises :class:`NessusIngestError` on any parse
    failure, a refused construct, or a root element other than
    ``NessusClientData_v2``.
    """
    try:
        root = DefusedET.fromstring(xml_bytes)
    except DefusedXmlException as exc:
        raise NessusIngestError(f"refused an unsafe XML construct (entity/external-reference): {exc}") from exc
    except ET.ParseError as exc:
        raise NessusIngestError(f"not valid XML: {exc}") from exc

    if root.tag != "NessusClientData_v2":
        raise NessusIngestError(f"unsupported root element {root.tag!r}; expected 'NessusClientData_v2'")

    hosts: list[NessusHost] = []
    items: list[NessusReportItem] = []
    report_name = "unknown"

    for report_el in root.findall("Report"):
        report_name = report_el.get("name") or report_name
        for host_el in report_el.findall("ReportHost"):
            host_name = host_el.get("name") or "unknown-host"
            tags: dict[str, str] = {}
            props_el = host_el.find("HostProperties")
            if props_el is not None:
                for tag_el in props_el.findall("tag"):
                    tag_name = tag_el.get("name")
                    if tag_name:
                        tags[tag_name] = (tag_el.text or "").strip()
            host_ip = tags.get("host-ip") or None
            host_start = _parse_nessus_timestamp(tags.get("HOST_START"))
            host_end = _parse_nessus_timestamp(tags.get("HOST_END"))
            hosts.append(
                NessusHost(
                    name=host_name,
                    host_ip=host_ip,
                    host_start=host_start,
                    host_end=host_end,
                )
            )

            for item_el in host_el.findall("ReportItem"):
                cve_list = [
                    cve_el.text.strip() for cve_el in item_el.findall("cve") if cve_el.text and cve_el.text.strip()
                ]
                cvss3_raw = _child_text(item_el, "cvss3_base_score")
                cvss3_score: float | None
                try:
                    cvss3_score = float(cvss3_raw) if cvss3_raw else None
                except ValueError:
                    cvss3_score = None
                try:
                    port = int(item_el.get("port") or 0)
                except ValueError:
                    port = 0
                try:
                    severity = int(item_el.get("severity") or 0)
                except ValueError:
                    severity = 0

                items.append(
                    NessusReportItem(
                        host_name=host_name,
                        host_ip=host_ip,
                        port=port,
                        protocol=item_el.get("protocol") or "",
                        svc_name=item_el.get("svc_name") or "",
                        severity=severity,
                        plugin_id=item_el.get("pluginID") or "",
                        plugin_name=item_el.get("pluginName") or "",
                        plugin_family=item_el.get("pluginFamily") or "",
                        synopsis=_child_text(item_el, "synopsis"),
                        description=_child_text(item_el, "description"),
                        plugin_output=_child_text(item_el, "plugin_output"),
                        risk_factor=_child_text(item_el, "risk_factor"),
                        cve=cve_list,
                        cvss3_base_score=cvss3_score,
                        solution=_child_text(item_el, "solution"),
                    )
                )

    valid_starts = [h.host_start for h in hosts if h.host_start is not None]
    valid_ends = [h.host_end for h in hosts if h.host_end is not None]
    return ParsedScan(
        report_name=report_name,
        hosts=hosts,
        items=items,
        earliest_host_start=min(valid_starts) if valid_starts else None,
        latest_host_end=max(valid_ends) if valid_ends else None,
    )


def _build_finding(
    item: NessusReportItem,
    *,
    context: CollectionContext,
    collected_at: datetime,
    plugin_output_max_chars: int,
) -> SecurityFinding:
    """Map one :class:`NessusReportItem` to a :class:`SecurityFinding`.

    ``id`` is never set directly — ``source_system`` + ``source_finding_id``
    drive :func:`evidentia_core.models.common.deterministic_finding_id` via
    the model's own ``@model_validator``, so re-ingesting an unchanged
    export reproduces the same finding identities.
    """
    description_parts = [part for part in (item.synopsis, item.description) if part]
    description = "\n\n".join(description_parts) or "(no description provided by the plugin)"
    trimmed_output = item.plugin_output[:plugin_output_max_chars] if item.plugin_output else ""
    raw_data: dict[str, Any] = {
        "plugin_family": item.plugin_family,
        "risk_factor": item.risk_factor,
        "cve": item.cve,
        "cvss3_base_score": item.cvss3_base_score,
        "plugin_output": trimmed_output,
    }
    return SecurityFinding(
        title=f"{item.plugin_name} on {item.host_name}:{item.port}/{item.protocol}",
        description=description,
        remediation=item.solution or None,
        severity=nessus_severity_to_severity(item.severity),
        source_system="nessus",
        source_finding_id=(f"{context.source_system_id}:{item.host_name}:{item.plugin_id}:{item.port}/{item.protocol}"),
        resource_type="host",
        resource_id=item.host_ip or item.host_name,
        control_mappings=list(VULNERABILITY_SCAN_MAPPINGS),
        collection_context=context.model_copy(update={"collected_at": collected_at}),
        raw_data=raw_data,
        first_observed=collected_at,
        last_observed=collected_at,
    )


def _collect_from_bytes(
    raw: bytes,
    *,
    cadence_slug: str | None,
    plugin_output_max_chars: int,
) -> tuple[list[SecurityFinding], CollectionManifest, EvidenceArtifact]:
    """Shared body of :func:`collect_nessus_file` / :func:`collect_nessus_text`."""
    if len(raw) > _MAX_INPUT_BYTES:
        raise NessusIngestError(f"input exceeds the {_MAX_INPUT_BYTES}-byte cap ({len(raw)} bytes)")

    parsed = parse_nessus(raw)
    run_id = new_run_id()
    now = utc_now()
    resolved_cadence_slug = cadence_slug or DEFAULT_CADENCE_SLUG

    context = CollectionContext(
        collector_id=COLLECTOR_ID,
        collector_version=current_version(),
        run_id=run_id,
        credential_identity="file",
        source_system_id=parsed.report_name,
    )

    # Per-host resolved collected_at: the host's own HOST_END when parseable,
    # else `now` — every finding on that host shares its host's timestamp.
    resolved_host_end: dict[str, datetime] = {
        host.name: (host.host_end if host.host_end is not None else now) for host in parsed.hosts
    }
    findings = [
        _build_finding(
            item,
            context=context,
            collected_at=resolved_host_end.get(item.host_name, now),
            plugin_output_max_chars=plugin_output_max_chars,
        )
        for item in parsed.items
    ]

    hosts_missing_end = [host.name for host in parsed.hosts if host.host_end is None]
    is_complete = not hosts_missing_end
    warnings: list[str] = []
    incomplete_reason: str | None = None
    if hosts_missing_end:
        warnings.append(
            "host(s) missing or unparseable HOST_END; used the collection "
            f"time as a fallback: {', '.join(hosts_missing_end)}"
        )
        incomplete_reason = (
            f"{len(hosts_missing_end)} of {len(parsed.hosts)} host(s) had no parseable HOST_END timestamp"
        )
    empty_categories = ["report_items"] if parsed.hosts and not parsed.items else []

    manifest = CollectionManifest(
        run_id=run_id,
        collector_id=COLLECTOR_ID,
        collector_version=current_version(),
        collection_started_at=now,
        collection_finished_at=now,
        source_system_ids=[parsed.report_name],
        filters_applied={},
        coverage_counts=[
            CoverageCount(
                resource_type="host",
                scanned=len(parsed.hosts),
                matched_filter=len(parsed.hosts),
                collected=len(parsed.hosts),
            ),
            CoverageCount(
                resource_type="report_item",
                scanned=len(parsed.items),
                matched_filter=len(parsed.items),
                collected=len(parsed.items),
            ),
        ],
        total_findings=len(findings),
        is_complete=is_complete,
        incomplete_reason=incomplete_reason,
        empty_categories=empty_categories,
        warnings=warnings,
    )

    items_by_severity: dict[str, int] = {}
    for item in parsed.items:
        severity_value = nessus_severity_to_severity(item.severity).value
        items_by_severity[severity_value] = items_by_severity.get(severity_value, 0) + 1
    artifact_collected_at = parsed.latest_host_end or now

    artifact = EvidenceArtifact(
        title=f"Nessus scan report: {parsed.report_name}",
        description=(f"Nessus vulnerability scan of {len(parsed.hosts)} host(s), {len(parsed.items)} finding(s)."),
        evidence_type=EvidenceType.TEST_RESULT,
        source_system="nessus",
        collected_by=COLLECTOR_ID,
        collected_at=artifact_collected_at,
        content={
            "report_name": parsed.report_name,
            "hosts_scanned": len(parsed.hosts),
            "items_by_severity": items_by_severity,
            "scan_start": (parsed.earliest_host_start.isoformat() if parsed.earliest_host_start else None),
            "scan_end": (parsed.latest_host_end.isoformat() if parsed.latest_host_end else None),
            "run_id": run_id,
        },
        content_format="json",
        metadata={
            CADENCE_SLUG_METADATA_KEY: resolved_cadence_slug,
            "scanner": "nessus",
            "report_name": parsed.report_name,
            "run_id": run_id,
        },
        tags=["vulnerability-scan", "nessus"],
        control_mappings=list(VULNERABILITY_SCAN_MAPPINGS),
    )
    artifact.compute_hash()

    return findings, manifest, artifact


def collect_nessus_file(
    path: str | Path,
    *,
    cadence_slug: str | None = None,
    plugin_output_max_chars: int = 4000,
) -> tuple[list[SecurityFinding], CollectionManifest, EvidenceArtifact]:
    """Read a Nessus v2 ``.nessus`` XML file and convert it.

    Returns ``(findings, manifest, artifact)`` — see the module
    docstring. Raises :class:`NessusIngestError` on an unreadable file,
    an oversized file (over 50 MB), or any parse/mapping failure.
    """
    file_path = Path(path)
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise NessusIngestError(f"could not stat Nessus file {file_path}: {exc}") from exc
    if size > _MAX_INPUT_BYTES:
        raise NessusIngestError(f"{file_path} exceeds the {_MAX_INPUT_BYTES}-byte cap ({size} bytes)")
    try:
        raw = file_path.read_bytes()
    except OSError as exc:
        raise NessusIngestError(f"could not read Nessus file {file_path}: {exc}") from exc
    return _collect_from_bytes(
        raw,
        cadence_slug=cadence_slug,
        plugin_output_max_chars=plugin_output_max_chars,
    )


def collect_nessus_text(
    xml_text: str,
    *,
    source_name: str,
    cadence_slug: str | None = None,
    plugin_output_max_chars: int = 4000,
) -> tuple[list[SecurityFinding], CollectionManifest, EvidenceArtifact]:
    """Convert an in-memory Nessus v2 XML string (e.g. an API request body).

    ``source_name`` is used only in the size-cap error message (there is
    no file path to report). Returns ``(findings, manifest, artifact)``;
    raises :class:`NessusIngestError` on an oversized payload or any
    parse/mapping failure.
    """
    raw = xml_text.encode("utf-8")
    if len(raw) > _MAX_INPUT_BYTES:
        raise NessusIngestError(f"{source_name} exceeds the {_MAX_INPUT_BYTES}-byte cap ({len(raw)} bytes)")
    return _collect_from_bytes(
        raw,
        cadence_slug=cadence_slug,
        plugin_output_max_chars=plugin_output_max_chars,
    )
