"""Greenbone GMP report XML ingestion (v0.13 V13-05 second half).

Parses a Greenbone Community Edition (OpenVAS) GMP report export (the
``<report>`` XML document ``gvm-cli`` or the Greenbone web UI write when
you export a scan report) into ``SecurityFinding`` records, a
``CollectionManifest``, and one scan-report ``EvidenceArtifact`` that
feeds ``evidentia conmon series``. No network access: the input is
always a local file or an already-in-memory XML string, matching the
design's "free and self-hostable, no network access in tests" framing
for this item (``docs/designs/cadence-assertion-layer-design.md``
section 2.6). This is the second of the two file-ingest collectors that
item describes; ``evidentia_collectors.nessus`` is the first and this
module deliberately mirrors its shape.

The GMP report document is either a wrapping ``<report id=... format_id=...
extension="xml">`` around an inner ``<report id=...>`` (the shape
``gvm-cli``'s ``get_reports`` XML output produces), or a bare inner
``<report>`` on its own; both are accepted.

XML is parsed with ``defusedxml`` (via the shared
:mod:`evidentia_collectors._xml` loader) so external entities and entity
expansion (XXE / billion-laughs) are refused before any element is read;
input is capped at 50 MB, mirroring the Nessus and OCSF ingests' own cap.
Requires the optional ``scan`` extra:
``pip install 'evidentia-collectors[scan]'``.

Trust boundary: a Greenbone report is third-party input (the scanner, not
Evidentia, produced it). Every ``SecurityFinding`` this module emits gets
its ``id`` from :func:`evidentia_core.models.common.
deterministic_finding_id` via ``source_system`` + ``source_finding_id``;
the collector never sets ``id`` directly, so nothing in the XML can
forge a finding identity (see ``docs/collector-idempotency-audit.md``
section 4).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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

from evidentia_collectors._xml import parse_defused_xml
from evidentia_collectors.greenbone.mapping import (
    VULNERABILITY_SCAN_MAPPINGS,
    greenbone_severity_to_severity,
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

COLLECTOR_ID = "greenbone-file"

# The bundled cadence a scan-report artifact is assumed to satisfy when the
# caller doesn't name one. A real, registered cadence (evidentia_core.conmon
# .calendar.BUNDLED_CADENCES): FedRAMP ConMon monthly vulnerability scans.
DEFAULT_CADENCE_SLUG = "fedramp-conmon-scans"

# Mirrors the Nessus and OCSF ingests' 50 MB cap. A Greenbone report is
# untrusted third-party input; the cap bounds both memory use and
# defusedxml parse time before any element is read.
_MAX_INPUT_BYTES = 50 * 1024 * 1024

BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "EVIDENTIA-GREENBONE-UNAUTHENTICATED-SCAN",
        "title": "Unauthenticated scans see less than credentialed ones",
        "description": (
            "A Greenbone scan run without host credentials relies on "
            "network-visible banners and responses; it cannot enumerate "
            "installed packages, local patch levels, or configuration "
            "files the way a credentialed (authenticated) scan can. The "
            "report carries no marker distinguishing which mode produced "
            "it. Operators should track scan-config authentication "
            "settings out of band."
        ),
    },
    {
        "id": "EVIDENTIA-GREENBONE-SCOPE-LIMITED-TO-TARGETS",
        "title": "Hosts outside the configured target list are absent",
        "description": (
            "The report contains exactly the hosts the scan's target list "
            "named. A host that exists on the network but was never in "
            "scope produces no <result> entries and is silently absent "
            "from both the findings and the coverage counts; this "
            "ingest cannot detect an under-scoped target list."
        ),
    },
    {
        "id": "EVIDENTIA-GREENBONE-QOD-BELOW-THRESHOLD-HIDDEN",
        "title": "Results below the report's QoD threshold are hidden",
        "description": (
            "Greenbone's Quality of Detection (QoD) score reflects how "
            "confident the detection method was in a positive match. A "
            "report generated with a QoD filter (for example, only "
            "results at 70% confidence or above) never includes results "
            "under that floor; this ingest sees only what the report "
            "already chose to include, not the full result set the scan "
            "engine produced."
        ),
    },
    {
        "id": "EVIDENTIA-GREENBONE-FEED-AGE",
        "title": "NVT feed staleness is not in the export",
        "description": (
            "The GMP report XML does not carry the NVT feed's publish or "
            "sync date. A scan run against a months-stale feed looks "
            "identical, on the wire, to one run the day an NVT shipped; "
            "operators should verify feed currency in the scanner itself, "
            "not from this export."
        ),
    },
]


class GreenboneIngestError(RuntimeError):
    """Raised when Greenbone ingestion cannot proceed.

    Common causes: malformed XML, a forbidden entity / external
    reference construct (XXE / entity-expansion refusal via
    ``defusedxml``), a root element other than ``report``, an oversized
    input (over the 50 MB cap), or an unreadable file.
    """


@dataclass(frozen=True)
class GreenboneResult:
    """One ``<result>``: a single NVT match against one host."""

    result_id: str
    host_ip: str
    hostname: str | None
    port: str
    nvt_oid: str
    nvt_name: str
    nvt_family: str
    cvss_base: float | None
    cvss_base_vector: str
    summary: str
    solution: str
    solution_type: str
    cve: list[str] = field(default_factory=list)
    threat: str = ""
    severity: float | None = None
    qod: int | None = None
    description: str = ""


@dataclass(frozen=True)
class ParsedReport:
    """The result of parsing a Greenbone GMP report XML export.

    Deliberately decoupled from ``SecurityFinding`` construction so the
    XML-parsing step is unit-testable on its own (shape, timestamps,
    entity refusal) without touching the finding-mapping rules.
    """

    task_name: str
    report_id: str
    scan_start: datetime | None
    scan_end: datetime | None
    results: list[GreenboneResult]


def _parse_iso_timestamp(raw: str | None) -> datetime | None:
    """Parse a Greenbone ``<scan_start>``/``<scan_end>`` ISO-8601 timestamp.

    Returns ``None`` (never raises) when ``raw`` is empty/``None`` or
    doesn't parse as ISO-8601; the caller supplies the fallback. A naive
    (timezone-less) timestamp is assumed UTC; an explicit offset is
    converted to UTC.
    """
    if raw is None:
        return None
    text = raw.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _child_text(element: ET.Element | None, tag: str) -> str:
    """Return the stripped text of ``element``'s first ``tag`` child, or ``""``."""
    if element is None:
        return ""
    child = element.find(tag)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def _parse_nvt_tags(raw: str) -> dict[str, str]:
    """Parse an NVT ``<tags>`` string: pipe-separated ``key=value`` pairs.

    For example ``"cvss_base_vector=AV:N/AC:L|summary=...|solution=..."``.
    A segment with no ``=`` is skipped rather than raising: an
    unexpected tag shape from a third-party export shouldn't abort the
    whole ingest. Splits each segment on the FIRST ``=`` only, so a value
    that itself contains ``=`` (unlikely, but not impossible) survives
    intact.
    """
    if not raw:
        return {}
    tags: dict[str, str] = {}
    for segment in raw.split("|"):
        if "=" not in segment:
            continue
        key, _, value = segment.partition("=")
        key = key.strip()
        if key:
            tags[key] = value
    return tags


def parse_greenbone(xml_bytes: bytes) -> ParsedReport:
    """Parse Greenbone GMP report XML bytes into a :class:`ParsedReport`.

    Uses the shared :func:`evidentia_collectors._xml.parse_defused_xml`
    loader, so a DOCTYPE with an ``<!ENTITY`` declaration or an external
    (SYSTEM/PUBLIC) reference raises before any element is read,
    refusing XXE and entity-expansion (billion-laughs) payloads.

    Accepts either the wrapping ``<report id=... format_id=...
    extension="xml">`` around an inner ``<report id=...>``, or a bare
    inner ``<report>`` on its own (no wrapper). Raises
    :class:`GreenboneIngestError` on any parse failure, a refused
    construct, or a root element other than ``report``.
    """
    root = parse_defused_xml(xml_bytes, error_cls=GreenboneIngestError)

    if root.tag != "report":
        raise GreenboneIngestError(f"unsupported root element {root.tag!r}; expected 'report'")

    inner = root.find("report")
    if inner is None:
        inner = root  # bare inner-report form: no outer wrapper present

    report_id = inner.get("id") or root.get("id") or "unknown"

    task_el = inner.find("task")
    task_name = _child_text(task_el, "name")

    scan_start = _parse_iso_timestamp(_child_text(inner, "scan_start") or None)
    scan_end = _parse_iso_timestamp(_child_text(inner, "scan_end") or None)

    results: list[GreenboneResult] = []
    results_el = inner.find("results")
    if results_el is not None:
        for result_el in results_el.findall("result"):
            host_el = result_el.find("host")
            host_ip = (host_el.text or "").strip() if host_el is not None and host_el.text else ""
            hostname: str | None = None
            if host_el is not None:
                hostname_el = host_el.find("hostname")
                if hostname_el is not None and hostname_el.text and hostname_el.text.strip():
                    hostname = hostname_el.text.strip()

            nvt_el = result_el.find("nvt")
            nvt_oid = (nvt_el.get("oid") or "") if nvt_el is not None else ""
            nvt_name = _child_text(nvt_el, "name")
            nvt_family = _child_text(nvt_el, "family")
            cvss_base_raw = _child_text(nvt_el, "cvss_base")
            try:
                cvss_base = float(cvss_base_raw) if cvss_base_raw else None
            except ValueError:
                cvss_base = None
            tags = _parse_nvt_tags(_child_text(nvt_el, "tags"))

            cve_list: list[str] = []
            if nvt_el is not None:
                refs_el = nvt_el.find("refs")
                if refs_el is not None:
                    cve_list = [
                        ref_el.get("id", "")
                        for ref_el in refs_el.findall("ref")
                        if (ref_el.get("type") or "").lower() == "cve" and ref_el.get("id")
                    ]

            severity_raw = _child_text(result_el, "severity")
            try:
                severity_value = float(severity_raw) if severity_raw else None
            except ValueError:
                severity_value = None

            qod_el = result_el.find("qod")
            qod_raw = _child_text(qod_el, "value")
            try:
                qod_value = int(qod_raw) if qod_raw else None
            except ValueError:
                qod_value = None

            results.append(
                GreenboneResult(
                    result_id=result_el.get("id") or "",
                    host_ip=host_ip,
                    hostname=hostname,
                    port=_child_text(result_el, "port"),
                    nvt_oid=nvt_oid,
                    nvt_name=nvt_name,
                    nvt_family=nvt_family,
                    cvss_base=cvss_base,
                    cvss_base_vector=tags.get("cvss_base_vector", ""),
                    summary=tags.get("summary", ""),
                    solution=tags.get("solution", ""),
                    solution_type=tags.get("solution_type", ""),
                    cve=cve_list,
                    threat=_child_text(result_el, "threat"),
                    severity=severity_value,
                    qod=qod_value,
                    description=_child_text(result_el, "description"),
                )
            )

    return ParsedReport(
        task_name=task_name,
        report_id=report_id,
        scan_start=scan_start,
        scan_end=scan_end,
        results=results,
    )


def _build_finding(
    result: GreenboneResult,
    *,
    context: CollectionContext,
    collected_at: datetime,
    description_max_chars: int,
) -> SecurityFinding:
    """Map one :class:`GreenboneResult` to a :class:`SecurityFinding`.

    ``id`` is never set directly: ``source_system`` + ``source_finding_id``
    drive :func:`evidentia_core.models.common.deterministic_finding_id` via
    the model's own ``@model_validator``, so re-ingesting an unchanged
    report reproduces the same finding identities.
    """
    host_label = result.hostname or result.host_ip
    description_source = result.summary or result.description or "(no description provided by the scan)"
    raw_data: dict[str, Any] = {
        "family": result.nvt_family,
        "cvss_base": result.cvss_base,
        "cvss_base_vector": result.cvss_base_vector,
        "qod": result.qod,
        "cve": result.cve,
        "solution_type": result.solution_type,
    }
    return SecurityFinding(
        title=f"{result.nvt_name} on {host_label}:{result.port}",
        description=description_source[:description_max_chars],
        remediation=result.solution or None,
        severity=greenbone_severity_to_severity(result.severity, result.threat),
        source_system="greenbone",
        source_finding_id=(f"{context.source_system_id}:{result.host_ip}:{result.nvt_oid}:{result.port}"),
        resource_type="host",
        resource_id=result.host_ip,
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
    description_max_chars: int,
) -> tuple[list[SecurityFinding], CollectionManifest, EvidenceArtifact]:
    """Shared body of :func:`collect_greenbone_file` / :func:`collect_greenbone_text`."""
    if len(raw) > _MAX_INPUT_BYTES:
        raise GreenboneIngestError(f"input exceeds the {_MAX_INPUT_BYTES}-byte cap ({len(raw)} bytes)")

    parsed = parse_greenbone(raw)
    run_id = new_run_id()
    now = utc_now()
    resolved_cadence_slug = cadence_slug or DEFAULT_CADENCE_SLUG

    context = CollectionContext(
        collector_id=COLLECTOR_ID,
        collector_version=current_version(),
        run_id=run_id,
        credential_identity="file",
        source_system_id=parsed.report_id,
    )

    # Report-level collected_at (unlike Nessus, which has a HOST_END per
    # host): scan_end when present, else scan_start, else now. The last
    # tier gets a manifest warning since the report carries no reliable
    # completion timestamp at all.
    warnings: list[str] = []
    if parsed.scan_end is not None:
        collected_at = parsed.scan_end
    elif parsed.scan_start is not None:
        collected_at = parsed.scan_start
        warnings.append("report missing <scan_end>; used <scan_start> as a fallback timestamp")
    else:
        collected_at = now
        warnings.append("report missing both <scan_end> and <scan_start>; used the collection time as a fallback")

    findings = [
        _build_finding(
            result,
            context=context,
            collected_at=collected_at,
            description_max_chars=description_max_chars,
        )
        for result in parsed.results
    ]

    distinct_hosts = sorted({result.host_ip for result in parsed.results if result.host_ip})
    is_complete = parsed.scan_end is not None
    incomplete_reason = None if is_complete else "report has no <scan_end> timestamp"
    empty_categories = ["results"] if not parsed.results else []

    manifest = CollectionManifest(
        run_id=run_id,
        collector_id=COLLECTOR_ID,
        collector_version=current_version(),
        collection_started_at=now,
        collection_finished_at=now,
        source_system_ids=[parsed.report_id],
        filters_applied={},
        coverage_counts=[
            CoverageCount(
                resource_type="host",
                scanned=len(distinct_hosts),
                matched_filter=len(distinct_hosts),
                collected=len(distinct_hosts),
            ),
            CoverageCount(
                resource_type="result",
                scanned=len(parsed.results),
                matched_filter=len(parsed.results),
                collected=len(parsed.results),
            ),
        ],
        total_findings=len(findings),
        is_complete=is_complete,
        incomplete_reason=incomplete_reason,
        empty_categories=empty_categories,
        warnings=warnings,
    )

    results_by_severity: dict[str, int] = {}
    for result in parsed.results:
        severity_value = greenbone_severity_to_severity(result.severity, result.threat).value
        results_by_severity[severity_value] = results_by_severity.get(severity_value, 0) + 1

    artifact = EvidenceArtifact(
        title=f"Greenbone scan report: {parsed.task_name or parsed.report_id}",
        description=(
            f"Greenbone vulnerability scan of {len(distinct_hosts)} host(s), {len(parsed.results)} finding(s)."
        ),
        evidence_type=EvidenceType.TEST_RESULT,
        source_system="greenbone",
        collected_by=COLLECTOR_ID,
        collected_at=collected_at,
        content={
            "task_name": parsed.task_name,
            "report_id": parsed.report_id,
            "hosts_scanned": len(distinct_hosts),
            "results_by_severity": results_by_severity,
            "scan_start": (parsed.scan_start.isoformat() if parsed.scan_start else None),
            "scan_end": (parsed.scan_end.isoformat() if parsed.scan_end else None),
            "run_id": run_id,
        },
        content_format="json",
        metadata={
            CADENCE_SLUG_METADATA_KEY: resolved_cadence_slug,
            "scanner": "greenbone",
            "report_id": parsed.report_id,
            "task_name": parsed.task_name,
            "run_id": run_id,
        },
        tags=["vulnerability-scan", "greenbone"],
        control_mappings=list(VULNERABILITY_SCAN_MAPPINGS),
    )
    artifact.compute_hash()

    return findings, manifest, artifact


def collect_greenbone_file(
    path: str | Path,
    *,
    cadence_slug: str | None = None,
    description_max_chars: int = 4000,
) -> tuple[list[SecurityFinding], CollectionManifest, EvidenceArtifact]:
    """Read a Greenbone GMP report XML file and convert it.

    Returns ``(findings, manifest, artifact)``; see the module
    docstring. Raises :class:`GreenboneIngestError` on an unreadable
    file, an oversized file (over 50 MB), or any parse/mapping failure.
    """
    file_path = Path(path)
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise GreenboneIngestError(f"could not stat Greenbone report file {file_path}: {exc}") from exc
    if size > _MAX_INPUT_BYTES:
        raise GreenboneIngestError(f"{file_path} exceeds the {_MAX_INPUT_BYTES}-byte cap ({size} bytes)")
    try:
        raw = file_path.read_bytes()
    except OSError as exc:
        raise GreenboneIngestError(f"could not read Greenbone report file {file_path}: {exc}") from exc
    return _collect_from_bytes(
        raw,
        cadence_slug=cadence_slug,
        description_max_chars=description_max_chars,
    )


def collect_greenbone_text(
    xml_text: str,
    *,
    source_name: str,
    cadence_slug: str | None = None,
    description_max_chars: int = 4000,
) -> tuple[list[SecurityFinding], CollectionManifest, EvidenceArtifact]:
    """Convert an in-memory Greenbone GMP report XML string (e.g. an API request body).

    ``source_name`` is used only in the size-cap error message (there is
    no file path to report). Returns ``(findings, manifest, artifact)``;
    raises :class:`GreenboneIngestError` on an oversized payload or any
    parse/mapping failure.
    """
    raw = xml_text.encode("utf-8")
    if len(raw) > _MAX_INPUT_BYTES:
        raise GreenboneIngestError(f"{source_name} exceeds the {_MAX_INPUT_BYTES}-byte cap ({len(raw)} bytes)")
    return _collect_from_bytes(
        raw,
        cadence_slug=cadence_slug,
        description_max_chars=description_max_chars,
    )
