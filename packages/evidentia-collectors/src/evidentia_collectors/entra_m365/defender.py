"""Read source-reported Defender event observations."""

from __future__ import annotations

from typing import Literal

from evidentia_core.models.common import Severity
from evidentia_core.models.finding import FindingStatus, SecurityFinding

from ._client import EntraM365GraphReader
from ._contracts import (
    EntraM365CapabilityRead,
    EntraM365CollectRequest,
    EntraM365Diagnostic,
    EntraM365DlpExport,
    EntraM365RunContext,
    EntraM365SourceRead,
    JsonObject,
    clock_text,
    parse_source_timestamp,
    source_age_seconds,
)


def _observe(
    source: EntraM365SourceRead,
    run_context: EntraM365RunContext,
    rule: Literal["defender-alert-observation", "defender-incident-observation"],
) -> EntraM365CapabilityRead:
    end = parse_source_timestamp(clock_text(run_context.window_end))
    findings: list[SecurityFinding] = []
    precision_warnings = 0
    for record in source.records:
        severity = next(
            (
                level
                for level in (Severity.LOW, Severity.MEDIUM, Severity.HIGH)
                if level.value == record.fields.get("severity")
            ),
            Severity.INFORMATIONAL,
        )
        status = FindingStatus.RESOLVED if record.fields.get("status") == "resolved" else FindingStatus.ACTIVE
        updated = record.fields.get("lastUpdateDateTime")
        observation: JsonObject = {
            "severity": severity.value,
            "status": status.value,
            "last_update_age_seconds": (
                source_age_seconds(end, parse_source_timestamp(updated)) if updated is not None else None
            ),
        }
        resolved_at = None
        source_resolution = record.fields.get("resolvedDateTime")
        if rule == "defender-alert-observation" and status == FindingStatus.RESOLVED and source_resolution is not None:
            resolved_at = parse_source_timestamp(source_resolution).exact_datetime()
            if resolved_at is None:
                precision_warnings += 1
        findings.append(
            run_context.make_finding(
                source,
                rule,
                source_id=record.source_id,
                raw_data=observation,
                severity=severity,
                status=status,
                resolved_at=resolved_at,
            )
        )
    diagnostics = (
        [EntraM365Diagnostic(code="timestamp_precision_unrepresentable", count=precision_warnings, http_status=None)]
        if precision_warnings
        else []
    )
    return run_context.finish_read(source, findings=findings, diagnostics=diagnostics)


def read_defender_alerts(
    request: EntraM365CollectRequest,
    graph_reader: EntraM365GraphReader,
    run_context: EntraM365RunContext,
    dlp_export: EntraM365DlpExport | None = None,
) -> EntraM365CapabilityRead:
    """Observe admitted alert metadata without inferring protection deployment."""
    source = graph_reader.read_collection("defender-alerts", request, run_context)
    return _observe(source, run_context, "defender-alert-observation")


def read_defender_incidents(
    request: EntraM365CollectRequest,
    graph_reader: EntraM365GraphReader,
    run_context: EntraM365RunContext,
    dlp_export: EntraM365DlpExport | None = None,
) -> EntraM365CapabilityRead:
    """Observe admitted incident state without inferring response completion."""
    source = graph_reader.read_collection("defender-incidents", request, run_context)
    return _observe(source, run_context, "defender-incident-observation")
